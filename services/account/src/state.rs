//! Account service state: database, schema, views, and shared helpers.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::error::AccountServiceError;
use crate::totp_wrapping_key;

pub(crate) const SESSION_TTL_SECONDS: u64 = 30 * 60;
pub(crate) const RECOVERY_SESSION_TTL_SECONDS: u64 = 15 * 60;
pub(crate) const CHALLENGE_TTL_SECONDS: u64 = 5 * 60;
pub(crate) const SESSION_HANDOFF_TTL_SECONDS: u64 = 2 * 60;
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024;
pub(crate) const SESSION_COOKIE_NAME: &str = "ciphervault_account_session";
pub(crate) const TOTP_KEY_ENV: &str = "CIPHERVAULT_ACCOUNT_TOTP_KEY";
pub(crate) const TOTP_KEY_FILE_ENV: &str = "CIPHERVAULT_ACCOUNT_TOTP_KEY_FILE";
pub(crate) const REQUIRE_TOTP_KEY_ENV: &str = "CIPHERVAULT_ACCOUNT_REQUIRE_TOTP_KEY";
pub(crate) const TOTP_NONCE_BYTES: usize = 12;
pub(crate) const AUTH_RATE_WINDOW_SECONDS: u64 = 5 * 60;
pub(crate) const AUTH_RATE_MAX_FAILURES: u32 = 5;
pub(crate) const AUTH_RATE_LOCK_SECONDS: u64 = 5 * 60;
pub(crate) const AUTH_RATE_MAX_KEYS: usize = 10_000;

#[derive(Clone)]
pub struct AccountState {
    db: Arc<Mutex<Connection>>,
    pub(crate) http: reqwest::Client,
}

/// SQLite lock-contention waits since process start (B7). Installed as the
/// connection busy handler in [`AccountState::open`]: each lock wait bumps the
/// counter, the handler sleeps 5 ms (SQLite does not sleep for custom handlers
/// — returning `true` without sleeping would hot-spin), and it gives up after
/// ~1000 waits to preserve the historical 5 s timeout. `synchronous`
/// deliberately stays at the default FULL: the account database keeps crash
/// durability, and load gates assert this counter instead of weakening
/// persistence.
pub(crate) static SQLITE_BUSY_RETRIES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn counting_busy_handler(prior_waits: i32) -> bool {
    SQLITE_BUSY_RETRIES.fetch_add(1, Ordering::Relaxed);
    if prior_waits >= 1000 {
        return false;
    }
    std::thread::sleep(std::time::Duration::from_millis(5));
    true
}

/// Total SQLite busy-handler waits since process start.
pub fn sqlite_busy_retries() -> u64 {
    SQLITE_BUSY_RETRIES.load(Ordering::Relaxed)
}

impl AccountState {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self, AccountServiceError> {
        let data_dir = data_dir.into();
        fs::create_dir_all(&data_dir)?;
        let db_path = data_dir.join("accounts.sqlite3");
        let connection = Connection::open(db_path.clone())?;
        connection.busy_handler(Some(counting_busy_handler))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS accounts (
                 account_id TEXT PRIMARY KEY,
                 display_name TEXT NOT NULL,
                 account_public_key_hex TEXT NOT NULL UNIQUE,
                 created_at_utc INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS devices (
                 account_id TEXT NOT NULL,
                 device_id_hex TEXT NOT NULL,
                 public_key_hex TEXT NOT NULL,
                 label TEXT NOT NULL,
                 enrolled_at_utc INTEGER NOT NULL,
                 last_seen_at_utc INTEGER,
                 revoked_at_utc INTEGER,
                 PRIMARY KEY (account_id, device_id_hex),
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS vault_links (
                 account_id TEXT NOT NULL,
                 vault_id_hex TEXT NOT NULL,
                 alias TEXT NOT NULL,
                 role TEXT NOT NULL,
                 linked_at_utc INTEGER NOT NULL,
                 PRIMARY KEY (account_id, vault_id_hex),
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS memberships (
                 account_id TEXT NOT NULL,
                 member_account_id TEXT NOT NULL,
                 role TEXT NOT NULL,
                 status TEXT NOT NULL,
                 invited_at_utc INTEGER NOT NULL,
                 accepted_at_utc INTEGER,
                 revoked_at_utc INTEGER,
                 PRIMARY KEY (account_id, member_account_id),
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE,
                 FOREIGN KEY (member_account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS invitations (
                 invitation_id TEXT PRIMARY KEY,
                 account_id TEXT NOT NULL,
                 invitee_account_id TEXT NOT NULL,
                 role TEXT NOT NULL,
                 token_hash_hex TEXT NOT NULL UNIQUE,
                 created_at_utc INTEGER NOT NULL,
                 expires_at_utc INTEGER NOT NULL,
                 accepted_at_utc INTEGER,
                 revoked_at_utc INTEGER,
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE,
                 FOREIGN KEY (invitee_account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS recovery_codes (
                 account_id TEXT NOT NULL,
                 code_hash_hex TEXT PRIMARY KEY,
                 created_at_utc INTEGER NOT NULL,
                 used_at_utc INTEGER,
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS challenges (
                 challenge_id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 account_id TEXT NOT NULL,
                 device_id_hex TEXT,
                 public_key_hex TEXT,
                 nonce_hex TEXT NOT NULL,
                 expires_at_utc INTEGER NOT NULL,
                 used_at_utc INTEGER,
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS sessions (
                 token_hash_hex TEXT PRIMARY KEY,
                 account_id TEXT NOT NULL,
                 device_id_hex TEXT,
                 credential_id_hex TEXT,
                 session_kind TEXT NOT NULL DEFAULT 'device',
                 issued_at_utc INTEGER NOT NULL,
                 expires_at_utc INTEGER NOT NULL,
                 revoked_at_utc INTEGER,
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS session_handoffs (
                 handoff_hash_hex TEXT PRIMARY KEY,
                 account_id TEXT NOT NULL,
                 device_id_hex TEXT,
                 auth_method TEXT NOT NULL,
                 created_at_utc INTEGER NOT NULL,
                 expires_at_utc INTEGER NOT NULL,
                 used_at_utc INTEGER,
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS webauthn_credentials (
                 account_id TEXT NOT NULL,
                 credential_id_hex TEXT NOT NULL,
                 device_id_hex TEXT,
                 algorithm INTEGER NOT NULL,
                 public_key_hex TEXT NOT NULL,
                 sign_count INTEGER NOT NULL DEFAULT 0,
                 created_at_utc INTEGER NOT NULL,
                 last_used_at_utc INTEGER,
                 revoked_at_utc INTEGER,
                 PRIMARY KEY (account_id, credential_id_hex),
                 UNIQUE (credential_id_hex),
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS totp_credentials (
                 account_id TEXT PRIMARY KEY,
                 secret_ciphertext_b64 TEXT NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 0,
                 created_at_utc INTEGER NOT NULL,
                 last_used_step INTEGER,
                 last_used_at_utc INTEGER,
                 revoked_at_utc INTEGER,
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS audit_events (
                 event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 account_id TEXT NOT NULL,
                 event TEXT NOT NULL,
                 details_json TEXT NOT NULL,
                 created_at_utc INTEGER NOT NULL,
                 FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS auth_rate_limits (
                 rate_key TEXT PRIMARY KEY,
                 window_started_at_utc INTEGER NOT NULL,
                 failures INTEGER NOT NULL,
                 blocked_until_utc INTEGER NOT NULL,
                 updated_at_utc INTEGER NOT NULL
             );",
        )?;
        // Older account databases predate device-bound WebAuthn credentials.
        // Add the nullable binding in place so existing installations can
        // migrate without dropping credentials; new registrations require a
        // device-bound session and therefore populate it.
        let has_device_binding: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM pragma_table_info('webauthn_credentials')
                 WHERE name = 'device_id_hex'
             )",
            [],
            |row| row.get(0),
        )?;
        if !has_device_binding {
            connection.execute(
                "ALTER TABLE webauthn_credentials ADD COLUMN device_id_hex TEXT",
                [],
            )?;
        }
        let has_session_credential: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM pragma_table_info('sessions')
                 WHERE name = 'credential_id_hex'
             )",
            [],
            |row| row.get(0),
        )?;
        if !has_session_credential {
            connection.execute("ALTER TABLE sessions ADD COLUMN credential_id_hex TEXT", [])?;
        }
        let has_session_kind: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM pragma_table_info('sessions')
                 WHERE name = 'session_kind'
             )",
            [],
            |row| row.get(0),
        )?;
        if !has_session_kind {
            connection.execute(
                "ALTER TABLE sessions ADD COLUMN session_kind TEXT NOT NULL DEFAULT 'device'",
                [],
            )?;
        }
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_device
             ON webauthn_credentials(account_id, device_id_hex)",
            [],
        )?;
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_credential
             ON sessions(account_id, credential_id_hex)",
            [],
        )?;
        if std::env::var(REQUIRE_TOTP_KEY_ENV)
            .ok()
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            // Production must fail before accepting traffic when its TOTP
            // wrapping key is missing, malformed, or unreadable.
            let _ = totp_wrapping_key()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            db: Arc::new(Mutex::new(connection)),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        })
    }

    pub(crate) fn connection(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Connection>, AccountServiceError> {
        // Recover, don't fail: poison is permanent until recovered, so an
        // error here would wedge every later request. SQLite itself finds
        // no partial transaction (rusqlite rolls back on unwind), and the
        // stderr line keeps the recovery honest.
        match self.db.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                eprintln!("account database lock poisoned; recovering with prior state");
                self.db.clear_poison();
                Ok(poisoned.into_inner())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountView {
    pub account_id: String,
    pub display_name: String,
    pub account_public_key_hex: String,
    pub created_at_utc: u64,
    pub devices: Vec<DeviceView>,
    pub vaults: Vec<VaultLinkView>,
    pub webauthn_credentials: Vec<WebAuthnCredentialView>,
    pub totp_enabled: bool,
    pub totp_last_used_at_utc: Option<u64>,
    pub memberships: Vec<MembershipView>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceView {
    pub device_id_hex: String,
    pub public_key_hex: String,
    pub label: String,
    pub enrolled_at_utc: u64,
    pub last_seen_at_utc: Option<u64>,
    pub revoked_at_utc: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultLinkView {
    pub vault_id_hex: String,
    pub alias: String,
    pub role: String,
    pub linked_at_utc: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    pub display_name: String,
    pub account_public_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceChallengeRequest {
    pub device_id_hex: String,
    pub public_key_hex: String,
    #[serde(default = "default_device_label")]
    pub label: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceEnrollmentRequest {
    pub device_id_hex: String,
    pub public_key_hex: String,
    #[serde(default = "default_device_label")]
    pub label: String,
    pub challenge_id: String,
    pub proof_signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginChallengeRequest {
    pub account_id: String,
    #[serde(default)]
    pub device_id_hex: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionLoginRequest {
    pub challenge_id: String,
    pub signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeView {
    pub challenge_id: String,
    pub nonce_hex: String,
    pub expires_at_utc: u64,
    pub ceremony: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionView {
    pub account_id: String,
    pub device_id_hex: Option<String>,
    #[serde(default = "default_session_kind")]
    pub auth_method: String,
    pub issued_at_utc: u64,
    pub expires_at_utc: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub token: String,
    pub session: SessionView,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionHandoffResponse {
    pub handoff_code: String,
    pub expires_at_utc: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionHandoffConsumeRequest {
    pub handoff_code: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEventView {
    pub event_id: u64,
    pub event: String,
    pub details: serde_json::Value,
    pub created_at_utc: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationVerifyRequest {
    pub challenge_id: String,
    pub credential_id_b64: String,
    pub client_data_json_b64: String,
    pub attestation_object_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationOptionsRequest {
    pub account_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationVerifyRequest {
    pub challenge_id: String,
    pub credential_id_b64: String,
    pub client_data_json_b64: String,
    pub authenticator_data_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebAuthnOptionsView {
    pub challenge_id: String,
    pub challenge: String,
    pub rp_id: String,
    pub user_id_b64: String,
    pub timeout_ms: u64,
    pub ceremony: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebAuthnCredentialView {
    pub credential_id_b64: String,
    pub device_id_hex: Option<String>,
    pub algorithm: i64,
    pub sign_count: u32,
    pub created_at_utc: u64,
    pub last_used_at_utc: Option<u64>,
    pub revoked_at_utc: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TotpEnrollmentView {
    pub account_id: String,
    pub secret_base32: String,
    pub otpauth_uri: String,
    pub issuer: String,
    pub algorithm: String,
    pub digits: u8,
    pub period_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpCodeRequest {
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpAuthenticationOptionsRequest {
    pub account_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpAuthenticationVerifyRequest {
    pub account_id: String,
    pub challenge_id: String,
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TotpAuthenticationOptionsView {
    pub account_id: String,
    pub challenge_id: String,
    pub expires_at_utc: u64,
    pub digits: u8,
    pub period_seconds: u64,
    pub ceremony: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkVaultRequest {
    pub vault_id_hex: String,
    #[serde(default = "default_vault_alias")]
    pub alias: String,
    #[serde(default = "default_vault_role")]
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MembershipView {
    pub account_id: String,
    pub member_account_id: String,
    pub role: String,
    pub status: String,
    pub invited_at_utc: u64,
    pub accepted_at_utc: Option<u64>,
    pub revoked_at_utc: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvitationRequest {
    pub invitee_account_id: String,
    #[serde(default = "default_member_role")]
    pub role: String,
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InvitationView {
    pub invitation_id: String,
    pub account_id: String,
    pub invitee_account_id: String,
    pub role: String,
    pub created_at_utc: u64,
    pub expires_at_utc: u64,
    pub accepted_at_utc: Option<u64>,
    pub revoked_at_utc: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvitationAcceptRequest {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryCodesRequest {
    #[serde(default = "default_recovery_code_count")]
    pub count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryRedeemRequest {
    pub account_id: String,
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationResponse {
    pub revoked: bool,
    pub operator_targets: usize,
    pub operator_revocations: usize,
    pub operator_failures: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub status: &'static str,
    pub code: &'static str,
    pub error: String,
}

pub(crate) fn now_utc() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn default_device_label() -> String {
    "CipherVault device".into()
}

pub(crate) fn default_vault_alias() -> String {
    "Vault".into()
}

pub(crate) fn default_vault_role() -> String {
    "owner".into()
}

pub(crate) fn default_member_role() -> String {
    "viewer".into()
}

pub(crate) fn default_session_kind() -> String {
    "device".into()
}

pub(crate) fn default_recovery_code_count() -> usize {
    8
}
