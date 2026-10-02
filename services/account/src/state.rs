//! Account service state: database, schema, views, and shared helpers.

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

/// Time-to-acquire samples for the single global connection mutex (Step 0 of
/// the production soak plan): acquisition count, cumulative wait, and maximum
/// observed wait. Read via [`db_lock_wait_stats`]; soak analysis compares the
/// average and maximum against arrival rate and audit-history size.
pub(crate) static DB_LOCK_ACQUISITIONS: AtomicU64 = AtomicU64::new(0);
pub(crate) static DB_LOCK_WAIT_MICROS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(crate) static DB_LOCK_WAIT_MICROS_MAX: AtomicU64 = AtomicU64::new(0);
/// Waits at or above this threshold also log one stderr line each, keeping
/// contention visible in canary logs without a metrics pipeline.
pub(crate) const DB_LOCK_WAIT_LOG_THRESHOLD_MICROS: u64 = 10_000;

/// (acquisitions, total wait micros, max wait micros) since process start.
pub fn db_lock_wait_stats() -> (u64, u64, u64) {
    (
        DB_LOCK_ACQUISITIONS.load(Ordering::Relaxed),
        DB_LOCK_WAIT_MICROS_TOTAL.load(Ordering::Relaxed),
        DB_LOCK_WAIT_MICROS_MAX.load(Ordering::Relaxed),
    )
}

fn record_db_lock_wait(elapsed: std::time::Duration) {
    let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
    DB_LOCK_ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
    DB_LOCK_WAIT_MICROS_TOTAL.fetch_add(micros, Ordering::Relaxed);
    DB_LOCK_WAIT_MICROS_MAX.fetch_max(micros, Ordering::Relaxed);
    if micros >= DB_LOCK_WAIT_LOG_THRESHOLD_MICROS {
        eprintln!("account database lock wait {micros}us exceeds threshold; contention rising");
    }
}

fn lock_database_files(data_dir: &Path) -> Result<PathBuf, AccountServiceError> {
    let database =
        crate::disaster_recovery::checked_database_path(&data_dir.join("accounts.sqlite3"))?;
    for suffix in crate::disaster_recovery::DATABASE_FILE_SUFFIXES {
        let path = data_dir.join(format!("accounts.sqlite3{suffix}"));
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                crate::disaster_recovery::checked_regular_database_path(&path)?;
                ciphervault_file_lock::lock_secret_file(&path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(database)
}

impl AccountState {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self, AccountServiceError> {
        let data_dir = data_dir.into();
        fs::create_dir_all(&data_dir)?;
        crate::disaster_recovery::checked_existing(&data_dir)?;
        ciphervault_file_lock::lock_secret_directory(&data_dir)?;
        let db_path = data_dir.join("accounts.sqlite3");
        match ciphervault_file_lock::create_secret_file(&db_path) {
            Ok(file) => file.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                crate::disaster_recovery::checked_regular_database_path(&db_path)?;
                ciphervault_file_lock::lock_secret_file(&db_path)?;
            }
            Err(error) => return Err(error.into()),
        }
        // Reject unsafe existing sidecars before SQLite touches them. Closing
        // any raw descriptor for a live SQLite inode releases its POSIX locks,
        // even when SQLite owns another descriptor in this process. Metadata
        // checks and path-based permission changes preserve those locks.
        let db_path = lock_database_files(&data_dir)?;
        let connection = Connection::open_with_flags(
            &db_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
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
                 origin_session_hash TEXT,
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
             );
             CREATE TABLE IF NOT EXISTS abuse_quotas (
                 quota_key TEXT PRIMARY KEY,
                 window_started_at_utc INTEGER NOT NULL,
                 count INTEGER NOT NULL,
                 updated_at_utc INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS dpop_proofs (
                 proof_hash_hex TEXT PRIMARY KEY,
                 expires_at_utc INTEGER NOT NULL
             );",
        )?;
        crate::scoped::init_scoped_schema(&connection)?;
        crate::migration_ledger::init_migration_schema(&connection)?;
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
        let has_handoff_origin: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('session_handoffs') WHERE name = 'origin_session_hash')",
            [], |row| row.get(0),
        )?;
        if !has_handoff_origin {
            connection.execute(
                "ALTER TABLE session_handoffs ADD COLUMN origin_session_hash TEXT",
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
        // The owner-only parent protects future sidecars too; tighten current
        // WAL/SHM files before traffic so old deployments migrate safely.
        lock_database_files(&data_dir)?;
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
        let started = Instant::now();
        let guard = self.db.lock();
        record_db_lock_wait(started.elapsed());
        match guard {
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
    #[serde(default)]
    pub mfa_required: bool,
    #[serde(default)]
    pub mfa_verified_at_utc: Option<u64>,
    /// Internal binding for scope claims; never accepted from a client view.
    #[serde(skip)]
    pub(crate) mfa_proof_id: Option<String>,
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

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use rusqlite::OpenFlags;

    use super::*;

    const CHILD_MODE: &str = "CV_ACCOUNT_WAL_TEST_CHILD_MODE";
    const CHILD_DATABASE: &str = "CV_ACCOUNT_WAL_TEST_CHILD_DATABASE";
    const TEST_NAME: &str = "state::tests::wal_visibility_survives_database_path_validation";

    fn insert_marker(db: &Connection, marker: &str, public_key: &str) {
        db.execute(
            "INSERT INTO accounts VALUES(?1, 'WAL visibility regression', ?2, 1)",
            [marker, public_key],
        )
        .unwrap();
    }

    fn run_child(database: &Path, mode: &str) {
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_MODE, mode)
            .env(CHILD_DATABASE, database)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "independent SQLite {mode} failed:\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
        );
    }

    #[test]
    fn wal_visibility_survives_database_path_validation() {
        if let Ok(mode) = std::env::var(CHILD_MODE) {
            let database = std::env::var_os(CHILD_DATABASE).unwrap();
            match mode.as_str() {
                "writer" => {
                    // A different process closing its last SQLite connection
                    // must not remove the live account service's WAL.
                    let db = Connection::open(database).unwrap();
                    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                    insert_marker(&db, "child", &"22".repeat(32));
                    drop(db);
                }
                "reader" => {
                    let db =
                        Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
                            .unwrap();
                    let rows: u64 = db
                        .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))
                        .unwrap();
                    assert_eq!(
                        rows, 3,
                        "committed rows must be visible before checkpointing"
                    );
                    let after: u64 = db
                        .query_row(
                            "SELECT COUNT(*) FROM accounts WHERE account_id = 'after'",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert_eq!(after, 1);
                }
                _ => panic!("unexpected child mode"),
            }
            return;
        }

        for operation in ["startup", "reopen", "backup"] {
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "cv-account-wal-{operation}-{}",
                crate::util::random_hex(8)
            ));
            let data_dir = root.join("source");
            let state = AccountState::open(&data_dir).unwrap();
            {
                let db = state.connection().unwrap();
                // Keep committed rows in the WAL until the independent reader
                // checks visibility; a checkpoint would hide this regression.
                db.execute_batch("PRAGMA wal_autocheckpoint=0").unwrap();
                insert_marker(&db, "before", &"11".repeat(32));
            }
            let second_state = match operation {
                "reopen" => Some(AccountState::open(&data_dir).unwrap()),
                "backup" => {
                    let receipt =
                        crate::disaster_recovery::backup_accounts(&data_dir, &root.join("backup"))
                            .unwrap();
                    assert_eq!(receipt.table_rows["accounts"], 1);
                    None
                }
                _ => None,
            };
            let database = data_dir.join("accounts.sqlite3");
            run_child(&database, "writer");
            {
                let db = state.connection().unwrap();
                insert_marker(&db, "after", &"33".repeat(32));
                let rows: u64 = db
                    .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(rows, 3);
            }
            run_child(&database, "reader");
            drop(second_state);
            drop(state);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn unsafe_database_paths_are_rejected_before_sqlite_opens() {
        use std::os::unix::fs::symlink;

        for suffix in crate::disaster_recovery::DATABASE_FILE_SUFFIXES {
            for kind in ["symlink", "dangling-symlink", "directory"] {
                let root = std::env::temp_dir()
                    .canonicalize()
                    .unwrap()
                    .join(format!("cv-account-path-{}", crate::util::random_hex(8)));
                let data_dir = root.join("source");
                fs::create_dir_all(&data_dir).unwrap();
                let path = data_dir.join(format!("accounts.sqlite3{suffix}"));
                let target = root.join("external-file");
                match kind {
                    "symlink" => {
                        fs::write(&target, b"must remain untouched").unwrap();
                        symlink(&target, &path).unwrap();
                    }
                    "dangling-symlink" => symlink(&target, &path).unwrap(),
                    "directory" => fs::create_dir(&path).unwrap(),
                    _ => unreachable!(),
                }
                assert!(
                    matches!(
                        AccountState::open(&data_dir),
                        Err(AccountServiceError::Invalid(_))
                    ),
                    "unsafe SQLite path {suffix:?} ({kind}) must be rejected before opening",
                );
                if kind == "symlink" {
                    assert_eq!(fs::read(&target).unwrap(), b"must remain untouched");
                } else {
                    assert!(!target.exists());
                }
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validated_system_alias_supports_sqlite_nofollow() {
        // checked_existing permits Darwin's immutable /tmp -> /private/tmp
        // alias. SQLite NOFOLLOW also checks ancestors, so its input must be
        // canonicalized after validation rather than rejecting this layout.
        let root = Path::new("/tmp").join(format!(
            "cv-account-system-alias-{}",
            crate::util::random_hex(8)
        ));
        let state = AccountState::open(&root).unwrap();
        let receipt =
            crate::disaster_recovery::backup_accounts(&root, &root.join("backup")).unwrap();
        assert_eq!(receipt.table_rows["accounts"], 0);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }
}
