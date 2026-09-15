//! Local-first CipherVault account and device registry.
//!
//! An account is a control-plane identity.  It contains no vault plaintext and
//! never replaces the vault's recovery authority.  The account signing key is
//! protected by the same host key facility used for vault device keys.

use crate::keyring::{protect_secret, unprotect_secret};
use ciphervault_crypto::signatures::sign_with_domain;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ACCOUNT_SCHEMA_VERSION: u32 = 1;
const ACCOUNT_FILE: &str = "account.json";
const ACCOUNT_KEY_FILE: &str = "account.key";
const ACCOUNT_SESSION_FILE: &str = "session.json";
const ACCOUNT_SESSION_TTL_SECONDS: u64 = 30 * 60;

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("account file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("account file is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("account key protection failed: {0}")]
    KeyProtection(String),
    #[error("no CipherVault account exists; run `ciphervault auth init` first")]
    NotInitialized,
    #[error("invalid account data: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountDevice {
    pub device_id_hex: String,
    pub public_key_hex: String,
    pub label: String,
    pub enrolled_at_utc: u64,
    #[serde(default)]
    pub last_seen_at_utc: Option<u64>,
    #[serde(default)]
    pub revoked_at_utc: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountVault {
    pub vault_id_hex: String,
    pub alias: String,
    pub role: String,
    pub linked_at_utc: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRecord {
    pub schema_version: u32,
    pub account_id: String,
    pub display_name: String,
    pub account_public_key_hex: String,
    pub created_at_utc: u64,
    #[serde(default)]
    pub devices: Vec<AccountDevice>,
    #[serde(default)]
    pub vaults: Vec<AccountVault>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedSession {
    account_id: String,
    device_id_hex: Option<String>,
    issued_at_utc: u64,
    expires_at_utc: u64,
    token_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSessionStatus {
    pub authenticated: bool,
    pub account_id: String,
    pub device_id_hex: Option<String>,
    pub expires_at_utc: Option<u64>,
}

/// A local account registry.  The JSON metadata is portable; the signing key
/// is deliberately kept in a separate OS-protected file.
pub struct AccountStore {
    path: PathBuf,
    key_path: PathBuf,
    session_path: PathBuf,
    record: AccountRecord,
}

fn now_utc() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    hex::decode(value)
        .map(|decoded| decoded.len() == bytes)
        .unwrap_or(false)
}

fn account_dir_from_env() -> Option<PathBuf> {
    std::env::var_os("CIPHERVAULT_ACCOUNT_DIR").map(PathBuf::from)
}

impl AccountStore {
    /// Resolves the account metadata path without creating it.
    pub fn default_path() -> PathBuf {
        if let Ok(path) = std::env::var("CIPHERVAULT_ACCOUNT_PATH") {
            return PathBuf::from(path);
        }
        if let Some(dir) = account_dir_from_env() {
            return dir.join(ACCOUNT_FILE);
        }
        #[cfg(windows)]
        {
            if let Some(app_data) = std::env::var_os("APPDATA") {
                return PathBuf::from(app_data)
                    .join("CipherVault")
                    .join(ACCOUNT_FILE);
            }
        }
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("ciphervault").join(ACCOUNT_FILE);
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".config")
                .join("ciphervault")
                .join(ACCOUNT_FILE);
        }
        PathBuf::from(ACCOUNT_FILE)
    }

    fn paths(path: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        (
            path.to_path_buf(),
            dir.join(ACCOUNT_KEY_FILE),
            dir.join(ACCOUNT_SESSION_FILE),
        )
    }

    pub fn create(display_name: Option<&str>, path: Option<PathBuf>) -> Result<Self, AccountError> {
        let path = path.unwrap_or_else(Self::default_path);
        if path.exists() {
            return Err(AccountError::Invalid(format!(
                "account already exists at {}",
                path.display()
            )));
        }
        let (path, key_path, session_path) = Self::paths(&path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let digest = Sha256::digest(signing_key.verifying_key().as_bytes());
        let account_id = format!("cvacct_{}", hex::encode(&digest[..16]));
        let record = AccountRecord {
            schema_version: ACCOUNT_SCHEMA_VERSION,
            account_id,
            display_name: display_name
                .unwrap_or("CipherVault user")
                .trim()
                .chars()
                .take(120)
                .collect(),
            account_public_key_hex: public_key_hex,
            created_at_utc: now_utc(),
            devices: Vec::new(),
            vaults: Vec::new(),
        };
        let protected = protect_secret(&signing_key.to_bytes())
            .map_err(|e| AccountError::KeyProtection(e.to_string()))?;
        write_atomic(&key_path, &protected, true)?;
        let store = Self {
            path,
            key_path,
            session_path,
            record,
        };
        store.persist_record()?;
        Ok(store)
    }

    pub fn open(path: Option<PathBuf>) -> Result<Self, AccountError> {
        let path = path.unwrap_or_else(Self::default_path);
        if !path.exists() {
            return Err(AccountError::NotInitialized);
        }
        let (path, key_path, session_path) = Self::paths(&path);
        let record: AccountRecord = serde_json::from_slice(&fs::read(&path)?)?;
        if record.schema_version != ACCOUNT_SCHEMA_VERSION
            || !valid_hex(&record.account_public_key_hex, 32)
        {
            return Err(AccountError::Invalid("unsupported account metadata".into()));
        }
        let public_key = hex::decode(&record.account_public_key_hex)
            .map_err(|_| AccountError::Invalid("account public key is not valid hex".into()))?;
        let expected_id = format!("cvacct_{}", hex::encode(&Sha256::digest(&public_key)[..16]));
        if record.account_id != expected_id {
            return Err(AccountError::Invalid(
                "account ID does not match account public key".into(),
            ));
        }
        Ok(Self {
            path,
            key_path,
            session_path,
            record,
        })
    }

    fn persist_record(&self) -> Result<(), AccountError> {
        let encoded = serde_json::to_vec_pretty(&self.record)?;
        write_atomic(&self.path, &encoded, false)
    }

    pub fn record(&self) -> &AccountRecord {
        &self.record
    }

    pub fn account_id(&self) -> &str {
        &self.record.account_id
    }

    pub fn public_key_hex(&self) -> &str {
        &self.record.account_public_key_hex
    }

    /// Signs a hosted login or device-enrollment challenge with the account
    /// key after the host key facility has authorized its use. Callers should
    /// use a protocol-specific domain string; vault content is never signed
    /// by this key.
    pub fn sign_challenge(&self, domain: &[u8], message: &[u8]) -> Result<[u8; 64], AccountError> {
        let signing_key = self.unlock_signing_key()?;
        Ok(sign_with_domain(&signing_key, domain, message))
    }

    /// Unlocks and verifies the OS-protected account signing key.
    pub fn unlock_signing_key(&self) -> Result<SigningKey, AccountError> {
        let protected = fs::read(&self.key_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AccountError::Invalid("account signing key is missing".into())
            } else {
                AccountError::Io(error)
            }
        })?;
        let raw =
            unprotect_secret(&protected).map_err(|e| AccountError::KeyProtection(e.to_string()))?;
        if raw.len() != 32 {
            return Err(AccountError::Invalid(
                "account signing key has invalid length".into(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        let signing_key = SigningKey::from_bytes(&bytes);
        if hex::encode(signing_key.verifying_key().as_bytes()) != self.record.account_public_key_hex
        {
            return Err(AccountError::Invalid(
                "account signing key does not match account metadata".into(),
            ));
        }
        Ok(signing_key)
    }

    pub fn register_device(
        &mut self,
        device_id_hex: &str,
        public_key_hex: &str,
        label: &str,
    ) -> Result<(), AccountError> {
        if !valid_hex(device_id_hex, 32) || !valid_hex(public_key_hex, 32) {
            return Err(AccountError::Invalid(
                "device_id_hex and public_key_hex must be 32-byte hex".into(),
            ));
        }
        let now = now_utc();
        if let Some(device) = self.record.devices.iter_mut().find(|device| {
            device.device_id_hex.eq_ignore_ascii_case(device_id_hex)
                && device.public_key_hex.eq_ignore_ascii_case(public_key_hex)
        }) {
            device.label = label.trim().chars().take(120).collect();
            device.last_seen_at_utc = Some(now);
            device.revoked_at_utc = None;
        } else {
            self.record.devices.push(AccountDevice {
                device_id_hex: device_id_hex.to_ascii_lowercase(),
                public_key_hex: public_key_hex.to_ascii_lowercase(),
                label: label.trim().chars().take(120).collect(),
                enrolled_at_utc: now,
                last_seen_at_utc: Some(now),
                revoked_at_utc: None,
            });
        }
        self.persist_record()
    }

    pub fn revoke_device(&mut self, device_id_hex: &str) -> Result<bool, AccountError> {
        let now = now_utc();
        let mut changed = false;
        for device in self
            .record
            .devices
            .iter_mut()
            .filter(|device| device.device_id_hex.eq_ignore_ascii_case(device_id_hex))
        {
            if device.revoked_at_utc.is_none() {
                device.revoked_at_utc = Some(now);
                changed = true;
            }
        }
        if changed {
            self.persist_record()?;
            self.logout_for_device(device_id_hex)?;
        }
        Ok(changed)
    }

    pub fn link_vault(
        &mut self,
        vault_id_hex: &str,
        alias: &str,
        role: &str,
    ) -> Result<(), AccountError> {
        if !valid_hex(vault_id_hex, 32) {
            return Err(AccountError::Invalid(
                "vault_id_hex must be 32-byte hex".into(),
            ));
        }
        let vault_id_hex = vault_id_hex.to_ascii_lowercase();
        if let Some(vault) = self
            .record
            .vaults
            .iter_mut()
            .find(|vault| vault.vault_id_hex == vault_id_hex)
        {
            vault.alias = alias.trim().chars().take(120).collect();
            vault.role = role.trim().chars().take(40).collect();
        } else {
            self.record.vaults.push(AccountVault {
                vault_id_hex,
                alias: alias.trim().chars().take(120).collect(),
                role: role.trim().chars().take(40).collect(),
                linked_at_utc: now_utc(),
            });
        }
        self.persist_record()
    }

    pub fn unlink_vault(&mut self, vault_id_hex: &str) -> Result<bool, AccountError> {
        let before = self.record.vaults.len();
        self.record
            .vaults
            .retain(|vault| !vault.vault_id_hex.eq_ignore_ascii_case(vault_id_hex));
        if self.record.vaults.len() != before {
            self.persist_record()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn is_vault_linked(&self, vault_id_hex: &str) -> bool {
        self.record
            .vaults
            .iter()
            .any(|vault| vault.vault_id_hex.eq_ignore_ascii_case(vault_id_hex))
    }

    pub fn is_device_active(&self, device_id_hex: &str, public_key_hex: &str) -> bool {
        self.record.devices.iter().any(|device| {
            device.revoked_at_utc.is_none()
                && device.device_id_hex.eq_ignore_ascii_case(device_id_hex)
                && device.public_key_hex.eq_ignore_ascii_case(public_key_hex)
        })
    }

    /// Creates a short-lived local account session after unlocking the key.
    /// A hosted identity provider can later exchange the same device-bound key
    /// for a remote session without changing the vault cryptographic root.
    pub fn login(&self, device_id_hex: Option<&str>) -> Result<AccountSessionStatus, AccountError> {
        let _ = self.unlock_signing_key()?;
        if let Some(device_id) = device_id_hex {
            if !self.record.devices.iter().any(|device| {
                device.device_id_hex.eq_ignore_ascii_case(device_id)
                    && device.revoked_at_utc.is_none()
            }) {
                return Err(AccountError::Invalid(
                    "device is not enrolled in this account".into(),
                ));
            }
        }
        let now = now_utc();
        let mut token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        let token_hash_hex = hex::encode(Sha256::digest(token));
        let session = PersistedSession {
            account_id: self.record.account_id.clone(),
            device_id_hex: device_id_hex.map(str::to_ascii_lowercase),
            issued_at_utc: now,
            expires_at_utc: now + ACCOUNT_SESSION_TTL_SECONDS,
            token_hash_hex,
        };
        write_atomic(&self.session_path, &serde_json::to_vec(&session)?, true)?;
        Ok(AccountSessionStatus {
            authenticated: true,
            account_id: self.record.account_id.clone(),
            device_id_hex: session.device_id_hex,
            expires_at_utc: Some(session.expires_at_utc),
        })
    }

    pub fn logout(&self) -> Result<(), AccountError> {
        if self.session_path.exists() {
            fs::remove_file(&self.session_path)?;
        }
        Ok(())
    }

    fn logout_for_device(&self, device_id_hex: &str) -> Result<(), AccountError> {
        if let Ok(bytes) = fs::read(&self.session_path) {
            if let Ok(session) = serde_json::from_slice::<PersistedSession>(&bytes) {
                if session
                    .device_id_hex
                    .as_deref()
                    .is_some_and(|value| value.eq_ignore_ascii_case(device_id_hex))
                {
                    let _ = fs::remove_file(&self.session_path);
                }
            }
        }
        Ok(())
    }

    pub fn session_status(&self) -> AccountSessionStatus {
        let Ok(bytes) = fs::read(&self.session_path) else {
            return AccountSessionStatus {
                authenticated: false,
                account_id: self.record.account_id.clone(),
                device_id_hex: None,
                expires_at_utc: None,
            };
        };
        let Ok(session) = serde_json::from_slice::<PersistedSession>(&bytes) else {
            return AccountSessionStatus {
                authenticated: false,
                account_id: self.record.account_id.clone(),
                device_id_hex: None,
                expires_at_utc: None,
            };
        };
        let active = session.account_id == self.record.account_id
            && session.expires_at_utc > now_utc()
            && session.device_id_hex.as_deref().is_none_or(|device_id| {
                self.record.devices.iter().any(|device| {
                    device.device_id_hex.eq_ignore_ascii_case(device_id)
                        && device.revoked_at_utc.is_none()
                })
            });
        if !active {
            let _ = fs::remove_file(&self.session_path);
        }
        AccountSessionStatus {
            authenticated: active,
            account_id: self.record.account_id.clone(),
            device_id_hex: active.then_some(session.device_id_hex).flatten(),
            expires_at_utc: active.then_some(session.expires_at_utc),
        }
    }

    /// Returns true only when the account, vault link, device enrollment, and
    /// local account session all agree on the same device-bound identity.
    pub fn is_authenticated_for_device(
        &self,
        vault_id_hex: &str,
        device_id_hex: &str,
        public_key_hex: &str,
    ) -> bool {
        self.is_vault_linked(vault_id_hex)
            && self.is_device_active(device_id_hex, public_key_hex)
            && self.session_status().authenticated
            && self
                .session_status()
                .device_id_hex
                .is_some_and(|session_device| session_device.eq_ignore_ascii_case(device_id_hex))
    }
}

fn write_atomic(path: &Path, bytes: &[u8], restrictive: bool) -> Result<(), AccountError> {
    #[cfg(not(unix))]
    let _ = restrictive;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("account"),
        std::process::id()
    ));
    fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    if restrictive {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if restrictive {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_lifecycle_is_device_and_vault_scoped() {
        let root = std::env::temp_dir().join(format!("cv-account-{}", rand::random::<u128>()));
        let path = root.join("account.json");
        let mut account = match AccountStore::create(Some("Alice"), Some(path.clone())) {
            Ok(account) => account,
            Err(AccountError::KeyProtection(_)) => {
                let _ = fs::remove_dir_all(&root);
                return;
            }
            Err(error) => panic!("account creation failed: {error}"),
        };
        let device_id = "11".repeat(32);
        let device_pk = "22".repeat(32);
        let vault_id = "33".repeat(32);
        account
            .register_device(&device_id, &device_pk, "laptop")
            .unwrap();
        account
            .link_vault(&vault_id, "production", "owner")
            .unwrap();
        assert!(!account.is_authenticated_for_device(&vault_id, &device_id, &device_pk));
        account.login(Some(&device_id)).unwrap();
        assert!(account.is_authenticated_for_device(&vault_id, &device_id, &device_pk));
        assert!(account.revoke_device(&device_id).unwrap());
        assert!(!account.session_status().authenticated);
        let _ = fs::remove_dir_all(root);
    }
}
