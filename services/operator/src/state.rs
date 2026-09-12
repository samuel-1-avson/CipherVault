use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::RngCore;

use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::compute_digest;
use ciphervault_storage::types::LeaseReceipt;

pub const MAX_OBJECT_SIZE: usize = 4 * 1024 * 1024; // 4 MiB max per chunk/manifest object
pub const MAX_RECOVERY_RECORD_SIZE: usize = 64 * 1024; // 64 KiB max per recovery record

pub struct OperatorState {
    pub operator_id: String,
    pub signing_key: SigningKey,
    pub data_dir: PathBuf,
    // Active challenges: challenge_id -> (nonce_hex, expires_at_utc)
    pub challenges: Mutex<HashMap<String, (String, u64)>>,
    // Active sessions: token -> expires_at_utc
    pub sessions: Mutex<HashMap<String, u64>>,
}

impl OperatorState {
    pub fn new(operator_id: String, data_dir: PathBuf, signing_key: SigningKey) -> Self {
        fs::create_dir_all(data_dir.join("objects")).unwrap();
        fs::create_dir_all(data_dir.join("recovery")).unwrap();
        fs::create_dir_all(data_dir.join("leases")).unwrap();

        Self {
            operator_id,
            signing_key,
            data_dir,
            challenges: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue_challenge(&self) -> (String, String, u64) {
        let mut id_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let challenge_id = hex::encode(id_bytes);
        let nonce_hex = hex::encode(nonce_bytes);
        let expires_at = Utc::now().timestamp() as u64 + 300; // 5 minutes

        let mut lock = self.challenges.lock().unwrap();
        lock.insert(challenge_id.clone(), (nonce_hex.clone(), expires_at));

        (challenge_id, nonce_hex, expires_at)
    }

    pub fn verify_and_create_session(
        &self,
        challenge_id: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Option<String> {
        let (nonce_hex, expires_at) = {
            let mut lock = self.challenges.lock().unwrap();
            lock.remove(challenge_id)?
        };

        if Utc::now().timestamp() as u64 > expires_at {
            return None;
        }

        let pk_bytes = hex::decode(public_key_hex).ok()?;
        if pk_bytes.len() != 32 {
            return None;
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);

        let sig_bytes = hex::decode(signature_hex).ok()?;
        if sig_bytes.len() != 64 {
            return None;
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        let nonce_bytes = hex::decode(nonce_hex).ok()?;

        // Verify signature with domain separation
        if ciphervault_crypto::signatures::verify_with_domain(
            &pk_arr,
            b"operator_challenge",
            &nonce_bytes,
            &sig_arr,
        ).is_err() {
            return None;
        }

        // Generate session token
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let token_exp = Utc::now().timestamp() as u64 + 3600; // 1 hour

        let mut lock = self.sessions.lock().unwrap();
        lock.insert(token.clone(), token_exp);

        Some(token)
    }

    /// Validates a session token for read-only object operations.
    /// Allows anonymous reads for disaster recovery of end-to-end encrypted ciphertext objects,
    /// or active signed session tokens.
    pub fn validate_read_session(&self, token: &str) -> bool {
        if token == "recovery_anonymous" {
            return true;
        }
        self.validate_write_session(token)
    }

    /// Validates an authenticated, challenge-signed session token for state modifications.
    /// Strictly rejects any anonymous, bypass, or expired tokens.
    pub fn validate_write_session(&self, token: &str) -> bool {
        if token.is_empty() || token == "recovery_anonymous" {
            return false;
        }
        let lock = self.sessions.lock().unwrap();
        if let Some(&expires_at) = lock.get(token) {
            Utc::now().timestamp() as u64 <= expires_at
        } else {
            false
        }
    }

    pub fn validate_session(&self, token: &str) -> bool {
        self.validate_write_session(token)
    }

    pub fn put_object(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_OBJECT_SIZE {
            return Err(format!("Object exceeds maximum size limit of {} bytes", MAX_OBJECT_SIZE));
        }
        if cid_hex.len() != 64 {
            return Err("Invalid CID length (must be 64 hex characters)".into());
        }
        let expected_digest = hex::decode(cid_hex).map_err(|e| e.to_string())?;
        if expected_digest.len() != 32 {
            return Err("Invalid CID digest length".into());
        }
        let actual_digest = compute_digest(bytes);

        if actual_digest.as_slice() != expected_digest.as_slice() {
            return Err("Digest mismatch".into());
        }

        let obj_path = self.data_dir.join("objects").join(cid_hex);
        if !obj_path.exists() {
            fs::write(obj_path, bytes).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn get_object(&self, cid_hex: &str) -> Option<Vec<u8>> {
        if cid_hex.len() != 64 || hex::decode(cid_hex).is_err() {
            return None;
        }
        let obj_path = self.data_dir.join("objects").join(cid_hex);
        fs::read(obj_path).ok()
    }

    pub fn create_lease(
        &self,
        closure_digest_hex: &str,
        bytes: u64,
        term_days: u32,
    ) -> LeaseReceipt {
        let mut lease_id_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut lease_id_bytes);
        let lease_id = hex::encode(lease_id_bytes);

        let now = Utc::now().timestamp() as u64;
        let expires = now + (term_days as u64 * 86400);

        // Sign the lease promise: operator_id || lease_id || closure_digest || expires
        let msg = format!("{}:{}:{}:{}", self.operator_id, lease_id, closure_digest_hex, expires);
        let sig = sign_with_domain(&self.signing_key, b"operator_lease", msg.as_bytes());

        let receipt = LeaseReceipt {
            lease_id: lease_id.clone(),
            operator_id: self.operator_id.clone(),
            closure_digest_hex: closure_digest_hex.to_string(),
            term_days,
            bytes,
            issued_at_utc: now,
            expires_at_utc: expires,
            signature_hex: hex::encode(sig),
        };

        // Persist lease to disk
        let lease_path = self.data_dir.join("leases").join(format!("{}.json", lease_id));
        if let Ok(serialized) = serde_json::to_string_pretty(&receipt) {
            let _ = fs::write(lease_path, serialized);
        }

        receipt
    }

    pub fn renew_lease(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
    ) -> LeaseReceipt {
        let now = Utc::now().timestamp() as u64;
        let expires = now + (additional_days as u64 * 86400);

        let msg = format!("{}:{}:{}:{}", self.operator_id, lease_id, "renewed", expires);
        let sig = sign_with_domain(&self.signing_key, b"operator_lease", msg.as_bytes());

        let receipt = LeaseReceipt {
            lease_id: lease_id.to_string(),
            operator_id: self.operator_id.clone(),
            closure_digest_hex: "renewed".to_string(),
            term_days: additional_days,
            bytes,
            issued_at_utc: now,
            expires_at_utc: expires,
            signature_hex: hex::encode(sig),
        };

        // Persist renewed lease to disk
        let lease_path = self.data_dir.join("leases").join(format!("{}.json", lease_id));
        if let Ok(serialized) = serde_json::to_string_pretty(&receipt) {
            let _ = fs::write(lease_path, serialized);
        }

        receipt
    }

    pub fn append_recovery_record(&self, locator_hex: &str, record: &[u8]) -> Result<u64, String> {
        if locator_hex.len() != 64 || hex::decode(locator_hex).is_err() {
            return Err("Invalid recovery locator (must be 64 hex characters)".into());
        }
        if record.len() > MAX_RECOVERY_RECORD_SIZE {
            return Err(format!(
                "Record exceeds maximum size limit of {} bytes",
                MAX_RECOVERY_RECORD_SIZE
            ));
        }
        let log_path = self.data_dir.join("recovery").join(format!("{}.log", locator_hex));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| e.to_string())?;

        // Format: [4 bytes length prefix in big endian][record bytes]
        let len = (record.len() as u32).to_be_bytes();
        file.write_all(&len).map_err(|e| e.to_string())?;
        file.write_all(record).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;

        Ok(1)
    }

    pub fn get_recovery_records(&self, locator_hex: &str) -> Vec<Vec<u8>> {
        if locator_hex.len() != 64 || hex::decode(locator_hex).is_err() {
            return Vec::new();
        }
        let log_path = self.data_dir.join("recovery").join(format!("{}.log", locator_hex));
        if !log_path.exists() {
            return Vec::new();
        }

        let data = match fs::read(log_path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::new();
        let mut cursor = 0;
        while cursor + 4 <= data.len() {
            let len = u32::from_be_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;
            cursor += 4;
            if cursor + len <= data.len() {
                out.push(data[cursor..cursor + len].to_vec());
                cursor += len;
            } else {
                break;
            }
        }
        out
    }
}
