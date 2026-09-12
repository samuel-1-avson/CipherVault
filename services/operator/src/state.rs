use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::{
    compute_digest, from_canonical_cbor, DeviceCertificate, EpochEnvelope, GenesisRecord,
    HeadRecord, SnapshotRecord, PROTOCOL_VERSION,
};
use ciphervault_storage::types::LeaseReceipt;

pub const MAX_OBJECT_SIZE: usize = 4 * 1024 * 1024; // 4 MiB max per chunk/manifest object
pub const MAX_RECOVERY_RECORD_SIZE: usize = 64 * 1024; // 64 KiB max per recovery record
pub const MAX_ACTIVE_CHALLENGES: usize = 5_000;
pub const MAX_ACTIVE_SESSIONS: usize = 5_000;
pub const MAX_RECORDS_PER_LOCATOR: usize = 10_000;
pub const MAX_RELAYED_CHECKPOINTS: usize = 5_000;

pub struct OperatorState {
    pub operator_id: String,
    pub signing_key: SigningKey,
    pub data_dir: PathBuf,
    io_lock: Mutex<()>,
    // Active challenges: challenge_id -> (nonce_hex, expires_at_utc)
    pub challenges: Mutex<HashMap<String, (String, u64)>>,
    // Active sessions: token -> expires_at_utc
    pub sessions: Mutex<HashMap<String, u64>>,
    // Authenticated caller public key: token -> public_key
    pub session_keys: Mutex<HashMap<String, [u8; 32]>>,
    // Relayed L2 checkpoints: commitment_hex -> RelayerReceipt
    pub relayed_checkpoints: Mutex<HashMap<String, ciphervault_storage::RelayerReceipt>>,
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
            io_lock: Mutex::new(()),
            challenges: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            session_keys: Mutex::new(HashMap::new()),
            relayed_checkpoints: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue_challenge(&self) -> (String, String, u64) {
        let mut id_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let challenge_id = hex::encode(id_bytes);
        let nonce_hex = hex::encode(nonce_bytes);
        let now = Utc::now().timestamp() as u64;
        let expires_at = now + 300; // 5 minutes

        let mut lock = self.challenges.lock().unwrap();
        // TTL eviction: remove expired challenges
        lock.retain(|_, (_, exp)| *exp > now);
        // Quota bound: if at capacity, evict oldest
        if lock.len() >= MAX_ACTIVE_CHALLENGES {
            if let Some(oldest_key) = lock
                .iter()
                .min_by_key(|(_, (_, exp))| *exp)
                .map(|(k, _)| k.clone())
            {
                lock.remove(&oldest_key);
            }
        }
        lock.insert(challenge_id.clone(), (nonce_hex.clone(), expires_at));

        (challenge_id, nonce_hex, expires_at)
    }

    pub fn verify_and_create_session(
        &self,
        challenge_id: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Option<String> {
        let now = Utc::now().timestamp() as u64;
        let (nonce_hex, expires_at) = {
            let mut lock = self.challenges.lock().unwrap();
            lock.remove(challenge_id)?
        };

        if now > expires_at {
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
        )
        .is_err()
        {
            return None;
        }

        // Generate session token
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let token_exp = now + 3600; // 1 hour

        let mut lock = self.sessions.lock().unwrap();
        // TTL eviction: remove expired sessions
        lock.retain(|_, exp| *exp > now);
        if lock.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest_token) = lock
                .iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                lock.remove(&oldest_token);
                self.session_keys.lock().unwrap().remove(&oldest_token);
            }
        }
        lock.insert(token.clone(), token_exp);

        let mut key_lock = self.session_keys.lock().unwrap();
        key_lock.insert(token.clone(), pk_arr);

        Some(token)
    }

    pub fn get_session_public_key(&self, token: &str) -> Option<[u8; 32]> {
        let lock = self.session_keys.lock().unwrap();
        lock.get(token).copied()
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
            return Err(format!(
                "Object exceeds maximum size limit of {} bytes",
                MAX_OBJECT_SIZE
            ));
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

        let _guard = self.io_lock.lock().map_err(|e| e.to_string())?;
        let obj_path = self.data_dir.join("objects").join(cid_hex);
        if fs::read(&obj_path).ok().as_deref() != Some(bytes) {
            self.persist_atomic(&obj_path, bytes)?;
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

    /// Computes and signs a cryptographic Proof-of-Storage receipt for a challenged object.
    pub fn generate_pos_proof(
        &self,
        cid_hex: &str,
        nonce: &[u8; 32],
    ) -> Result<ciphervault_storage::ProofOfStorageReceipt, String> {
        if cid_hex.len() != 64 {
            return Err("Invalid CID length (must be 64 hex characters)".into());
        }
        let cid_bytes = hex::decode(cid_hex).map_err(|e| e.to_string())?;
        if cid_bytes.len() != 32 {
            return Err("Invalid CID digest length".into());
        }
        let mut cid_arr = [0u8; 32];
        cid_arr.copy_from_slice(&cid_bytes);

        let obj_path = self.data_dir.join("objects").join(cid_hex);
        let bytes = fs::read(&obj_path).map_err(|_| "Object not found".to_string())?;

        let proof = ciphervault_storage::compute_pos_proof(&cid_arr, nonce, &bytes);

        let mut receipt = ciphervault_storage::ProofOfStorageReceipt {
            operator_id: self.operator_id.clone(),
            cid_hex: cid_hex.to_lowercase(),
            nonce_hex: hex::encode(nonce),
            proof_hex: hex::encode(proof),
            signature_hex: String::new(),
            size_bytes: bytes.len() as u64,
        };

        let msg = receipt.signing_bytes();
        let sig = ciphervault_crypto::signatures::sign_with_domain(
            &self.signing_key,
            b"operator_pos",
            &msg,
        );
        receipt.signature_hex = hex::encode(sig);

        Ok(receipt)
    }

    fn persist_atomic(&self, path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
        let temp = path.with_extension(format!("{}.tmp", rand::random::<u128>()));
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, path)?;
            #[cfg(unix)]
            std::fs::File::open(path.parent().unwrap())?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(|e| e.to_string())
    }

    fn persist_lease(&self, mut receipt: LeaseReceipt) -> Result<LeaseReceipt, String> {
        receipt.signature_hex = hex::encode(sign_with_domain(
            &self.signing_key,
            b"operator_lease",
            &receipt.signing_bytes(),
        ));
        let path = self
            .data_dir
            .join("leases")
            .join(format!("{}.json", receipt.lease_id));
        let serialized = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        self.persist_atomic(&path, &serialized)?;
        Ok(receipt)
    }

    pub fn create_lease(
        &self,
        closure_digest_hex: &str,
        bytes: u64,
        term_days: u32,
    ) -> Result<LeaseReceipt, String> {
        if closure_digest_hex.len() != 64
            || hex::decode(closure_digest_hex).is_err()
            || term_days == 0
        {
            return Err("Invalid closure digest or retention term".into());
        }
        let _guard = self.io_lock.lock().map_err(|e| e.to_string())?;
        let now = Utc::now().timestamp() as u64;
        self.persist_lease(LeaseReceipt {
            lease_id: hex::encode(rand::random::<[u8; 16]>()),
            operator_id: self.operator_id.clone(),
            closure_digest_hex: closure_digest_hex.into(),
            term_days,
            bytes,
            issued_at_utc: now,
            expires_at_utc: now + u64::from(term_days) * 86400,
            signature_hex: String::new(),
        })
    }

    pub fn renew_lease(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
    ) -> Result<LeaseReceipt, String> {
        if lease_id.len() != 32 || hex::decode(lease_id).is_err() || additional_days == 0 {
            return Err("Invalid lease ID or retention term".into());
        }
        let _guard = self.io_lock.lock().map_err(|e| e.to_string())?;
        let path = self
            .data_dir
            .join("leases")
            .join(format!("{}.json", lease_id));
        let mut receipt: LeaseReceipt =
            serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        receipt
            .verify(&self.signing_key.verifying_key().to_bytes())
            .map_err(|e| e.to_string())?;
        if receipt.bytes != bytes {
            return Err("Lease byte count mismatch".into());
        }
        receipt.term_days = receipt
            .term_days
            .checked_add(additional_days)
            .ok_or("Retention overflow")?;
        receipt.expires_at_utc = receipt
            .expires_at_utc
            .max(Utc::now().timestamp() as u64)
            .checked_add(u64::from(additional_days) * 86400)
            .ok_or("Expiry overflow")?;
        self.persist_lease(receipt)
    }

    pub fn append_authorized_recovery_record(
        &self,
        locator_hex: &str,
        record: &[u8],
        caller_pk: Option<&[u8; 32]>,
    ) -> Result<u64, String> {
        if locator_hex.len() != 64 || hex::decode(locator_hex).is_err() {
            return Err("Invalid recovery locator (must be 64 hex characters)".into());
        }
        if record.len() > MAX_RECOVERY_RECORD_SIZE {
            return Err(format!(
                "Record exceeds maximum size limit of {} bytes",
                MAX_RECOVERY_RECORD_SIZE
            ));
        }

        // Cryptographic Authorization Check
        // Inspect existing records to find registered recovery_signing_pk and authorized device public keys.
        let existing = self.get_recovery_records(locator_hex);
        if existing.len() >= MAX_RECORDS_PER_LOCATOR {
            return Err(format!(
                "Locator recovery log capacity limit of {} records exceeded",
                MAX_RECORDS_PER_LOCATOR
            ));
        }

        let mut registered_recovery_pk: Option<[u8; 32]> = None;
        let mut authorized_device_pks: Vec<[u8; 32]> = Vec::new();

        for r in &existing {
            if let Ok(genesis) = from_canonical_cbor::<GenesisRecord>(r) {
                if genesis.verify().is_ok() && genesis.recovery_signing_pk.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&genesis.recovery_signing_pk);
                    registered_recovery_pk = Some(pk);
                }
            }
        }

        for r in &existing {
            if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(r) {
                if let Some(r_pk) = registered_recovery_pk {
                    if cert.verify(&r_pk).is_ok() && cert.device_signing_pk.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&cert.device_signing_pk);
                        if !authorized_device_pks.contains(&pk) {
                            authorized_device_pks.push(pk);
                        }
                    }
                }
            }
        }

        // Verify incoming record against authority
        let mut is_authorized = false;

        // 1. GenesisRecord: Must be signed by recovery authority. If one already registered, must match it.
        if let Ok(genesis) = from_canonical_cbor::<GenesisRecord>(record) {
            if genesis.version == PROTOCOL_VERSION
                && genesis.verify().is_ok()
                && genesis.recovery_signing_pk.len() == 32
            {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&genesis.recovery_signing_pk);
                if let Some(existing_pk) = registered_recovery_pk {
                    if existing_pk == pk {
                        is_authorized = true;
                    }
                } else {
                    is_authorized = true;
                }
            }
        }

        // 2. DeviceCertificate: Must be signed by registered recovery authority (r_pk)
        if !is_authorized {
            if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(record) {
                if cert.version == PROTOCOL_VERSION && cert.device_signing_pk.len() == 32 {
                    if let Some(r_pk) = registered_recovery_pk {
                        if cert.verify(&r_pk).is_ok() {
                            is_authorized = true;
                        }
                    }
                }
            }
        }

        // 3. HeadRecord: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(head) = from_canonical_cbor::<HeadRecord>(record) {
                if head.version == PROTOCOL_VERSION && head.snapshot_id.len() == 32 {
                    for d_pk in &authorized_device_pks {
                        if head.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if head.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        // 4. EpochEnvelope: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(envelope) = from_canonical_cbor::<EpochEnvelope>(record) {
                if envelope.version == PROTOCOL_VERSION
                    && envelope.recipient_fingerprint.len() == 32
                {
                    for d_pk in &authorized_device_pks {
                        if envelope.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if envelope.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        // 5. SnapshotRecord: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(snap) = from_canonical_cbor::<SnapshotRecord>(record) {
                if snap.version == PROTOCOL_VERSION {
                    for d_pk in &authorized_device_pks {
                        if snap.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if snap.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        if !is_authorized {
            return Err("Record failed cryptographic authorization against registered vault recovery key or authorized device certificate".into());
        }

        // Caller authorization check:
        // Once recovery authority is registered, any caller modifying the log MUST be either
        // the recovery authority or one of the certified device public keys.
        if let Some(c_pk) = caller_pk {
            if let Some(r_pk) = registered_recovery_pk {
                let newly_certified_pk =
                    if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(record) {
                        if cert.verify(&r_pk).is_ok() && cert.device_signing_pk.len() == 32 {
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(&cert.device_signing_pk);
                            Some(pk)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                let is_trusted_caller = c_pk == &r_pk
                    || authorized_device_pks.contains(c_pk)
                    || newly_certified_pk.as_ref() == Some(c_pk);
                if !is_trusted_caller {
                    return Err(
                        "Caller session key is not authorized for this vault locator".into(),
                    );
                }
            }
        }

        let _guard = self.io_lock.lock().unwrap();
        let log_path = self
            .data_dir
            .join("recovery")
            .join(format!("{}.log", locator_hex));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| e.to_string())?;

        // Format: [4 bytes length prefix in big endian][record bytes]
        let len = (record.len() as u32).to_be_bytes();
        let original_len = file.metadata().map_err(|e| e.to_string())?.len();
        if let Err(e) = file
            .write_all(&len)
            .and_then(|_| file.write_all(record))
            .and_then(|_| file.sync_all())
        {
            let _ = file.set_len(original_len);
            let _ = file.sync_all();
            return Err(e.to_string());
        }

        Ok(1)
    }

    pub fn append_recovery_record(&self, locator_hex: &str, record: &[u8]) -> Result<u64, String> {
        self.append_authorized_recovery_record(locator_hex, record, None)
    }

    pub fn get_recovery_records(&self, locator_hex: &str) -> Vec<Vec<u8>> {
        if locator_hex.len() != 64 || hex::decode(locator_hex).is_err() {
            return Vec::new();
        }
        let _guard = self.io_lock.lock().unwrap();
        let log_path = self
            .data_dir
            .join("recovery")
            .join(format!("{}.log", locator_hex));
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

    /// Submits and registers an L2 commitment checkpoint through the relayer.
    pub fn relay_checkpoint(
        &self,
        evidence: &ciphervault_format::CheckpointEvidence,
    ) -> Result<ciphervault_storage::RelayerReceipt, String> {
        if !evidence.verify_commitment() {
            return Err(
                "Invalid commitment preimage math: salt and head do not match commitment".into(),
            );
        }

        let commitment_hex = hex::encode(&evidence.commitment);
        let mut lock = self.relayed_checkpoints.lock().unwrap();
        if let Some(existing) = lock.get(&commitment_hex) {
            return Ok(existing.clone());
        }

        // If evidence contains confirmed on-chain data (block > 0 and non-zero tx_hash):
        // status is "SequencerConfirmed". Otherwise it is truthfully "QueuedForRelay".
        let has_on_chain_tx =
            !evidence.tx_hash.is_empty() && evidence.tx_hash.iter().any(|b| *b != 0);
        let (status, block_number, tx_hash_hex) = if evidence.block_number > 0 && has_on_chain_tx {
            (
                "SequencerConfirmed".to_string(),
                evidence.block_number,
                hex::encode(&evidence.tx_hash),
            )
        } else {
            ("QueuedForRelay".to_string(), 0, String::new())
        };

        let receipt = ciphervault_storage::RelayerReceipt {
            commitment_hex: commitment_hex.clone(),
            tx_hash_hex,
            block_number,
            status,
            timestamp: Utc::now().timestamp() as u64,
        };

        lock.insert(commitment_hex, receipt.clone());
        Ok(receipt)
    }

    /// Updates the on-chain settlement status of a relayed checkpoint once mined.
    pub fn update_relayed_checkpoint(
        &self,
        commitment_hex: &str,
        tx_hash_hex: &str,
        block_number: u64,
        status: &str,
    ) -> Option<ciphervault_storage::RelayerReceipt> {
        let mut lock = self.relayed_checkpoints.lock().unwrap();
        if let Some(existing) = lock.get_mut(commitment_hex) {
            existing.tx_hash_hex = tx_hash_hex.to_string();
            existing.block_number = block_number;
            existing.status = status.to_string();
            Some(existing.clone())
        } else {
            None
        }
    }

    /// Queries an existing relayed L2 checkpoint receipt by its commitment hex.
    pub fn get_relayed_checkpoint(
        &self,
        commitment_hex: &str,
    ) -> Option<ciphervault_storage::RelayerReceipt> {
        let lock = self.relayed_checkpoints.lock().unwrap();
        lock.get(commitment_hex).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_persistence_renewal_and_signed_fields() {
        let root = std::env::temp_dir().join(format!("cv-lease-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test".into(), root.clone(), key.clone());
        let receipt = state.create_lease(&"a".repeat(64), 100, 90).unwrap();
        let pk = key.verifying_key().to_bytes();
        receipt.verify(&pk).unwrap();
        let mut tampered = receipt.clone();
        tampered.bytes += 1;
        assert!(tampered.verify(&pk).is_err());
        drop(state);
        let restarted = OperatorState::new("test".into(), root.clone(), key);
        let renewed = restarted.renew_lease(&receipt.lease_id, 30, 100).unwrap();
        assert_eq!(renewed.closure_digest_hex, receipt.closure_digest_hex);
        assert_eq!(renewed.expires_at_utc, receipt.expires_at_utc + 30 * 86400);
        assert!(restarted.renew_lease("../escape", 30, 100).is_err());
        assert!(restarted.renew_lease(&"0".repeat(32), 30, 100).is_err());
        assert!(restarted.renew_lease(&receipt.lease_id, 30, 999).is_err());
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_failed_persistence_and_anonymous_writes() {
        let root = std::env::temp_dir().join(format!("cv-write-{}", rand::random::<u128>()));
        let state = OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        assert!(state.validate_read_session("recovery_anonymous"));
        assert!(!state.validate_write_session("recovery_anonymous"));
        fs::remove_dir(root.join("leases")).unwrap();
        fs::write(root.join("leases"), b"block writes").unwrap();
        assert!(state.create_lease(&"a".repeat(64), 100, 90).is_err());
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_operator_recovery_record_cryptographic_authorization() {
        use ciphervault_crypto::RecoverySecret;
        use ciphervault_format::to_canonical_cbor;

        let root = std::env::temp_dir().join(format!("cv-auth-{}", rand::random::<u128>()));
        let op_key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test".into(), root.clone(), op_key);

        let vault_id = vec![0x42u8; 32];
        let locator_hex = "a".repeat(64);

        let r_secret = RecoverySecret::generate();
        let r_sk = r_secret.derive_recovery_signing_key().unwrap();
        let (_, r_enc_pk) = r_secret.derive_recovery_encryption_keys().unwrap();

        // 1. Poisoning attempt with arbitrary bytes must be rejected
        let poisoned = b"malicious random garbage payload";
        assert!(state
            .append_recovery_record(&locator_hex, poisoned)
            .is_err());

        // 2. GenesisRecord signed by recovery authority must be accepted
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.clone(),
            recovery_signing_pk: r_sk.verifying_key().to_bytes().to_vec(),
            recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0u8; 32],
            created_at_utc: 1000,
            creation_nonce: vec![1u8; 32],
            signature: Vec::new(),
        };
        genesis.sign(&r_sk).unwrap();
        let genesis_cbor = to_canonical_cbor(&genesis).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &genesis_cbor)
            .is_ok());

        // 3. Forged GenesisRecord for the same locator must be rejected
        let rogue_sk = ciphervault_crypto::generate_signing_key();
        let mut forged_genesis = genesis.clone();
        forged_genesis.recovery_signing_pk = rogue_sk.verifying_key().to_bytes().to_vec();
        forged_genesis.sign(&rogue_sk).unwrap();
        let forged_genesis_cbor = to_canonical_cbor(&forged_genesis).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &forged_genesis_cbor)
            .is_err());

        // 4. Valid DeviceCertificate signed by recovery authority must be accepted
        let dev_sk = ciphervault_crypto::generate_signing_key();
        let mut cert = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.clone(),
            certificate_id: vec![2u8; 32],
            device_signing_pk: dev_sk.verifying_key().to_bytes().to_vec(),
            permissions: 1,
            authority_generation: 1,
            issued_at_utc: 1001,
            signature: Vec::new(),
        };
        cert.sign(&r_sk).unwrap();
        let cert_cbor = to_canonical_cbor(&cert).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &cert_cbor)
            .is_ok());

        // 5. Forged DeviceCertificate signed by attacker must be rejected
        let mut forged_cert = cert.clone();
        forged_cert.certificate_id = vec![3u8; 32];
        forged_cert.sign(&rogue_sk).unwrap();
        let forged_cert_cbor = to_canonical_cbor(&forged_cert).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &forged_cert_cbor)
            .is_err());

        // 6. Valid HeadRecord signed by authorized device must be accepted
        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.clone(),
            snapshot_id: vec![0xAAu8; 32],
            parent_snapshot_ids: Vec::new(),
            closure_digest: vec![0xBBu8; 32],
            device_id: vec![0xCCu8; 32],
            device_counter: 1,
            signature: Vec::new(),
        };
        head.sign(&dev_sk).unwrap();
        let head_cbor = to_canonical_cbor(&head).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &head_cbor)
            .is_ok());

        // 7. Forged HeadRecord signed by unauthorized key must be rejected
        let mut forged_head = head.clone();
        forged_head.device_counter = 2;
        forged_head.sign(&rogue_sk).unwrap();
        let forged_head_cbor = to_canonical_cbor(&forged_head).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &forged_head_cbor)
            .is_err());

        // Verify that only the 3 valid records were committed to disk
        let stored = state.get_recovery_records(&locator_hex);
        assert_eq!(stored.len(), 3);

        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_operator_l2_relayer_checkpoint() {
        let root = std::env::temp_dir().join(format!("cv-relayer-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test-relayer".into(), root.clone(), key);

        let salt = [0x11u8; 32];
        let head_cid = [0x22u8; 32];
        let contract = [0x33u8; 20];
        let tx_dummy = [0u8; 32];

        // Valid evidence
        let evidence = ciphervault_format::CheckpointEvidence::new(
            salt, head_cid, 42161, contract, tx_dummy, 12345, 1700000000,
        );
        let receipt = state.relay_checkpoint(&evidence).unwrap();
        assert_eq!(receipt.commitment_hex, hex::encode(&evidence.commitment));
        assert_eq!(receipt.status, "QueuedForRelay");
        assert_eq!(receipt.block_number, 0);

        // Confirm mined status update
        let updated = state
            .update_relayed_checkpoint(
                &receipt.commitment_hex,
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                12345,
                "SequencerConfirmed",
            )
            .unwrap();
        assert_eq!(updated.status, "SequencerConfirmed");
        assert_eq!(updated.block_number, 12345);

        // Idempotent query
        let queried = state
            .get_relayed_checkpoint(&receipt.commitment_hex)
            .unwrap();
        assert_eq!(queried.tx_hash_hex, updated.tx_hash_hex);
        assert_eq!(queried.status, "SequencerConfirmed");

        // Rejects tampered commitment math
        let mut tampered = evidence.clone();
        tampered.salt[0] ^= 0xFF;
        assert!(state.relay_checkpoint(&tampered).is_err());

        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_operator_pos_challenge_and_proof() {
        let root = std::env::temp_dir().join(format!("cv-pos-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let operator_pk = key.verifying_key().to_bytes();
        let state = OperatorState::new("test-pos-operator".into(), root.clone(), key);

        let data = b"encrypted-blob-for-proof-of-storage-challenge";
        let cid = ciphervault_format::compute_digest(data);
        let cid_hex = hex::encode(cid);

        // Put object
        state.put_object(&cid_hex, data).unwrap();

        // 1. Valid challenge generates matching verifiable receipt
        let nonce = [0x55u8; 32];
        let receipt = state.generate_pos_proof(&cid_hex, &nonce).unwrap();
        assert_eq!(receipt.operator_id, "test-pos-operator");
        assert_eq!(receipt.cid_hex, cid_hex);
        assert_eq!(receipt.nonce_hex, hex::encode(nonce));
        assert_eq!(receipt.size_bytes, data.len() as u64);

        let expected_proof = ciphervault_storage::compute_pos_proof(&cid, &nonce, data);
        assert!(receipt.verify(&operator_pk, &expected_proof).is_ok());

        // 2. Nonexistent CID fails with Object not found
        let missing_cid = hex::encode([0x99u8; 32]);
        let err = state.generate_pos_proof(&missing_cid, &nonce).unwrap_err();
        assert_eq!(err, "Object not found");

        // 3. Invalid CID hex length fails
        assert!(state.generate_pos_proof("short_cid", &nonce).is_err());

        drop(state);
        fs::remove_dir_all(root).unwrap();
    }
}
