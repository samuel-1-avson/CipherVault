use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OperatorInfo {
    pub operator_id: String,
    pub operator_signing_pk_hex: String,
    pub supported_version: u32,
    pub retention_terms: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChallengeRequest {
    pub vault_id_hex: String,
    pub public_key_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub nonce_hex: String,
    pub expires_at_utc: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionRequest {
    pub challenge_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionResponse {
    pub token: String,
    pub expires_at_utc: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LeaseRequest {
    pub closure_digest_hex: String,
    pub byte_count: u64,
    pub term_days: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LeaseRenewRequest {
    pub additional_days: u32,
    pub byte_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LeaseReceipt {
    pub lease_id: String,
    pub operator_id: String,
    pub closure_digest_hex: String,
    pub term_days: u32,
    pub bytes: u64,
    pub issued_at_utc: u64,
    pub expires_at_utc: u64,
    pub signature_hex: String,
}

impl LeaseReceipt {
    /// Cryptographically verifies that this lease receipt was signed by the specified operator public key.
    pub fn verify(&self, operator_pk: &[u8; 32]) -> Result<(), crate::error::StorageError> {
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| crate::error::StorageError::ServerError {
                status: 400,
                message: format!("Invalid hex in lease signature: {}", e),
            })?;
        if sig_bytes.len() != 64 {
            return Err(crate::error::StorageError::ServerError {
                status: 400,
                message: "Invalid lease signature length (expected 64 bytes)".into(),
            });
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        let msg = format!("{}:{}:{}:{}", self.operator_id, self.lease_id, self.closure_digest_hex, self.expires_at_utc);
        ciphervault_crypto::signatures::verify_with_domain(operator_pk, b"operator_lease", msg.as_bytes(), &sig)
            .map_err(|e| crate::error::StorageError::ServerError {
                status: 400,
                message: format!("Cryptographic lease signature invalid: {}", e),
            })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppendRecordResponse {
    pub sequence: u64,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecoveryRecordsResponse {
    pub records_hex: Vec<String>,
}
