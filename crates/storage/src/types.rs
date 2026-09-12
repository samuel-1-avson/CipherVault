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
    pub fn signing_bytes(&self) -> Vec<u8> {
        // All retention and accounting fields belong to the signed promise.
        serde_json::to_vec(&(
            &self.lease_id,
            &self.operator_id,
            &self.closure_digest_hex,
            self.term_days,
            self.bytes,
            self.issued_at_utc,
            self.expires_at_utc,
        ))
        .expect("serializable receipt fields")
    }

    /// Cryptographically verifies that this lease receipt was signed by the specified operator public key.
    pub fn verify(&self, operator_pk: &[u8; 32]) -> Result<(), crate::error::StorageError> {
        let sig_bytes = hex::decode(&self.signature_hex).map_err(|e| {
            crate::error::StorageError::ServerError {
                status: 400,
                message: format!("Invalid hex in lease signature: {}", e),
            }
        })?;
        if sig_bytes.len() != 64 {
            return Err(crate::error::StorageError::ServerError {
                status: 400,
                message: "Invalid lease signature length (expected 64 bytes)".into(),
            });
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        let msg = self.signing_bytes();
        ciphervault_crypto::signatures::verify_with_domain(
            operator_pk,
            b"operator_lease",
            &msg,
            &sig,
        )
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PosChallengeRequest {
    pub nonce_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProofOfStorageReceipt {
    pub operator_id: String,
    pub cid_hex: String,
    pub nonce_hex: String,
    pub proof_hex: String,
    pub signature_hex: String,
    pub size_bytes: u64,
}

impl ProofOfStorageReceipt {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.operator_id.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.cid_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.nonce_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.proof_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&self.size_bytes.to_le_bytes());
        bytes
    }

    pub fn verify(
        &self,
        operator_pk: &[u8; 32],
        expected_proof: &[u8; 32],
    ) -> Result<(), crate::error::StorageError> {
        let expected_proof_hex = hex::encode(expected_proof);
        if self.proof_hex.to_lowercase() != expected_proof_hex.to_lowercase() {
            return Err(crate::error::StorageError::ServerError {
                status: 400,
                message: format!(
                    "Proof-of-Storage proof mismatch: expected {}, received {}",
                    expected_proof_hex, self.proof_hex
                ),
            });
        }

        let sig_bytes = hex::decode(&self.signature_hex).map_err(|e| {
            crate::error::StorageError::ServerError {
                status: 400,
                message: format!("Invalid hex in PoS signature: {}", e),
            }
        })?;
        if sig_bytes.len() != 64 {
            return Err(crate::error::StorageError::ServerError {
                status: 400,
                message: "Invalid PoS signature length (expected 64 bytes)".into(),
            });
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        let msg = self.signing_bytes();
        ciphervault_crypto::signatures::verify_with_domain(operator_pk, b"operator_pos", &msg, &sig)
            .map_err(|e| crate::error::StorageError::ServerError {
                status: 400,
                message: format!("Cryptographic Proof-of-Storage signature invalid: {}", e),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::generate_signing_key;

    #[test]
    fn test_pos_receipt_verification_and_tamper_matrix() {
        let signing_key = generate_signing_key();
        let operator_pk = signing_key.verifying_key().to_bytes();
        let cid = [0x42u8; 32];
        let nonce = [0x77u8; 32];
        let data = b"confidential-chunk-payload-data";
        let proof = crate::compute_pos_proof(&cid, &nonce, data);

        let mut receipt = ProofOfStorageReceipt {
            operator_id: "operator_alpha".to_string(),
            cid_hex: hex::encode(cid),
            nonce_hex: hex::encode(nonce),
            proof_hex: hex::encode(proof),
            signature_hex: String::new(),
            size_bytes: data.len() as u64,
        };

        let msg = receipt.signing_bytes();
        let sig =
            ciphervault_crypto::signatures::sign_with_domain(&signing_key, b"operator_pos", &msg);
        receipt.signature_hex = hex::encode(sig);

        // 1. Valid receipt passes verification
        assert!(receipt.verify(&operator_pk, &proof).is_ok());

        // 2. Mismatched expected proof fails
        let wrong_proof = [0x99u8; 32];
        assert!(receipt.verify(&operator_pk, &wrong_proof).is_err());

        // 3. Tampered proof_hex in receipt fails
        let mut tampered_receipt = receipt.clone();
        tampered_receipt.proof_hex = hex::encode(wrong_proof);
        assert!(tampered_receipt.verify(&operator_pk, &proof).is_err());

        // 4. Wrong operator key fails
        let other_key = generate_signing_key();
        let other_pk = other_key.verifying_key().to_bytes();
        assert!(receipt.verify(&other_pk, &proof).is_err());
    }
}
