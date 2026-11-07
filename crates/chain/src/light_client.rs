use std::collections::HashSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::ChainError;
use crate::types::{AnchorProofResponse, CommitmentTx};

/// Result of an autonomous light-client verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignVerificationResult {
    pub verified: bool,
    pub chain_id: String,
    pub height: u64,
    pub block_hash_hex: String,
    pub timestamp_ms: u64,
    pub commitment_hex: String,
    pub head_cid_hex: String,
    pub proposer_hex: String,
    pub signatures_verified: usize,
    pub quorum_required: usize,
    pub message: String,
}

/// Zero-dependency light client verifier for CipherChain anchors.
#[derive(Debug, Clone)]
pub struct SovereignLightClient {
    chain_id: String,
    trusted_validators: HashSet<[u8; 32]>,
}

impl SovereignLightClient {
    /// Creates a light client configured with the trusted validator keys.
    pub fn new(chain_id: &str, trusted_validators: Vec<[u8; 32]>) -> Self {
        Self {
            chain_id: chain_id.to_string(),
            trusted_validators: trusted_validators.into_iter().collect(),
        }
    }

    /// Quorum threshold rule: ⌊2N/3⌋ + 1.
    pub fn quorum_threshold(&self) -> usize {
        let n = self.trusted_validators.len();
        if n <= 2 {
            n
        } else {
            (2 * n) / 3 + 1
        }
    }

    /// Verifies that an anchor proof cryptographically proves the commitment's inclusion in CipherChain.
    pub fn verify_anchor(
        &self,
        expected_head_cid: &[u8; 32],
        expected_salt: &[u8; 32],
        proof: &AnchorProofResponse,
    ) -> Result<SovereignVerificationResult, ChainError> {
        // 1. Verify chain ID
        if proof.chain_id != self.chain_id {
            return Err(ChainError::InvalidGenesis(format!(
                "Chain ID mismatch: expected '{}', got '{}'",
                self.chain_id, proof.chain_id
            )));
        }

        // 2. Verify CID and salt match client expectation
        if &proof.head_cid != expected_head_cid {
            return Err(ChainError::CommitmentMismatch {
                computed: hex::encode(expected_head_cid),
                declared: hex::encode(proof.head_cid),
            });
        }
        if &proof.salt != expected_salt {
            return Err(ChainError::CommitmentMismatch {
                computed: hex::encode(expected_salt),
                declared: hex::encode(proof.salt),
            });
        }

        // 3. Verify commitment derivation: SHA-256(salt || head_cid)
        let computed_commitment = CommitmentTx::calculate_commitment(&proof.salt, &proof.head_cid);
        if computed_commitment != proof.commitment {
            return Err(ChainError::CommitmentMismatch {
                computed: hex::encode(computed_commitment),
                declared: hex::encode(proof.commitment),
            });
        }

        // 4. Verify block header consistency
        let computed_block_hash = proof.header.block_hash();
        if computed_block_hash != proof.block_hash {
            return Err(ChainError::InvalidPrevHash {
                expected: hex::encode(computed_block_hash),
                found: hex::encode(proof.block_hash),
            });
        }
        if proof.header.height != proof.height {
            return Err(ChainError::InvalidHeight {
                expected: proof.height,
                found: proof.header.height,
            });
        }

        // 5. Verify Merkle inclusion proof against tx_root
        if !proof.tx_proof.verify(&proof.header.tx_root) {
            return Err(ChainError::InvalidInclusionProof(
                "Merkle audit path does not resolve to header tx_root".to_string(),
            ));
        }

        // 6. Verify validator quorum threshold and Ed25519 signatures
        let required_quorum = self.quorum_threshold();
        let signing_payload = proof.header.signing_bytes();

        let mut valid_signatures = 0;
        let mut seen = HashSet::new();

        for sig in &proof.header.signatures {
            if self.trusted_validators.contains(&sig.validator) && seen.insert(sig.validator) {
                if let Ok(verifying_key) = VerifyingKey::from_bytes(&sig.validator) {
                    let ed_sig = Signature::from_bytes(&sig.signature);
                    if verifying_key
                        .verify_strict(&signing_payload, &ed_sig)
                        .is_ok()
                    {
                        valid_signatures += 1;
                    }
                }
            }
        }

        if valid_signatures < required_quorum {
            return Err(ChainError::InsufficientQuorum {
                required: required_quorum,
                actual: valid_signatures,
            });
        }

        Ok(SovereignVerificationResult {
            verified: true,
            chain_id: self.chain_id.clone(),
            height: proof.height,
            block_hash_hex: hex::encode(proof.block_hash),
            timestamp_ms: proof.timestamp_ms,
            commitment_hex: hex::encode(proof.commitment),
            head_cid_hex: hex::encode(proof.head_cid),
            proposer_hex: hex::encode(proof.header.proposer),
            signatures_verified: valid_signatures,
            quorum_required: required_quorum,
            message: format!(
                "Anchor cryptographically verified on sovereign CipherChain (Block #{}, {}/{} validator signatures)",
                proof.height, valid_signatures, required_quorum
            ),
        })
    }
}
