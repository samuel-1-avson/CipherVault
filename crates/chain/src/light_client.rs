use std::collections::HashSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::ChainError;
use crate::types::{
    verify_signed_median, AnchorProofResponse, BlockHeader, CommitmentTx, SIGNED_TIME_VERSION,
};

/// Result of an autonomous light-client verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignVerificationResult {
    pub verified: bool,
    pub chain_id: String,
    pub height: u64,
    pub block_hash_hex: String,
    /// Block time from the verified header, never the proof's own copy.
    pub timestamp_ms: u64,
    /// Whether `timestamp_ms` is covered by validator signatures. False for
    /// block versions 2 and 3, whose committed median no signature covers:
    /// report that time, but do not rely on it as evidence.
    #[serde(default)]
    pub timestamp_signed: bool,
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

    /// Number of currently trusted validator keys.
    pub fn trusted_len(&self) -> usize {
        self.trusted_validators.len()
    }

    /// Verifies a header's validator quorum under the trusted set and returns
    /// how many trusted signatures verified. Signatures from untrusted keys,
    /// duplicates and bad signatures are skipped (never counted). Version 4+
    /// headers must also carry a timestamp equal to the median of the
    /// verified signers' signed observed times, so the block time cannot be
    /// rewritten by whoever stores or serves the header.
    pub fn verify_header(&self, header: &BlockHeader) -> Result<usize, ChainError> {
        if header.chain_id != self.chain_id {
            return Err(ChainError::InvalidGenesis(format!(
                "Chain ID mismatch: expected '{}', header carries '{}'",
                self.chain_id, header.chain_id
            )));
        }
        let mut verified: HashSet<[u8; 32]> = HashSet::new();
        let mut observed = Vec::with_capacity(header.signatures.len());
        for sig in &header.signatures {
            if !self.trusted_validators.contains(&sig.validator)
                || verified.contains(&sig.validator)
            {
                continue;
            }
            let Ok(payload) = header.payload_for_signature(sig) else {
                continue;
            };
            let Ok(verifying_key) = VerifyingKey::from_bytes(&sig.validator) else {
                continue;
            };
            let ed_sig = Signature::from_bytes(&sig.signature);
            if verifying_key.verify_strict(&payload, &ed_sig).is_ok() {
                verified.insert(sig.validator);
                if let Some(t) = sig.observed_ms {
                    observed.push(t);
                }
            }
        }

        // An empty trusted set must never "verify" anything.
        let required = self.quorum_threshold().max(1);
        if verified.len() < required {
            return Err(ChainError::InsufficientQuorum {
                required,
                actual: verified.len(),
            });
        }
        if header.version >= SIGNED_TIME_VERSION {
            verify_signed_median(header.timestamp_ms, &mut observed)?;
        }
        Ok(verified.len())
    }

    /// Advances trust across a rotation block. The rotation header must
    /// verify under the CURRENT trusted set (quorum signatures checked here,
    /// not left to the caller) before the trusted set swaps to the new
    /// members. Callers feed rotation headers in height order; proofs for
    /// later heights then verify against the rotated set.
    pub fn advance_to_rotation(&mut self, header: &BlockHeader) -> Result<(), ChainError> {
        let Some(keys) = &header.next_validators else {
            return Err(ChainError::InvalidRotation(
                "header carries no rotation".to_string(),
            ));
        };
        if header.version < 3 {
            return Err(ChainError::InvalidRotation(format!(
                "rotation in version {} header (requires v3+)",
                header.version
            )));
        }
        if keys.is_empty() {
            return Err(ChainError::InvalidRotation(
                "rotation to an empty set".to_string(),
            ));
        }
        let mut seen = HashSet::new();
        for key in keys {
            if !seen.insert(key) {
                return Err(ChainError::InvalidRotation(
                    "rotation set contains duplicates".to_string(),
                ));
            }
        }
        self.verify_header(header).map_err(|e| {
            ChainError::InvalidRotation(format!(
                "rotation at height {} is not certified by the current set: {e}",
                header.height
            ))
        })?;
        self.trusted_validators = keys.iter().copied().collect();
        Ok(())
    }

    /// Verifies that an anchor proof cryptographically proves the inclusion of
    /// the commitment to (`expected_salt`, `expected_head_cid`) in CipherChain.
    ///
    /// Everything that matters is recomputed by the verifier: the commitment
    /// from its own preimage, the Merkle leaf from the carried transaction,
    /// and (for version 4+) the block time from the signed samples. Proof
    /// fields that merely restate those values are cross-checked or ignored.
    pub fn verify_anchor(
        &self,
        expected_head_cid: &[u8; 32],
        expected_salt: &[u8; 32],
        proof: &AnchorProofResponse,
    ) -> Result<SovereignVerificationResult, ChainError> {
        // 1. Chain ID.
        if proof.chain_id != self.chain_id {
            return Err(ChainError::InvalidGenesis(format!(
                "Chain ID mismatch: expected '{}', got '{}'",
                self.chain_id, proof.chain_id
            )));
        }

        // 2. The commitment comes from the verifier's preimage, not the proof.
        let expected_commitment =
            CommitmentTx::calculate_commitment(expected_salt, expected_head_cid);
        if proof.commitment != expected_commitment {
            return Err(ChainError::CommitmentMismatch {
                computed: hex::encode(expected_commitment),
                declared: hex::encode(proof.commitment),
            });
        }

        // 3. The carried transaction must be that commitment's and validly
        // signed. Legacy (v0/v1) transactions publish the preimage, which must
        // be ours; private (v2) ones carry only the commitment.
        let tx = &proof.tx;
        if tx.commitment != expected_commitment {
            return Err(ChainError::CommitmentMismatch {
                computed: hex::encode(expected_commitment),
                declared: hex::encode(tx.commitment),
            });
        }
        if tx.version < 2 && (tx.salt != *expected_salt || tx.head_cid != *expected_head_cid) {
            return Err(ChainError::CommitmentMismatch {
                computed: hex::encode(expected_commitment),
                declared: hex::encode(CommitmentTx::calculate_commitment(&tx.salt, &tx.head_cid)),
            });
        }
        tx.verify_signature(&self.chain_id)?;

        // 4. Header consistency, including the proof's copy of the time.
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
        if proof.timestamp_ms != proof.header.timestamp_ms {
            return Err(ChainError::InvalidInclusionProof(format!(
                "proof timestamp {} does not match the block header's {}",
                proof.timestamp_ms, proof.header.timestamp_ms
            )));
        }

        // 5. Merkle inclusion, bound to THIS transaction: the leaf is
        // recomputed, so a genuine audit path for another transaction in the
        // same (or any) block cannot be relabelled with our commitment.
        let leaf = tx.tx_leaf_hash();
        if proof.tx_proof.leaf_hash != leaf {
            return Err(ChainError::InvalidInclusionProof(
                "audit path leaf is not the carried transaction".to_string(),
            ));
        }
        if proof.tx_proof.leaf_index != proof.tx_index {
            return Err(ChainError::InvalidInclusionProof(format!(
                "audit path index {} does not match tx index {}",
                proof.tx_proof.leaf_index, proof.tx_index
            )));
        }
        if !proof.tx_proof.verify(&proof.header.tx_root) {
            return Err(ChainError::InvalidInclusionProof(
                "Merkle audit path does not resolve to header tx_root".to_string(),
            ));
        }

        // 6. Validator quorum (and, for v4+, the signed median time).
        let signatures_verified = self.verify_header(&proof.header)?;
        let quorum_required = self.quorum_threshold().max(1);
        let timestamp_signed = proof.header.timestamp_is_signed();

        Ok(SovereignVerificationResult {
            verified: true,
            chain_id: self.chain_id.clone(),
            height: proof.height,
            block_hash_hex: hex::encode(proof.block_hash),
            timestamp_ms: proof.header.timestamp_ms,
            timestamp_signed,
            commitment_hex: hex::encode(expected_commitment),
            head_cid_hex: hex::encode(expected_head_cid),
            proposer_hex: hex::encode(proof.header.proposer),
            signatures_verified,
            quorum_required,
            message: format!(
                "Anchor verified on sovereign CipherChain (Block #{}, {}/{} validator signatures; block time {})",
                proof.height,
                signatures_verified,
                quorum_required,
                if timestamp_signed {
                    "validator-signed".to_string()
                } else {
                    format!("NOT signed: block version {}", proof.header.version)
                }
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusSigner;

    fn header_with_rotation(
        proposer: [u8; 32],
        version: u16,
        rotation: Option<Vec<[u8; 32]>>,
    ) -> BlockHeader {
        BlockHeader {
            version,
            chain_id: "test-chain".to_string(),
            height: 1,
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            timestamp_ms: 2_000,
            proposer,
            next_validators: rotation,
            signatures: Vec::new(),
        }
    }

    #[test]
    fn test_advance_to_rotation_rekeys_trust() {
        let signer = ConsensusSigner::generate();
        let mut client = SovereignLightClient::new("test-chain", vec![signer.public_key()]);
        assert_eq!(client.quorum_threshold(), 1);

        // No rotation payload: rejected.
        let plain = header_with_rotation(signer.public_key(), 3, None);
        assert!(client.advance_to_rotation(&plain).is_err());

        // Rotation in a pre-v3 header: rejected even if well-formed.
        let legacy = header_with_rotation(signer.public_key(), 2, Some(vec![[0x02; 32]]));
        assert!(client.advance_to_rotation(&legacy).is_err());

        // Unsigned rotation: rejected, trust does not move (CC-12).
        let mut rotated =
            header_with_rotation(signer.public_key(), 3, Some(vec![[0x02; 32], [0x03; 32]]));
        assert!(client.advance_to_rotation(&rotated).is_err());
        assert_eq!(client.quorum_threshold(), 1);

        // Certified by the current set: trust advances.
        rotated.signatures.push(signer.sign_header(&rotated));
        client.advance_to_rotation(&rotated).unwrap();
        assert_eq!(client.quorum_threshold(), 2);
    }

    #[test]
    fn test_v4_header_time_must_be_signed_median() {
        let signers: Vec<ConsensusSigner> = (0..3).map(|_| ConsensusSigner::generate()).collect();
        let client = SovereignLightClient::new(
            "test-chain",
            signers.iter().map(|s| s.public_key()).collect(),
        );
        let mut header = header_with_rotation(signers[0].public_key(), SIGNED_TIME_VERSION, None);
        for (signer, observed) in signers.iter().zip([1_000u64, 2_000, 9_000]) {
            header
                .signatures
                .push(signer.sign_header_at(&header, observed));
        }
        // Declared time must be the median of the signed samples (2_000):
        // an assembler claiming the proposer's 9_000 is caught.
        header.timestamp_ms = 9_000;
        assert!(client.verify_header(&header).is_err());
        header.timestamp_ms = 2_000;
        assert_eq!(client.verify_header(&header).unwrap(), 3);
        // Rewriting the time afterwards breaks verification.
        header.timestamp_ms = 1_500;
        assert!(matches!(
            client.verify_header(&header),
            Err(ChainError::TimestampNotMedian { .. })
        ));
        // An empty trusted set verifies nothing.
        header.timestamp_ms = 2_000;
        assert!(SovereignLightClient::new("test-chain", Vec::new())
            .verify_header(&header)
            .is_err());
    }
}
