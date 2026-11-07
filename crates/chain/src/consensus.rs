use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::ChainError;
use crate::types::{BlockHeader, BlockSignature, CommitmentTx};

/// Set of registered fleet operators authorized to produce and endorse blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<[u8; 32]>,
}

impl ValidatorSet {
    /// Creates a new validator set from a list of Ed25519 public keys.
    pub fn new(validators: Vec<[u8; 32]>) -> Result<Self, ChainError> {
        if validators.is_empty() {
            return Err(ChainError::InvalidGenesis(
                "Validator set cannot be empty".to_string(),
            ));
        }

        // Ensure no duplicates
        let mut seen = HashSet::new();
        for v in &validators {
            if !seen.insert(*v) {
                return Err(ChainError::InvalidGenesis(format!(
                    "Duplicate validator public key: {}",
                    hex::encode(v)
                )));
            }
        }

        Ok(Self { validators })
    }

    /// Number of active validators in the set.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Read-only slice of authorized validator public keys.
    pub fn validators(&self) -> &[[u8; 32]] {
        &self.validators
    }

    /// Checks if a public key belongs to this validator set.
    pub fn contains(&self, pubkey: &[u8; 32]) -> bool {
        self.validators.contains(pubkey)
    }

    /// Minimum number of valid signatures required to finalize a block (BFT quorum: ⌊2N/3⌋ + 1).
    pub fn quorum_threshold(&self) -> usize {
        let n = self.validators.len();
        if n <= 2 {
            n
        } else {
            (2 * n) / 3 + 1
        }
    }

    /// Verifies that the block header has gathered sufficient cryptographic quorum signatures from authorized validators.
    pub fn verify_header_signatures(&self, header: &BlockHeader) -> Result<(), ChainError> {
        // 1. Proposer must belong to the active validator set
        if !self.contains(&header.proposer) {
            return Err(ChainError::InvalidProposer(format!(
                "Proposer {} is not in active validator set",
                hex::encode(header.proposer)
            )));
        }

        // 2. Quorum count check
        let required_quorum = self.quorum_threshold();
        let actual_count = header.signatures.len();
        if actual_count < required_quorum {
            return Err(ChainError::InsufficientQuorum {
                required: required_quorum,
                actual: actual_count,
            });
        }

        // 3. Duplicate and authorization checks
        let mut seen = HashSet::new();
        let signing_payload = header.signing_bytes();

        for sig in &header.signatures {
            if !self.contains(&sig.validator) {
                return Err(ChainError::UnauthorizedValidator(hex::encode(
                    sig.validator,
                )));
            }

            if !seen.insert(sig.validator) {
                return Err(ChainError::DuplicateValidatorSignature(hex::encode(
                    sig.validator,
                )));
            }

            let verifying_key = VerifyingKey::from_bytes(&sig.validator).map_err(|e| {
                ChainError::InvalidSignature(format!("Invalid validator public key: {}", e))
            })?;
            let signature = Signature::from_bytes(&sig.signature);

            verifying_key
                .verify_strict(&signing_payload, &signature)
                .map_err(|e| {
                    ChainError::InvalidSignature(format!(
                        "Validator {} signature verification failed: {}",
                        hex::encode(sig.validator),
                        e
                    ))
                })?;
        }

        Ok(())
    }
}

/// Cryptographic signing authority held by an Operator node.
pub struct ConsensusSigner {
    signing_key: SigningKey,
    public_key: [u8; 32],
}

impl ConsensusSigner {
    /// Generates a new random Ed25519 consensus signing identity.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            public_key,
        }
    }

    /// Loads a consensus signer from a 32-byte Ed25519 private seed.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            public_key,
        }
    }

    /// Returns the public key of the signer.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Endorses and cryptographically signs a block header.
    pub fn sign_header(&self, header: &BlockHeader) -> BlockSignature {
        let payload = header.signing_bytes();
        let signature = self.signing_key.sign(&payload);
        BlockSignature {
            validator: self.public_key,
            signature: signature.to_bytes(),
        }
    }

    /// Signs a commitment transaction with the client's private key.
    pub fn sign_tx(&self, tx: &mut CommitmentTx, chain_id: &str) {
        tx.client_pubkey = self.public_key;
        let payload = tx.signing_bytes(chain_id);
        let signature = self.signing_key.sign(&payload);
        tx.signature = signature.to_bytes();
    }
}
