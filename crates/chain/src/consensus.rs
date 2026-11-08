use std::collections::HashSet;
use std::fs;
use std::path::Path;

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
        let signing_payload = header.signing_payload();

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

    /// Verifies a pre-quorum proposal: the proposer must belong to the set and
    /// at least one header signature must be a valid endorsement from them.
    /// Unlike [`Self::verify_header_signatures`], no quorum count is required.
    pub fn verify_proposer_signature(&self, header: &BlockHeader) -> Result<(), ChainError> {
        if !self.contains(&header.proposer) {
            return Err(ChainError::InvalidProposer(format!(
                "Proposer {} is not in active validator set",
                hex::encode(header.proposer)
            )));
        }
        let signing_payload = header.signing_payload();
        let verifying_key = VerifyingKey::from_bytes(&header.proposer).map_err(|e| {
            ChainError::InvalidSignature(format!("Invalid proposer public key: {e}"))
        })?;
        let mut saw_proposer_sig = false;
        for sig in &header.signatures {
            if sig.validator != header.proposer {
                continue;
            }
            saw_proposer_sig = true;
            let signature = Signature::from_bytes(&sig.signature);
            if verifying_key
                .verify_strict(&signing_payload, &signature)
                .is_ok()
            {
                return Ok(());
            }
        }
        if saw_proposer_sig {
            return Err(ChainError::InvalidSignature(format!(
                "Proposer {} endorsement failed verification",
                hex::encode(header.proposer)
            )));
        }
        Err(ChainError::InvalidProposer(format!(
            "Proposal carries no endorsement from proposer {}",
            hex::encode(header.proposer)
        )))
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

    /// Loads a persistent consensus signer from a 32-byte seed file, generating
    /// and storing a fresh key (owner-only permissions on Unix) when absent.
    /// Corrupt (wrong-length) key files are rejected, never overwritten.
    pub fn load_or_create(path: &Path) -> Result<Self, ChainError> {
        if path.exists() {
            let seed = fs::read(path).map_err(|e| ChainError::Io(e.to_string()))?;
            if seed.len() != 32 {
                return Err(ChainError::InvalidGenesis(format!(
                    "Corrupt consensus key file {}: expected 32 bytes, found {}",
                    path.display(),
                    seed.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed);
            return Ok(Self::from_bytes(&arr));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| ChainError::Io(e.to_string()))?;
        }
        let signer = Self::generate();
        Self::write_seed_file(path, &signer.signing_key.to_bytes())?;
        Ok(signer)
    }

    fn write_seed_file(path: &Path, seed: &[u8; 32]) -> Result<(), ChainError> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| ChainError::Io(e.to_string()))?;
            file.write_all(seed)
                .map_err(|e| ChainError::Io(e.to_string()))?;
        }
        #[cfg(not(unix))]
        {
            // Windows: write then apply the owner-only DACL; fails
            // closed so a consensus seed never sits at default ACLs.
            fs::write(path, seed).map_err(|e| ChainError::Io(e.to_string()))?;
            ciphervault_file_lock::lock_secret_file(path)
                .map_err(|e| ChainError::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// Returns the public key of the signer.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Signs opaque bytes (gossip envelopes, challenges) with the device key.
    pub fn sign_raw(&self, payload: &[u8]) -> [u8; 64] {
        self.signing_key.sign(payload).to_bytes()
    }

    /// Endorses and cryptographically signs a block header.
    pub fn sign_header(&self, header: &BlockHeader) -> BlockSignature {
        let payload = header.signing_payload();
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

/// Verifies an opaque device-key signature (gossip envelope admission).
pub fn verify_raw_signature(
    pubkey: &[u8; 32],
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), ChainError> {
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| ChainError::InvalidSignature(format!("Invalid validator key: {e}")))?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|e| ChainError::InvalidSignature(format!("Envelope signature failure: {e}")))
}
