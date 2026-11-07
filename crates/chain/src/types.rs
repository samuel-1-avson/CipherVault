use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ChainError;
use crate::merkle::{hash_leaf, InclusionProof};

/// Protocol version of the CipherChain ledger.
pub const PROTOCOL_VERSION: u16 = 1;

/// Canonical Sovereign Chain numeric identifier.
pub const SOVEREIGN_CHAIN_ID_NUM: u64 = 777777;

/// Canonical Sovereign Chain string identifier.
pub const SOVEREIGN_CHAIN_ID_STR: &str = "ciphervault-sovereign-1";

/// Domain separator prefix for block signing bytes.
pub const BLOCK_SIGNING_DOMAIN: &[u8] = b"CIPHERVAULT_BLOCK_V1:";

/// Domain separator prefix for transaction signing bytes.
pub const TX_SIGNING_DOMAIN: &[u8] = b"CIPHERVAULT_TX_V1:";

pub mod serde_hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if decoded.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes for signature"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}

/// Ed25519 validator signature endorsing a block header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSignature {
    pub validator: [u8; 32],
    #[serde(with = "serde_hex_64")]
    pub signature: [u8; 64],
}

/// Sovereign block header containing consensus state and Merkle roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u16,
    pub chain_id: String,
    pub height: u64,
    pub prev_block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub tx_root: [u8; 32],
    pub timestamp_ms: u64,
    pub proposer: [u8; 32],
    pub signatures: Vec<BlockSignature>,
}

impl BlockHeader {
    /// Canonical signing payload for validator threshold signatures (excludes the signatures themselves).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + self.chain_id.len());
        buf.extend_from_slice(BLOCK_SIGNING_DOMAIN);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(self.chain_id.as_bytes());
        buf.extend_from_slice(&[0x00]); // null separator
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.prev_block_hash);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.tx_root);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf.extend_from_slice(&self.proposer);
        buf
    }

    /// Computes the unique cryptographic identifier (SHA-256 hash) of the block.
    pub fn block_hash(&self) -> [u8; 32] {
        let signing = self.signing_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&signing);
        hasher.update((self.signatures.len() as u32).to_le_bytes());
        for sig in &self.signatures {
            hasher.update(sig.validator);
            hasher.update(sig.signature);
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Salted cryptographic commitment transaction submitted by a vault client or operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentTx {
    pub vault_id: [u8; 32],
    pub salt: [u8; 32],
    pub head_cid: [u8; 32],
    pub commitment: [u8; 32],
    pub client_pubkey: [u8; 32],
    #[serde(with = "serde_hex_64")]
    pub signature: [u8; 64],
    pub nonce: u64,
    pub timestamp_ms: u64,
}

impl CommitmentTx {
    /// Computes the canonical salted commitment: SHA-256("CIPHERVAULT-ANCHOR-V1" || salt || head_cid).
    pub fn calculate_commitment(salt: &[u8; 32], head_cid: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"CIPHERVAULT-ANCHOR-V1");
        hasher.update(salt);
        hasher.update(head_cid);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Canonical serialization payload for client signature verification.
    pub fn signing_bytes(&self, chain_id: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + chain_id.len());
        buf.extend_from_slice(TX_SIGNING_DOMAIN);
        buf.extend_from_slice(chain_id.as_bytes());
        buf.extend_from_slice(&[0x00]);
        buf.extend_from_slice(&self.vault_id);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.head_cid);
        buf.extend_from_slice(&self.commitment);
        buf.extend_from_slice(&self.client_pubkey);
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf
    }

    /// Computes the unique transaction leaf hash for the block's Merkle tree.
    pub fn tx_leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.vault_id);
        hasher.update(self.commitment);
        hasher.update(self.client_pubkey);
        hasher.update(self.signature);
        hasher.update(self.nonce.to_le_bytes());
        let digest = hasher.finalize();
        hash_leaf(&digest)
    }

    /// Validates the internal commitment derivation and Ed25519 client signature.
    pub fn verify_signature(&self, chain_id: &str) -> Result<(), ChainError> {
        let expected_commitment = Self::calculate_commitment(&self.salt, &self.head_cid);
        if expected_commitment != self.commitment {
            return Err(ChainError::CommitmentMismatch {
                computed: hex::encode(expected_commitment),
                declared: hex::encode(self.commitment),
            });
        }

        let verifying_key = VerifyingKey::from_bytes(&self.client_pubkey)
            .map_err(|e| ChainError::InvalidSignature(format!("Invalid public key: {}", e)))?;
        let sig = Signature::from_bytes(&self.signature);

        let signing_payload = self.signing_bytes(chain_id);
        verifying_key
            .verify_strict(&signing_payload, &sig)
            .map_err(|e| ChainError::InvalidSignature(format!("Ed25519 signature failure: {}", e)))
    }
}

/// Full sovereign block with header and transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherChainBlock {
    pub header: BlockHeader,
    pub transactions: Vec<CommitmentTx>,
}

/// Light client proof response verifying commitment inclusion in CipherChain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorProofResponse {
    pub chain_id: String,
    pub height: u64,
    pub block_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub commitment: [u8; 32],
    pub head_cid: [u8; 32],
    pub salt: [u8; 32],
    pub tx_index: usize,
    pub tx_proof: InclusionProof,
    pub header: BlockHeader,
    pub validator_signatures_count: usize,
}
