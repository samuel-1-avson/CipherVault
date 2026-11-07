use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ChainError;
use crate::merkle::{hash_leaf, InclusionProof};

/// Protocol version of the CipherChain ledger.
pub const PROTOCOL_VERSION: u16 = 2;

/// Canonical Sovereign Chain numeric identifier.
pub const SOVEREIGN_CHAIN_ID_NUM: u64 = 777777;

/// Canonical Sovereign Chain string identifier.
pub const SOVEREIGN_CHAIN_ID_STR: &str = "ciphervault-sovereign-1";

/// Domain separator prefix for block signing bytes.
pub const BLOCK_SIGNING_DOMAIN: &[u8] = b"CIPHERVAULT_BLOCK_V1:";

/// Domain separator prefix for transaction signing bytes.
pub const TX_SIGNING_DOMAIN: &[u8] = b"CIPHERVAULT_TX_V1:";

/// Maximum skew between a proposal's suggested timestamp and a voter's
/// local clock for the voter to endorse it. Bounds how far a Byzantine
/// proposer can drag the pre-quorum suggestion; the committed median
/// itself is robust to f < quorum/3 liars on its own.
pub const MAX_PROPOSAL_CLOCK_SKEW_MS: u64 = 60_000;

/// Median of observed validator times (upper median, sorts in place).
/// With 2f+1 samples and at most f Byzantine voters, the result falls
/// inside the honest range — this is what v2 blocks commit as
/// `header.timestamp_ms`. Panics on an empty slice (quorum assembly
/// always holds at least one sample: the proposer's suggestion).
pub fn median_timestamp_ms(times: &mut [u64]) -> u64 {
    times.sort_unstable();
    times[times.len() / 2]
}

/// Whether a voter should endorse a proposal's suggested timestamp given
/// its local clock: strict skew bound, no grace. Voters enforce this
/// before sealing a vote; the hub does not re-check (it has no clock
/// abstraction and the quorum median is self-protecting).
pub fn proposal_time_acceptable(proposal_ms: u64, local_ms: u64) -> bool {
    proposal_ms.abs_diff(local_ms) <= MAX_PROPOSAL_CLOCK_SKEW_MS
}

/// Clamps a voter's observed time so the quorum median can never violate
/// chain monotonicity: no honest vote may predate the parent plus one
/// millisecond. Voters apply this when sealing a vote.
pub fn vote_observed_ms(local_now_ms: u64, parent_timestamp_ms: u64) -> u64 {
    local_now_ms.max(parent_timestamp_ms.saturating_add(1))
}

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
    /// Canonical signing payload for validator threshold signatures
    /// (excludes the signatures themselves) under the version-1 rule:
    /// packs `timestamp_ms` (proposer-stamped time). Kept verbatim so
    /// pre-median history keeps verifying; new code signs and verifies
    /// through [`Self::signing_payload`], which branches on
    /// `header.version`.
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
    ///
    /// Version 1 hashes the v1 signing payload plus signatures (timestamp
    /// committed inside the signed bytes). Version 2+ hashes the
    /// timestamp-free vote payload, then the finalized median timestamp,
    /// then the signatures — so the hash commits to validator-voted time
    /// while the signatures stay valid across the median substitution.
    pub fn block_hash(&self) -> [u8; 32] {
        let signing = self.signing_payload();
        let mut hasher = Sha256::new();
        hasher.update(&signing);
        if self.version >= 2 {
            hasher.update(&self.timestamp_ms.to_le_bytes());
        }
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

    /// Version-2 signing payload: everything `signing_bytes` packs EXCEPT
    /// `timestamp_ms`. Validators endorse proposal content; each voter's
    /// observed time travels alongside in `VoteMsg` and the committed
    /// timestamp is the quorum median.
    pub fn vote_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + self.chain_id.len());
        buf.extend_from_slice(BLOCK_SIGNING_DOMAIN);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(self.chain_id.as_bytes());
        buf.extend_from_slice(&[0x00]); // null separator
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.prev_block_hash);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.tx_root);
        buf.extend_from_slice(&self.proposer);
        buf
    }

    /// Payload validators actually sign and verifiers actually check:
    /// version 2+ uses [`Self::vote_bytes`], version 1 uses
    /// [`Self::signing_bytes`].
    pub fn signing_payload(&self) -> Vec<u8> {
        if self.version >= 2 {
            self.vote_bytes()
        } else {
            self.signing_bytes()
        }
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

    /// Enforces strictly-increasing per-client nonces against the last committed
    /// nonce for this transaction's client key (replay protection).
    pub fn check_nonce(&self, last_committed_nonce: u64) -> Result<(), ChainError> {
        if self.nonce <= last_committed_nonce {
            return Err(ChainError::StaleNonce {
                pubkey: hex::encode(self.client_pubkey),
                nonce: self.nonce,
                last: last_committed_nonce,
            });
        }
        Ok(())
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
