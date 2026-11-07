//! # CipherVault Sovereign Blockchain (`ciphervault-chain`)
//!
//! Autonomous zero-gas Proof-of-Authority (PoA) consensus ledger and Merkle state
//! commitment engine for CipherVault.
//!
//! Eliminates reliance on external L1/L2 blockchains (such as Arbitrum or Ethereum),
//! third-party RPC providers (Alchemy, Infura), and gas tokens. State commitments
//! (`commitment = SHA-256(salt || head_cid)`) are anchored directly to sovereign blocks
//! endorsed by Byzantine quorum signatures of active Operator nodes.

pub mod consensus;
pub mod error;
pub mod ledger;
pub mod light_client;
pub mod merkle;
pub mod types;

pub use consensus::{ConsensusSigner, ValidatorSet};
pub use error::ChainError;
pub use ledger::{CommitmentRecord, SovereignLedger};
pub use light_client::{SovereignLightClient, SovereignVerificationResult};
pub use merkle::{hash_leaf, hash_nodes, InclusionProof, MerkleTree, EMPTY_TREE_ROOT};
pub use types::{
    AnchorProofResponse, BlockHeader, BlockSignature, CipherChainBlock, CommitmentTx,
    BLOCK_SIGNING_DOMAIN, PROTOCOL_VERSION, SOVEREIGN_CHAIN_ID_NUM, SOVEREIGN_CHAIN_ID_STR,
    TX_SIGNING_DOMAIN,
};
