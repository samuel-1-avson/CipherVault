//! # CipherVault Storage Client & Multi-Operator Pool
//!
//! Handles client-to-operator HTTPS communication, Ed25519 challenge-response sessions,
//! bounded parallel object uploads, mandatory readback integrity checks, and recovery log queries.

pub mod chain;
pub mod client;
pub mod error;
pub mod pool;
pub mod transport;
pub mod types;
pub mod vouchers;

use sha2::{Digest, Sha256};

pub use chain::{
    AnchorFinalityStage, AnchorRelayerClient, AnchorVerificationReport, ArbitrumAnchorClient,
    RelayerReceipt,
};
pub use client::OperatorClient;
pub use error::StorageError;
pub use pool::MultiOperatorPool;
pub use transport::{HttpTransport, MemoryTransport, OperatorTransport};
pub use types::{
    ApiErrorBody, LeaseReceipt, OperatorInfo, PeerDescriptor, PosChallengeRequest,
    ProofOfStorageReceipt,
};

/// Computes the deterministic domain-separated Proof-of-Storage digest for an object.
///
/// proof = SHA-256("CIPHERVAULT-POS-V1" || cid || nonce || data)
pub fn compute_pos_proof(cid: &[u8; 32], nonce: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"CIPHERVAULT-POS-V1");
    hasher.update(cid);
    hasher.update(nonce);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
