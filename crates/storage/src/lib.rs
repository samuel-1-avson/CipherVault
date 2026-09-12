//! # CipherVault Storage Client & Multi-Operator Pool
//!
//! Handles client-to-operator HTTPS communication, Ed25519 challenge-response sessions,
//! bounded parallel object uploads, mandatory readback integrity checks, and recovery log queries.

pub mod chain;
pub mod client;
pub mod error;
pub mod pool;
pub mod types;

pub use chain::{AnchorFinalityStage, AnchorVerificationReport, ArbitrumAnchorClient};
pub use client::OperatorClient;
pub use error::StorageError;
pub use pool::MultiOperatorPool;
pub use types::{LeaseReceipt, OperatorInfo};
