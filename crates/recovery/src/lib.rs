//! # CipherVault Offline Recovery and Bootstrap
//!
//! Handles generation, verification, and formatting of the emergency offline recovery kit,
//! envelope opening, and clean-machine discovery primitives.

pub mod error;
pub mod kit;
pub mod trust;

pub use error::RecoveryError;
pub use kit::{OfflineRecoveryKit, ThresholdRecoveryKit};
