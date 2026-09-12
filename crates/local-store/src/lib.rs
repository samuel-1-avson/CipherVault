//! # CipherVault Local Storage
//!
//! Provides transactional SQLite storage for vault configuration, device authority,
//! confidential tracked files, local encrypted chunk outbox, and snapshot history.

pub mod db;
pub mod error;

pub use db::LocalVaultStore;
pub use error::LocalStoreError;
