//! # CipherVault Local Storage
//!
//! Provides transactional SQLite storage for vault configuration, device authority,
//! confidential tracked files, local encrypted chunk outbox, and snapshot history.

pub mod account;
pub mod db;
pub mod error;
pub mod keyring;

pub use account::{
    AccountDevice, AccountError, AccountRecord, AccountSessionStatus, AccountStore, AccountVault,
};
pub use db::{
    sqlite_busy_retries, ActivityEntry, LocalVaultStore, PendingUpload, RecoveryDescriptors,
};
pub use error::LocalStoreError;
pub use keyring::{protect_secret, unprotect_secret};
