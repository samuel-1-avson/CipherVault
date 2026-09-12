//! # CipherVault Watcher Agent
//!
//! Provides background filesystem monitoring, debounced snapshot triggering,
//! coherent pre/post stat verification, and background operator replication.

pub mod watcher;

pub use watcher::{VaultWatcher, WatcherConfig};
