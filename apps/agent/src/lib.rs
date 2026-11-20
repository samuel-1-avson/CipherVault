//! # CipherVault Watcher Agent
//!
//! Provides background filesystem monitoring, debounced snapshot triggering,
//! coherent pre/post stat verification, and background operator replication.

pub mod guardian;
pub mod status;
pub mod watcher;

pub use guardian::{GuardianReport, GuardianViolation, LocalGuardian};
pub use status::{
    assess_liveness, read_watcher_status, WatcherLiveness, WatcherStatusRecord,
    WatcherStatusWriter, HEARTBEAT_INTERVAL_SECS, HEARTBEAT_STALE_AFTER_SECS,
};
pub use watcher::{VaultWatcher, WatcherConfig};
