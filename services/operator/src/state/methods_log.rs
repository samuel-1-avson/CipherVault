//! OperatorState: transparency-log access (ADR-014 Phase 2).
//!
//! The log is optional in the state object only so a damaged log (bad
//! key file, origin mismatch, corrupt entry) takes the log endpoints
//! down with 503 instead of taking the whole storage operator down at
//! boot. The open error is kept and logged loudly.

use super::*;
use crate::log_store::{LogConfig, LogError, LogStore};

impl OperatorState {
    /// Opens the transparency log for this operator. Called once during
    /// construction; failure is recorded, not fatal to the operator.
    pub(crate) fn open_transparency_log(&mut self, config: &LogConfig) {
        match LogStore::open(&self.data_dir, config, &self.operator_id) {
            Ok(store) => {
                let info = store.info();
                println!(
                    "  Transparency log: {} (tree size {}, key {})",
                    info.origin, info.tree_size, info.verifier_key
                );
                self.transparency_log = Some(store);
                self.transparency_log_error = None;
            }
            Err(e) => {
                eprintln!("ERROR: transparency log unavailable (log endpoints will 503): {e}");
                self.transparency_log = None;
                self.transparency_log_error = Some(e.to_string());
            }
        }
    }

    /// The operator's transparency log, or the recorded open error.
    pub fn transparency_log(&self) -> Result<&LogStore, LogError> {
        self.transparency_log.as_ref().ok_or_else(|| {
            LogError::Io(
                self.transparency_log_error
                    .clone()
                    .unwrap_or_else(|| "transparency log is not open".to_string()),
            )
        })
    }
}
