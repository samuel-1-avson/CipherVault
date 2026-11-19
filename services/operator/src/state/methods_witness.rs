//! OperatorState: witness access (ADR-014 Phase 3).

use super::*;
use crate::witness_api::WitnessService;
use crate::witness_store::{WitnessConfig, WitnessStore};

impl OperatorState {
    /// Opens the witness when the configuration enables it. Called once
    /// during construction; failure is recorded, not fatal to the operator.
    pub(crate) fn open_witness(&mut self, config: &WitnessConfig) {
        self.witness = std::sync::Arc::new(if config.is_enabled() {
            WitnessService::open(&self.data_dir, config, &self.operator_id)
        } else {
            WitnessService::disabled()
        });
    }

    /// The witness service behind `/v1/witness`.
    pub fn witness_service(&self) -> std::sync::Arc<WitnessService> {
        self.witness.clone()
    }

    /// The running witness, or why there is none.
    pub fn witness(&self) -> Result<&WitnessStore, String> {
        self.witness.store().ok_or_else(|| {
            self.witness
                .error()
                .unwrap_or("witness is not enabled")
                .to_string()
        })
    }
}
