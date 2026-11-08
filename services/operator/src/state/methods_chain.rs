//! OperatorState: Chain admission, constructors, and sovereign hub sync.

use super::*;

impl OperatorState {
    pub fn admit_chain_envelope(&self, envelope: &ChainSyncEnvelope) -> ChainAdmission {
        let slot = lock_or_recover(&self.chain_sync, "chain_sync");
        let Some(set) = slot.validators.as_ref() else {
            return ChainAdmission::Ignore;
        };
        let msg = match envelope.open(set) {
            Ok(msg) => msg.clone(),
            Err(e) => return ChainAdmission::Reject(e.to_string()),
        };
        if msg.chain_id() != SOVEREIGN_CHAIN_ID_STR {
            return ChainAdmission::Ignore;
        }
        ChainAdmission::Admitted {
            sender: envelope.validator,
            msg,
        }
    }

    pub fn new(operator_id: String, data_dir: PathBuf, signing_key: SigningKey) -> Self {
        Self::new_with_security(
            operator_id,
            data_dir,
            signing_key,
            OperatorSecurityConfig::from_env(),
        )
    }

    pub fn new_with_security(
        operator_id: String,
        data_dir: PathBuf,
        signing_key: SigningKey,
        security: OperatorSecurityConfig,
    ) -> Self {
        fs::create_dir_all(data_dir.join("objects")).expect("operator data dir must be creatable");
        fs::create_dir_all(data_dir.join("recovery")).expect("operator data dir must be creatable");
        fs::create_dir_all(data_dir.join("leases")).expect("operator data dir must be creatable");

        let state = Self {
            operator_id,
            signing_key,
            data_dir,
            security,
            identity_lock: Mutex::new(()),
            event_lock: Mutex::new(()),
            io_stripes: (0..IO_STRIPE_COUNT)
                .map(|_| Mutex::new(()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            metrics: OperatorMetrics::new(),
            challenges: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            session_keys: Mutex::new(HashMap::new()),
            session_vaults: Mutex::new(HashMap::new()),
            session_bindings: Mutex::new(HashMap::new()),
            enrolled_identities: Mutex::new(Vec::new()),
            peer_routing_table: Mutex::new(HashMap::new()),
            peer_membership: Mutex::new(HashMap::new()),
            spent_invites: Mutex::new(HashMap::new()),
            admissions: Mutex::new(Vec::new()),
            join_requests: Mutex::new(Vec::new()),
            approval_challenges: Mutex::new(HashMap::new()),
            voucher_ledger: Mutex::new(VoucherLedger::new(u64::MAX)),
            voucher_ledger_failed: AtomicBool::new(false),
            vouchers_required: AtomicBool::new(false),
            repair_budget: Mutex::new(TokenBucket::new(DEFAULT_REPAIR_BUDGET_PER_SEC)),
            swarm_handle: Mutex::new(None),
            chain_sync: Mutex::new(ChainSyncSlot::default()),
        };
        state.load_enrolled_identities();
        state.load_sessions();
        state.load_challenges();
        state.load_peer_routing_table();
        state.load_peer_membership();
        state.load_spent_invites();
        state.load_admissions();
        state.load_join_requests();
        state.load_approval_challenges();
        state.load_voucher_ledger();
        state
    }

    /// Stores the live swarm handle at boot (dual mode only).
    pub fn set_swarm_handle(&self, handle: SwarmHandle) {
        *lock_or_recover(&self.swarm_handle, "swarm_handle") = Some(handle);
    }

    /// Clones the live swarm handle, if P2P is enabled on this node.
    pub fn swarm_handle(&self) -> Option<SwarmHandle> {
        lock_or_recover(&self.swarm_handle, "swarm_handle").clone()
    }

    /// Installs the fleet validator set authorizing chain-sync gossip. Opens
    /// the hub replica from `data_dir/chain` when blocks are present
    /// (complete when no tip snapshot lingers); otherwise the hub is
    /// created on the first adopted certified tip.
    pub fn set_chain_validators(&self, validators: ValidatorSet) {
        let mut slot = lock_or_recover(&self.chain_sync, "chain_sync");
        let dir = self.data_dir.join("chain");
        if dir.join("blocks").exists() {
            if let Ok(ledger) =
                SovereignLedger::open(SOVEREIGN_CHAIN_ID_STR, validators.clone(), &dir)
            {
                let mut hub = ChainSyncHub::new(ledger);
                if dir.join("tip.json").exists() {
                    hub.mark_syncing();
                }
                // Trust the chain over the file: replay derives in-band
                // rotations, so admission must follow the derived set. The
                // file remains the seed for fresh chains and the human's
                // declared intent.
                slot.validators = Some(hub.ledger().validator_set().clone());
                slot.hub = Some(hub);
                return;
            }
        }
        slot.validators = Some(validators);
    }

    /// Feeds an admitted chain message to the hub replica, adopting the
    /// first certified tip when no hub exists yet. `sender` is the envelope
    /// sealer (the hub re-verifies endorsements cryptographically and
    /// rejects relayed votes). Returns the hub outcome.
    pub fn ingest_chain_msg(
        &self,
        sender: [u8; 32],
        msg: ciphervault_chain::sync::ChainSyncMsg,
    ) -> ciphervault_chain::sync::IngestOutcome {
        use ciphervault_chain::sync::{ChainSyncHub, IngestOutcome};
        let mut slot = lock_or_recover(&self.chain_sync, "chain_sync");
        if slot.hub.is_none() {
            let (Some(validators), ciphervault_chain::sync::ChainSyncMsg::CertifiedBlock(block)) =
                (slot.validators.clone(), &msg)
            else {
                return IngestOutcome::Rejected(
                    "no chain replica yet: only certified tips bootstrap".to_string(),
                );
            };
            let dir = self.data_dir.join("chain");
            match ChainSyncHub::adopt_tip(
                SOVEREIGN_CHAIN_ID_STR,
                validators,
                block.clone(),
                Some(dir),
            ) {
                Ok(hub) => {
                    let height = hub.ledger().height();
                    let hash = hex::encode(hub.ledger().latest_block().header.block_hash());
                    slot.hub = Some(hub);
                    return IngestOutcome::Committed { height, hash };
                }
                Err(e) => {
                    return IngestOutcome::Rejected(format!("tip adoption failed: {e}"));
                }
            }
        }
        let hub = slot.hub.as_mut().expect("hub present");
        let outcome = hub.ingest_msg(sender, &msg);
        // Rotations commit through the hub: admission follows the chain,
        // not the operator's (possibly stale) configured file.
        if matches!(
            outcome,
            ciphervault_chain::sync::IngestOutcome::Committed { .. }
        ) {
            slot.validators = Some(hub.ledger().validator_set().clone());
        }
        outcome
    }

    /// Rebuilds the hub replica from backfilled blocks (marks complete).
    /// `genesis` must be the set that certified block 0 (served alongside
    /// the blocks); `None` (legacy peers) falls back to the hub's current
    /// set, which verifies block 0 only when no rotation ever happened.
    pub fn chain_backfill(
        &self,
        blocks: Vec<ciphervault_chain::CipherChainBlock>,
        genesis: Option<ciphervault_chain::ValidatorSet>,
    ) -> Result<(), String> {
        let mut slot = lock_or_recover(&self.chain_sync, "chain_sync");
        let hub = slot.hub.as_mut().ok_or("no chain hub".to_string())?;
        let genesis_set = genesis.unwrap_or_else(|| hub.ledger().validator_set().clone());
        hub.backfill(blocks, genesis_set)
            .map_err(|e| e.to_string())?;
        // Replay may have applied rotations: admission follows the chain.
        slot.validators = Some(hub.ledger().validator_set().clone());
        Ok(())
    }

    /// Hub replica height, if a hub exists (adopted or full).
    pub fn chain_hub_height(&self) -> Option<u64> {
        let slot = lock_or_recover(&self.chain_sync, "chain_sync");
        slot.hub.as_ref().map(|hub| hub.ledger().height())
    }

    /// Whether the hub replica holds genesis-anchored history.
    pub fn chain_hub_complete(&self) -> bool {
        let slot = lock_or_recover(&self.chain_sync, "chain_sync");
        slot.hub
            .as_ref()
            .map(|hub| hub.is_complete())
            .unwrap_or(false)
    }

    /// Backfill target when the hub exists but is unanchored; `None` when
    /// complete or absent. Single-flight is enforced by the event loop.
    pub fn chain_needs_backfill(&self) -> Option<u64> {
        let slot = lock_or_recover(&self.chain_sync, "chain_sync");
        let hub = slot.hub.as_ref()?;
        if hub.is_complete() {
            None
        } else {
            Some(hub.ledger().height())
        }
    }

    /// Serves a chain catch-up window from the hub replica. Returns the
    /// blocks, the earliest locally held height (tip snapshot when
    /// unbackfilled, genesis otherwise), and the genesis validator set that
    /// certified block 0 (disk record when present, else the hub's current
    /// set — which authenticates block 0 exactly when no rotation ever
    /// happened, since verification itself fails closed otherwise).
    pub fn chain_block_range(
        &self,
        from_height: u64,
        limit: u64,
    ) -> (
        Vec<ciphervault_chain::CipherChainBlock>,
        u64,
        Option<Vec<[u8; 32]>>,
    ) {
        let slot = lock_or_recover(&self.chain_sync, "chain_sync");
        let Some(hub) = slot.hub.as_ref() else {
            return (Vec::new(), 0, None);
        };
        let limit = (limit.min(256)) as usize;
        let mut blocks = Vec::new();
        let mut height = from_height;
        while blocks.len() < limit {
            match hub.ledger().block_at_height(height) {
                Some(block) => {
                    blocks.push(block.clone());
                    height += 1;
                }
                None => break,
            }
        }
        let genesis = self
            .chain_genesis_validators()
            .map(|set| set.validators().to_vec());
        (blocks, hub.ledger().earliest_height(), genesis)
    }

    /// The validator set that certified block 0: the on-disk genesis record
    /// when present, else the hub's current set (correct exactly when no
    /// rotation ever happened; otherwise backfill verification fails
    /// closed on block 0 and the peer must upgrade).
    pub fn chain_genesis_validators(&self) -> Option<ciphervault_chain::ValidatorSet> {
        let dir = self.data_dir.join("chain");
        match ciphervault_chain::SovereignLedger::read_genesis_validators(&dir) {
            Ok(Some(set)) => Some(set),
            _ => {
                let slot = lock_or_recover(&self.chain_sync, "chain_sync");
                slot.hub
                    .as_ref()
                    .map(|hub| hub.ledger().validator_set().clone())
            }
        }
    }
}
