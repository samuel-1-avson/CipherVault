use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::metrics::OperatorMetrics;
use crate::swarm::repair::{TokenBucket, DEFAULT_REPAIR_BUDGET_PER_SEC};
use crate::swarm::SwarmHandle;
use ciphervault_chain::sync::ChainSyncHub;
use ciphervault_chain::{ChainSyncEnvelope, SovereignLedger, ValidatorSet, SOVEREIGN_CHAIN_ID_STR};
use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::{
    compute_digest, from_canonical_cbor, DeviceCertificate, EpochEnvelope, GenesisRecord,
    HeadRecord, SnapshotRecord, PROTOCOL_VERSION,
};
use ciphervault_storage::invites::JoinInvite;
use ciphervault_storage::types::LeaseReceipt;
use ciphervault_storage::vouchers::{VoucherLedger, WriteVoucher};
use ciphervault_storage::StorageError;
use sha2::{Digest, Sha256};

mod identity;
mod limits;
mod methods_chain;
mod methods_identity;
mod methods_leases;
mod methods_ledger;
mod methods_peers;
mod methods_recovery;
mod methods_sessions;

#[cfg(test)]
mod tests;

pub use identity::*;
pub use limits::*;

#[derive(Clone, Debug)]
struct ChallengeRecord {
    nonce_hex: String,
    expires_at_utc: u64,
    vault_id_hex: String,
    public_key_hex: String,
    account_id: Option<String>,
    device_id_hex: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedSession {
    token: String,
    expires_at_utc: u64,
    public_key_hex: String,
    vault_id_hex: String,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    device_id_hex: Option<String>,
}

type AccountDeviceBinding = (Option<String>, Option<String>);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedChallenge {
    challenge_id: String,
    nonce_hex: String,
    expires_at_utc: u64,
    vault_id_hex: String,
    public_key_hex: String,
    account_id: Option<String>,
    device_id_hex: Option<String>,
}

pub struct OperatorState {
    pub operator_id: String,
    pub signing_key: SigningKey,
    pub data_dir: PathBuf,
    pub security: OperatorSecurityConfig,
    // Serializes the single identities.json store (fixed temp-file persist).
    identity_lock: Mutex<()>,
    // Leaf lock serializing appends to events.log; never held while
    // acquiring any other lock (lock order is always stripe -> event).
    event_lock: Mutex<()>,
    // Per-key striped locks for objects, leases, and recovery logs.
    io_stripes: Box<[Mutex<()>]>,
    // Prometheus counters + span observer (R11).
    pub metrics: OperatorMetrics,
    // Active challenges are bound to the requested vault and device key.
    challenges: Mutex<HashMap<String, ChallengeRecord>>,
    // Active sessions: token -> expires_at_utc
    pub sessions: Mutex<HashMap<String, u64>>,
    // Authenticated caller public key: token -> public_key
    pub session_keys: Mutex<HashMap<String, [u8; 32]>>,
    // Vault scope for each authenticated session: token -> vault id hex.
    session_vaults: Mutex<HashMap<String, String>>,
    session_bindings: Mutex<HashMap<String, AccountDeviceBinding>>,
    // Explicitly enrolled device identities, persisted across restarts.
    pub enrolled_identities: Mutex<Vec<EnrolledIdentity>>,
    // Active P2P peers: operator_id -> PeerDescriptor
    pub peer_routing_table: Mutex<HashMap<String, ciphervault_storage::PeerDescriptor>>,
    // Fleet membership standing: operator_id -> PeerMembership. Missing
    // entries read as Full (pre-verified-join meshes); ticket joins
    // insert Probation. Persisted via peer-membership.json.
    peer_membership: Mutex<HashMap<String, PeerMembership>>,
    // Spent join-invite nonces: nonce_hex -> invite expiry. Single-use
    // enforcement for ticket joins; expired entries are pruned on every
    // write so the set cannot grow without bound. Persisted via
    // join-invites.json so a restart cannot double-spend a ticket.
    spent_invites: Mutex<HashMap<String, u64>>,
    // Ticket admission evidence: one record per successful join, in
    // admission order. Append-only; persisted via join-admissions.json
    // so restarts keep the full history. Read via the control-plane
    // admissions route.
    admissions: Mutex<Vec<AdmissionRecord>>,
    // Inbound fleet-join requests: one record per candidate operator id,
    // resubmits update in place. No trust granted — admission still goes
    // through tickets/graduation. Persisted via join-requests.json so the
    // inbox survives restarts. Read via the control-plane join-requests
    // route; written by the public join-request route.
    join_requests: Mutex<Vec<JoinRequestRecord>>,
    // Write-voucher spend ledger (D4): nonce -> charge. Held across
    // verify→charge→persist so concurrent writes on one voucher cannot
    // overspend (in memory or in the file). Spend survives restarts via
    // voucher-ledger.json; a corrupt file is backed up and the ledger
    // starts empty (vouchers re-pin terms on next use). Vouchers are
    // opt-in (`vouchers_required`, default false).
    voucher_ledger: Mutex<VoucherLedger>,
    voucher_ledger_failed: AtomicBool,
    // When true, writes without a voucher are rejected before persistence.
    // Default false: static mode keeps working byte-for-byte; mesh/testnet
    // operators opt in via `--require-write-vouchers`.
    vouchers_required: AtomicBool,
    // Receiver-side repair budget (Phase 4): repair bytes accepted per
    // second across all senders. Repair is a separate lane from user
    // quotas — bounded here instead of by voucher — so over-budget
    // pushes 429 without storing. Never blocks client writes.
    // Memory-only by design: a token bucket is a rate over wall-clock
    // time (`Instant`), so there is no meaningful spend to persist — a
    // restart refills to full, admitting at most one capacity burst.
    repair_budget: Mutex<TokenBucket>,
    // Live P2P swarm handle (dual mode only): set once at boot so HTTP
    // handlers can report the peer id and listeners. Memory-only.
    swarm_handle: Mutex<Option<SwarmHandle>>,
    // Sovereign chain sync slot (Phase 2 item 3): fleet validator set +
    // hub replica. The hub is absent until the set is installed; its
    // ledger opens from data_dir/chain when present and adopts certified
    // tips otherwise (unready until backfilled to genesis).
    chain_sync: Mutex<ChainSyncSlot>,
    // Out-of-band authorization challenges: challenge_id -> (ApprovalChallenge, Vec<SignedApprovalReceipt>)
    pub approval_challenges: Mutex<
        HashMap<
            String,
            (
                ciphervault_recovery::ApprovalChallenge,
                Vec<ciphervault_recovery::SignedApprovalReceipt>,
            ),
        >,
    >,
}

/// Pre-consensus admission verdict for one chain envelope. Shared by the
/// gossip path and the HTTP publish endpoint so both enforce the same
/// rule: no validator set or wrong chain is ignored, everything else that
/// fails (unparsable, non-member, bad seal) is rejected.
///
/// `Admitted` is the hot path and carries the full message inline: boxing it
/// would add a heap allocation to every envelope for no correctness gain.
#[allow(clippy::large_enum_variant)]
pub enum ChainAdmission {
    Admitted {
        sender: [u8; 32],
        msg: ciphervault_chain::sync::ChainSyncMsg,
    },
    Reject(String),
    Ignore,
}
