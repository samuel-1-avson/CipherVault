use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::metrics::OperatorMetrics;
use crate::swarm::repair::{TokenBucket, DEFAULT_REPAIR_BUDGET_PER_SEC};
use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::{
    compute_digest, from_canonical_cbor, DeviceCertificate, EpochEnvelope, GenesisRecord,
    HeadRecord, SnapshotRecord, PROTOCOL_VERSION,
};
use ciphervault_storage::types::LeaseReceipt;
use ciphervault_storage::vouchers::{VoucherLedger, WriteVoucher};
use ciphervault_storage::StorageError;

pub const MAX_OBJECT_SIZE: usize = 4 * 1024 * 1024; // 4 MiB max per chunk/manifest object
pub const MAX_RECOVERY_RECORD_SIZE: usize = 64 * 1024; // 64 KiB max per recovery record
pub const MAX_ACTIVE_CHALLENGES: usize = 5_000;
pub const MAX_ACTIVE_SESSIONS: usize = 5_000;
pub const MAX_RECORDS_PER_LOCATOR: usize = 10_000;
pub const MAX_RECOVERY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RELAYED_CHECKPOINTS: usize = 5_000;
pub const MAX_ACTIVE_PEERS: usize = 128;
/// Peer announces older than this are rejected at registration (replay
/// bound). Matches the routing-table prune window so accepted ⟺ retained.
pub const MAX_PEER_ANNOUNCE_AGE_SECS: u64 = 86400;
/// Peer announces farther in the future than this are rejected (clock
/// bound); without it a future-dated descriptor would never be pruned.
pub const MAX_PEER_ANNOUNCE_SKEW_SECS: u64 = 3600;
/// Number of striped filesystem locks sharding operator disk I/O (R8).
/// Distinct CIDs/locators hash to different stripes so concurrent uploads
/// for different objects no longer serialize on a single global lock.
pub const IO_STRIPE_COUNT: usize = 64;

/// Locks an operator-state mutex, recovering from poisoning with a loud
/// stderr log instead of panicking. Poison is permanent until cleared —
/// every later `lock()` would fail — so recovery is the only stay-alive
/// option; the log keeps it honest. The poison flag is cleared after the
/// single log line so later locks run silently. Recovered state is
/// whatever the panicking holder left behind; every guarded map tolerates
/// that (entries are validated on read and TTL-evicted on write).
pub(crate) fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, name: &'static str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            eprintln!("operator lock {name} poisoned; recovering with pre-panic state");
            mutex.clear_poison();
            poisoned.into_inner()
        }
    }
}

/// Parses a byte size: plain bytes (`8388608`) or suffixed kilobytes/megabytes
/// (`64KB`, `8MB`, case-insensitive, trailing `B` optional). Else `None`.
pub fn parse_byte_size(value: &str) -> Option<usize> {
    let mut text = value.trim();
    text = text.strip_suffix(['B', 'b']).unwrap_or(text);
    let (digits, multiplier) = if let Some(number) = text.strip_suffix(['M', 'm']) {
        (number, 1024 * 1024)
    } else if let Some(number) = text.strip_suffix(['K', 'k']) {
        (number, 1024)
    } else {
        (text, 1)
    };
    let number: usize = digits.trim().parse().ok()?;
    number.checked_mul(multiplier)
}

/// Reads a byte-size operator limit from the environment. Missing, invalid, or
/// below-`floor` values fall back to `default` with a stderr warning, so a typo
/// can never silently zero a limit.
pub fn operator_limit_from_env(name: &str, default: usize, floor: usize) -> usize {
    let raw = match std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
    {
        Some(value) if !value.is_empty() => value,
        _ => return default,
    };
    match parse_byte_size(&raw) {
        Some(bytes) if bytes >= floor => bytes,
        _ => {
            eprintln!("operator limit {name}={raw} invalid or below floor {floor}; using default {default}");
            default
        }
    }
}

/// Maximum accepted object size. Must fit the largest FastCDC profile chunk
/// (256 KiB) plus encryption/CBOR overhead; the floor enforces that.
pub fn max_object_size() -> usize {
    operator_limit_from_env("CIPHERVAULT_MAX_OBJECT_SIZE", MAX_OBJECT_SIZE, 512 * 1024)
}

pub fn max_recovery_record_size() -> usize {
    operator_limit_from_env(
        "CIPHERVAULT_MAX_RECOVERY_RECORD_SIZE",
        MAX_RECOVERY_RECORD_SIZE,
        4 * 1024,
    )
}

pub fn max_recovery_response_bytes() -> usize {
    operator_limit_from_env(
        "CIPHERVAULT_MAX_RECOVERY_RESPONSE_BYTES",
        MAX_RECOVERY_RESPONSE_BYTES,
        1024 * 1024,
    )
}

fn valid_account_id(value: &str) -> bool {
    let value = value.trim();
    value.len() == 39
        && value
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("cvacct_"))
        && hex::decode(&value[7..]).map(|bytes| bytes.len()) == Ok(16)
}

fn valid_device_id(value: &str) -> bool {
    hex::decode(value.trim()).map(|bytes| bytes.len()) == Ok(32)
}

fn normalize_identity_binding(
    account_id: Option<&str>,
    device_id_hex: Option<&str>,
) -> Result<(Option<String>, Option<String>), String> {
    let account_id = account_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let device_id_hex = device_id_hex
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    if let Some(account_id) = account_id.as_deref() {
        if !valid_account_id(account_id) {
            return Err("account_id must use the cvacct_<32 hex characters> format".into());
        }
    }
    if let Some(device_id_hex) = device_id_hex.as_deref() {
        if !valid_device_id(device_id_hex) {
            return Err("device_id_hex must be 32-byte hex".into());
        }
    }
    if account_id.is_none() != device_id_hex.is_none() {
        return Err("account_id and device_id_hex must be supplied together".into());
    }
    Ok((account_id, device_id_hex))
}

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
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrolledIdentity {
    pub vault_id_hex: String,
    pub public_key_hex: String,
    pub permissions: u32,
    pub enrolled_at_utc: u64,
    #[serde(default)]
    pub revoked_at_utc: Option<u64>,
    /// Optional control-plane account that owns this device identity.
    /// Older identity records remain valid with this field omitted.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Optional account device ID. When present, strict challenge issuance
    /// requires the caller to present the same device binding.
    #[serde(default)]
    pub device_id_hex: Option<String>,
}

pub struct OperatorState {
    pub operator_id: String,
    pub signing_key: SigningKey,
    pub data_dir: PathBuf,
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
    // Explicitly enrolled device identities, persisted across restarts.
    pub enrolled_identities: Mutex<Vec<EnrolledIdentity>>,
    // Relayed L2 checkpoints: commitment_hex -> RelayerReceipt
    pub relayed_checkpoints: Mutex<HashMap<String, ciphervault_storage::RelayerReceipt>>,
    // Active P2P peers: operator_id -> PeerDescriptor
    pub peer_routing_table: Mutex<HashMap<String, ciphervault_storage::PeerDescriptor>>,
    // Write-voucher spend ledger (D4): nonce -> charge. Held across
    // verify→charge so concurrent writes on one voucher cannot overspend.
    // Memory-only by design: a restart resets spend to zero, so a voucher
    // can be re-spent up to its quota after an operator restart. Bounded
    // (never more than one quota per boot) and requires operator restart
    // access; vouchers are opt-in (`vouchers_required`, default false).
    voucher_ledger: Mutex<VoucherLedger>,
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

impl OperatorState {
    pub fn new(operator_id: String, data_dir: PathBuf, signing_key: SigningKey) -> Self {
        fs::create_dir_all(data_dir.join("objects")).unwrap();
        fs::create_dir_all(data_dir.join("recovery")).unwrap();
        fs::create_dir_all(data_dir.join("leases")).unwrap();

        let state = Self {
            operator_id,
            signing_key,
            data_dir,
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
            enrolled_identities: Mutex::new(Vec::new()),
            relayed_checkpoints: Mutex::new(HashMap::new()),
            peer_routing_table: Mutex::new(HashMap::new()),
            approval_challenges: Mutex::new(HashMap::new()),
            voucher_ledger: Mutex::new(VoucherLedger::new(u64::MAX)),
            vouchers_required: AtomicBool::new(false),
            repair_budget: Mutex::new(TokenBucket::new(DEFAULT_REPAIR_BUDGET_PER_SEC)),
        };
        state.load_enrolled_identities();
        state.load_sessions();
        state.load_challenges();
        state.load_relayed_checkpoints();
        state.load_peer_routing_table();
        state.load_approval_challenges();
        state
    }

    fn identity_store_path(&self) -> PathBuf {
        self.data_dir.join("identities.json")
    }

    /// Returns the I/O stripe serializing one filesystem key (CID, lease ID,
    /// or recovery locator). FNV-1a keeps this dependency-free; only the
    /// same-key-same-stripe property matters, not cross-process stability.
    fn io_stripe(&self, key: &str) -> &Mutex<()> {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in key.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        &self.io_stripes[(hash as usize) % self.io_stripes.len()]
    }

    fn load_enrolled_identities(&self) {
        let Ok(bytes) = fs::read(self.identity_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<Vec<EnrolledIdentity>>(&bytes) else {
            return;
        };
        let mut identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
        identities.extend(records.into_iter().filter(|record| {
            hex::decode(&record.vault_id_hex).map(|b| b.len()) == Ok(32)
                && hex::decode(&record.public_key_hex).map(|b| b.len()) == Ok(32)
                && record.vault_id_hex == record.vault_id_hex.to_ascii_lowercase()
                && record.public_key_hex == record.public_key_hex.to_ascii_lowercase()
                && record.account_id.as_deref().is_none_or(valid_account_id)
                && record.device_id_hex.as_deref().is_none_or(valid_device_id)
                && record.account_id.is_some() == record.device_id_hex.is_some()
        }));
    }

    fn persist_enrolled_identities(&self) -> Result<(), String> {
        let identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities").clone();
        let encoded = serde_json::to_vec_pretty(&identities).map_err(|e| e.to_string())?;
        self.persist_atomic_secure(&self.identity_store_path(), &encoded)
    }

    fn enrollment_required() -> bool {
        std::env::var("CIPHERVAULT_OPERATOR_STRICT_AUTH")
            .ok()
            .is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes"
                )
            })
            || std::env::var("CIPHERVAULT_OPERATOR_REQUIRE_ENROLLMENT")
                .ok()
                .is_some_and(|value| {
                    matches!(
                        value.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes"
                    )
                })
    }

    pub fn is_identity_enrolled(&self, vault_id_hex: &str, public_key_hex: &str) -> bool {
        self.is_identity_enrolled_with_binding(vault_id_hex, public_key_hex, None, None)
    }

    pub fn is_identity_enrolled_with_binding(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
        account_id: Option<&str>,
        device_id_hex: Option<&str>,
    ) -> bool {
        let vault_id_hex = vault_id_hex.trim().to_ascii_lowercase();
        let public_key_hex = public_key_hex.trim().to_ascii_lowercase();
        let Ok((account_id, device_id_hex)) = normalize_identity_binding(account_id, device_id_hex)
        else {
            return false;
        };
        lock_or_recover(&self.enrolled_identities, "enrolled_identities")
            .iter()
            .any(|identity| {
                identity.revoked_at_utc.is_none()
                    && identity.vault_id_hex == vault_id_hex
                    && identity.public_key_hex == public_key_hex
                    && identity
                        .account_id
                        .as_deref()
                        .is_none_or(|bound| account_id.as_deref() == Some(bound))
                    && identity
                        .device_id_hex
                        .as_deref()
                        .is_none_or(|bound| device_id_hex.as_deref() == Some(bound))
            })
    }

    pub fn enroll_identity(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
        permissions: u32,
    ) -> Result<(), String> {
        self.enroll_identity_with_binding(vault_id_hex, public_key_hex, permissions, None, None)
    }

    pub fn enroll_identity_with_binding(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
        permissions: u32,
        account_id: Option<&str>,
        device_id_hex: Option<&str>,
    ) -> Result<(), String> {
        let vault_id_hex = vault_id_hex.trim().to_ascii_lowercase();
        let public_key_hex = public_key_hex.trim().to_ascii_lowercase();
        if hex::decode(&vault_id_hex).map(|b| b.len()) != Ok(32) {
            return Err("vault_id_hex must be 32-byte hex".into());
        }
        if hex::decode(&public_key_hex).map(|b| b.len()) != Ok(32) {
            return Err("public_key_hex must be 32-byte hex".into());
        }
        let (account_id, device_id_hex) = normalize_identity_binding(account_id, device_id_hex)?;
        let _identity_guard = lock_or_recover(&self.identity_lock, "identity_lock");
        let mut identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
        if let Some(existing) = identities.iter_mut().find(|identity| {
            identity.vault_id_hex == vault_id_hex && identity.public_key_hex == public_key_hex
        }) {
            existing.permissions = permissions;
            existing.revoked_at_utc = None;
            // An omitted binding preserves an existing enrollment binding so
            // legacy administrative updates cannot accidentally unbind a device.
            if account_id.is_some() {
                existing.account_id = account_id.clone();
                existing.device_id_hex = device_id_hex.clone();
            }
        } else {
            identities.push(EnrolledIdentity {
                vault_id_hex: vault_id_hex.clone(),
                public_key_hex: public_key_hex.clone(),
                permissions,
                enrolled_at_utc: Utc::now().timestamp().max(0) as u64,
                revoked_at_utc: None,
                account_id: account_id.clone(),
                device_id_hex: device_id_hex.clone(),
            });
        }
        drop(identities);
        self.persist_enrolled_identities()?;
        self.audit_event(
            "identity_enrolled",
            serde_json::json!({
                "vault_id_hex": vault_id_hex,
                "public_key_hex": public_key_hex,
                "permissions": permissions,
                "account_id": account_id,
                "device_id_hex": device_id_hex,
            }),
        );
        Ok(())
    }

    pub fn revoke_identity(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
    ) -> Result<bool, String> {
        let vault_id_hex = vault_id_hex.trim().to_ascii_lowercase();
        let public_key_hex = public_key_hex.trim().to_ascii_lowercase();
        let now = Utc::now().timestamp().max(0) as u64;
        let _identity_guard = lock_or_recover(&self.identity_lock, "identity_lock");
        let mut identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
        // Indices (not timestamps) identify what this call revoked: the
        // identity lock serializes enrollment against revocation, so no
        // push can shift the Vec between mark and rollback below.
        let mut revoked_indices = Vec::new();
        for (index, identity) in identities.iter_mut().enumerate().filter(|(_, identity)| {
            identity.vault_id_hex == vault_id_hex && identity.public_key_hex == public_key_hex
        }) {
            if identity.revoked_at_utc.is_none() {
                identity.revoked_at_utc = Some(now);
                revoked_indices.push(index);
            }
        }
        drop(identities);
        if revoked_indices.is_empty() {
            return Ok(false);
        }
        if let Err(error) = self.persist_enrolled_identities() {
            let mut identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
            for index in revoked_indices {
                if let Some(identity) = identities.get_mut(index) {
                    identity.revoked_at_utc = None;
                }
            }
            return Err(format!("Unable to persist identity revocation: {error}"));
        }
        let revoked_tokens: Vec<String> = lock_or_recover(&self.session_keys, "session_keys")
            .iter()
            .filter(|(_, key)| hex::encode(key) == public_key_hex)
            .map(|(token, _)| token.clone())
            .collect();
        if !revoked_tokens.is_empty() {
            let mut sessions = lock_or_recover(&self.sessions, "sessions");
            let mut keys = lock_or_recover(&self.session_keys, "session_keys");
            let mut vaults = lock_or_recover(&self.session_vaults, "session_vaults");
            let mut removed = Vec::with_capacity(revoked_tokens.len());
            for token in &revoked_tokens {
                removed.push((
                    token.clone(),
                    sessions.remove(token),
                    keys.remove(token),
                    vaults.remove(token),
                ));
            }
            drop(vaults);
            drop(keys);
            drop(sessions);
            if let Err(error) = self.persist_sessions() {
                // Disk still holds the sessions, so memory must too.
                let mut sessions = lock_or_recover(&self.sessions, "sessions");
                let mut keys = lock_or_recover(&self.session_keys, "session_keys");
                let mut vaults = lock_or_recover(&self.session_vaults, "session_vaults");
                for (token, expires_at, key, vault) in removed {
                    if let Some(expires_at) = expires_at {
                        sessions.insert(token.clone(), expires_at);
                    }
                    if let Some(key) = key {
                        keys.insert(token.clone(), key);
                    }
                    if let Some(vault) = vault {
                        vaults.insert(token, vault);
                    }
                }
                return Err(format!("Unable to persist session revocation: {error}"));
            }
        }
        self.audit_event(
            "identity_revoked",
            serde_json::json!({
                "vault_id_hex": vault_id_hex,
                "public_key_hex": public_key_hex,
                "sessions_revoked": revoked_tokens.len(),
            }),
        );
        Ok(true)
    }

    pub fn list_enrolled_identities(&self) -> Vec<EnrolledIdentity> {
        lock_or_recover(&self.enrolled_identities, "enrolled_identities").clone()
    }

    fn session_store_path(&self) -> PathBuf {
        self.data_dir.join("sessions.json")
    }

    fn challenge_store_path(&self) -> PathBuf {
        self.data_dir.join("challenges.json")
    }

    fn load_sessions(&self) {
        let Ok(bytes) = fs::read(self.session_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<Vec<PersistedSession>>(&bytes) else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut sessions = lock_or_recover(&self.sessions, "sessions");
        let mut keys = lock_or_recover(&self.session_keys, "session_keys");
        let mut vaults = lock_or_recover(&self.session_vaults, "session_vaults");
        for record in records {
            if record.expires_at_utc <= now || record.token.is_empty() {
                continue;
            }
            let Ok(key_bytes) = hex::decode(&record.public_key_hex) else {
                continue;
            };
            if key_bytes.len() != 32 || hex::decode(&record.vault_id_hex).map(|b| b.len()) != Ok(32)
            {
                continue;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            sessions.insert(record.token.clone(), record.expires_at_utc);
            keys.insert(record.token.clone(), key);
            vaults.insert(record.token, record.vault_id_hex);
        }
    }

    fn load_challenges(&self) {
        let Ok(bytes) = fs::read(self.challenge_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<Vec<PersistedChallenge>>(&bytes) else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut challenges = lock_or_recover(&self.challenges, "challenges");
        for record in records {
            if record.expires_at_utc <= now || record.challenge_id.is_empty() {
                continue;
            }
            if hex::decode(&record.nonce_hex).map(|b| b.len()) != Ok(32)
                || hex::decode(&record.vault_id_hex).map(|b| b.len()) != Ok(32)
                || hex::decode(&record.public_key_hex).map(|b| b.len()) != Ok(32)
            {
                continue;
            }
            challenges.insert(
                record.challenge_id,
                ChallengeRecord {
                    nonce_hex: record.nonce_hex,
                    expires_at_utc: record.expires_at_utc,
                    vault_id_hex: record.vault_id_hex,
                    public_key_hex: record.public_key_hex,
                    account_id: record.account_id,
                    device_id_hex: record.device_id_hex,
                },
            );
        }
    }

    fn relayed_checkpoint_store_path(&self) -> PathBuf {
        self.data_dir.join("relayed-checkpoints.json")
    }

    fn load_relayed_checkpoints(&self) {
        let Ok(bytes) = fs::read(self.relayed_checkpoint_store_path()) else {
            return;
        };
        let Ok(records) =
            serde_json::from_slice::<HashMap<String, ciphervault_storage::RelayerReceipt>>(&bytes)
        else {
            return;
        };
        let mut stored = lock_or_recover(&self.relayed_checkpoints, "relayed_checkpoints");
        for (commitment, receipt) in records {
            let tx_hash = receipt.tx_hash_hex.trim_start_matches("0x");
            if commitment.len() == 64
                && hex::decode(&commitment).is_ok()
                && receipt.commitment_hex == commitment
                && (tx_hash.is_empty() || (tx_hash.len() == 64 && hex::decode(tx_hash).is_ok()))
                && matches!(
                    receipt.status.as_str(),
                    "QueuedForRelay"
                        | "SequencerConfirmed"
                        | "ParentDataFinalized"
                        | "AssertionSettled"
                )
            {
                stored.insert(commitment, receipt);
            }
        }
    }

    fn persist_relayed_checkpoints(
        &self,
        records: &HashMap<String, ciphervault_storage::RelayerReceipt>,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.relayed_checkpoint_store_path(), &encoded)
    }

    fn peer_store_path(&self) -> PathBuf {
        self.data_dir.join("peers.json")
    }

    fn load_peer_routing_table(&self) {
        let Ok(bytes) = fs::read(self.peer_store_path()) else {
            return;
        };
        let Ok(records) =
            serde_json::from_slice::<HashMap<String, ciphervault_storage::PeerDescriptor>>(&bytes)
        else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut peers = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
        for (operator_id, peer) in records {
            if peer.operator_id == operator_id
                && peer.verify().is_ok()
                && now.saturating_sub(peer.timestamp_utc) < 86400
            {
                peers.insert(operator_id, peer);
            }
        }
    }

    fn persist_peer_routing_table(
        &self,
        records: &HashMap<String, ciphervault_storage::PeerDescriptor>,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.peer_store_path(), &encoded)
    }

    fn approval_store_path(&self) -> PathBuf {
        self.data_dir.join("approvals.json")
    }

    fn load_approval_challenges(&self) {
        let Ok(bytes) = fs::read(self.approval_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<
            HashMap<
                String,
                (
                    ciphervault_recovery::ApprovalChallenge,
                    Vec<ciphervault_recovery::SignedApprovalReceipt>,
                ),
            >,
        >(&bytes) else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut challenges = lock_or_recover(&self.approval_challenges, "approval_challenges");
        for (challenge_id, (challenge, receipts)) in records {
            if challenge.challenge_id != challenge_id || challenge.expires_at_utc <= now {
                continue;
            }
            let verified_receipts: Vec<_> = receipts
                .into_iter()
                .filter(|receipt| {
                    receipt.challenge_id == challenge_id && receipt.verify(&challenge).is_ok()
                })
                .collect();
            challenges.insert(challenge_id, (challenge, verified_receipts));
        }
    }

    fn persist_approval_challenges(
        &self,
        records: &HashMap<
            String,
            (
                ciphervault_recovery::ApprovalChallenge,
                Vec<ciphervault_recovery::SignedApprovalReceipt>,
            ),
        >,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.approval_store_path(), &encoded)
    }

    fn persist_sessions(&self) -> Result<(), String> {
        let sessions = lock_or_recover(&self.sessions, "sessions");
        let keys = lock_or_recover(&self.session_keys, "session_keys");
        let vaults = lock_or_recover(&self.session_vaults, "session_vaults");
        let records: Vec<PersistedSession> = sessions
            .iter()
            .filter_map(|(token, expires_at_utc)| {
                Some(PersistedSession {
                    token: token.clone(),
                    expires_at_utc: *expires_at_utc,
                    public_key_hex: hex::encode(keys.get(token)?),
                    vault_id_hex: vaults.get(token)?.clone(),
                })
            })
            .collect();
        let encoded = serde_json::to_vec(&records).map_err(|error| error.to_string())?;
        self.persist_atomic_secure(&self.session_store_path(), &encoded)
    }

    fn persist_challenges(&self) -> Result<(), String> {
        let challenges = lock_or_recover(&self.challenges, "challenges");
        let records: Vec<PersistedChallenge> = challenges
            .iter()
            .map(|(challenge_id, record)| PersistedChallenge {
                challenge_id: challenge_id.clone(),
                nonce_hex: record.nonce_hex.clone(),
                expires_at_utc: record.expires_at_utc,
                vault_id_hex: record.vault_id_hex.clone(),
                public_key_hex: record.public_key_hex.clone(),
                account_id: record.account_id.clone(),
                device_id_hex: record.device_id_hex.clone(),
            })
            .collect();
        let encoded = serde_json::to_vec(&records).map_err(|error| error.to_string())?;
        self.persist_atomic_secure(&self.challenge_store_path(), &encoded)
    }

    fn audit_event(&self, event: &str, fields: serde_json::Value) {
        // Leaf serialization for concurrent events.log appends. This lock is
        // taken here only and never held while acquiring another lock.
        let _event_guard = lock_or_recover(&self.event_lock, "event_lock");
        let path = self.data_dir.join("events.log");
        let payload = serde_json::json!({
            "event": event,
            "operator_id": self.operator_id,
            "timestamp_utc": Utc::now().to_rfc3339(),
            "fields": fields,
        });
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "{}", payload);
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
    }

    pub fn issue_challenge(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
    ) -> Result<(String, String, u64), String> {
        self.issue_challenge_with_binding(vault_id_hex, public_key_hex, None, None)
    }

    pub fn issue_challenge_with_binding(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
        account_id: Option<&str>,
        device_id_hex: Option<&str>,
    ) -> Result<(String, String, u64), String> {
        if hex::decode(vault_id_hex).map(|b| b.len()) != Ok(32) {
            return Err("vault_id_hex must be 32-byte hex".into());
        }
        if hex::decode(public_key_hex).map(|b| b.len()) != Ok(32) {
            return Err("public_key_hex must be 32-byte hex".into());
        }
        let (account_id, device_id_hex) = normalize_identity_binding(account_id, device_id_hex)?;
        let vault_id_hex = vault_id_hex.to_ascii_lowercase();
        let public_key_hex = public_key_hex.to_ascii_lowercase();
        if Self::enrollment_required()
            && !self.is_identity_enrolled_with_binding(
                &vault_id_hex,
                &public_key_hex,
                account_id.as_deref(),
                device_id_hex.as_deref(),
            )
        {
            return Err("device identity is not enrolled for this vault".into());
        }
        let mut id_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let challenge_id = hex::encode(id_bytes);
        let nonce_hex = hex::encode(nonce_bytes);
        let now = Utc::now().timestamp() as u64;
        let expires_at = now + 300; // 5 minutes

        let mut lock = lock_or_recover(&self.challenges, "challenges");
        // TTL eviction: remove expired challenges
        lock.retain(|_, record| record.expires_at_utc > now);
        // Quota bound: if at capacity, evict oldest
        if lock.len() >= MAX_ACTIVE_CHALLENGES {
            if let Some(oldest_key) = lock
                .iter()
                .min_by_key(|(_, record)| record.expires_at_utc)
                .map(|(k, _)| k.clone())
            {
                lock.remove(&oldest_key);
            }
        }
        lock.insert(
            challenge_id.clone(),
            ChallengeRecord {
                nonce_hex: nonce_hex.clone(),
                expires_at_utc: expires_at,
                vault_id_hex: vault_id_hex.clone(),
                public_key_hex: public_key_hex.clone(),
                account_id: account_id.clone(),
                device_id_hex: device_id_hex.clone(),
            },
        );
        drop(lock);
        if let Err(error) = self.persist_challenges() {
            lock_or_recover(&self.challenges, "challenges").remove(&challenge_id);
            return Err(format!("Unable to persist challenges: {error}"));
        }
        self.audit_event(
            "challenge_issued",
            serde_json::json!({
                "vault_id_hex": vault_id_hex,
                "public_key_hex": public_key_hex,
                "account_id": account_id,
                "device_id_hex": device_id_hex,
            }),
        );

        Ok((challenge_id, nonce_hex, expires_at))
    }

    pub fn verify_and_create_session(
        &self,
        challenge_id: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<Option<String>, String> {
        let now = Utc::now().timestamp() as u64;
        let challenge = {
            let mut lock = lock_or_recover(&self.challenges, "challenges");
            lock.remove(challenge_id)
        };
        let Some(challenge) = challenge else {
            return Ok(None);
        };
        if let Err(error) = self.persist_challenges() {
            return Err(format!("Unable to persist challenge removal: {error}"));
        }

        if now > challenge.expires_at_utc {
            return Ok(None);
        }
        if !challenge
            .public_key_hex
            .eq_ignore_ascii_case(public_key_hex)
        {
            return Ok(None);
        }
        if Self::enrollment_required()
            && !self.is_identity_enrolled_with_binding(
                &challenge.vault_id_hex,
                &challenge.public_key_hex,
                challenge.account_id.as_deref(),
                challenge.device_id_hex.as_deref(),
            )
        {
            return Ok(None);
        }

        let Some(pk_bytes) = hex::decode(public_key_hex).ok() else {
            return Ok(None);
        };
        if pk_bytes.len() != 32 {
            return Ok(None);
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);

        let Some(sig_bytes) = hex::decode(signature_hex).ok() else {
            return Ok(None);
        };
        if sig_bytes.len() != 64 {
            return Ok(None);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        let Some(nonce_bytes) = hex::decode(challenge.nonce_hex).ok() else {
            return Ok(None);
        };

        // Verify signature with domain separation
        if ciphervault_crypto::signatures::verify_with_domain(
            &pk_arr,
            b"operator_challenge",
            &nonce_bytes,
            &sig_arr,
        )
        .is_err()
        {
            return Ok(None);
        }

        // Generate session token
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let token_exp = now + 3600; // 1 hour

        let mut lock = lock_or_recover(&self.sessions, "sessions");
        // TTL eviction: remove expired sessions
        lock.retain(|_, exp| *exp > now);
        if lock.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest_token) = lock
                .iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                lock.remove(&oldest_token);
                lock_or_recover(&self.session_keys, "session_keys").remove(&oldest_token);
                lock_or_recover(&self.session_vaults, "session_vaults").remove(&oldest_token);
            }
        }
        lock.insert(token.clone(), token_exp);
        drop(lock);

        let mut key_lock = lock_or_recover(&self.session_keys, "session_keys");
        key_lock.insert(token.clone(), pk_arr);

        let mut vault_lock = lock_or_recover(&self.session_vaults, "session_vaults");
        vault_lock.insert(token.clone(), challenge.vault_id_hex);

        drop(vault_lock);
        drop(key_lock);
        if let Err(error) = self.persist_sessions() {
            // Roll back the in-memory session: without durable state the
            // login must fail cleanly rather than mint a restart-fragile one.
            lock_or_recover(&self.sessions, "sessions").remove(&token);
            lock_or_recover(&self.session_keys, "session_keys").remove(&token);
            lock_or_recover(&self.session_vaults, "session_vaults").remove(&token);
            return Err(format!("Unable to persist session: {error}"));
        }
        self.audit_event(
            "session_created",
            serde_json::json!({
                "vault_id_hex": self.get_session_vault_id(&token),
                "public_key_hex": hex::encode(pk_arr),
                "expires_at_utc": token_exp
            }),
        );

        Ok(Some(token))
    }

    pub fn revoke_session(&self, token: &str) -> Result<bool, String> {
        let removed_expires_at = lock_or_recover(&self.sessions, "sessions").remove(token);
        let removed_key = lock_or_recover(&self.session_keys, "session_keys").remove(token);
        let removed_vault = lock_or_recover(&self.session_vaults, "session_vaults").remove(token);
        let removed = removed_expires_at.is_some();
        if removed {
            if let Err(error) = self.persist_sessions() {
                // Disk still holds the session, so memory must too.
                if let Some(expires_at) = removed_expires_at {
                    lock_or_recover(&self.sessions, "sessions")
                        .insert(token.to_string(), expires_at);
                }
                if let Some(key) = removed_key {
                    lock_or_recover(&self.session_keys, "session_keys")
                        .insert(token.to_string(), key);
                }
                if let Some(vault) = removed_vault {
                    lock_or_recover(&self.session_vaults, "session_vaults")
                        .insert(token.to_string(), vault);
                }
                return Err(format!("Unable to persist session revocation: {error}"));
            }
            self.audit_event(
                "session_revoked",
                serde_json::json!({
                    "token_hash": hex::encode(compute_digest(token.as_bytes()))
                }),
            );
        }
        Ok(removed)
    }

    pub fn get_session_public_key(&self, token: &str) -> Option<[u8; 32]> {
        let lock = lock_or_recover(&self.session_keys, "session_keys");
        lock.get(token).copied()
    }

    pub fn get_session_vault_id(&self, token: &str) -> Option<String> {
        lock_or_recover(&self.session_vaults, "session_vaults")
            .get(token)
            .cloned()
    }

    pub fn validate_session_for_vault(&self, token: &str, vault_id_hex: &str) -> bool {
        let valid = self.validate_session_for_vault_inner(token, vault_id_hex);
        if !valid {
            self.metrics.observe_auth_failure();
        }
        valid
    }

    fn validate_session_for_vault_inner(&self, token: &str, vault_id_hex: &str) -> bool {
        if !self.validate_write_session(token) {
            return false;
        }
        let Some(scope) = self.get_session_vault_id(token) else {
            return false;
        };
        if !scope.eq_ignore_ascii_case(vault_id_hex) {
            return false;
        }
        if Self::enrollment_required() {
            let Some(public_key) = self.get_session_public_key(token) else {
                return false;
            };
            return self.is_identity_enrolled(&scope, &hex::encode(public_key));
        }
        true
    }

    /// Validates a session token for read-only object operations.
    /// Allows anonymous reads for disaster recovery of end-to-end encrypted ciphertext objects,
    /// or active signed session tokens.
    pub fn validate_read_session(&self, token: &str) -> bool {
        if token == "recovery_anonymous" {
            return true;
        }
        self.validate_write_session(token)
    }

    /// Validates an authenticated, challenge-signed session token for state modifications.
    /// Strictly rejects any anonymous, bypass, or expired tokens.
    pub fn validate_write_session(&self, token: &str) -> bool {
        if token.is_empty() || token == "recovery_anonymous" {
            return false;
        }
        let lock = lock_or_recover(&self.sessions, "sessions");
        if let Some(&expires_at) = lock.get(token) {
            Utc::now().timestamp() as u64 <= expires_at
        } else {
            false
        }
    }

    pub fn validate_session(&self, token: &str) -> bool {
        self.validate_write_session(token)
    }

    /// Enables voucher enforcement: writes without a valid voucher are
    /// rejected before persistence. Default off (static mode unchanged).
    pub fn set_vouchers_required(&self, required: bool) {
        self.vouchers_required.store(required, Ordering::SeqCst);
    }

    pub fn vouchers_required(&self) -> bool {
        self.vouchers_required.load(Ordering::SeqCst)
    }

    /// Caps the largest single voucher grant this operator honors.
    pub fn set_voucher_max_quota(&self, max_quota_bytes: u64) {
        lock_or_recover(&self.voucher_ledger, "voucher_ledger").set_max_quota(max_quota_bytes);
    }

    /// Self-issues a voucher (D3 barter model): this operator's key signs a
    /// grant the operator itself will honor. Served over HTTP with service-
    /// token auth; never over P2P (no operator-admin surface there).
    pub fn issue_voucher(
        &self,
        holder_pk_hex: String,
        quota_bytes: u64,
        ttl_secs: u64,
    ) -> Result<WriteVoucher, StorageError> {
        WriteVoucher::issue(&self.signing_key, holder_pk_hex, quota_bytes, ttl_secs)
    }

    fn issuer_pk_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Pre-persistence write gate shared by all transports: verifies the
    /// presented voucher and charges `bytes`, or rejects voucherless writes
    /// when policy requires vouchers. Returns the charge to release if
    /// persistence fails or stores no new bytes.
    fn authorize_write(
        &self,
        voucher: Option<&WriteVoucher>,
        bytes: u64,
    ) -> Result<Option<(String, u64)>, StorageError> {
        match voucher {
            Some(voucher) => {
                let mut ledger = lock_or_recover(&self.voucher_ledger, "voucher_ledger");
                let now = chrono::Utc::now().timestamp() as u64;
                ledger.try_consume(voucher, &self.issuer_pk_hex(), now, bytes)?;
                Ok(Some((voucher.nonce_hex.clone(), bytes)))
            }
            None if self.vouchers_required() => Err(StorageError::ServerError {
                status: 403,
                message: "write voucher required".into(),
            }),
            None => Ok(None),
        }
    }

    fn release_write(&self, charge: Option<(String, u64)>) {
        if let Some((nonce, bytes)) = charge {
            lock_or_recover(&self.voucher_ledger, "voucher_ledger").release(&nonce, bytes);
        }
    }

    /// Legacy policy gate for the original write methods: identical behavior
    /// when policy is off, hard rejection when on. Keeps frozen callers
    /// compiling and behaving while closing the voucherless bypass.
    fn require_voucher_legacy(&self) -> Result<(), String> {
        if self.vouchers_required() {
            return Err("write voucher required".into());
        }
        Ok(())
    }

    pub fn put_object(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), String> {
        self.require_voucher_legacy()?;
        let started = std::time::Instant::now();
        let outcome = self.put_object_inner(cid_hex, bytes).map(|_| ());
        self.metrics
            .observe_put(bytes.len() as u64, started.elapsed(), outcome.is_ok());
        outcome
    }

    /// Overrides the receiver-side repair budget (bytes/sec). Tests and
    /// operators tune the repair lane without touching client quotas.
    pub fn set_repair_budget(&self, bytes_per_sec: u64) {
        lock_or_recover(&self.repair_budget, "repair_budget").set_rate(bytes_per_sec);
    }

    /// Spends `bytes` from the repair budget. False means the push must
    /// 429 without storing.
    pub fn try_spend_repair_budget(&self, bytes: u64) -> bool {
        lock_or_recover(&self.repair_budget, "repair_budget").try_take(bytes)
    }

    /// Persists one operator-signed repair push. Runs the SAME validation
    /// as client puts (size cap, digest match, atomic persist) but skips
    /// the voucher/quota lane — repair is bounded by the repair budget
    /// instead (checked by the caller BEFORE invoking this). Returns
    /// whether the bytes were net-new. Deliberately absent from
    /// `objects_put_*` metrics: repair has its own telemetry series.
    pub fn put_repair_object(&self, cid_hex: &str, bytes: &[u8]) -> Result<bool, String> {
        self.put_object_inner(cid_hex, bytes)
    }

    /// Whether the store holds a complete object for `cid_hex` (atomic
    /// renames mean presence implies completeness). Metadata-only: the
    /// repair scanner filters candidates without reading bytes.
    pub fn has_object(&self, cid_hex: &str) -> bool {
        cid_hex.len() == 64 && self.data_dir.join("objects").join(cid_hex).is_file()
    }

    /// Lists locally stored object CIDs for the repair scanner: up to
    /// `limit` entries past `offset`, in directory order. Unparseable
    /// names (tmp files, future layouts) are skipped, never errors. A
    /// short return (fewer than `limit`) signals the cursor should wrap.
    pub fn list_object_cids(&self, offset: usize, limit: usize) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        if limit == 0 {
            return out;
        }
        let entries = match fs::read_dir(self.data_dir.join("objects")) {
            Ok(entries) => entries,
            Err(_) => return out,
        };
        for entry in entries.filter_map(|entry| entry.ok()).skip(offset) {
            if out.len() >= limit {
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() != 64 {
                continue;
            }
            let Ok(raw) = hex::decode(&name) else {
                continue;
            };
            if raw.len() != 32 {
                continue;
            }
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&raw);
            out.push(cid);
        }
        out
    }

    /// Voucher-carrying put: verifies the voucher, charges quota only for
    /// bytes not already stored, then persists. The pre-check keeps
    /// idempotent retries free even with the quota fully spent (mesh repair
    /// depends on this); objects are content-addressed and never deleted,
    /// so a present pre-check stays present. Any race the other way (absent
    /// at pre-check, stored by a concurrent put) releases after the fact.
    /// Inner errors keep the legacy 400 mapping.
    pub fn put_object_with_voucher(
        &self,
        cid_hex: &str,
        bytes: &[u8],
        voucher: Option<&WriteVoucher>,
    ) -> Result<(), StorageError> {
        let already_present = self.object_matches(cid_hex, bytes);
        let billable = if already_present {
            0
        } else {
            bytes.len() as u64
        };
        let charge = self.authorize_write(voucher, billable)?;
        let started = std::time::Instant::now();
        let outcome = self.put_object_inner(cid_hex, bytes);
        self.metrics
            .observe_put(bytes.len() as u64, started.elapsed(), outcome.is_ok());
        match outcome {
            Ok(net_new) => {
                if !net_new {
                    self.release_write(charge);
                }
                Ok(())
            }
            Err(e) => {
                self.release_write(charge);
                Err(StorageError::ServerError {
                    status: 400,
                    message: e,
                })
            }
        }
    }

    /// Best-effort idempotency pre-check: true only if the object file
    /// exists with byte-identical content. False on any doubt (missing,
    /// unreadable, malformed CID) — the inner write then validates fully.
    fn object_matches(&self, cid_hex: &str, bytes: &[u8]) -> bool {
        if cid_hex.len() != 64 {
            return false;
        }
        let obj_path = self.data_dir.join("objects").join(cid_hex);
        fs::read(&obj_path).ok().as_deref() == Some(bytes)
    }

    fn put_object_inner(&self, cid_hex: &str, bytes: &[u8]) -> Result<bool, String> {
        let limit = max_object_size();
        if bytes.len() > limit {
            return Err(format!(
                "Object exceeds maximum size limit of {} bytes",
                limit
            ));
        }
        if cid_hex.len() != 64 {
            return Err("Invalid CID length (must be 64 hex characters)".into());
        }
        let expected_digest = hex::decode(cid_hex).map_err(|e| e.to_string())?;
        if expected_digest.len() != 32 {
            return Err("Invalid CID digest length".into());
        }
        let actual_digest = compute_digest(bytes);

        if actual_digest.as_slice() != expected_digest.as_slice() {
            return Err("Digest mismatch".into());
        }

        let _stripe_guard = lock_or_recover(self.io_stripe(cid_hex), "io_stripe");
        let obj_path = self.data_dir.join("objects").join(cid_hex);
        if fs::read(&obj_path).ok().as_deref() != Some(bytes) {
            self.persist_atomic(&obj_path, bytes)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn get_object(&self, cid_hex: &str) -> Option<Vec<u8>> {
        let started = std::time::Instant::now();
        let outcome = self.get_object_inner(cid_hex);
        self.metrics.observe_get(
            outcome.as_ref().map(|bytes| bytes.len() as u64),
            started.elapsed(),
        );
        outcome
    }

    fn get_object_inner(&self, cid_hex: &str) -> Option<Vec<u8>> {
        if cid_hex.len() != 64 || hex::decode(cid_hex).is_err() {
            return None;
        }
        let obj_path = self.data_dir.join("objects").join(cid_hex);
        fs::read(obj_path).ok()
    }

    /// Computes and signs a cryptographic Proof-of-Storage receipt for a challenged object.
    pub fn generate_pos_proof(
        &self,
        cid_hex: &str,
        nonce: &[u8; 32],
    ) -> Result<ciphervault_storage::ProofOfStorageReceipt, String> {
        let started = std::time::Instant::now();
        let outcome = self.generate_pos_proof_inner(cid_hex, nonce);
        self.metrics.observe_pos(started.elapsed(), outcome.is_ok());
        outcome
    }

    fn generate_pos_proof_inner(
        &self,
        cid_hex: &str,
        nonce: &[u8; 32],
    ) -> Result<ciphervault_storage::ProofOfStorageReceipt, String> {
        if cid_hex.len() != 64 {
            return Err("Invalid CID length (must be 64 hex characters)".into());
        }
        let cid_bytes = hex::decode(cid_hex).map_err(|e| e.to_string())?;
        if cid_bytes.len() != 32 {
            return Err("Invalid CID digest length".into());
        }
        let mut cid_arr = [0u8; 32];
        cid_arr.copy_from_slice(&cid_bytes);

        let obj_path = self.data_dir.join("objects").join(cid_hex);
        let bytes = fs::read(&obj_path).map_err(|_| "Object not found".to_string())?;

        let proof = ciphervault_storage::compute_pos_proof(&cid_arr, nonce, &bytes);

        let mut receipt = ciphervault_storage::ProofOfStorageReceipt {
            operator_id: self.operator_id.clone(),
            cid_hex: cid_hex.to_lowercase(),
            nonce_hex: hex::encode(nonce),
            proof_hex: hex::encode(proof),
            signature_hex: String::new(),
            size_bytes: bytes.len() as u64,
        };

        let msg = receipt.signing_bytes();
        let sig = ciphervault_crypto::signatures::sign_with_domain(
            &self.signing_key,
            b"operator_pos",
            &msg,
        );
        receipt.signature_hex = hex::encode(sig);

        Ok(receipt)
    }

    fn persist_atomic(&self, path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
        self.persist_atomic_inner(path, bytes, false)
    }

    /// Atomic + fsynced persist for secret-bearing stores (sessions,
    /// challenges, enrolled identities). On unix the temp file is created
    /// 0600, so bearer tokens are never visible at wider perms — not even
    /// between creation and rename. Rename carries the mode to `path`.
    fn persist_atomic_secure(&self, path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
        self.persist_atomic_inner(path, bytes, true)
    }

    fn persist_atomic_inner(
        &self,
        path: &std::path::Path,
        bytes: &[u8],
        secure: bool,
    ) -> Result<(), String> {
        #[cfg(not(unix))]
        let _ = secure;
        let temp = path.with_extension(format!("{}.tmp", rand::random::<u128>()));
        let result = (|| -> std::io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            if secure {
                opts.mode(0o600);
            }
            let mut file = opts.open(&temp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, path)?;
            #[cfg(unix)]
            std::fs::File::open(path.parent().unwrap())?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(|e| e.to_string())
    }

    fn persist_lease(&self, mut receipt: LeaseReceipt) -> Result<LeaseReceipt, String> {
        receipt.signature_hex = hex::encode(sign_with_domain(
            &self.signing_key,
            b"operator_lease",
            &receipt.signing_bytes(),
        ));
        let path = self
            .data_dir
            .join("leases")
            .join(format!("{}.json", receipt.lease_id));
        let serialized = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        self.persist_atomic(&path, &serialized)?;
        Ok(receipt)
    }

    pub fn create_lease(
        &self,
        closure_digest_hex: &str,
        bytes: u64,
        term_days: u32,
    ) -> Result<LeaseReceipt, String> {
        self.require_voucher_legacy()?;
        let outcome = self.create_lease_inner(closure_digest_hex, bytes, term_days);
        self.metrics.observe_lease_create(outcome.is_ok());
        outcome
    }

    /// Voucher-carrying lease commit: the voucher authorizes, nothing is
    /// charged (leases store no bytes). Inner errors keep the legacy 500
    /// mapping.
    pub fn create_lease_with_voucher(
        &self,
        closure_digest_hex: &str,
        bytes: u64,
        term_days: u32,
        voucher: Option<&WriteVoucher>,
    ) -> Result<LeaseReceipt, StorageError> {
        self.authorize_write(voucher, 0)?;
        let outcome = self.create_lease_inner(closure_digest_hex, bytes, term_days);
        self.metrics.observe_lease_create(outcome.is_ok());
        outcome.map_err(|e| StorageError::ServerError {
            status: 500,
            message: e,
        })
    }

    fn create_lease_inner(
        &self,
        closure_digest_hex: &str,
        bytes: u64,
        term_days: u32,
    ) -> Result<LeaseReceipt, String> {
        if closure_digest_hex.len() != 64
            || hex::decode(closure_digest_hex).is_err()
            || term_days == 0
        {
            return Err("Invalid closure digest or retention term".into());
        }
        let _stripe_guard = lock_or_recover(self.io_stripe(closure_digest_hex), "io_stripe");
        let now = Utc::now().timestamp() as u64;
        self.persist_lease(LeaseReceipt {
            lease_id: hex::encode(rand::random::<[u8; 16]>()),
            operator_id: self.operator_id.clone(),
            closure_digest_hex: closure_digest_hex.into(),
            term_days,
            bytes,
            issued_at_utc: now,
            expires_at_utc: now + u64::from(term_days) * 86400,
            signature_hex: String::new(),
        })
    }

    pub fn renew_lease(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
    ) -> Result<LeaseReceipt, String> {
        self.require_voucher_legacy()?;
        let outcome = self.renew_lease_inner(lease_id, additional_days, bytes);
        self.metrics.observe_lease_renew(outcome.is_ok());
        outcome
    }

    /// Voucher-carrying lease renewal: authorizes without charging (no new
    /// bytes). Inner errors keep the legacy 400 mapping.
    pub fn renew_lease_with_voucher(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
        voucher: Option<&WriteVoucher>,
    ) -> Result<LeaseReceipt, StorageError> {
        self.authorize_write(voucher, 0)?;
        let outcome = self.renew_lease_inner(lease_id, additional_days, bytes);
        self.metrics.observe_lease_renew(outcome.is_ok());
        outcome.map_err(|e| StorageError::ServerError {
            status: 400,
            message: e,
        })
    }

    fn renew_lease_inner(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
    ) -> Result<LeaseReceipt, String> {
        if lease_id.len() != 32 || hex::decode(lease_id).is_err() || additional_days == 0 {
            return Err("Invalid lease ID or retention term".into());
        }
        let _stripe_guard = lock_or_recover(self.io_stripe(lease_id), "io_stripe");
        let path = self
            .data_dir
            .join("leases")
            .join(format!("{}.json", lease_id));
        let mut receipt: LeaseReceipt =
            serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        receipt
            .verify(&self.signing_key.verifying_key().to_bytes())
            .map_err(|e| e.to_string())?;
        if receipt.bytes != bytes {
            return Err("Lease byte count mismatch".into());
        }
        receipt.term_days = receipt
            .term_days
            .checked_add(additional_days)
            .ok_or("Retention overflow")?;
        receipt.expires_at_utc = receipt
            .expires_at_utc
            .max(Utc::now().timestamp() as u64)
            .checked_add(u64::from(additional_days) * 86400)
            .ok_or("Expiry overflow")?;
        self.persist_lease(receipt)
    }

    pub fn append_authorized_recovery_record(
        &self,
        locator_hex: &str,
        record: &[u8],
        caller_pk: Option<&[u8; 32]>,
    ) -> Result<u64, String> {
        self.require_voucher_legacy()?;
        let outcome = self.append_authorized_recovery_record_inner(locator_hex, record, caller_pk);
        self.metrics
            .observe_recovery_append(record.len() as u64, outcome.is_ok());
        outcome
    }

    /// Voucher-carrying recovery append: authorizes and charges quota before
    /// touching disk, releases the charge when persistence fails. Appends
    /// always store new bytes, so success never releases. Inner errors keep
    /// the legacy 400 mapping.
    pub fn append_recovery_record_with_voucher(
        &self,
        locator_hex: &str,
        record: &[u8],
        caller_pk: Option<&[u8; 32]>,
        voucher: Option<&WriteVoucher>,
    ) -> Result<u64, StorageError> {
        let charge = self.authorize_write(voucher, record.len() as u64)?;
        let outcome = self.append_authorized_recovery_record_inner(locator_hex, record, caller_pk);
        self.metrics
            .observe_recovery_append(record.len() as u64, outcome.is_ok());
        match outcome {
            Ok(sequence) => Ok(sequence),
            Err(e) => {
                self.release_write(charge);
                Err(StorageError::ServerError {
                    status: 400,
                    message: e,
                })
            }
        }
    }

    fn append_authorized_recovery_record_inner(
        &self,
        locator_hex: &str,
        record: &[u8],
        caller_pk: Option<&[u8; 32]>,
    ) -> Result<u64, String> {
        if locator_hex.len() != 64 || hex::decode(locator_hex).is_err() {
            return Err("Invalid recovery locator (must be 64 hex characters)".into());
        }
        let limit = max_recovery_record_size();
        if record.len() > limit {
            return Err(format!(
                "Record exceeds maximum size limit of {} bytes",
                limit
            ));
        }

        // Cryptographic Authorization Check
        // Inspect existing records to find registered recovery_signing_pk and authorized device public keys.
        let existing = self.get_recovery_records_inner(locator_hex);
        if existing.len() >= MAX_RECORDS_PER_LOCATOR {
            return Err(format!(
                "Locator recovery log capacity limit of {} records exceeded",
                MAX_RECORDS_PER_LOCATOR
            ));
        }

        let mut registered_recovery_pk: Option<[u8; 32]> = None;
        let mut authorized_device_pks: Vec<[u8; 32]> = Vec::new();

        for r in &existing {
            if let Ok(genesis) = from_canonical_cbor::<GenesisRecord>(r) {
                if genesis.verify().is_ok() && genesis.recovery_signing_pk.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&genesis.recovery_signing_pk);
                    registered_recovery_pk = Some(pk);
                }
            }
        }

        for r in &existing {
            if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(r) {
                if let Some(r_pk) = registered_recovery_pk {
                    if cert.verify(&r_pk).is_ok() && cert.device_signing_pk.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&cert.device_signing_pk);
                        if !authorized_device_pks.contains(&pk) {
                            authorized_device_pks.push(pk);
                        }
                    }
                }
            }
        }

        // Verify incoming record against authority
        let mut is_authorized = false;

        // 1. GenesisRecord: Must be signed by recovery authority. If one already registered, must match it.
        if let Ok(genesis) = from_canonical_cbor::<GenesisRecord>(record) {
            if genesis.version == PROTOCOL_VERSION
                && genesis.verify().is_ok()
                && genesis.recovery_signing_pk.len() == 32
            {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&genesis.recovery_signing_pk);
                if let Some(existing_pk) = registered_recovery_pk {
                    if existing_pk == pk {
                        is_authorized = true;
                    }
                } else {
                    is_authorized = true;
                }
            }
        }

        // 2. DeviceCertificate: Must be signed by registered recovery authority (r_pk)
        if !is_authorized {
            if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(record) {
                if cert.version == PROTOCOL_VERSION && cert.device_signing_pk.len() == 32 {
                    if let Some(r_pk) = registered_recovery_pk {
                        if cert.verify(&r_pk).is_ok() {
                            is_authorized = true;
                        }
                    }
                }
            }
        }

        // 3. HeadRecord: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(head) = from_canonical_cbor::<HeadRecord>(record) {
                if head.version == PROTOCOL_VERSION && head.snapshot_id.len() == 32 {
                    for d_pk in &authorized_device_pks {
                        if head.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if head.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        // 4. EpochEnvelope: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(envelope) = from_canonical_cbor::<EpochEnvelope>(record) {
                if envelope.version == PROTOCOL_VERSION
                    && envelope.recipient_fingerprint.len() == 32
                {
                    for d_pk in &authorized_device_pks {
                        if envelope.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if envelope.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        // 5. SnapshotRecord: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(snap) = from_canonical_cbor::<SnapshotRecord>(record) {
                if snap.version == PROTOCOL_VERSION {
                    for d_pk in &authorized_device_pks {
                        if snap.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if snap.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        if !is_authorized {
            return Err("Record failed cryptographic authorization against registered vault recovery key or authorized device certificate".into());
        }

        // Caller authorization check:
        // Once recovery authority is registered, any caller modifying the log MUST be either
        // the recovery authority or one of the certified device public keys.
        if let Some(c_pk) = caller_pk {
            if let Some(r_pk) = registered_recovery_pk {
                let newly_certified_pk =
                    if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(record) {
                        if cert.verify(&r_pk).is_ok() && cert.device_signing_pk.len() == 32 {
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(&cert.device_signing_pk);
                            Some(pk)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                let is_trusted_caller = c_pk == &r_pk
                    || authorized_device_pks.contains(c_pk)
                    || newly_certified_pk.as_ref() == Some(c_pk);
                if !is_trusted_caller {
                    return Err(
                        "Caller session key is not authorized for this vault locator".into(),
                    );
                }
            }
        }

        let _stripe_guard = lock_or_recover(self.io_stripe(locator_hex), "io_stripe");
        let log_path = self
            .data_dir
            .join("recovery")
            .join(format!("{}.log", locator_hex));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| e.to_string())?;

        // Format: [4 bytes length prefix in big endian][record bytes]
        let len = (record.len() as u32).to_be_bytes();
        let original_len = file.metadata().map_err(|e| e.to_string())?.len();
        if let Err(e) = file
            .write_all(&len)
            .and_then(|_| file.write_all(record))
            .and_then(|_| file.sync_all())
        {
            let _ = file.set_len(original_len);
            let _ = file.sync_all();
            return Err(e.to_string());
        }

        Ok(1)
    }

    pub fn append_recovery_record(&self, locator_hex: &str, record: &[u8]) -> Result<u64, String> {
        self.append_authorized_recovery_record(locator_hex, record, None)
    }

    pub fn get_recovery_records(&self, locator_hex: &str) -> Vec<Vec<u8>> {
        let records = self.get_recovery_records_inner(locator_hex);
        self.metrics.observe_recovery_read(&records);
        records
    }

    fn get_recovery_records_inner(&self, locator_hex: &str) -> Vec<Vec<u8>> {
        if locator_hex.len() != 64 || hex::decode(locator_hex).is_err() {
            return Vec::new();
        }
        let _stripe_guard = lock_or_recover(self.io_stripe(locator_hex), "io_stripe");
        let log_path = self
            .data_dir
            .join("recovery")
            .join(format!("{}.log", locator_hex));
        if !log_path.exists() {
            return Vec::new();
        }

        let data = match fs::read(log_path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::new();
        let mut cursor = 0;
        while cursor + 4 <= data.len() {
            let len = u32::from_be_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;
            cursor += 4;
            if cursor + len <= data.len() {
                out.push(data[cursor..cursor + len].to_vec());
                cursor += len;
            } else {
                break;
            }
        }
        out
    }

    /// Submits and registers an L2 commitment checkpoint through the relayer.
    pub fn relay_checkpoint(
        &self,
        evidence: &ciphervault_format::CheckpointEvidence,
    ) -> Result<ciphervault_storage::RelayerReceipt, String> {
        if !evidence.verify_commitment() {
            return Err(
                "Invalid commitment preimage math: salt and head do not match commitment".into(),
            );
        }

        let commitment_hex = hex::encode(&evidence.commitment);
        let mut lock = lock_or_recover(&self.relayed_checkpoints, "relayed_checkpoints");
        if let Some(existing) = lock.get(&commitment_hex) {
            return Ok(existing.clone());
        }
        if lock.len() >= MAX_RELAYED_CHECKPOINTS {
            return Err("Relayer checkpoint capacity reached".into());
        }

        // Client-supplied transaction hashes and block numbers are hints only.
        // Keep every new checkpoint pending until a trusted RPC verifier has
        // independently checked the receipt and registry inclusion.
        let receipt = ciphervault_storage::RelayerReceipt {
            commitment_hex: commitment_hex.clone(),
            tx_hash_hex: String::new(),
            block_number: 0,
            status: "QueuedForRelay".to_string(),
            timestamp: Utc::now().timestamp() as u64,
        };

        lock.insert(commitment_hex.clone(), receipt.clone());
        let snapshot = lock.clone();
        if let Err(error) = self.persist_relayed_checkpoints(&snapshot) {
            lock.remove(&commitment_hex);
            return Err(format!("Unable to persist relayed checkpoint: {error}"));
        }
        Ok(receipt)
    }

    /// Marks a queued checkpoint as confirmed only after an independent RPC
    /// verifier has validated its receipt and registry inclusion. This method
    /// intentionally accepts the verifier's report separately so callers
    /// cannot promote a client-supplied block/transaction pair by themselves.
    pub fn confirm_relayed_checkpoint(
        &self,
        evidence: &ciphervault_format::CheckpointEvidence,
        report: &ciphervault_storage::AnchorVerificationReport,
    ) -> Result<ciphervault_storage::RelayerReceipt, String> {
        if !report.preimage_valid || !report.on_chain_confirmed || !report.receipt_verified {
            return Err("Checkpoint has no independently verified on-chain receipt".into());
        }
        if report.commitment_hex != hex::encode(&evidence.commitment)
            || report.receipt_block_number.is_none()
            || evidence.tx_hash.len() != 32
            || evidence.tx_hash.iter().all(|byte| *byte == 0)
        {
            return Err("Independent checkpoint receipt does not match evidence".into());
        }
        let commitment_hex = hex::encode(&evidence.commitment);
        let tx_hash_hex = hex::encode(&evidence.tx_hash);
        let block_number = report
            .receipt_block_number
            .ok_or_else(|| "Verified checkpoint receipt has no block number".to_string())?;
        let mut lock = lock_or_recover(&self.relayed_checkpoints, "relayed_checkpoints");
        let existing = lock
            .get_mut(&commitment_hex)
            .ok_or_else(|| "Checkpoint is not queued for relay".to_string())?;
        let previous = existing.clone();
        existing.tx_hash_hex = tx_hash_hex;
        existing.block_number = block_number;
        existing.status = "SequencerConfirmed".to_string();
        let updated = existing.clone();
        let snapshot = lock.clone();
        if let Err(error) = self.persist_relayed_checkpoints(&snapshot) {
            lock.insert(commitment_hex, previous);
            return Err(format!("Unable to persist relayed checkpoint: {error}"));
        }
        Ok(updated)
    }

    /// Updates the on-chain settlement status of a relayed checkpoint once mined.
    pub fn update_relayed_checkpoint(
        &self,
        commitment_hex: &str,
        tx_hash_hex: &str,
        block_number: u64,
        status: &str,
    ) -> Option<ciphervault_storage::RelayerReceipt> {
        let mut lock = lock_or_recover(&self.relayed_checkpoints, "relayed_checkpoints");
        if let Some(existing) = lock.get_mut(commitment_hex) {
            let previous = existing.clone();
            existing.tx_hash_hex = tx_hash_hex.to_string();
            existing.block_number = block_number;
            existing.status = status.to_string();
            let updated = existing.clone();
            let snapshot = lock.clone();
            if self.persist_relayed_checkpoints(&snapshot).is_err() {
                lock.insert(commitment_hex.to_string(), previous);
                return None;
            }
            Some(updated)
        } else {
            None
        }
    }

    /// Queries an existing relayed L2 checkpoint receipt by its commitment hex.
    pub fn get_relayed_checkpoint(
        &self,
        commitment_hex: &str,
    ) -> Option<ciphervault_storage::RelayerReceipt> {
        let lock = lock_or_recover(&self.relayed_checkpoints, "relayed_checkpoints");
        lock.get(commitment_hex).cloned()
    }

    /// Registers a gossip peer announcement in the active routing table.
    pub fn register_peer(
        &self,
        peer: ciphervault_storage::PeerDescriptor,
    ) -> Result<usize, String> {
        peer.verify()
            .map_err(|e| format!("Invalid peer signature: {}", e))?;
        // Freshness: the timestamp is signature-covered, so these bounds
        // close replay of stale announces and immortal future-dated ones.
        // Covers the HTTP route, the P2P mirror, and test callers alike.
        let now = Utc::now().timestamp() as u64;
        if peer.timestamp_utc > now.saturating_add(MAX_PEER_ANNOUNCE_SKEW_SECS) {
            return Err("Peer announcement timestamp is too far in the future".into());
        }
        if now.saturating_sub(peer.timestamp_utc) >= MAX_PEER_ANNOUNCE_AGE_SECS {
            return Err("Peer announcement is stale".into());
        }
        let endpoint = peer.endpoint.trim();
        if !(endpoint.starts_with("https://") || endpoint.starts_with("http://"))
            || endpoint.contains('@')
            || endpoint.bytes().any(|byte| byte < 0x20)
        {
            return Err("Peer endpoint must be an absolute HTTP(S) URL without credentials".into());
        }
        if let Ok(allowed) = std::env::var("CIPHERVAULT_TRUSTED_PEER_KEYS") {
            let trusted = allowed
                .split(',')
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .any(|value| value == peer.signing_pk_hex.to_ascii_lowercase());
            if !trusted {
                return Err("Peer signing key is not in the configured trust registry".into());
            }
        }
        let mut lock = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
        let now = Utc::now().timestamp() as u64;
        lock.retain(|_, p| now.saturating_sub(p.timestamp_utc) < 86400);
        if !lock.contains_key(&peer.operator_id) && lock.len() >= MAX_ACTIVE_PEERS {
            return Err("Peer routing table capacity reached".into());
        }
        let peer_id = peer.operator_id.clone();
        lock.insert(peer_id.clone(), peer);
        let snapshot = lock.clone();
        if let Err(error) = self.persist_peer_routing_table(&snapshot) {
            lock.remove(&peer_id);
            return Err(format!("Unable to persist peer routing table: {error}"));
        }
        Ok(lock.len())
    }

    /// Retrieves all currently active and unexpired peer operators in the cluster.
    pub fn get_active_peers(&self) -> Vec<ciphervault_storage::PeerDescriptor> {
        let now = Utc::now().timestamp() as u64;
        let mut lock = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
        lock.retain(|_, peer| now.saturating_sub(peer.timestamp_utc) < 86400);
        lock.values().cloned().collect()
    }

    /// Registers a pending out-of-band authorization challenge.
    pub fn register_approval_challenge(
        &self,
        challenge: ciphervault_recovery::ApprovalChallenge,
    ) -> Result<(), String> {
        if challenge.is_expired() {
            return Err("Challenge is already expired".into());
        }
        let mut lock = lock_or_recover(&self.approval_challenges, "approval_challenges");
        let now = Utc::now().timestamp() as u64;
        lock.retain(|_, (c, _)| c.expires_at_utc > now);
        let challenge_id = challenge.challenge_id.clone();
        lock.insert(challenge_id.clone(), (challenge, Vec::new()));
        let snapshot = lock.clone();
        if let Err(error) = self.persist_approval_challenges(&snapshot) {
            lock.remove(&challenge_id);
            return Err(format!("Unable to persist approval challenges: {error}"));
        }
        Ok(())
    }

    /// Lists all pending and unexpired authorization challenges.
    pub fn get_pending_challenges(&self) -> Vec<ciphervault_recovery::ApprovalChallenge> {
        let lock = lock_or_recover(&self.approval_challenges, "approval_challenges");
        let now = Utc::now().timestamp() as u64;
        lock.values()
            .filter(|(c, receipts)| c.expires_at_utc > now && receipts.is_empty())
            .map(|(c, _)| c.clone())
            .collect()
    }

    /// Retrieves challenge details and collected signed receipts.
    pub fn get_challenge_status(
        &self,
        challenge_id: &str,
    ) -> Option<(
        ciphervault_recovery::ApprovalChallenge,
        Vec<ciphervault_recovery::SignedApprovalReceipt>,
    )> {
        let lock = lock_or_recover(&self.approval_challenges, "approval_challenges");
        lock.get(challenge_id).cloned()
    }

    /// Submits a cryptographically signed approval receipt.
    pub fn submit_approval_receipt(
        &self,
        receipt: ciphervault_recovery::SignedApprovalReceipt,
    ) -> Result<usize, String> {
        let challenge_id = receipt.challenge_id.clone();
        let mut lock = lock_or_recover(&self.approval_challenges, "approval_challenges");
        let (already_recorded, count) =
            if let Some((challenge, receipts)) = lock.get_mut(&challenge_id) {
                receipt
                    .verify(challenge)
                    .map_err(|e| format!("Invalid receipt: {}", e))?;
                let already_recorded = receipts
                    .iter()
                    .any(|r| r.approver_pk_hex == receipt.approver_pk_hex);
                if !already_recorded {
                    receipts.push(receipt);
                }
                (already_recorded, receipts.len())
            } else {
                return Err("Challenge ID not found or already expired".into());
            };
        let snapshot = lock.clone();
        if let Err(error) = self.persist_approval_challenges(&snapshot) {
            if !already_recorded {
                if let Some((_, receipts)) = lock.get_mut(&challenge_id) {
                    receipts.pop();
                }
            }
            return Err(format!("Unable to persist approval challenges: {error}"));
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_persistence_renewal_and_signed_fields() {
        let root = std::env::temp_dir().join(format!("cv-lease-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test".into(), root.clone(), key.clone());
        let receipt = state.create_lease(&"a".repeat(64), 100, 90).unwrap();
        let pk = key.verifying_key().to_bytes();
        receipt.verify(&pk).unwrap();
        let mut tampered = receipt.clone();
        tampered.bytes += 1;
        assert!(tampered.verify(&pk).is_err());
        drop(state);
        let restarted = OperatorState::new("test".into(), root.clone(), key);
        let renewed = restarted.renew_lease(&receipt.lease_id, 30, 100).unwrap();
        assert_eq!(renewed.closure_digest_hex, receipt.closure_digest_hex);
        assert_eq!(renewed.expires_at_utc, receipt.expires_at_utc + 30 * 86400);
        assert!(restarted.renew_lease("../escape", 30, 100).is_err());
        assert!(restarted.renew_lease(&"0".repeat(32), 30, 100).is_err());
        assert!(restarted.renew_lease(&receipt.lease_id, 30, 999).is_err());
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_failed_persistence_and_anonymous_writes() {
        let root = std::env::temp_dir().join(format!("cv-write-{}", rand::random::<u128>()));
        let state = OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        assert!(state.validate_read_session("recovery_anonymous"));
        assert!(!state.validate_write_session("recovery_anonymous"));
        fs::remove_dir(root.join("leases")).unwrap();
        fs::write(root.join("leases"), b"block writes").unwrap();
        assert!(state.create_lease(&"a".repeat(64), 100, 90).is_err());
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn challenge_binds_device_key_and_vault_and_persists_session() {
        std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");
        let root = std::env::temp_dir().join(format!("cv-session-{}", rand::random::<u128>()));
        let operator_key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test-auth".into(), root.clone(), operator_key);
        let device_key = ciphervault_crypto::generate_signing_key();
        let other_key = ciphervault_crypto::generate_signing_key();
        let vault_id = "11".repeat(32);
        let other_vault = "22".repeat(32);
        let device_pk = hex::encode(device_key.verifying_key().as_bytes());

        let (challenge_id, nonce_hex, _) = state
            .issue_challenge(&vault_id, &device_pk)
            .expect("valid challenge inputs");
        let nonce = hex::decode(nonce_hex).unwrap();
        let signature = ciphervault_crypto::signatures::sign_with_domain(
            &device_key,
            b"operator_challenge",
            &nonce,
        );
        assert!(state
            .verify_and_create_session(
                &challenge_id,
                &hex::encode(other_key.verifying_key().as_bytes()),
                &hex::encode(signature)
            )
            .expect("persist ok")
            .is_none());

        let (challenge_id, nonce_hex, _) = state
            .issue_challenge(&vault_id, &device_pk)
            .expect("valid challenge inputs");
        let nonce = hex::decode(nonce_hex).unwrap();
        let signature = ciphervault_crypto::signatures::sign_with_domain(
            &device_key,
            b"operator_challenge",
            &nonce,
        );
        let token = state
            .verify_and_create_session(&challenge_id, &device_pk, &hex::encode(signature))
            .expect("persist ok")
            .expect("bound session");
        assert!(state.validate_session_for_vault(&token, &vault_id));
        assert!(!state.validate_session_for_vault(&token, &other_vault));

        drop(state);
        let restarted = OperatorState::new(
            "test-auth".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        assert!(restarted.validate_session_for_vault(&token, &vault_id));
        assert!(restarted.revoke_session(&token).expect("persist ok"));
        assert!(!restarted.validate_write_session(&token));
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
        std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    }

    #[test]
    fn test_operator_recovery_record_cryptographic_authorization() {
        use ciphervault_crypto::RecoverySecret;
        use ciphervault_format::to_canonical_cbor;

        let root = std::env::temp_dir().join(format!("cv-auth-{}", rand::random::<u128>()));
        let op_key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test".into(), root.clone(), op_key);

        let vault_id = vec![0x42u8; 32];
        let locator_hex = "a".repeat(64);

        let r_secret = RecoverySecret::generate();
        let r_sk = r_secret.derive_recovery_signing_key().unwrap();
        let (_, r_enc_pk) = r_secret.derive_recovery_encryption_keys().unwrap();

        // 1. Poisoning attempt with arbitrary bytes must be rejected
        let poisoned = b"malicious random garbage payload";
        assert!(state
            .append_recovery_record(&locator_hex, poisoned)
            .is_err());

        // 2. GenesisRecord signed by recovery authority must be accepted
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.clone(),
            recovery_signing_pk: r_sk.verifying_key().to_bytes().to_vec(),
            recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0u8; 32],
            created_at_utc: 1000,
            creation_nonce: vec![1u8; 32],
            signature: Vec::new(),
        };
        genesis.sign(&r_sk).unwrap();
        let genesis_cbor = to_canonical_cbor(&genesis).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &genesis_cbor)
            .is_ok());

        // 3. Forged GenesisRecord for the same locator must be rejected
        let rogue_sk = ciphervault_crypto::generate_signing_key();
        let mut forged_genesis = genesis.clone();
        forged_genesis.recovery_signing_pk = rogue_sk.verifying_key().to_bytes().to_vec();
        forged_genesis.sign(&rogue_sk).unwrap();
        let forged_genesis_cbor = to_canonical_cbor(&forged_genesis).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &forged_genesis_cbor)
            .is_err());

        // 4. Valid DeviceCertificate signed by recovery authority must be accepted
        let dev_sk = ciphervault_crypto::generate_signing_key();
        let mut cert = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.clone(),
            certificate_id: vec![2u8; 32],
            device_signing_pk: dev_sk.verifying_key().to_bytes().to_vec(),
            permissions: 1,
            authority_generation: 1,
            issued_at_utc: 1001,
            signature: Vec::new(),
        };
        cert.sign(&r_sk).unwrap();
        let cert_cbor = to_canonical_cbor(&cert).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &cert_cbor)
            .is_ok());

        // 5. Forged DeviceCertificate signed by attacker must be rejected
        let mut forged_cert = cert.clone();
        forged_cert.certificate_id = vec![3u8; 32];
        forged_cert.sign(&rogue_sk).unwrap();
        let forged_cert_cbor = to_canonical_cbor(&forged_cert).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &forged_cert_cbor)
            .is_err());

        // 6. Valid HeadRecord signed by authorized device must be accepted
        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.clone(),
            snapshot_id: vec![0xAAu8; 32],
            parent_snapshot_ids: Vec::new(),
            closure_digest: vec![0xBBu8; 32],
            device_id: vec![0xCCu8; 32],
            device_counter: 1,
            signature: Vec::new(),
        };
        head.sign(&dev_sk).unwrap();
        let head_cbor = to_canonical_cbor(&head).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &head_cbor)
            .is_ok());

        // 7. Forged HeadRecord signed by unauthorized key must be rejected
        let mut forged_head = head.clone();
        forged_head.device_counter = 2;
        forged_head.sign(&rogue_sk).unwrap();
        let forged_head_cbor = to_canonical_cbor(&forged_head).unwrap();
        assert!(state
            .append_recovery_record(&locator_hex, &forged_head_cbor)
            .is_err());

        // Verify that only the 3 valid records were committed to disk
        let stored = state.get_recovery_records(&locator_hex);
        assert_eq!(stored.len(), 3);

        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_operator_l2_relayer_checkpoint() {
        let root = std::env::temp_dir().join(format!("cv-relayer-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test-relayer".into(), root.clone(), key);

        let salt = [0x11u8; 32];
        let head_cid = [0x22u8; 32];
        let contract = [0x33u8; 20];
        let tx_dummy = [0u8; 32];

        // Valid evidence
        let evidence = ciphervault_format::CheckpointEvidence::new(
            salt, head_cid, 42161, contract, tx_dummy, 12345, 1700000000,
        );
        let receipt = state.relay_checkpoint(&evidence).unwrap();
        assert_eq!(receipt.commitment_hex, hex::encode(&evidence.commitment));
        assert_eq!(receipt.status, "QueuedForRelay");
        assert_eq!(receipt.block_number, 0);

        // Client-supplied on-chain fields must never promote a new checkpoint
        // before an independent RPC verifier has checked them.
        let claimed = ciphervault_format::CheckpointEvidence::new(
            [0x12u8; 32],
            [0x23u8; 32],
            42161,
            contract,
            [0x44u8; 32],
            12345,
            1700000000,
        );
        let queued_claim = state.relay_checkpoint(&claimed).unwrap();
        assert_eq!(queued_claim.status, "QueuedForRelay");
        assert!(queued_claim.tx_hash_hex.is_empty());
        assert_eq!(queued_claim.block_number, 0);

        // Confirm mined status update
        let updated = state
            .update_relayed_checkpoint(
                &receipt.commitment_hex,
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                12345,
                "SequencerConfirmed",
            )
            .unwrap();
        assert_eq!(updated.status, "SequencerConfirmed");
        assert_eq!(updated.block_number, 12345);

        // Idempotent query
        let queried = state
            .get_relayed_checkpoint(&receipt.commitment_hex)
            .unwrap();
        assert_eq!(queried.tx_hash_hex, updated.tx_hash_hex);
        assert_eq!(queried.status, "SequencerConfirmed");

        // The relay receipt survives an operator restart so clients can
        // continue polling settlement progress after a process crash.
        drop(state);
        let restarted = OperatorState::new(
            "test-relayer".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        let restored = restarted
            .get_relayed_checkpoint(&receipt.commitment_hex)
            .unwrap();
        assert_eq!(restored.status, "SequencerConfirmed");
        assert_eq!(restored.block_number, 12345);
        assert_eq!(restored.tx_hash_hex, updated.tx_hash_hex);

        // Rejects tampered commitment math
        let mut tampered = evidence.clone();
        tampered.salt[0] ^= 0xFF;
        assert!(restarted.relay_checkpoint(&tampered).is_err());

        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_operator_pos_challenge_and_proof() {
        let root = std::env::temp_dir().join(format!("cv-pos-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let operator_pk = key.verifying_key().to_bytes();
        let state = OperatorState::new("test-pos-operator".into(), root.clone(), key);

        let data = b"encrypted-blob-for-proof-of-storage-challenge";
        let cid = ciphervault_format::compute_digest(data);
        let cid_hex = hex::encode(cid);

        // Put object
        state.put_object(&cid_hex, data).unwrap();

        // 1. Valid challenge generates matching verifiable receipt
        let nonce = [0x55u8; 32];
        let receipt = state.generate_pos_proof(&cid_hex, &nonce).unwrap();
        assert_eq!(receipt.operator_id, "test-pos-operator");
        assert_eq!(receipt.cid_hex, cid_hex);
        assert_eq!(receipt.nonce_hex, hex::encode(nonce));
        assert_eq!(receipt.size_bytes, data.len() as u64);

        let expected_proof = ciphervault_storage::compute_pos_proof(&cid, &nonce, data);
        assert!(receipt.verify(&operator_pk, &expected_proof).is_ok());

        // 2. Nonexistent CID fails with Object not found
        let missing_cid = hex::encode([0x99u8; 32]);
        let err = state.generate_pos_proof(&missing_cid, &nonce).unwrap_err();
        assert_eq!(err, "Object not found");

        // 3. Invalid CID hex length fails
        assert!(state.generate_pos_proof("short_cid", &nonce).is_err());

        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_peer_gossip_registry() {
        let root = std::env::temp_dir().join(format!("cv-peer-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test-op".into(), root.clone(), key);

        let peer_key = ciphervault_crypto::generate_signing_key();
        let peer_pk = peer_key.verifying_key().to_bytes();
        let mut peer = ciphervault_storage::PeerDescriptor {
            operator_id: "peer-1".into(),
            endpoint: "http://127.0.0.1:8102".into(),
            signing_pk_hex: hex::encode(peer_pk),
            timestamp_utc: Utc::now().timestamp() as u64,
            signature_hex: String::new(),
        };
        peer.sign(&peer_key);

        assert_eq!(state.register_peer(peer.clone()).unwrap(), 1);
        let peers = state.get_active_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].operator_id, "peer-1");

        // Invalid signature rejected
        let mut bad_peer = peer.clone();
        bad_peer.signature_hex = hex::encode([0x00u8; 64]);
        assert!(state.register_peer(bad_peer).is_err());

        // Stale and future-dated announces are rejected even with a VALID
        // signature (re-signed after backdating so only freshness fails).
        let now = Utc::now().timestamp() as u64;
        let mut stale = peer.clone();
        stale.timestamp_utc = now - MAX_PEER_ANNOUNCE_AGE_SECS - 1;
        stale.sign(&peer_key);
        assert!(state.register_peer(stale).is_err());

        let mut future = peer.clone();
        future.timestamp_utc = now + MAX_PEER_ANNOUNCE_SKEW_SECS + 1;
        future.sign(&peer_key);
        assert!(state.register_peer(future).is_err());

        // Control: the fresh descriptor still registers.
        assert!(state.register_peer(peer.clone()).is_ok());

        // Routing state survives an operator restart.
        drop(state);
        let reopened = OperatorState::new(
            "test-op".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        let peers = reopened.get_active_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].operator_id, "peer-1");
        assert_eq!(peers[0].endpoint, "http://127.0.0.1:8102");

        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn byte_size_limits_parse_and_clamp() {
        assert_eq!(parse_byte_size("8388608"), Some(8_388_608));
        assert_eq!(parse_byte_size("8MB"), Some(8 * 1024 * 1024));
        assert_eq!(parse_byte_size("64kb"), Some(64 * 1024));
        assert_eq!(parse_byte_size("512"), Some(512));
        assert_eq!(parse_byte_size(""), None);
        assert_eq!(parse_byte_size("nope"), None);
        std::env::set_var("CIPHERVAULT_TEST_LIMIT_BYTES", "2MB");
        assert_eq!(
            operator_limit_from_env("CIPHERVAULT_TEST_LIMIT_BYTES", 1024, 512),
            2 * 1024 * 1024
        );
        std::env::set_var("CIPHERVAULT_TEST_LIMIT_BYTES", "1");
        assert_eq!(
            operator_limit_from_env("CIPHERVAULT_TEST_LIMIT_BYTES", 1024, 512),
            1024
        );
        std::env::remove_var("CIPHERVAULT_TEST_LIMIT_BYTES");
        assert_eq!(
            operator_limit_from_env("CIPHERVAULT_TEST_LIMIT_BYTES", 1024, 512),
            1024
        );
    }

    #[test]
    fn test_approval_challenge_registry() {
        let root = std::env::temp_dir().join(format!("cv-appr-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let state = OperatorState::new("test-op".into(), root.clone(), key);

        let vault_id = [0xAAu8; 32];
        let device_id = [0xBBu8; 32];
        let challenge = ciphervault_recovery::ApprovalChallenge::new(
            &vault_id,
            ciphervault_recovery::ApprovalAction::EmergencyRecovery,
            &device_id,
            "Recovery test".into(),
            300,
        );

        state
            .register_approval_challenge(challenge.clone())
            .unwrap();
        let pending = state.get_pending_challenges();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].challenge_id, challenge.challenge_id);

        let approver_key = ciphervault_crypto::generate_signing_key();
        let receipt = ciphervault_recovery::SignedApprovalReceipt::sign(
            &challenge,
            "Alice Lead".into(),
            &approver_key,
        );

        assert_eq!(state.submit_approval_receipt(receipt.clone()).unwrap(), 1);

        let status = state.get_challenge_status(&challenge.challenge_id).unwrap();
        assert_eq!(status.1.len(), 1);
        assert_eq!(status.1[0].approver_name, "Alice Lead");

        // Challenge + receipts survive an operator restart.
        drop(state);
        let reopened = OperatorState::new(
            "test-op".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        let status = reopened
            .get_challenge_status(&challenge.challenge_id)
            .unwrap();
        assert_eq!(status.1.len(), 1);
        assert_eq!(status.1[0].approver_name, "Alice Lead");

        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn io_stripes_shard_by_key() {
        let root = std::env::temp_dir().join(format!("cv-stripes-{}", rand::random::<u128>()));
        let state = OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        // Distinct keys must spread across stripes so concurrent uploads for
        // different CIDs do not serialize on one lock.
        let mut shards = std::collections::HashSet::new();
        for index in 0..256u32 {
            shards.insert(state.io_stripe(&format!("{index:064x}")) as *const _ as usize);
        }
        assert!(
            shards.len() > 16,
            "expected striped locks to spread 256 keys, got {}",
            shards.len()
        );
        // The same key must always resolve to the same stripe.
        let first = state.io_stripe(&"ab".repeat(32)) as *const _ as usize;
        let second = state.io_stripe(&"ab".repeat(32)) as *const _ as usize;
        assert_eq!(first, second);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn metrics_count_operations_and_render_prometheus() {
        let root = std::env::temp_dir().join(format!("cv-metrics-{}", rand::random::<u128>()));
        let state = OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        let payload = b"metrics-observed-object";
        let cid_hex = hex::encode(ciphervault_format::compute_digest(payload));
        state.put_object(&cid_hex, payload).unwrap();
        assert!(state.put_object(&cid_hex, b"wrong bytes!!").is_err());
        assert_eq!(state.get_object(&cid_hex).as_deref(), Some(&payload[..]));
        assert!(state.get_object(&"00".repeat(32)).is_none());
        let nonce = [0x77u8; 32];
        assert!(state.generate_pos_proof(&cid_hex, &nonce).is_ok());
        assert!(state.generate_pos_proof(&"00".repeat(32), &nonce).is_err());
        assert!(!state.validate_session_for_vault("bogus", &"11".repeat(32)));

        let exposition = state.metrics.render_prometheus();
        for line in [
            "ciphervault_operator_objects_put_total 1",
            "ciphervault_operator_objects_put_failures_total 1",
            "ciphervault_operator_objects_get_total 2",
            "ciphervault_operator_pos_challenges_total 2",
            "ciphervault_operator_pos_failures_total 1",
            "ciphervault_operator_auth_failures_total 1",
            "ciphervault_operator_uptime_seconds ",
        ] {
            assert!(
                exposition.contains(line),
                "missing metric line {line:?} in:\n{exposition}"
            );
        }
        assert!(exposition.contains("# TYPE ciphervault_operator_put_latency_ms histogram"));
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn poisoned_locks_recover_with_prior_state() {
        let root = std::env::temp_dir().join(format!("cv-poison-{}", rand::random::<u128>()));
        let state = OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        lock_or_recover(&state.sessions, "sessions").insert("tok".into(), u64::MAX);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = state.sessions.lock().unwrap();
            panic!("intentional poison");
        }));
        assert!(state.sessions.is_poisoned());
        // Recovery, not panic: prior state is intact and the lock works again.
        assert!(state.validate_write_session("tok"));
        assert!(!state.sessions.is_poisoned());
        assert!(state.revoke_session("tok").expect("revoke recovers"));
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    /// Blocks an atomic-persist target the way a full disk would: the temp
    /// file writes fine but the rename onto a non-empty directory fails on
    /// every platform.
    fn block_persist_target(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        fs::create_dir(path).unwrap();
        fs::write(path.join("block"), b"no renames here").unwrap();
    }

    #[test]
    fn session_persist_failure_rolls_back_and_errors() {
        let root = std::env::temp_dir().join(format!("cv-sessfail-{}", rand::random::<u128>()));
        let state = OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        lock_or_recover(&state.sessions, "sessions").insert("tok".into(), u64::MAX);
        lock_or_recover(&state.session_keys, "session_keys").insert("tok".into(), [9u8; 32]);
        lock_or_recover(&state.session_vaults, "session_vaults")
            .insert("tok".into(), "ab".repeat(32));
        block_persist_target(&root.join("sessions.json"));
        assert!(state.persist_sessions().is_err());
        // Revocation fails loudly and restores the in-memory session so
        // memory still matches the (unwritten) disk state.
        let error = state.revoke_session("tok").expect_err("persist must fail");
        assert!(
            error.contains("Unable to persist session revocation"),
            "{error}"
        );
        assert!(state.validate_write_session("tok"));
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn challenge_persist_failure_rolls_back_and_errors() {
        std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");
        let root = std::env::temp_dir().join(format!("cv-chalfail-{}", rand::random::<u128>()));
        let state = OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        block_persist_target(&root.join("challenges.json"));
        let error = state
            .issue_challenge(&"11".repeat(32), &"22".repeat(32))
            .expect_err("persist must fail");
        assert!(error.contains("Unable to persist challenges"), "{error}");
        assert!(lock_or_recover(&state.challenges, "challenges").is_empty());
        // The removal persist runs before validation, so a seeded challenge
        // also surfaces the store error rather than an auth verdict.
        lock_or_recover(&state.challenges, "challenges").insert(
            "cid".into(),
            ChallengeRecord {
                nonce_hex: "00".repeat(32),
                expires_at_utc: u64::MAX,
                vault_id_hex: "11".repeat(32),
                public_key_hex: "22".repeat(32),
                account_id: None,
                device_id_hex: None,
            },
        );
        let error = state
            .verify_and_create_session("cid", &"22".repeat(32), &"00".repeat(64))
            .expect_err("persist must fail");
        assert!(
            error.contains("Unable to persist challenge removal"),
            "{error}"
        );
        drop(state);
        fs::remove_dir_all(root).unwrap();
        std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    }

    #[test]
    fn session_issue_persist_failure_rolls_back_login() {
        std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");
        let root = std::env::temp_dir().join(format!("cv-loginfail-{}", rand::random::<u128>()));
        let state = OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        );
        let device_key = ciphervault_crypto::generate_signing_key();
        let device_pk = hex::encode(device_key.verifying_key().as_bytes());
        let vault_id = "11".repeat(32);
        let (challenge_id, nonce_hex, _) =
            state.issue_challenge(&vault_id, &device_pk).expect("issue");
        let nonce = hex::decode(nonce_hex).unwrap();
        let signature = ciphervault_crypto::signatures::sign_with_domain(
            &device_key,
            b"operator_challenge",
            &nonce,
        );
        block_persist_target(&root.join("sessions.json"));
        let error = state
            .verify_and_create_session(&challenge_id, &device_pk, &hex::encode(signature))
            .expect_err("persist must fail");
        assert!(error.contains("Unable to persist session"), "{error}");
        // No half-minted session lingers in memory.
        assert!(lock_or_recover(&state.sessions, "sessions").is_empty());
        drop(state);
        fs::remove_dir_all(root).unwrap();
        std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    }
}
