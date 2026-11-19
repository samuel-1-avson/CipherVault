//! Operator transparency-log storage and sequencer (ADR-014 Phase 2).
//!
//! One append-only log per operator, under `data_dir/log/`:
//!
//! * `entries.bin` — concatenated 65-byte v1 entries. The index of an
//!   entry is its byte offset divided by 65. An append is one `write_all`
//!   plus `sync_all` before the caller is acked, so an acked entry survives
//!   a crash and an unacked torn tail is truncated on the next open.
//! * `log.key` — the 32-byte Ed25519 seed signing checkpoints. Created
//!   owner-only on first open and never overwritten; a wrong-length file
//!   fails the open. Rotating this key means starting a new log (ADR-014).
//! * `origin` — the log origin, pinned on first open. A later open that
//!   configures a different origin for the same directory fails instead
//!   of silently becoming a different log.
//! * `checkpoint` — the latest signed checkpoint, rewritten atomically
//!   after every append for static serving. It is a cache: the entries
//!   file is the truth, and the checkpoint is recomputed and re-signed
//!   from it on open, so a crash between the two writes loses nothing.
//!
//! Tiles and entry bundles are derived from the entries on demand; they
//! are a deterministic function of the tree, so there are no separate
//! tile files to corrupt or keep in sync. The tree root comes from an
//! incremental [`CompactRange`], so appends cost O(log n) hashes.
//! Proof generation is O(n) (Phase 1 `proof` module); acceptable at
//! anchoring scale and noted for tile-based proofs later.
//!
//! Sequencing is immediate: a single mutex serializes appends, assigns
//! the next index, extends the tree and signs a fresh checkpoint. A
//! submitter therefore always polls a checkpoint that already covers
//! its index; there is no timer batch to wait for in Phase 2.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ciphervault_translog::checkpoint::Checkpoint;
use ciphervault_translog::compact::CompactRange;
use ciphervault_translog::entry::{LogEntry, ENTRY_V1_LEN};
use ciphervault_translog::hash::{root_from_leaf_hashes, Hash};
use ciphervault_translog::note::Ed25519NoteSigner;
use ciphervault_translog::proof::{consistency_proof, inclusion_proof, ProofError};
use ciphervault_translog::tiles::{Tile, TileKind, TILE_WIDTH};
use ed25519_dalek::SigningKey;

use crate::state::lock_or_recover;

/// Default per-device submission limit (entries per 60 s sliding window)
/// when `CIPHERVAULT_LOG_ADD_LIMIT_PER_MIN` is unset. Anchoring is a
/// low-frequency action; 120/min leaves burst room for backfill drills
/// while bounding log-filling by one compromised device session.
pub const DEFAULT_LOG_ADD_LIMIT_PER_MIN: u32 = 120;
const LOG_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_LOG_RATE_TRACKED_KEYS: usize = 4096;

/// Default seconds between rounds of pushing the checkpoint to witnesses.
pub const DEFAULT_LOG_WITNESS_INTERVAL_SECS: u64 = 10;

/// Transparency-log configuration, fixed when the operator state is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Log origin override (`CIPHERVAULT_LOG_ORIGIN` / `--log-origin`).
    /// `None` derives `cipherchain.<operator-id>.cipherv.online/log`.
    pub origin: Option<String>,
    /// Per-device submissions per minute; 0 disables the limiter.
    pub add_limit_per_min: u32,
    /// Witnesses this log pushes its checkpoints to, each
    /// `<witness vkey>@<submission URL>` (`CIPHERVAULT_LOG_WITNESSES`,
    /// separated by commas or whitespace / `--log-witness`, repeatable).
    /// Validated by `LogConfig::witness_plan` at startup.
    pub witnesses: Vec<String>,
    /// Cosignatures a checkpoint needs before it is published as witnessed
    /// (`CIPHERVAULT_LOG_WITNESS_QUORUM` / `--log-witness-quorum`). `None`
    /// means ADR-014's default of 2, or every witness when fewer are
    /// configured.
    pub witness_quorum: Option<usize>,
    /// Seconds between witnessing rounds
    /// (`CIPHERVAULT_LOG_WITNESS_INTERVAL_SECS` /
    /// `--log-witness-interval-secs`).
    pub witness_interval_secs: u64,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl LogConfig {
    /// Configuration from the environment. Invalid values fall back to
    /// the defaults with a stderr warning, matching the operator's other
    /// limit knobs: a typo must never silently disable a limit.
    pub fn from_env() -> Self {
        let origin = std::env::var("CIPHERVAULT_LOG_ORIGIN")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let add_limit_per_min = match std::env::var("CIPHERVAULT_LOG_ADD_LIMIT_PER_MIN")
            .ok()
            .map(|value| value.trim().to_string())
        {
            Some(value) if !value.is_empty() => match value.parse::<u32>() {
                Ok(limit) => limit,
                Err(_) => {
                    eprintln!(
                        "operator limit CIPHERVAULT_LOG_ADD_LIMIT_PER_MIN={value} invalid; \
                         using default {DEFAULT_LOG_ADD_LIMIT_PER_MIN}"
                    );
                    DEFAULT_LOG_ADD_LIMIT_PER_MIN
                }
            },
            _ => DEFAULT_LOG_ADD_LIMIT_PER_MIN,
        };
        let witnesses = std::env::var("CIPHERVAULT_LOG_WITNESSES")
            .map(|value| crate::witness_store::split_list(&value))
            .unwrap_or_default();
        // An invalid quorum is kept as an impossible one, so startup
        // validation fails instead of silently lowering it.
        let witness_quorum = std::env::var("CIPHERVAULT_LOG_WITNESS_QUORUM")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<usize>().unwrap_or(usize::MAX));
        let witness_interval_secs = std::env::var("CIPHERVAULT_LOG_WITNESS_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|secs| *secs > 0)
            .unwrap_or(DEFAULT_LOG_WITNESS_INTERVAL_SECS);
        Self {
            origin,
            add_limit_per_min,
            witnesses,
            witness_quorum,
            witness_interval_secs,
        }
    }

    /// A configuration with the given origin and limit and no witnesses,
    /// independent of the environment.
    pub fn new(origin: Option<String>, add_limit_per_min: u32) -> Self {
        Self {
            origin,
            add_limit_per_min,
            witnesses: Vec::new(),
            witness_quorum: None,
            witness_interval_secs: DEFAULT_LOG_WITNESS_INTERVAL_SECS,
        }
    }

    /// The origin this configuration asks for, derived from the operator
    /// id when unset. Invalid characters in the id become `-` so the
    /// result is always a valid checkpoint origin / key name.
    pub fn origin_for(&self, operator_id: &str) -> String {
        if let Some(origin) = &self.origin {
            return origin.clone();
        }
        format!(
            "cipherchain.{}.cipherv.online/log",
            crate::witness_store::slug(operator_id)
        )
    }
}

/// Why a log operation failed.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// The log directory or a file in it could not be read or written.
    #[error("transparency log I/O: {0}")]
    Io(String),
    /// The configured origin differs from the origin pinned in the log
    /// directory: that directory is a different log.
    #[error("log origin mismatch: configured {configured:?}, stored {stored:?}")]
    OriginMismatch {
        /// The origin this open was configured with.
        configured: String,
        /// The origin pinned in the log directory.
        stored: String,
    },
    /// Stored bytes are not a valid entry sequence (beyond a torn tail).
    #[error("transparency log is corrupt: {0}")]
    Corrupt(String),
    /// The submitting device is over its per-minute limit.
    #[error("log submission rate limit exceeded for this device")]
    RateLimited,
    /// A proof was requested for a position or size the tree lacks.
    #[error(transparent)]
    Proof(#[from] ProofError),
    /// Checkpoint construction or signing failed.
    #[error("checkpoint error: {0}")]
    Checkpoint(String),
}

pub(crate) fn io_err(path: &Path, error: io::Error) -> LogError {
    LogError::Io(format!("{}: {error}", path.display()))
}

/// Writes `bytes` to `path` crash-safely, mirroring the chain ledger's
/// CC-11 pattern: sibling temp file, fsync, rename, parent-dir fsync.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), LogError> {
    let mut tmp_name = path
        .file_name()
        .ok_or_else(|| LogError::Io(format!("{} has no file name", path.display())))?
        .to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        let mut file = fs::File::create(&tmp).map_err(|e| io_err(&tmp, e))?;
        file.write_all(bytes).map_err(|e| io_err(&tmp, e))?;
        file.sync_all().map_err(|e| io_err(&tmp, e))?;
    }
    fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    sync_parent_dir(path);
    Ok(())
}

#[cfg(unix)]
pub(crate) fn sync_parent_dir(path: &Path) {
    if let Some(dir) = path.parent().and_then(|p| fs::File::open(p).ok()) {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
pub(crate) fn sync_parent_dir(_path: &Path) {}

/// Loads the log signing key, creating it owner-only on first use. A
/// wrong-length file is rejected and never overwritten (CC-17 posture:
/// the human decides what a damaged key file means).
fn load_or_create_signing_key(path: &Path) -> Result<SigningKey, LogError> {
    match fs::read(path) {
        Ok(bytes) => {
            let seed: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                LogError::Corrupt(format!(
                    "log signing key {} must contain exactly 32 bytes, got {}",
                    path.display(),
                    bytes.len()
                ))
            })?;
            Ok(SigningKey::from_bytes(seed))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = ciphervault_crypto::generate_signing_key();
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(&key.to_bytes())
                        .map_err(|e| io_err(path, e))?;
                    file.sync_all().map_err(|e| io_err(path, e))?;
                    sync_parent_dir(path);
                    Ok(key)
                }
                // Lost a creation race: read the winner's key.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    load_or_create_signing_key(path)
                }
                Err(e) => Err(io_err(path, e)),
            }
        }
        Err(e) => Err(io_err(path, e)),
    }
}

/// Per-device rate limiter: sliding 60 s window,
/// bounded tracker, fail-closed past the tracker cap. Mirrors the HTTP
/// rate limiter in `lib.rs` so both tiers behave the same way.
fn rate_allowed_at(
    hits: &mut HashMap<String, VecDeque<Instant>>,
    key: &str,
    limit: u32,
    now: Instant,
) -> bool {
    if limit == 0 {
        return true;
    }
    let window_start = now.checked_sub(LOG_RATE_WINDOW);
    if hits.len() > MAX_LOG_RATE_TRACKED_KEYS / 2 {
        hits.retain(|_, times| {
            while window_start.is_some_and(|start| times.front().is_some_and(|t| *t <= start)) {
                times.pop_front();
            }
            !times.is_empty()
        });
    }
    if !hits.contains_key(key) && hits.len() >= MAX_LOG_RATE_TRACKED_KEYS {
        return false;
    }
    let times = hits.entry(key.to_string()).or_default();
    while window_start.is_some_and(|start| times.front().is_some_and(|t| *t <= start)) {
        times.pop_front();
    }
    if times.len() >= limit as usize {
        return false;
    }
    times.push_back(now);
    true
}

/// One accepted submission: where it landed and the tree it landed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendReceipt {
    /// Leaf index assigned by the sequencer.
    pub index: u64,
    /// RFC 9162 leaf hash of the entry.
    pub leaf_hash: Hash,
    /// Tree size after the append (so `index < tree_size`).
    pub tree_size: u64,
    /// Root hash after the append.
    pub root: Hash,
}

/// Public description of the log for discovery and startup logging. The
/// verifier key is how clients pin the log (out of band in production;
/// served here for fleet setup and tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogInfo {
    /// The log origin.
    pub origin: String,
    /// C2SP verifier key (`<name>+<id>+<key>`) of the checkpoint signer.
    pub verifier_key: String,
    /// Current tree size.
    pub tree_size: u64,
    /// Current root hash.
    pub root: Hash,
    /// Size of the latest checkpoint published with a witness quorum.
    pub witnessed_tree_size: Option<u64>,
}

/// The latest checkpoint published with a quorum of witness cosignatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessedCheckpoint {
    /// Its tree size.
    pub size: u64,
    /// The signed note: the log's signature and the witnesses'
    /// cosignatures.
    pub note: String,
}

struct LogInner {
    entries: Vec<LogEntry>,
    leaf_hashes: Vec<Hash>,
    range: CompactRange,
}

/// The operator's transparency log. Cheap to share behind the operator
/// state's `Arc`; all methods take `&self` and serialize internally.
pub struct LogStore {
    dir: PathBuf,
    origin: String,
    signer_name: String,
    signing_key: SigningKey,
    verifier_key: String,
    add_limit_per_min: u32,
    inner: Mutex<LogInner>,
    rate_hits: Mutex<HashMap<String, VecDeque<Instant>>>,
    witnessed: Mutex<Option<WitnessedCheckpoint>>,
}

impl LogStore {
    /// Opens (or creates) the log in `data_dir/log`.
    ///
    /// The entries file is the truth: a torn final entry left by a crash
    /// mid-append is truncated (it was never acked), the tree is rebuilt
    /// from the surviving entries, and the published checkpoint is
    /// re-signed from that rebuilt tree.
    pub fn open(data_dir: &Path, config: &LogConfig, operator_id: &str) -> Result<Self, LogError> {
        let dir = data_dir.join("log");
        fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;

        let configured_origin = config.origin_for(operator_id);
        let origin_path = dir.join("origin");
        let origin = match fs::read_to_string(&origin_path) {
            Ok(stored) => {
                let stored = stored.trim().to_string();
                if stored != configured_origin {
                    return Err(LogError::OriginMismatch {
                        configured: configured_origin,
                        stored,
                    });
                }
                stored
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Validate before pinning: an origin the checkpoint
                // format rejects must fail here, not at first signing.
                Checkpoint::new(
                    configured_origin.clone(),
                    0,
                    ciphervault_translog::empty_root(),
                )
                .map_err(|e| LogError::Checkpoint(e.to_string()))?;
                write_atomic(&origin_path, configured_origin.as_bytes())?;
                configured_origin
            }
            Err(e) => return Err(io_err(&origin_path, e)),
        };

        let signing_key = load_or_create_signing_key(&dir.join("log.key"))?;
        // The checkpoint key name is the origin (the sumdb convention);
        // both follow the same validity rules.
        let signer = Ed25519NoteSigner::new(origin.clone(), signing_key.clone())
            .map_err(|e| LogError::Checkpoint(e.to_string()))?;
        let verifier_key = signer
            .verifier()
            .map_err(|e| LogError::Checkpoint(e.to_string()))?
            .verifier_key()
            .to_string();

        let entries_path = dir.join("entries.bin");
        let raw = match fs::read(&entries_path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(io_err(&entries_path, e)),
        };
        let usable = raw.len() / ENTRY_V1_LEN * ENTRY_V1_LEN;
        if usable != raw.len() {
            eprintln!(
                "transparency log: truncating {} torn tail bytes in {} (unacked append)",
                raw.len() - usable,
                entries_path.display()
            );
            let file = OpenOptions::new()
                .write(true)
                .open(&entries_path)
                .map_err(|e| io_err(&entries_path, e))?;
            file.set_len(usable as u64)
                .map_err(|e| io_err(&entries_path, e))?;
            file.sync_all().map_err(|e| io_err(&entries_path, e))?;
        }
        let mut entries = Vec::with_capacity(usable / ENTRY_V1_LEN);
        let mut leaf_hashes = Vec::with_capacity(usable / ENTRY_V1_LEN);
        let mut range = CompactRange::new(0);
        for chunk in raw[..usable].as_chunks::<ENTRY_V1_LEN>().0 {
            let entry = LogEntry::from_bytes(chunk)
                .map_err(|e| LogError::Corrupt(format!("entry {}: {e}", entries.len())))?;
            let leaf_hash = entry.leaf_hash();
            range
                .append(leaf_hash)
                .map_err(|e| LogError::Corrupt(e.to_string()))?;
            entries.push(entry);
            leaf_hashes.push(leaf_hash);
        }

        let store = Self {
            dir,
            signer_name: origin.clone(),
            origin,
            signing_key,
            verifier_key,
            add_limit_per_min: config.add_limit_per_min,
            inner: Mutex::new(LogInner {
                entries,
                leaf_hashes,
                range,
            }),
            rate_hits: Mutex::new(HashMap::new()),
            witnessed: Mutex::new(None),
        };
        // Republish the checkpoint from the rebuilt tree so static
        // serving never shows a pre-crash copy.
        store.publish_checkpoint()?;
        store.load_witnessed_checkpoint();
        Ok(store)
    }

    fn witnessed_path(&self) -> PathBuf {
        self.dir.join("checkpoint.witnessed")
    }

    /// Reloads the published witnessed checkpoint. It is a cache of what
    /// witnesses already returned, so a copy that no longer matches this
    /// log is dropped with a warning instead of failing the open.
    fn load_witnessed_checkpoint(&self) {
        let path = self.witnessed_path();
        let note = match fs::read_to_string(&path) {
            Ok(note) => note,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => {
                eprintln!("transparency log: cannot read {}: {e}", path.display());
                return;
            }
        };
        match self.check_own_checkpoint(&note) {
            Ok(checkpoint) => {
                *lock_or_recover(&self.witnessed, "log_witnessed") = Some(WitnessedCheckpoint {
                    size: checkpoint.size(),
                    note,
                })
            }
            Err(e) => eprintln!(
                "transparency log: ignoring {} ({e}); witnesses will cosign again",
                path.display()
            ),
        }
    }

    /// Checks that `note` is a checkpoint of this log, signed by its key,
    /// whose root matches the tree at that size.
    fn check_own_checkpoint(&self, note: &str) -> Result<Checkpoint, LogError> {
        let verifier = self
            .signer()?
            .verifier()
            .map_err(|e| LogError::Checkpoint(e.to_string()))?;
        let opened =
            ciphervault_translog::open_checkpoint(note.as_bytes(), &self.origin, &verifier, &[])
                .map_err(|e| LogError::Checkpoint(e.to_string()))?;
        let checkpoint = opened.checkpoint().clone();
        let inner = lock_or_recover(&self.inner, "transparency_log");
        let size = usize::try_from(checkpoint.size())
            .ok()
            .filter(|size| *size <= inner.leaf_hashes.len())
            .ok_or_else(|| LogError::Checkpoint("checkpoint is beyond the tree".into()))?;
        if &root_from_leaf_hashes(&inner.leaf_hashes[..size]) != checkpoint.root() {
            return Err(LogError::Checkpoint(
                "checkpoint root does not match the tree".into(),
            ));
        }
        Ok(checkpoint)
    }

    /// Signs the current tree head and returns the checkpoint with its
    /// encoded signed note, both from the same state.
    pub fn signed_head(&self) -> Result<(Checkpoint, String), LogError> {
        let inner = lock_or_recover(&self.inner, "transparency_log");
        let note = self.sign_checkpoint_locked(&inner)?;
        let root = inner
            .range
            .root()
            .map_err(|e| LogError::Checkpoint(e.to_string()))?;
        let checkpoint = Checkpoint::new(self.origin.clone(), inner.range.end(), root)
            .map_err(|e| LogError::Checkpoint(e.to_string()))?;
        Ok((checkpoint, note))
    }

    /// Publishes `note`, a checkpoint of this log carrying a witness
    /// quorum's cosignatures, as the latest witnessed checkpoint. Returns
    /// `false` without change when a larger one is already published, so
    /// the published size never goes backwards. The caller checks the
    /// cosignatures; this checks the log's own signature and root.
    pub fn publish_witnessed(&self, note: String) -> Result<bool, LogError> {
        // A round with no new entries and the same cosignatures changes
        // nothing: skip the tree check and the fsync.
        if self
            .witnessed_checkpoint()
            .is_some_and(|current| current.note == note)
        {
            return Ok(false);
        }
        let checkpoint = self.check_own_checkpoint(&note)?;
        let mut witnessed = lock_or_recover(&self.witnessed, "log_witnessed");
        if witnessed
            .as_ref()
            .is_some_and(|current| current.size > checkpoint.size())
        {
            return Ok(false);
        }
        write_atomic(&self.witnessed_path(), note.as_bytes())?;
        *witnessed = Some(WitnessedCheckpoint {
            size: checkpoint.size(),
            note,
        });
        Ok(true)
    }

    /// The latest checkpoint published with a witness quorum.
    pub fn witnessed_checkpoint(&self) -> Option<WitnessedCheckpoint> {
        lock_or_recover(&self.witnessed, "log_witnessed").clone()
    }

    fn signer(&self) -> Result<Ed25519NoteSigner, LogError> {
        Ed25519NoteSigner::new(self.signer_name.clone(), self.signing_key.clone())
            .map_err(|e| LogError::Checkpoint(e.to_string()))
    }

    /// Signs the current tree head and returns the encoded checkpoint.
    /// Signing is from live state, so the result always matches the
    /// entries the log holds at call time.
    pub fn signed_checkpoint(&self) -> Result<String, LogError> {
        let inner = lock_or_recover(&self.inner, "transparency_log");
        self.sign_checkpoint_locked(&inner)
    }

    fn sign_checkpoint_locked(&self, inner: &LogInner) -> Result<String, LogError> {
        let root = inner
            .range
            .root()
            .map_err(|e| LogError::Checkpoint(e.to_string()))?;
        let checkpoint = Checkpoint::new(self.origin.clone(), inner.range.end(), root)
            .map_err(|e| LogError::Checkpoint(e.to_string()))?;
        let note = checkpoint
            .sign(&self.signer()?)
            .map_err(|e| LogError::Checkpoint(e.to_string()))?;
        note.encode()
            .map_err(|e| LogError::Checkpoint(e.to_string()))
    }

    fn publish_checkpoint(&self) -> Result<(), LogError> {
        let text = {
            let inner = lock_or_recover(&self.inner, "transparency_log");
            self.sign_checkpoint_locked(&inner)?
        };
        write_atomic(&self.dir.join("checkpoint"), text.as_bytes())
    }

    /// Origin, pinning key and current tree head.
    pub fn info(&self) -> LogInfo {
        let witnessed_tree_size = self.witnessed_checkpoint().map(|w| w.size);
        let inner = lock_or_recover(&self.inner, "transparency_log");
        LogInfo {
            origin: self.origin.clone(),
            verifier_key: self.verifier_key.clone(),
            tree_size: inner.range.end(),
            root: inner.range.root().unwrap_or([0u8; 32]),
            witnessed_tree_size,
        }
    }

    /// Checks the device's submission budget. Called before any disk
    /// work so over-limit submitters cost almost nothing.
    pub fn check_rate_limit(&self, device_key: &str) -> Result<(), LogError> {
        let mut hits = lock_or_recover(&self.rate_hits, "log_rate_limit");
        if rate_allowed_at(
            &mut hits,
            device_key,
            self.add_limit_per_min,
            Instant::now(),
        ) {
            Ok(())
        } else {
            Err(LogError::RateLimited)
        }
    }

    /// Sequences one entry: appends it durably, extends the tree, and
    /// republishes the checkpoint, in that order. The entry lock covers
    /// the whole sequence, so indices are assigned in durable order and
    /// never reused, even across a crash (a crashed append either fsynced
    /// and is rebuilt on open, or left a torn tail that is truncated).
    pub fn append(&self, device_key: &str, entry: LogEntry) -> Result<AppendReceipt, LogError> {
        self.check_rate_limit(device_key)?;
        let mut inner = lock_or_recover(&self.inner, "transparency_log");
        let entries_path = self.dir.join("entries.bin");
        let index = inner.range.end();
        let encoded = entry.to_bytes();
        {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&entries_path)
                .map_err(|e| io_err(&entries_path, e))?;
            file.write_all(&encoded)
                .map_err(|e| io_err(&entries_path, e))?;
            file.sync_all().map_err(|e| io_err(&entries_path, e))?;
        }
        let leaf_hash = entry.leaf_hash();
        inner
            .range
            .append(leaf_hash)
            .map_err(|e| LogError::Corrupt(e.to_string()))?;
        inner.entries.push(entry);
        inner.leaf_hashes.push(leaf_hash);
        let receipt = AppendReceipt {
            index,
            leaf_hash,
            tree_size: inner.range.end(),
            root: inner
                .range
                .root()
                .map_err(|e| LogError::Checkpoint(e.to_string()))?,
        };
        // Static-serving copy. A failure here does not un-commit the
        // entry: the checkpoint endpoint signs from live state, and the
        // next append or open rewrites this file.
        if let Err(e) = self.publish_checkpoint_locked(&inner) {
            eprintln!("transparency log: checkpoint publish failed (entry {index} committed): {e}");
        }
        Ok(receipt)
    }

    fn publish_checkpoint_locked(&self, inner: &LogInner) -> Result<(), LogError> {
        let text = self.sign_checkpoint_locked(inner)?;
        write_atomic(&self.dir.join("checkpoint"), text.as_bytes())
    }

    /// Inclusion proof for `index` against the tree of `tree_size`
    /// leaves (default: the current tree).
    pub fn inclusion_proof(
        &self,
        index: u64,
        tree_size: Option<u64>,
    ) -> Result<(u64, Hash, Vec<Hash>), LogError> {
        let inner = lock_or_recover(&self.inner, "transparency_log");
        let size = tree_size.unwrap_or_else(|| inner.range.end());
        let size_usize = usize::try_from(size).map_err(|_| {
            LogError::Proof(ProofError::IndexOutOfRange {
                index,
                tree_size: size,
            })
        })?;
        if size_usize > inner.leaf_hashes.len() {
            return Err(LogError::Proof(ProofError::IndexOutOfRange {
                index,
                tree_size: size,
            }));
        }
        let proof = inclusion_proof(&inner.leaf_hashes[..size_usize], index)?;
        let index_usize = usize::try_from(index).map_err(|_| {
            LogError::Proof(ProofError::IndexOutOfRange {
                index,
                tree_size: size,
            })
        })?;
        Ok((size, inner.leaf_hashes[index_usize], proof))
    }

    /// Consistency proof that the tree of `from_size` is a prefix of the
    /// tree of `to_size` (default: the current tree). Callers verify it
    /// against the two signed roots they hold.
    pub fn consistency_proof(
        &self,
        from_size: u64,
        to_size: Option<u64>,
    ) -> Result<Vec<Hash>, LogError> {
        let inner = lock_or_recover(&self.inner, "transparency_log");
        let to = to_size.unwrap_or_else(|| inner.range.end());
        let to_usize = usize::try_from(to).map_err(|_| {
            LogError::Proof(ProofError::SizeOrder {
                old_size: from_size,
                new_size: to,
            })
        })?;
        if to_usize > inner.leaf_hashes.len() {
            return Err(LogError::Proof(ProofError::SizeOrder {
                old_size: from_size,
                new_size: to,
            }));
        }
        Ok(consistency_proof(
            &inner.leaf_hashes[..to_usize],
            from_size,
        )?)
    }

    /// Indices at which `commitment` was submitted (log semantics keep
    /// duplicates: re-anchoring the same head is a new leaf).
    pub fn lookup_commitment(&self, commitment: &[u8; 32]) -> Vec<u64> {
        let inner = lock_or_recover(&self.inner, "transparency_log");
        inner
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| &entry.commitment == commitment)
            .map(|(index, _)| index as u64)
            .collect()
    }

    /// Serialized tile bytes for a canonical tile request, or `None`
    /// when the tile does not exist for the current tree (beyond the
    /// tree, or a width that differs from the tile's actual width).
    pub fn tile_bytes(&self, tile: &Tile) -> Option<Vec<u8>> {
        let inner = lock_or_recover(&self.inner, "transparency_log");
        let tree_size = inner.leaf_hashes.len() as u64;
        match tile.kind() {
            TileKind::Entries => {
                let start = tile.index().checked_mul(u64::from(TILE_WIDTH))?;
                if tile.width() != available_width(0, tile.index(), tree_size) {
                    return None;
                }
                let start = usize::try_from(start).ok()?;
                let mut out = Vec::with_capacity(ENTRY_V1_LEN * usize::from(tile.width()));
                for entry in &inner.entries[start..start + usize::from(tile.width())] {
                    out.extend_from_slice(&entry.to_bytes());
                }
                Some(out)
            }
            TileKind::Hashes(level) => {
                if tile.width() != available_width(level, tile.index(), tree_size) {
                    return None;
                }
                let mut out = Vec::with_capacity(32 * usize::from(tile.width()));
                for element in 0..u64::from(tile.width()) {
                    let (start, end) = element_leaf_range(level, tile.index(), element, tree_size)?;
                    if start == end {
                        return None;
                    }
                    let hash = if end - start == 1 {
                        inner.leaf_hashes[start as usize]
                    } else {
                        root_from_leaf_hashes(&inner.leaf_hashes[start as usize..end as usize])
                    };
                    out.extend_from_slice(&hash);
                }
                Some(out)
            }
        }
    }
}

/// How many elements the tile at (`level`, `index`) actually holds in a
/// tree of `tree_size` leaves: 256, or fewer for the rightmost tile, or
/// 0 when the tile starts beyond the tree.
fn available_width(level: u8, index: u64, tree_size: u64) -> u16 {
    let tile_first = (index as u128) * (TILE_WIDTH as u128) * span_of(level);
    if tile_first >= tree_size as u128 {
        return 0;
    }
    let remaining_leaves = (tree_size as u128) - tile_first;
    let elements = remaining_leaves.div_ceil(span_of(level));
    elements.min(TILE_WIDTH as u128) as u16
}

/// Leaves covered by one element of a level-`level` tile.
fn span_of(level: u8) -> u128 {
    1u128.checked_shl(8 * u32::from(level)).unwrap_or(u128::MAX)
}

/// The leaf range `[start, end)` of element `element` in tile
/// (`level`, `index`), clipped to `tree_size`. An empty range at or past
/// the tree size means the element does not exist.
fn element_leaf_range(
    level: u8,
    tile_index: u64,
    element: u64,
    tree_size: u64,
) -> Option<(u64, u64)> {
    let span = span_of(level);
    let start128 = (tile_index as u128) * (TILE_WIDTH as u128) * span + (element as u128) * span;
    let size = tree_size as u128;
    let start = start128.min(size);
    let end = (start128 + span).min(size).max(start);
    // start/end are clipped to tree_size, which fits in u64.
    Some((start as u64, end as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_translog::{open_checkpoint, Ed25519NoteVerifier};

    fn fresh_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cv-log-{tag}-{}", rand::random::<u128>()))
    }

    fn test_config(limit: u32) -> LogConfig {
        LogConfig::new(Some("example.com/log".into()), limit)
    }

    fn entry(byte: u8) -> LogEntry {
        LogEntry::untagged([byte; 32])
    }

    #[test]
    fn appends_survive_reopen_in_order() {
        let root = fresh_dir("reopen");
        let store = LogStore::open(&root, &test_config(0), "op-test").unwrap();
        let key_before = store.info().verifier_key;
        for byte in 1..=5u8 {
            store.append("device", entry(byte)).unwrap();
        }
        let info_before = store.info();
        drop(store);

        let store = LogStore::open(&root, &test_config(0), "op-test").unwrap();
        assert_eq!(store.info().verifier_key, key_before, "key persists");
        assert_eq!(store.info().tree_size, 5);
        assert_eq!(store.info().root, info_before.root, "root persists");
        assert_eq!(store.lookup_commitment(&[3u8; 32]), vec![2]);
        assert_eq!(store.lookup_commitment(&[9u8; 32]), Vec::<u64>::new());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn torn_tail_is_truncated_and_never_reused() {
        let root = fresh_dir("torn");
        let store = LogStore::open(&root, &test_config(0), "op-test").unwrap();
        store.append("device", entry(1)).unwrap();
        drop(store);
        // Simulate a crash mid-append: 30 bytes of a 65-byte entry.
        let entries_path = root.join("log").join("entries.bin");
        let mut file = OpenOptions::new().append(true).open(&entries_path).unwrap();
        file.write_all(&[7u8; 30]).unwrap();
        drop(file);

        let store = LogStore::open(&root, &test_config(0), "op-test").unwrap();
        assert_eq!(store.info().tree_size, 1);
        let receipt = store.append("device", entry(2)).unwrap();
        assert_eq!(receipt.index, 1, "the torn entry's index is reused");
        drop(store);
        let store = LogStore::open(&root, &test_config(0), "op-test").unwrap();
        assert_eq!(store.info().tree_size, 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn origin_change_and_bad_key_fail_closed() {
        let root = fresh_dir("origin");
        let store = LogStore::open(&root, &test_config(0), "op-test").unwrap();
        drop(store);
        let other = LogConfig::new(Some("other.example/log".into()), 0);
        assert!(matches!(
            LogStore::open(&root, &other, "op-test"),
            Err(LogError::OriginMismatch { .. })
        ));
        std::fs::write(root.join("log").join("log.key"), b"short").unwrap();
        assert!(matches!(
            LogStore::open(&root, &test_config(0), "op-test"),
            Err(LogError::Corrupt(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_opens_and_proofs_verify() {
        let root = fresh_dir("proof");
        let store = LogStore::open(&root, &test_config(0), "op-test").unwrap();
        for byte in 1..=9u8 {
            store.append("device", entry(byte)).unwrap();
        }
        let verifier = Ed25519NoteVerifier::from_vkey(&store.info().verifier_key).unwrap();
        let verified = open_checkpoint(
            store.signed_checkpoint().unwrap().as_bytes(),
            "example.com/log",
            &verifier,
            &[],
        )
        .unwrap();
        let (size, root_hash) = (verified.checkpoint().size(), *verified.checkpoint().root());
        assert_eq!(size, 9);
        for byte in 1..=9u8 {
            let (proof_size, leaf_hash, proof) =
                store.inclusion_proof(u64::from(byte) - 1, None).unwrap();
            assert_eq!(proof_size, size);
            ciphervault_translog::verify_inclusion(
                &leaf_hash,
                u64::from(byte) - 1,
                size,
                &proof,
                &root_hash,
            )
            .unwrap();
            assert_eq!(leaf_hash, entry(byte).leaf_hash());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rate_limit_is_per_device_and_windowed() {
        let mut hits = HashMap::new();
        let now = Instant::now();
        assert!(rate_allowed_at(&mut hits, "a", 2, now));
        assert!(rate_allowed_at(&mut hits, "a", 2, now));
        assert!(!rate_allowed_at(&mut hits, "a", 2, now));
        assert!(
            rate_allowed_at(&mut hits, "b", 2, now),
            "isolated per device"
        );
        let later = now + LOG_RATE_WINDOW + Duration::from_secs(1);
        assert!(
            rate_allowed_at(&mut hits, "a", 2, later),
            "window expiry readmits"
        );
        assert!(rate_allowed_at(&mut hits, "any", 0, now), "0 disables");
    }

    #[test]
    fn tile_widths_follow_the_tree() {
        assert_eq!(available_width(0, 0, 0), 0);
        assert_eq!(available_width(0, 0, 5), 5);
        assert_eq!(available_width(0, 0, 256), 256);
        assert_eq!(available_width(0, 1, 300), 44);
        assert_eq!(available_width(0, 2, 300), 0);
        assert_eq!(available_width(1, 0, 300), 2);
        assert_eq!(available_width(1, 0, 256 * 256), 256);
    }
}
