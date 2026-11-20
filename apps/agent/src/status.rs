// Copyright (c) 2026 Samuel Avornyoh and CipherVault Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Watcher-owned evidence behind `ciphervault status --json --watcher`.
//!
//! A running watcher (`ciphervault watch` or `ciphervault-agent`) holds an
//! exclusive OS lock on `.ciphervault/watcher.lock` for its whole life, so a
//! vault has at most one watcher and readers can ask the OS whether a watcher
//! process is alive. It also rewrites one small JSON record next to it: a
//! main-loop heartbeat, a separate capture-worker beat, the last tracked-file
//! change it detected, the last snapshot it captured, and the last replication
//! outcome. Readers report `running` only when the process is alive and both
//! beats are fresh; a live process with a silent worker or loop is `stalled`;
//! a released lock or a clean stop is `stopped`; missing, foreign, unreadable,
//! or contradictory evidence is `unknown`. The record carries IDs, times,
//! counts and error text only, never file contents. A `--dry-run` watcher
//! takes no lock and writes nothing, keeping inspector mode free of persistence.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const WATCHER_STATUS_FILE: &str = "watcher-status.json";
pub const WATCHER_LOCK_FILE: &str = "watcher.lock";
pub const WATCHER_STATUS_VERSION: u32 = 1;
/// How often a running watcher refreshes its heartbeat (and flushes the
/// capture worker's latest beat with it).
pub const HEARTBEAT_INTERVAL_SECS: u64 = 10;
/// The main loop never blocks on captures or uploads, so six missed beats
/// mean it is not responding.
pub const HEARTBEAT_STALE_AFTER_SECS: u64 = 60;
/// The capture worker reports after every scan (about every 3 s when idle).
/// A capture or upload may hold it for up to 90 s before it times out, and
/// its beat reaches the file with the next heartbeat, up to 10 s later.
pub const CAPTURE_WORKER_STALE_AFTER_SECS: u64 = 150;
/// Heartbeats this far in the future point at a clock change, not liveness.
const MAX_CLOCK_SKEW_SECS: u64 = 300;
const MAX_STATUS_BYTES: u64 = 64 * 1024;
const MAX_ERROR_CHARS: usize = 300;
/// A status reader probes the lock with a brief shared lock; a starting
/// watcher retries for about a second before deciding another one runs.
const LOCK_ATTEMPTS: u32 = 6;
const LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

/// A snapshot the watcher captured and committed as the local head.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureEvidence {
    pub at_utc: u64,
    /// Record CID (the ID `status` reports as the active head).
    pub snapshot_id: String,
    /// Logical ID (printed by `push` and the text `history`).
    pub logical_id: String,
}

/// The latest replication attempt: `verified` means the complete recovery
/// set was replicated and read back from the required operator quorum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEvidence {
    pub at_utc: u64,
    /// `verified`, `failed`, or `timeout`.
    pub outcome: String,
    pub snapshot_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorEvidence {
    pub at_utc: u64,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatcherStatusRecord {
    pub version: u32,
    pub vault_id: String,
    pub instance_id: String,
    pub pid: u32,
    pub sync_enabled: bool,
    pub operator_count: usize,
    pub debounce_secs: u64,
    pub started_at_utc: u64,
    /// Main-loop heartbeat: the process is alive and its event loop responds.
    pub heartbeat_at_utc: u64,
    pub heartbeat_interval_secs: u64,
    /// Capture-worker beat: the thread that scans, captures and uploads
    /// finished a cycle (or started) at this time.
    #[serde(default)]
    pub capture_worker_beat_at_utc: Option<u64>,
    pub stopped_at_utc: Option<u64>,
    /// When a scan last found tracked content that differs from the last capture.
    pub last_change_detected_at_utc: Option<u64>,
    pub last_capture: Option<CaptureEvidence>,
    /// The last capture-or-sync job that failed (sync failures also appear in `last_sync`).
    pub last_error: Option<ErrorEvidence>,
    pub last_sync: Option<SyncEvidence>,
}

pub fn now_utc() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn bounded_error(error: &str) -> String {
    let flat = error.replace(['\n', '\r'], " ");
    flat.chars().take(MAX_ERROR_CHARS).collect()
}

pub fn watcher_status_path(root: &Path) -> PathBuf {
    root.join(".ciphervault").join(WATCHER_STATUS_FILE)
}

pub fn watcher_lock_path(root: &Path) -> PathBuf {
    root.join(".ciphervault").join(WATCHER_LOCK_FILE)
}

/// One watcher per vault: an exclusive OS lock held for the watcher's life.
/// The OS releases it when the process exits for any reason, including a
/// crash, so a held lock is evidence of a live watcher process.
#[derive(Debug)]
pub struct WatcherInstanceLock {
    _file: fs::File,
}

impl WatcherInstanceLock {
    pub fn acquire(root: &Path) -> Result<Self, String> {
        let path = watcher_lock_path(root);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
        let mut attempt = 1;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(fs::TryLockError::WouldBlock) if attempt < LOCK_ATTEMPTS => {
                    attempt += 1;
                    std::thread::sleep(LOCK_RETRY_DELAY);
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(format!(
                        "another CipherVault watcher is already running for this vault \
                         (it holds {}); stop it first, a vault allows one watcher",
                        path.display()
                    ))
                }
                Err(fs::TryLockError::Error(error)) => {
                    return Err(format!("cannot lock {}: {error}", path.display()))
                }
            }
        }
    }
}

/// What the OS says about the watcher lock right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockProbe {
    /// A process holds the lock: a watcher process is alive.
    Held,
    /// Nobody holds it: no watcher process is running.
    Free,
    /// No lock file: no watcher with lock support has run here.
    Absent,
    /// The lock could not be checked (unsupported filesystem, permissions).
    Unavailable(String),
}

impl LockProbe {
    pub fn as_str(&self) -> &'static str {
        match self {
            LockProbe::Held => "held",
            LockProbe::Free => "free",
            LockProbe::Absent => "absent",
            LockProbe::Unavailable(_) => "unavailable",
        }
    }
}

/// Checks the lock with a brief shared lock on a read-only handle. Reads and
/// writes nothing; a link or reparse point at the lock path is not trusted.
pub fn probe_watcher_lock(root: &Path) -> LockProbe {
    let path = watcher_lock_path(root);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return LockProbe::Absent,
        Err(error) => return LockProbe::Unavailable(error.to_string()),
        Ok(_) => {}
    }
    let file = match ciphervault_file_lock::open_regular_file(&path) {
        Ok(file) => file,
        Err(error) => return LockProbe::Unavailable(error.to_string()),
    };
    match file.try_lock_shared() {
        Ok(()) => {
            let _ = file.unlock();
            LockProbe::Free
        }
        Err(fs::TryLockError::WouldBlock) => LockProbe::Held,
        Err(fs::TryLockError::Error(error)) => LockProbe::Unavailable(error.to_string()),
    }
}

/// Serialises every update of this watcher's record behind one lock and
/// rewrites the file atomically, so readers see a whole record or none.
/// Write failures are ignored: status reporting never stops a capture.
pub struct WatcherStatusWriter {
    path: PathBuf,
    record: Mutex<WatcherStatusRecord>,
}

impl WatcherStatusWriter {
    pub fn start(
        root: &Path,
        vault_id: &[u8; 32],
        sync_enabled: bool,
        operator_count: usize,
        debounce_secs: u64,
    ) -> Self {
        let now = now_utc();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos())
            .unwrap_or(0);
        let record = WatcherStatusRecord {
            version: WATCHER_STATUS_VERSION,
            vault_id: hex::encode(vault_id),
            instance_id: format!("{:08x}{:08x}{:08x}", std::process::id(), now as u32, nanos),
            pid: std::process::id(),
            sync_enabled,
            operator_count,
            debounce_secs,
            started_at_utc: now,
            heartbeat_at_utc: now,
            heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS,
            capture_worker_beat_at_utc: None,
            stopped_at_utc: None,
            last_change_detected_at_utc: None,
            last_capture: None,
            last_error: None,
            last_sync: None,
        };
        let writer = Self {
            path: watcher_status_path(root),
            record: Mutex::new(record),
        };
        writer.update(|_| {});
        writer
    }

    /// Applies `change`, refreshes the heartbeat, and rewrites the record.
    pub fn update(&self, change: impl FnOnce(&mut WatcherStatusRecord)) {
        let Ok(mut record) = self.record.lock() else {
            return;
        };
        change(&mut record);
        record.heartbeat_at_utc = now_utc();
        let _ = write_record(&self.path, &record);
    }

    pub fn heartbeat(&self) {
        self.update(|_| {});
    }

    /// The capture worker is up; written at once so readers see it early.
    pub fn worker_started(&self) {
        self.update(|record| record.capture_worker_beat_at_utc = Some(now_utc()));
    }

    /// The capture worker finished a cycle. Kept in memory and written with
    /// the next heartbeat, so an idle watcher does not rewrite the file on
    /// every 3-second scan.
    pub fn worker_beat(&self) {
        if let Ok(mut record) = self.record.lock() {
            record.capture_worker_beat_at_utc = Some(now_utc());
        }
    }

    pub fn change_detected(&self) {
        self.update(|record| record.last_change_detected_at_utc = Some(now_utc()));
    }

    pub fn captured(&self, record_cid: &[u8; 32], logical_id: &[u8]) {
        self.update(|record| {
            record.last_capture = Some(CaptureEvidence {
                at_utc: now_utc(),
                snapshot_id: hex::encode(record_cid),
                logical_id: hex::encode(logical_id),
            })
        });
    }

    pub fn synced(&self, record_cid: Option<&[u8; 32]>, outcome: &str, error: Option<&str>) {
        self.update(|record| {
            record.last_sync = Some(SyncEvidence {
                at_utc: now_utc(),
                outcome: outcome.to_string(),
                snapshot_id: record_cid.map(hex::encode),
                error: error.map(bounded_error),
            })
        });
    }

    pub fn failed(&self, error: &str) {
        self.update(|record| {
            record.last_error = Some(ErrorEvidence {
                at_utc: now_utc(),
                error: bounded_error(error),
            })
        });
    }

    pub fn stopped(&self) {
        self.update(|record| record.stopped_at_utc = Some(now_utc()));
    }

    pub fn snapshot(&self) -> Option<WatcherStatusRecord> {
        self.record.lock().ok().map(|record| record.clone())
    }
}

fn write_record(path: &Path, record: &WatcherStatusRecord) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
    let tmp = path.with_file_name(format!("{WATCHER_STATUS_FILE}.{}.tmp", record.instance_id));
    let written = (|| {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        ciphervault_file_lock::atomic_replace(&tmp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// Reads the vault's watcher record. `Ok(None)` when there is none; `Err`
/// when one exists but cannot be trusted (a link, oversized, malformed, or
/// an unknown version).
pub fn read_watcher_status(root: &Path) -> Result<Option<WatcherStatusRecord>, String> {
    let path = watcher_status_path(root);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect the watcher status record: {error}")),
        Ok(_) => {}
    }
    let file = ciphervault_file_lock::open_regular_file(&path)
        .map_err(|error| format!("cannot open the watcher status record: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read the watcher status record: {error}"))?;
    if bytes.len() as u64 > MAX_STATUS_BYTES {
        return Err("the watcher status record is too large".to_string());
    }
    let record: WatcherStatusRecord = serde_json::from_slice(&bytes)
        .map_err(|_| "the watcher status record is malformed".to_string())?;
    if record.version != WATCHER_STATUS_VERSION {
        return Err(format!(
            "unsupported watcher status record version {}",
            record.version
        ));
    }
    Ok(Some(record))
}

/// What the evidence establishes about the watcher right now.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WatcherLiveness {
    /// `running`, `stalled`, `stopped`, or `unknown`.
    pub state: &'static str,
    /// `lock_and_heartbeat`, `heartbeat`, `worker_stalled`, `loop_stalled`,
    /// `no_worker_beat`, `stop_record`, `lock_released`, `stale_heartbeat`,
    /// `lock_without_record`, `restarting`, `clock_skew`, `foreign_record`,
    /// `unreadable_record`, or `no_record`.
    pub evidence: &'static str,
    pub reason: String,
    /// The OS lock: `held`, `free`, `absent`, or `unavailable`.
    pub lock: &'static str,
    pub heartbeat_at_utc: Option<u64>,
    pub heartbeat_age_secs: Option<u64>,
    pub stale_after_secs: u64,
    pub capture_worker_beat_at_utc: Option<u64>,
    pub capture_worker_age_secs: Option<u64>,
    pub capture_worker_stale_after_secs: u64,
    pub started_at_utc: Option<u64>,
    pub stopped_at_utc: Option<u64>,
    pub pid: Option<u32>,
    pub sync_enabled: Option<bool>,
    pub operator_count: Option<usize>,
}

/// Liveness from this vault's lock and record only.
///
/// - `running`: the process is alive (lock held, or a fresh heartbeat where
///   the lock cannot be checked) and both the main loop and the capture
///   worker reported recently.
/// - `stalled`: the process is alive but its main loop or capture worker has
///   gone quiet, so new changes may not be captured.
/// - `stopped`: a clean stop record, or a released lock with no heartbeat
///   since the stale window.
/// - `unknown`: no record, a foreign or unreadable record, a stale heartbeat
///   without lock evidence, clock skew, or a released lock with a fresh
///   heartbeat (the watcher just exited, or locks are not enforced here).
pub fn assess_liveness(
    record: Result<Option<&WatcherStatusRecord>, &str>,
    lock: &LockProbe,
    vault_id_hex: &str,
    now_utc: u64,
) -> WatcherLiveness {
    let mut out = WatcherLiveness {
        state: "unknown",
        evidence: "no_record",
        reason: String::new(),
        lock: lock.as_str(),
        heartbeat_at_utc: None,
        heartbeat_age_secs: None,
        stale_after_secs: HEARTBEAT_STALE_AFTER_SECS,
        capture_worker_beat_at_utc: None,
        capture_worker_age_secs: None,
        capture_worker_stale_after_secs: CAPTURE_WORKER_STALE_AFTER_SECS,
        started_at_utc: None,
        stopped_at_utc: None,
        pid: None,
        sync_enabled: None,
        operator_count: None,
    };
    let held = *lock == LockProbe::Held;
    let record = match record {
        Err(error) => {
            out.evidence = "unreadable_record";
            out.reason = format!("Watcher state unknown: {error}.");
            return out;
        }
        Ok(None) if held => {
            out.evidence = "lock_without_record";
            out.reason = "Watcher state unknown: a watcher process holds this vault's lock \
                but has not written a status record yet (it may be starting)."
                .to_string();
            return out;
        }
        Ok(None) => {
            out.reason = "Watcher state unknown: this vault has no watcher status record. \
                No watcher may have run here, it may predate status records, or it runs \
                with --dry-run, which records nothing."
                .to_string();
            return out;
        }
        Ok(Some(record)) => record,
    };
    if !record.vault_id.eq_ignore_ascii_case(vault_id_hex) {
        out.evidence = "foreign_record";
        out.reason =
            "Watcher state unknown: the status record belongs to a different vault.".to_string();
        return out;
    }
    let stale_after = HEARTBEAT_STALE_AFTER_SECS.max(record.heartbeat_interval_secs * 4);
    out.stale_after_secs = stale_after;
    out.heartbeat_at_utc = Some(record.heartbeat_at_utc);
    out.capture_worker_beat_at_utc = record.capture_worker_beat_at_utc;
    out.started_at_utc = Some(record.started_at_utc);
    out.stopped_at_utc = record.stopped_at_utc;
    out.pid = Some(record.pid);
    out.sync_enabled = Some(record.sync_enabled);
    out.operator_count = Some(record.operator_count);
    if record.heartbeat_at_utc > now_utc.saturating_add(MAX_CLOCK_SKEW_SECS) {
        out.evidence = "clock_skew";
        out.reason = "Watcher state unknown: its last heartbeat is in the future (clock change)."
            .to_string();
        return out;
    }
    let age = now_utc.saturating_sub(record.heartbeat_at_utc);
    out.heartbeat_age_secs = Some(age);
    out.capture_worker_age_secs = record
        .capture_worker_beat_at_utc
        .map(|beat| now_utc.saturating_sub(beat));

    if let Some(stopped) = record.stopped_at_utc {
        if held {
            out.evidence = "restarting";
            out.reason = "Watcher state unknown: a watcher process holds the lock, but the \
                record still shows the previous clean stop (it is probably starting)."
                .to_string();
        } else {
            out.state = "stopped";
            out.evidence = "stop_record";
            out.reason = format!("The watcher recorded a clean stop at {stopped} (UTC seconds).");
        }
        return out;
    }
    if *lock == LockProbe::Free {
        out.evidence = "lock_released";
        if age <= stale_after {
            out.reason = format!(
                "Watcher state unknown: no process holds the watcher lock, yet a heartbeat \
                 arrived {age}s ago. The watcher just exited, or this filesystem does not \
                 enforce locks."
            );
        } else {
            out.state = "stopped";
            out.reason = format!(
                "The watcher is not running: no process holds its lock and no clean stop \
                 was recorded, so it exited unexpectedly (crash, kill, or reboot). Last \
                 heartbeat {age}s ago."
            );
        }
        return out;
    }

    // Alive: the OS says so (held), or a fresh heartbeat where the lock is
    // absent or cannot be checked.
    if age > stale_after {
        if held {
            out.state = "stalled";
            out.evidence = "loop_stalled";
            out.reason = format!(
                "A watcher process holds the lock, but its heartbeat is {age}s old \
                 (limit {stale_after}s): its main loop is not responding."
            );
        } else {
            out.evidence = "stale_heartbeat";
            out.reason = format!(
                "Watcher state unknown: last heartbeat {age}s ago, older than {stale_after}s. \
                 It may have crashed, been killed, or the machine slept."
            );
        }
        return out;
    }
    match out.capture_worker_age_secs {
        None => {
            out.evidence = "no_worker_beat";
            out.reason = "Watcher state unknown: the process is alive but its capture \
                worker has not reported yet."
                .to_string();
        }
        Some(worker_age) if worker_age > CAPTURE_WORKER_STALE_AFTER_SECS => {
            out.state = "stalled";
            out.evidence = "worker_stalled";
            out.reason = format!(
                "The watcher process is alive, but its capture worker last reported \
                 {worker_age}s ago (limit {CAPTURE_WORKER_STALE_AFTER_SECS}s): new changes \
                 may not be captured or uploaded until it recovers or the watcher restarts."
            );
        }
        Some(worker_age) => {
            out.state = "running";
            out.evidence = if held {
                "lock_and_heartbeat"
            } else {
                "heartbeat"
            };
            out.reason = format!(
                "Watcher running: heartbeat {age}s ago, capture worker {worker_age}s ago \
                 (pid {}{}).",
                record.pid,
                if held { ", process lock held" } else { "" }
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "cv-watcher-status-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".ciphervault")).unwrap();
        root
    }

    #[test]
    fn writer_round_trips_and_worker_beats_ride_on_the_heartbeat() {
        let root = temp_root("roundtrip");
        let vault = [7u8; 32];
        let writer = WatcherStatusWriter::start(&root, &vault, true, 3, 2);
        assert_eq!(
            read_watcher_status(&root)
                .unwrap()
                .unwrap()
                .capture_worker_beat_at_utc,
            None
        );
        writer.worker_started();
        assert!(read_watcher_status(&root)
            .unwrap()
            .unwrap()
            .capture_worker_beat_at_utc
            .is_some());
        writer.change_detected();
        writer.captured(&[1u8; 32], &[2u8; 32]);
        writer.synced(Some(&[1u8; 32]), "failed", Some("operator down\nretrying"));
        writer.failed("capture failed");
        let record = read_watcher_status(&root).unwrap().unwrap();
        assert_eq!(record, writer.snapshot().unwrap());
        assert_eq!(
            record.last_capture.as_ref().unwrap().snapshot_id,
            hex::encode([1u8; 32])
        );
        assert_eq!(
            record.last_sync.as_ref().unwrap().error.as_deref(),
            Some("operator down retrying")
        );
        // A worker beat changes memory only; the next heartbeat writes it.
        let before = fs::read(watcher_status_path(&root)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        writer.worker_beat();
        assert_eq!(fs::read(watcher_status_path(&root)).unwrap(), before);
        writer.heartbeat();
        let flushed = read_watcher_status(&root).unwrap().unwrap();
        assert!(flushed.capture_worker_beat_at_utc > record.capture_worker_beat_at_utc);
        let leftovers: Vec<_> = fs::read_dir(root.join(".ciphervault"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            leftovers,
            vec![WATCHER_STATUS_FILE.to_string()],
            "no temp files remain"
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture(heartbeat: u64, worker: Option<u64>) -> WatcherStatusRecord {
        WatcherStatusRecord {
            version: WATCHER_STATUS_VERSION,
            vault_id: hex::encode([7u8; 32]),
            instance_id: "fixture".into(),
            pid: 42,
            sync_enabled: true,
            operator_count: 3,
            debounce_secs: 2,
            started_at_utc: heartbeat.saturating_sub(100),
            heartbeat_at_utc: heartbeat,
            heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS,
            capture_worker_beat_at_utc: worker,
            stopped_at_utc: None,
            last_change_detected_at_utc: None,
            last_capture: None,
            last_error: None,
            last_sync: None,
        }
    }

    #[test]
    fn liveness_needs_a_live_process_and_both_beats() {
        let id = hex::encode([7u8; 32]);
        let now = 2_000_000_000u64;
        let assess = |record: &WatcherStatusRecord, lock: LockProbe| {
            let out = assess_liveness(Ok(Some(record)), &lock, &id, now);
            (out.state, out.evidence)
        };
        let healthy = fixture(now - 5, Some(now - 3));
        assert_eq!(
            assess(&healthy, LockProbe::Held),
            ("running", "lock_and_heartbeat")
        );
        assert_eq!(
            assess(&healthy, LockProbe::Absent),
            ("running", "heartbeat")
        );
        assert_eq!(
            assess(&healthy, LockProbe::Unavailable("no locks".into())),
            ("running", "heartbeat")
        );

        // A hung capture worker behind a live main loop: stalled, not running.
        let hung_worker = fixture(now - 5, Some(now - CAPTURE_WORKER_STALE_AFTER_SECS - 1));
        assert_eq!(
            assess(&hung_worker, LockProbe::Held),
            ("stalled", "worker_stalled")
        );
        assert_eq!(
            assess(&fixture(now - 5, None), LockProbe::Held),
            ("unknown", "no_worker_beat")
        );

        // Main loop silent while the process still holds the lock.
        let silent = fixture(now - HEARTBEAT_STALE_AFTER_SECS - 1, Some(now - 3));
        assert_eq!(
            assess(&silent, LockProbe::Held),
            ("stalled", "loop_stalled")
        );
        assert_eq!(
            assess(&silent, LockProbe::Absent),
            ("unknown", "stale_heartbeat")
        );

        // The OS released the lock without a clean stop: exited.
        assert_eq!(
            assess(&silent, LockProbe::Free),
            ("stopped", "lock_released")
        );
        assert_eq!(
            assess(&healthy, LockProbe::Free),
            ("unknown", "lock_released"),
            "a fresh heartbeat with a free lock is contradictory, so unknown"
        );

        let mut stopped = fixture(now - 7_200, Some(now - 7_200));
        stopped.stopped_at_utc = Some(now - 7_200);
        assert_eq!(
            assess(&stopped, LockProbe::Free),
            ("stopped", "stop_record")
        );
        assert_eq!(assess(&stopped, LockProbe::Held), ("unknown", "restarting"));

        assert_eq!(
            assess(&fixture(now + 10_000, Some(now)), LockProbe::Held),
            ("unknown", "clock_skew")
        );
        let mut foreign = healthy.clone();
        foreign.vault_id = hex::encode([8u8; 32]);
        assert_eq!(
            assess(&foreign, LockProbe::Held),
            ("unknown", "foreign_record")
        );
        let none = assess_liveness(Ok(None), &LockProbe::Absent, &id, now);
        assert_eq!((none.state, none.evidence), ("unknown", "no_record"));
        let starting = assess_liveness(Ok(None), &LockProbe::Held, &id, now);
        assert_eq!(
            (starting.state, starting.evidence),
            ("unknown", "lock_without_record")
        );
        let broken = assess_liveness(Err("malformed"), &LockProbe::Held, &id, now);
        assert_eq!(
            (broken.state, broken.evidence),
            ("unknown", "unreadable_record")
        );
    }

    #[test]
    fn instance_lock_allows_one_watcher_and_readers_see_it() {
        let root = temp_root("lock");
        assert_eq!(probe_watcher_lock(&root), LockProbe::Absent);
        let first = WatcherInstanceLock::acquire(&root).unwrap();
        assert_eq!(probe_watcher_lock(&root), LockProbe::Held);
        let second = WatcherInstanceLock::acquire(&root).unwrap_err();
        assert!(second.contains("already running"), "{second}");
        drop(first);
        assert_eq!(probe_watcher_lock(&root), LockProbe::Free);
        let again = WatcherInstanceLock::acquire(&root).unwrap();
        drop(again);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn untrusted_records_are_errors_not_evidence() {
        let root = temp_root("untrusted");
        assert_eq!(read_watcher_status(&root).unwrap(), None);
        let path = watcher_status_path(&root);
        fs::write(&path, b"{not json").unwrap();
        assert!(read_watcher_status(&root).is_err());
        fs::write(&path, vec![b' '; (MAX_STATUS_BYTES + 10) as usize]).unwrap();
        assert!(read_watcher_status(&root).is_err());
        let writer = WatcherStatusWriter::start(&root, &[3u8; 32], false, 0, 2);
        let mut record = writer.snapshot().unwrap();
        record.version = 99;
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(read_watcher_status(&root).unwrap_err().contains("version"));
        // Records written before the worker beat existed still parse.
        let mut legacy = serde_json::to_value(fixture(1, None)).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("capture_worker_beat_at_utc");
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(
            read_watcher_status(&root)
                .unwrap()
                .unwrap()
                .capture_worker_beat_at_utc,
            None
        );
        fs::remove_dir_all(root).unwrap();
    }
}
