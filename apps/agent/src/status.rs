// Copyright (c) 2026 Samuel Avornyoh and CipherVault Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Watcher-owned status record behind `ciphervault status --json --watcher`.
//!
//! A running watcher (`ciphervault watch` or `ciphervault-agent`) rewrites one
//! small JSON file in its vault's `.ciphervault/` directory: a heartbeat, the
//! last tracked-file change it detected, the last snapshot it captured, and the
//! last replication outcome. Readers treat a missing, unreadable, foreign, or
//! stale record as "unknown", never as "running". The record carries IDs,
//! times, counts and error text only, never file contents. A `--dry-run`
//! watcher writes nothing, keeping inspector mode free of persistence.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const WATCHER_STATUS_FILE: &str = "watcher-status.json";
pub const WATCHER_STATUS_VERSION: u32 = 1;
/// How often a running watcher refreshes its heartbeat.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 10;
/// A heartbeat older than this no longer shows the watcher is running. It
/// exceeds the 90-second capture/upload timeout plus several heartbeats.
pub const HEARTBEAT_STALE_AFTER_SECS: u64 = 120;
/// Heartbeats this far in the future point at a clock change, not liveness.
const MAX_CLOCK_SKEW_SECS: u64 = 300;
const MAX_STATUS_BYTES: u64 = 64 * 1024;
const MAX_ERROR_CHARS: usize = 300;

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
    pub heartbeat_at_utc: u64,
    pub heartbeat_interval_secs: u64,
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
    /// `running`, `stopped`, or `unknown`.
    pub state: &'static str,
    /// `heartbeat`, `stop_record`, `stale_heartbeat`, `clock_skew`,
    /// `foreign_record`, `unreadable_record`, or `no_record`.
    pub evidence: &'static str,
    pub reason: String,
    pub heartbeat_at_utc: Option<u64>,
    pub heartbeat_age_secs: Option<u64>,
    pub stale_after_secs: u64,
    pub started_at_utc: Option<u64>,
    pub stopped_at_utc: Option<u64>,
    pub pid: Option<u32>,
    pub sync_enabled: Option<bool>,
    pub operator_count: Option<usize>,
}

/// Liveness from this vault's record only. A fresh heartbeat from a record
/// bound to `vault_id_hex` is `running`; a clean stop record is `stopped`;
/// everything else (no record, foreign vault, unreadable, stale, or clock
/// skew) is `unknown`.
pub fn assess_liveness(
    record: Result<Option<&WatcherStatusRecord>, &str>,
    vault_id_hex: &str,
    now_utc: u64,
) -> WatcherLiveness {
    let mut out = WatcherLiveness {
        state: "unknown",
        evidence: "no_record",
        reason: String::new(),
        heartbeat_at_utc: None,
        heartbeat_age_secs: None,
        stale_after_secs: HEARTBEAT_STALE_AFTER_SECS,
        started_at_utc: None,
        stopped_at_utc: None,
        pid: None,
        sync_enabled: None,
        operator_count: None,
    };
    let record = match record {
        Err(error) => {
            out.evidence = "unreadable_record";
            out.reason = format!("Watcher state unknown: {error}.");
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
    out.started_at_utc = Some(record.started_at_utc);
    out.stopped_at_utc = record.stopped_at_utc;
    out.pid = Some(record.pid);
    out.sync_enabled = Some(record.sync_enabled);
    out.operator_count = Some(record.operator_count);
    if let Some(stopped) = record.stopped_at_utc {
        out.state = "stopped";
        out.evidence = "stop_record";
        out.heartbeat_age_secs = Some(now_utc.saturating_sub(record.heartbeat_at_utc));
        out.reason = format!("The watcher recorded a clean stop at {stopped} (UTC seconds).");
        return out;
    }
    if record.heartbeat_at_utc > now_utc.saturating_add(MAX_CLOCK_SKEW_SECS) {
        out.evidence = "clock_skew";
        out.reason = "Watcher state unknown: its last heartbeat is in the future (clock change)."
            .to_string();
        return out;
    }
    let age = now_utc.saturating_sub(record.heartbeat_at_utc);
    out.heartbeat_age_secs = Some(age);
    if age <= stale_after {
        out.state = "running";
        out.evidence = "heartbeat";
        out.reason = format!("Watcher heartbeat {age}s ago (pid {}).", record.pid);
    } else {
        out.evidence = "stale_heartbeat";
        out.reason = format!(
            "Watcher state unknown: last heartbeat {age}s ago, older than {stale_after}s. \
             It may have crashed, been killed, or the machine slept."
        );
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
            now_utc()
        ));
        fs::create_dir_all(root.join(".ciphervault")).unwrap();
        root
    }

    #[test]
    fn writer_round_trips_and_readers_judge_liveness_by_vault_and_age() {
        let root = temp_root("roundtrip");
        let vault = [7u8; 32];
        let writer = WatcherStatusWriter::start(&root, &vault, true, 3, 2);
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
        assert!(record.last_change_detected_at_utc.is_some());
        let leftovers: Vec<_> = fs::read_dir(root.join(".ciphervault"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            leftovers,
            vec![WATCHER_STATUS_FILE.to_string()],
            "no temp files remain"
        );

        let id = hex::encode(vault);
        let now = record.heartbeat_at_utc;
        let fresh = assess_liveness(Ok(Some(&record)), &id, now + 5);
        assert_eq!((fresh.state, fresh.evidence), ("running", "heartbeat"));
        assert_eq!(fresh.heartbeat_age_secs, Some(5));
        let stale = assess_liveness(Ok(Some(&record)), &id, now + HEARTBEAT_STALE_AFTER_SECS + 1);
        assert_eq!(
            (stale.state, stale.evidence),
            ("unknown", "stale_heartbeat")
        );
        let foreign = assess_liveness(Ok(Some(&record)), &hex::encode([8u8; 32]), now);
        assert_eq!(
            (foreign.state, foreign.evidence),
            ("unknown", "foreign_record")
        );
        let skewed = assess_liveness(Ok(Some(&record)), &id, now.saturating_sub(10_000));
        assert_eq!((skewed.state, skewed.evidence), ("unknown", "clock_skew"));
        let none = assess_liveness(Ok(None), &id, now);
        assert_eq!((none.state, none.evidence), ("unknown", "no_record"));
        let broken = assess_liveness(Err("the watcher status record is malformed"), &id, now);
        assert_eq!(
            (broken.state, broken.evidence),
            ("unknown", "unreadable_record")
        );

        writer.stopped();
        let stopped = read_watcher_status(&root).unwrap().unwrap();
        let assessed = assess_liveness(Ok(Some(&stopped)), &id, now + 10_000);
        assert_eq!(
            (assessed.state, assessed.evidence),
            ("stopped", "stop_record")
        );
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
        fs::remove_dir_all(root).unwrap();
    }
}
