//! History, prune and rekey commands.

use anyhow::Result;
use chrono::{TimeZone, Utc};
use colored::Colorize;

use crate::util::{epoch_key_status, get_vault_store, DEFAULT_REKEY_WARN_DAYS};

pub(crate) fn cmd_history() -> Result<()> {
    let store = get_vault_store()?;
    let snapshots = store.list_snapshots()?;

    println!("{}", "CipherVault Snapshot History".bold());
    println!("--------------------------------------------------------------------------------");

    if snapshots.is_empty() {
        println!("No snapshots found.");
        return Ok(());
    }

    for (i, snap) in snapshots.iter().enumerate() {
        let snap_hex = hex::encode(&snap.snapshot_id);
        let time_str = Utc
            .timestamp_opt(snap.advisory_timestamp_utc as i64, 0)
            .single()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unknown".into());

        println!("[{}] Snapshot: {}", i + 1, snap_hex.yellow().bold());
        println!("    Timestamp:       {}", time_str);
        println!("    Device Counter:  {}", snap.device_counter);
        println!("    Epoch:           {}", snap.epoch);
        println!(
            "    Manifest CID:    {}",
            hex::encode(&snap.encrypted_manifest_cid).dimmed()
        );

        if snap.parent_snapshot_ids.is_empty() {
            println!("    Parents:         (genesis)");
        } else {
            let parents = snap
                .parent_snapshot_ids
                .iter()
                .map(|p| hex::encode(&p[0..4]))
                .collect::<Vec<_>>()
                .join(", ");
            println!("    Parents:         {}", parents);
        }
        println!();
    }

    Ok(())
}

/// Default and hard cap for `history --json --limit`.
pub(crate) const DEFAULT_HISTORY_JSON_LIMIT: usize = 20;
pub(crate) const MAX_HISTORY_JSON_LIMIT: usize = 100;

/// One snapshot in `history --json`: metadata only, never manifest
/// contents, file names, or plaintext.
#[derive(Debug, Clone, serde::Serialize)]
struct HistorySnapshotJson {
    /// Record CID: primary store key, the ID `status` reports as the active
    /// head, and the recovery checkpoint. Accepted by `restore` and `diff`.
    snapshot_id: String,
    /// Logical ID printed by `push` and the text `history`; also accepted.
    logical_id: String,
    /// Advisory timestamp signed into the record by the capturing device.
    recorded_at_utc: Option<u64>,
    epoch: u64,
    device_counter: u64,
    parent_snapshot_ids: Vec<String>,
    is_active_head: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct HistoryReportJson {
    vault: bool,
    cli_version: &'static str,
    order: &'static str,
    total: usize,
    returned: usize,
    limit: usize,
    truncated: bool,
    active_head_id: Option<String>,
    /// Stored records whose CID could not be computed (skipped, not listed).
    unreadable_records: usize,
    snapshots: Vec<HistorySnapshotJson>,
}

/// Snapshots with their record CIDs, newest first: advisory timestamp, then
/// device counter, then record CID, so equal timestamps sort deterministically.
/// Also returns how many records had no computable CID (skipped).
pub(crate) fn snapshots_newest_first(
    snapshots: &[ciphervault_format::SnapshotRecord],
) -> (Vec<([u8; 32], &ciphervault_format::SnapshotRecord)>, usize) {
    let mut unreadable = 0usize;
    let mut rows: Vec<([u8; 32], &ciphervault_format::SnapshotRecord)> = Vec::new();
    for snap in snapshots {
        match snap.compute_record_cid() {
            Ok(cid) => rows.push((cid, snap)),
            Err(_) => unreadable += 1,
        }
    }
    rows.sort_by(|(a_cid, a), (b_cid, b)| {
        b.advisory_timestamp_utc
            .cmp(&a.advisory_timestamp_utc)
            .then_with(|| b.device_counter.cmp(&a.device_counter))
            .then_with(|| b_cid.cmp(a_cid))
    });
    (rows, unreadable)
}

fn build_history_report(
    snapshots: &[ciphervault_format::SnapshotRecord],
    active_head: Option<[u8; 32]>,
    limit: usize,
) -> HistoryReportJson {
    let limit = limit.clamp(1, MAX_HISTORY_JSON_LIMIT);
    let (rows, unreadable) = snapshots_newest_first(snapshots);
    let total = rows.len();
    let listed: Vec<HistorySnapshotJson> = rows
        .iter()
        .take(limit)
        .map(|(cid, snap)| HistorySnapshotJson {
            snapshot_id: hex::encode(cid),
            logical_id: hex::encode(&snap.snapshot_id),
            recorded_at_utc: Some(snap.advisory_timestamp_utc).filter(|at| *at > 0),
            epoch: snap.epoch,
            device_counter: snap.device_counter,
            parent_snapshot_ids: snap.parent_snapshot_ids.iter().map(hex::encode).collect(),
            is_active_head: active_head == Some(*cid),
        })
        .collect();
    HistoryReportJson {
        vault: true,
        cli_version: env!("CARGO_PKG_VERSION"),
        order: "newest_first",
        total,
        returned: listed.len(),
        limit,
        truncated: total > listed.len(),
        active_head_id: active_head.map(hex::encode),
        unreadable_records: unreadable,
        snapshots: listed,
    }
}

/// `history --json`: bounded, newest-first snapshot metadata for agents
/// and scripts. A directory without a vault gets a parseable answer.
pub(crate) fn cmd_history_json(limit: Option<usize>) -> Result<()> {
    let limit = limit.unwrap_or(DEFAULT_HISTORY_JSON_LIMIT);
    let store = match get_vault_store() {
        Ok(store) => store,
        Err(err) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "vault": false,
                    "cli_version": env!("CARGO_PKG_VERSION"),
                    "order": "newest_first",
                    "total": 0,
                    "returned": 0,
                    "limit": limit.clamp(1, MAX_HISTORY_JSON_LIMIT),
                    "truncated": false,
                    "snapshots": [],
                    "error": err.to_string(),
                    "next": "Run 'ciphervault init' in this directory to create a vault."
                }))?
            );
            return Ok(());
        }
    };
    let snapshots = store.list_snapshots()?;
    let active_head: Option<[u8; 32]> = store
        .get_active_head()?
        .and_then(|head| head.snapshot_id.as_slice().try_into().ok());
    let report = build_history_report(&snapshots, active_head, limit);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

const DEFAULT_PRUNE_KEEP_LAST: usize = 10;
const DEFAULT_PRUNE_KEEP_DAYS: u64 = 30;

/// Snapshot metadata for retention selection.
struct PruneCandidate {
    record_cid: [u8; 32],
    created_at_utc: u64,
    is_head: bool,
    has_pending_upload: bool,
}

/// Selects prune targets under newest-first protection: keeps the newest
/// `keep_last`, anything younger than `keep_days`, plus the active head and
/// unreplicated snapshots always. Returns targets oldest-first for stable output.
fn select_prune_targets(
    candidates: &[PruneCandidate],
    keep_last: usize,
    keep_days: u64,
    now_utc: u64,
) -> Vec<[u8; 32]> {
    let mut ordered: Vec<&PruneCandidate> = candidates.iter().collect();
    ordered.sort_by(|a, b| {
        b.created_at_utc
            .cmp(&a.created_at_utc)
            .then_with(|| b.record_cid.cmp(&a.record_cid))
    });
    let cutoff = now_utc.saturating_sub(keep_days.saturating_mul(86_400));
    let mut targets = Vec::new();
    for (index, candidate) in ordered.iter().enumerate() {
        if candidate.is_head || candidate.has_pending_upload {
            continue;
        }
        if index < keep_last {
            continue;
        }
        if candidate.created_at_utc >= cutoff {
            continue;
        }
        targets.push(candidate.record_cid);
    }
    targets.reverse();
    targets
}

pub(crate) fn cmd_prune(
    keep_last: Option<usize>,
    keep_days: Option<u64>,
    dry_run: bool,
) -> Result<()> {
    let keep_last = keep_last.unwrap_or(DEFAULT_PRUNE_KEEP_LAST);
    let keep_days = keep_days.unwrap_or(DEFAULT_PRUNE_KEEP_DAYS);
    let store = get_vault_store()?;
    let snapshots = store.list_snapshots()?;
    if snapshots.is_empty() {
        println!("No snapshots found.");
        return Ok(());
    }
    let head_cid: Option<[u8; 32]> = store
        .get_active_head()?
        .and_then(|head| head.snapshot_id.as_slice().try_into().ok());
    let pending: std::collections::HashSet<[u8; 32]> = store
        .list_pending_uploads()?
        .into_iter()
        .map(|upload| upload.record_cid)
        .collect();
    let mut candidates = Vec::new();
    for snap in &snapshots {
        let Ok(record_cid) = snap.compute_record_cid() else {
            continue;
        };
        candidates.push(PruneCandidate {
            record_cid,
            created_at_utc: snap.advisory_timestamp_utc,
            is_head: head_cid == Some(record_cid),
            has_pending_upload: pending.contains(&record_cid),
        });
    }
    let now_utc = Utc::now().timestamp().max(0) as u64;
    let targets = select_prune_targets(&candidates, keep_last, keep_days, now_utc);

    println!("{}", "CipherVault Snapshot Retention".bold());
    println!("--------------------------------------------------------------------------------");
    println!("  Policy:         keep-last {keep_last}, keep-days {keep_days}");
    println!("  Snapshots:      {}", candidates.len());
    println!("  Prune targets:  {}", targets.len());
    for target in &targets {
        println!("    - {}", hex::encode(target).dimmed());
    }
    if dry_run {
        println!("  Dry run:        no changes made");
        return Ok(());
    }
    if targets.is_empty() {
        println!("  Nothing to prune.");
        return Ok(());
    }
    let outcome = store.prune_snapshots(&targets)?;
    println!(
        "  Removed:        {} snapshot(s)",
        outcome.snapshots_removed
    );
    println!(
        "  Skipped:        {} protected snapshot(s)",
        outcome.snapshots_skipped_protected
    );
    println!(
        "  Chunks:         {} removed ({} bytes reclaimed)",
        outcome.chunks_removed, outcome.chunk_bytes_reclaimed
    );
    if outcome.chunk_gc_skipped {
        println!("  Chunk GC:       skipped (a retained snapshot has no recovery set)");
    }
    Ok(())
}
pub(crate) fn cmd_rekey(check: bool, warn_days: Option<u64>) -> Result<()> {
    let warn_days = warn_days.unwrap_or(DEFAULT_REKEY_WARN_DAYS);
    let store = get_vault_store()?;
    let (_, _, _, current_epoch) = store.get_device_state()?;
    let epochs = store.list_epoch_keys()?;
    let now_utc = Utc::now().timestamp().max(0) as u64;

    println!("{}", "CipherVault Epoch Keys".bold());
    println!("--------------------------------------------------------------------------------");
    let mut stale_current = false;
    for info in &epochs {
        let (age, stale) = epoch_key_status(info.created_at_utc, warn_days, now_utc);
        let marker = if info.epoch == current_epoch {
            " (active)"
        } else {
            ""
        };
        match age {
            Some(days) => println!(
                "  Epoch {:>4}{}: {} day(s) old{}",
                info.epoch,
                marker,
                days,
                if stale { " -- STALE" } else { "" }
            ),
            None => println!("  Epoch {:>4}{}: age unknown -- ROTATE", info.epoch, marker),
        }
        if stale && info.epoch == current_epoch {
            stale_current = true;
        }
    }
    if check {
        if stale_current {
            println!("  Verdict:        active epoch key needs rotation");
        } else {
            println!("  Verdict:        rotation not required");
        }
        return Ok(());
    }
    let (next, _) = store.rotate_epoch_key()?;
    println!("  Rotated:        epoch {current_epoch} -> {next} (new snapshots use epoch {next})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: u8, at: u64, counter: u64) -> ciphervault_format::SnapshotRecord {
        ciphervault_format::SnapshotRecord {
            version: 1,
            vault_id: vec![1; 32],
            snapshot_id: vec![id; 32],
            parent_snapshot_ids: Vec::new(),
            device_id: vec![2; 32],
            device_counter: counter,
            authority_generation: 0,
            epoch: 1,
            encrypted_manifest_cid: vec![3; 32],
            encrypted_manifest_len: 10,
            advisory_timestamp_utc: at,
            signature: Vec::new(),
        }
    }

    #[test]
    fn history_json_is_newest_first_bounded_and_marks_head() {
        let records = vec![
            record(1, 1_000, 1),
            record(2, 3_000, 3),
            record(3, 2_000, 2),
            record(4, 0, 4), // pre-timestamp record: kept, time unknown
        ];
        let head = records[1].compute_record_cid().unwrap();
        let report = build_history_report(&records, Some(head), 2);
        assert_eq!(report.total, 4);
        assert_eq!(report.returned, 2);
        assert!(report.truncated);
        assert_eq!(report.snapshots[0].logical_id, hex::encode([2u8; 32]));
        assert_eq!(report.snapshots[0].snapshot_id, hex::encode(head));
        assert!(report.snapshots[0].is_active_head);
        assert_eq!(report.snapshots[1].logical_id, hex::encode([3u8; 32]));
        assert!(!report.snapshots[1].is_active_head);
        assert_eq!(report.active_head_id, Some(hex::encode(head)));

        let all = build_history_report(&records, None, MAX_HISTORY_JSON_LIMIT + 50);
        assert_eq!(all.limit, MAX_HISTORY_JSON_LIMIT);
        assert_eq!(all.returned, 4);
        assert!(!all.truncated);
        assert_eq!(all.snapshots[3].recorded_at_utc, None);
        let json = serde_json::to_value(&all).unwrap();
        assert!(json["snapshots"][0]["snapshot_id"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn history_json_for_empty_vault_is_explicit() {
        let report = build_history_report(&[], None, 5);
        assert_eq!(report.total, 0);
        assert_eq!(report.returned, 0);
        assert!(!report.truncated);
        assert!(report.snapshots.is_empty());
        assert!(report.active_head_id.is_none());
    }

    #[test]
    fn prune_selection_keeps_head_pending_recent_and_last_n() {
        let candidate = |id: u8, age_days: u64, head: bool, pending: bool| PruneCandidate {
            record_cid: [id; 32],
            created_at_utc: 2_000_000_000 - age_days * 86_400,
            is_head: head,
            has_pending_upload: pending,
        };
        let now = 2_000_000_000u64;
        let candidates = vec![
            candidate(1, 60, false, false),
            candidate(2, 45, false, false),
            candidate(3, 5, false, false),
            candidate(4, 90, true, false),
            candidate(5, 90, false, true),
        ];
        let targets = select_prune_targets(&candidates, 2, 30, now);
        assert_eq!(targets, vec![[1u8; 32]]);
        // keep-last 0 still protects head/pending/young.
        let targets = select_prune_targets(&candidates, 0, 30, now);
        assert_eq!(targets, vec![[1u8; 32], [2u8; 32]]);
    }
}
