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
