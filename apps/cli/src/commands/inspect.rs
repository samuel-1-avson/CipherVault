//! Status and doctor inspection commands.

use anyhow::{bail, Result};
use chrono::Utc;
use colored::Colorize;
use std::fs;

use ciphervault_storage::OperatorClient;

use crate::util::{
    epoch_key_status, get_active_vault_path, get_configured_operators, get_vault_store,
    mask_operator_endpoint, DEFAULT_REKEY_WARN_DAYS,
};

/// Machine-readable vault status for editor gutter feeds and CI (R17).
/// Field names are the gutter data contract; see docs/PLATFORM_SUPPORT.md.
#[derive(Debug, Clone, serde::Serialize)]
struct LeaseStatusJson {
    lease_id: String,
    operator: String,
    bytes: u64,
    expires_at_utc: u64,
    expired: bool,
}

/// Durable replication health: last operator-confirmed snapshot plus the
/// live backlog. Drives the CLI status section and the dashboard pill.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct SyncHealthJson {
    last_ok_at_utc: Option<i64>,
    last_ok_kind: Option<String>,
    last_ok_snapshot_hex: Option<String>,
    pending: u64,
    failed: u64,
    oldest_pending_at_utc: Option<i64>,
    last_error: Option<String>,
    key_backup_locator_hex: Option<String>,
    key_backup_at_utc: Option<i64>,
}

pub(crate) fn build_sync_health(
    store: &ciphervault_local_store::LocalVaultStore,
) -> Result<SyncHealthJson> {
    let latest = store.latest_sync_success()?;
    let summary = store.pending_upload_summary()?;
    let last_error = if summary.failed_count > 0 {
        store
            .list_pending_uploads()?
            .into_iter()
            .find(|upload| upload.attempts > 0)
            .and_then(|upload| upload.last_error)
    } else {
        None
    };
    let (kind, at, snapshot) = match latest {
        Some(entry) => {
            let snap = serde_json::from_str::<serde_json::Value>(&entry.details_json)
                .ok()
                .and_then(|value| value.get("snapshot_id")?.as_str().map(str::to_string));
            (Some(entry.event_type), Some(entry.created_at_utc), snap)
        }
        None => (None, None, None),
    };
    let key_backup = store.latest_key_backup()?;
    let (key_locator, key_at) = match key_backup {
        Some(entry) => {
            let locator = serde_json::from_str::<serde_json::Value>(&entry.details_json)
                .ok()
                .and_then(|value| value.get("locator")?.as_str().map(str::to_string));
            (locator, Some(entry.created_at_utc))
        }
        None => (None, None),
    };
    Ok(SyncHealthJson {
        last_ok_at_utc: at,
        last_ok_kind: kind,
        last_ok_snapshot_hex: snapshot,
        pending: summary.count,
        failed: summary.failed_count,
        oldest_pending_at_utc: summary.oldest_created_at_utc,
        last_error,
        key_backup_locator_hex: key_locator,
        key_backup_at_utc: key_at,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
struct StatusReport {
    /// Machine-readable status for agent/CI consumers. Stable fields:
    /// `vault` (bool), `cli_version`, `tracked_paths` (relative paths,
    /// never contents), `*_short` truncated identifiers (first 8 hex).
    /// The full `*_hex` fields are kept for existing consumers.
    vault: bool,
    cli_version: String,
    vault_id_hex: String,
    vault_id_short: String,
    device_id_hex: String,
    device_id_short: String,
    current_epoch: u64,
    device_counter: u64,
    active_head_hex: Option<String>,
    active_head_short: Option<String>,
    tracked_files: usize,
    tracked_paths: Vec<String>,
    working_tree_plaintext_files: usize,
    working_tree_sealed: bool,
    operators: Vec<String>,
    pending_uploads: usize,
    sync_health: SyncHealthJson,
    active_epoch_age_days: Option<u64>,
    active_epoch_stale: bool,
    leases: Vec<LeaseStatusJson>,
}

impl StatusReport {
    /// Builds a report, masking operator endpoints. Missing epoch metadata
    /// degrades honestly (`stale: true`, `age_days: null`).
    #[allow(clippy::too_many_arguments)]
    fn new(
        vault_id: &[u8; 32],
        device_id: &[u8; 32],
        current_epoch: u64,
        device_counter: u64,
        active_head: Option<[u8; 32]>,
        tracked_files: usize,
        tracked_paths: Vec<String>,
        operators: Vec<String>,
        pending_uploads: usize,
        sync_health: SyncHealthJson,
        active_epoch_created_at: Option<u64>,
        warn_days: u64,
        now_utc: u64,
        leases: Vec<LeaseStatusJson>,
    ) -> Self {
        let (age_days, stale) = match active_epoch_created_at {
            Some(created) => epoch_key_status(created, warn_days, now_utc),
            None => (None, true),
        };
        Self {
            vault: true,
            cli_version: env!("CARGO_PKG_VERSION").to_string(),
            vault_id_hex: hex::encode(vault_id),
            vault_id_short: short_hex(vault_id, 8),
            device_id_hex: hex::encode(device_id),
            device_id_short: short_hex(device_id, 8),
            current_epoch,
            device_counter,
            active_head_hex: active_head.map(hex::encode),
            active_head_short: active_head.as_ref().map(|h| short_hex(h, 8)),
            tracked_files,
            tracked_paths,
            working_tree_plaintext_files: tracked_files,
            working_tree_sealed: false,
            operators: operators
                .iter()
                .map(|op| mask_operator_endpoint(op))
                .collect::<Vec<_>>(),
            pending_uploads,
            sync_health,
            active_epoch_age_days: age_days,
            active_epoch_stale: stale,
            leases,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct OverviewSnapshotJson {
    snapshot_id_hex: String,
    epoch: u64,
    advisory_timestamp_utc: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OverviewAnchorJson {
    tx_hash_hex: String,
    block_number: u64,
    chain_id: u64,
    timestamp_utc: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OverviewActivityJson {
    event_type: String,
    summary: String,
    created_at_utc: i64,
}

/// My Data overview: local-first aggregation. Everything here reads the
/// on-device store; nothing phones home. Live replica health stays in `audit`.
#[derive(Debug, Clone, serde::Serialize)]
struct OverviewReport {
    vault_id_hex: String,
    device_id_hex: String,
    current_epoch: u64,
    snapshots: Vec<OverviewSnapshotJson>,
    active_head_hex: Option<String>,
    tracked_files: usize,
    tracked_bytes_on_disk: u64,
    operators: Vec<String>,
    leases: Vec<LeaseStatusJson>,
    anchors: Vec<OverviewAnchorJson>,
    recent_activity: Vec<OverviewActivityJson>,
}

fn short_hex(bytes: &[u8], len: usize) -> String {
    hex::encode(bytes).chars().take(len).collect::<String>()
}

fn build_overview_report(
    store: &ciphervault_local_store::LocalVaultStore,
    now_utc: u64,
) -> Result<OverviewReport> {
    let vault_id = store.get_vault_id()?;
    let (device_id, _, _, epoch) = store.get_device_state()?;
    let snapshots = store.list_snapshots()?;
    let active_head = store.get_active_head()?;
    let tracked = store.list_tracked_files()?;
    let operators = get_configured_operators();
    let lease_receipts = store.list_lease_receipts()?;
    let anchors = store.list_checkpoint_evidence()?;
    let activity = store.list_activity(5)?;

    let mut tracked_bytes: u64 = 0;
    for (rel_path, _) in &tracked {
        if let Ok(meta) = fs::metadata(crate::util::get_workspace_root()?.join(rel_path)) {
            tracked_bytes = tracked_bytes.saturating_add(meta.len());
        }
    }

    Ok(OverviewReport {
        vault_id_hex: hex::encode(vault_id),
        device_id_hex: hex::encode(device_id),
        current_epoch: epoch,
        snapshots: snapshots
            .iter()
            .map(|snap| OverviewSnapshotJson {
                snapshot_id_hex: hex::encode(&snap.snapshot_id),
                epoch: snap.epoch,
                advisory_timestamp_utc: snap.advisory_timestamp_utc,
            })
            .collect(),
        active_head_hex: active_head
            .as_ref()
            .map(|head| hex::encode(&head.snapshot_id)),
        tracked_files: tracked.len(),
        tracked_bytes_on_disk: tracked_bytes,
        operators: operators
            .iter()
            .map(|op| mask_operator_endpoint(op))
            .collect::<Vec<_>>(),
        leases: lease_receipts
            .iter()
            .map(|receipt| LeaseStatusJson {
                lease_id: receipt.lease_id.clone(),
                operator: mask_operator_endpoint(&receipt.operator_endpoint),
                bytes: receipt.bytes,
                expires_at_utc: receipt.expires_at_utc,
                expired: receipt.expires_at_utc <= now_utc,
            })
            .collect(),
        anchors: anchors
            .iter()
            .map(|evidence| OverviewAnchorJson {
                tx_hash_hex: hex::encode(&evidence.tx_hash),
                block_number: evidence.block_number,
                chain_id: evidence.chain_id,
                timestamp_utc: evidence.timestamp_utc,
            })
            .collect(),
        recent_activity: activity
            .iter()
            .map(|entry| OverviewActivityJson {
                event_type: entry.event_type.clone(),
                summary: entry.summary.clone(),
                created_at_utc: entry.created_at_utc,
            })
            .collect(),
    })
}

fn print_overview_report(report: &OverviewReport, now_utc: u64) {
    println!("{}", "CipherVault My Data Overview".bold());
    println!("--------------------------------------------------");
    println!("  Vault ID:        {}", report.vault_id_hex.yellow());
    println!("  Device ID:       {}", report.device_id_hex.cyan());
    println!("  Current Epoch:   {}", report.current_epoch);

    println!("\nSnapshots ({}):", report.snapshots.len());
    match &report.active_head_hex {
        Some(head) => println!(
            "  Active Head:     {}",
            short_hex(&hex::decode(head).unwrap_or_default(), 16).green()
        ),
        None => println!(
            "  Active Head:     {}",
            "None (no snapshots committed yet)".dimmed()
        ),
    }
    for snap in report.snapshots.iter().rev().take(5) {
        println!(
            "  - {} (epoch {}, t={})",
            short_hex(&hex::decode(&snap.snapshot_id_hex).unwrap_or_default(), 16),
            snap.epoch,
            snap.advisory_timestamp_utc,
        );
    }
    if report.snapshots.len() > 5 {
        println!("  ... and {} older", report.snapshots.len() - 5);
    }

    println!(
        "\nTracked Files ({}):      {} bytes on disk",
        report.tracked_files, report.tracked_bytes_on_disk
    );
    println!("\nOperators ({}):", report.operators.len());
    for op in &report.operators {
        println!("  - {}", op.cyan());
    }

    println!("\nStorage Leases ({}):", report.leases.len());
    for lease in &report.leases {
        let expiry = if lease.expired {
            "expired".red()
        } else {
            let days_left = lease.expires_at_utc.saturating_sub(now_utc) / 86400;
            format!("in {}d", days_left).green()
        };
        println!(
            "  - {} [{}] {} bytes ({})",
            lease.lease_id.chars().take(12).collect::<String>().yellow(),
            lease.operator.cyan(),
            lease.bytes,
            expiry,
        );
    }

    println!("\nAnchors ({}):", report.anchors.len());
    for anchor in &report.anchors {
        println!(
            "  - tx {} block {} (chain {})",
            short_hex(&hex::decode(&anchor.tx_hash_hex).unwrap_or_default(), 16),
            anchor.block_number,
            anchor.chain_id,
        );
    }

    println!("\nRecent Activity ({}):", report.recent_activity.len());
    for entry in &report.recent_activity {
        println!("  - [{}] {}", entry.event_type.dimmed(), entry.summary);
    }
}

pub(crate) fn cmd_status(json: bool, overview: bool) -> Result<()> {
    let store = match get_vault_store() {
        Ok(store) => store,
        Err(err) if json && !overview => {
            // Machine consumers (agent plugins) need a parseable
            // "no vault here" answer, not a human error banner.
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "vault": false,
                    "cli_version": env!("CARGO_PKG_VERSION"),
                    "tracked_paths": [],
                    "tracked_files": 0,
                    "operators": [],
                    "error": err.to_string(),
                    "next": "Run 'ciphervault init' in this directory to create a vault."
                }))?
            );
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    if overview {
        let now_utc = Utc::now().timestamp().max(0) as u64;
        let report = build_overview_report(&store, now_utc)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_overview_report(&report, now_utc);
        }
        return Ok(());
    }
    let vault_id = store.get_vault_id()?;
    let (device_id, _, counter, epoch) = store.get_device_state()?;
    let tracked = store.list_tracked_files()?;
    let active_head = store.get_active_head()?;
    let operators = get_configured_operators();
    let pending_uploads = store.list_pending_uploads()?.len();
    let epoch_created_at = store
        .list_epoch_keys()?
        .into_iter()
        .find(|info| info.epoch == epoch)
        .map(|info| info.created_at_utc);
    let now_utc = Utc::now().timestamp().max(0) as u64;
    let head_cid: Option<[u8; 32]> = active_head
        .as_ref()
        .and_then(|head| head.snapshot_id.as_slice().try_into().ok());
    let lease_receipts = store.list_lease_receipts()?;
    let lease_statuses: Vec<LeaseStatusJson> = lease_receipts
        .iter()
        .map(|receipt| LeaseStatusJson {
            lease_id: receipt.lease_id.clone(),
            operator: mask_operator_endpoint(&receipt.operator_endpoint),
            bytes: receipt.bytes,
            expires_at_utc: receipt.expires_at_utc,
            expired: receipt.expires_at_utc <= now_utc,
        })
        .collect();

    let sync_health = build_sync_health(&store)?;
    let root_dir = crate::util::get_workspace_root()?;
    let plaintext_on_disk_count = tracked
        .iter()
        .filter(|(rel_path, _)| root_dir.join(rel_path).exists())
        .count();
    let working_tree_sealed =
        head_cid.is_some() && !tracked.is_empty() && plaintext_on_disk_count == 0;
    if json {
        let mut report = StatusReport::new(
            &vault_id,
            &device_id,
            epoch,
            counter,
            head_cid,
            tracked.len(),
            tracked
                .iter()
                .map(|(p, _)| p.to_string_lossy().replace('\\', "/"))
                .collect(),
            operators,
            pending_uploads,
            sync_health,
            epoch_created_at,
            DEFAULT_REKEY_WARN_DAYS,
            now_utc,
            lease_statuses,
        );
        report.working_tree_plaintext_files = plaintext_on_disk_count;
        report.working_tree_sealed = working_tree_sealed;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{}", "CipherVault Status".bold());
    println!("--------------------------------------------------");
    println!("  Vault ID:        {}", hex::encode(vault_id).yellow());
    println!("  Device ID:       {}", hex::encode(device_id).cyan());
    println!("  Current Epoch:   {}", epoch);
    println!("  Device Counter:  {}", counter);

    if let Some(ref head) = active_head {
        println!(
            "  Active Head:     {}",
            hex::encode(&head.snapshot_id).green()
        );
    } else {
        println!(
            "  Active Head:     {}",
            "None (no snapshots committed yet)".dimmed()
        );
    }

    println!("\nConfigured Operators ({}):", operators.len());
    for op in operators {
        println!("  - {}", mask_operator_endpoint(&op).cyan());
    }

    println!("\nTracked Confidential Files ({}):", tracked.len());
    if tracked.is_empty() {
        println!(
            "  (None). Use '{}' to track files like .env or keys.",
            "ciphervault track <path>".cyan()
        );
    } else {
        for (rel_path, file_id) in tracked {
            let full_path = root_dir.join(&rel_path);
            let exists = full_path.exists();
            let state = if exists {
                match fs::metadata(&full_path) {
                    Ok(meta) => format!("{} bytes", meta.len()).green(),
                    Err(error) => format!("unreadable ({error})").red(),
                }
            } else if active_head.is_some() {
                "sealed in vault (0 bytes on disk)".cyan()
            } else {
                "missing on disk".red()
            };
            println!(
                "  - {:<30} [{}] (ID: {})",
                rel_path.display(),
                state,
                hex::encode(&file_id[0..4]).dimmed()
            );
        }
    }

    println!("\nStorage Leases ({}):", lease_receipts.len());
    if lease_receipts.is_empty() {
        println!(
            "  (None). Use '{}' to pin a snapshot closure on an operator.",
            "ciphervault lease create <closure> <bytes>".cyan()
        );
    } else {
        for receipt in &lease_receipts {
            let short_id: String = receipt.lease_id.chars().take(12).collect();
            let expiry = if receipt.expires_at_utc <= now_utc {
                "expired".red()
            } else {
                let days_left = (receipt.expires_at_utc - now_utc) / 86400;
                format!("in {}d", days_left).green()
            };
            println!(
                "  - {} [{}] {} bytes ({})",
                short_id.yellow(),
                mask_operator_endpoint(&receipt.operator_endpoint).cyan(),
                receipt.bytes,
                expiry,
            );
        }
    }

    print_sync_health(&sync_health, now_utc);

    Ok(())
}

fn print_sync_health(health: &SyncHealthJson, now_utc: u64) {
    let state = if health.failed > 0 {
        "Degraded".red().bold()
    } else if health.pending > 0 {
        "Behind".yellow().bold()
    } else if health.last_ok_at_utc.is_some() {
        "Healthy".green().bold()
    } else {
        "Never replicated".red().bold()
    };
    println!("\nReplication Health: {state}");
    match health.last_ok_at_utc {
        Some(at) => {
            let age = now_utc.saturating_sub(at.max(0) as u64);
            let kind = health.last_ok_kind.as_deref().unwrap_or("sync");
            let snap = health
                .last_ok_snapshot_hex
                .as_ref()
                .map(|hex| short_hex(&hex::decode(hex).unwrap_or_default(), 12))
                .unwrap_or_else(|| "-".to_string());
            println!("  Last confirmed: {kind} {snap} ({} ago)", humane_age(age));
        }
        None => println!(
            "  Last confirmed: {}",
            "none — run 'ciphervault push' or start 'ciphervault watch --sync'".dimmed()
        ),
    }
    if health.pending > 0 {
        println!(
            "  Backlog:        {} pending ({} failed)",
            health.pending, health.failed
        );
        if let Some(err) = &health.last_error {
            println!(
                "  Last error:     {}",
                err.chars().take(160).collect::<String>()
            );
        }
    }
    match (&health.key_backup_locator_hex, health.key_backup_at_utc) {
        (Some(locator), Some(at)) => {
            let age = now_utc.saturating_sub(at.max(0) as u64);
            let short: String = locator.chars().take(12).collect();
            println!("  Key backup:     {short}… ({} ago)", humane_age(age));
        }
        _ => println!(
            "  Key backup:     {}",
            "none — run 'ciphervault recovery key-backup'".dimmed()
        ),
    }
}

fn humane_age(secs: u64) -> String {
    if secs < 90 {
        format!("{secs}s")
    } else if secs < 5400 {
        format!("{}m", secs / 60)
    } else if secs < 172800 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

struct DoctorCheck {
    name: &'static str,
    ok: bool,
    detail: String,
}

/// Recovery coverage from the activity log: a recorded passphrase key
/// backup, or a kit drill (`recovery test`) that restored this vault.
/// Either proves a path back if this machine is lost.
pub(crate) fn recovery_coverage(
    entries: &[ciphervault_local_store::ActivityEntry],
    now_utc: i64,
) -> (bool, String) {
    if entries.iter().any(|e| e.event_type == "KEYBACKUP_OK") {
        return (
            true,
            "passphrase key-backup recorded (see activity log for locator)".to_string(),
        );
    }
    if let Some(drill) = entries
        .iter()
        .filter(|e| e.event_type == "RECOVERY_TEST_OK")
        .max_by_key(|e| e.created_at_utc)
    {
        let days = now_utc.saturating_sub(drill.created_at_utc).max(0) / 86_400;
        return (
            true,
            format!(
                "kit recovery drill passed {days} day(s) ago — re-run 'recovery test --kit <file>' after changing operators"
            ),
        );
    }
    (
        false,
        "no passphrase key-backup or passed kit drill on record — run 'recovery key-backup --kit <file>' or drill with 'recovery test --kit <file>'".to_string(),
    )
}

fn doctor_report(checks: &[DoctorCheck]) -> serde_json::Value {
    let failures = checks.iter().filter(|check| !check.ok).count();
    let rendered: Vec<serde_json::Value> = checks
        .iter()
        .map(|check| {
            serde_json::json!({
                "name": check.name,
                "ok": check.ok,
                "detail": check.detail,
            })
        })
        .collect();
    serde_json::json!({
        "status": if failures == 0 { "ok" } else { "degraded" },
        "failures": failures,
        "checks": rendered,
    })
}

/// Local self-check: vault database, OS keyring, operator reachability,
/// quorum, and anchor freshness. Prints a human report (or JSON with `--json`)
/// and fails when any check fails, for monitoring scripts.
pub(crate) async fn cmd_doctor(json: bool) -> Result<()> {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    // 1. Vault database opens and core state reads back.
    let store = get_vault_store().ok();
    match store.as_ref() {
        Some(store) => match (|| -> Result<String> {
            let vault_id = store.get_vault_id()?;
            let tracked = store.list_tracked_files()?;
            let head = store.get_active_head()?;
            Ok(format!(
                "vault={} tracked={} head={}",
                hex::encode(vault_id),
                tracked.len(),
                head.map(|record| hex::encode(&record.snapshot_id))
                    .unwrap_or_else(|| "none".to_string())
            ))
        })() {
            Ok(detail) => checks.push(DoctorCheck {
                name: "vault",
                ok: true,
                detail,
            }),
            Err(error) => checks.push(DoctorCheck {
                name: "vault",
                ok: false,
                detail: format!("read failed: {error}"),
            }),
        },
        None => checks.push(DoctorCheck {
            name: "vault",
            ok: false,
            detail: format!("no vault at {}", get_active_vault_path().display()),
        }),
    }

    // 2. OS keyring round-trip with random (non-secret) bytes.
    let mut probe = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut probe);
    match ciphervault_local_store::protect_secret(&probe)
        .ok()
        .and_then(|sealed| ciphervault_local_store::unprotect_secret(&sealed).ok())
    {
        Some(opened) if opened == probe => checks.push(DoctorCheck {
            name: "keyring",
            ok: true,
            detail: format!(
                "protect/unprotect round-trip ok ({})",
                ciphervault_local_store::active_keyring_backend()
            ),
        }),
        _ => checks.push(DoctorCheck {
            name: "keyring",
            ok: false,
            detail: "OS keyring round-trip failed".to_string(),
        }),
    }

    // 3-4. Operator reachability counts toward quorum.
    let operators = get_configured_operators();
    let mut reachable = 0usize;
    let mut operator_details = Vec::new();
    for endpoint in &operators {
        let client = OperatorClient::new(endpoint.clone());
        match client.get_info().await {
            Ok(info) => {
                reachable += 1;
                operator_details.push(format!(
                    "{} ok ({})",
                    mask_operator_endpoint(endpoint),
                    info.operator_id
                ));
            }
            Err(error) => {
                operator_details.push(format!(
                    "{} unreachable ({error})",
                    mask_operator_endpoint(endpoint)
                ));
            }
        }
    }
    checks.push(DoctorCheck {
        name: "operators",
        ok: reachable == operators.len() && !operators.is_empty(),
        detail: operator_details.join("; "),
    });
    let quorum = operators.len() / 2 + 1;
    checks.push(DoctorCheck {
        name: "quorum",
        ok: reachable >= quorum,
        detail: format!(
            "reachable={reachable} required={quorum} total={}",
            operators.len()
        ),
    });

    // 5. Anchor freshness from local checkpoint evidence.
    match store.as_ref() {
        Some(store) => match store.list_checkpoint_evidence() {
            Ok(evidence) => {
                let newest = evidence.iter().map(|entry| entry.timestamp_utc).max();
                match newest {
                    Some(timestamp) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|elapsed| elapsed.as_secs())
                            .unwrap_or(timestamp);
                        let age = now.saturating_sub(timestamp);
                        checks.push(DoctorCheck {
                            name: "anchors",
                            ok: true,
                            detail: format!("newest evidence age={age}s count={}", evidence.len()),
                        });
                    }
                    None => checks.push(DoctorCheck {
                        name: "anchors",
                        ok: true,
                        detail: "no local checkpoint evidence yet".to_string(),
                    }),
                }
            }
            Err(error) => checks.push(DoctorCheck {
                name: "anchors",
                ok: false,
                detail: format!("evidence read failed: {error}"),
            }),
        },
        None => checks.push(DoctorCheck {
            name: "anchors",
            ok: false,
            detail: "skipped (no vault)".to_string(),
        }),
    }

    // 6. Recovery coverage: a recorded passphrase backup or a tested kit.
    // Lose the paper kit with neither and the vault is unrecoverable (U-M).
    match store.as_ref() {
        Some(store) => match store.list_activity(200) {
            Ok(entries) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let (ok, detail) = recovery_coverage(&entries, now);
                checks.push(DoctorCheck {
                    name: "recovery",
                    ok,
                    detail,
                });
            }
            Err(error) => checks.push(DoctorCheck {
                name: "recovery",
                ok: false,
                detail: format!("activity read failed: {error}"),
            }),
        },
        None => checks.push(DoctorCheck {
            name: "recovery",
            ok: false,
            detail: "skipped (no vault)".to_string(),
        }),
    }

    let failures = checks.iter().filter(|check| !check.ok).count();
    if json {
        println!("{}", serde_json::to_string_pretty(&doctor_report(&checks))?);
    } else {
        println!("{}", "CipherVault Doctor".bold());
        println!("--------------------------------------------------");
        for check in &checks {
            let state = if check.ok {
                "PASS".green()
            } else {
                "FAIL".red()
            };
            println!("  [{state}] {:<10} {}", check.name, check.detail);
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        bail!("doctor: {failures} failing check(s)")
    }
}

fn is_valid_env_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn strip_dotenv_inline_comment(val: &str) -> &str {
    let mut best = val.len();
    for marker in [" #", "\t#"] {
        if let Some(pos) = val.find(marker) {
            if pos < best {
                best = pos;
            }
        }
    }
    &val[..best]
}

fn is_placeholder_value(val: &str) -> bool {
    let lower = val.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "changeme"
            | "change_me"
            | "change-me"
            | "your_api_key"
            | "your_api_key_here"
            | "your-api-key"
            | "your-key-here"
            | "your_secret_here"
            | "replace_me"
            | "replaceme"
            | "todo"
            | "tbd"
            | "xxx"
            | "xxxx"
            | "xxxxx"
            | "placeholder"
            | "<insert>"
    ) || lower.starts_with("your_")
        || lower.starts_with("your-")
        || lower.starts_with("<your")
}

fn expected_key_prefixes(key: &str) -> Option<&'static [&'static str]> {
    match key {
        "OPENAI_API_KEY" => Some(&["sk-"]),
        "ANTHROPIC_API_KEY" => Some(&["sk-ant-"]),
        "GEMINI_API_KEY" | "GOOGLE_API_KEY" => Some(&["AIza"]),
        "STRIPE_SECRET_KEY" | "STRIPE_API_KEY" => Some(&["sk_live_", "sk_test_", "rk_live_", "rk_test_"]),
        "STRIPE_PUBLISHABLE_KEY" => Some(&["pk_live_", "pk_test_"]),
        "GITHUB_TOKEN" | "GH_TOKEN" => Some(&["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]),
        "HF_TOKEN" | "HUGGINGFACE_TOKEN" => Some(&["hf_"]),
        "OPENROUTER_API_KEY" => Some(&["sk-or-"]),
        _ => None,
    }
}

pub(crate) fn lint_dotenv_bytes(
    bytes: &[u8],
    keys_out: &mut std::collections::BTreeSet<String>,
    anomalies_out: &mut Vec<serde_json::Value>,
    seen_pairs: &mut std::collections::BTreeSet<(String, String)>,
) {
    use zeroize::Zeroize;
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    for raw_line in text.split_inclusive('\n') {
        let line_no_bom = raw_line.trim_start_matches('\u{feff}');
        let trimmed = line_no_bom.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let body = line_no_bom.trim_start();
        let body = body.strip_prefix("export ").map(str::trim_start).unwrap_or(body);
        let Some((raw_key, raw_rhs)) = body.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        if !is_valid_env_ident(key) {
            continue;
        }
        keys_out.insert(key.to_string());

        let mut issues: Vec<&'static str> = Vec::new();
        let raw_no_nl = raw_rhs.strip_suffix('\n').unwrap_or(raw_rhs);
        let (raw_no_nl, had_cr) = match raw_no_nl.strip_suffix('\r') {
            Some(s) => (s, true),
            None => (raw_no_nl, false),
        };
        let stripped = raw_no_nl.trim();
        let val: String = if (stripped.starts_with('"') && stripped.ends_with('"') && stripped.len() >= 2)
            || (stripped.starts_with('\'') && stripped.ends_with('\'') && stripped.len() >= 2)
        {
            let inner = &stripped[1..stripped.len() - 1];
            if inner != inner.trim() || had_cr {
                issues.push("WHITESPACE_WRAPPED");
            }
            if (inner.starts_with('"') && inner.ends_with('"') && inner.len() >= 2)
                || (inner.starts_with('\'') && inner.ends_with('\'') && inner.len() >= 2)
            {
                issues.push("UNSTRIPPED_QUOTES");
            }
            inner.to_string()
        } else {
            let before_comment = strip_dotenv_inline_comment(raw_no_nl);
            let before_comment = if before_comment.starts_with('#') {
                ""
            } else {
                before_comment
            };
            if !before_comment.is_empty()
                && (before_comment != before_comment.trim_matches([' ', '\t']) || had_cr)
            {
                issues.push("WHITESPACE_WRAPPED");
            }
            let v = before_comment.trim();
            if (v.starts_with('"') && !v.ends_with('"'))
                || (v.ends_with('"') && !v.starts_with('"'))
                || (v.starts_with('\'') && !v.ends_with('\''))
                || (v.ends_with('\'') && !v.starts_with('\''))
                || v == "\""
                || v == "'"
            {
                issues.push("UNSTRIPPED_QUOTES");
            }
            v.to_string()
        };

        let val_trimmed = val.trim();
        if val_trimmed.is_empty() {
            issues.push("EMPTY_VALUE");
        } else if is_placeholder_value(val_trimmed) {
            issues.push("PLACEHOLDER_VALUE");
        } else {
            if key.ends_with("_URL")
                || key.ends_with("_URI")
                || key.ends_with("_ENDPOINT")
                || key.ends_with("_DSN")
            {
                let url_ok = if val_trimmed.chars().any(char::is_whitespace) {
                    false
                } else if let Some((scheme, rest)) = val_trimmed.split_once("://") {
                    let scheme_ok = !scheme.is_empty()
                        && scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                        && scheme
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
                    let host_ok = !rest.is_empty() && !rest.starts_with('/');
                    let file_ok =
                        matches!(scheme.to_ascii_lowercase().as_str(), "sqlite" | "file") && !rest.is_empty();
                    scheme_ok && (host_ok || file_ok)
                } else {
                    false
                };
                if !url_ok {
                    issues.push("INVALID_URL");
                }
            }
            if key.ends_with("_JSON") && serde_json::from_str::<serde_json::Value>(val_trimmed).is_err() {
                issues.push("INVALID_JSON");
            }
            if let Some(prefixes) = expected_key_prefixes(key) {
                if !prefixes.iter().any(|p| val.starts_with(p)) {
                    issues.push("PREFIX_MISMATCH");
                }
            }
        }
        let mut zeroize_val = val;
        zeroize_val.zeroize();

        for issue in issues {
            let pair = (key.to_string(), issue.to_string());
            if seen_pairs.insert(pair) {
                anomalies_out.push(serde_json::json!({
                    "key": key,
                    "issue": issue,
                }));
            }
        }
    }
    text.zeroize();
}

fn extract_ident_after(haystack: &str, needle: &str, out: &mut std::collections::BTreeSet<String>) {
    let mut rest = haystack;
    while let Some(pos) = rest.find(needle) {
        let after = &rest[pos + needle.len()..];
        let ident_len = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .map(char::len_utf8)
            .sum::<usize>();
        if ident_len > 0 {
            let cand = &after[..ident_len];
            if is_valid_env_ident(cand) {
                out.insert(cand.to_string());
            }
        }
        rest = &after[ident_len..];
    }
}

fn extract_quoted_arg_after(
    haystack: &str,
    needle: &str,
    out: &mut std::collections::BTreeSet<String>,
) {
    let mut rest = haystack;
    while let Some(pos) = rest.find(needle) {
        let after = rest[pos + needle.len()..].trim_start();
        let first = after.chars().next();
        if matches!(first, Some('"' | '\'')) {
            let q = first.unwrap();
            let inner = &after[1..];
            if let Some(end) = inner.find(q) {
                let cand = &inner[..end];
                if is_valid_env_ident(cand) {
                    out.insert(cand.to_string());
                }
            }
        }
        rest = &rest[pos + needle.len()..];
    }
}

fn scan_code_env_refs(root: &std::path::Path) -> std::collections::BTreeSet<String> {
    let mut refs = std::collections::BTreeSet::new();
    let skip_dirs = [
        ".git",
        ".ciphervault",
        "node_modules",
        "target",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
    ];
    let exts = ["py", "js", "ts", "tsx", "jsx", "rs", "go", "rb", "sh", "yml", "yaml"];
    let mut stack = vec![root.to_path_buf()];
    let mut files_seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut sorted: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        sorted.sort_by_key(|e| e.file_name());
        for entry in sorted {
            if files_seen >= 400 {
                return refs;
            }
            let path = entry.path();
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                if !skip_dirs.contains(&fname_str.as_ref()) {
                    stack.push(path);
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let is_docker = fname_str == "Dockerfile" || fname_str.starts_with("Dockerfile.");
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .unwrap_or_default();
            if !is_docker && !exts.contains(&ext.as_str()) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.len() > 512 * 1024 {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            files_seen += 1;
            extract_ident_after(&content, "process.env.", &mut refs);
            extract_ident_after(&content, "import.meta.env.", &mut refs);
            extract_quoted_arg_after(&content, "os.environ.get(", &mut refs);
            extract_quoted_arg_after(&content, "os.environ[", &mut refs);
            extract_quoted_arg_after(&content, "os.getenv(", &mut refs);
            extract_quoted_arg_after(&content, "std::env::var(", &mut refs);
            extract_quoted_arg_after(&content, "std::env::var_os(", &mut refs);
            extract_quoted_arg_after(&content, "env::var(", &mut refs);
            extract_quoted_arg_after(&content, "os.Getenv(", &mut refs);
            if matches!(ext.as_str(), "yml" | "yaml") || is_docker {
                let mut slice = content.as_str();
                while let Some(pos) = slice.find("${") {
                    let after = &slice[pos + 2..];
                    let ident_len = after
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .map(char::len_utf8)
                        .sum::<usize>();
                    if ident_len > 0 {
                        let cand = &after[..ident_len];
                        if cand.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                            && is_valid_env_ident(cand)
                        {
                            refs.insert(cand.to_string());
                        }
                    }
                    slice = &after[ident_len..];
                }
            }
        }
    }
    refs
}

pub(crate) fn cmd_env_doctor(
    env_file: Option<String>,
    sync_env_example: bool,
    json: bool,
) -> Result<()> {
    use zeroize::Zeroize;
    let root = crate::util::get_workspace_root().unwrap_or_else(|_| {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    });
    let mut vault_keys = std::collections::BTreeSet::new();
    let mut anomalies = Vec::new();
    let mut seen_pairs = std::collections::BTreeSet::new();
    let mut sealed = false;

    let store_opt = get_vault_store().ok();
    let tracked: Vec<String> = store_opt
        .as_ref()
        .and_then(|s| s.list_tracked_files().ok())
        .map(|list| {
            list.into_iter()
                .map(|(p, _)| p.to_string_lossy().replace('\\', "/"))
                .collect()
        })
        .unwrap_or_default();

    let target_rel_files: Vec<String> = if let Some(ref rel) = env_file {
        let clean = rel.trim().replace('\\', "/");
        if clean.is_empty() || clean.starts_with('/') || clean.split('/').any(|p| p == "..") {
            bail!("env_file must stay inside workspace cwd");
        }
        vec![clean]
    } else if !tracked.is_empty() {
        tracked
            .iter()
            .filter(|rel| {
                let name = rel.rsplit('/').next().unwrap_or(rel);
                (name == ".env" || name.starts_with(".env.") || name.ends_with(".env"))
                    && !name.ends_with(".example")
                    && !name.ends_with(".sample")
                    && !name.ends_with(".template")
            })
            .cloned()
            .collect()
    } else {
        [".env", ".env.local", ".env.development", ".env.production", ".env.test"]
            .iter()
            .filter(|name| root.join(name).is_file())
            .map(|s| (*s).to_string())
            .collect()
    };

    let mut any_on_disk = false;
    for rel in &target_rel_files {
        let full = root.join(rel);
        if let Ok(mut bytes) = fs::read(&full) {
            any_on_disk = true;
            lint_dotenv_bytes(&bytes, &mut vault_keys, &mut anomalies, &mut seen_pairs);
            bytes.zeroize();
        }
    }

    if !any_on_disk {
        if let Some(ref store) = store_opt {
            if let Ok(mut bundle) = super::run::load_local_snapshot_bundle_sync(store) {
                sealed = !tracked.is_empty();
                for file in &mut bundle.files {
                    let norm = file.relative_path.replace('\\', "/");
                    let matches_target = if let Some(ref want) = env_file {
                        norm == want.trim().replace('\\', "/")
                    } else {
                        let name = norm.rsplit('/').next().unwrap_or(&norm);
                        name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
                    };
                    if matches_target {
                        lint_dotenv_bytes(
                            &file.plaintext,
                            &mut vault_keys,
                            &mut anomalies,
                            &mut seen_pairs,
                        );
                    }
                    file.plaintext.zeroize();
                }
            }
        }
    }

    let referenced = scan_code_env_refs(&root);
    let example_path = root.join(".env.example");
    let mut example_keys = std::collections::BTreeSet::new();
    if let Ok(ex_text) = fs::read_to_string(&example_path) {
        for raw_line in ex_text.lines() {
            let line = raw_line.trim().trim_start_matches('\u{feff}');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").map(str::trim_start).unwrap_or(line);
            if let Some((k, _)) = line.split_once('=') {
                let k = k.trim();
                if is_valid_env_ident(k) {
                    example_keys.insert(k.to_string());
                }
            }
        }
    }

    let mut expected = referenced.clone();
    expected.extend(example_keys.iter().cloned());
    let missing_in_vault: Vec<String> = expected.difference(&vault_keys).cloned().collect();
    let unreferenced_in_code: Vec<String> = vault_keys.difference(&referenced).cloned().collect();

    let mut synced_added: Vec<String> = Vec::new();
    if sync_env_example {
        let mut desired = vault_keys.clone();
        desired.extend(referenced.iter().cloned());
        for k in &desired {
            if !example_keys.contains(k) {
                synced_added.push(k.clone());
                example_keys.insert(k.clone());
            }
        }
        if !synced_added.is_empty() || !example_path.exists() {
            let mut existing = fs::read_to_string(&example_path).unwrap_or_default();
            if !existing.is_empty() && !existing.ends_with('\n') {
                existing.push('\n');
            }
            for k in &synced_added {
                existing.push_str(&format!("{k}= # [required]\n"));
            }
            fs::write(&example_path, existing)?;
        }
    }

    let mut out = serde_json::json!({
        "success": true,
        "sealed": sealed,
        "vault_keys": vault_keys.into_iter().collect::<Vec<_>>(),
        "referenced_in_code": referenced.into_iter().collect::<Vec<_>>(),
        "example_keys": example_keys.into_iter().collect::<Vec<_>>(),
        "missing_in_vault": missing_in_vault,
        "unreferenced_in_code": unreferenced_in_code,
        "value_anomalies": anomalies,
    });
    if sync_env_example {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("env_example_synced".to_string(), serde_json::Value::Bool(true));
            obj.insert(
                "env_example_added".to_string(),
                serde_json::json!(synced_added),
            );
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("{}", "CipherVault Environment Doctor".bold());
        println!("  Vault keys:       {}", out["vault_keys"].as_array().map(|a| a.len()).unwrap_or(0));
        println!("  Missing keys:     {}", out["missing_in_vault"].as_array().map(|a| a.len()).unwrap_or(0));
        println!("  Value anomalies:  {}", out["value_anomalies"].as_array().map(|a| a.len()).unwrap_or(0));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_coverage_accepts_a_passed_kit_drill() {
        let entry = |event: &str, at: i64| ciphervault_local_store::ActivityEntry {
            id: 1,
            event_type: event.to_string(),
            summary: String::new(),
            details_json: "{}".to_string(),
            created_at_utc: at,
        };
        let now = 1_800_000_000;
        let (ok, detail) = recovery_coverage(&[], now);
        assert!(!ok && detail.contains("recovery test --kit"), "{detail}");
        let (ok, detail) = recovery_coverage(&[entry("PUSH_OK", now)], now);
        assert!(!ok, "a push is not recovery coverage: {detail}");
        let (ok, detail) = recovery_coverage(&[entry("RECOVERY_TEST_OK", now - 3 * 86_400)], now);
        assert!(ok, "{detail}");
        assert!(detail.contains("3 day"), "{detail}");
        let (ok, detail) = recovery_coverage(&[entry("KEYBACKUP_OK", now)], now);
        assert!(ok && detail.contains("key-backup"), "{detail}");
    }

    #[test]
    fn status_report_masks_operators_and_marks_stale_epoch() {
        let report = StatusReport::new(
            &[0x11u8; 32],
            &[0x22u8; 32],
            3,
            42,
            Some([0x33u8; 32]),
            2,
            vec![".env".to_string()],
            vec!["http://192.0.2.10:8101".to_string()],
            1,
            SyncHealthJson {
                last_ok_at_utc: Some(2_000_000_000 - 60),
                last_ok_kind: Some("PUSH_OK".to_string()),
                last_ok_snapshot_hex: Some("ab".repeat(32)),
                pending: 1,
                failed: 0,
                oldest_pending_at_utc: Some(2_000_000_000 - 30),
                last_error: None,
                key_backup_locator_hex: Some("cc".repeat(32)),
                key_backup_at_utc: Some(2_000_000_000 - 3600),
            },
            Some(2_000_000_000 - 100 * 86_400),
            90,
            2_000_000_000,
            vec![LeaseStatusJson {
                lease_id: "lease-1".to_string(),
                operator: "https://op1.cipherv.online".to_string(),
                bytes: 100,
                expires_at_utc: 2_000_000_000 + 86_400,
                expired: false,
            }],
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["leases"][0]["lease_id"], serde_json::json!("lease-1"));
        assert_eq!(json["leases"][0]["expired"], serde_json::json!(false));
        assert_eq!(json["vault_id_hex"], serde_json::json!("11".repeat(32)));
        assert_eq!(json["current_epoch"], serde_json::json!(3));
        assert_eq!(json["active_head_hex"], serde_json::json!("33".repeat(32)));
        assert_eq!(json["tracked_files"], serde_json::json!(2));
        assert_eq!(json["pending_uploads"], serde_json::json!(1));
        assert_eq!(
            json["sync_health"]["last_ok_kind"],
            serde_json::json!("PUSH_OK")
        );
        assert_eq!(json["sync_health"]["pending"], serde_json::json!(1));
        assert_eq!(json["sync_health"]["failed"], serde_json::json!(0));
        assert_eq!(json["active_epoch_age_days"], serde_json::json!(100));
        assert_eq!(json["active_epoch_stale"], serde_json::json!(true));
        assert_eq!(
            json["operators"][0],
            serde_json::json!("Operator (192.***.***.10):8101")
        );
        // Missing epoch metadata degrades honestly.
        let report = StatusReport::new(
            &[0x11u8; 32],
            &[0x22u8; 32],
            3,
            42,
            None,
            0,
            Vec::new(),
            Vec::new(),
            0,
            SyncHealthJson {
                last_ok_at_utc: None,
                last_ok_kind: None,
                last_ok_snapshot_hex: None,
                pending: 0,
                failed: 0,
                oldest_pending_at_utc: None,
                last_error: None,
                key_backup_locator_hex: None,
                key_backup_at_utc: None,
            },
            None,
            90,
            2_000_000_000,
            Vec::new(),
        );
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["leases"].as_array().unwrap().is_empty());
        assert!(json["active_head_hex"].is_null());
        assert!(json["active_epoch_age_days"].is_null());
        assert_eq!(json["active_epoch_stale"], serde_json::json!(true));
    }

    #[test]
    fn overview_report_serializes_stable_contract() {
        let report = OverviewReport {
            vault_id_hex: "aa".repeat(32),
            device_id_hex: "bb".repeat(32),
            current_epoch: 1,
            snapshots: vec![OverviewSnapshotJson {
                snapshot_id_hex: "cc".repeat(32),
                epoch: 1,
                advisory_timestamp_utc: 1_000_000,
            }],
            active_head_hex: Some("cc".repeat(32)),
            tracked_files: 1,
            tracked_bytes_on_disk: 42,
            operators: vec!["https://op1.cipherv.online".to_string()],
            leases: vec![LeaseStatusJson {
                lease_id: "lease-1".to_string(),
                operator: "https://op1.cipherv.online".to_string(),
                bytes: 100,
                expires_at_utc: 2_000_000,
                expired: false,
            }],
            anchors: vec![OverviewAnchorJson {
                tx_hash_hex: "dd".repeat(32),
                block_number: 7,
                chain_id: 42161,
                timestamp_utc: 1_000_001,
            }],
            recent_activity: vec![OverviewActivityJson {
                event_type: "push".to_string(),
                summary: "snapshot".to_string(),
                created_at_utc: 1_000_002,
            }],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["snapshots"].as_array().unwrap().len(), 1);
        assert_eq!(json["tracked_files"], serde_json::json!(1));
        assert_eq!(json["leases"][0]["lease_id"], serde_json::json!("lease-1"));
        assert_eq!(json["anchors"][0]["chain_id"], serde_json::json!(42161));
        assert_eq!(
            json["recent_activity"][0]["event_type"],
            serde_json::json!("push")
        );
    }

    #[test]
    fn doctor_report_marks_degraded_on_any_failure() {
        let ok = vec![
            DoctorCheck {
                name: "vault",
                ok: true,
                detail: "v".to_string(),
            },
            DoctorCheck {
                name: "keyring",
                ok: true,
                detail: "k".to_string(),
            },
        ];
        assert_eq!(doctor_report(&ok)["status"], "ok");
        let bad = vec![DoctorCheck {
            name: "vault",
            ok: false,
            detail: "missing".to_string(),
        }];
        let report = doctor_report(&bad);
        assert_eq!(report["status"], "degraded");
        assert_eq!(report["failures"], 1);
        assert_eq!(report["checks"][0]["name"], "vault");
    }

    #[test]
    fn lint_dotenv_bytes_detects_structural_anomalies_without_leaking_values() {
        let sample = b"EMPTY_VAR=\nPLACEHOLDER_VAR=CHANGEME\nWRAP_VAR=\" padded_secret_123 \"\nQUOTE_VAR=\"\"double_quoted\"\"\nDATABASE_URL=not-a-valid-url\nCFG_JSON={bad_json\nOPENAI_API_KEY=wrong_prefix_secret_999\n";
        let mut keys = std::collections::BTreeSet::new();
        let mut anomalies = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        lint_dotenv_bytes(sample, &mut keys, &mut anomalies, &mut seen);
        let serialized = serde_json::to_string(&anomalies).unwrap();
        assert!(!serialized.contains("padded_secret_123"));
        assert!(!serialized.contains("wrong_prefix_secret_999"));
        assert!(seen.contains(&("EMPTY_VAR".to_string(), "EMPTY_VALUE".to_string())));
        assert!(seen.contains(&("PLACEHOLDER_VAR".to_string(), "PLACEHOLDER_VALUE".to_string())));
        assert!(seen.contains(&("WRAP_VAR".to_string(), "WHITESPACE_WRAPPED".to_string())));
        assert!(seen.contains(&("QUOTE_VAR".to_string(), "UNSTRIPPED_QUOTES".to_string())));
        assert!(seen.contains(&("DATABASE_URL".to_string(), "INVALID_URL".to_string())));
        assert!(seen.contains(&("CFG_JSON".to_string(), "INVALID_JSON".to_string())));
        assert!(seen.contains(&("OPENAI_API_KEY".to_string(), "PREFIX_MISMATCH".to_string())));
    }
}
