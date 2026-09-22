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

#[derive(Debug, Clone, serde::Serialize)]
struct StatusReport {
    vault_id_hex: String,
    device_id_hex: String,
    current_epoch: u64,
    device_counter: u64,
    active_head_hex: Option<String>,
    tracked_files: usize,
    operators: Vec<String>,
    pending_uploads: usize,
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
        operators: Vec<String>,
        pending_uploads: usize,
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
            vault_id_hex: hex::encode(vault_id),
            device_id_hex: hex::encode(device_id),
            current_epoch,
            device_counter,
            active_head_hex: active_head.map(hex::encode),
            tracked_files,
            operators: operators
                .iter()
                .map(|op| mask_operator_endpoint(op))
                .collect::<Vec<_>>(),
            pending_uploads,
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
        if let Ok(meta) = fs::metadata(rel_path) {
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
    let store = get_vault_store()?;
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

    if json {
        let report = StatusReport::new(
            &vault_id,
            &device_id,
            epoch,
            counter,
            head_cid,
            tracked.len(),
            operators,
            pending_uploads,
            epoch_created_at,
            DEFAULT_REKEY_WARN_DAYS,
            now_utc,
            lease_statuses,
        );
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{}", "CipherVault Status".bold());
    println!("--------------------------------------------------");
    println!("  Vault ID:        {}", hex::encode(vault_id).yellow());
    println!("  Device ID:       {}", hex::encode(device_id).cyan());
    println!("  Current Epoch:   {}", epoch);
    println!("  Device Counter:  {}", counter);

    if let Some(head) = active_head {
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
            let exists = rel_path.exists();
            let state = if exists {
                let len = fs::metadata(&rel_path)?.len();
                format!("{} bytes", len).green()
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

    Ok(())
}

struct DoctorCheck {
    name: &'static str,
    ok: bool,
    detail: String,
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
            detail: "protect/unprotect round-trip ok".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_report_masks_operators_and_marks_stale_epoch() {
        let report = StatusReport::new(
            &[0x11u8; 32],
            &[0x22u8; 32],
            3,
            42,
            Some([0x33u8; 32]),
            2,
            vec!["http://192.0.2.10:8101".to_string()],
            1,
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
            0,
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
}
