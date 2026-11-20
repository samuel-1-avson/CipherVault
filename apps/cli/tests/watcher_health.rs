// Copyright (c) 2026 Samuel Avornyoh and CipherVault Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `status --json --watcher`: recorded watcher and backup evidence, scoped to
//! one vault, with missing or stale evidence reported as unknown. Runs the
//! real CLI in an isolated process environment; no operator is contacted.
use ciphervault_agent::{WatcherStatusRecord, HEARTBEAT_INTERVAL_SECS};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphervault"))
        .args(args)
        .current_dir(root)
        .env("CIPHERVAULT_ACCOUNT_DIR", root.join("isolated-account"))
        .env(
            "CIPHERVAULT_KEYSTORE_PATH",
            root.join("isolated-master.key"),
        )
        .env("CIPHERVAULT_MASTER_KEY", "77".repeat(32))
        .env("CIPHERVAULT_OPERATORS", "http://127.0.0.1:1")
        .env_remove("CIPHERVAULT_SCOPE_TOKEN")
        .env_remove("CIPHERVAULT_ACCOUNT_ENDPOINT")
        .env_remove("CIPHERVAULT_OPERATOR_SERVICE_TOKEN")
        .env_remove("CIPHERVAULT_OPERATOR_PINS")
        .env_remove("CIPHERVAULT_DASHBOARD_URL")
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

/// Runs the CLI with the same isolated environment, killing it if it is
/// still running after `secs`. `None` means it did not exit in time.
fn exits_within(root: &Path, args: &[&str], secs: u64) -> Option<std::process::ExitStatus> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ciphervault"))
        .args(args)
        .current_dir(root)
        .env("CIPHERVAULT_ACCOUNT_DIR", root.join("isolated-account"))
        .env(
            "CIPHERVAULT_KEYSTORE_PATH",
            root.join("isolated-master.key"),
        )
        .env("CIPHERVAULT_MASTER_KEY", "77".repeat(32))
        .env("CIPHERVAULT_OPERATORS", "http://127.0.0.1:1")
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

fn succeeds(output: Output) -> String {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn json(output: Output) -> serde_json::Value {
    serde_json::from_str(&succeeds(output)).unwrap()
}

fn health(root: &Path) -> serde_json::Value {
    json(cli(root, &["status", "--json", "--watcher"]))["watcher_health"].clone()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn write_record(root: &Path, record: &WatcherStatusRecord) {
    fs::write(
        root.join(".ciphervault").join("watcher-status.json"),
        serde_json::to_vec_pretty(record).unwrap(),
    )
    .unwrap();
}

fn record(vault_id: &str, heartbeat_at_utc: u64) -> WatcherStatusRecord {
    WatcherStatusRecord {
        version: 1,
        vault_id: vault_id.to_string(),
        instance_id: "fixture".to_string(),
        pid: 4242,
        sync_enabled: true,
        operator_count: 3,
        debounce_secs: 2,
        started_at_utc: heartbeat_at_utc.saturating_sub(60),
        heartbeat_at_utc,
        heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS,
        capture_worker_beat_at_utc: Some(heartbeat_at_utc),
        stopped_at_utc: None,
        last_change_detected_at_utc: None,
        last_capture: None,
        last_error: None,
        last_sync: None,
    }
}

#[test]
fn watcher_health_separates_detection_capture_and_recorded_remote_verification() {
    let root =
        std::env::temp_dir().join(format!("cv-watcher-health-{:032x}", rand::random::<u128>()));
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    succeeds(cli(&root, &["init", "--operators", "http://127.0.0.1:1"]));

    // Empty vault: nothing recorded, nothing claimed.
    let empty = health(&root);
    assert_eq!(empty["live_check_performed"], false);
    assert_eq!(empty["watcher"]["state"], "unknown");
    assert_eq!(empty["watcher"]["evidence"], "no_record");
    assert!(empty["last_capture"].is_null());
    assert!(empty["remote_verification"]["verified_snapshot"].is_null());
    assert_eq!(empty["remote_verification"]["evidence"], "recorded");
    let plain = json(cli(&root, &["status", "--json"]));
    assert!(
        plain.get("watcher_health").is_none(),
        "plain status is unchanged"
    );
    assert!(!cli(&root, &["status", "--watcher"]).status.success());
    assert!(
        !cli(&root, &["status", "--json", "--overview", "--watcher"])
            .status
            .success()
    );

    fs::write(root.join(".env"), b"SYNTHETIC_WATCH_SECRET=one\n").unwrap();
    succeeds(cli(&root, &["track", ".env"]));
    succeeds(cli(&root, &["push", "--local"]));
    let first = json(cli(&root, &["history", "--json"]))["snapshots"][0].clone();
    let vault_id = plain["vault_id_hex"].as_str().unwrap().to_string();

    // An older snapshot with a recorded quorum replication...
    let verified_at = {
        let store = ciphervault_local_store::LocalVaultStore::open(
            root.join(".ciphervault").join("vault.db"),
        )
        .unwrap();
        store
            .record_activity(
                "PUSH_OK",
                "fixture: replicated",
                &serde_json::json!({
                    "snapshot_id": first["logical_id"],
                    "replicas": 3,
                    "required_replicas": 3,
                })
                .to_string(),
            )
            .unwrap();
        // A push below quorum is not a verification.
        store
            .record_activity(
                "PUSH_OK",
                "fixture: short of quorum",
                &serde_json::json!({
                    "snapshot_id": "ab".repeat(32),
                    "replicas": 1,
                    "required_replicas": 3,
                })
                .to_string(),
            )
            .unwrap();
        now()
    };
    let older = health(&root);
    assert_eq!(
        older["remote_verification"]["verified_snapshot"]["snapshot_id"],
        first["snapshot_id"]
    );
    assert_eq!(older["remote_verification"]["head_verified"], true);
    assert!(
        older["remote_verification"]["checked_at_utc"]
            .as_i64()
            .unwrap()
            .abs_diff(verified_at as i64)
            <= 5
    );

    // ...followed by a newer local capture with none.
    fs::write(root.join(".env"), b"SYNTHETIC_WATCH_SECRET=two\n").unwrap();
    succeeds(cli(&root, &["push", "--local"]));
    let newer = health(&root);
    let remote = &newer["remote_verification"];
    assert_eq!(
        remote["verified_snapshot"]["snapshot_id"],
        first["snapshot_id"]
    );
    assert_eq!(remote["head_verified"], false);
    assert_eq!(remote["newer_unverified_snapshots"], 1);
    assert_ne!(remote["head"]["snapshot_id"], first["snapshot_id"]);
    assert_eq!(remote["live_check_performed"], false);
    assert!(newer["sync"]["pending"].as_u64().unwrap() >= 1);
    let head_id = remote["head"]["snapshot_id"].as_str().unwrap().to_string();
    assert!(!newer.to_string().contains("SYNTHETIC_WATCH_SECRET"));

    // A fresh heartbeat from this vault's watcher: running, with its evidence.
    let mut live = record(&vault_id, now());
    live.last_change_detected_at_utc = Some(now());
    live.last_capture = Some(ciphervault_agent::status::CaptureEvidence {
        at_utc: now(),
        snapshot_id: head_id.clone(),
        logical_id: "cd".repeat(32),
    });
    live.last_sync = Some(ciphervault_agent::status::SyncEvidence {
        at_utc: now(),
        outcome: "failed".to_string(),
        snapshot_id: Some(head_id.clone()),
        error: Some("operator unreachable".to_string()),
    });
    write_record(&root, &live);
    let running = health(&root);
    assert_eq!(running["watcher"]["state"], "running");
    assert_eq!(running["watcher"]["evidence"], "heartbeat");
    assert_eq!(running["watcher"]["pid"], 4242);
    assert_eq!(running["last_capture"]["snapshot_id"], head_id.as_str());
    assert_eq!(running["last_capture"]["source"], "watcher_status");
    assert_eq!(running["sync"]["last_watcher_attempt"]["outcome"], "failed");
    assert!(running["last_change_detected_at_utc"].as_u64().is_some());

    // Stale, foreign, and unreadable evidence is unknown, never running.
    write_record(&root, &record(&vault_id, now() - 3_600));
    let stale = health(&root);
    assert_eq!(stale["watcher"]["state"], "unknown");
    assert_eq!(stale["watcher"]["evidence"], "stale_heartbeat");
    write_record(&root, &record(&"ef".repeat(32), now()));
    let foreign = health(&root);
    assert_eq!(foreign["watcher"]["state"], "unknown");
    assert_eq!(foreign["watcher"]["evidence"], "foreign_record");
    assert!(
        foreign["last_change_detected_at_utc"].is_null(),
        "another vault's record contributes no evidence"
    );
    fs::write(
        root.join(".ciphervault").join("watcher-status.json"),
        b"{ not json",
    )
    .unwrap();
    let corrupt = json(cli(&root, &["status", "--json", "--watcher"]));
    assert_eq!(corrupt["vault"], true, "a bad record never breaks status");
    assert_eq!(corrupt["watcher_health"]["watcher"]["state"], "unknown");
    assert_eq!(
        corrupt["watcher_health"]["watcher"]["evidence"],
        "unreadable_record"
    );

    let mut stopped = record(&vault_id, now() - 7_200);
    stopped.stopped_at_utc = Some(now() - 7_200);
    write_record(&root, &stopped);
    assert_eq!(health(&root)["watcher"]["state"], "stopped");

    // A live main loop over a hung capture worker is stalled, not running.
    let mut hung = record(&vault_id, now());
    hung.capture_worker_beat_at_utc = Some(now() - 3_600);
    write_record(&root, &hung);
    let stalled = health(&root);
    assert_eq!(stalled["watcher"]["state"], "stalled");
    assert_eq!(stalled["watcher"]["evidence"], "worker_stalled");
    assert!(
        stalled["watcher"]["capture_worker_age_secs"]
            .as_u64()
            .unwrap()
            >= 3_600
    );

    // The OS lock outranks the heartbeat clock. Held: the process is alive,
    // so a silent loop is stalled. Released with no clean stop: it exited.
    let lock = ciphervault_agent::WatcherInstanceLock::acquire(&root).unwrap();
    write_record(&root, &record(&vault_id, now() - 3_600));
    let held = health(&root);
    assert_eq!(held["watcher"]["lock"], "held");
    assert_eq!(held["watcher"]["state"], "stalled");
    assert_eq!(held["watcher"]["evidence"], "loop_stalled");
    let refused = exits_within(&root, &["watch", "--debounce", "1"], 20);
    assert_eq!(
        refused.map(|status| status.success()),
        Some(false),
        "a second watcher on the same vault must refuse to start, not run"
    );
    write_record(&root, &record(&vault_id, now()));
    let fresh = health(&root);
    assert_eq!(fresh["watcher"]["state"], "running");
    assert_eq!(fresh["watcher"]["evidence"], "lock_and_heartbeat");
    drop(lock);
    write_record(&root, &record(&vault_id, now() - 3_600));
    let crashed = health(&root);
    assert_eq!(crashed["watcher"]["lock"], "free");
    assert_eq!(crashed["watcher"]["state"], "stopped");
    assert_eq!(crashed["watcher"]["evidence"], "lock_released");

    fs::remove_dir_all(root).unwrap();
}
