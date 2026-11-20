// Copyright (c) 2026 Samuel Avornyoh and CipherVault Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A real `ciphervault watch --sync` process against three in-process
//! operators. The watcher captures, replicates and reads back the recovery
//! set; `status --json --watcher` reports that verification and OS-verified
//! liveness; a second watcher is refused; and a killed watcher stops counting
//! as running. The operators use local legacy mode, as in the other
//! replication fixtures; production enrollment is covered by boundary tests.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};

async fn spawn_operator(name: &str, storage_dir: PathBuf) -> (String, tokio::task::JoinHandle<()>) {
    fs::create_dir_all(&storage_dir).unwrap();
    let state = Arc::new(OperatorState::new_with_security(
        name.into(),
        storage_dir,
        generate_signing_key(),
        ciphervault_operator::state::OperatorSecurityConfig::legacy(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, create_router(state)).await.unwrap();
    });
    (url, handle)
}

/// The CLI in an isolated process environment that uses the vault's own
/// `operators.json` (the local operators), never a user or fleet default.
fn cli(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ciphervault"));
    command
        .args(args)
        .current_dir(root)
        .env("CIPHERVAULT_ACCOUNT_DIR", root.join("isolated-account"))
        .env(
            "CIPHERVAULT_KEYSTORE_PATH",
            root.join("isolated-master.key"),
        )
        .env("CIPHERVAULT_MASTER_KEY", "66".repeat(32))
        .env_remove("CIPHERVAULT_OPERATORS")
        .env_remove("CIPHERVAULT_SCOPE_TOKEN")
        .env_remove("CIPHERVAULT_ACCOUNT_ENDPOINT")
        .env_remove("CIPHERVAULT_OPERATOR_SERVICE_TOKEN")
        .env_remove("CIPHERVAULT_OPERATOR_PINS")
        .env_remove("CIPHERVAULT_DASHBOARD_URL")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null());
    command
}

fn succeeds(output: Output) -> String {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Kills the watcher process however the test ends.
struct WatchProcess(Child);

impl Drop for WatchProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn health(root: &Path) -> Option<(serde_json::Value, serde_json::Value)> {
    let output = cli(root, &["status", "--json", "--watcher"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None; // e.g. the store is briefly busy while the watcher writes
    }
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let health = status.get("watcher_health")?.clone();
    Some((status, health))
}

async fn wait_for(
    root: &Path,
    what: &str,
    predicate: impl Fn(&serde_json::Value, &serde_json::Value) -> bool,
) -> (serde_json::Value, serde_json::Value) {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = None;
    while Instant::now() < deadline {
        if let Some((status, health)) = health(root) {
            if predicate(&status, &health) {
                return (status, health);
            }
            last = Some(health);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("timed out waiting for {what}; last watcher_health: {last:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_watch_sync_records_a_verified_backup_and_os_liveness() {
    let base = std::env::temp_dir().join(format!("cv-watch-sync-{:032x}", rand::random::<u128>()));
    fs::create_dir_all(&base).unwrap();
    let base = base.canonicalize().unwrap();
    let (url1, _op1) = spawn_operator("watch-op-1", base.join("op1")).await;
    let (url2, _op2) = spawn_operator("watch-op-2", base.join("op2")).await;
    let (url3, _op3) = spawn_operator("watch-op-3", base.join("op3")).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let root = base.join("vault");
    fs::create_dir_all(&root).unwrap();
    succeeds(
        cli(&root, &["init", "--operators", &url1, &url2, &url3])
            .output()
            .unwrap(),
    );
    fs::write(root.join(".env"), b"SYNTHETIC_WATCH_SYNC=first\n").unwrap();
    succeeds(cli(&root, &["track", ".env"]).output().unwrap());

    let watcher = WatchProcess(
        cli(&root, &["watch", "--sync", "--debounce", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    // The startup scan captures .env, replicates it to all three operators,
    // and reads the recovery set back.
    let (status, first) = wait_for(&root, "a verified watcher capture", |status, health| {
        health["watcher"]["state"] == "running"
            && health["remote_verification"]["head_verified"] == true
            && health["sync"]["last_watcher_attempt"]["outcome"] == "verified"
            && health["last_capture"]["snapshot_id"] == status["active_head_hex"]
    })
    .await;
    assert_eq!(first["watcher"]["lock"], "held");
    assert_eq!(first["watcher"]["evidence"], "lock_and_heartbeat");
    assert_eq!(first["watcher"]["sync_enabled"], true);
    assert_eq!(first["watcher"]["operator_count"], 3);
    let remote = &first["remote_verification"];
    assert_eq!(
        remote["verified_snapshot"]["snapshot_id"],
        status["active_head_hex"]
    );
    assert_eq!(remote["live_check_performed"], false);
    assert_eq!(first["sync"]["pending"], 0);
    assert_eq!(first["sync"]["failed"], 0);
    assert!(first["last_change_detected_at_utc"].as_u64().is_some());

    // A second watcher on the vault refuses to start instead of racing.
    let mut second = cli(&root, &["watch", "--debounce", "1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let refused = loop {
        if let Some(exit) = second.try_wait().unwrap() {
            break Some(exit);
        }
        if Instant::now() > deadline {
            let _ = second.kill();
            let _ = second.wait();
            break None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        refused.map(|exit| exit.success()),
        Some(false),
        "a second watcher must exit with an error, not run"
    );

    // An edit is detected, captured as a new head, and verified remotely.
    let first_head = status["active_head_hex"].as_str().unwrap().to_string();
    fs::write(root.join(".env"), b"SYNTHETIC_WATCH_SYNC=second\n").unwrap();
    let (status, second_capture) = wait_for(
        &root,
        "the edit to be captured and verified",
        |status, health| {
            status["active_head_hex"] != first_head.as_str()
                && health["last_capture"]["snapshot_id"] == status["active_head_hex"]
                && health["remote_verification"]["head_verified"] == true
        },
    )
    .await;
    assert_eq!(
        second_capture["remote_verification"]["verified_snapshot"]["snapshot_id"],
        status["active_head_hex"]
    );
    assert!(!second_capture.to_string().contains("SYNTHETIC_WATCH_SYNC"));

    // Killed without a clean stop: the OS releases the lock at once, so the
    // watcher no longer counts as running even though its heartbeat is recent.
    drop(watcher);
    let (_, killed) = wait_for(&root, "the released lock", |_, health| {
        health["watcher"]["lock"] == "free"
    })
    .await;
    assert_ne!(killed["watcher"]["state"], "running");
    assert_eq!(killed["watcher"]["evidence"], "lock_released");
    assert!(killed["watcher"]["stopped_at_utc"].is_null());

    let _ = fs::remove_dir_all(base);
}
