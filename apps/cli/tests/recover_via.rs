//! A printed kit keeps the operator endpoints from `init`. When the vault
//! later moves to another fleet, recovery must still work from the same
//! kit by naming the current operators with `--via`; records stay
//! authenticated by the kit's recovery key, not by the endpoint.
// Local legacy-mode operators, as in pivotal_drill.rs.
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use ciphervault_crypto::generate_signing_key;
use ciphervault_local_store::LocalVaultStore;
use ciphervault_operator::state::{OperatorSecurityConfig, PERMISSION_READ, PERMISSION_WRITE};
use ciphervault_operator::{create_router, OperatorState};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
}

fn sha256_file(path: &Path) -> Vec<u8> {
    Sha256::digest(fs::read(path).expect("restored file must exist")).to_vec()
}

fn run(dir: &Path, args: &[&str]) -> Output {
    cli(dir)
        .args(args)
        .output()
        .expect("failed to run ciphervault")
}

fn cli(dir: &Path) -> Command {
    let mut command = Command::new(bin());
    command
        .current_dir(dir)
        .env_remove("CIPHERVAULT_OPERATORS")
        .env_remove("CIPHERVAULT_OPERATOR_PINS");
    command
}

/// `doctor --json` prints its report even when other checks fail; this
/// reads only the recovery-coverage check.
fn doctor_recovery_ok(dir: &Path) -> bool {
    let out = run(dir, &["doctor", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("doctor --json is not JSON ({e})\n{}", text(&out)));
    report["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .any(|check| check["name"] == "recovery" && check["ok"] == true)
}

fn text(output: &Output) -> String {
    format!(
        "STDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn backup_status(dir: &Path) -> serde_json::Value {
    let status = run(dir, &["status", "--json"]);
    assert!(status.status.success(), "{}", text(&status));
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(report["backup"].is_object());
    report["backup"].clone()
}

fn unique_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(dir).unwrap()
}

async fn spawn_operator(name: &str, dir: PathBuf) -> (String, JoinHandle<()>) {
    let state = Arc::new(OperatorState::new_with_security(
        name.into(),
        dir,
        generate_signing_key(),
        ciphervault_operator::state::OperatorSecurityConfig::legacy(),
    ));
    serve_operator(state).await
}

async fn serve_operator(state: Arc<OperatorState>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, create_router(state)).await.unwrap();
    });
    (url, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clean_recovery_checks_checkpoint_with_strict_operators() {
    let base = unique_dir("ciphervault_checkpoint");
    let original = base.join("original");
    let clean = base.join("clean");
    fs::create_dir_all(&original).unwrap();
    fs::create_dir_all(&clean).unwrap();
    let kit = base.join("kit.txt");
    let kit = kit.to_str().unwrap();
    let mut nodes = Vec::new();
    for (name, dir) in [("current", "current-store"), ("older", "older-store")] {
        let state = Arc::new(OperatorState::new_with_security(
            name.into(),
            base.join(dir),
            generate_signing_key(),
            OperatorSecurityConfig {
                strict_auth: true,
                require_enrollment: true,
            },
        ));
        let (endpoint, task) = serve_operator(state.clone()).await;
        nodes.push((state, endpoint, task));
    }
    let [(current, current_url, _), (older, older_url, older_task)] = nodes.as_slice() else {
        unreachable!()
    };
    let init = run(
        &original,
        &[
            "init",
            "--save-kit",
            kit,
            "--operators",
            current_url,
            older_url,
        ],
    );
    assert!(init.status.success(), "fixture initialization failed");
    let store = LocalVaultStore::open(original.join(".ciphervault/vault.db")).unwrap();
    let vault_id = hex::encode(store.get_vault_id().unwrap());
    let (_, device_key, _, _) = store.get_device_state().unwrap();
    let device_pk = hex::encode(device_key.verifying_key().to_bytes());
    drop(store);
    for state in [current, older] {
        state
            .enroll_identity(&vault_id, &device_pk, PERMISSION_READ | PERMISSION_WRITE)
            .unwrap();
    }
    let current_pin = hex::encode(current.signing_key.verifying_key().to_bytes());
    let older_pin = hex::encode(older.signing_key.verifying_key().to_bytes());
    let pins = format!("{current_url}={current_pin},{older_url}={older_pin}");
    let fixture_path = original.join(".env");
    fs::write(&fixture_path, b"DEMO_VALUE=older-test-value\r\n").unwrap();
    assert!(run(&original, &["track", ".env"]).status.success());
    assert!(backup_status(&original)["head_record_cid"].is_null());
    let local = run(&original, &["push", "--local"]);
    assert!(local.status.success(), "{}", text(&local));
    let local_status = backup_status(&original);
    assert!(local_status["head_record_cid"].is_string());
    assert!(local_status["replicated_at_utc"].is_null());
    let first = cli(&original)
        .env("CIPHERVAULT_OPERATOR_PINS", &pins)
        .args(["push", "--replicas", "2"])
        .output()
        .unwrap();
    assert!(
        first.status.success() && text(&first).contains("RemoteDurable"),
        "{}",
        text(&first)
    );

    let expected = b"DEMO_VALUE=expected-test-value\r\n";
    fs::write(&fixture_path, expected).unwrap();
    let second = cli(&original)
        .env("CIPHERVAULT_OPERATOR_PINS", &pins)
        .env("CIPHERVAULT_OPERATORS", current_url)
        .args(["push", "--replicas", "1"])
        .output()
        .unwrap();
    assert!(
        second.status.success() && text(&second).contains("RemoteDurable"),
        "{}",
        text(&second)
    );
    let output = String::from_utf8(second.stdout).unwrap();
    let checkpoint = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Recovery checkpoint: "))
        .expect("verified replication must print a checkpoint");
    assert_eq!(checkpoint.len(), 64);

    let target = clean.join("restored");
    let target_arg = target.to_str().unwrap();
    let stale = cli(&clean)
        .env("CIPHERVAULT_OPERATOR_PINS", &pins)
        .args([
            "recover",
            "--kit",
            kit,
            "--to",
            target_arg,
            "--via",
            older_url,
            "--expect-record-cid",
            checkpoint,
        ])
        .output()
        .unwrap();
    assert!(
        !stale.status.success() && text(&stale).contains("Recovery checkpoint mismatch"),
        "{}",
        text(&stale)
    );
    assert!(
        !target.exists(),
        "a checkpoint mismatch must precede any destination writes"
    );

    let wrong_pin = format!("{current_url}={older_pin}");
    let unpinned = cli(&clean)
        .env("CIPHERVAULT_OPERATOR_PINS", wrong_pin)
        .args([
            "recover",
            "--kit",
            kit,
            "--to",
            target_arg,
            "--via",
            current_url,
            "--expect-record-cid",
            checkpoint,
        ])
        .output()
        .unwrap();
    assert!(
        !unpinned.status.success() && text(&unpinned).contains("No recovery operators verified"),
        "{}",
        text(&unpinned)
    );
    assert!(!target.exists());

    let status = backup_status(&original);
    assert_eq!(status["head_record_cid"], checkpoint);
    assert!(status["replicated_at_utc"].is_number());
    assert!(status["head_verified_at_utc"].is_null());

    let drill = cli(&original)
        .env("CIPHERVAULT_OPERATOR_PINS", &pins)
        .args([
            "recovery",
            "test",
            "--kit",
            kit,
            "--to",
            base.join("without-checkpoint").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(drill.status.success(), "{}", text(&drill));
    let status = backup_status(&original);
    assert!(status["last_drill_at_utc"].is_number());
    assert!(status["head_verified_at_utc"].is_null());

    let verified_dir = base.join("verified-drill");
    let drill = cli(&original)
        .env("CIPHERVAULT_OPERATOR_PINS", &pins)
        .args([
            "recovery",
            "test",
            "--kit",
            kit,
            "--to",
            verified_dir.to_str().unwrap(),
            "--expect-record-cid",
            checkpoint,
        ])
        .output()
        .unwrap();
    assert!(drill.status.success(), "{}", text(&drill));
    assert_eq!(fs::read(verified_dir.join(".env")).unwrap(), expected);
    assert!(backup_status(&original)["head_verified_at_utc"].is_number());

    fs::write(&fixture_path, b"DEMO_VALUE=not-yet-replicated\r\n").unwrap();
    let newest_local = run(&original, &["push", "--local"]);
    assert!(newest_local.status.success(), "{}", text(&newest_local));
    let status = backup_status(&original);
    assert_ne!(status["head_record_cid"], checkpoint);
    assert!(status["replicated_at_utc"].is_null());
    assert!(status["head_verified_at_utc"].is_null());
    assert!(status["last_drill_at_utc"].is_number());

    older_task.abort();
    fs::remove_dir_all(&original).unwrap();
    let recovered = cli(&clean)
        .env("CIPHERVAULT_OPERATOR_PINS", &pins)
        .args([
            "recover",
            "--kit",
            kit,
            "--to",
            target_arg,
            "--expect-record-cid",
            checkpoint,
        ])
        .output()
        .unwrap();
    assert!(
        recovered.status.success()
            && text(&recovered).contains("Matched the expected recovery checkpoint"),
        "{}",
        text(&recovered)
    );
    assert_eq!(fs::read(target.join(".env")).unwrap(), expected);
    assert!(target.join(".ciphervault/vault.db").is_file());

    for (_, _, task) in nodes {
        task.abort();
    }
    let _ = fs::remove_dir_all(&base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kit_from_a_retired_fleet_recovers_via_the_current_fleet() {
    let base = unique_dir("ciphervault_recover_via");
    let (retired, retired_task) = spawn_operator("retired-operator", base.join("retired")).await;
    let (current_1, _task_1) = spawn_operator("current-operator-1", base.join("current1")).await;
    let (current_2, _task_2) = spawn_operator("current-operator-2", base.join("current2")).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let laptop = base.join("laptop");
    fs::create_dir_all(&laptop).unwrap();
    let kit = base.join("printed-kit.txt");
    let kit_arg = kit.to_str().unwrap();
    let init = run(
        &laptop,
        &["init", "--operators", &retired, "--save-kit", kit_arg],
    );
    assert!(init.status.success(), "init failed\n{}", text(&init));
    fs::write(laptop.join(".env"), "DEMO_VALUE=test-only-fixture-value\n").unwrap();
    let track = run(&laptop, &["track", ".env"]);
    assert!(track.status.success(), "track failed\n{}", text(&track));

    // The vault moves to a new fleet after the kit was printed, pushes
    // there, and the retired fleet disappears.
    fs::write(
        laptop.join(".ciphervault").join("operators.json"),
        serde_json::to_string(&[&current_1, &current_2]).unwrap(),
    )
    .unwrap();
    let push = run(&laptop, &["push", "-m", "fleet moved", "--replicas", "2"]);
    assert!(
        push.status.success() && String::from_utf8_lossy(&push.stdout).contains("RemoteDurable"),
        "push to the current fleet failed\n{}",
        text(&push)
    );
    retired_task.abort();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The kit alone points at the retired fleet: an honest failure whose
    // guidance names the vault's current operators and a flag that exists.
    let stale = run(
        &laptop,
        &[
            "recovery",
            "test",
            "--kit",
            kit_arg,
            "--to",
            base.join("drill_stale").to_str().unwrap(),
        ],
    );
    let stale_text = text(&stale);
    assert!(
        !stale.status.success(),
        "stale kit must not succeed\n{stale_text}"
    );
    assert!(stale_text.contains("No recovery records"), "{stale_text}");
    assert!(stale_text.contains("--via"), "{stale_text}");
    assert!(stale_text.contains(&current_1), "{stale_text}");
    assert!(
        !doctor_recovery_ok(&laptop),
        "a failed drill is not recovery coverage"
    );

    // The same kit recovers through the current fleet.
    let drill_dir = base.join("drill_via");
    let drill = run(
        &laptop,
        &[
            "recovery",
            "test",
            "--kit",
            kit_arg,
            "--to",
            drill_dir.to_str().unwrap(),
            "--via",
            &current_1,
            &current_2,
        ],
    );
    assert!(
        drill.status.success(),
        "drill via current fleet failed\n{}",
        text(&drill)
    );
    assert_eq!(
        sha256_file(&drill_dir.join(".env")),
        sha256_file(&laptop.join(".env"))
    );
    // A passing drill run inside the vault is recorded as recovery
    // coverage, so `doctor` stops reporting the vault as unrecoverable.
    assert!(
        doctor_recovery_ok(&laptop),
        "a passing kit drill must count as recovery coverage"
    );

    // A clean machine rebuilds a store that points at the fleet it used,
    // not at the retired endpoints printed in the kit.
    let clean = base.join("clean_machine");
    fs::create_dir_all(&clean).unwrap();
    let restored = clean.join("restored");
    let recovered = run(
        &clean,
        &[
            "recover",
            "--kit",
            kit_arg,
            "--to",
            restored.to_str().unwrap(),
            "--via",
            &format!("{current_1}/"),
            &current_2,
        ],
    );
    assert!(
        recovered.status.success(),
        "recover --via failed\n{}",
        text(&recovered)
    );
    assert_eq!(
        sha256_file(&restored.join(".env")),
        sha256_file(&laptop.join(".env"))
    );
    let operators: Vec<String> = serde_json::from_str(
        &fs::read_to_string(restored.join(".ciphervault").join("operators.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(operators, vec![current_1.clone(), current_2.clone()]);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn via_rejects_non_http_endpoints_before_reading_the_kit() {
    let dir = unique_dir("ciphervault_recover_via_invalid");
    let output = run(
        &dir,
        &[
            "recover",
            "--kit",
            "absent-kit.txt",
            "--to",
            "restored",
            "--via",
            "ftp://operator.invalid",
        ],
    );
    let output_text = text(&output);
    assert!(!output.status.success(), "{output_text}");
    assert!(
        output_text.contains("Invalid --via endpoint"),
        "{output_text}"
    );
    assert!(!output_text.contains("does not exist"), "{output_text}");
    let _ = fs::remove_dir_all(&dir);
}
