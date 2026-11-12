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
use ciphervault_operator::{create_router, OperatorState};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
}

fn sha256_file(path: &Path) -> Vec<u8> {
    Sha256::digest(fs::read(path).expect("restored file must exist")).to_vec()
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env_remove("CIPHERVAULT_OPERATORS")
        .output()
        .expect("failed to run ciphervault")
}

fn text(output: &Output) -> String {
    format!(
        "STDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, create_router(state)).await.unwrap();
    });
    (url, task)
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
