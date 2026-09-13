use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};

fn get_ciphervault_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
}

async fn spawn_operator(name: &str, storage_dir: PathBuf) -> (String, tokio::task::JoinHandle<()>) {
    fs::create_dir_all(&storage_dir).unwrap();
    let state = Arc::new(OperatorState::new(
        name.into(),
        storage_dir,
        generate_signing_key(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, create_router(state)).await.unwrap();
    });
    (url, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multi_workstation_pull_synchronization() {
    let bin = get_ciphervault_bin();
    assert!(
        bin.exists(),
        "ciphervault binary does not exist at {:?}",
        bin
    );

    let base_test_dir = std::env::temp_dir().join(format!(
        "ciphervault_pull_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&base_test_dir).unwrap();

    // 1. Spawn 3 operator nodes for federation
    let (url1, _h1) = spawn_operator("op-1", base_test_dir.join("op1_store")).await;
    let (url2, _h2) = spawn_operator("op-2", base_test_dir.join("op2_store")).await;
    let (url3, _h3) = spawn_operator("op-3", base_test_dir.join("op3_store")).await;

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 2. Setup Workstation 1
    let ws1_dir = base_test_dir.join("workstation_1");
    fs::create_dir_all(&ws1_dir).unwrap();

    let init1 = Command::new(&bin)
        .args(["init", "--operators", &url1, &url2, &url3])
        .current_dir(&ws1_dir)
        .output()
        .expect("failed to init ws1");
    assert!(init1.status.success(), "ws1 init failed: {:?}", init1);

    // Initial secrets on Workstation 1
    let env_v1 = "DATABASE_URL=postgres://app:secret1@cluster/prod\nAPI_KEY=sk_live_ws1_v1\n";
    fs::write(ws1_dir.join(".env"), env_v1).unwrap();

    let track1 = Command::new(&bin)
        .args(["track", ".env"])
        .current_dir(&ws1_dir)
        .output()
        .expect("ws1 track failed");
    assert!(track1.status.success());

    let push1 = Command::new(&bin)
        .args(["push", "-m", "Commit 1 from WS1"])
        .current_dir(&ws1_dir)
        .output()
        .expect("ws1 push failed");
    assert!(push1.status.success());

    // 3. Setup Workstation 2 (simulate cloned / synchronized workstation at Commit 1)
    let ws2_dir = base_test_dir.join("workstation_2");
    fs::create_dir_all(&ws2_dir).unwrap();

    // Copy .ciphervault and .env from ws1 to ws2
    let copy_dir = |src: &PathBuf, dst: &PathBuf| {
        for entry in walkdir::WalkDir::new(src) {
            let entry = entry.unwrap();
            let rel = entry.path().strip_prefix(src).unwrap();
            let target = dst.join(rel);
            if entry.file_type().is_dir() {
                fs::create_dir_all(&target).unwrap();
            } else {
                fs::copy(entry.path(), &target).unwrap();
            }
        }
    };
    copy_dir(&ws1_dir.join(".ciphervault"), &ws2_dir.join(".ciphervault"));
    fs::write(ws2_dir.join(".env"), env_v1).unwrap();

    // 4. Test `ciphervault pull` on Workstation 2 when already up to date
    let pull_uptodate = Command::new(&bin)
        .args(["pull"])
        .current_dir(&ws2_dir)
        .output()
        .expect("failed pull on ws2");
    assert!(pull_uptodate.status.success());
    let pull_uptodate_out = String::from_utf8_lossy(&pull_uptodate.stdout);
    assert!(
        pull_uptodate_out.contains("Already up to date with operator cluster"),
        "Pull should detect already up to date: {}",
        pull_uptodate_out
    );

    // 5. Workstation 1 updates secret and commits Commit 2
    let env_v2 = "DATABASE_URL=postgres://app:new_rotated_secret_999@cluster/prod\nAPI_KEY=sk_live_ws1_v2\nFEATURE_FLAG=enabled\n";
    fs::write(ws1_dir.join(".env"), env_v2).unwrap();

    let push2 = Command::new(&bin)
        .args(["push", "-m", "Commit 2 from WS1 - Rotated Credentials"])
        .current_dir(&ws1_dir)
        .output()
        .expect("ws1 push commit 2 failed");
    assert!(push2.status.success(), "ws1 push 2 failed: {:?}", push2);

    // 6. Test `ciphervault pull --dry-run` on Workstation 2
    let pull_dry = Command::new(&bin)
        .args(["pull", "--dry-run"])
        .current_dir(&ws2_dir)
        .output()
        .expect("failed pull dry-run");
    assert!(pull_dry.status.success());
    let pull_dry_out = String::from_utf8_lossy(&pull_dry.stdout);
    assert!(
        pull_dry_out.contains("Found newer remote snapshot"),
        "Dry run should find newer snapshot: {}",
        pull_dry_out
    );
    assert!(
        pull_dry_out.contains("Dry run complete: updates are available from operators"),
        "Dry run message expected: {}",
        pull_dry_out
    );
    // Working tree must NOT be mutated in dry-run
    assert_eq!(
        fs::read_to_string(ws2_dir.join(".env")).unwrap(),
        env_v1,
        "Dry run must not alter .env file on disk"
    );

    // 7. Test uncommitted dirty changes safety guard:
    // Modify .env locally on WS2
    let dirty_env = "DATABASE_URL=postgres://uncommitted:dirty@localhost/dev\n";
    fs::write(ws2_dir.join(".env"), dirty_env).unwrap();

    let pull_dirty = Command::new(&bin)
        .args(["pull"])
        .current_dir(&ws2_dir)
        .output()
        .expect("failed pull dirty check");
    assert!(
        !pull_dirty.status.success(),
        "Pull without --force must fail if uncommitted changes exist!"
    );
    let pull_dirty_err = String::from_utf8_lossy(&pull_dirty.stderr);
    assert!(
        pull_dirty_err.contains("uncommitted modifications") || pull_dirty_err.contains("--force"),
        "Expected uncommitted modifications guard: {}",
        pull_dirty_err
    );

    // 8. Test `ciphervault pull --force` to override and synchronize
    let pull_force = Command::new(&bin)
        .args(["pull", "--force"])
        .current_dir(&ws2_dir)
        .output()
        .expect("failed pull --force");
    assert!(
        pull_force.status.success(),
        "pull --force failed: {:?}",
        pull_force
    );
    let pull_force_out = String::from_utf8_lossy(&pull_force.stdout);
    assert!(
        pull_force_out.contains("Successfully synchronized with operator cluster"),
        "Expected success sync output: {}",
        pull_force_out
    );

    // Verify .env on Workstation 2 is now restored to env_v2!
    let synced_env = fs::read_to_string(ws2_dir.join(".env")).unwrap();
    assert_eq!(
        synced_env, env_v2,
        "Working tree .env on Workstation 2 must match Workstation 1's commit 2"
    );

    // 9. Running `ciphervault pull` again on WS2 should now report already up to date
    let pull_again = Command::new(&bin)
        .args(["pull"])
        .current_dir(&ws2_dir)
        .output()
        .expect("failed pull again");
    assert!(pull_again.status.success());
    let pull_again_out = String::from_utf8_lossy(&pull_again.stdout);
    assert!(pull_again_out.contains("Already up to date with operator cluster"));

    // Clean up
    let _ = fs::remove_dir_all(&base_test_dir);
}
