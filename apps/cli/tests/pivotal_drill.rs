use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};

fn get_ciphervault_bin() -> PathBuf {
    PathBuf::from("C:/Users/samue/.cargo-targets/ciphervault/debug/ciphervault.exe")
}

fn sha256_file(path: &Path) -> [u8; 32] {
    let bytes = fs::read(path).expect("failed to read file for sha256");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let res = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_pivotal_acceptance_drill() {
    let bin = get_ciphervault_bin();
    assert!(bin.exists(), "ciphervault binary does not exist at {:?}", bin);

    let base_test_dir = std::env::temp_dir().join(format!("ciphervault_pivotal_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()));
    fs::create_dir_all(&base_test_dir).unwrap();

    // 1. Spawn 3 independent operator servers
    let op1_dir = base_test_dir.join("op1_storage");
    let op2_dir = base_test_dir.join("op2_storage");
    let op3_dir = base_test_dir.join("op3_storage");

    let op1_state = Arc::new(OperatorState::new("operator-1".into(), op1_dir.clone(), generate_signing_key()));
    let op2_state = Arc::new(OperatorState::new("operator-2".into(), op2_dir.clone(), generate_signing_key()));
    let op3_state = Arc::new(OperatorState::new("operator-3".into(), op3_dir.clone(), generate_signing_key()));

    let listener_1 = TcpListener::bind("127.0.0.1:8201").await.unwrap();
    let listener_2 = TcpListener::bind("127.0.0.1:8202").await.unwrap();
    let listener_3 = TcpListener::bind("127.0.0.1:8203").await.unwrap();

    let op1_task = tokio::spawn(async move {
        axum::serve(listener_1, create_router(op1_state)).await.unwrap();
    });
    let op2_task = tokio::spawn(async move {
        axum::serve(listener_2, create_router(op2_state)).await.unwrap();
    });
    let op3_task = tokio::spawn(async move {
        axum::serve(listener_3, create_router(op3_state)).await.unwrap();
    });

    // Short wait for operators to listen
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 2. Set up initial developer machine
    let client_laptop = base_test_dir.join("original_laptop");
    fs::create_dir_all(&client_laptop).unwrap();

    // Run ciphervault init with the 3 operator endpoints
    let init_output = Command::new(&bin)
        .args([
            "init",
            "--operators",
            "http://127.0.0.1:8201",
            "http://127.0.0.1:8202",
            "http://127.0.0.1:8203",
        ])
        .current_dir(&client_laptop)
        .output()
        .expect("ciphervault init failed");
    assert!(init_output.status.success(), "ciphervault init failed: {}", String::from_utf8_lossy(&init_output.stderr));

    // Save offline recovery kit in safe offline simulated location
    let kit_backup_path = client_laptop.join(".ciphervault").join("recovery_kit_backup.txt");
    assert!(kit_backup_path.exists());
    let safe_offline_kit = base_test_dir.join("printed_emergency_recovery_kit.txt");
    fs::copy(&kit_backup_path, &safe_offline_kit).unwrap();

    // 3. Create confidential files on client
    let env_bytes = b"DATABASE_URL=postgres://samuel:super_secret_pw@localhost:5432/main_db\nAPI_KEY=sk_live_synthetic_9876543210\n";
    let env_path = client_laptop.join(".env");
    fs::write(&env_path, env_bytes).unwrap();

    let keys_dir = client_laptop.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();
    let dev_key_bytes = b"-----BEGIN PRIVATE KEY-----\nSYNTHETIC_DEVELOPMENT_SECRET_KEY_NEVER_IN_GIT\n-----END PRIVATE KEY-----\n";
    let dev_key_path = keys_dir.join("dev.key");
    fs::write(&dev_key_path, dev_key_bytes).unwrap();

    let expected_env_sha = sha256_file(&env_path);
    let expected_key_sha = sha256_file(&dev_key_path);

    // 4. Track files
    let track_output = Command::new(&bin)
        .args(["track", ".env", "keys/dev.key"])
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    assert!(track_output.status.success());

    // 5. Push snapshot to the 3 operators
    let push_output = Command::new(&bin)
        .args(["push", "--message", "v1 production secrets"])
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    let push_stdout = String::from_utf8_lossy(&push_output.stdout);
    let push_stderr = String::from_utf8_lossy(&push_output.stderr);
    assert!(
        push_output.status.success() && push_stdout.contains("RemoteDurable (3/3 independent replicas verified and read back)"),
        "Expected RemoteDurable with 3/3 operators, got:\nSTDOUT:\n{}\nSTDERR:\n{}",
        push_stdout,
        push_stderr
    );

    // Verify all 3 operator directories have stored ciphertext objects
    assert!(!fs::read_dir(op1_dir.join("objects")).unwrap().next().is_none());
    assert!(!fs::read_dir(op2_dir.join("objects")).unwrap().next().is_none());
    assert!(!fs::read_dir(op3_dir.join("objects")).unwrap().next().is_none());

    // =========================================================================
    // 6. THE DISASTER: Original laptop is destroyed & Operator 1 is offline!
    // =========================================================================
    fs::remove_dir_all(&client_laptop).unwrap(); // Original laptop, OS keychain, local SQLite DB ALL GONE!
    assert!(!client_laptop.exists());

    // Kill Operator 1 (leaving only Operator 2 and 3 alive)
    op1_task.abort();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // =========================================================================
    // 7. CLEAN-MACHINE RECOVERY: Restore exact files using only the offline kit
    // =========================================================================
    let clean_machine = base_test_dir.join("clean_replacement_laptop");
    fs::create_dir_all(&clean_machine).unwrap();

    let recover_output = Command::new(&bin)
        .args([
            "recover",
            "--kit",
            safe_offline_kit.to_str().unwrap(),
            "--to",
            clean_machine.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute ciphervault recover");

    let recover_stdout = String::from_utf8_lossy(&recover_output.stdout);
    let recover_stderr = String::from_utf8_lossy(&recover_output.stderr);
    assert!(
        recover_output.status.success(),
        "ciphervault recover failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        recover_stdout,
        recover_stderr
    );

    assert!(recover_stdout.contains("CLEAN-MACHINE RECOVERY COMPLETED SUCCESSFULLY!"));

    // 8. Verify exact byte equality and SHA-256 digest match on restored files
    let restored_env = clean_machine.join(".env");
    let restored_dev_key = clean_machine.join("keys").join("dev.key");

    assert!(restored_env.exists(), ".env was not restored");
    assert!(restored_dev_key.exists(), "keys/dev.key was not restored");

    assert_eq!(sha256_file(&restored_env), expected_env_sha);
    assert_eq!(sha256_file(&restored_dev_key), expected_key_sha);
    assert_eq!(fs::read(&restored_env).unwrap(), env_bytes);
    assert_eq!(fs::read(&restored_dev_key).unwrap(), dev_key_bytes);

    // Teardown operators
    op2_task.abort();
    op3_task.abort();
    let _ = fs::remove_dir_all(&base_test_dir);
}
