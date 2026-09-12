use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};

fn get_ciphervault_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
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
    assert!(
        bin.exists(),
        "ciphervault binary does not exist at {:?}",
        bin
    );

    let base_test_dir = std::env::temp_dir().join(format!(
        "ciphervault_pivotal_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&base_test_dir).unwrap();

    // 1. Spawn 3 independent operator servers
    let op1_dir = base_test_dir.join("op1_storage");
    let op2_dir = base_test_dir.join("op2_storage");
    let op3_dir = base_test_dir.join("op3_storage");

    let op1_state = Arc::new(OperatorState::new(
        "operator-1".into(),
        op1_dir.clone(),
        generate_signing_key(),
    ));
    let op2_state = Arc::new(OperatorState::new(
        "operator-2".into(),
        op2_dir.clone(),
        generate_signing_key(),
    ));
    let op3_state = Arc::new(OperatorState::new(
        "operator-3".into(),
        op3_dir.clone(),
        generate_signing_key(),
    ));

    let listener_1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_3 = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let url1 = format!("http://{}", listener_1.local_addr().unwrap());
    let url2 = format!("http://{}", listener_2.local_addr().unwrap());
    let url3 = format!("http://{}", listener_3.local_addr().unwrap());
    let op1_task = tokio::spawn(async move {
        axum::serve(listener_1, create_router(op1_state))
            .await
            .unwrap();
    });
    let op2_task = tokio::spawn(async move {
        axum::serve(listener_2, create_router(op2_state))
            .await
            .unwrap();
    });
    let op3_task = tokio::spawn(async move {
        axum::serve(listener_3, create_router(op3_state))
            .await
            .unwrap();
    });

    // Short wait for operators to listen
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 2. Set up initial developer machine
    let client_laptop = base_test_dir.join("original_laptop");
    fs::create_dir_all(&client_laptop).unwrap();

    // Run ciphervault init with the 3 operator endpoints
    let init_output = Command::new(&bin)
        .args(["init", "--operators", &url1, &url2, &url3])
        .current_dir(&client_laptop)
        .output()
        .expect("ciphervault init failed");
    assert!(
        init_output.status.success(),
        "ciphervault init failed: {}",
        String::from_utf8_lossy(&init_output.stderr)
    );

    // Save offline recovery kit in safe offline simulated location
    let kit_backup_path = client_laptop
        .join(".ciphervault")
        .join("recovery_kit_backup.txt");
    assert!(kit_backup_path.exists());
    let safe_offline_kit = base_test_dir.join("printed_emergency_recovery_kit.txt");
    fs::copy(&kit_backup_path, &safe_offline_kit).unwrap();

    // 3. Create confidential files on client
    let env_bytes = b"SERVICE_ENDPOINT=https://samuel.cluster.local:5432/main\nAUTH_HASH_TOKEN=mock_synthetic_token_9876543210\n";
    let env_path = client_laptop.join(".env");
    fs::write(&env_path, env_bytes).unwrap();

    let keys_dir = client_laptop.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();
    let dev_key_bytes = b"TEST_MOCK_CERTIFICATE_PAYLOAD_BLOCK\nSYNTHETIC_DEVELOPMENT_TEST_DATA_NEVER_IN_GIT\nTEST_MOCK_CERTIFICATE_PAYLOAD_END\n";
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

    // Disk persistence failure on one operator must prevent RemoteDurable.
    fs::remove_dir(op3_dir.join("leases")).unwrap();
    fs::write(op3_dir.join("leases"), b"injected write failure").unwrap();
    let failed = Command::new(&bin)
        .arg("push")
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stdout).contains("RemoteDurable"));
    fs::remove_file(op3_dir.join("leases")).unwrap();
    fs::create_dir(op3_dir.join("leases")).unwrap();

    // Discovery-log failure must also prevent success, even with all objects uploaded.
    let kit = ciphervault_recovery::OfflineRecoveryKit::parse_from_printable(
        &fs::read_to_string(&safe_offline_kit).unwrap(),
    )
    .unwrap();
    let blocked_log = op3_dir
        .join("recovery")
        .join(format!("{}.log", kit.recovery_locator_hex));
    fs::create_dir(&blocked_log).unwrap();
    let failed = Command::new(&bin)
        .arg("push")
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stdout).contains("RemoteDurable"));
    fs::remove_dir(&blocked_log).unwrap();

    // 5. Push snapshot to the 3 operators
    let push_output = Command::new(&bin)
        .args(["push", "--message", "v1 production secrets"])
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    let push_stdout = String::from_utf8_lossy(&push_output.stdout);
    let push_stderr = String::from_utf8_lossy(&push_output.stderr);
    assert!(
        push_output.status.success()
            && push_stdout
                .contains("RemoteDurable (3/3 independent replicas verified and read back)"),
        "Expected RemoteDurable with 3/3 operators, got:\nSTDOUT:\n{}\nSTDERR:\n{}",
        push_stdout,
        push_stderr
    );

    // Verify all 3 operator directories have stored ciphertext objects
    assert!(!fs::read_dir(op1_dir.join("objects"))
        .unwrap()
        .next()
        .is_none());
    assert!(!fs::read_dir(op2_dir.join("objects"))
        .unwrap()
        .next()
        .is_none());
    assert!(!fs::read_dir(op3_dir.join("objects"))
        .unwrap()
        .next()
        .is_none());

    // A missing chunk, envelope object, and discovery log must all affect health.
    let db =
        ciphervault_local_store::LocalVaultStore::open(client_laptop.join(".ciphervault/vault.db"))
            .unwrap();
    let head = db.get_active_head().unwrap().unwrap();
    let head_cid: [u8; 32] = head.snapshot_id.as_slice().try_into().unwrap();
    let set = db.get_recovery_set(&head_cid).unwrap();
    fs::remove_file(
        op3_dir
            .join("objects")
            .join(hex::encode(&set.closure.chunk_cids[0])),
    )
    .unwrap();
    fs::remove_file(
        op3_dir
            .join("objects")
            .join(hex::encode(&set.closure.envelope_ids[1])),
    )
    .unwrap();
    fs::remove_file(
        op3_dir
            .join("recovery")
            .join(format!("{}.log", hex::encode(set.locator))),
    )
    .unwrap();
    let audit = Command::new(&bin)
        .arg("audit")
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    assert!(
        !audit.status.success(),
        "Incomplete recovery set must fail audit"
    );
    let repair = Command::new(&bin)
        .arg("repair")
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    assert!(
        repair.status.success(),
        "{}",
        String::from_utf8_lossy(&repair.stderr)
    );
    let audit = Command::new(&bin)
        .arg("audit")
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    assert!(
        audit.status.success(),
        "{}",
        String::from_utf8_lossy(&audit.stderr)
    );
    drop(db);

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
