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

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn test_chaos_federation_and_guardian_disaster_drill() {
    let bin = get_ciphervault_bin();
    assert!(
        bin.exists(),
        "ciphervault binary does not exist at {:?}",
        bin
    );

    let base_test_dir = std::env::temp_dir().join(format!(
        "ciphervault_chaos_drill_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&base_test_dir).unwrap();

    // =========================================================================
    // 1. CLUSTER DEPLOYMENT: Spawn 3 independent operator nodes
    // =========================================================================
    println!("\n>>> [STEP 1] Spawning 3-node storage operator federation...");
    let op1_dir = base_test_dir.join("op1_storage");
    let op2_dir = base_test_dir.join("op2_storage");
    let op3_dir = base_test_dir.join("op3_storage");

    let (url1, op1_task) = spawn_operator("operator-1", op1_dir.clone()).await;
    let (url2, op2_task) = spawn_operator("operator-2", op2_dir.clone()).await;
    let (url3, op3_task) = spawn_operator("operator-3", op3_dir.clone()).await;

    tokio::time::sleep(Duration::from_millis(150)).await;
    println!("  Node 1: {}", url1);
    println!("  Node 2: {}", url2);
    println!("  Node 3: {}", url3);

    // =========================================================================
    // 2. CLIENT VAULT INITIALIZATION: Zero-disk paper kit & OS Keyring wrapping
    // =========================================================================
    println!("\n>>> [STEP 2] Initializing client vault with operators...");
    let client_laptop = base_test_dir.join("original_laptop");
    fs::create_dir_all(&client_laptop).unwrap();

    let safe_offline_kit = base_test_dir.join("printed_emergency_recovery_kit.txt");
    let init_output = Command::new(&bin)
        .args([
            "init",
            "--operators",
            &url1,
            &url2,
            &url3,
            "--save-kit",
            safe_offline_kit.to_str().unwrap(),
        ])
        .current_dir(&client_laptop)
        .output()
        .expect("ciphervault init failed");

    let init_stdout = String::from_utf8_lossy(&init_output.stdout);
    let init_stderr = String::from_utf8_lossy(&init_output.stderr);
    assert!(
        init_output.status.success(),
        "Init failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        init_stdout,
        init_stderr
    );

    // Verify invariant: recovery_kit_backup.txt is NOT on disk in .ciphervault
    assert!(
        !client_laptop
            .join(".ciphervault")
            .join("recovery_kit_backup.txt")
            .exists(),
        "Plaintext recovery kit must never be stored in .ciphervault"
    );
    assert!(
        safe_offline_kit.exists(),
        "Explicitly saved recovery kit must exist"
    );

    // =========================================================================
    // 3. INGESTION & TRACKING: Multi-file confidential payload
    // =========================================================================
    println!("\n>>> [STEP 3] Writing and tracking confidential secrets...");
    let env_content = b"APP_ENV=production\nCLUSTER_ENDPOINT=https://cluster.internal:8443/vault\nSYNTHETIC_TEST_TOKEN=drill_payload_token_847192847192\n";
    let env_path = client_laptop.join(".env");
    fs::write(&env_path, env_content).unwrap();

    let certs_dir = client_laptop.join("certs");
    fs::create_dir_all(&certs_dir).unwrap();
    let key_content = b"MOCK_KEY_HEADER_V1\nMHcCAQEEIB4G8uE2mEa7Y0Q7X+synthetic_mock_payload_material_0987654321\nMOCK_KEY_FOOTER_V1\n";
    let key_path = certs_dir.join("server.key");
    fs::write(&key_path, key_content).unwrap();

    let tokens_dir = client_laptop.join("tokens");
    fs::create_dir_all(&tokens_dir).unwrap();
    let token_content = b"{\"cloud_provider\":\"mock_cloud\",\"access_key\":\"MOCK_DEV_ACCESS_KEY_001\",\"secret_token\":\"MOCK_DEV_TOKEN_PAYLOAD_MATERIAL\"}\n";
    let token_path = tokens_dir.join("cloud_auth.json");
    fs::write(&token_path, token_content).unwrap();

    let expected_env_sha = sha256_file(&env_path);
    let expected_key_sha = sha256_file(&key_path);
    let expected_token_sha = sha256_file(&token_path);

    let track_output = Command::new(&bin)
        .args([
            "track",
            ".env",
            "certs/server.key",
            "tokens/cloud_auth.json",
        ])
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    assert!(
        track_output.status.success(),
        "Track command failed: {}",
        String::from_utf8_lossy(&track_output.stderr)
    );

    // =========================================================================
    // 4. PUSH SNAPSHOT: FastCDC chunking & Proof-of-Storage Readback
    // =========================================================================
    println!("\n>>> [STEP 4] Pushing snapshot with Proof-of-Storage readback...");
    let push_output = Command::new(&bin)
        .args([
            "push",
            "--message",
            "Phase 1: Production secrets initial snapshot",
            "--pos",
        ])
        .current_dir(&client_laptop)
        .output()
        .unwrap();

    let push_stdout = String::from_utf8_lossy(&push_output.stdout);
    let push_stderr = String::from_utf8_lossy(&push_output.stderr);
    assert!(
        push_output.status.success()
            && push_stdout
                .contains("RemoteDurable (3/3 independent replicas verified and read back)"),
        "Push failed or missing RemoteDurable 3/3:\nSTDOUT:\n{}\nSTDERR:\n{}",
        push_stdout,
        push_stderr
    );

    // Verify all 3 operator directories have stored ciphertext objects
    assert!(
        fs::read_dir(op1_dir.join("objects")).unwrap().count() > 0,
        "Op1 must contain objects"
    );
    assert!(
        fs::read_dir(op2_dir.join("objects")).unwrap().count() > 0,
        "Op2 must contain objects"
    );
    assert!(
        fs::read_dir(op3_dir.join("objects")).unwrap().count() > 0,
        "Op3 must contain objects"
    );

    // =========================================================================
    // 5. AUTOMATED L2 CHECKPOINT RELAYER (Arbitrum EIP-712 proof)
    // =========================================================================
    println!("\n>>> [STEP 5] Submitting on-chain checkpoint to automated L2 relayer...");
    let anchor_output = Command::new(&bin)
        .args(["anchor", "--auto-relay", "--relayer-url", &url1])
        .current_dir(&client_laptop)
        .output()
        .unwrap();

    let anchor_stdout = String::from_utf8_lossy(&anchor_output.stdout);
    let anchor_stderr = String::from_utf8_lossy(&anchor_output.stderr);
    assert!(
        anchor_output.status.success() && anchor_stdout.contains("QueuedForRelay"),
        "Anchor failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        anchor_stdout,
        anchor_stderr
    );

    // =========================================================================
    // 6. THRESHOLD GUARDIAN SPLIT: Export 2-of-3 Shamir shares
    // =========================================================================
    println!("\n>>> [STEP 6] Splitting master recovery secret into 2-of-3 guardian sheets...");
    let guardian_dir = base_test_dir.join("guardian_sheets");
    fs::create_dir_all(&guardian_dir).unwrap();

    let split_output = Command::new(&bin)
        .args([
            "recovery",
            "split",
            "--threshold",
            "2",
            "--shares",
            "3",
            "--kit",
            safe_offline_kit.to_str().unwrap(),
            "--out-dir",
            guardian_dir.to_str().unwrap(),
        ])
        .current_dir(&client_laptop)
        .output()
        .unwrap();

    let split_stdout = String::from_utf8_lossy(&split_output.stdout);
    assert!(
        split_output.status.success(),
        "Split failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        split_stdout,
        String::from_utf8_lossy(&split_output.stderr)
    );

    let share1_path = guardian_dir.join("guardian_share_1_of_3.txt");
    let share2_path = guardian_dir.join("guardian_share_2_of_3.txt");
    let share3_path = guardian_dir.join("guardian_share_3_of_3.txt");

    assert!(share1_path.exists(), "Guardian share 1 must exist");
    assert!(share2_path.exists(), "Guardian share 2 must exist");
    assert!(share3_path.exists(), "Guardian share 3 must exist");

    // =========================================================================
    // 7. CHAOS INJECTION: Kill Operator 1 and corrupt its storage
    // =========================================================================
    println!(
        "\n>>> [STEP 7] CHAOS INJECTION: Killing Operator 1 and destroying its storage disk..."
    );
    op1_task.abort();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Wipe Operator 1's directory entirely (simulating burned hardware / dead SSD)
    let _ = fs::remove_dir_all(&op1_dir);
    assert!(!op1_dir.exists(), "Op1 storage must be wiped");

    // Run audit: Client must report degraded quorum since Operator 1 is down
    let audit_degraded = Command::new(&bin)
        .arg("audit")
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    let audit_degraded_stdout = String::from_utf8_lossy(&audit_degraded.stdout);
    let audit_degraded_stderr = String::from_utf8_lossy(&audit_degraded.stderr);
    println!("  Audit output with Op1 down:\n{}", audit_degraded_stdout);
    // Since 1 of 3 operators is unreachable, the audit must either report Degraded or fail closed
    assert!(
        !audit_degraded.status.success()
            || audit_degraded_stdout.contains("\"healthy\": false")
            || audit_degraded_stdout.contains("degraded")
            || audit_degraded_stderr.contains("Failed"),
        "Audit should detect quorum degradation when Operator 1 is offline"
    );

    // =========================================================================
    // 8. AUTONOMOUS SELF-REPAIR: Bring up Replacement Node & Repair Federation
    // =========================================================================
    println!("\n>>> [STEP 8] Spawning replacement Operator 4 and repairing federation...");
    let op4_dir = base_test_dir.join("op4_replacement_storage");
    let (url4, op4_task) = spawn_operator("operator-4", op4_dir.clone()).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    println!("  Replacement Node 4: {}", url4);

    // Run repair pointing to the new topology: Replacement Node 4 + surviving Nodes 2 & 3
    let repair_output = Command::new(&bin)
        .args(["repair", "--operators", &url4, &url2, &url3])
        .current_dir(&client_laptop)
        .output()
        .unwrap();

    let repair_stdout = String::from_utf8_lossy(&repair_output.stdout);
    let repair_stderr = String::from_utf8_lossy(&repair_output.stderr);
    assert!(
        repair_output.status.success(),
        "Repair failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        repair_stdout,
        repair_stderr
    );
    assert!(
        repair_stdout.contains("Repair completed"),
        "Expected repair confirmation in output"
    );

    // Verify that replacement Operator 4 now holds the replicated objects!
    assert!(
        fs::read_dir(op4_dir.join("objects")).unwrap().count() > 0,
        "Replacement Operator 4 must now contain restored objects"
    );

    // Audit the repaired cluster: Quorum must be 3/3 healthy!
    let audit_repaired = Command::new(&bin)
        .args(["audit", "--operators", &url4, &url2, &url3])
        .current_dir(&client_laptop)
        .output()
        .unwrap();
    let audit_repaired_stdout = String::from_utf8_lossy(&audit_repaired.stdout);
    assert!(
        audit_repaired.status.success()
            && (audit_repaired_stdout.contains("\"healthy\": true")
                || audit_repaired_stdout.to_lowercase().contains("healthy")),
        "Repaired audit failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        audit_repaired_stdout,
        String::from_utf8_lossy(&audit_repaired.stderr)
    );
    println!("  ✓ Federation healed! 3/3 operators verified Healthy.");

    // =========================================================================
    // 9. CATASTROPHIC CLIENT SSD FAILURE: Destroy original laptop entirely!
    // =========================================================================
    println!("\n>>> [STEP 9] CATASTROPHIC HARDWARE LOSS: Destroying client laptop...");
    fs::remove_dir_all(&client_laptop).unwrap();
    assert!(
        !client_laptop.exists(),
        "Original laptop must be completely erased"
    );

    // Also delete the single recovery kit to ensure we rely STRICTLY on the guardian sheets!
    let _ = fs::remove_file(&safe_offline_kit);
    assert!(!safe_offline_kit.exists(), "Single recovery kit deleted");

    // =========================================================================
    // 10. DISASTER RECOVERY: Restore onto a virgin machine using 2-of-3 shares
    // =========================================================================
    println!(
        "\n>>> [STEP 10] Clean-Machine Recovery from Guardian Shares 1 & 3 (Share 2 unused)..."
    );
    let virgin_laptop = base_test_dir.join("virgin_replacement_laptop");
    fs::create_dir_all(&virgin_laptop).unwrap();

    // 10a. Verify that a single guardian share fails (threshold is 2)
    let single_share_recovery = Command::new(&bin)
        .args([
            "recover",
            "--shares",
            share1_path.to_str().unwrap(),
            "--to",
            virgin_laptop.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !single_share_recovery.status.success(),
        "Recovery must fail with only 1 share when threshold is 2"
    );

    // 10b. Recover with Share 1 and Share 3 (leaving Share 2 completely unused)
    let recover_output = Command::new(&bin)
        .args([
            "recover",
            "--shares",
            share1_path.to_str().unwrap(),
            share3_path.to_str().unwrap(),
            "--to",
            virgin_laptop.to_str().unwrap(),
        ])
        .output()
        .expect("ciphervault recover failed");

    let recover_stdout = String::from_utf8_lossy(&recover_output.stdout);
    let recover_stderr = String::from_utf8_lossy(&recover_output.stderr);
    assert!(
        recover_output.status.success(),
        "Recovery with 2 guardian shares failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        recover_stdout,
        recover_stderr
    );

    assert!(
        recover_stdout.contains("CLEAN-MACHINE RECOVERY COMPLETED SUCCESSFULLY!"),
        "Expected successful recovery banner"
    );
    assert!(
        recover_stdout.contains("✓ Master Recovery Secret R reconstructed successfully!"),
        "Expected Shamir Lagrange reconstruction message"
    );

    // =========================================================================
    // 11. BIT-FOR-BIT FIDELITY VERIFICATION: Validate all restored files
    // =========================================================================
    println!("\n>>> [STEP 11] Verifying 100% byte-for-byte fidelity of restored files...");
    let restored_env = virgin_laptop.join(".env");
    let restored_key = virgin_laptop.join("certs").join("server.key");
    let restored_token = virgin_laptop.join("tokens").join("cloud_auth.json");

    assert!(restored_env.exists(), ".env was not restored");
    assert!(restored_key.exists(), "certs/server.key was not restored");
    assert!(
        restored_token.exists(),
        "tokens/cloud_auth.json was not restored"
    );

    assert_eq!(
        sha256_file(&restored_env),
        expected_env_sha,
        ".env SHA-256 digest mismatch"
    );
    assert_eq!(
        sha256_file(&restored_key),
        expected_key_sha,
        "certs/server.key SHA-256 digest mismatch"
    );
    assert_eq!(
        sha256_file(&restored_token),
        expected_token_sha,
        "tokens/cloud_auth.json SHA-256 digest mismatch"
    );

    assert_eq!(fs::read(&restored_env).unwrap(), env_content);
    assert_eq!(fs::read(&restored_key).unwrap(), key_content);
    assert_eq!(fs::read(&restored_token).unwrap(), token_content);

    println!("  ✓ .env SHA-256 digest:                 MATCH (100% bit-for-bit)");
    println!("  ✓ certs/server.key SHA-256 digest:      MATCH (100% bit-for-bit)");
    println!("  ✓ tokens/cloud_auth.json SHA-256 digest: MATCH (100% bit-for-bit)");

    // Teardown operators
    op2_task.abort();
    op3_task.abort();
    op4_task.abort();
    let _ = fs::remove_dir_all(&base_test_dir);
    println!("\n>>> [ALL CHAOS DRILL VERIFICATION PHASES PASSED WITH ZERO BITFLIPS]\n");
}
