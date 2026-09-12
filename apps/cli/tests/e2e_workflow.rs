use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

#[test]
fn test_end_to_end_ciphervault_workflow() {
    let bin = get_ciphervault_bin();
    assert!(
        bin.exists(),
        "ciphervault binary does not exist at {:?}",
        bin
    );

    // Setup isolated temporary test directory
    let test_dir = std::env::temp_dir().join(format!(
        "ciphervault_e2e_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    // 1. Run ciphervault init
    let init_output = Command::new(&bin)
        .args(["init", "--operators", "http://127.0.0.1:1"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault init");
    assert!(
        init_output.status.success(),
        "ciphervault init failed: {:?}",
        String::from_utf8_lossy(&init_output.stderr)
    );

    // Verify .ciphervault and local database exist, while kit is not saved to disk
    let vault_dir = test_dir.join(".ciphervault");
    assert!(vault_dir.exists());
    assert!(vault_dir.join("vault.db").exists());
    assert!(
        !vault_dir.join("recovery_kit_backup.txt").exists(),
        "Recovery kit must not be written to disk by default"
    );

    // Verify .gitignore
    let gitignore_content = fs::read_to_string(test_dir.join(".gitignore")).unwrap();
    assert!(gitignore_content.contains(".ciphervault/"));

    // 2. Create synthetic confidential files
    let env_content = b"SERVICE_ENDPOINT=https://cluster.internal.local:5432/production\nAUTH_KEY_HASH=token_synthetic_auth_123456\nPAYLOAD_IDENTIFIER=marker_payload_data_987654";
    let env_path = test_dir.join(".env");
    fs::write(&env_path, env_content).unwrap();

    let config_dir = test_dir.join("config");
    fs::create_dir_all(&config_dir).unwrap();
    let key_content = b"TEST_MOCK_CONFIGURATION_DATA_BLOCK\nSYNTHETIC_TEST_FIXTURE_PAYLOAD_NOT_A_REAL_SECRET\nTEST_MOCK_CONFIGURATION_DATA_END\n";
    let key_path = config_dir.join("app_key.pem");
    fs::write(&key_path, key_content).unwrap();

    let orig_env_hash = sha256_file(&env_path);
    let orig_key_hash = sha256_file(&key_path);

    // 3. Run ciphervault track .env config/app_key.pem
    let track_output = Command::new(&bin)
        .args(["track", ".env", "config/app_key.pem"])
        .current_dir(&test_dir)
        .output()
        .unwrap();
    assert!(track_output.status.success());

    // 4. Run ciphervault status
    let status_output = Command::new(&bin)
        .arg("status")
        .current_dir(&test_dir)
        .output()
        .unwrap();
    assert!(status_output.status.success());
    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    assert!(status_stdout.contains("Tracked Confidential Files (2):"));

    // 5. Run ciphervault push --message "v1 initial snapshot"
    let push_output = Command::new(&bin)
        .args(["push", "--message", "v1 initial snapshot"])
        .current_dir(&test_dir)
        .output()
        .unwrap();
    assert!(!push_output.status.success());
    let push_stdout = String::from_utf8_lossy(&push_output.stdout);
    assert!(push_stdout.contains("Snapshot captured and encrypted locally"));

    // 6. Test restoration into clean directory
    let restore_dir_v1 = test_dir.join("restored_v1");
    let restore_output = Command::new(&bin)
        .args(["restore", "--to", restore_dir_v1.to_str().unwrap()])
        .current_dir(&test_dir)
        .output()
        .unwrap();
    assert!(restore_output.status.success());

    // Verify exact byte-for-byte and SHA-256 match on restored files
    let restored_env = restore_dir_v1.join(".env");
    let restored_key = restore_dir_v1.join("config").join("app_key.pem");
    assert!(restored_env.exists());
    assert!(restored_key.exists());

    assert_eq!(sha256_file(&restored_env), orig_env_hash);
    assert_eq!(sha256_file(&restored_key), orig_key_hash);
    assert_eq!(fs::read(&restored_env).unwrap(), env_content);
    assert_eq!(fs::read(&restored_key).unwrap(), key_content);

    // 7. Modify .env and create snapshot v2 (testing history & rollback)
    let env_content_v2 = b"SERVICE_ENDPOINT=https://cluster.internal.local:5432/production_v2\n";
    fs::write(&env_path, env_content_v2).unwrap();
    let env_v2_hash = sha256_file(&env_path);

    let push_v2_output = Command::new(&bin)
        .args(["push", "--message", "v2 updated password"])
        .current_dir(&test_dir)
        .output()
        .unwrap();
    assert!(!push_v2_output.status.success());

    // 8. Run ciphervault history
    let history_output = Command::new(&bin)
        .arg("history")
        .current_dir(&test_dir)
        .output()
        .unwrap();
    assert!(history_output.status.success());
    let history_stdout = String::from_utf8_lossy(&history_output.stdout);
    assert!(history_stdout.contains("[1] Snapshot:"));
    assert!(history_stdout.contains("[2] Snapshot:"));

    // 9. Restore v2 into clean directory
    let restore_dir_v2 = test_dir.join("restored_v2");
    let restore_v2_output = Command::new(&bin)
        .args(["restore", "--to", restore_dir_v2.to_str().unwrap()])
        .current_dir(&test_dir)
        .output()
        .unwrap();
    assert!(restore_v2_output.status.success());

    let restored_env_v2 = restore_dir_v2.join(".env");
    assert_eq!(sha256_file(&restored_env_v2), env_v2_hash);
    assert_eq!(fs::read(&restored_env_v2).unwrap(), env_content_v2);

    // Cleanup test directory
    let _ = fs::remove_dir_all(&test_dir);
}
