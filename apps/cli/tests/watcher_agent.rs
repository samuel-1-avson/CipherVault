use ciphervault_agent::{VaultWatcher, WatcherConfig};
use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
use ciphervault_format::{GenesisRecord, PROTOCOL_VERSION};
use ciphervault_local_store::LocalVaultStore;
use std::fs;
use std::time::Duration;

#[tokio::test]
async fn test_watcher_agent_and_coherent_capture() {
    let test_dir = std::env::temp_dir().join(format!("cv_watcher_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let root_dir = test_dir.clone();
    let vault_dir = root_dir.join(".ciphervault");
    fs::create_dir_all(&vault_dir).unwrap();

    // 1. Initialize vault
    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();

    let vault_id = [0x77u8; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![0u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();

    let dev_sk = generate_signing_key();
    let dev_id = [0x88u8; 32];
    let epoch_key = VaultEpochKey::generate();

    let db_path = vault_dir.join("vault.db");
    let store = LocalVaultStore::open(&db_path).unwrap();
    store.init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key).unwrap();

    // 2. Track a file
    let secret_path = root_dir.join(".env");
    fs::write(&secret_path, "SERVICE_ENDPOINT=https://cluster.internal.local/db\nAUTH_KEY=token_cluster_auth_12345\n").unwrap();
    store.track_file(".env").unwrap();

    // 3. Test coherent read
    let data = VaultWatcher::read_file_coherently(&secret_path).unwrap().unwrap();
    assert!(data.starts_with(b"SERVICE_ENDPOINT="));

    // 4. Test change detection
    let config = WatcherConfig {
        root_dir: root_dir.clone(),
        debounce: Duration::from_millis(50),
        replicate_remote: false,
        operators: Vec::new(),
    };

    let watcher = VaultWatcher::new(config).unwrap();
    assert!(watcher.check_for_changes().unwrap()); // First check detects untracked initial content

    // 5. Test automated capture
    let snap_cid = watcher.capture_and_sync(Some("Agent test capture".into())).await.unwrap();
    assert_ne!(snap_cid, [0u8; 32]);

    // Verify snapshot stored in local database
    let active_head = store.get_active_head().unwrap().unwrap();
    assert_eq!(active_head.snapshot_id, snap_cid.to_vec());
    assert_eq!(active_head.device_counter, 1);

    // After capture, without edits, check_for_changes should be false
    assert!(!watcher.check_for_changes().unwrap());

    // 6. Modify tracked file and check detection
    fs::write(&secret_path, "SERVICE_ENDPOINT=https://cluster.internal.local/db_v2\n").unwrap();
    assert!(watcher.check_for_changes().unwrap());

    // Trigger second snapshot
    let snap_cid_2 = watcher.capture_and_sync(Some("Updated secrets".into())).await.unwrap();
    assert_ne!(snap_cid_2, snap_cid);

    let active_head_2 = store.get_active_head().unwrap().unwrap();
    assert_eq!(active_head_2.snapshot_id, snap_cid_2.to_vec());
    assert_eq!(active_head_2.device_counter, 2);

    let _ = fs::remove_dir_all(test_dir);
}
