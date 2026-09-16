use ciphervault_agent::{VaultWatcher, WatcherConfig};
use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
use ciphervault_format::{DeviceCertificate, GenesisRecord, PROTOCOL_VERSION};
use ciphervault_local_store::LocalVaultStore;
use std::fs;
use std::time::Duration;

/// R15: dry-run inspection reports what a capture would do while persisting
/// nothing (no snapshots, no counter moves, no activity rows, no replication).
#[tokio::test]
async fn test_watch_dry_run_inspects_without_persisting() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_watch_dryrun_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let root_dir = test_dir.clone();
    let vault_dir = root_dir.join(".ciphervault");
    fs::create_dir_all(&vault_dir).unwrap();

    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();

    let vault_id = [0x99u8; 32];
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
    let dev_id = [0xAAu8; 32];
    let epoch_key = VaultEpochKey::generate();

    let locator = r.derive_recovery_locator().unwrap();
    let db_path = vault_dir.join("vault.db");
    let store = LocalVaultStore::open(&db_path).unwrap();
    store
        .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
        .unwrap();

    let mut cert = DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        certificate_id: vec![1; 32],
        device_signing_pk: dev_sk.verifying_key().to_bytes().to_vec(),
        permissions: 1,
        authority_generation: 1,
        issued_at_utc: 1000,
        signature: Vec::new(),
    };
    cert.sign(&r_sk).unwrap();
    store.save_device_certificate(&cert).unwrap();

    let secret_path = root_dir.join(".env");
    fs::write(&secret_path, "DRY_RUN_KEY=dry_run_value_123\n").unwrap();
    store.track_file(".env").unwrap();

    // Local-only inspector: reports content, persists nothing.
    let config = WatcherConfig {
        root_dir: root_dir.clone(),
        debounce: Duration::from_millis(50),
        replicate_remote: false,
        operators: Vec::new(),
        dry_run: true,
    };
    let watcher = VaultWatcher::new(config).unwrap();
    let report = watcher.inspect_pending_capture().unwrap();
    assert_eq!(report.files, 1);
    assert!(report.chunks >= 1);
    assert!(report.bytes > 0);
    assert!(!report.would_replicate);
    assert_eq!(report.operator_count, 0);

    assert!(store.list_snapshots().unwrap().is_empty());
    let (_, _, counter, _) = store.get_device_state().unwrap();
    assert_eq!(counter, 0);
    assert!(store.list_activity(10).unwrap().is_empty());

    // Sync-configured inspector reports replication intent, still persisting nothing.
    let config = WatcherConfig {
        root_dir: root_dir.clone(),
        debounce: Duration::from_millis(50),
        replicate_remote: true,
        operators: vec!["http://127.0.0.1:8101".into(), "http://127.0.0.1:8102".into()],
        dry_run: true,
    };
    let watcher = VaultWatcher::new(config).unwrap();
    let report = watcher.inspect_pending_capture().unwrap();
    assert!(report.would_replicate);
    assert_eq!(report.operator_count, 2);
    assert!(store.list_snapshots().unwrap().is_empty());

    // A real capture records a WATCH_SNAPSHOT activity row for the event log UI.
    let config = WatcherConfig {
        root_dir: root_dir.clone(),
        debounce: Duration::from_millis(50),
        replicate_remote: false,
        operators: Vec::new(),
        dry_run: false,
    };
    let watcher = VaultWatcher::new(config).unwrap();
    watcher.capture_and_sync(None).await.unwrap();
    let events = store.list_activity(10).unwrap();
    assert!(events.iter().any(|event| event.event_type == "WATCH_SNAPSHOT"));

    let _ = fs::remove_dir_all(test_dir);
}
