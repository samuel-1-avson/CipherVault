use ciphervault_agent::{VaultWatcher, WatcherConfig};
use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
use ciphervault_format::{GenesisRecord, PROTOCOL_VERSION};
use ciphervault_local_store::LocalVaultStore;
use std::fs;
use std::time::Duration;

#[test]
fn coherent_hashing_rejects_nonregular_and_oversized_inputs_before_reading() {
    let root =
        std::env::temp_dir().join(format!("cv-watcher-read-{:032x}", rand::random::<u128>()));
    fs::create_dir_all(&root).unwrap();
    // macOS temp paths may include /var -> /private/var; resolve the fixture root.
    let root = fs::canonicalize(root).unwrap();
    assert!(VaultWatcher::read_file_coherently(&root).is_err());
    assert_eq!(
        VaultWatcher::read_file_coherently(root.join("missing")).unwrap(),
        None
    );
    let oversized = root.join("too-large.env");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(ciphervault_snapshot::MAX_FILE_SIZE + 1)
        .unwrap();
    assert!(VaultWatcher::read_file_coherently(&oversized).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn coherent_hashing_rejects_final_and_parent_symlinks() {
    let root =
        std::env::temp_dir().join(format!("cv-watcher-links-{:032x}", rand::random::<u128>()));
    fs::create_dir_all(&root).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let original = root.join("original");
    fs::create_dir_all(&original).unwrap();
    fs::write(original.join("synthetic.env"), b"SYNTHETIC=test\n").unwrap();
    std::os::unix::fs::symlink(original.join("synthetic.env"), root.join("final.env")).unwrap();
    std::os::unix::fs::symlink(&original, root.join("linked-parent")).unwrap();
    assert!(VaultWatcher::read_file_coherently(root.join("final.env")).is_err());
    assert!(VaultWatcher::read_file_coherently(root.join("linked-parent/synthetic.env")).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn test_watcher_agent_and_coherent_capture() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_watcher_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();
    let test_dir = fs::canonicalize(test_dir).unwrap();
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

    let locator = r.derive_recovery_locator().unwrap();
    let db_path = vault_dir.join("vault.db");
    let store = LocalVaultStore::open(&db_path).unwrap();
    store
        .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
        .unwrap();

    let mut cert = ciphervault_format::DeviceCertificate {
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

    // 2. Track a file
    let secret_path = root_dir.join(".env");
    fs::write(
        &secret_path,
        "SERVICE_ENDPOINT=https://cluster.internal.local/db\nAUTH_KEY=token_cluster_auth_12345\n",
    )
    .unwrap();
    store.track_file(".env").unwrap();

    // 3. Test coherent read
    let data = VaultWatcher::read_file_coherently(&secret_path)
        .unwrap()
        .unwrap();
    assert!(data.starts_with(b"SERVICE_ENDPOINT="));

    // 4. Test change detection
    let config = WatcherConfig {
        root_dir: root_dir.clone(),
        debounce: Duration::from_millis(50),
        replicate_remote: false,
        operators: Vec::new(),
        dry_run: false,
    };

    let watcher = VaultWatcher::new(config).unwrap();
    assert!(watcher.check_for_changes().unwrap()); // First check detects untracked initial content
    assert!(watcher.check_for_changes().unwrap()); // Detection must not acknowledge uncaptured bytes.

    // 5. Test automated capture
    let snap_cid = watcher
        .capture_and_sync(Some("Agent test capture".into()))
        .await
        .unwrap();
    assert_ne!(snap_cid, [0u8; 32]);

    // Verify snapshot stored in local database
    let active_head = store.get_active_head().unwrap().unwrap();
    assert_eq!(active_head.snapshot_id, snap_cid.to_vec());
    assert_eq!(active_head.device_counter, 1);

    // After capture, without edits, check_for_changes should be false
    assert!(!watcher.check_for_changes().unwrap());

    // 6. Modify tracked file and check detection
    fs::write(
        &secret_path,
        "SERVICE_ENDPOINT=https://cluster.internal.local/db_v2\n",
    )
    .unwrap();
    assert!(watcher.check_for_changes().unwrap());

    // Trigger second snapshot
    let snap_cid_2 = watcher
        .capture_and_sync(Some("Updated secrets".into()))
        .await
        .unwrap();
    assert_ne!(snap_cid_2, snap_cid);

    let active_head_2 = store.get_active_head().unwrap().unwrap();
    assert_eq!(active_head_2.snapshot_id, snap_cid_2.to_vec());
    assert_eq!(active_head_2.device_counter, 2);

    let _ = fs::remove_dir_all(test_dir);
}

struct LoopFixture {
    root: std::path::PathBuf,
    store: LocalVaultStore,
    certificate: ciphervault_format::DeviceCertificate,
    recovery_signer: ed25519_dalek::SigningKey,
    relative: String,
}

impl LoopFixture {
    fn new(relative: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("cv-watcher-loop-{:032x}", rand::random::<u128>()));
        fs::create_dir_all(root.join(".ciphervault")).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let recovery = RecoverySecret::generate();
        let recovery_signer = recovery.derive_recovery_signing_key().unwrap();
        let (_, encryption) = recovery.derive_recovery_encryption_keys().unwrap();
        let vault_id = [7; 32];
        let mut genesis = GenesisRecord {
            version: 1,
            vault_id: vault_id.to_vec(),
            recovery_signing_pk: recovery_signer.verifying_key().to_bytes().to_vec(),
            recovery_encryption_pk: encryption.as_bytes().to_vec(),
            policy_digest: vec![0; 32],
            created_at_utc: 1,
            creation_nonce: vec![0; 32],
            signature: vec![],
        };
        genesis.sign(&recovery_signer).unwrap();
        let signer = generate_signing_key();
        let store = LocalVaultStore::open(root.join(".ciphervault/vault.db")).unwrap();
        store
            .init_vault(
                &vault_id,
                &genesis,
                &signer,
                &[8; 32],
                &VaultEpochKey::generate(),
                &recovery.derive_recovery_locator().unwrap(),
            )
            .unwrap();
        let mut certificate = ciphervault_format::DeviceCertificate {
            version: 1,
            vault_id: vault_id.to_vec(),
            certificate_id: vec![9; 32],
            device_signing_pk: signer.verifying_key().to_bytes().to_vec(),
            permissions: 1,
            authority_generation: 1,
            issued_at_utc: 1,
            signature: vec![],
        };
        certificate.sign(&recovery_signer).unwrap();
        store.save_device_certificate(&certificate).unwrap();
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"SYNTHETIC=baseline\n").unwrap();
        store.track_file(relative).unwrap();
        Self {
            root,
            store,
            certificate,
            recovery_signer,
            relative: relative.into(),
        }
    }
    fn config(&self) -> WatcherConfig {
        WatcherConfig {
            root_dir: self.root.clone(),
            debounce: Duration::from_millis(50),
            replicate_remote: false,
            operators: vec![],
            dry_run: false,
        }
    }
    async fn baseline(&self) {
        VaultWatcher::new(self.config())
            .unwrap()
            .capture_and_sync(None)
            .await
            .unwrap();
    }
    fn write(&self, bytes: &[u8]) {
        fs::write(self.root.join(&self.relative), bytes).unwrap();
    }
    fn plaintext(&self) -> Vec<u8> {
        let head = self.store.get_active_head().unwrap().unwrap();
        let cid: [u8; 32] = head.snapshot_id.as_slice().try_into().unwrap();
        let (record, encrypted) = self.store.get_snapshot(&cid).unwrap();
        let needed: Vec<[u8; 32]> = self
            .store
            .get_recovery_set(&cid)
            .unwrap()
            .closure
            .chunk_cids
            .iter()
            .map(|cid| cid.as_slice().try_into().unwrap())
            .collect();
        let files = ciphervault_snapshot::decrypt_snapshot(
            &[7; 32],
            &self.store.get_epoch_key(record.epoch).unwrap(),
            record.epoch,
            &encrypted,
            &self.store.get_chunks(&needed).unwrap(),
        )
        .unwrap();
        files[0].plaintext.clone()
    }
}

struct RunningLoop {
    shutdown: tokio::sync::broadcast::Sender<()>,
    result: std::sync::mpsc::Receiver<anyhow::Result<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl RunningLoop {
    fn start(config: WatcherConfig) -> Self {
        let (shutdown, receiver) = tokio::sync::broadcast::channel(8);
        let (result_tx, result) = std::sync::mpsc::channel();
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let watcher = VaultWatcher::new(config).unwrap();
            ready_tx.send(()).unwrap();
            let outcome = runtime.block_on(watcher.run_loop(receiver));
            result_tx.send(outcome).unwrap();
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            shutdown,
            result,
            thread: Some(thread),
        }
    }
    fn stop(mut self) {
        self.shutdown.send(()).unwrap();
        self.result
            .recv_timeout(Duration::from_secs(2))
            .expect("Watcher shutdown blocked on work/upload")
            .unwrap();
        self.thread.take().unwrap().join().unwrap();
    }
}
impl Drop for RunningLoop {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = self.shutdown.send(());
            if self.result.recv_timeout(Duration::from_secs(5)).is_ok() {
                let _ = thread.join();
            }
        }
    }
}

async fn wait_until(description: &str, predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Timed out waiting for {description}"));
}

#[tokio::test]
async fn polling_only_change_is_committed_by_the_real_loop() {
    let fixture = LoopFixture::new(".git/poll-only.env");
    fixture.baseline().await;
    let running = RunningLoop::start(fixture.config());
    tokio::time::sleep(Duration::from_millis(300)).await;
    fixture.write(b"SYNTHETIC=changed_without_native_event\n");
    wait_until("polling-only capture", || {
        fixture
            .store
            .get_active_head()
            .unwrap()
            .unwrap()
            .device_counter
            >= 2
    })
    .await;
    assert_eq!(
        fixture.plaintext(),
        b"SYNTHETIC=changed_without_native_event\n"
    );
    // Restart baseline reflects committed manifest contents instead of treating all files as dirty.
    assert!(!VaultWatcher::new(fixture.config())
        .unwrap()
        .check_for_changes()
        .unwrap());
    running.stop();
    drop(fixture.store);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[tokio::test]
async fn failed_capture_remains_dirty_and_is_retried_by_polling() {
    let fixture = LoopFixture::new(".git/poll-only.env");
    fixture.baseline().await;
    let running = RunningLoop::start(fixture.config());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut invalid = fixture.certificate.clone();
    invalid.permissions = 0;
    invalid.sign(&fixture.recovery_signer).unwrap();
    fixture.store.save_device_certificate(&invalid).unwrap();
    fixture.write(b"SYNTHETIC=retry_after_failure\n");
    wait_until("recorded capture failure", || {
        fixture
            .store
            .list_activity(50)
            .unwrap()
            .iter()
            .any(|event| event.event_type == "WATCH_CAPTURE_FAILED")
    })
    .await;
    assert_eq!(
        fixture
            .store
            .get_active_head()
            .unwrap()
            .unwrap()
            .device_counter,
        1
    );
    assert!(VaultWatcher::new(fixture.config())
        .unwrap()
        .check_for_changes()
        .unwrap());
    fixture
        .store
        .save_device_certificate(&fixture.certificate)
        .unwrap();
    wait_until("capture retry after repairing signing certificate", || {
        fixture
            .store
            .get_active_head()
            .unwrap()
            .unwrap()
            .device_counter
            >= 2
    })
    .await;
    assert_eq!(fixture.plaintext(), b"SYNTHETIC=retry_after_failure\n");
    running.stop();
    drop(fixture.store);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[tokio::test]
async fn native_event_burst_coalesces_and_commits_the_final_bytes() {
    let fixture = LoopFixture::new(".env");
    fixture.baseline().await;
    let running = RunningLoop::start(fixture.config());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let noise = fixture.root.join("burst");
    fs::create_dir(&noise).unwrap();
    for index in 0..500 {
        fs::write(noise.join(format!("event-{index}")), b"untracked event").unwrap();
        fixture.write(format!("SYNTHETIC=burst_{index}\n").as_bytes());
    }
    fixture.write(b"SYNTHETIC=final_burst_value\n");
    wait_until("coalesced final capture", || {
        fixture
            .store
            .get_active_head()
            .unwrap()
            .unwrap()
            .device_counter
            >= 2
    })
    .await;
    wait_until("final committed bytes", || {
        fixture.plaintext() == b"SYNTHETIC=final_burst_value\n"
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        fixture
            .store
            .get_active_head()
            .unwrap()
            .unwrap()
            .device_counter
            <= 5,
        "Native burst caused unbounded duplicate captures"
    );
    running.stop();
    drop(fixture.store);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[tokio::test]
async fn shutdown_cancels_slow_operator_request_and_preserves_pending_upload() {
    let fixture = LoopFixture::new(".git/poll-only.env");
    fixture.baseline().await;
    let reached = std::sync::Arc::new(tokio::sync::Notify::new());
    let callback = reached.clone();
    let app = axum::Router::new().fallback(move || {
        let reached = callback.clone();
        async move {
            reached.notify_one();
            std::future::pending::<String>().await
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut config = fixture.config();
    config.replicate_remote = true;
    config.operators = vec![endpoint];
    let running = RunningLoop::start(config);
    tokio::time::sleep(Duration::from_millis(300)).await;
    fixture.write(b"SYNTHETIC=pending_slow_upload\n");
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .expect("Slow operator was not contacted");
    running.stop();
    assert_eq!(fixture.plaintext(), b"SYNTHETIC=pending_slow_upload\n");
    assert_eq!(fixture.store.list_pending_uploads().unwrap().len(), 1);
    server.abort();
    let _ = server.await;
    drop(fixture.store);
    fs::remove_dir_all(fixture.root).unwrap();
}
