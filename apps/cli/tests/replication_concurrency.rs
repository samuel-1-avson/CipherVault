use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
use ciphervault_format::{
    to_canonical_cbor, DeviceCertificate, GenesisRecord, HeadRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_operator::{create_router, OperatorState};
use ciphervault_snapshot::create_snapshot;
use ciphervault_storage::{LeaseReceipt, MultiOperatorPool};

async fn spawn_operator(
    port: u16,
    data_dir: std::path::PathBuf,
) -> (String, tokio::task::JoinHandle<()>) {
    let state = Arc::new(OperatorState::new(
        format!("op_{}", port),
        data_dir,
        generate_signing_key(),
    ));
    let app = create_router(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = TcpListener::bind(addr).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (url, handle)
}

struct ReplicationFixture {
    op_dirs: Vec<std::path::PathBuf>,
    operators: Vec<String>,
    vault_id: [u8; 32],
    dev_sk: ed25519_dalek::SigningKey,
    wire_objects: Vec<([u8; 32], Vec<u8>)>,
    closure_digest: [u8; 32],
    total_bytes: u64,
    locator: [u8; 32],
    head_cbor: Vec<u8>,
    recovery_records: Vec<Vec<u8>>,
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ReplicationFixture {
    async fn replicate(
        &self,
        pool: &MultiOperatorPool,
        required: usize,
    ) -> Result<Vec<LeaseReceipt>, ciphervault_storage::StorageError> {
        pool.replicate_and_verify(
            &self.vault_id,
            &self.dev_sk,
            &self.wire_objects,
            &self.closure_digest,
            self.total_bytes,
            90,
            &self.locator,
            &self.head_cbor,
            &self.recovery_records,
            required,
        )
        .await
    }
}

fn assert_quorum_receipts(receipts: &[LeaseReceipt], closure_digest: &[u8; 32]) {
    assert_eq!(
        receipts.len(),
        3,
        "All 3 operators should have verified replicas"
    );
    let operator_ids: Vec<&str> = receipts
        .iter()
        .map(|receipt| receipt.operator_id.as_str())
        .collect();
    let mut sorted_ids = operator_ids.clone();
    sorted_ids.sort_unstable();
    assert_eq!(
        operator_ids, sorted_ids,
        "Receipts must be sorted by operator_id for deterministic output"
    );
    sorted_ids.dedup();
    assert_eq!(
        sorted_ids.len(),
        3,
        "Each receipt must come from a distinct operator"
    );
    let expected_digest = hex::encode(closure_digest);
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.closure_digest_hex == expected_digest),
        "All receipts must commit to the replicated closure digest"
    );
}

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

async fn setup_replication_fixture() -> ReplicationFixture {
    // Wall-clock nanos collide across parallel test threads on coarse
    // timers; the pid + counter suffix keeps every fixture dir unique.
    let slot = FIXTURE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let test_dir = std::env::temp_dir().join(format!(
        "cv_repl_conc_test_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        slot
    ));
    fs::create_dir_all(&test_dir).unwrap();

    // 1. Spawn 3 operator instances
    let op1_dir = test_dir.join("op1");
    let op2_dir = test_dir.join("op2");
    let op3_dir = test_dir.join("op3");

    let (url1, h1) = spawn_operator(8501, op1_dir.clone()).await;
    let (url2, h2) = spawn_operator(8502, op2_dir.clone()).await;
    let (url3, h3) = spawn_operator(8503, op3_dir.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let operators = vec![url1, url2, url3];

    // 2. Setup vault and snapshot
    let vault_dir = test_dir.join("client_vault");
    fs::create_dir_all(&vault_dir).unwrap();

    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();
    let locator = r.derive_recovery_locator().unwrap();

    let vault_id = [0x55u8; 32];
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
    let dev_id = [0x66u8; 32];
    let epoch_key = VaultEpochKey::generate();

    let db_path = vault_dir.join("vault.db");
    let store = LocalVaultStore::open(&db_path).unwrap();
    store
        .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
        .unwrap();

    let test_file = vault_dir.join("secrets.txt");
    fs::write(
        &test_file,
        "CONCURRENT_REPLICATION_PAYLOAD=marker_payload_data_4242\n",
    )
    .unwrap();
    store.track_file("secrets.txt").unwrap();

    let tracked = store.list_tracked_files().unwrap();
    let snap_out = create_snapshot(
        &vault_dir,
        &tracked,
        &vault_id,
        1,
        &epoch_key,
        Vec::new(),
        &dev_id,
        1,
        1,
        &dev_sk,
    )
    .unwrap();

    store
        .save_snapshot(
            &snap_out.record,
            &snap_out.encrypted_manifest,
            &snap_out.chunks,
        )
        .unwrap();

    let record_cid = snap_out.record.compute_record_cid().unwrap();
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        snapshot_id: record_cid.to_vec(),
        parent_snapshot_ids: Vec::new(),
        closure_digest: snap_out
            .closure
            .compute_base_closure_digest()
            .unwrap()
            .to_vec(),
        device_id: dev_id.to_vec(),
        device_counter: 1,
        signature: Vec::new(),
    };
    head.sign(&dev_sk).unwrap();
    store.set_head(&head).unwrap();

    let mut cert = DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        certificate_id: vec![1u8; 32],
        device_signing_pk: dev_sk.verifying_key().as_bytes().to_vec(),
        permissions: 0xFFFFFFFF,
        authority_generation: 1,
        issued_at_utc: 1000,
        signature: Vec::new(),
    };
    cert.sign(&r_sk).unwrap();
    store.save_device_certificate(&cert).unwrap();
    let recovery_set = store.prepare_recovery_set(&snap_out.record).unwrap();

    // 3. Wire objects for the concurrent pipeline (replication happens per-test)
    let mut wire_objects = Vec::new();
    for chunk in &snap_out.chunks {
        let cid = chunk.compute_cid().unwrap();
        let cbor = to_canonical_cbor(chunk).unwrap();
        wire_objects.push((cid, cbor));
    }
    wire_objects.push((snap_out.manifest_cid, snap_out.encrypted_manifest.clone()));
    wire_objects.push((record_cid, to_canonical_cbor(&snap_out.record).unwrap()));

    let closure_digest = snap_out.closure.compute_base_closure_digest().unwrap();
    let head_cbor = to_canonical_cbor(&head).unwrap();

    ReplicationFixture {
        op_dirs: vec![op1_dir, op2_dir, op3_dir],
        operators,
        vault_id,
        dev_sk,
        wire_objects,
        closure_digest,
        total_bytes: snap_out.closure.total_bytes,
        locator,
        head_cbor,
        recovery_records: recovery_set.records,
        _handles: vec![h1, h2, h3],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_replication_reaches_quorum_with_stable_order() {
    let fixture = setup_replication_fixture().await;

    // 3. Replicate across all 3 operators through the concurrent pipeline
    let pool = MultiOperatorPool::new(fixture.operators.clone());

    let receipts = fixture.replicate(&pool, 3).await.unwrap();

    // Quorum must survive the concurrent pipeline at default settings...
    assert_quorum_receipts(&receipts, &fixture.closure_digest);

    // ...and at both ends of the object-concurrency range.
    pool.set_object_concurrency(1);
    let sequential = fixture.replicate(&pool, 3).await.unwrap();
    assert_quorum_receipts(&sequential, &fixture.closure_digest);

    pool.set_object_concurrency(8);
    let concurrent = fixture.replicate(&pool, 3).await.unwrap();
    assert_quorum_receipts(&concurrent, &fixture.closure_digest);
}

/// A push cancelled mid-flight (for example by quorum early-exit when a
/// sibling operator fails) leaves a partial recovery log behind. The next
/// push must heal that operator instead of failing quorum: the operator
/// rejects the already-registered records with 400, the client skips them,
/// appends the missing suffix, and the discovery readback confirms the set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_replication_heals_operator_with_partial_recovery_log() {
    let fixture = setup_replication_fixture().await;
    let pool = MultiOperatorPool::new(fixture.operators.clone());

    // First push completes everywhere.
    let receipts = fixture.replicate(&pool, 3).await.unwrap();
    assert_quorum_receipts(&receipts, &fixture.closure_digest);

    // Simulate a push cancelled after its first record: truncate op1's log to
    // the genesis record alone (records are u32-big-endian length-prefixed).
    let log_path = fixture.op_dirs[0]
        .join("recovery")
        .join(format!("{}.log", hex::encode(fixture.locator)));
    let bytes = fs::read(&log_path).unwrap();
    assert!(bytes.len() > 4, "expected a populated recovery log");
    let first_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    fs::write(&log_path, &bytes[..4 + first_len]).unwrap();

    // The next push must heal the partial log and still reach quorum.
    let healed = fixture.replicate(&pool, 3).await.unwrap();
    assert_quorum_receipts(&healed, &fixture.closure_digest);
}
