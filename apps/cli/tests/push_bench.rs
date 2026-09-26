//! Phase 3 perf proof: sequential vs concurrent multi-object replication.
//!
//! Ignored by default; run release-mode so timings are meaningful:
//! `cargo test -p ciphervault-cli --release --test push_bench -- --ignored --nocapture`
//!
//! Knobs: `CIPHERVAULT_BENCH_OBJECTS` (default 48),
//! `CIPHERVAULT_BENCH_OBJECT_KB` (default 16),
//! `CIPHERVAULT_BENCH_SOAK_ITERS` (default 2),
//! `CIPHERVAULT_BENCH_ASSERT=1` (fail unless speedup >= 2.0; warn-only otherwise).

use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
use ciphervault_format::{
    to_canonical_cbor, DeviceCertificate, GenesisRecord, HeadRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_operator::{create_router, OperatorState};
use ciphervault_snapshot::create_snapshot;
use ciphervault_storage::MultiOperatorPool;

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

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

type BenchObjects = (Vec<([u8; 32], Vec<u8>)>, u64);

/// Deterministic pseudo-random object bytes; distinct per (seed, index) so
/// every bench run uploads fresh CIDs (no PoS dedup short-circuit).
fn bench_objects(seed: u64, count: usize, size: usize) -> BenchObjects {
    let mut objects = Vec::with_capacity(count);
    let mut total = 0u64;
    for index in 0..count {
        // xorshift64* stream: no extra deps, distinct per object.
        let mut state = seed
            .wrapping_add(index as u64)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            | 1;
        let mut bytes = Vec::with_capacity(size);
        while bytes.len() < size {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            bytes.extend_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
        }
        bytes.truncate(size);
        let cid = ciphervault_format::compute_digest(&bytes);
        total += bytes.len() as u64;
        objects.push((cid, bytes));
    }
    (objects, total)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_push_sequential_vs_concurrent() {
    let object_count = env_usize("CIPHERVAULT_BENCH_OBJECTS", 48);
    let object_kb = env_usize("CIPHERVAULT_BENCH_OBJECT_KB", 16);
    let soak_iters = env_usize("CIPHERVAULT_BENCH_SOAK_ITERS", 2);
    let assert_speedup = matches!(
        std::env::var("CIPHERVAULT_BENCH_ASSERT").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );

    let test_dir = std::env::temp_dir().join(format!(
        "cv_push_bench_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    // Soak operators run with a raised HTTP rate limit: one loopback client
    // firing ~150 requests per batch per operator would otherwise trip the
    // default 600/min limiter (readback challenges fail closed on 429).
    std::env::set_var("CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN", "120000");

    // 1. Spawn 3 operator instances.
    let op1_dir = test_dir.join("op1");
    let op2_dir = test_dir.join("op2");
    let op3_dir = test_dir.join("op3");

    let (url1, _h1) = spawn_operator(8601, op1_dir).await;
    let (url2, _h2) = spawn_operator(8602, op2_dir).await;
    let (url3, _h3) = spawn_operator(8603, op3_dir).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let operators = vec![url1, url2, url3];

    // 2. Setup vault and snapshot (recovery ceremony reused across runs).
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
    fs::write(&test_file, "PUSH_BENCH_PAYLOAD=marker_payload_data_4343\n").unwrap();
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

    let pool = MultiOperatorPool::new(operators);
    let closure_digest = snap_out.closure.compute_base_closure_digest().unwrap();
    let head_cbor = to_canonical_cbor(&head).unwrap();
    let object_size = object_kb * 1024;

    // 3. Baseline: strictly sequential object pipeline.
    pool.set_object_concurrency(1);
    let (objects_seq, bytes_seq) = bench_objects(0x5eed_0001, object_count, object_size);
    let started = Instant::now();
    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &dev_sk,
            &objects_seq,
            &closure_digest,
            bytes_seq,
            90,
            &locator,
            &head_cbor,
            &recovery_set.records,
            3,
        )
        .await
        .expect("sequential run must reach quorum");
    assert_eq!(receipts.len(), 3);
    let sequential = started.elapsed();

    // 4. Concurrent pipeline with FRESH objects (fair: no dedup reuse).
    pool.set_object_concurrency(8);
    let (objects_conc, bytes_conc) = bench_objects(0x5eed_0002, object_count, object_size);
    let started = Instant::now();
    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &dev_sk,
            &objects_conc,
            &closure_digest,
            bytes_conc,
            90,
            &locator,
            &head_cbor,
            &recovery_set.records,
            3,
        )
        .await
        .expect("concurrent run must reach quorum");
    assert_eq!(receipts.len(), 3);
    let concurrent = started.elapsed();

    // 5. Soak: repeated concurrent quorums must all succeed (catches
    // busy-timeout and flake regressions under sustained load).
    for iter in 0..soak_iters {
        // Stride by object count: bench_objects mixes seed+index, so a
        // stride of 1 would re-push the same CIDs every iteration.
        let (objects, total_bytes) = bench_objects(
            0x5eed_1000 + iter as u64 * object_count as u64,
            object_count,
            object_size,
        );
        let receipts = pool
            .replicate_and_verify(
                &vault_id,
                &dev_sk,
                &objects,
                &closure_digest,
                total_bytes,
                90,
                &locator,
                &head_cbor,
                &recovery_set.records,
                3,
            )
            .await
            .expect("soak run must reach quorum");
        assert_eq!(receipts.len(), 3);
    }
    assert_eq!(
        ciphervault_local_store::sqlite_busy_retries(),
        0,
        "soak must not hit SQLite lock contention"
    );

    let speedup = sequential.as_secs_f64() / concurrent.as_secs_f64().max(1e-9);
    println!("push_bench: {object_count} x {object_kb} KiB objects on 3 loopback operators");
    println!("push_bench: sequential(c=1) {sequential:.2?}  concurrent(c=8) {concurrent:.2?}  speedup {speedup:.2}x");
    println!(
        "PUSH_BENCH_JSON {}",
        serde_json::json!({
            "objects": object_count,
            "object_kb": object_kb,
            "sequential_secs": sequential.as_secs_f64(),
            "concurrent_secs": concurrent.as_secs_f64(),
            "speedup": speedup,
            "soak_iters": soak_iters,
            "quorum": 3,
            "sqlite_busy_retries": ciphervault_local_store::sqlite_busy_retries(),
        })
    );
    if speedup < 2.0 {
        if assert_speedup {
            panic!("push bench speedup {speedup:.2}x below required 2.0x");
        }
        eprintln!(
            "push_bench WARNING: speedup {speedup:.2}x below 2.0x target (warn-only; set CIPHERVAULT_BENCH_ASSERT=1 to enforce)"
        );
    }
}
