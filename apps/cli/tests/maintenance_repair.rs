use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
use ciphervault_format::{
    to_canonical_cbor, DeviceCertificate, GenesisRecord, HeadRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_maintenance::MaintenanceEngine;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_maintenance_audit_and_self_repair() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_maint_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    // 1. Spawn 3 operator instances
    let op1_dir = test_dir.join("op1");
    let op2_dir = test_dir.join("op2");
    let op3_dir = test_dir.join("op3");

    let (url1, _h1) = spawn_operator(8401, op1_dir.clone()).await;
    let (url2, _h2) = spawn_operator(8402, op2_dir.clone()).await;
    let (url3, _h3) = spawn_operator(8403, op3_dir.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let operators = vec![url1.clone(), url2.clone(), url3.clone()];

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
        "CONFIDENTIAL_PAYLOAD=marker_payload_data_9999\n",
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

    // 3. Replicate across all 3 operators
    let pool = MultiOperatorPool::new(operators.clone());
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

    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &dev_sk,
            &wire_objects,
            &closure_digest,
            snap_out.closure.total_bytes,
            90,
            &locator,
            &head_cbor,
            &recovery_set.records,
            3,
        )
        .await
        .unwrap();

    assert_eq!(
        receipts.len(),
        3,
        "All 3 operators should have verified replicas"
    );

    // 4. Test MaintenanceEngine Audit on healthy state
    let engine = MaintenanceEngine::new(operators.clone());
    let sessions = engine.authenticate_all(&vault_id, &dev_sk).await;
    assert_eq!(sessions.len(), 3);

    let initial_audit = engine
        .audit_closure(&snap_out.closure, &sessions)
        .await
        .unwrap();
    assert_eq!(initial_audit.healthy_count, initial_audit.total_objects);
    assert_eq!(initial_audit.degraded_count, 0);
    assert_eq!(initial_audit.lost_count, 0);

    // 5. Fault Injection: Delete a chunk object from Operator 1's disk
    let chunk_cid = snap_out.chunks[0].compute_cid().unwrap();
    let op1_chunk_path = op1_dir.join("objects").join(hex::encode(chunk_cid));
    assert!(
        op1_chunk_path.exists(),
        "Chunk should exist on Operator 1 disk"
    );
    fs::remove_file(&op1_chunk_path).unwrap();

    // 6. Audit again: should detect Operator 1 is degraded
    let degraded_audit = engine
        .audit_closure(&snap_out.closure, &sessions)
        .await
        .unwrap();
    assert_eq!(
        degraded_audit.degraded_count, 1,
        "Should detect 1 degraded object"
    );
    assert_eq!(degraded_audit.degraded_objects[0].cid, chunk_cid);
    assert!(degraded_audit.degraded_objects[0]
        .missing_on
        .contains(&url1));
    assert!(degraded_audit.degraded_objects[0]
        .present_on
        .contains(&url2));
    assert!(degraded_audit.degraded_objects[0]
        .present_on
        .contains(&url3));

    // 7. Execute Autonomous Self-Repair
    let repair_res = engine
        .repair_closure(&degraded_audit, &sessions, &dev_sk)
        .await
        .unwrap();
    assert_eq!(repair_res.objects_repaired, 1);
    assert_eq!(repair_res.objects_failed, 0);
    assert_eq!(repair_res.placement_updates.len(), 1);

    // Verify chunk object restored on Operator 1 disk
    assert!(
        op1_chunk_path.exists(),
        "Chunk should have been restored onto Operator 1 disk"
    );

    // 8. Re-audit: should be 100% HEALTHY again!
    let healed_audit = engine
        .audit_closure(&snap_out.closure, &sessions)
        .await
        .unwrap();
    assert_eq!(healed_audit.healthy_count, healed_audit.total_objects);
    assert_eq!(healed_audit.degraded_count, 0);
    assert_eq!(healed_audit.lost_count, 0);

    // 9. Test Lease Renewal
    let renewed_receipts = engine.renew_leases(&receipts, &sessions, 30).await;
    assert_eq!(renewed_receipts.len(), 3, "All 3 leases should be renewed");
    for r in &renewed_receipts {
        assert_eq!(r.term_days, 120);
        let original = receipts
            .iter()
            .find(|old| old.lease_id == r.lease_id)
            .unwrap();
        assert_eq!(r.closure_digest_hex, original.closure_digest_hex);
        assert_eq!(r.expires_at_utc, original.expires_at_utc + 30 * 86400);
    }

    let _ = fs::remove_dir_all(test_dir);
}

#[test]
fn test_persisted_fleet_maintenance_scheduler() {
    use ciphervault_maintenance::MaintenanceDb;

    let test_dir = std::env::temp_dir().join(format!(
        "cv_fleet_sched_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();
    let db_path = test_dir.join("fleet_scheduler.db");

    let db = MaintenanceDb::open(&db_path).unwrap();

    // 1. Register fleet vaults
    let locator_a = "a".repeat(64);
    let locator_b = "b".repeat(64);
    db.register_vault(&locator_a, Some("Vault Alpha")).unwrap();
    db.register_vault(&locator_b, Some("Vault Beta")).unwrap();

    let initial_vaults = db.list_vaults().unwrap();
    assert_eq!(initial_vaults.len(), 2);
    assert_eq!(initial_vaults[0].label, "Vault Alpha");
    assert_eq!(initial_vaults[1].label, "Vault Beta");
    assert_eq!(initial_vaults[0].last_status, "Registered");

    // 2. Record audits
    db.record_audit(&locator_a, true, 25, 0, r#"{"healthy": true}"#)
        .unwrap();
    db.record_audit(
        &locator_b,
        false,
        25,
        3,
        r#"{"healthy": false, "degraded": 3}"#,
    )
    .unwrap();

    let updated_vaults = db.list_vaults().unwrap();
    assert_eq!(updated_vaults[0].last_status, "Healthy");
    assert_eq!(updated_vaults[1].last_status, "Degraded");
    assert!(updated_vaults[0].last_audit_at_utc.is_some());
    assert!(updated_vaults[1].last_audit_at_utc.is_some());

    // 3. Track operator health
    db.update_operator_health("http://127.0.0.1:8787", 25, true)
        .unwrap();
    db.update_operator_health("http://127.0.0.1:8788", 40, true)
        .unwrap();
    db.update_operator_health("http://127.0.0.1:8789", 0, false)
        .unwrap();

    // 4. Validate fleet summary
    let summary = db.get_fleet_summary().unwrap();
    assert_eq!(summary.total_tracked_vaults, 2);
    assert_eq!(summary.healthy_vaults, 1);
    assert_eq!(summary.degraded_vaults, 1);
    assert_eq!(summary.total_audits_recorded, 2);
    assert_eq!(summary.total_operators, 3);
    assert_eq!(summary.online_operators, 2);

    let _ = fs::remove_dir_all(test_dir);
}
