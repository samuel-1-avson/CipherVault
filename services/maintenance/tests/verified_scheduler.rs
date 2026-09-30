use ciphervault_crypto::generate_signing_key;
use ciphervault_format::{
    compute_digest, to_canonical_cbor, DeviceCertificate, GenesisRecord, HeadRecord,
    RecoveryClosure, RecoverySet, SnapshotRecord, PROTOCOL_VERSION,
};
use ciphervault_maintenance::{
    scheduler::{run_inventory_job, MaintenanceInventory},
    MaintenanceDb,
};
use ciphervault_operator::{create_router, OperatorState};
use std::{collections::HashMap, sync::Arc};

fn inventory_fixture() -> (MaintenanceInventory, Vec<Vec<u8>>) {
    let root_key = generate_signing_key();
    let device = generate_signing_key();
    let vault = [1; 32];
    let locator = [2; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        recovery_signing_pk: root_key.verifying_key().to_bytes().to_vec(),
        recovery_encryption_pk: vec![2; 32],
        policy_digest: vec![3; 32],
        creation_nonce: vec![4; 32],
        created_at_utc: 1,
        signature: vec![],
    };
    genesis.sign(&root_key).unwrap();
    let mut certificate = DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        certificate_id: vec![3; 32],
        device_signing_pk: device.verifying_key().to_bytes().to_vec(),
        permissions: 1,
        authority_generation: 1,
        issued_at_utc: 1,
        signature: vec![],
    };
    certificate.sign(&root_key).unwrap();
    let manifest = b"synthetic encrypted manifest".to_vec();
    let chunk = b"synthetic encrypted chunk".to_vec();
    let mut snapshot = SnapshotRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        snapshot_id: vec![4; 32],
        parent_snapshot_ids: vec![],
        device_id: vec![5; 32],
        device_counter: 1,
        authority_generation: 1,
        epoch: 1,
        encrypted_manifest_cid: compute_digest(&manifest).to_vec(),
        encrypted_manifest_len: manifest.len() as u64,
        advisory_timestamp_utc: 1,
        signature: vec![],
    };
    snapshot.sign(&device).unwrap();
    let snapshot_bytes = to_canonical_cbor(&snapshot).unwrap();
    let records = vec![
        to_canonical_cbor(&genesis).unwrap(),
        to_canonical_cbor(&certificate).unwrap(),
    ];
    let closure = RecoveryClosure {
        snapshot_id: snapshot.snapshot_id.clone(),
        snapshot_record_cid: compute_digest(&snapshot_bytes).to_vec(),
        manifest_cid: compute_digest(&manifest).to_vec(),
        envelope_ids: records
            .iter()
            .map(|record| compute_digest(record).to_vec())
            .collect(),
        chunk_cids: vec![compute_digest(&chunk).to_vec()],
        total_bytes: chunk.len() as u64,
    };
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        snapshot_id: compute_digest(&snapshot_bytes).to_vec(),
        parent_snapshot_ids: vec![],
        closure_digest: closure.compute_base_closure_digest().unwrap().to_vec(),
        device_id: snapshot.device_id,
        device_counter: 1,
        signature: vec![],
    };
    head.sign(&device).unwrap();
    let mut objects = vec![snapshot_bytes, manifest, chunk];
    objects.extend(records.clone());
    (
        MaintenanceInventory {
            set: RecoverySet {
                closure,
                locator,
                records,
            },
            head: to_canonical_cbor(&head).unwrap(),
            vault_id: vault,
            recovery_signing_pk: root_key.verifying_key().to_bytes(),
            operator_keys: HashMap::new(),
            required_replicas: 1,
            leases: vec![],
            account_id: None,
            device_id_hex: None,
        },
        objects,
    )
}

#[tokio::test]
async fn daemon_job_rejects_metadata_only_and_missing_chunk_while_logs_remain() {
    let root =
        std::env::temp_dir().join(format!("cv-maintenance-audit-{}", rand::random::<u128>()));
    let (mut inventory, objects) = inventory_fixture();
    inventory.validate().unwrap();
    let operator_key = generate_signing_key();
    let pk = operator_key.verifying_key().to_bytes();
    let state = Arc::new(OperatorState::new_with_security(
        "maintenance-fixture".into(),
        root.join("operator"),
        operator_key,
        ciphervault_operator::state::OperatorSecurityConfig::from_flags(None, None),
    ));
    for record in inventory
        .set
        .records
        .iter()
        .chain(std::iter::once(&inventory.head))
    {
        state
            .append_recovery_record(&hex::encode(inventory.set.locator), record)
            .unwrap();
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    inventory.operator_keys.insert(endpoint, pk);
    let app = create_router(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let db = MaintenanceDb::open(&root.join("maintenance.db")).unwrap();
    db.store_inventory(&inventory).unwrap();
    let metadata_only = run_inventory_job(&db, &mut inventory, None).await.unwrap();
    assert!(!metadata_only.healthy);
    assert!(metadata_only.objects.lost_count > 0);
    for object in &objects {
        state
            .put_object(&hex::encode(compute_digest(object)), object)
            .unwrap();
    }
    assert!(
        run_inventory_job(&db, &mut inventory, None)
            .await
            .unwrap()
            .healthy
    );
    let chunk_cid = hex::encode(&inventory.set.closure.chunk_cids[0]);
    std::fs::remove_file(root.join("operator/objects").join(chunk_cid)).unwrap();
    let after_loss = run_inventory_job(&db, &mut inventory, None).await.unwrap();
    assert!(!after_loss.healthy);
    assert_eq!(after_loss.objects.lost_count, 1);
    assert!(!state
        .get_recovery_records(&hex::encode(inventory.set.locator))
        .is_empty());
    assert_eq!(db.get_fleet_summary().unwrap().healthy_vaults, 0);
    task.abort();
    let _ = task.await;
    drop(state);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inventories_and_retry_deadlines_survive_restart_and_reject_changed_closures() {
    let root = std::env::temp_dir().join(format!("cv-maintenance-jobs-{}", rand::random::<u128>()));
    std::fs::create_dir_all(&root).unwrap();
    let (inventory, _) = inventory_fixture();
    let locator = hex::encode(inventory.set.locator);
    let db = MaintenanceDb::open(&root.join("maintenance.db")).unwrap();
    db.store_inventory(&inventory).unwrap();
    db.record_job_result(&locator, 30, Some("missing chunk"))
        .unwrap();
    drop(db);
    let db = MaintenanceDb::open(&root.join("maintenance.db")).unwrap();
    assert!(db.get_inventory(&locator).unwrap().is_some());
    assert!(!db
        .job_due(&locator, chrono::Utc::now().timestamp() as u64)
        .unwrap());
    let mut tampered = inventory;
    tampered.set.closure.chunk_cids.push(vec![9; 32]);
    assert!(db.store_inventory(&tampered).is_err());
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
