use std::fs;

use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
use ciphervault_format::{DeviceCertificate, GenesisRecord, HeadRecord, PROTOCOL_VERSION};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_snapshot::create_snapshot;

/// R18: retention prune removes old snapshot rows, recovery sets, and only
/// the chunks no retained recovery set references. The active head and
/// unreplicated snapshots are fail-closed.
#[test]
fn prune_retains_head_pending_and_shared_chunks() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_prune_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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

    let store = LocalVaultStore::open(vault_dir.join("vault.db")).unwrap();
    store
        .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
        .unwrap();

    let test_file = vault_dir.join("secrets.txt");
    fs::write(&test_file, "PRUNE_V1_SECRET=alpha\n").unwrap();
    store.track_file("secrets.txt").unwrap();

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

    // Snapshot v1.
    let tracked = store.list_tracked_files().unwrap();
    let snap1 = create_snapshot(
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
        .save_snapshot(&snap1.record, &snap1.encrypted_manifest, &snap1.chunks)
        .unwrap();
    let set1 = store.prepare_recovery_set(&snap1.record).unwrap();
    let v1_cid = snap1.record.compute_record_cid().unwrap();

    // Snapshot v2 with changed content.
    fs::write(
        &test_file,
        "PRUNE_V2_SECRET=beta-longer-content-to-shift-chunks\n",
    )
    .unwrap();
    let tracked = store.list_tracked_files().unwrap();
    let snap2 = create_snapshot(
        &vault_dir,
        &tracked,
        &vault_id,
        1,
        &epoch_key,
        vec![v1_cid],
        &dev_id,
        2,
        1,
        &dev_sk,
    )
    .unwrap();
    store
        .save_snapshot(&snap2.record, &snap2.encrypted_manifest, &snap2.chunks)
        .unwrap();
    let set2 = store.prepare_recovery_set(&snap2.record).unwrap();
    let v2_cid = snap2.record.compute_record_cid().unwrap();

    // Head -> v2, both replicated.
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        snapshot_id: v2_cid.to_vec(),
        parent_snapshot_ids: Vec::new(),
        closure_digest: set2.closure.compute_base_closure_digest().unwrap().to_vec(),
        device_id: dev_id.to_vec(),
        device_counter: 2,
        signature: Vec::new(),
    };
    head.sign(&dev_sk).unwrap();
    store.set_head(&head).unwrap();
    let v1_logical: [u8; 32] = snap1.record.snapshot_id.as_slice().try_into().unwrap();
    let v2_logical: [u8; 32] = snap2.record.snapshot_id.as_slice().try_into().unwrap();
    store.mark_upload_completed(&v1_logical).unwrap();
    store.mark_upload_completed(&v2_logical).unwrap();

    // Exclusive/shared chunk partition BEFORE pruning.
    let set1_chunks: std::collections::HashSet<[u8; 32]> = set1
        .closure
        .chunk_cids
        .iter()
        .map(|c| c.as_slice().try_into().unwrap())
        .collect();
    let set2_chunks: std::collections::HashSet<[u8; 32]> = set2
        .closure
        .chunk_cids
        .iter()
        .map(|c| c.as_slice().try_into().unwrap())
        .collect();
    let exclusive: Vec<[u8; 32]> = set1_chunks.difference(&set2_chunks).copied().collect();

    // Prune v1: rows + set + exclusive chunks go; v2 and shared chunks stay.
    let outcome = store.prune_snapshots(&[v1_cid]).unwrap();
    assert_eq!(outcome.snapshots_removed, 1);
    assert_eq!(outcome.snapshots_skipped_protected, 0);
    assert!(!outcome.chunk_gc_skipped);
    assert_eq!(outcome.chunks_removed, exclusive.len());
    assert!(store.get_snapshot(&v1_cid).is_err());
    assert!(store.get_recovery_set(&v1_cid).is_err());
    assert!(store.get_snapshot(&v2_cid).is_ok());
    let remaining = store.list_all_chunk_cids().unwrap();
    for cid in &exclusive {
        assert!(!remaining.contains(cid));
    }
    for cid in &set2_chunks {
        assert!(remaining.contains(cid));
    }

    // Head is fail-closed.
    let outcome = store.prune_snapshots(&[v2_cid]).unwrap();
    assert_eq!(outcome.snapshots_removed, 0);
    assert_eq!(outcome.snapshots_skipped_protected, 1);
    assert!(store.get_snapshot(&v2_cid).is_ok());

    // Unreplicated snapshots are fail-closed.
    fs::write(&test_file, "PRUNE_V3_SECRET=gamma\n").unwrap();
    let tracked = store.list_tracked_files().unwrap();
    let snap3 = create_snapshot(
        &vault_dir,
        &tracked,
        &vault_id,
        1,
        &epoch_key,
        vec![v2_cid],
        &dev_id,
        3,
        1,
        &dev_sk,
    )
    .unwrap();
    store
        .save_snapshot(&snap3.record, &snap3.encrypted_manifest, &snap3.chunks)
        .unwrap();
    let v3_cid = snap3.record.compute_record_cid().unwrap();
    let outcome = store.prune_snapshots(&[v3_cid]).unwrap();
    assert_eq!(outcome.snapshots_removed, 0);
    assert_eq!(outcome.snapshots_skipped_protected, 1);
    assert!(store.get_snapshot(&v3_cid).is_ok());

    let _ = fs::remove_dir_all(&test_dir);
}
