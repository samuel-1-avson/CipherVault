//! Ciphertext availability audit and explicit read-only plaintext recovery drill.
use anyhow::{bail, ensure, Context, Result};
use ciphervault_format::{
    compute_digest, from_canonical_cbor, to_canonical_cbor, ChunkWireObject, SnapshotManifest,
    SnapshotRecord,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_storage::OperatorClient;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

use crate::util::{configured_operator_pool, get_configured_operators, get_vault_store};

pub(crate) async fn cmd_audit(
    custom_operators: Option<Vec<String>>,
    export_inventory: Option<std::path::PathBuf>,
    operator_pins: Vec<String>,
    recovery_drill: bool,
) -> Result<()> {
    if recovery_drill {
        let store = LocalVaultStore::open_read_only(
            crate::util::get_vault_directory().join(crate::util::DB_FILE),
        )?;
        let mut pins = crate::util::configured_operator_pins()?;
        merge_pins(&mut pins, &operator_pins)?;
        let pool =
            configured_operator_pool(custom_operators.unwrap_or_else(get_configured_operators));
        let mut clients = Vec::new();
        for client in pool.clients() {
            let pin = *pins.get(client.endpoint()).with_context(|| format!(
                "Recovery drill requires an independently trusted signing key for {}; provide --operator-pin or operator_pins.json", client.endpoint()))?;
            client.pin_signing_key(pin);
            clients.push((client.clone(), pin));
        }
        let report = verify_plaintext_recovery(&store, &clients).await?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    ensure!(
        export_inventory.is_some() || operator_pins.is_empty(),
        "--operator-pin requires --recovery-drill or --export-inventory"
    );
    let report = if let Some(path) = export_inventory {
        let inventory =
            super::fleet_cli::export_maintenance_inventory(&path, custom_operators, operator_pins)
                .await?;
        let store = get_vault_store()?;
        let (_, device_key, _, _) = store.get_device_state()?;
        let engine = inventory.engine();
        let sessions = engine
            .authenticate_all(&inventory.vault_id, &device_key)
            .await;
        let cache = store
            .recovery_objects(&inventory.set)?
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        engine
            .audit_recovery_set_with_cache(&inventory.set, &inventory.head, &sessions, Some(&cache))
            .await?
    } else {
        super::fleet_cli::audit_current(custom_operators).await?
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    ensure!(report.healthy, "Ciphertext recovery set is not durable: {} complete replicas, {} lost objects, {} missing discovery logs",
        report.recoverable_operators.len(), report.objects.lost_count, report.discovery_missing.len());
    Ok(())
}

fn merge_pins(pins: &mut BTreeMap<String, [u8; 32]>, supplied: &[String]) -> Result<()> {
    for entry in supplied {
        let (endpoint, hex_key) = entry
            .rsplit_once('=')
            .context("--operator-pin must be endpoint=64hex")?;
        let decoded = hex::decode(hex_key.trim()).context("Invalid operator signing key hex")?;
        let key = decoded
            .as_slice()
            .try_into()
            .context("Operator signing key must be 32 bytes")?;
        let endpoint = endpoint.trim().trim_end_matches('/');
        ensure!(!endpoint.is_empty(), "Operator pin endpoint is empty");
        pins.insert(endpoint.to_string(), key);
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct RecoveryDrillReport {
    verification: &'static str,
    snapshot_record_cid: String,
    epoch: u64,
    files_verified: usize,
    plaintext_bytes_verified: u64,
    remote_objects_verified: usize,
    independently_pinned_operators_authenticated: usize,
    plaintext_written: bool,
    key_source: &'static str,
}

async fn fetch_verified(
    sessions: &[(OperatorClient, Zeroizing<String>)],
    cid: &[u8; 32],
) -> Result<Vec<u8>> {
    for (client, token) in sessions {
        if let Ok(bytes) = client.get_object(token, cid).await {
            // The client verifies this as well; keep the drill's trust boundary explicit.
            if compute_digest(&bytes) == *cid {
                return Ok(bytes);
            }
        }
    }
    bail!(
        "Recovery drill cannot obtain an integrity-checked remote object {}",
        hex::encode(cid)
    )
}

/// Reconstruct only from remote objects; local ciphertext cache is never a fallback.
async fn verify_plaintext_recovery(
    store: &LocalVaultStore,
    clients: &[(OperatorClient, [u8; 32])],
) -> Result<RecoveryDrillReport> {
    ensure!(
        !clients.is_empty(),
        "Recovery drill requires independently pinned operators"
    );
    let vault = store.get_vault_id()?;
    let head = store
        .get_active_head()?
        .context("No current snapshot for recovery drill")?;
    let record_cid: [u8; 32] = head
        .snapshot_id
        .as_slice()
        .try_into()
        .context("Invalid current head CID")?;
    let set = store.get_recovery_set(&record_cid)?;
    ensure!(
        set.closure.snapshot_record_cid == record_cid
            && set.closure.compute_base_closure_digest()?.as_slice() == head.closure_digest,
        "Recovery inventory does not match the signed head"
    );
    ensure!(
        set.closure.total_bytes <= 1024 * 1024 * 1024,
        "In-memory recovery drill exceeds the 1 GiB plaintext bound"
    );
    let (root_key, _, locator) = store.get_recovery_descriptors()?;
    ensure!(
        set.locator == locator,
        "Recovery inventory locator mismatch"
    );
    let head_bytes = to_canonical_cbor(&head)?;
    let mut candidates = set.records.clone();
    candidates.push(head_bytes.clone());
    let (certified_head, certificate) =
        ciphervault_recovery::trust::select_head(&candidates, &vault, &root_key)?;
    ensure!(
        certified_head == head,
        "Current head is not certified by the stored recovery root"
    );
    let (_, device_key, _, _) = store.get_device_state()?;
    let mut sessions = Vec::new();
    for (client, key) in clients {
        if client.get_info_pinned(key).await.is_ok() {
            if let Ok(token) = client.authenticate(&vault, &device_key).await {
                sessions.push((client.clone(), Zeroizing::new(token)));
            }
        }
    }
    ensure!(
        !sessions.is_empty(),
        "No independently pinned operator authenticated for recovery drill"
    );
    let mut discovery_present = false;
    for (client, _) in &sessions {
        if let Ok(records) = client.get_recovery_records(&locator).await {
            if records.contains(&head_bytes)
                && set.records.iter().all(|record| records.contains(record))
            {
                discovery_present = true;
                break;
            }
        }
    }
    ensure!(
        discovery_present,
        "Current certified head/bootstrap records are unavailable in remote discovery"
    );
    let record_bytes = fetch_verified(&sessions, &record_cid).await?;
    let record: SnapshotRecord = from_canonical_cbor(&record_bytes)?;
    ciphervault_recovery::trust::verify_snapshot(&record, &head, &certificate)?;
    ensure!(
        record.snapshot_id == set.closure.snapshot_id
            && record.encrypted_manifest_cid == set.closure.manifest_cid,
        "Remote snapshot does not match recovery inventory"
    );
    let manifest_cid: [u8; 32] = record
        .encrypted_manifest_cid
        .as_slice()
        .try_into()
        .context("Invalid manifest CID")?;
    ensure!(
        record.encrypted_manifest_len <= 16 * 1024 * 1024,
        "Recovery manifest exceeds 16 MiB bound"
    );
    let encrypted_manifest = fetch_verified(&sessions, &manifest_cid).await?;
    ensure!(
        encrypted_manifest.len() as u64 == record.encrypted_manifest_len,
        "Manifest wire length mismatch"
    );
    let epoch_key = store
        .get_epoch_key(record.epoch)
        .context("Historical epoch key unavailable for recovery drill")?;
    let manifest_key = Zeroizing::new(epoch_key.derive_manifest_key(record.epoch)?);
    let aad = [
        b"CipherVault-Manifest:".as_slice(),
        vault.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let plaintext_manifest = Zeroizing::new(ciphervault_crypto::decrypt_chunk(
        &manifest_key,
        &encrypted_manifest,
        &aad,
    )?);
    let manifest: SnapshotManifest = from_canonical_cbor(&plaintext_manifest)?;
    ensure!(
        manifest.snapshot_id == record.snapshot_id
            && manifest.vault_id == vault
            && manifest.epoch == record.epoch
            && manifest.version == ciphervault_format::PROTOCOL_VERSION,
        "Manifest snapshot/version/vault/epoch binding mismatch"
    );
    let (raw_bytes, padded_bytes) = manifest
        .files
        .iter()
        .filter(|file| !file.is_deleted)
        .try_fold((0u64, 0u64), |(raw, padded), file| -> Result<_> {
            Ok((
                raw.checked_add(file.raw_length)
                    .context("Manifest raw length overflow")?,
                padded
                    .checked_add(file.padded_length)
                    .context("Manifest padded length overflow")?,
            ))
        })?;
    ensure!(
        raw_bytes == set.closure.total_bytes && padded_bytes <= 1024 * 1024 * 1024,
        "Manifest lengths exceed the signed inventory or 1 GiB in-memory drill bound"
    );
    let needed: BTreeSet<[u8; 32]> = manifest
        .files
        .iter()
        .filter(|file| !file.is_deleted)
        .flat_map(|file| &file.chunk_cids)
        .map(|cid| {
            cid.as_slice()
                .try_into()
                .context("Invalid manifest chunk CID")
        })
        .collect::<Result<_>>()?;
    let inventory_chunks: BTreeSet<[u8; 32]> = set
        .closure
        .chunk_cids
        .iter()
        .map(|cid| {
            cid.as_slice()
                .try_into()
                .context("Invalid inventory chunk CID")
        })
        .collect::<Result<_>>()?;
    ensure!(
        needed == inventory_chunks,
        "Manifest and recovery inventory chunk sets differ"
    );
    let mut verified_objects = BTreeSet::from([record_cid, manifest_cid]);
    let mut chunks = Vec::with_capacity(needed.len());
    for cid in needed {
        let bytes = fetch_verified(&sessions, &cid).await?;
        let chunk: ChunkWireObject = from_canonical_cbor(&bytes)?;
        chunks.push(chunk);
        verified_objects.insert(cid);
    }
    let bootstrap_ids: BTreeSet<[u8; 32]> = set
        .records
        .iter()
        .map(|record| compute_digest(record))
        .collect();
    let inventory_bootstrap: BTreeSet<[u8; 32]> = set
        .closure
        .envelope_ids
        .iter()
        .map(|cid| cid.as_slice().try_into().context("Invalid bootstrap CID"))
        .collect::<Result<_>>()?;
    ensure!(
        bootstrap_ids == inventory_bootstrap,
        "Bootstrap recovery inventory mismatch"
    );
    for cid in bootstrap_ids {
        fetch_verified(&sessions, &cid).await?;
        verified_objects.insert(cid);
    }
    let files = ciphervault_snapshot::decrypt_snapshot(
        &vault,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    )?;
    let bytes: u64 = files.iter().map(|file| file.plaintext.len() as u64).sum();
    ensure!(
        bytes == set.closure.total_bytes,
        "Recovered plaintext byte count differs from signed inventory"
    );
    let report = RecoveryDrillReport {
        verification: "remote_plaintext_reconstruction",
        snapshot_record_cid: hex::encode(record_cid),
        epoch: record.epoch,
        files_verified: files.len(),
        plaintext_bytes_verified: bytes,
        remote_objects_verified: verified_objects.len(),
        independently_pinned_operators_authenticated: sessions.len(),
        plaintext_written: false,
        key_source: "local_historical_epoch_key",
    };
    // DecryptedFile and manifest key owners wipe sensitive buffers on drop.
    drop(files);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
    use ciphervault_format::{DeviceCertificate, GenesisRecord, HeadRecord, PROTOCOL_VERSION};
    use ciphervault_operator::{create_router, state::OperatorSecurityConfig, OperatorState};
    use ciphervault_snapshot::{create_snapshot_with_write_version, ChunkWriteVersion};
    use std::{fs, path::PathBuf, sync::Arc};

    #[test]
    fn explicit_operator_pins_are_strict_and_endpoint_normalized() {
        let mut pins = BTreeMap::new();
        assert!(merge_pins(&mut pins, &["http://127.0.0.1:1=short".into()]).is_err());
        assert!(merge_pins(&mut pins, &[format!("={}", "ab".repeat(32))]).is_err());
        merge_pins(
            &mut pins,
            &[format!("http://127.0.0.1:1/={}", "ab".repeat(32))],
        )
        .unwrap();
        assert_eq!(pins["http://127.0.0.1:1"], [0xab; 32]);
    }

    #[tokio::test]
    async fn real_pinned_operator_drill_decrypts_historical_epoch_and_rejects_loss_or_corruption() {
        let root = std::env::temp_dir().join(format!(
            "cv-plaintext-drill-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir_all(&root).unwrap();
        // macOS exposes its temporary directory through /var -> /private/var.
        // Resolve this fixture-owned root before invoking strict capture checks.
        let root = fs::canonicalize(root).unwrap();
        let recovery = RecoverySecret::generate();
        let root_key = recovery.derive_recovery_signing_key().unwrap();
        let (_, recovery_enc_pk) = recovery.derive_recovery_encryption_keys().unwrap();
        let vault = [61; 32];
        let device = [62; 32];
        let signer = generate_signing_key();
        let epoch_key = VaultEpochKey::generate();
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault.to_vec(),
            recovery_signing_pk: root_key.verifying_key().to_bytes().to_vec(),
            recovery_encryption_pk: recovery_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0; 32],
            created_at_utc: 1,
            creation_nonce: vec![0; 32],
            signature: vec![],
        };
        genesis.sign(&root_key).unwrap();
        let store = LocalVaultStore::open(root.join("vault.db")).unwrap();
        store
            .init_vault(
                &vault,
                &genesis,
                &signer,
                &device,
                &epoch_key,
                &recovery.derive_recovery_locator().unwrap(),
            )
            .unwrap();
        let mut certificate = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vault.to_vec(),
            certificate_id: vec![63; 32],
            device_signing_pk: signer.verifying_key().to_bytes().to_vec(),
            permissions: 1,
            authority_generation: 1,
            issued_at_utc: 1,
            signature: vec![],
        };
        certificate.sign(&root_key).unwrap();
        store.save_device_certificate(&certificate).unwrap();
        let bytes = b"SYNTHETIC_DRILL_SECRET=only_in_memory\n";
        fs::write(root.join("synthetic.env"), bytes).unwrap();
        let output = create_snapshot_with_write_version(
            &root,
            &[(PathBuf::from("synthetic.env"), [64; 32])],
            &vault,
            1,
            &epoch_key,
            vec![],
            &device,
            1,
            1,
            &signer,
            ChunkWriteVersion::V2,
        )
        .unwrap();
        store
            .save_snapshot(&output.record, &output.encrypted_manifest, &output.chunks)
            .unwrap();
        store.increment_device_counter().unwrap();
        let set = store.prepare_recovery_set(&output.record).unwrap();
        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault.to_vec(),
            snapshot_id: output.record.compute_record_cid().unwrap().to_vec(),
            parent_snapshot_ids: vec![],
            closure_digest: set.closure.compute_base_closure_digest().unwrap().to_vec(),
            device_id: device.to_vec(),
            device_counter: 1,
            signature: vec![],
        };
        head.sign(&signer).unwrap();
        store.set_head(&head).unwrap();
        // Active snapshot still belongs to epoch 1 although current epoch is 2.
        store.rotate_epoch_key().unwrap();
        let operator_key = generate_signing_key();
        let operator_pk = operator_key.verifying_key().to_bytes();
        let state = Arc::new(OperatorState::new_with_security(
            "plaintext-drill".into(),
            root.join("operator"),
            operator_key,
            OperatorSecurityConfig {
                strict_auth: true,
                require_enrollment: true,
            },
        ));
        state
            .enroll_identity(
                &hex::encode(vault),
                &hex::encode(signer.verifying_key().to_bytes()),
                ciphervault_operator::state::PERMISSION_VAULT_DEFAULT,
            )
            .unwrap();
        for (cid, object) in store.recovery_objects(&set).unwrap() {
            state.put_object(&hex::encode(cid), &object).unwrap();
        }
        let locator = hex::encode(set.locator);
        for record in &set.records {
            state.append_recovery_record(&locator, record).unwrap();
        }
        state
            .append_recovery_record(&locator, &to_canonical_cbor(&head).unwrap())
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = create_router(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = OperatorClient::new_pinned(endpoint.clone(), operator_pk);
        let read_only = LocalVaultStore::open_read_only(root.join("vault.db")).unwrap();
        let pending_before = store.list_pending_uploads().unwrap();
        let activity_before = store.list_activity(100).unwrap().len();
        let report = verify_plaintext_recovery(&read_only, &[(client.clone(), operator_pk)])
            .await
            .unwrap();
        assert_eq!(report.files_verified, 1);
        assert_eq!(report.plaintext_bytes_verified, bytes.len() as u64);
        assert_eq!(report.epoch, 1);
        assert!(!report.plaintext_written);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("only_in_memory"));
        let cid = output.chunks[0].compute_cid().unwrap();
        let remote_path = root.join("operator/objects").join(hex::encode(cid));
        fs::write(&remote_path, b"corrupted operator object").unwrap();
        assert!(
            verify_plaintext_recovery(&read_only, &[(client.clone(), operator_pk)])
                .await
                .unwrap_err()
                .to_string()
                .contains("integrity-checked remote object")
        );
        fs::remove_file(remote_path).unwrap();
        assert!(
            verify_plaintext_recovery(&read_only, &[(client, operator_pk)])
                .await
                .is_err(),
            "Local cached ciphertext must never conceal remote object loss"
        );
        let wrong_key = [77; 32];
        let untrusted = OperatorClient::new_pinned(endpoint, wrong_key);
        assert!(
            verify_plaintext_recovery(&read_only, &[(untrusted, wrong_key)])
                .await
                .is_err()
        );
        assert!(verify_plaintext_recovery(&read_only, &[]).await.is_err());
        assert_eq!(store.list_pending_uploads().unwrap(), pending_before);
        assert_eq!(store.list_activity(100).unwrap().len(), activity_before);
        assert_eq!(store.get_active_head().unwrap().unwrap(), head);
        assert_eq!(store.get_device_state().unwrap().2, 1);
        assert_eq!(fs::read(root.join("synthetic.env")).unwrap(), bytes);
        assert!(!root.join(".ciphervault-restore").exists());
        server.abort();
        let _ = server.await;
        drop(read_only);
        drop(store);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }
}
