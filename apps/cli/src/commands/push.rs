//! Snapshot push command.

use anyhow::{bail, Context, Result};
use ciphervault_crypto::HardwareSecurityModule;
use colored::Colorize;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use ciphervault_format::{to_canonical_cbor, HeadRecord, HEAD_RECORD_VERSION_V2};
use ciphervault_snapshot::{create_snapshot, create_snapshot_with_signer, DeviceSigner};

use crate::cmd_anchor;
use crate::util::{
    configured_operator_pool, get_vault_store, load_configured_operators, resolve_hardware_token,
    resolve_required_replicas,
};

#[allow(
    clippy::too_many_arguments,
    reason = "One arg per push flag; matches the existing CLI plumbing style"
)]
pub(crate) async fn cmd_push(
    message: Option<String>,
    touch: bool,
    local: bool,
    anchor: bool,
    reader: Option<String>,
    pin: Option<String>,
    concurrency: Option<usize>,
    replicas: Option<usize>,
    shred: bool,
) -> Result<()> {
    let store = get_vault_store()?;
    let shred = resolve_push_shred(shred, &crate::util::get_vault_directory())?;
    let vault_id = store.get_vault_id()?;
    let (device_id, device_sk, counter, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;
    let tracked = store.list_tracked_files()?;

    if tracked.is_empty() {
        bail!(
            "No files are tracked. Track files using '{}' before pushing.",
            "ciphervault track <path>".cyan()
        );
    }

    let active_head = store.get_active_head()?;
    let parent_ids = match active_head {
        Some(ref h) => vec![{
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h.snapshot_id);
            arr
        }],
        None => Vec::new(),
    };

    let certs = store.list_device_certificates()?;
    let is_hardware_bound = !certs
        .iter()
        .any(|certificate| certificate.device_signing_pk == device_sk.verifying_key().to_bytes());

    let maybe_token = if touch || is_hardware_bound {
        if touch {
            println!(
                "{}",
                "Hardware Touch Presence Authorization (--touch):"
                    .bold()
                    .yellow()
            );
            println!(
                "  Please tap your physical YubiKey / hardware token to sign snapshot commit..."
            );
        } else {
            println!("{}", "Hardware-Bound Vault Signing Ceremony:".bold().cyan());
            println!(
                "  Using physical YubiKey / hardware token (Slot 9C) for snapshot signature..."
            );
        }
        let token = resolve_hardware_token(reader.as_deref(), pin.as_deref(), false)?;
        println!("  Found token on reader: {}", token.reader_name().cyan());
        Some(token)
    } else {
        None
    };

    let signing_key: [u8; 32] = match &maybe_token {
        Some(token) => token
            .get_public_key(ciphervault_crypto::HsmSlot::DigitalSignature)?
            .as_slice()
            .try_into()
            .context("Hardware signing key must be Ed25519")?,
        None => device_sk.verifying_key().to_bytes(),
    };
    let (recovery_root, _, _) = store.get_recovery_descriptors()?;
    let authority_generation = certs
        .iter()
        .filter(|certificate| {
            certificate.vault_id == vault_id
                && certificate.device_signing_pk == signing_key
                && certificate.permissions & 1 != 0
                && certificate.verify(&recovery_root).is_ok()
        })
        .map(|certificate| certificate.authority_generation)
        .max()
        .context("No trusted signing authority; local snapshot state was not advanced")?;
    store.validate_capture_authority_for_key(&signing_key, authority_generation)?;

    let current_dir = crate::util::get_workspace_root()?;
    let missing_on_disk: Vec<PathBuf> = tracked
        .iter()
        .filter(|(rel, _)| !current_dir.join(rel).exists())
        .map(|(rel, _)| rel.clone())
        .collect();

    let mut temp_restored: Vec<(PathBuf, [u8; 32])> = Vec::new();
    if !missing_on_disk.is_empty() && active_head.is_some() {
        if let Ok(mut bundle) = crate::commands::run::load_local_snapshot_bundle_sync(&store) {
            let mut restorable_indices: Vec<(PathBuf, [u8; 32], usize)> = Vec::new();
            for (rel, fid) in &tracked {
                let norm = rel.to_string_lossy().replace('\\', "/");
                if !current_dir.join(rel).exists() {
                    if let Some(idx) = bundle
                        .files
                        .iter()
                        .position(|f| f.relative_path.replace('\\', "/") == norm)
                    {
                        restorable_indices.push((rel.clone(), *fid, idx));
                    }
                }
            }
            if missing_on_disk.len() == tracked.len() && restorable_indices.len() == tracked.len() {
                for f in &mut bundle.files {
                    f.plaintext.zeroize();
                }
                if shred {
                    println!(
                        "{}",
                        "✓ Working tree is already sealed (0 plaintext bytes on disk); active head snapshot is up to date."
                            .bold()
                            .green()
                    );
                    return Ok(());
                }
                bail!(
                    "Tracked confidential files are currently sealed in the vault (not on disk). \
                     Run 'ciphervault restore' before pushing new edits, or 'ciphervault untrack <file>' to remove a file."
                );
            }
            for (rel, fid, idx) in restorable_indices {
                let full = current_dir.join(&rel);
                if let Some(parent) = full.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut f = ciphervault_file_lock::create_secret_file(&full)?;
                f.write_all(&bundle.files[idx].plaintext)?;
                f.sync_all()?;
                temp_restored.push((rel, fid));
            }
            for f in &mut bundle.files {
                f.plaintext.zeroize();
            }
        }
    }

    println!("{}", "Capturing and encrypting snapshot...".bold());

    let snap_res = match &maybe_token {
        Some(token) => create_snapshot_with_signer(
            &current_dir,
            &tracked,
            &vault_id,
            epoch,
            &epoch_key,
            parent_ids.clone(),
            &device_id,
            counter + 1,
            authority_generation,
            &DeviceSigner::Hardware(token, ciphervault_crypto::HsmSlot::DigitalSignature),
        ),
        None => create_snapshot(
            &current_dir,
            &tracked,
            &vault_id,
            epoch,
            &epoch_key,
            parent_ids.clone(),
            &device_id,
            counter + 1,
            authority_generation,
            &device_sk,
        ),
    };
    if !temp_restored.is_empty() {
        let _ = shred_working_tree_files(&current_dir, &temp_restored);
    }
    let output = snap_res?;

    // Store snapshot and chunks in local transactional queue
    store.save_snapshot(&output.record, &output.encrypted_manifest, &output.chunks)?;
    store.increment_device_counter()?;

    let recovery_set = match &maybe_token {
        Some(token) => store.prepare_recovery_set_with_hsm(
            &output.record,
            token,
            ciphervault_crypto::HsmSlot::DigitalSignature,
        )?,
        None => store.prepare_recovery_set(&output.record)?,
    };
    let record_cid = output.record.compute_record_cid()?;

    // Create and sign updated HeadRecord v2 pointing to snapshot-record CID
    let mut head = HeadRecord {
        version: HEAD_RECORD_VERSION_V2,
        vault_id: vault_id.to_vec(),
        snapshot_id: record_cid.to_vec(),
        parent_snapshot_ids: output.record.parent_snapshot_ids.clone(),
        closure_digest: recovery_set.closure.compute_base_closure_digest()?.to_vec(),
        device_id: device_id.to_vec(),
        device_counter: counter + 1,
        authority_generation: Some(output.record.authority_generation),
        signature: Vec::new(),
    };

    if let Some(ref token) = maybe_token {
        head.sign_with_hsm(token, ciphervault_crypto::HsmSlot::DigitalSignature)?;
        if touch {
            println!(
                "  {}",
                "✓ Physical touch presence confirmed!".green().bold()
            );
        } else {
            println!(
                "  {}",
                "✓ Hardware token Slot 9C signature confirmed!"
                    .green()
                    .bold()
            );
        }
    } else {
        head.sign(&device_sk)?;
    }

    store.set_head(&head)?;

    let snapshot_hex = hex::encode(&output.record.snapshot_id);
    println!(
        "{}",
        "✓ Snapshot captured and encrypted locally!".bold().green()
    );
    println!("  Snapshot ID:    {}", snapshot_hex.yellow());
    println!("  Files captured: {}", tracked.len());
    println!("  Plaintext size: {} bytes", output.closure.total_bytes);
    println!("  Chunks created: {}", output.chunks.len());
    if let Some(msg) = message {
        println!("  Message:        \"{}\"", msg);
    }

    if local {
        if anchor {
            eprintln!(
                "{}",
                "WARNING: --anchor is ignored with --local (offline commit never reaches the ledger). Push without --local to anchor."
                    .yellow()
                    .bold()
            );
        }
        println!(
            "  Durability:     {} (offline / local-only commit)",
            "LocalOnly".yellow().bold()
        );
        if shred {
            let shredded = shred_working_tree_files(&current_dir, &tracked)?;
            println!(
                "  Working tree:   {} ({} tracked file(s) zero-filled and removed; 0 bytes on disk)",
                "Sealed".green().bold(),
                shredded
            );
        }
        return Ok(());
    }

    // Attempt multi-operator replication. Strict operator resolution: a
    // present-but-broken operators.json is a hard stop here, never a
    // silent fallback to the default fleet (U-H1).
    let operators = load_configured_operators()?;
    let required_replicas = resolve_required_replicas(replicas)?;
    if required_replicas > operators.len() {
        bail!(
            "--replicas {required_replicas} exceeds the {} configured operator(s); lower it or add endpoints (note: --local skips replication entirely)",
            operators.len()
        );
    }
    println!(
        "\nReplicating across {} independent operators...",
        operators.len()
    );

    let pool = configured_operator_pool(operators.clone());
    let trace_id = ciphervault_storage::client::OperatorClient::new_trace_id();
    pool.set_trace_id(&trace_id);
    if let Some(requested) = concurrency {
        if !(1..=ciphervault_storage::pool::MAX_OBJECT_CONCURRENCY).contains(&requested) {
            eprintln!(
                "warning: --concurrency {requested} out of range, clamped to 1-{}",
                ciphervault_storage::pool::MAX_OBJECT_CONCURRENCY
            );
        }
        pool.set_object_concurrency(requested);
    }

    let wire_objects = store.recovery_objects(&recovery_set)?;
    let head_cbor = to_canonical_cbor(&head)?;
    let closure_digest = recovery_set.closure.compute_base_closure_digest()?;
    let replication_started = std::time::Instant::now();
    let rep_result = pool
        .replicate_and_verify_with_endpoints(
            &vault_id,
            &device_sk,
            &wire_objects,
            &closure_digest,
            output.closure.total_bytes,
            90, // 90-day retention
            &recovery_set.locator,
            &head_cbor,
            &recovery_set.records,
            required_replicas,
        )
        .await;

    match rep_result {
        Ok(issued) => {
            record_replication_receipts(&store, &issued);
            let snapshot_id: [u8; 32] = output
                .record
                .snapshot_id
                .as_slice()
                .try_into()
                .context("Snapshot ID must be 32 bytes")?;
            match finish_remote_push(&store, &snapshot_id, issued.len(), required_replicas) {
                Ok(Some(0)) => {}
                Ok(Some(cleared)) => {
                    println!(
                        "  Upload queue:   cleared {cleared} older local-only snapshot(s) superseded by this replicated head"
                    );
                    let _ = store.record_activity(
                        "UPLOAD_QUEUE_SUPERSEDED",
                        &format!("{cleared} queued local-only snapshot(s) superseded by a replicated head"),
                        &serde_json::json!({
                            "snapshot_id": hex::encode(snapshot_id),
                            "cleared": cleared,
                        })
                        .to_string(),
                    );
                }
                Ok(None) => eprintln!(
                    "warning: verified replicas did not meet the required threshold; snapshot remains queued"
                ),
                Err(e) => eprintln!(
                    "warning: could not clear the completed upload from the pending queue: {e}"
                ),
            }
            // Anchor the agent-audit head off-machine with the same
            // replication round (best-effort: never fail a good push).
            match crate::commands::anchor_agent_audit(&operators).await {
                Ok((confirmed, _cid, entries, head)) => {
                    println!(
                        "  Audit anchor:   {} entries, head {}… confirmed by {} operator(s)",
                        entries,
                        &head[..head.len().min(8)],
                        confirmed
                    );
                }
                Err(e) => {
                    println!("  Audit anchor:   skipped ({e})");
                }
            }
            let snapshot_hex = hex::encode(&output.record.snapshot_id);
            let _ = store.record_activity(
                "PUSH_OK",
                &format!("Push replicated snapshot {snapshot_hex}"),
                &serde_json::json!({
                    "snapshot_id": snapshot_hex,
                    "replicas": issued.len(),
                    "required_replicas": required_replicas,
                })
                .to_string(),
            );
            if issued.len() >= required_replicas {
                println!(
                    "  Durability:     {} ({}/{} independent replicas verified and read back)",
                    "RemoteDurable".green().bold(),
                    issued.len(),
                    operators.len()
                );
                println!("  Recovery checkpoint: {}", hex::encode(record_cid));
            } else {
                println!(
                    "  Durability:     {} ({}/{} replicas verified; degraded)",
                    "Degraded".yellow().bold(),
                    issued.len(),
                    operators.len()
                );
            }
            println!(
                "  Replication:    {:.2}s (trace {})",
                replication_started.elapsed().as_secs_f64(),
                trace_id
            );
        }
        Err(e) => {
            println!(
                "  Durability:     {} (Remote upload failed: {})",
                "Local only".yellow().bold(),
                e
            );
            if let ciphervault_storage::StorageError::QuorumDeficit { successful: 0, .. } = &e {
                println!(
                    "{}",
                    "  Hint:           0 operators accepted the upload. When the warnings \
                     above say 'not enrolled', this vault's device identity is unknown to \
                     the fleet (closed permissioned fleet: ask the fleet operator to \
                     enroll it, or point at your own operators). When they say 'connect \
                     failed' or 'timeout', check network access first."
                        .yellow()
                );
                println!(
                    "{}",
                    "  Next steps:     1) 'ciphervault push --local' saves this snapshot on this machine now. \
                     2) 'ciphervault doctor' checks operators and enrollment. \
                     3) To join a fleet, ask its operator to enroll this device (see 'ciphervault invite --help')."
                        .yellow()
                );
            }
            println!("  Trace ID:       {trace_id}");
            return Err(e.into());
        }
    }

    if anchor {
        println!(
            "{}",
            "Triggering automated post-push CipherChain anchoring...".cyan()
        );
        if let Err(e) = cmd_anchor(None, None).await {
            eprintln!("{}: {}", "Notice: Post-push anchoring failed".yellow(), e);
        }
    }

    if shred {
        let shredded = shred_working_tree_files(&current_dir, &tracked)?;
        println!(
            "  Working tree:   {} ({} tracked file(s) zero-filled and removed; 0 bytes on disk)",
            "Sealed".green().bold(),
            shredded
        );
    }

    Ok(())
}

pub(crate) fn resolve_push_shred(shred_flag: bool, vault_dir: &Path) -> Result<bool> {
    if shred_flag {
        return Ok(true);
    }
    Ok(crate::commands::run::load_workspace_policy(vault_dir)?
        .is_some_and(|policy| policy.sealed_mode))
}

/// Zero-fills and removes tracked plaintext working-tree files so confidential
/// values live only encrypted in `.ciphervault/vault.db` (and on operators).
pub(crate) fn shred_working_tree_files(
    root: &Path,
    tracked: &[(PathBuf, [u8; 32])],
) -> Result<usize> {
    let mut shredded = 0usize;
    let zeros = [0u8; 64 * 1024];
    for (rel_path, _) in tracked {
        let full = root.join(rel_path);
        let meta = match std::fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("stat '{}'", rel_path.display())),
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            bail!(
                "Refusing to shred non-regular/symlink tracked path '{}'",
                rel_path.display()
            );
        }
        let len = meta.len();
        if len > 0 {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&full) {
                let mut remaining = len;
                while remaining > 0 {
                    let chunk = (remaining as usize).min(zeros.len());
                    f.write_all(&zeros[..chunk])?;
                    remaining -= chunk as u64;
                }
                let _ = f.sync_all();
            }
        }
        std::fs::remove_file(&full)
            .with_context(|| format!("remove shredded tracked file '{}'", rel_path.display()))?;
        shredded += 1;
    }
    Ok(shredded)
}

/// Clears a snapshot from the pending-upload queue once the required
/// number of independent operators has verified its replica set, together
/// with the queued ancestors that replicated head supersedes (each local
/// push queues an upload; replicating an older snapshot after this one
/// would republish a stale head). `None`: threshold not met, nothing
/// cleared; `Some(n)`: completed, plus `n` superseded uploads cleared.
fn finish_remote_push(
    store: &ciphervault_local_store::LocalVaultStore,
    snapshot_id: &[u8; 32],
    verified_replicas: usize,
    required_replicas: usize,
) -> Result<Option<usize>> {
    if verified_replicas < required_replicas {
        return Ok(None);
    }
    store.mark_upload_completed(snapshot_id)?;
    Ok(Some(store.supersede_pending_ancestors(snapshot_id)?))
}

/// Files replication receipts (push, repair) into the local lease receipt
/// log so `status --overview` shows them without a `lease list` round-trip.
/// A log failure warns instead of failing the command: the data is safe on
/// the operators and `lease list` backfills the log. Returns the count filed.
pub(crate) fn record_replication_receipts(
    store: &ciphervault_local_store::LocalVaultStore,
    issued: &[(String, ciphervault_storage::LeaseReceipt)],
) -> usize {
    let mut recorded = 0;
    for (endpoint, receipt) in issued {
        if let Err(e) = store.record_lease_receipt(
            &receipt.lease_id,
            endpoint,
            &receipt.closure_digest_hex,
            receipt.term_days,
            receipt.bytes,
            receipt.issued_at_utc,
            receipt.expires_at_utc,
            &receipt.signature_hex,
        ) {
            eprintln!(
                "warning: lease receipt log failed for {}: {e}; run `lease list` to backfill",
                receipt.lease_id
            );
            continue;
        }
        recorded += 1;
    }
    recorded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push-time receipt filing maps every field to the right column:
    /// distinct values per field catch transposition, and re-filing the
    /// same receipts is idempotent (INSERT OR REPLACE).
    #[test]
    fn replication_receipts_file_with_exact_fields() {
        let store = ciphervault_local_store::LocalVaultStore::open(":memory:").unwrap();
        let receipt = ciphervault_storage::LeaseReceipt {
            lease_id: "push-lease-1".to_string(),
            operator_id: "op-1".to_string(),
            closure_digest_hex: "cc".to_string(),
            term_days: 90,
            bytes: 30,
            issued_at_utc: 1000,
            expires_at_utc: 2000,
            signature_hex: "sig".to_string(),
        };
        let issued = vec![("https://op1.test".to_string(), receipt)];
        assert_eq!(record_replication_receipts(&store, &issued), 1);
        assert_eq!(record_replication_receipts(&store, &issued), 1);
        let rows = store.list_lease_receipts().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.lease_id, "push-lease-1");
        assert_eq!(row.operator_endpoint, "https://op1.test");
        assert_eq!(row.closure_digest_hex, "cc");
        assert_eq!(row.term_days, 90);
        assert_eq!(row.bytes, 30);
        assert_eq!(row.issued_at_utc, 1000);
        assert_eq!(row.expires_at_utc, 2000);
        assert_eq!(row.signature_hex, "sig");
    }

    #[test]
    fn verified_remote_push_clears_its_pending_upload() {
        let store = ciphervault_local_store::LocalVaultStore::open(":memory:").unwrap();
        let snapshot_id = [0x5Au8; 32];
        let record = ciphervault_format::SnapshotRecord {
            version: ciphervault_format::PROTOCOL_VERSION,
            vault_id: vec![0x11u8; 32],
            snapshot_id: snapshot_id.to_vec(),
            parent_snapshot_ids: Vec::new(),
            device_id: vec![0x33u8; 32],
            device_counter: 1,
            authority_generation: 1,
            epoch: 1,
            encrypted_manifest_cid: vec![0x22u8; 32],
            encrypted_manifest_len: 4,
            advisory_timestamp_utc: 1_700_000_000,
            signature: Vec::new(),
        };
        store.save_snapshot(&record, b"manifest", &[]).unwrap();
        assert_eq!(store.list_pending_uploads().unwrap().len(), 1);

        assert_eq!(
            finish_remote_push(&store, &snapshot_id, 3, 3).unwrap(),
            Some(0)
        );
        assert!(store.list_pending_uploads().unwrap().is_empty());
    }

    #[test]
    fn verified_remote_push_also_clears_superseded_local_snapshots() {
        // Local pushes (the Hermes plugin's default) queue a pending
        // upload each; a later replicated head supersedes them.
        let store = ciphervault_local_store::LocalVaultStore::open(":memory:").unwrap();
        let mut parent: Option<[u8; 32]> = None;
        for (i, id) in [0x61u8, 0x62, 0x63].into_iter().enumerate() {
            let record = ciphervault_format::SnapshotRecord {
                version: ciphervault_format::PROTOCOL_VERSION,
                vault_id: vec![0x11u8; 32],
                snapshot_id: vec![id; 32],
                parent_snapshot_ids: parent.iter().map(|p| p.to_vec()).collect(),
                device_id: vec![0x33u8; 32],
                device_counter: i as u64 + 1,
                authority_generation: 1,
                epoch: 1,
                encrypted_manifest_cid: vec![0x22u8; 32],
                encrypted_manifest_len: 4,
                advisory_timestamp_utc: 1_700_000_000 + i as u64,
                signature: Vec::new(),
            };
            store.save_snapshot(&record, b"manifest", &[]).unwrap();
            parent = Some([id; 32]);
        }
        assert_eq!(store.list_pending_uploads().unwrap().len(), 3);
        assert_eq!(finish_remote_push(&store, &[0x63; 32], 2, 3).unwrap(), None);
        assert_eq!(store.list_pending_uploads().unwrap().len(), 3);
        assert_eq!(
            finish_remote_push(&store, &[0x63; 32], 3, 3).unwrap(),
            Some(2)
        );
        assert!(store.list_pending_uploads().unwrap().is_empty());
    }

    #[test]
    fn shred_working_tree_files_zero_fills_and_removes_regular_files() {
        let dir = std::env::temp_dir().join(format!("cv-shred-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        let sub_path = dir.join("sub/.env.prod");
        std::fs::create_dir_all(sub_path.parent().unwrap()).unwrap();
        std::fs::write(&env_path, b"API_KEY=secret_value_123456\n").unwrap();
        std::fs::write(&sub_path, b"DB_PASS=another_secret_987\n").unwrap();

        let tracked = vec![
            (PathBuf::from(".env"), [0x11u8; 32]),
            (PathBuf::from("sub/.env.prod"), [0x22u8; 32]),
            (PathBuf::from(".env.missing"), [0x33u8; 32]),
        ];
        let count = shred_working_tree_files(&dir, &tracked).unwrap();
        assert_eq!(count, 2);
        assert!(!env_path.exists());
        assert!(!sub_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_mode_auto_shreds_on_push() {
        let dir =
            std::env::temp_dir().join(format!("cv-sealed-push-test-{}", rand::random::<u64>()));
        let vault_dir = dir.join(".ciphervault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        let env_path = dir.join(".env");
        std::fs::write(&env_path, b"SECRET=sealed_value\n").unwrap();

        // No policy.toml -> false
        assert!(!resolve_push_shred(false, &vault_dir).unwrap());
        assert!(resolve_push_shred(true, &vault_dir).unwrap());

        // sealed_mode = false -> false
        std::fs::write(
            vault_dir.join("policy.toml"),
            "[vault]\nsealed_mode = false\n",
        )
        .unwrap();
        assert!(!resolve_push_shred(false, &vault_dir).unwrap());

        // sealed_mode = true -> true, and shreds tracked files
        std::fs::write(
            vault_dir.join("policy.toml"),
            "[vault]\nsealed_mode = true\n",
        )
        .unwrap();
        assert!(resolve_push_shred(false, &vault_dir).unwrap());

        let tracked = vec![(PathBuf::from(".env"), [0x44u8; 32])];
        if resolve_push_shred(false, &vault_dir).unwrap() {
            let count = shred_working_tree_files(&dir, &tracked).unwrap();
            assert_eq!(count, 1);
        }
        assert!(!env_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
