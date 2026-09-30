//! Restore and pull commands.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::io::IsTerminal;
use std::path::PathBuf;
use zeroize::Zeroizing;

use ciphervault_format::{from_canonical_cbor, ChunkWireObject, SnapshotManifest, SnapshotRecord};
use ciphervault_snapshot::{decrypt_snapshot, restore_snapshot};

use crate::util::{
    configured_operator_pool, get_configured_operators, get_vault_store, resolve_hardware_token,
};

pub(crate) fn cmd_restore(
    snapshot_hex_opt: Option<String>,
    to_dir_opt: Option<PathBuf>,
    hardware_token: bool,
    reader_opt: Option<String>,
    pin_opt: Option<String>,
    dry_run: bool,
) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, _) = store.get_device_state()?;

    let certs = store.list_device_certificates()?;
    let is_hardware_bound = certs
        .first()
        .map(|c| c.device_signing_pk != device_sk.verifying_key().to_bytes())
        .unwrap_or(false);

    if hardware_token || is_hardware_bound {
        println!("{}", "Hardware Token Authentication:".bold().cyan());
        let token = resolve_hardware_token(
            reader_opt.as_deref(),
            pin_opt.as_deref(),
            !std::io::stdin().is_terminal(),
        )?;
        println!(
            "  ✓ Hardware Key Verified: {} (Slot 9C/9D authenticated)",
            token.reader_name().green()
        );
    }

    let root = crate::util::get_workspace_root()?;
    let target_dir = match to_dir_opt {
        Some(path) if path.is_absolute() => path,
        Some(path) => root.join(path),
        None => root,
    };

    let snapshot_id = match snapshot_hex_opt {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim())?;
            if bytes.len() != 32 {
                bail!("Snapshot ID must be 32 bytes hex string (64 characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            let head = store
                .get_active_head()?
                .context("No active head snapshot found to restore")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

    println!(
        "Restoring snapshot {} into '{}'...",
        hex::encode(snapshot_id).yellow(),
        target_dir.display()
    );

    let (record, encrypted_manifest) = store.get_snapshot(&snapshot_id)?;
    crate::util::verify_local_snapshot_record(&store, &record)?;
    let epoch_key = store.get_epoch_key(record.epoch).with_context(|| {
        format!(
            "Epoch {} key is required to restore this snapshot",
            record.epoch
        )
    })?;

    let manifest_key = Zeroizing::new(epoch_key.derive_manifest_key(record.epoch)?);
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes = Zeroizing::new(ciphervault_crypto::decrypt_chunk(
        &manifest_key,
        &encrypted_manifest,
        &aad,
    )?);
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;

    let mut needed_cids = Vec::new();
    for file in &manifest.files {
        for cid_bytes in &file.chunk_cids {
            let arr: [u8; 32] = cid_bytes
                .as_slice()
                .try_into()
                .context("Invalid manifest chunk CID")?;
            needed_cids.push(arr);
        }
    }
    needed_cids.sort();
    needed_cids.dedup();

    let chunks = store.get_chunks(&needed_cids)?;
    if chunks.len() != needed_cids.len() {
        bail!(
            "Missing chunks in local store (required {}, found {})",
            needed_cids.len(),
            chunks.len()
        );
    }

    if dry_run {
        let files = decrypt_snapshot(
            &vault_id,
            &epoch_key,
            record.epoch,
            &encrypted_manifest,
            &chunks,
        )?;
        println!("Verified restore preview (merge mode; unrelated files are retained):");
        for file in files {
            let destination = target_dir.join(&file.relative_path);
            let action = match std::fs::symlink_metadata(&destination) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => "create",
                Err(error) => return Err(error).context("Inspecting restore destination"),
                Ok(_) => {
                    let previous = read_current_file(&destination)?;
                    if previous.as_slice() == file.plaintext.as_slice() {
                        "unchanged"
                    } else {
                        "replace"
                    }
                }
            };
            println!(
                "  {action}: {} ({} bytes)",
                file.relative_path,
                file.plaintext.len()
            );
        }
        return Ok(());
    }

    let restored = restore_snapshot(
        &target_dir,
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    )?;

    println!(
        "{}",
        "✓ Snapshot restored and verified successfully!"
            .bold()
            .green()
    );
    for p in restored {
        println!("  - Restored: {}", p.display().to_string().cyan());
    }

    Ok(())
}

pub(crate) async fn cmd_pull(dry_run: bool, force: bool) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (recovery_signing_pk, _, locator) = store.get_recovery_descriptors()?;

    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured. Cannot pull from remote federation.");
    }

    println!(
        "Connecting to {} independent storage operator(s)...",
        operators.len()
    );
    let pool = configured_operator_pool(operators);

    let raw_records = pool.query_recovery_records(&locator).await;
    if raw_records.is_empty() {
        bail!("No recovery records found on any surviving operator for this vault locator.");
    }

    let (chosen_head, certificate) =
        ciphervault_recovery::trust::select_head(&raw_records, &vault_id, &recovery_signing_pk)?;

    let local_head = store.get_active_head()?;
    if let Some(lh) = &local_head {
        let any_missing = store
            .list_tracked_files()
            .unwrap_or_default()
            .iter()
            .any(|(p, _)| {
                crate::util::get_workspace_root()
                    .map(|root| !root.join(p).exists())
                    .unwrap_or(true)
            });
        if lh.snapshot_id == chosen_head.snapshot_id && !force && !any_missing {
            println!(
                "{}",
                format!(
                    "✓ Already up to date with operator cluster (Head: {})",
                    hex::encode(&lh.snapshot_id)[..12].yellow()
                )
                .green()
            );
            return Ok(());
        }
    }

    let mut snap_cid = [0u8; 32];
    snap_cid.copy_from_slice(&chosen_head.snapshot_id);

    if let Some(lh) = &local_head {
        if lh.snapshot_id == chosen_head.snapshot_id {
            println!(
                "Syncing confidential files from remote snapshot: {}",
                hex::encode(snap_cid)[..12].yellow()
            );
        } else {
            println!(
                "Found newer remote snapshot: {}",
                hex::encode(snap_cid)[..12].yellow()
            );
        }
    } else {
        println!(
            "Found remote snapshot: {}",
            hex::encode(snap_cid)[..12].yellow()
        );
    }

    if dry_run {
        println!(
            "{}",
            "✓ Dry run complete: updates are available from operators. Run 'ciphervault pull' to apply."
                .green()
        );
        return Ok(());
    }

    // Safety guard against uncommitted local modifications unless --force
    if !force {
        let tracked = store.list_tracked_files()?;
        let mut captured = std::collections::HashMap::new();
        if let Some(head) = store.get_active_head()? {
            let snapshot_id: [u8; 32] = head
                .snapshot_id
                .as_slice()
                .try_into()
                .context("Invalid local snapshot head")?;
            let (previous, encrypted) = store.get_snapshot(&snapshot_id)?;
            let previous_key = store.get_epoch_key(previous.epoch)?;
            let aad = [
                b"CipherVault-Manifest:",
                vault_id.as_slice(),
                &previous.epoch.to_le_bytes(),
            ]
            .concat();
            let plaintext = zeroize::Zeroizing::new(ciphervault_crypto::decrypt_chunk(
                &previous_key.derive_manifest_key(previous.epoch)?,
                &encrypted,
                &aad,
            )?);
            let manifest: SnapshotManifest = from_canonical_cbor(&plaintext)?;
            for file in &manifest.files {
                if !file.is_deleted {
                    captured.insert(file.relative_path.clone(), file.plaintext_sha256.clone());
                }
            }
        }
        let root = crate::util::get_workspace_root()?;
        let mut dirty_files = Vec::new();
        for (rel_path, _) in &tracked {
            let full_path = root.join(rel_path);
            if full_path.exists() {
                {
                    let bytes = read_current_file(&full_path).with_context(|| {
                        format!(
                            "Cannot check local changes in {}; refusing to overwrite",
                            rel_path.display()
                        )
                    })?;
                    use sha2::Digest;
                    let cur_hash = sha2::Sha256::digest(&bytes);
                    if !captured
                        .get(&rel_path.to_string_lossy().replace('\\', "/"))
                        .is_some_and(|hash| cur_hash.as_slice() == hash.as_slice())
                    {
                        dirty_files.push(rel_path.display().to_string());
                    }
                }
            } else if captured.contains_key(&rel_path.to_string_lossy().replace('\\', "/")) {
                dirty_files.push(rel_path.display().to_string());
            }
        }
        if !dirty_files.is_empty() {
            bail!(
                "Local tracked file(s) have uncommitted modifications: {}\nCommit changes with 'ciphervault push' or discard with 'ciphervault pull --force'",
                dirty_files.join(", ")
            );
        }
    }

    // Fetch and authenticate snapshot record object
    let snap_record_bytes = pool.fetch_object_from_any(&snap_cid).await?;
    let record: SnapshotRecord = from_canonical_cbor(&snap_record_bytes)?;
    ciphervault_recovery::trust::verify_snapshot(&record, &chosen_head, &certificate)?;
    let epoch_key = store.get_epoch_key(record.epoch).with_context(|| {
        format!(
            "Epoch {} key is required to pull this snapshot",
            record.epoch
        )
    })?;

    // Fetch encrypted manifest
    let mut manifest_cid = [0u8; 32];
    manifest_cid.copy_from_slice(&record.encrypted_manifest_cid);
    let encrypted_manifest = pool.fetch_object_from_any(&manifest_cid).await?;

    let manifest_key = Zeroizing::new(epoch_key.derive_manifest_key(record.epoch)?);
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes = Zeroizing::new(ciphervault_crypto::decrypt_chunk(
        &manifest_key,
        &encrypted_manifest,
        &aad,
    )?);
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;

    // Download any missing chunk objects from operators
    let mut all_chunks = Vec::new();
    let mut missing_cids = Vec::new();

    for file in &manifest.files {
        if file.is_deleted {
            continue;
        }
        for cid_bytes in &file.chunk_cids {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(cid_bytes);
            missing_cids.push(arr);
        }
    }
    missing_cids.sort();
    missing_cids.dedup();

    let local_chunks = store.get_chunks(&missing_cids).unwrap_or_default();
    let local_chunk_map: std::collections::HashMap<[u8; 32], ChunkWireObject> = local_chunks
        .into_iter()
        .filter_map(|c| c.compute_cid().ok().map(|cid| (cid, c)))
        .collect();

    for cid in &missing_cids {
        if let Some(local_c) = local_chunk_map.get(cid) {
            all_chunks.push(local_c.clone());
        } else {
            let chunk_bytes = pool.fetch_object_from_any(cid).await?;
            let chunk: ChunkWireObject = from_canonical_cbor(&chunk_bytes)?;
            all_chunks.push(chunk);
        }
    }

    // Atomically restore the updated files into the current workspace
    println!("Applying updated confidential files into workspace...");
    let restored = restore_snapshot(
        &crate::util::get_workspace_root()?,
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &all_chunks,
    )?;

    // Ensure pulled files are tracked in local store
    for file in &manifest.files {
        if !file.is_deleted {
            let _ = store.track_file(&file.relative_path);
        }
    }

    // Persist snapshot record, encrypted manifest, and chunks in local database
    store.save_snapshot(&record, &encrypted_manifest, &all_chunks)?;

    // Advance local head to the verified remote head
    store.set_head(&chosen_head)?;

    println!(
        "{}",
        format!(
            "✓ Successfully synchronized with operator cluster (Head: {})",
            hex::encode(snap_cid)[..12].yellow()
        )
        .bold()
        .green()
    );
    for p in restored {
        println!("  - Updated: {}", p.display().to_string().cyan());
    }

    Ok(())
}

fn read_current_file(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let file = ciphervault_file_lock::open_regular_file(path)?;
    anyhow::ensure!(
        file.metadata()?.len() <= ciphervault_snapshot::MAX_FILE_SIZE,
        "Existing file exceeds the supported size limit"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(ciphervault_snapshot::MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= ciphervault_snapshot::MAX_FILE_SIZE,
        "Existing file grew beyond the supported size limit"
    );
    Ok(bytes)
}
