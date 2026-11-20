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

/// U-H8: shared dirty-working-file guard. Compares tracked working files
/// against the last captured snapshot head and bails listing the dirty
/// ones. Used by `pull` (remote) and `restore` (local) — both overwrite
/// working files, so both need the guard.
fn ensure_no_uncommitted_changes(
    store: &ciphervault_local_store::LocalVaultStore,
    vault_id: &[u8; 32],
) -> Result<()> {
    let dirty_files = uncommitted_tracked_changes(store, vault_id)?;
    if !dirty_files.is_empty() {
        bail!(
            "Local tracked file(s) have uncommitted modifications: {}\nCommit changes with 'ciphervault push' or discard with '--force'",
            dirty_files.join(", ")
        );
    }
    Ok(())
}

/// Tracked working files that differ from the active head (or that the head
/// captured and are now missing). A workspace restore refuses these unless
/// `--force` is given.
fn uncommitted_tracked_changes(
    store: &ciphervault_local_store::LocalVaultStore,
    vault_id: &[u8; 32],
) -> Result<Vec<String>> {
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
        let plaintext = Zeroizing::new(ciphervault_crypto::decrypt_chunk(
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
                if captured
                    .get(&rel_path.to_string_lossy().replace('\\', "/"))
                    .is_none_or(|hash| cur_hash.as_slice() != hash.as_slice())
                {
                    dirty_files.push(rel_path.display().to_string());
                }
            }
        } else if captured.contains_key(&rel_path.to_string_lossy().replace('\\', "/")) {
            dirty_files.push(rel_path.display().to_string());
        }
    }
    Ok(dirty_files)
}

pub(crate) fn cmd_restore(
    snapshot_hex_opt: Option<String>,
    to_dir_opt: Option<PathBuf>,
    hardware_token: bool,
    reader_opt: Option<String>,
    pin_opt: Option<String>,
    dry_run: bool,
    force: bool,
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
    let into_workspace = to_dir_opt.is_none();
    let target_dir = match &to_dir_opt {
        Some(path) if path.is_absolute() => path.clone(),
        Some(path) => root.join(path),
        None => root.clone(),
    };

    // U-H8: restoring into the workspace overwrites working files — same
    // guard as `pull`. A separate `--to` dir is out of the way; still
    // previewable with --dry-run.
    if into_workspace && !dry_run && !force {
        ensure_no_uncommitted_changes(&store, &vault_id)?;
    }

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

/// Exit status of a refused `restore --dry-run --json` preview. The JSON
/// report on stdout carries the machine-readable reason (`error_code`).
pub(crate) const RESTORE_PREVIEW_REFUSED_EXIT: i32 = 3;

#[derive(Debug, serde::Serialize)]
struct RestorePreviewFile {
    path: String,
    action: &'static str,
    bytes: u64,
}

#[derive(Debug, Default, serde::Serialize)]
struct RestorePreviewCounts {
    create: usize,
    replace: usize,
    unchanged: usize,
    total: usize,
}

#[derive(Debug, serde::Serialize)]
struct RestorePreviewVerification {
    status: &'static str,
    checks: Vec<&'static str>,
    checked_at_utc: u64,
}

/// Machine-readable restore preview. File paths are relative to the restore
/// target. Never carries plaintext, plaintext digests, or key material.
#[derive(Debug, serde::Serialize)]
struct RestorePreviewReport {
    success: bool,
    dry_run: bool,
    /// Record CID: the primary store key, the active-head ID, and the
    /// recovery checkpoint. Accepted by `restore --snapshot` and `diff`.
    snapshot_id: String,
    /// Logical snapshot ID printed by `push` and the text `history`; also
    /// accepted by `restore --snapshot` and `diff`.
    logical_id: String,
    is_active_head: bool,
    recorded_at_utc: Option<u64>,
    epoch: u64,
    destination: &'static str,
    mode: &'static str,
    verification: RestorePreviewVerification,
    files: Vec<RestorePreviewFile>,
    counts: RestorePreviewCounts,
    /// Tracked working files that differ from the active head. A workspace
    /// restore refuses them without `--force`. `null` when not checked.
    uncommitted_changes: Option<Vec<String>>,
    restore_requires_force: bool,
    interrupted_restore_pending: bool,
}

#[derive(Debug)]
struct RestorePreviewFailure {
    code: &'static str,
    check: Option<&'static str>,
    message: String,
}

impl RestorePreviewFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            check: None,
            message: message.into(),
        }
    }

    fn check(check: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: "verification_failed",
            check: Some(check),
            message: message.into(),
        }
    }

    fn store(error: impl std::fmt::Display) -> Self {
        Self::new("store_error", format!("Local vault store error: {error}"))
    }

    fn to_json(&self, snapshot_ref: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "success": false,
            "dry_run": true,
            "error_code": self.code,
            "failed_check": self.check,
            "error": self.message,
            "snapshot_ref": snapshot_ref,
        })
    }
}

fn parse_snapshot_ref(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return None;
    }
    hex::decode(trimmed).ok()?.as_slice().try_into().ok()
}

/// `restore --dry-run --json`: the verified preview as one JSON document.
/// Runs the same record, manifest, chunk, integrity and destination checks
/// as a restore, writes nothing, and exits with
/// [`RESTORE_PREVIEW_REFUSED_EXIT`] when the preview is refused.
pub(crate) fn cmd_restore_preview_json(
    snapshot_hex_opt: Option<String>,
    to_dir_opt: Option<PathBuf>,
    hardware_token: bool,
    reader_opt: Option<String>,
    pin_opt: Option<String>,
) -> Result<()> {
    let outcome = build_restore_preview(
        snapshot_hex_opt.as_deref(),
        to_dir_opt.as_deref(),
        hardware_token,
        reader_opt.as_deref(),
        pin_opt.as_deref(),
    );
    match outcome {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Err(failure) => {
            // Echo the reference only when it is a well-formed ID.
            let reference = snapshot_hex_opt
                .as_deref()
                .filter(|raw| parse_snapshot_ref(raw).is_some())
                .map(|raw| raw.trim().to_ascii_lowercase());
            println!(
                "{}",
                serde_json::to_string_pretty(&failure.to_json(reference.as_deref()))?
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();
            std::process::exit(RESTORE_PREVIEW_REFUSED_EXIT);
        }
    }
}

fn build_restore_preview(
    snapshot_ref: Option<&str>,
    to_dir: Option<&std::path::Path>,
    hardware_token: bool,
    reader: Option<&str>,
    pin: Option<&str>,
) -> std::result::Result<RestorePreviewReport, RestorePreviewFailure> {
    use ciphervault_snapshot::SnapshotError;
    use RestorePreviewFailure as Failure;

    let store = get_vault_store().map_err(|error| Failure::new("no_vault", error.to_string()))?;
    let vault_id = store.get_vault_id().map_err(Failure::store)?;
    let (_, device_sk, _, _) = store.get_device_state().map_err(Failure::store)?;
    let certs = store.list_device_certificates().map_err(Failure::store)?;
    let is_hardware_bound = certs
        .first()
        .map(|c| c.device_signing_pk != device_sk.verifying_key().to_bytes())
        .unwrap_or(false);
    if hardware_token || is_hardware_bound {
        // Headless: an interactive token picker would corrupt the JSON on stdout.
        resolve_hardware_token(reader, pin, true).map_err(|error| {
            Failure::new(
                "hardware_token_required",
                format!("Hardware token authentication failed: {error}"),
            )
        })?;
    }

    let root = crate::util::get_workspace_root()
        .map_err(|error| Failure::new("no_vault", error.to_string()))?;
    let into_workspace = to_dir.is_none();
    let target_dir = match to_dir {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => root.join(path),
        None => root.clone(),
    };

    let active_head: Option<[u8; 32]> = store
        .get_active_head()
        .map_err(Failure::store)?
        .and_then(|head| head.snapshot_id.as_slice().try_into().ok());
    let requested = match snapshot_ref {
        Some(raw) => parse_snapshot_ref(raw).ok_or_else(|| {
            Failure::new(
                "invalid_snapshot_id",
                "Snapshot ID must be a 64-character hex string",
            )
        })?,
        None => active_head.ok_or_else(|| {
            Failure::new(
                "no_snapshots",
                "This vault has no snapshots yet; create one with 'ciphervault push'",
            )
        })?,
    };
    let (record, encrypted_manifest) = match store.get_snapshot(&requested) {
        Ok(found) => found,
        Err(ciphervault_local_store::LocalStoreError::NotFound(_)) => {
            return Err(Failure::new(
                "snapshot_not_found",
                format!(
                    "Snapshot {} is not in this vault's local store",
                    hex::encode(requested)
                ),
            ))
        }
        Err(error) => return Err(Failure::store(error)),
    };

    let mut checks = Vec::new();
    let record_cid = record.compute_record_cid().map_err(|error| {
        Failure::check(
            "record_signature",
            format!("Malformed snapshot record: {error}"),
        )
    })?;
    crate::util::verify_local_snapshot_record(&store, &record)
        .map_err(|error| Failure::check("record_signature", format!("{error:#}")))?;
    checks.push("record_signature");

    let epoch_key = store.get_epoch_key(record.epoch).map_err(|_| {
        Failure::check(
            "epoch_key",
            format!(
                "Epoch {} key is required to verify this snapshot",
                record.epoch
            ),
        )
    })?;
    checks.push("epoch_key");

    let manifest_key = Zeroizing::new(
        epoch_key
            .derive_manifest_key(record.epoch)
            .map_err(|_| Failure::check("manifest", "Cannot derive the manifest key"))?,
    );
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes = Zeroizing::new(
        ciphervault_crypto::decrypt_chunk(&manifest_key, &encrypted_manifest, &aad).map_err(
            |_| {
                Failure::check(
                    "manifest",
                    "Snapshot manifest failed authenticated decryption",
                )
            },
        )?,
    );
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)
        .map_err(|_| Failure::check("manifest", "Snapshot manifest is malformed"))?;
    checks.push("manifest");

    let mut needed_cids = Vec::new();
    for file in &manifest.files {
        for cid_bytes in &file.chunk_cids {
            let arr: [u8; 32] = cid_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Failure::check("manifest", "Invalid manifest chunk CID"))?;
            needed_cids.push(arr);
        }
    }
    needed_cids.sort();
    needed_cids.dedup();
    let chunks = store.get_chunks(&needed_cids).map_err(Failure::store)?;
    if chunks.len() != needed_cids.len() {
        return Err(Failure::check(
            "chunks_present",
            format!(
                "Missing chunks in local store (required {}, found {})",
                needed_cids.len(),
                chunks.len()
            ),
        ));
    }
    checks.push("chunks_present");

    // Digests stay out of every message: a plaintext hash is not for agents.
    let files = decrypt_snapshot(
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    )
    .map_err(|error| match error {
        SnapshotError::MissingChunk { path, .. } => {
            Failure::check("chunks_present", format!("Missing chunk for {path}"))
        }
        SnapshotError::IntegrityMismatch { path, .. } => Failure::check(
            "file_integrity",
            format!("Integrity check failed for {path}"),
        ),
        SnapshotError::UnsafePath(message) => Failure::check("path_safety", message),
        SnapshotError::FileTooLarge { path, .. } => Failure::check(
            "file_integrity",
            format!("{path} exceeds the restore size limit"),
        ),
        _ => Failure::check("file_integrity", "Snapshot content failed verification"),
    })?;
    checks.push("file_integrity");

    let destinations = ciphervault_snapshot::preflight_restore_destinations(&target_dir, &files)
        .map_err(|error| match error {
            SnapshotError::UnsafePath(message) => Failure::new("unsafe_destination", message),
            other => Failure::new(
                "destination_unreadable",
                format!("Cannot inspect the restore destination: {other}"),
            ),
        })?;
    checks.push("destination_paths");

    let mut entries = Vec::with_capacity(files.len());
    let mut counts = RestorePreviewCounts::default();
    for (file, destination) in files.iter().zip(&destinations) {
        let action = match std::fs::symlink_metadata(destination) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "create",
            Err(error) => {
                return Err(Failure::new(
                    "destination_unreadable",
                    format!("Cannot inspect {}: {error}", file.relative_path),
                ))
            }
            Ok(_) => {
                let previous = read_current_file(destination).map_err(|error| {
                    Failure::new(
                        "destination_unreadable",
                        format!("Cannot read {}: {error}", file.relative_path),
                    )
                })?;
                if previous.as_slice() == file.plaintext.as_slice() {
                    "unchanged"
                } else {
                    "replace"
                }
            }
        };
        match action {
            "create" => counts.create += 1,
            "replace" => counts.replace += 1,
            _ => counts.unchanged += 1,
        }
        entries.push(RestorePreviewFile {
            path: file.relative_path.replace('\\', "/"),
            action,
            bytes: file.plaintext.len() as u64,
        });
    }
    drop(files);
    counts.total = entries.len();
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let uncommitted_changes = if into_workspace {
        uncommitted_tracked_changes(&store, &vault_id)
            .ok()
            .map(|paths| {
                let mut paths: Vec<String> =
                    paths.into_iter().map(|p| p.replace('\\', "/")).collect();
                paths.sort();
                paths
            })
    } else {
        None
    };
    let restore_requires_force = uncommitted_changes
        .as_ref()
        .is_some_and(|paths| !paths.is_empty());
    let checked_at_utc = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);

    Ok(RestorePreviewReport {
        success: true,
        dry_run: true,
        snapshot_id: hex::encode(record_cid),
        logical_id: hex::encode(&record.snapshot_id),
        is_active_head: active_head == Some(record_cid),
        recorded_at_utc: Some(record.advisory_timestamp_utc).filter(|at| *at > 0),
        epoch: record.epoch,
        destination: if into_workspace {
            "workspace"
        } else {
            "directory"
        },
        mode: "merge",
        verification: RestorePreviewVerification {
            status: "passed",
            checks,
            checked_at_utc,
        },
        files: entries,
        counts,
        uncommitted_changes,
        restore_requires_force,
        interrupted_restore_pending: ciphervault_snapshot::restore_transaction_pending(&target_dir),
    })
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
    // (shared with `restore`: both overwrite working files).
    if !force {
        ensure_no_uncommitted_changes(&store, &vault_id)?;
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
