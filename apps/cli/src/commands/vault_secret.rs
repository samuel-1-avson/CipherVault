//! Native in-vault secret mutations: `ciphervault vault set|generate|unset`.
//!
//! Mutates a single key in a tracked `.env` file strictly inside zeroizing RAM,
//! preserving every other key in the target file and every other tracked file
//! from the active encrypted snapshot (and unsealed working-tree files), then
//! commits a new signed encrypted snapshot locally. When `--seal`,
//! `[vault].sealed_mode = true`, or the working tree is already sealed, zero
//! plaintext bytes ever touch disk.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use chrono::Utc;
use colored::Colorize;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use ciphervault_crypto::encrypt_chunk;
use ciphervault_format::{
    compute_digest, to_canonical_cbor, ChunkWireObject, HeadRecord, ManifestFileEntry,
    SnapshotManifest, SnapshotRecord, HEAD_RECORD_VERSION_V2, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_snapshot::{
    chunk_and_encrypt_file, chunk_and_encrypt_file_v2, validate_safe_relative_path,
    ChunkWriteVersion, MAX_FILE_SIZE,
};

use crate::commands::push::shred_working_tree_files;
use crate::commands::run::{load_snapshot_bundle, load_workspace_policy};
use crate::util::{
    ensure_file_in_gitignore, get_vault_directory, get_vault_store, get_workspace_root,
};

const MAX_SECRET_NAME_LEN: usize = 256;
const MAX_SECRET_VALUE_BYTES: usize = 65_536;
const MIN_GENERATE_BYTES: usize = 16;
const MAX_GENERATE_BYTES: usize = 64;
const ALPHANUMERIC_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct VaultSetReport {
    pub success: bool,
    pub name: String,
    pub env_file: String,
    pub sealed: bool,
    pub snapshot_head: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct VaultGenerateReport {
    pub success: bool,
    pub name: String,
    pub format: String,
    pub length_chars: usize,
    pub sha256_prefix: String,
    pub env_file: String,
    pub sealed: bool,
    pub snapshot_head: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct VaultUnsetReport {
    pub success: bool,
    pub name: String,
    pub removed: bool,
    pub env_file: String,
    pub sealed: bool,
    pub snapshot_head: String,
}

enum DotenvMutation<'a> {
    Set {
        value: &'a str,
        allow_overwrite: bool,
    },
    Unset,
}

pub(crate) fn validate_env_key_name(name: &str) -> Result<String> {
    if name.is_empty() || name.len() > MAX_SECRET_NAME_LEN {
        bail!(
            "Invalid secret name '{}': must be 1..={} characters matching [A-Za-z_][A-Za-z0-9_]*",
            name.chars().take(64).collect::<String>(),
            MAX_SECRET_NAME_LEN
        );
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        bail!(
            "Invalid secret name '{}': must match ^[A-Za-z_][A-Za-z0-9_]*$",
            name.chars().take(64).collect::<String>()
        );
    }
    Ok(name.to_string())
}

pub(crate) fn validate_and_normalize_env_file(raw: &str, workspace_root: &Path) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("--env-file cannot be empty");
    }
    if trimmed.contains('\0')
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.contains(':')
    {
        bail!("--env-file must be a relative path inside the workspace: '{trimmed}'");
    }
    let mut norm = trimmed.replace('\\', "/");
    while let Some(stripped) = norm.strip_prefix("./") {
        norm = stripped.to_string();
    }
    if norm.is_empty() || norm == "." {
        bail!("--env-file must name a file inside the workspace");
    }
    validate_safe_relative_path(&norm)
        .map_err(|e| anyhow::anyhow!("Invalid --env-file '{trimmed}': {e}"))?;

    let rel_path = Path::new(&norm);
    for comp in rel_path.components() {
        match comp {
            Component::Normal(c) => {
                let s = c.to_string_lossy();
                if s.eq_ignore_ascii_case(".ciphervault") {
                    bail!("Refusing --env-file inside .ciphervault/: '{trimmed}'");
                }
            }
            _ => bail!("Invalid --env-file path component in '{trimmed}'"),
        }
    }

    ensure_no_symlink_escape(workspace_root, rel_path)?;
    Ok(norm)
}

fn ensure_no_symlink_escape(workspace_root: &Path, rel_path: &Path) -> Result<()> {
    let canonical_root =
        std::fs::canonicalize(workspace_root).unwrap_or_else(|_| workspace_root.to_path_buf());
    let mut cursor = workspace_root.to_path_buf();
    for comp in rel_path.components() {
        cursor.push(comp);
        match std::fs::symlink_metadata(&cursor) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    bail!(
                        "Refusing symlink in path '{}'",
                        rel_path.to_string_lossy()
                    );
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 {
                        bail!(
                            "Refusing reparse point in path '{}'",
                            rel_path.to_string_lossy()
                        );
                    }
                }
                if let Ok(canon) = std::fs::canonicalize(&cursor) {
                    if !canon.starts_with(&canonical_root) {
                        bail!(
                            "Path '{}' resolves outside the workspace root",
                            rel_path.to_string_lossy()
                        );
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("inspecting path '{}'", rel_path.to_string_lossy())
                });
            }
        }
    }
    Ok(())
}

fn parse_secret_stdin(mut raw: Zeroizing<String>) -> Result<Zeroizing<String>> {
    if raw.len() > MAX_SECRET_VALUE_BYTES {
        bail!(
            "Secret value exceeds maximum allowed size of {} bytes",
            MAX_SECRET_VALUE_BYTES
        );
    }
    // Strip a single trailing newline (\r\n or \n) from piped input.
    if raw.ends_with('\n') {
        raw.pop();
        if raw.ends_with('\r') {
            raw.pop();
        }
    }
    if raw.is_empty() {
        bail!("Secret value cannot be empty");
    }
    if raw.contains('\n') || raw.contains('\r') || raw.contains('\0') {
        bail!("Secret value must be a single line with no embedded newlines or NUL bytes");
    }
    Ok(raw)
}

fn read_secret_value(stdin_flag: bool, name: &str) -> Result<Zeroizing<String>> {
    if stdin_flag || !std::io::stdin().is_terminal() {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin()
            .take((MAX_SECRET_VALUE_BYTES as u64) + 1)
            .read_to_end(&mut buf)
            .context("Failed to read secret value from stdin")?;
        if buf.len() > MAX_SECRET_VALUE_BYTES {
            bail!(
                "Secret value on stdin exceeds maximum allowed size of {} bytes",
                MAX_SECRET_VALUE_BYTES
            );
        }
        let raw_str = match String::from_utf8(std::mem::take(&mut *buf)) {
            Ok(s) => Zeroizing::new(s),
            Err(e) => {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                bail!("Secret value on stdin must be valid UTF-8");
            }
        };
        return parse_secret_stdin(raw_str);
    }

    let prompted = rpassword::prompt_password(format!("Enter value for {name} (hidden): "))
        .context("Failed to read secret value interactively (pass --stdin for scripts)")?;
    parse_secret_stdin(Zeroizing::new(prompted))
}

fn format_dotenv_value(value: &str) -> Zeroizing<String> {
    let needs_quotes = value.is_empty()
        || value.starts_with(char::is_whitespace)
        || value.ends_with(char::is_whitespace)
        || value.starts_with('"')
        || value.starts_with('\'')
        || value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '\\'));
    if !needs_quotes {
        return Zeroizing::new(value.to_string());
    }
    let mut out = Zeroizing::new(String::with_capacity(value.len() + 4));
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            '$' => out.push_str("\\$"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn extract_dotenv_line_key(line: &str, is_first_line: bool) -> Option<&str> {
    let without_bom = if is_first_line {
        line.strip_prefix('\u{FEFF}').unwrap_or(line)
    } else {
        line
    };
    let trimmed = without_bom.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let body = trimmed
        .strip_prefix("export ")
        .map(str::trim_start)
        .unwrap_or(trimmed);
    let (raw_key, _) = body.split_once('=')?;
    let key = raw_key.trim();
    if key.is_empty() {
        return None;
    }
    Some(key)
}

fn mutate_dotenv_bytes(
    existing: &[u8],
    name: &str,
    op: DotenvMutation<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(existing)
        .context("Target env file is not valid UTF-8 and cannot be safely edited")?;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();

    let exists = lines
        .iter()
        .enumerate()
        .any(|(idx, line)| extract_dotenv_line_key(line, idx == 0) == Some(name));

    match op {
        DotenvMutation::Set {
            value,
            allow_overwrite,
        } => {
            if exists && !allow_overwrite {
                bail!("Key '{name}' already exists; pass --overwrite to replace it");
            }
            let formatted = format_dotenv_value(value);
            let mut out = Zeroizing::new(String::with_capacity(
                existing.len() + name.len() + formatted.len() + 4,
            ));
            let mut replaced = false;
            for (idx, line) in lines.iter().enumerate() {
                if extract_dotenv_line_key(line, idx == 0) == Some(name) {
                    if !replaced {
                        if idx == 0 && line.starts_with('\u{FEFF}') {
                            out.push('\u{FEFF}');
                        }
                        let ending = if line.ends_with("\r\n") { "\r\n" } else { "\n" };
                        out.push_str(name);
                        out.push('=');
                        out.push_str(&formatted);
                        out.push_str(ending);
                        replaced = true;
                    }
                    // Drop duplicate occurrences of the same key so stale values never shadow it.
                } else {
                    out.push_str(line);
                }
            }
            if !replaced {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(name);
                out.push('=');
                out.push_str(&formatted);
                out.push('\n');
            }
            Ok(Zeroizing::new(out.as_bytes().to_vec()))
        }
        DotenvMutation::Unset => {
            if !exists {
                bail!("Key '{name}' not found");
            }
            let mut out = Zeroizing::new(String::with_capacity(existing.len()));
            for (idx, line) in lines.iter().enumerate() {
                if extract_dotenv_line_key(line, idx == 0) == Some(name) {
                    continue;
                }
                out.push_str(line);
            }
            Ok(Zeroizing::new(out.as_bytes().to_vec()))
        }
    }
}

fn generate_secret_value(format: &str, bytes: usize) -> Result<(&'static str, Zeroizing<String>)> {
    if !(MIN_GENERATE_BYTES..=MAX_GENERATE_BYTES).contains(&bytes) {
        bail!(
            "--bytes must be an integer between {} and {} (got {})",
            MIN_GENERATE_BYTES,
            MAX_GENERATE_BYTES,
            bytes
        );
    }
    let fmt_lower = format.trim().to_ascii_lowercase();
    match fmt_lower.as_str() {
        "base64url" => {
            let mut raw = Zeroizing::new(vec![0u8; bytes]);
            OsRng.fill_bytes(&mut raw);
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*raw);
            Ok(("base64url", Zeroizing::new(encoded)))
        }
        "hex" => {
            let mut raw = Zeroizing::new(vec![0u8; bytes]);
            OsRng.fill_bytes(&mut raw);
            Ok(("hex", Zeroizing::new(hex::encode(&*raw))))
        }
        "uuid" => {
            let mut raw = Zeroizing::new([0u8; 16]);
            OsRng.fill_bytes(&mut *raw);
            raw[6] = (raw[6] & 0x0f) | 0x40;
            raw[8] = (raw[8] & 0x3f) | 0x80;
            let formatted = format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                raw[0], raw[1], raw[2], raw[3],
                raw[4], raw[5],
                raw[6], raw[7],
                raw[8], raw[9],
                raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
            );
            Ok(("uuid", Zeroizing::new(formatted)))
        }
        "alphanumeric" => {
            // Rejection sampling avoids modulo bias across the 62-char alphabet (248 = 62 * 4).
            let limit = 248u8;
            let mut out = Zeroizing::new(String::with_capacity(bytes));
            let mut chunk = Zeroizing::new([0u8; 64]);
            while out.len() < bytes {
                OsRng.fill_bytes(&mut *chunk);
                for &b in chunk.iter() {
                    if b < limit {
                        out.push(ALPHANUMERIC_ALPHABET[(b % 62) as usize] as char);
                        if out.len() == bytes {
                            break;
                        }
                    }
                }
            }
            Ok(("alphanumeric", out))
        }
        other => bail!(
            "Invalid --format '{other}': expected one of base64url, hex, uuid, alphanumeric"
        ),
    }
}

fn normalize_rel_key(path: &Path) -> String {
    let mut norm = path.to_string_lossy().replace('\\', "/");
    while let Some(stripped) = norm.strip_prefix("./") {
        norm = stripped.to_string();
    }
    norm
}

fn read_regular_file_zeroizing(workspace_root: &Path, rel_path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    ensure_no_symlink_escape(workspace_root, rel_path)?;
    let full = workspace_root.join(rel_path);
    let mut file = ciphervault_file_lock::open_regular_file(&full)
        .with_context(|| format!("opening '{}'", rel_path.display()))?;
    let meta = file.metadata()?;
    if meta.len() > MAX_FILE_SIZE {
        bail!(
            "Tracked file '{}' exceeds maximum size ({} bytes)",
            rel_path.display(),
            MAX_FILE_SIZE
        );
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    (&mut file)
        .take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("reading '{}'", rel_path.display()))?;
    if buf.len() as u64 > MAX_FILE_SIZE {
        bail!(
            "Tracked file '{}' exceeds maximum size ({} bytes)",
            rel_path.display(),
            MAX_FILE_SIZE
        );
    }
    Ok(buf)
}

fn write_secret_file_atomic(
    workspace_root: &Path,
    rel_norm: &str,
    plaintext: &[u8],
) -> Result<()> {
    let rel_path = Path::new(rel_norm);
    ensure_no_symlink_escape(workspace_root, rel_path)?;
    let full = workspace_root.join(rel_path);
    let parent = full
        .parent()
        .context("target env file has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating parent directory for '{rel_norm}'"))?;
    ensure_no_symlink_escape(workspace_root, rel_path)?;

    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let file_name = full
        .file_name()
        .and_then(|n| n.to_str())
        .context("target env file has invalid filename")?;
    let tmp_path = parent.join(format!(
        ".{file_name}.cvtmp.{}.{}",
        std::process::id(),
        hex::encode(suffix)
    ));

    let write_res = (|| -> Result<()> {
        let mut f = ciphervault_file_lock::create_secret_file(&tmp_path)
            .with_context(|| format!("creating temporary file for '{rel_norm}'"))?;
        f.write_all(plaintext)?;
        f.sync_all()?;
        drop(f);
        ciphervault_file_lock::atomic_replace(&tmp_path, &full)
            .with_context(|| format!("replacing '{rel_norm}' atomically"))?;
        let _ = ciphervault_file_lock::sync_directory(parent);
        Ok(())
    })();

    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

/// Encrypts `files_in_ram` into a signed local snapshot and updates the vault's
/// active `HeadRecord`, without writing any plaintext to disk.
fn commit_in_memory_snapshot(
    store: &LocalVaultStore,
    tracked: &[(PathBuf, [u8; 32])],
    files_in_ram: &BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> Result<String> {
    let vault_id = store.get_vault_id()?;
    let (device_id, device_sk, counter, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;
    let signing_key = device_sk.verifying_key().to_bytes();

    let certs = store.list_device_certificates()?;
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
        .context(
            "No trusted software signing authority for this device (hardware-bound vaults require interactive push with --touch)",
        )?;
    store.validate_capture_authority_for_key(&signing_key, authority_generation)?;

    let active_head = store.get_active_head()?;
    let parent_ids: Vec<Vec<u8>> = match active_head {
        Some(ref h) => vec![h.snapshot_id.clone()],
        None => Vec::new(),
    };

    let write_version = ChunkWriteVersion::from_env()?;
    let mut manifest_entries = Vec::with_capacity(tracked.len());
    let mut all_chunks: Vec<ChunkWireObject> = Vec::new();

    for (rel_path, file_id) in tracked {
        let rel_norm = normalize_rel_key(rel_path);
        validate_safe_relative_path(&rel_norm)
            .map_err(|e| anyhow::anyhow!("Unsafe tracked path '{rel_norm}': {e}"))?;

        if let Some(plaintext) = files_in_ram.get(&rel_norm) {
            let chunked = match write_version {
                ChunkWriteVersion::LegacyV1 => {
                    chunk_and_encrypt_file(&vault_id, epoch, &epoch_key, plaintext)?
                }
                ChunkWriteVersion::V2 => {
                    chunk_and_encrypt_file_v2(&vault_id, epoch, &epoch_key, plaintext)?
                }
            };
            let mut file_chunk_cids = Vec::with_capacity(chunked.chunks.len());
            for chunk in chunked.chunks {
                let cid = chunk.compute_cid()?;
                file_chunk_cids.push(cid.to_vec());
                all_chunks.push(chunk);
            }
            manifest_entries.push(ManifestFileEntry {
                file_id: file_id.to_vec(),
                relative_path: rel_norm,
                file_version_id: chunked.file_version_id.to_vec(),
                raw_length: chunked.raw_length,
                padded_length: chunked.padded_length,
                plaintext_sha256: chunked.plaintext_sha256.to_vec(),
                file_version_key: chunked.file_version_key.as_bytes().to_vec(),
                chunk_cids: file_chunk_cids,
                is_deleted: false,
            });
        } else {
            manifest_entries.push(ManifestFileEntry {
                file_id: file_id.to_vec(),
                relative_path: rel_norm,
                file_version_id: vec![0u8; 32],
                raw_length: 0,
                padded_length: 0,
                plaintext_sha256: vec![0u8; 32],
                file_version_key: vec![0u8; 32],
                chunk_cids: Vec::new(),
                is_deleted: true,
            });
        }
    }

    let mut snapshot_id = [0u8; 32];
    OsRng.fill_bytes(&mut snapshot_id);

    let manifest = SnapshotManifest {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        epoch,
        snapshot_id: snapshot_id.to_vec(),
        files: manifest_entries,
    };

    let manifest_bytes = Zeroizing::new(to_canonical_cbor(&manifest)?);
    let manifest_key = Zeroizing::new(epoch_key.derive_manifest_key(epoch)?);
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &epoch.to_le_bytes(),
    ]
    .concat();
    let encrypted_manifest = encrypt_chunk(&manifest_key, &manifest_bytes, &aad)?;
    let manifest_cid = compute_digest(&encrypted_manifest);

    let mut record = SnapshotRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        snapshot_id: snapshot_id.to_vec(),
        parent_snapshot_ids: parent_ids,
        device_id: device_id.to_vec(),
        device_counter: counter + 1,
        authority_generation,
        epoch,
        encrypted_manifest_cid: manifest_cid.to_vec(),
        encrypted_manifest_len: encrypted_manifest.len() as u64,
        advisory_timestamp_utc: Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    record.sign(&device_sk)?;

    store.save_snapshot(&record, &encrypted_manifest, &all_chunks)?;
    store.increment_device_counter()?;

    let recovery_set = store.prepare_recovery_set(&record)?;
    let record_cid = record.compute_record_cid()?;

    let mut head = HeadRecord {
        version: HEAD_RECORD_VERSION_V2,
        vault_id: vault_id.to_vec(),
        snapshot_id: record_cid.to_vec(),
        parent_snapshot_ids: record.parent_snapshot_ids.clone(),
        closure_digest: recovery_set.closure.compute_base_closure_digest()?.to_vec(),
        device_id: device_id.to_vec(),
        device_counter: counter + 1,
        authority_generation: Some(record.authority_generation),
        signature: Vec::new(),
    };
    head.sign(&device_sk)?;
    store.set_head(&head)?;

    Ok(hex::encode(record_cid))
}

struct MutationOutcome {
    env_file: String,
    sealed: bool,
    snapshot_head: String,
}

async fn apply_vault_secret_mutation(
    name: &str,
    env_file_raw: &str,
    seal_flag: bool,
    op: DotenvMutation<'_>,
    activity_event: &str,
) -> Result<MutationOutcome> {
    let key_name = validate_env_key_name(name)?;
    let store = get_vault_store()?;
    let vault_dir = get_vault_directory();
    let workspace_root = get_workspace_root()?;
    let norm_env_file = validate_and_normalize_env_file(env_file_raw, &workspace_root)?;

    let policy_sealed = load_workspace_policy(&vault_dir)?.is_some_and(|p| p.sealed_mode);
    let active_head = store.get_active_head()?;
    let tracked_before = store.list_tracked_files()?;
    let plaintext_on_disk_before = tracked_before
        .iter()
        .filter(|(rel, _)| workspace_root.join(rel).exists())
        .count();
    let was_working_tree_sealed =
        active_head.is_some() && !tracked_before.is_empty() && plaintext_on_disk_before == 0;
    let effective_seal = seal_flag || policy_sealed || was_working_tree_sealed;

    let is_unset = matches!(op, DotenvMutation::Unset);
    let target_was_tracked = tracked_before
        .iter()
        .any(|(rel, _)| normalize_rel_key(rel) == norm_env_file);

    // Load active snapshot files strictly in zeroizing RAM first so we never
    // lose previously sealed keys or other tracked files.
    let mut files_in_ram: BTreeMap<String, Zeroizing<Vec<u8>>> = BTreeMap::new();
    if active_head.is_some() {
        let mut bundle = load_snapshot_bundle(&store, None).await?;
        for f in &mut bundle.files {
            let rel_norm = normalize_rel_key(Path::new(&f.relative_path));
            let owned = std::mem::take(&mut f.plaintext);
            files_in_ram.insert(rel_norm, Zeroizing::new(owned));
        }
    }

    // Overlay any tracked files that currently exist on disk (unsealed working tree),
    // plus the target env file if it already exists on disk before being tracked.
    for (rel_path, _) in &tracked_before {
        let full = workspace_root.join(rel_path);
        if full.exists() {
            let rel_norm = normalize_rel_key(rel_path);
            let bytes = read_regular_file_zeroizing(&workspace_root, rel_path)?;
            files_in_ram.insert(rel_norm, bytes);
        }
    }
    if !target_was_tracked {
        let target_full = workspace_root.join(&norm_env_file);
        if target_full.exists() {
            let bytes = read_regular_file_zeroizing(&workspace_root, Path::new(&norm_env_file))?;
            files_in_ram.insert(norm_env_file.clone(), bytes);
        } else if is_unset && !files_in_ram.contains_key(&norm_env_file) {
            bail!("Key '{key_name}' not found in '{norm_env_file}'");
        }
    }

    // Apply single-key mutation in zeroizing RAM BEFORE mutating tracked list or DB.
    let existing_target = files_in_ram
        .get(&norm_env_file)
        .map(|b| b.as_slice())
        .unwrap_or(&[]);
    let updated_target = mutate_dotenv_bytes(existing_target, &key_name, op).with_context(|| {
        format!("updating '{key_name}' in '{norm_env_file}'")
    })?;
    files_in_ram.insert(norm_env_file.clone(), updated_target);

    // Auto-track target env file (and ensure .gitignore covers it) on set/generate.
    if !target_was_tracked && !is_unset {
        store.track_file(&norm_env_file)?;
        let _ = ensure_file_in_gitignore(Path::new(&norm_env_file));
    }
    let tracked_after = store.list_tracked_files()?;

    // Commit new encrypted snapshot strictly from zeroizing RAM buffers.
    let snapshot_head = commit_in_memory_snapshot(&store, &tracked_after, &files_in_ram)?;

    // Synchronize working tree:
    // - Sealed: zero-fill & remove any tracked plaintext files on disk (0B left on disk).
    // - Unsealed: atomically update the target env file with restricted permissions.
    if effective_seal {
        shred_working_tree_files(&workspace_root, &tracked_after)?;
    } else if let Some(updated_bytes) = files_in_ram.get(&norm_env_file) {
        write_secret_file_atomic(&workspace_root, &norm_env_file, updated_bytes)?;
    }

    // Explicit zeroization of RAM map before returning/logging.
    files_in_ram.clear();

    let _ = store.record_activity(
        activity_event,
        &format!("Updated key {key_name} in {norm_env_file}"),
        &serde_json::json!({
            "name": key_name,
            "env_file": norm_env_file,
            "sealed": effective_seal,
            "snapshot_head": snapshot_head,
        })
        .to_string(),
    );

    Ok(MutationOutcome {
        env_file: norm_env_file,
        sealed: effective_seal,
        snapshot_head,
    })
}

pub(crate) async fn vault_set_value(
    name: &str,
    value: Zeroizing<String>,
    env_file: &str,
    seal: bool,
) -> Result<VaultSetReport> {
    let key_name = validate_env_key_name(name)?;
    let parsed_value = parse_secret_stdin(value)?;
    let outcome = apply_vault_secret_mutation(
        &key_name,
        env_file,
        seal,
        DotenvMutation::Set {
            value: parsed_value.as_str(),
            allow_overwrite: true,
        },
        "VAULT_SECRET_SET",
    )
    .await?;
    drop(parsed_value);
    Ok(VaultSetReport {
        success: true,
        name: key_name,
        env_file: outcome.env_file,
        sealed: outcome.sealed,
        snapshot_head: outcome.snapshot_head,
    })
}

pub(crate) async fn vault_generate_value(
    name: &str,
    format: &str,
    bytes: usize,
    env_file: &str,
    seal: bool,
    overwrite: bool,
) -> Result<VaultGenerateReport> {
    let key_name = validate_env_key_name(name)?;
    let (canonical_fmt, generated) = generate_secret_value(format, bytes)?;
    let length_chars = generated.chars().count();
    let sha256_prefix = hex::encode(Sha256::digest(generated.as_bytes()))[..8].to_string();

    let outcome = apply_vault_secret_mutation(
        &key_name,
        env_file,
        seal,
        DotenvMutation::Set {
            value: generated.as_str(),
            allow_overwrite: overwrite,
        },
        "VAULT_SECRET_GENERATE",
    )
    .await?;
    drop(generated);

    Ok(VaultGenerateReport {
        success: true,
        name: key_name,
        format: canonical_fmt.to_string(),
        length_chars,
        sha256_prefix,
        env_file: outcome.env_file,
        sealed: outcome.sealed,
        snapshot_head: outcome.snapshot_head,
    })
}

pub(crate) async fn vault_unset_value(
    name: &str,
    env_file: &str,
    seal: bool,
) -> Result<VaultUnsetReport> {
    let key_name = validate_env_key_name(name)?;
    let outcome = apply_vault_secret_mutation(
        &key_name,
        env_file,
        seal,
        DotenvMutation::Unset,
        "VAULT_SECRET_UNSET",
    )
    .await?;
    Ok(VaultUnsetReport {
        success: true,
        name: key_name,
        removed: true,
        env_file: outcome.env_file,
        sealed: outcome.sealed,
        snapshot_head: outcome.snapshot_head,
    })
}

pub(crate) async fn cmd_vault_set(
    name: String,
    stdin: bool,
    env_file: String,
    seal: bool,
    json: bool,
) -> Result<()> {
    let key_name = validate_env_key_name(&name)?;
    let value = read_secret_value(stdin, &key_name)?;
    let report = vault_set_value(&key_name, value, &env_file, seal).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} Stored '{}' in '{}' (head {}, {})",
            "✓".green().bold(),
            report.name.bold(),
            report.env_file.cyan(),
            &report.snapshot_head[..12],
            if report.sealed {
                "sealed (0B on disk)".green()
            } else {
                "unsealed".yellow()
            }
        );
    }
    Ok(())
}

pub(crate) async fn cmd_vault_generate(
    name: String,
    format: String,
    bytes: usize,
    env_file: String,
    seal: bool,
    overwrite: bool,
    json: bool,
) -> Result<()> {
    let report = vault_generate_value(&name, &format, bytes, &env_file, seal, overwrite).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} Generated '{}' ({}, {} chars, sha256:{}…) in '{}' (head {}, {})",
            "✓".green().bold(),
            report.name.bold(),
            report.format,
            report.length_chars,
            report.sha256_prefix,
            report.env_file.cyan(),
            &report.snapshot_head[..12],
            if report.sealed {
                "sealed (0B on disk)".green()
            } else {
                "unsealed".yellow()
            }
        );
    }
    Ok(())
}

pub(crate) async fn cmd_vault_unset(
    name: String,
    env_file: String,
    seal: bool,
    json: bool,
) -> Result<()> {
    let report = vault_unset_value(&name, &env_file, seal).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} Removed '{}' from '{}' (head {}, {})",
            "✓".green().bold(),
            report.name.bold(),
            report.env_file.cyan(),
            &report.snapshot_head[..12],
            if report.sealed {
                "sealed (0B on disk)".green()
            } else {
                "unsealed".yellow()
            }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
    use ciphervault_format::{DeviceCertificate, GenesisRecord};
    use crate::commands::run::load_local_snapshot_bundle_sync;
    use crate::dotenv::parse_dotenv_bytes;
    use crate::util::{VaultContext, REQUEST_VAULT_CONTEXT};

    fn init_test_vault(root: &Path) -> (VaultContext, LocalVaultStore) {
        let vault_dir = root.join(".ciphervault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        let db_path = vault_dir.join("vault.db");

        let mut vault_id = [0u8; 32];
        OsRng.fill_bytes(&mut vault_id);
        let recovery_secret = RecoverySecret::generate();
        let recovery_sk = recovery_secret.derive_recovery_signing_key().unwrap();
        let (_, recovery_enc_pk) = recovery_secret.derive_recovery_encryption_keys().unwrap();
        let recovery_locator = recovery_secret.derive_recovery_locator().unwrap();

        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            recovery_signing_pk: recovery_sk.verifying_key().as_bytes().to_vec(),
            recovery_encryption_pk: recovery_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0u8; 32],
            created_at_utc: Utc::now().timestamp() as u64,
            creation_nonce: vec![0x42u8; 32],
            signature: Vec::new(),
        };
        genesis.sign(&recovery_sk).unwrap();

        let device_sk = generate_signing_key();
        let mut device_id = [0u8; 32];
        OsRng.fill_bytes(&mut device_id);
        let epoch_key = VaultEpochKey::generate();

        let store = LocalVaultStore::open(&db_path).unwrap();
        store
            .init_vault(
                &vault_id,
                &genesis,
                &device_sk,
                &device_id,
                &epoch_key,
                &recovery_locator,
            )
            .unwrap();

        let mut cert = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            certificate_id: vec![0x77u8; 32],
            device_signing_pk: device_sk.verifying_key().as_bytes().to_vec(),
            permissions: 0xFFFF_FFFF,
            authority_generation: 1,
            issued_at_utc: Utc::now().timestamp() as u64,
            signature: Vec::new(),
        };
        cert.sign(&recovery_sk).unwrap();
        store.save_device_certificate(&cert).unwrap();

        let ctx = VaultContext::from_db_path(&db_path).unwrap();
        (ctx, store)
    }

    #[test]
    fn validates_names_paths_and_stdin_values() {
        assert!(validate_env_key_name("API_KEY_1").is_ok());
        assert!(validate_env_key_name("_PRIVATE").is_ok());
        assert!(validate_env_key_name("").is_err());
        assert!(validate_env_key_name("1INVALID").is_err());
        assert!(validate_env_key_name("BAD-KEY").is_err());
        assert!(validate_env_key_name("KEY\nINJECT=1").is_err());

        let dir = std::env::temp_dir().join(format!("cv-vsec-path-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(validate_and_normalize_env_file(".env", &dir).unwrap(), ".env");
        assert_eq!(
            validate_and_normalize_env_file("./config/.env.prod", &dir).unwrap(),
            "config/.env.prod"
        );
        assert!(validate_and_normalize_env_file("../escape.env", &dir).is_err());
        assert!(validate_and_normalize_env_file("/etc/passwd", &dir).is_err());
        assert!(validate_and_normalize_env_file(".ciphervault/policy.toml", &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            parse_secret_stdin(Zeroizing::new("secret_val\r\n".to_string()))
                .unwrap()
                .as_str(),
            "secret_val"
        );
        assert_eq!(
            parse_secret_stdin(Zeroizing::new("secret_val\n".to_string()))
                .unwrap()
                .as_str(),
            "secret_val"
        );
        assert!(parse_secret_stdin(Zeroizing::new("".to_string())).is_err());
        assert!(parse_secret_stdin(Zeroizing::new("\n".to_string())).is_err());
        assert!(parse_secret_stdin(Zeroizing::new("line1\nline2\n".to_string())).is_err());
        assert!(parse_secret_stdin(Zeroizing::new("nul\0byte".to_string())).is_err());
    }

    #[test]
    fn dotenv_mutation_preserves_other_keys_comments_and_special_chars() {
        let initial = b"\xEF\xBB\xBF# Header comment\nEXISTING=one\nexport TARGET=old_val\n# Trailing\nKEEP_ME=two\nTARGET=dup_val\n";
        // Refuses overwrite when allow_overwrite = false
        let err = mutate_dotenv_bytes(
            initial,
            "TARGET",
            DotenvMutation::Set {
                value: "new_val",
                allow_overwrite: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("--overwrite"));

        // Replaces target (and collapses duplicates) while keeping comments & other keys
        let updated = mutate_dotenv_bytes(
            initial,
            "TARGET",
            DotenvMutation::Set {
                value: "val with spaces # and $dollar \"q\"",
                allow_overwrite: true,
            },
        )
        .unwrap();
        let updated_str = std::str::from_utf8(&updated).unwrap();
        assert!(updated_str.contains("# Header comment"));
        assert!(updated_str.contains("# Trailing"));
        assert_eq!(updated_str.matches("TARGET=").count(), 1);
        let parsed: BTreeMap<String, String> =
            parse_dotenv_bytes(&updated).unwrap().into_iter().collect();
        assert_eq!(parsed.get("EXISTING").map(String::as_str), Some("one"));
        assert_eq!(parsed.get("KEEP_ME").map(String::as_str), Some("two"));
        assert_eq!(
            parsed.get("TARGET").map(String::as_str),
            Some("val with spaces # and $dollar \"q\"")
        );

        // Unset removes only TARGET
        let after_unset = mutate_dotenv_bytes(&updated, "TARGET", DotenvMutation::Unset).unwrap();
        let parsed_unset: BTreeMap<String, String> = parse_dotenv_bytes(&after_unset)
            .unwrap()
            .into_iter()
            .collect();
        assert!(!parsed_unset.contains_key("TARGET"));
        assert_eq!(parsed_unset.get("EXISTING").map(String::as_str), Some("one"));
        assert_eq!(parsed_unset.get("KEEP_ME").map(String::as_str), Some("two"));

        // Unset of missing key errors
        assert!(mutate_dotenv_bytes(&after_unset, "MISSING", DotenvMutation::Unset).is_err());
    }

    #[test]
    fn generate_secret_value_supports_all_formats_and_bounds() {
        let (f, v) = generate_secret_value("base64url", 32).unwrap();
        assert_eq!(f, "base64url");
        assert_eq!(v.len(), 43);
        assert!(v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

        let (f, v) = generate_secret_value("hex", 24).unwrap();
        assert_eq!(f, "hex");
        assert_eq!(v.len(), 48);
        assert!(v.chars().all(|c| c.is_ascii_hexdigit()));

        let (f, v) = generate_secret_value("uuid", 32).unwrap();
        assert_eq!(f, "uuid");
        assert_eq!(v.len(), 36);
        assert_eq!(v.as_bytes()[14], b'4');
        assert!(matches!(v.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));

        let (f, v) = generate_secret_value("alphanumeric", 40).unwrap();
        assert_eq!(f, "alphanumeric");
        assert_eq!(v.len(), 40);
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric()));

        assert!(generate_secret_value("hex", 15).is_err());
        assert!(generate_secret_value("hex", 65).is_err());
        assert!(generate_secret_value("invalid", 32).is_err());
    }

    #[tokio::test]
    async fn sealed_vault_set_generate_unset_preserves_all_keys_and_files_with_zero_disk_exposure()
    {
        let root = std::env::temp_dir().join(format!("cv-vsec-e2e-{}", rand::random::<u64>()));
        std::fs::create_dir_all(root.join("config")).unwrap();
        let (ctx, store) = init_test_vault(&root);

        // Seed two tracked files and seal them into an initial snapshot.
        std::fs::write(root.join(".env"), b"EXISTING_KEY=alpha_1\nKEEP_ME=beta_2\n").unwrap();
        std::fs::write(root.join("config/extra.env"), b"EXTRA_SECRET=gamma_3\n").unwrap();
        store.track_file(".env").unwrap();
        store.track_file("config/extra.env").unwrap();
        let tracked = store.list_tracked_files().unwrap();
        let mut initial_files = BTreeMap::new();
        initial_files.insert(
            ".env".to_string(),
            Zeroizing::new(b"EXISTING_KEY=alpha_1\nKEEP_ME=beta_2\n".to_vec()),
        );
        initial_files.insert(
            "config/extra.env".to_string(),
            Zeroizing::new(b"EXTRA_SECRET=gamma_3\n".to_vec()),
        );
        let head0 = commit_in_memory_snapshot(&store, &tracked, &initial_files).unwrap();
        shred_working_tree_files(&root, &tracked).unwrap();
        assert!(!root.join(".env").exists());
        assert!(!root.join("config/extra.env").exists());

        REQUEST_VAULT_CONTEXT
            .scope(ctx.clone(), async {
                // 1. Generate a new key on a sealed vault (without passing --seal; stays sealed!).
                let gen1 = vault_generate_value("JWT_SECRET", "base64url", 32, ".env", false, false)
                    .await
                    .unwrap();
                assert!(gen1.success);
                assert_eq!(gen1.name, "JWT_SECRET");
                assert_eq!(gen1.format, "base64url");
                assert_eq!(gen1.length_chars, 43);
                assert_eq!(gen1.sha256_prefix.len(), 8);
                assert_eq!(gen1.env_file, ".env");
                assert!(gen1.sealed);
                assert_ne!(gen1.snapshot_head, head0);
                // Zero plaintext on disk!
                assert!(!root.join(".env").exists());
                assert!(!root.join("config/extra.env").exists());

                // Decrypt head and verify ALL keys and BOTH files are preserved.
                let bundle1 = load_local_snapshot_bundle_sync(&store).unwrap();
                let env1 = bundle1
                    .files
                    .iter()
                    .find(|f| f.relative_path == ".env")
                    .unwrap();
                let map1: BTreeMap<String, String> = parse_dotenv_bytes(&env1.plaintext)
                    .unwrap()
                    .into_iter()
                    .collect();
                assert_eq!(map1.get("EXISTING_KEY").map(String::as_str), Some("alpha_1"));
                assert_eq!(map1.get("KEEP_ME").map(String::as_str), Some("beta_2"));
                let jwt1 = map1.get("JWT_SECRET").unwrap().clone();
                assert_eq!(jwt1.len(), 43);
                assert_eq!(
                    &hex::encode(Sha256::digest(jwt1.as_bytes()))[..8],
                    gen1.sha256_prefix
                );
                let extra1 = bundle1
                    .files
                    .iter()
                    .find(|f| f.relative_path == "config/extra.env")
                    .unwrap();
                assert_eq!(extra1.plaintext, b"EXTRA_SECRET=gamma_3\n");

                // 2. Re-generating existing key without --overwrite MUST fail closed.
                let dup_err =
                    vault_generate_value("JWT_SECRET", "hex", 32, ".env", true, false)
                        .await
                        .unwrap_err();
                assert!(format!("{dup_err:#}").contains("--overwrite"));

                // 3. Re-generating with --overwrite succeeds and preserves all other keys.
                let gen2 = vault_generate_value("JWT_SECRET", "hex", 24, ".env", true, true)
                    .await
                    .unwrap();
                assert_eq!(gen2.format, "hex");
                assert_eq!(gen2.length_chars, 48);
                assert!(gen2.sealed);
                assert!(!root.join(".env").exists());
                let bundle2 = load_local_snapshot_bundle_sync(&store).unwrap();
                let env2 = bundle2
                    .files
                    .iter()
                    .find(|f| f.relative_path == ".env")
                    .unwrap();
                let map2: BTreeMap<String, String> = parse_dotenv_bytes(&env2.plaintext)
                    .unwrap()
                    .into_iter()
                    .collect();
                assert_eq!(map2.get("EXISTING_KEY").map(String::as_str), Some("alpha_1"));
                assert_eq!(map2.get("KEEP_ME").map(String::as_str), Some("beta_2"));
                assert_ne!(map2.get("JWT_SECRET").unwrap(), &jwt1);
                assert_eq!(map2.get("JWT_SECRET").unwrap().len(), 48);

                // 4. `vault set` updates/adds a key in sealed vault without writing plaintext to disk.
                let set_rep = vault_set_value(
                    "API_KEY",
                    Zeroizing::new("token with #hash and spaces\n".to_string()),
                    ".env",
                    true,
                )
                .await
                .unwrap();
                assert!(set_rep.success);
                assert!(set_rep.sealed);
                assert!(!root.join(".env").exists());
                let bundle3 = load_local_snapshot_bundle_sync(&store).unwrap();
                let env3 = bundle3
                    .files
                    .iter()
                    .find(|f| f.relative_path == ".env")
                    .unwrap();
                let map3: BTreeMap<String, String> = parse_dotenv_bytes(&env3.plaintext)
                    .unwrap()
                    .into_iter()
                    .collect();
                assert_eq!(
                    map3.get("API_KEY").map(String::as_str),
                    Some("token with #hash and spaces")
                );
                assert_eq!(map3.get("EXISTING_KEY").map(String::as_str), Some("alpha_1"));
                assert_eq!(map3.get("KEEP_ME").map(String::as_str), Some("beta_2"));
                assert!(map3.contains_key("JWT_SECRET"));

                // 5. `vault unset` removes ONLY KEEP_ME while preserving everything else.
                let unset_rep = vault_unset_value("KEEP_ME", ".env", true).await.unwrap();
                assert!(unset_rep.success);
                assert!(unset_rep.removed);
                assert!(unset_rep.sealed);
                assert!(!root.join(".env").exists());
                let bundle4 = load_local_snapshot_bundle_sync(&store).unwrap();
                let env4 = bundle4
                    .files
                    .iter()
                    .find(|f| f.relative_path == ".env")
                    .unwrap();
                let map4: BTreeMap<String, String> = parse_dotenv_bytes(&env4.plaintext)
                    .unwrap()
                    .into_iter()
                    .collect();
                assert!(!map4.contains_key("KEEP_ME"));
                assert_eq!(map4.get("EXISTING_KEY").map(String::as_str), Some("alpha_1"));
                assert!(map4.contains_key("JWT_SECRET"));
                assert!(map4.contains_key("API_KEY"));
                let extra4 = bundle4
                    .files
                    .iter()
                    .find(|f| f.relative_path == "config/extra.env")
                    .unwrap();
                assert_eq!(extra4.plaintext, b"EXTRA_SECRET=gamma_3\n");

                // 6. Unsetting an absent key fails closed.
                assert!(vault_unset_value("DOES_NOT_EXIST", ".env", true)
                    .await
                    .is_err());
            })
            .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn unsealed_vault_and_fresh_sealed_vault_behavior() {
        let root = std::env::temp_dir().join(format!("cv-vsec-fresh-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&root).unwrap();
        let (ctx, store) = init_test_vault(&root);

        REQUEST_VAULT_CONTEXT
            .scope(ctx.clone(), async {
                // Fresh vault with NO snapshot yet + --seal writes 0 bytes to disk!
                let gen = vault_generate_value("FIRST_KEY", "uuid", 32, ".env", true, false)
                    .await
                    .unwrap();
                assert!(gen.sealed);
                assert!(!root.join(".env").exists());

                let bundle = load_local_snapshot_bundle_sync(&store).unwrap();
                let map: BTreeMap<String, String> =
                    parse_dotenv_bytes(&bundle.files[0].plaintext)
                        .unwrap()
                        .into_iter()
                        .collect();
                assert!(map.contains_key("FIRST_KEY"));
            })
            .await;

        let _ = std::fs::remove_dir_all(&root);

        // Now test unsealed vault + policy.toml sealed_mode=true auto-seal
        let root2 = std::env::temp_dir().join(format!("cv-vsec-unsealed-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&root2).unwrap();
        let (ctx2, _store2) = init_test_vault(&root2);
        std::fs::write(root2.join(".env"), b"PREEXISTING=keep_me\n").unwrap();

        REQUEST_VAULT_CONTEXT
            .scope(ctx2.clone(), async {
                // Unsealed set preserves PREEXISTING on disk AND in snapshot
                let set1 = vault_set_value(
                    "ADDED",
                    Zeroizing::new("added_val".to_string()),
                    ".env",
                    false,
                )
                .await
                .unwrap();
                assert!(!set1.sealed);
                assert!(root2.join(".env").is_file());
                let disk = std::fs::read(root2.join(".env")).unwrap();
                let disk_map: BTreeMap<String, String> =
                    parse_dotenv_bytes(&disk).unwrap().into_iter().collect();
                assert_eq!(disk_map.get("PREEXISTING").map(String::as_str), Some("keep_me"));
                assert_eq!(disk_map.get("ADDED").map(String::as_str), Some("added_val"));

                // Enable sealed_mode = true in policy.toml -> next mutation auto-seals & shreds disk
                std::fs::write(
                    root2.join(".ciphervault/policy.toml"),
                    "[vault]\nsealed_mode = true\n",
                )
                .unwrap();
                let set2 = vault_set_value(
                    "THIRD",
                    Zeroizing::new("third_val".to_string()),
                    ".env",
                    false,
                )
                .await
                .unwrap();
                assert!(set2.sealed);
                assert!(!root2.join(".env").exists());
            })
            .await;

        let _ = std::fs::remove_dir_all(&root2);
    }
}
