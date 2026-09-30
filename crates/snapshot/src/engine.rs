use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use ciphervault_crypto::{decrypt_chunk, encrypt_chunk, VaultEpochKey};
use ciphervault_crypto::{
    derive_v2_chunk_domain_key, derive_v2_chunk_id, derive_v2_chunk_key_nonce,
    derive_v2_file_version_id,
};
use ciphervault_format::{
    compute_digest, from_canonical_cbor, to_canonical_cbor, ChunkWireObject, ManifestFileEntry,
    RecoveryClosure, SnapshotManifest, SnapshotRecord, CHUNK_WIRE_VERSION_V2, PROTOCOL_VERSION,
};
use zeroize::{Zeroize, Zeroizing};

use crate::chunker::{chunk_and_encrypt_file, chunk_and_encrypt_file_v2, MAX_FILE_SIZE};
use crate::error::SnapshotError;

pub struct SnapshotOutput {
    pub record: SnapshotRecord,
    pub encrypted_manifest: Vec<u8>,
    pub manifest_cid: [u8; 32],
    pub chunks: Vec<ChunkWireObject>,
    pub closure: RecoveryClosure,
    /// Digests of the bytes committed by this capture, including deletion tombstones.
    pub captured_file_hashes: Vec<(PathBuf, Option<[u8; 32]>)>,
}

/// V2 writing remains an explicit deployment opt-in pending independent review.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ChunkWriteVersion {
    #[default]
    LegacyV1,
    V2,
}

impl ChunkWriteVersion {
    pub fn from_setting(value: Option<&str>) -> Result<Self, SnapshotError> {
        match value {
            None | Some("0") => Ok(Self::LegacyV1),
            Some("1") => Ok(Self::V2),
            _ => Err(SnapshotError::InvalidInput(
                "CIPHERVAULT_CHUNK_V2_WRITE must be exactly 0 or 1; unset defaults to legacy v1"
                    .into(),
            )),
        }
    }

    pub fn from_env() -> Result<Self, SnapshotError> {
        match std::env::var("CIPHERVAULT_CHUNK_V2_WRITE") {
            Ok(value) => Self::from_setting(Some(&value)),
            Err(std::env::VarError::NotPresent) => Self::from_setting(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(SnapshotError::InvalidInput(
                "CIPHERVAULT_CHUNK_V2_WRITE is not valid Unicode".into(),
            )),
        }
    }
}

use ciphervault_crypto::{HardwareSecurityModule, HsmSlot};

/// Device signing authority: either local software key or physical hardware token / HSM.
pub enum DeviceSigner<'a> {
    Software(&'a SigningKey),
    Hardware(&'a dyn HardwareSecurityModule, HsmSlot),
}

impl<'a> DeviceSigner<'a> {
    pub fn sign_snapshot(&self, record: &mut SnapshotRecord) -> Result<(), SnapshotError> {
        match self {
            DeviceSigner::Software(sk) => {
                record.sign(sk).map_err(SnapshotError::FormatError)?;
            }
            DeviceSigner::Hardware(hsm, slot) => {
                record
                    .sign_with_hsm(*hsm, *slot)
                    .map_err(SnapshotError::FormatError)?;
            }
        }
        Ok(())
    }
}

/// Captures and encrypts a complete snapshot from tracked files with a specified signer authority.
#[allow(
    clippy::too_many_arguments,
    reason = "Keep explicit protocol bindings in the existing public API"
)]
pub fn create_snapshot_with_signer(
    vault_root: &Path,
    tracked_files: &[(PathBuf, [u8; 32])], // (relative_path, confidential_file_id)
    vault_id: &[u8; 32],
    epoch: u64,
    epoch_key: &VaultEpochKey,
    parent_ids: Vec<[u8; 32]>,
    device_id: &[u8; 32],
    device_counter: u64,
    authority_generation: u64,
    signer: &DeviceSigner,
) -> Result<SnapshotOutput, SnapshotError> {
    create_snapshot_with_signer_and_write_version(
        vault_root,
        tracked_files,
        vault_id,
        epoch,
        epoch_key,
        parent_ids,
        device_id,
        device_counter,
        authority_generation,
        signer,
        ChunkWriteVersion::from_env()?,
    )
}

/// Capture using an explicit, caller-reviewed write policy without reading process
/// environment. Readers support both versions regardless of this writer setting.
#[allow(
    clippy::too_many_arguments,
    reason = "Explicit protocol and deployment policy bindings"
)]
pub fn create_snapshot_with_signer_and_write_version(
    vault_root: &Path,
    tracked_files: &[(PathBuf, [u8; 32])],
    vault_id: &[u8; 32],
    epoch: u64,
    epoch_key: &VaultEpochKey,
    parent_ids: Vec<[u8; 32]>,
    device_id: &[u8; 32],
    device_counter: u64,
    authority_generation: u64,
    signer: &DeviceSigner,
    write_version: ChunkWriteVersion,
) -> Result<SnapshotOutput, SnapshotError> {
    let mut manifest_entries = Vec::new();
    let mut all_chunks = Vec::new();
    let mut all_chunk_cids = Vec::new();
    let mut total_bytes = 0u64;
    let mut captured_file_hashes = Vec::new();
    validate_no_links(vault_root)?;
    let canonical_root = fs::canonicalize(vault_root)?;

    for (rel_path, file_id) in tracked_files {
        let rel_str = rel_path.to_string_lossy();
        validate_safe_relative_path(&rel_str)?;
        let full_path = vault_root.join(rel_path);
        validate_no_links(&full_path)?;

        if !full_path.exists() {
            captured_file_hashes.push((rel_path.clone(), None));
            // Tracked file was deleted -> record tombstone
            manifest_entries.push(ManifestFileEntry {
                file_id: file_id.to_vec(),
                relative_path: rel_path.to_string_lossy().replace('\\', "/"),
                file_version_id: vec![0u8; 32],
                raw_length: 0,
                padded_length: 0,
                plaintext_sha256: vec![0u8; 32],
                file_version_key: vec![0u8; 32],
                chunk_cids: Vec::new(),
                is_deleted: true,
            });
            continue;
        }

        // Coherent file read with pre/post stat checks
        if !fs::canonicalize(&full_path)?.starts_with(&canonical_root) {
            return Err(SnapshotError::UnsafePath(full_path.display().to_string()));
        }
        let mut file = ciphervault_file_lock::open_regular_file(&full_path)?;
        let pre_stat = file.metadata()?;
        if pre_stat.len() > MAX_FILE_SIZE {
            return Err(SnapshotError::FileTooLarge {
                path: rel_str.into(),
                size: pre_stat.len(),
            });
        }
        let mut contents = Zeroizing::new(Vec::with_capacity(pre_stat.len() as usize));
        (&mut file)
            .take(MAX_FILE_SIZE + 1)
            .read_to_end(&mut contents)?;
        if contents.len() as u64 > MAX_FILE_SIZE {
            return Err(SnapshotError::FileTooLarge {
                path: rel_str.into(),
                size: contents.len() as u64,
            });
        }
        let post_stat = file.metadata()?;
        validate_no_links(&full_path)?;
        if !fs::canonicalize(&full_path)?.starts_with(&canonical_root) {
            return Err(SnapshotError::UnsafePath(full_path.display().to_string()));
        }

        let path_stat = fs::metadata(&full_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if path_stat.dev() != post_stat.dev() || path_stat.ino() != post_stat.ino() {
                return Err(SnapshotError::ConcurrentModification(
                    rel_path.display().to_string(),
                ));
            }
        }
        if pre_stat.len() != post_stat.len()
            || pre_stat.modified()? != post_stat.modified()?
            || path_stat.len() != post_stat.len()
            || path_stat.modified()? != post_stat.modified()?
        {
            return Err(SnapshotError::ConcurrentModification(
                rel_path.to_string_lossy().into(),
            ));
        }

        let chunked = match write_version {
            ChunkWriteVersion::LegacyV1 => {
                chunk_and_encrypt_file(vault_id, epoch, epoch_key, &contents)?
            }
            ChunkWriteVersion::V2 => {
                chunk_and_encrypt_file_v2(vault_id, epoch, epoch_key, &contents)?
            }
        };
        captured_file_hashes.push((rel_path.clone(), Some(chunked.plaintext_sha256)));
        total_bytes += chunked.raw_length;

        let mut file_chunk_cids = Vec::new();
        for chunk in chunked.chunks {
            let cid = chunk.compute_cid()?;
            file_chunk_cids.push(cid.to_vec());
            all_chunk_cids.push(cid.to_vec());
            all_chunks.push(chunk);
        }

        manifest_entries.push(ManifestFileEntry {
            file_id: file_id.to_vec(),
            relative_path: rel_path.to_string_lossy().replace('\\', "/"),
            file_version_id: chunked.file_version_id.to_vec(),
            raw_length: chunked.raw_length,
            padded_length: chunked.padded_length,
            plaintext_sha256: chunked.plaintext_sha256.to_vec(),
            file_version_key: chunked.file_version_key.as_bytes().to_vec(),
            chunk_cids: file_chunk_cids,
            is_deleted: false,
        });
    }

    let mut snapshot_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut snapshot_id);

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
        parent_snapshot_ids: parent_ids.into_iter().map(|id| id.to_vec()).collect(),
        device_id: device_id.to_vec(),
        device_counter,
        authority_generation,
        epoch,
        encrypted_manifest_cid: manifest_cid.to_vec(),
        encrypted_manifest_len: encrypted_manifest.len() as u64,
        advisory_timestamp_utc: Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    signer.sign_snapshot(&mut record)?;

    let record_cid = record.compute_record_cid()?;

    let closure = RecoveryClosure {
        snapshot_id: snapshot_id.to_vec(),
        snapshot_record_cid: record_cid.to_vec(),
        manifest_cid: manifest_cid.to_vec(),
        envelope_ids: Vec::new(), // Populated by coordinator/store
        chunk_cids: all_chunk_cids,
        total_bytes,
    };

    Ok(SnapshotOutput {
        record,
        encrypted_manifest,
        manifest_cid,
        chunks: all_chunks,
        closure,
        captured_file_hashes,
    })
}

pub(crate) fn validate_no_links(path: &Path) -> Result<(), SnapshotError> {
    for component in path.ancestors() {
        match fs::symlink_metadata(component) {
            Ok(metadata) => {
                let link = metadata.file_type().is_symlink();
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(SnapshotError::UnsafePath(format!(
                            "Refusing reparse point: {}",
                            component.display()
                        )));
                    }
                }
                if link {
                    return Err(SnapshotError::UnsafePath(format!(
                        "Refusing symlink or reparse point: {}",
                        component.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Captures and encrypts a complete snapshot from tracked files on the local filesystem using a software signing key.
#[allow(
    clippy::too_many_arguments,
    reason = "Keep explicit protocol bindings in the existing public API"
)]
pub fn create_snapshot(
    vault_root: &Path,
    tracked_files: &[(PathBuf, [u8; 32])],
    vault_id: &[u8; 32],
    epoch: u64,
    epoch_key: &VaultEpochKey,
    parent_ids: Vec<[u8; 32]>,
    device_id: &[u8; 32],
    device_counter: u64,
    authority_generation: u64,
    device_sk: &SigningKey,
) -> Result<SnapshotOutput, SnapshotError> {
    create_snapshot_with_signer(
        vault_root,
        tracked_files,
        vault_id,
        epoch,
        epoch_key,
        parent_ids,
        device_id,
        device_counter,
        authority_generation,
        &DeviceSigner::Software(device_sk),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "Explicit protocol and deployment policy bindings"
)]
pub fn create_snapshot_with_write_version(
    vault_root: &Path,
    tracked_files: &[(PathBuf, [u8; 32])],
    vault_id: &[u8; 32],
    epoch: u64,
    epoch_key: &VaultEpochKey,
    parent_ids: Vec<[u8; 32]>,
    device_id: &[u8; 32],
    device_counter: u64,
    authority_generation: u64,
    device_sk: &SigningKey,
    write_version: ChunkWriteVersion,
) -> Result<SnapshotOutput, SnapshotError> {
    create_snapshot_with_signer_and_write_version(
        vault_root,
        tracked_files,
        vault_id,
        epoch,
        epoch_key,
        parent_ids,
        device_id,
        device_counter,
        authority_generation,
        &DeviceSigner::Software(device_sk),
        write_version,
    )
}

/// Validates that a relative path is cross-platform safe:
/// - No directory traversal (`..`) or root components
/// - No Windows reserved DOS device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
/// - No NTFS Alternate Data Streams (colons `:`)
/// - No null bytes or non-printable ASCII control characters (< 0x20)
/// - No trailing dots or spaces on path components
pub fn validate_safe_relative_path(path_str: &str) -> Result<(), SnapshotError> {
    if path_str.is_empty() {
        return Err(SnapshotError::UnsafePath("Path cannot be empty".into()));
    }

    // Reject null bytes, control characters, or Windows forbidden stream characters
    for ch in path_str.chars() {
        if ch < ' '
            || ch == '\0'
            || ch == '<'
            || ch == '>'
            || ch == ':'
            || ch == '"'
            || ch == '|'
            || ch == '?'
            || ch == '*'
        {
            return Err(SnapshotError::UnsafePath(format!(
                "Path contains illegal character '{}': {}",
                ch, path_str
            )));
        }
    }

    // Normalize slashes for component iteration
    let normalized = path_str.replace('\\', "/");
    let p = Path::new(&normalized);

    for comp in p.components() {
        match comp {
            Component::Normal(c) => {
                let s = c.to_string_lossy();
                // Windows strips trailing spaces and dots, which can create file collision vulnerabilities
                if s.ends_with('.') || s.ends_with(' ') {
                    return Err(SnapshotError::UnsafePath(format!(
                        "Component ends with space or dot: {}",
                        path_str
                    )));
                }

                // Check Windows reserved DOS device names (case-insensitive, with or without extension)
                let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
                match stem.as_str() {
                    "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5"
                    | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4"
                    | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9" => {
                        return Err(SnapshotError::UnsafePath(format!(
                            "Windows reserved device name rejected: {}",
                            path_str
                        )));
                    }
                    _ => {}
                }
            }
            _ => {
                return Err(SnapshotError::UnsafePath(format!(
                    "Unsafe path component rejected: {}",
                    path_str
                )));
            }
        }
    }

    Ok(())
}

const MAX_RESTORE_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

/// A decrypted file from a snapshot stored strictly in memory.
#[derive(Clone)]
pub struct DecryptedFile {
    pub relative_path: String,
    pub plaintext: Vec<u8>,
}

impl Drop for DecryptedFile {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}
impl std::fmt::Debug for DecryptedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedFile")
            .field("relative_path", &self.relative_path)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

/// Decrypts all files from a snapshot manifest strictly in memory without writing anything to disk.
pub fn decrypt_snapshot(
    vault_id: &[u8; 32],
    epoch_key: &VaultEpochKey,
    epoch: u64,
    encrypted_manifest: &[u8],
    chunks: &[ChunkWireObject],
) -> Result<Vec<DecryptedFile>, SnapshotError> {
    let manifest_key = Zeroizing::new(epoch_key.derive_manifest_key(epoch)?);
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes = Zeroizing::new(decrypt_chunk(&manifest_key, encrypted_manifest, &aad)?);
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;
    if manifest.version != PROTOCOL_VERSION
        || manifest.vault_id != vault_id
        || manifest.epoch != epoch
    {
        return Err(SnapshotError::InvalidInput(
            "Manifest version/vault/epoch mismatch".into(),
        ));
    }
    let domain_key = Zeroizing::new(derive_v2_chunk_domain_key(
        epoch_key.as_bytes(),
        vault_id,
        epoch,
    ));

    // 1. Single-pass index chunks into a HashMap by CID to avoid quadratic search and re-hashing
    let mut chunk_map: HashMap<[u8; 32], &ChunkWireObject> = HashMap::with_capacity(chunks.len());
    for chunk in chunks {
        let cid = chunk.compute_cid()?;
        chunk_map.insert(cid, chunk);
    }

    // 2. Decrypt and verify ALL files in memory
    let mut decrypted_files = Vec::new();

    for entry in &manifest.files {
        if entry.is_deleted {
            continue;
        }

        // Sanitize path against directory traversal, Windows reserved names, and streams
        validate_safe_relative_path(&entry.relative_path)?;

        // Bounds enforcement on input schema
        if entry.file_version_key.len() != 32 {
            return Err(SnapshotError::InvalidInput(format!(
                "Invalid file_version_key length for {}: expected 32, got {}",
                entry.relative_path,
                entry.file_version_key.len()
            )));
        }
        if entry.padded_length > MAX_RESTORE_FILE_SIZE || entry.raw_length > MAX_RESTORE_FILE_SIZE {
            return Err(SnapshotError::FileTooLarge {
                path: entry.relative_path.clone(),
                size: entry.raw_length.max(entry.padded_length),
            });
        }
        if entry.raw_length > entry.padded_length {
            return Err(SnapshotError::IntegrityMismatch {
                path: entry.relative_path.clone(),
                expected: format!("padded >= raw (raw={})", entry.raw_length),
                actual: format!("padded={}", entry.padded_length),
            });
        }

        let mut file_version_key = Zeroizing::new([0u8; 32]);
        file_version_key.copy_from_slice(&entry.file_version_key);

        let mut assembled_padded = Zeroizing::new(Vec::with_capacity(entry.padded_length as usize));
        let mut wire_version = None;

        for (position, expected_cid_vec) in entry.chunk_cids.iter().enumerate() {
            if expected_cid_vec.len() != 32 {
                return Err(SnapshotError::InvalidInput(format!(
                    "Invalid chunk CID length for {}",
                    entry.relative_path
                )));
            }
            let mut expected_cid = [0u8; 32];
            expected_cid.copy_from_slice(expected_cid_vec);

            let chunk = match chunk_map.get(&expected_cid) {
                Some(c) => *c,
                None => {
                    return Err(SnapshotError::MissingChunk {
                        path: entry.relative_path.clone(),
                        chunk_cid: hex::encode(expected_cid),
                    });
                }
            };

            if chunk.vault_id != vault_id
                || chunk.key_epoch != epoch
                || chunk.file_version_id.len() != 32
            {
                return Err(SnapshotError::InvalidInput(
                    "Chunk vault/epoch/identifier mismatch".into(),
                ));
            }
            let chunk_aad = chunk.compute_aad();
            if wire_version.is_some_and(|version| version != chunk.version) {
                return Err(SnapshotError::InvalidInput(
                    "Mixed chunk wire versions in one file".into(),
                ));
            }
            wire_version = Some(chunk.version);
            let decrypted = Zeroizing::new(match chunk.version {
                PROTOCOL_VERSION => {
                    if chunk.file_version_id != entry.file_version_id
                        || chunk.chunk_index as usize != position
                        || chunk.total_chunks as usize != entry.chunk_cids.len()
                    {
                        return Err(SnapshotError::InvalidInput(
                            "Legacy chunk order/file binding mismatch".into(),
                        ));
                    }
                    decrypt_chunk(&file_version_key, &chunk.payload, &chunk_aad)?
                }
                CHUNK_WIRE_VERSION_V2 => {
                    if chunk.chunk_index != 0
                        || chunk.total_chunks != 1
                        || file_version_key.as_ref() != domain_key.as_ref()
                    {
                        return Err(SnapshotError::InvalidInput(
                            "Invalid v2 chunk header or domain key".into(),
                        ));
                    }
                    let opaque_id: [u8; 32] = chunk.file_version_id.as_slice().try_into().unwrap();
                    let (key, nonce) =
                        derive_v2_chunk_key_nonce(&domain_key, vault_id, epoch, &opaque_id);
                    if chunk.payload.get(..24) != Some(nonce.as_slice()) {
                        return Err(SnapshotError::InvalidInput(
                            "Invalid v2 deterministic nonce".into(),
                        ));
                    }
                    let plaintext =
                        Zeroizing::new(decrypt_chunk(&key, &chunk.payload, &chunk_aad)?);
                    if derive_v2_chunk_id(&domain_key, vault_id, epoch, &compute_digest(&plaintext))
                        != opaque_id
                    {
                        return Err(SnapshotError::InvalidInput(
                            "V2 opaque chunk identifier mismatch".into(),
                        ));
                    }
                    plaintext.to_vec()
                }
                _ => {
                    return Err(SnapshotError::InvalidInput(
                        "Unsupported chunk wire version".into(),
                    ))
                }
            });
            if decrypted.len() != chunk.declared_padded_length as usize
                || assembled_padded.len().saturating_add(decrypted.len())
                    > entry.padded_length as usize
            {
                return Err(SnapshotError::InvalidInput(
                    "Chunk/manifest padded length mismatch".into(),
                ));
            }
            assembled_padded.extend_from_slice(&decrypted);
        }

        // Strip padding down to raw length
        if assembled_padded.len() as u64 != entry.padded_length {
            return Err(SnapshotError::IntegrityMismatch {
                path: entry.relative_path.clone(),
                expected: format!("{} bytes", entry.raw_length),
                actual: format!("{} bytes", assembled_padded.len()),
            });
        }
        let mut plaintext = Zeroizing::new(assembled_padded[0..entry.raw_length as usize].to_vec());

        // Verify SHA-256
        let actual_sha256 = compute_digest(&plaintext);
        if actual_sha256.as_slice() != entry.plaintext_sha256.as_slice() {
            return Err(SnapshotError::IntegrityMismatch {
                path: entry.relative_path.clone(),
                expected: hex::encode(&entry.plaintext_sha256),
                actual: hex::encode(actual_sha256),
            });
        }
        if wire_version == Some(CHUNK_WIRE_VERSION_V2)
            && derive_v2_file_version_id(&domain_key, vault_id, epoch, &actual_sha256).as_slice()
                != entry.file_version_id
        {
            return Err(SnapshotError::InvalidInput(
                "V2 file version identifier mismatch".into(),
            ));
        }

        decrypted_files.push(DecryptedFile {
            relative_path: entry.relative_path.clone(),
            plaintext: std::mem::take(&mut *plaintext),
        });
    }

    Ok(decrypted_files)
}

/// Restores snapshot files into a destination directory cleanly, atomically, and securely.
pub fn restore_snapshot(
    target_dir: &Path,
    vault_id: &[u8; 32],
    epoch_key: &VaultEpochKey,
    epoch: u64,
    encrypted_manifest: &[u8],
    chunks: &[ChunkWireObject],
) -> Result<Vec<PathBuf>, SnapshotError> {
    let verified_files = decrypt_snapshot(vault_id, epoch_key, epoch, encrypted_manifest, chunks)?;

    crate::restore::publish_verified_files(target_dir, &verified_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::generate_signing_key;

    fn encrypt_test_manifest(
        vault: &[u8; 32],
        epoch_key: &VaultEpochKey,
        manifest: &SnapshotManifest,
    ) -> Vec<u8> {
        let aad = [
            b"CipherVault-Manifest:",
            vault.as_slice(),
            &manifest.epoch.to_le_bytes(),
        ]
        .concat();
        encrypt_chunk(
            &epoch_key.derive_manifest_key(manifest.epoch).unwrap(),
            &to_canonical_cbor(manifest).unwrap(),
            &aad,
        )
        .unwrap()
    }

    #[test]
    fn legacy_snapshot_still_decrypts_without_changing_v1_wire_addresses() {
        let vault = [5; 32];
        let epoch_key = VaultEpochKey::from_bytes([6; 32]);
        let data = b"LEGACY_SYNTHETIC_TOKEN=protected\n";
        let chunked = crate::chunker::chunk_and_encrypt_file(&vault, 1, &epoch_key, data).unwrap();
        assert_eq!(
            hex::encode(chunked.file_version_id),
            "af05fcbea7dfdbdca8b13a97527196ff1146e40c6d99527d38e50f1e6822e827"
        );
        let entry = ManifestFileEntry {
            file_id: vec![7; 32],
            relative_path: "legacy.env".into(),
            file_version_id: chunked.file_version_id.to_vec(),
            raw_length: chunked.raw_length,
            padded_length: chunked.padded_length,
            plaintext_sha256: chunked.plaintext_sha256.to_vec(),
            file_version_key: chunked.file_version_key.as_bytes().to_vec(),
            chunk_cids: chunked
                .chunks
                .iter()
                .map(|c| c.compute_cid().unwrap().to_vec())
                .collect(),
            is_deleted: false,
        };
        let manifest = SnapshotManifest {
            version: 1,
            vault_id: vault.to_vec(),
            epoch: 1,
            snapshot_id: vec![8; 32],
            files: vec![entry],
        };
        let legacy_wire = to_canonical_cbor(&chunked.chunks[0]).unwrap();
        let decoded: ChunkWireObject = from_canonical_cbor(&legacy_wire).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.compute_cid().unwrap(), compute_digest(&legacy_wire));
        let files = decrypt_snapshot(
            &vault,
            &epoch_key,
            1,
            &encrypt_test_manifest(&vault, &epoch_key, &manifest),
            &chunked.chunks,
        )
        .unwrap();
        assert_eq!(files[0].plaintext, data);
    }

    #[test]
    fn v2_reordered_manifest_chunks_and_unknown_wire_versions_are_rejected() {
        let vault = [5; 32];
        let epoch_key = VaultEpochKey::from_bytes([6; 32]);
        let data: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let chunked =
            crate::chunker::chunk_and_encrypt_file_v2(&vault, 1, &epoch_key, &data).unwrap();
        assert!(chunked.chunks.len() > 1);
        let entry = ManifestFileEntry {
            file_id: vec![7; 32],
            relative_path: "synthetic.env".into(),
            file_version_id: chunked.file_version_id.to_vec(),
            raw_length: chunked.raw_length,
            padded_length: chunked.padded_length,
            plaintext_sha256: chunked.plaintext_sha256.to_vec(),
            file_version_key: chunked.file_version_key.as_bytes().to_vec(),
            chunk_cids: chunked
                .chunks
                .iter()
                .map(|c| c.compute_cid().unwrap().to_vec())
                .collect(),
            is_deleted: false,
        };
        let mut manifest = SnapshotManifest {
            version: 1,
            vault_id: vault.to_vec(),
            epoch: 1,
            snapshot_id: vec![8; 32],
            files: vec![entry],
        };
        assert_eq!(
            decrypt_snapshot(
                &vault,
                &epoch_key,
                1,
                &encrypt_test_manifest(&vault, &epoch_key, &manifest),
                &chunked.chunks
            )
            .unwrap()[0]
                .plaintext,
            data
        );
        manifest.files[0].chunk_cids.reverse();
        assert!(decrypt_snapshot(
            &vault,
            &epoch_key,
            1,
            &encrypt_test_manifest(&vault, &epoch_key, &manifest),
            &chunked.chunks
        )
        .is_err());
        manifest.files[0].chunk_cids.reverse();
        let mut chunks = chunked.chunks.clone();
        chunks[0].version = 99;
        manifest.files[0].chunk_cids[0] = chunks[0].compute_cid().unwrap().to_vec();
        assert!(decrypt_snapshot(
            &vault,
            &epoch_key,
            1,
            &encrypt_test_manifest(&vault, &epoch_key, &manifest),
            &chunks
        )
        .unwrap_err()
        .to_string()
        .contains("Unsupported chunk"));
        chunks[0] = chunked.chunks[0].clone();
        chunks[0].key_epoch = 2;
        manifest.files[0].chunk_cids[0] = chunks[0].compute_cid().unwrap().to_vec();
        assert!(decrypt_snapshot(
            &vault,
            &epoch_key,
            1,
            &encrypt_test_manifest(&vault, &epoch_key, &manifest),
            &chunks
        )
        .is_err());
    }

    #[test]
    fn capture_write_gate_defaults_to_compatible_v1_and_rejects_invalid_settings() {
        assert_eq!(
            ChunkWriteVersion::from_setting(None).unwrap(),
            ChunkWriteVersion::LegacyV1
        );
        assert_eq!(
            ChunkWriteVersion::from_setting(Some("0")).unwrap(),
            ChunkWriteVersion::LegacyV1
        );
        assert_eq!(
            ChunkWriteVersion::from_setting(Some("1")).unwrap(),
            ChunkWriteVersion::V2
        );
        for value in ["", "true", "false", "2", " 1", "1\n"] {
            assert!(ChunkWriteVersion::from_setting(Some(value)).is_err());
        }
        let root =
            std::env::temp_dir().join(format!("cv-v1-default-{:032x}", rand::random::<u128>()));
        fs::create_dir_all(&root).unwrap();
        // macOS temp paths may include /var -> /private/var; resolve the fixture root.
        let root = fs::canonicalize(root).unwrap();
        let bytes = b"SYNTHETIC_DEFAULT_CAPTURE=compatible\n";
        fs::write(root.join("synthetic.env"), bytes).unwrap();
        let vault = [51; 32];
        let key = VaultEpochKey::from_bytes([52; 32]);
        let capture = create_snapshot_with_write_version(
            &root,
            &[(PathBuf::from("synthetic.env"), [53; 32])],
            &vault,
            1,
            &key,
            vec![],
            &[54; 32],
            1,
            1,
            &generate_signing_key(),
            ChunkWriteVersion::default(),
        )
        .unwrap();
        let legacy = chunk_and_encrypt_file(&vault, 1, &key, bytes).unwrap();
        assert_eq!(
            capture.chunks, legacy.chunks,
            "Default must preserve v1 ciphertext addresses"
        );
        assert!(capture
            .chunks
            .iter()
            .all(|chunk| chunk.version == PROTOCOL_VERSION));
        assert_eq!(
            decrypt_snapshot(
                &vault,
                &key,
                1,
                &capture.encrypted_manifest,
                &capture.chunks
            )
            .unwrap()[0]
                .plaintext,
            bytes
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_repeated_identical_chunks_round_trip_from_unique_stored_objects() {
        let root =
            std::env::temp_dir().join(format!("cv-v2-repeat-{:032x}", rand::random::<u128>()));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        // Repeated content forces identical standalone chunks under every
        // supported chunk profile, plus one short trailing chunk.
        let content = vec![0u8; 1024 * 1024 + 23];
        fs::write(root.join("repeated.bin"), &content).unwrap();
        let vault = [31; 32];
        let epoch_key = VaultEpochKey::from_bytes([32; 32]);
        let output = create_snapshot_with_write_version(
            &root,
            &[(PathBuf::from("repeated.bin"), [33; 32])],
            &vault,
            1,
            &epoch_key,
            vec![],
            &[34; 32],
            1,
            1,
            &generate_signing_key(),
            ChunkWriteVersion::V2,
        )
        .unwrap();
        let mut unique = HashMap::new();
        for chunk in &output.chunks {
            unique.insert(chunk.compute_cid().unwrap(), chunk.clone());
        }
        assert!(
            unique.len() < output.chunks.len(),
            "Fixture must contain duplicate chunk references"
        );
        let objects: Vec<_> = unique.into_values().collect();
        let files =
            decrypt_snapshot(&vault, &epoch_key, 1, &output.encrypted_manifest, &objects).unwrap();
        assert_eq!(files[0].plaintext, content);
        let restored = root.join("restored");
        restore_snapshot(
            &restored,
            &vault,
            &epoch_key,
            1,
            &output.encrypted_manifest,
            &objects,
        )
        .unwrap();
        assert_eq!(fs::read(restored.join("repeated.bin")).unwrap(), content);
        let mut changed = content.clone();
        changed[1024 * 1024..].fill(7);
        fs::write(root.join("repeated.bin"), &changed).unwrap();
        let edited = create_snapshot_with_write_version(
            &root,
            &[(PathBuf::from("repeated.bin"), [33; 32])],
            &vault,
            1,
            &epoch_key,
            vec![],
            &[34; 32],
            2,
            1,
            &generate_signing_key(),
            ChunkWriteVersion::V2,
        )
        .unwrap();
        let prior: std::collections::HashSet<_> = objects
            .iter()
            .map(|chunk| chunk.compute_cid().unwrap())
            .collect();
        let reused = edited
            .chunks
            .iter()
            .filter(|chunk| prior.contains(&chunk.compute_cid().unwrap()))
            .count();
        assert!(
            reused >= edited.chunks.len() - 1,
            "Unedited repeated chunks must keep their v2 CIDs"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capture_bounds_checked_before_read_and_tombstone_hashes_are_reported() {
        let root =
            std::env::temp_dir().join(format!("cv-capture-bounds-{:032x}", rand::random::<u128>()));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let file = fs::File::create(root.join("huge.env")).unwrap();
        file.set_len(MAX_FILE_SIZE + 1).unwrap();
        let vault = [5; 32];
        let epoch_key = VaultEpochKey::generate();
        let signer = generate_signing_key();
        let tracked = vec![(PathBuf::from("huge.env"), [6; 32])];
        assert!(matches!(
            create_snapshot(
                &root,
                &tracked,
                &vault,
                1,
                &epoch_key,
                vec![],
                &[7; 32],
                1,
                1,
                &signer
            ),
            Err(SnapshotError::FileTooLarge { .. })
        ));
        drop(file);
        fs::remove_file(root.join("huge.env")).unwrap();
        let output = create_snapshot(
            &root,
            &tracked,
            &vault,
            1,
            &epoch_key,
            vec![],
            &[7; 32],
            1,
            1,
            &signer,
        )
        .unwrap();
        assert_eq!(
            output.captured_file_hashes,
            vec![(PathBuf::from("huge.env"), None)]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn capture_refuses_final_and_parent_symlinks() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "cv-capture-symlink-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir_all(root.join("vault")).unwrap();
        fs::create_dir_all(root.join("outside")).unwrap();
        let root = fs::canonicalize(root).unwrap();
        fs::write(root.join("outside/secret.env"), b"OUTSIDE=must_not_capture").unwrap();
        symlink(
            root.join("outside/secret.env"),
            root.join("vault/final.env"),
        )
        .unwrap();
        symlink(root.join("outside"), root.join("vault/link")).unwrap();
        let vault = [5; 32];
        let epoch_key = VaultEpochKey::generate();
        let signer = generate_signing_key();
        for path in ["final.env", "link/secret.env"] {
            assert!(matches!(
                create_snapshot(
                    &root.join("vault"),
                    &[(PathBuf::from(path), [6; 32])],
                    &vault,
                    1,
                    &epoch_key,
                    vec![],
                    &[7; 32],
                    1,
                    1,
                    &signer
                ),
                Err(SnapshotError::UnsafePath(_))
            ));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_atomic_all_or_nothing_restore_on_corruption() {
        let temp_dir =
            std::env::temp_dir().join(format!("cv_atomic_restore_{}", rand::random::<u64>()));
        fs::create_dir_all(&temp_dir).unwrap();
        let temp_dir = fs::canonicalize(temp_dir).unwrap();
        let vault_root = temp_dir.join("vault_root");
        let restore_target = temp_dir.join("restore_target");
        fs::create_dir_all(&vault_root).unwrap();

        let file1 = vault_root.join("file1.txt");
        let file2 = vault_root.join("file2.txt");
        fs::write(&file1, b"Valid confidential file 1").unwrap();
        fs::write(&file2, b"Valid confidential file 2").unwrap();

        let tracked = vec![
            (PathBuf::from("file1.txt"), [1u8; 32]),
            (PathBuf::from("file2.txt"), [2u8; 32]),
        ];

        let vault_id = [0x55u8; 32];
        let epoch_key = VaultEpochKey::generate();
        let dev_sk = generate_signing_key();
        let dev_id = [0x66u8; 32];

        let snap = create_snapshot(
            &vault_root,
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

        // Tamper chunks: remove or corrupt chunks for file2
        let mut tampered_chunks = snap.chunks.clone();
        // Drop the last chunk
        tampered_chunks.pop();

        let res = restore_snapshot(
            &restore_target,
            &vault_id,
            &epoch_key,
            1,
            &snap.encrypted_manifest,
            &tampered_chunks,
        );

        assert!(res.is_err(), "Restore must fail due to missing chunk");

        // INVARIANT: file1 must NOT exist in restore_target (all-or-nothing atomicity!)
        let restored_file1 = restore_target.join("file1.txt");
        assert!(
            !restored_file1.exists(),
            "Atomicity violated: file1 was written to disk despite failure on file2!"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_restore_bounds_enforcement_and_rejection() {
        let temp_dir = std::env::temp_dir().join(format!("cv_bounds_{}", rand::random::<u64>()));
        fs::create_dir_all(&temp_dir).unwrap();
        let temp_dir = fs::canonicalize(temp_dir).unwrap();
        let restore_target = temp_dir.join("target");
        fs::create_dir_all(&restore_target).unwrap();

        let vault_id = [0x55u8; 32];
        let epoch_key = VaultEpochKey::generate();

        // Craft manifest with invalid file_version_key length
        let bad_manifest = SnapshotManifest {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            epoch: 1,
            snapshot_id: vec![0x11u8; 32],
            files: vec![ManifestFileEntry {
                file_id: vec![1u8; 32],
                relative_path: "secret.txt".into(),
                file_version_id: vec![2u8; 32],
                raw_length: 10,
                padded_length: 16,
                plaintext_sha256: vec![0u8; 32],
                file_version_key: vec![0u8; 16], // Invalid length! Must be 32
                chunk_cids: Vec::new(),
                is_deleted: false,
            }],
        };

        let manifest_bytes = to_canonical_cbor(&bad_manifest).unwrap();
        let manifest_key = epoch_key.derive_manifest_key(1).unwrap();
        let aad = [
            b"CipherVault-Manifest:",
            vault_id.as_slice(),
            &1u64.to_le_bytes(),
        ]
        .concat();
        let encrypted_manifest = encrypt_chunk(&manifest_key, &manifest_bytes, &aad).unwrap();

        let res = restore_snapshot(
            &restore_target,
            &vault_id,
            &epoch_key,
            1,
            &encrypted_manifest,
            &[],
        );

        match res {
            Err(SnapshotError::InvalidInput(msg)) => {
                assert!(msg.contains("Invalid file_version_key length"));
            }
            other => panic!("Expected InvalidInput error, got: {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_decrypt_snapshot_in_memory() {
        let temp_dir =
            std::env::temp_dir().join(format!("cv_decrypt_mem_{}", rand::random::<u64>()));
        fs::create_dir_all(&temp_dir).unwrap();
        let temp_dir = fs::canonicalize(temp_dir).unwrap();
        let vault_root = temp_dir.join("vault_root");
        fs::create_dir_all(&vault_root).unwrap();

        let env_file = vault_root.join(".env");
        fs::write(
            &env_file,
            b"DATABASE_URL=postgres://localhost\nSECRET_KEY=12345",
        )
        .unwrap();

        let tracked = vec![(PathBuf::from(".env"), [1u8; 32])];
        let vault_id = [0x77u8; 32];
        let epoch_key = VaultEpochKey::generate();
        let dev_sk = generate_signing_key();
        let dev_id = [0x88u8; 32];

        let snap = create_snapshot(
            &vault_root,
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

        let decrypted = decrypt_snapshot(
            &vault_id,
            &epoch_key,
            1,
            &snap.encrypted_manifest,
            &snap.chunks,
        )
        .unwrap();

        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].relative_path, ".env");
        assert_eq!(
            decrypted[0].plaintext,
            b"DATABASE_URL=postgres://localhost\nSECRET_KEY=12345"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
