use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use ciphervault_crypto::{decrypt_chunk, encrypt_chunk, VaultEpochKey};
use ciphervault_format::{
    compute_digest, from_canonical_cbor, to_canonical_cbor, ChunkWireObject, ManifestFileEntry,
    RecoveryClosure, SnapshotManifest, SnapshotRecord, PROTOCOL_VERSION,
};

use crate::chunker::chunk_and_encrypt_file;
use crate::error::SnapshotError;

pub struct SnapshotOutput {
    pub record: SnapshotRecord,
    pub encrypted_manifest: Vec<u8>,
    pub manifest_cid: [u8; 32],
    pub chunks: Vec<ChunkWireObject>,
    pub closure: RecoveryClosure,
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
    let mut manifest_entries = Vec::new();
    let mut all_chunks = Vec::new();
    let mut all_chunk_cids = Vec::new();
    let mut total_bytes = 0u64;

    for (rel_path, file_id) in tracked_files {
        let rel_str = rel_path.to_string_lossy();
        validate_safe_relative_path(&rel_str)?;
        let full_path = vault_root.join(rel_path);

        if !full_path.exists() {
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
        let pre_stat = fs::metadata(&full_path)?;
        let mut file = File::open(&full_path)?;
        let mut contents = Vec::with_capacity(pre_stat.len() as usize);
        file.read_to_end(&mut contents)?;
        let post_stat = fs::metadata(&full_path)?;

        if pre_stat.len() != post_stat.len() || pre_stat.modified()? != post_stat.modified()? {
            return Err(SnapshotError::ConcurrentModification(
                rel_path.to_string_lossy().into(),
            ));
        }

        let chunked = chunk_and_encrypt_file(vault_id, epoch, epoch_key, &contents)?;
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

    let manifest_bytes = to_canonical_cbor(&manifest)?;
    let manifest_key = epoch_key.derive_manifest_key(epoch)?;
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
    })
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

/// Restores snapshot files into a destination directory cleanly, atomically, and securely.
pub fn restore_snapshot(
    target_dir: &Path,
    vault_id: &[u8; 32],
    epoch_key: &VaultEpochKey,
    epoch: u64,
    encrypted_manifest: &[u8],
    chunks: &[ChunkWireObject],
) -> Result<Vec<PathBuf>, SnapshotError> {
    let manifest_key = epoch_key.derive_manifest_key(epoch)?;
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes = decrypt_chunk(&manifest_key, encrypted_manifest, &aad)?;
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;

    // 1. Single-pass index chunks into a HashMap by CID to avoid quadratic search and re-hashing
    let mut chunk_map: HashMap<[u8; 32], &ChunkWireObject> = HashMap::with_capacity(chunks.len());
    for chunk in chunks {
        let cid = chunk.compute_cid()?;
        chunk_map.insert(cid, chunk);
    }

    // 2. Phase 1: Decrypt and verify ALL files in memory first.
    // If ANY file fails integrity, chunk lookup, or safety checks, fail immediately without touching destination files.
    struct VerifiedFile {
        rel_path: PathBuf,
        plaintext: Vec<u8>,
    }

    let mut verified_files = Vec::new();

    for entry in manifest.files {
        if entry.is_deleted {
            continue;
        }

        // Sanitize path against directory traversal, Windows reserved names, and streams
        validate_safe_relative_path(&entry.relative_path)?;
        let rel_path = PathBuf::from(&entry.relative_path);

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
                path: entry.relative_path,
                size: entry.raw_length.max(entry.padded_length),
            });
        }
        if entry.raw_length > entry.padded_length {
            return Err(SnapshotError::IntegrityMismatch {
                path: entry.relative_path,
                expected: format!("padded >= raw (raw={})", entry.raw_length),
                actual: format!("padded={}", entry.padded_length),
            });
        }

        let mut file_version_key = [0u8; 32];
        file_version_key.copy_from_slice(&entry.file_version_key);

        let mut assembled_padded = Vec::with_capacity(entry.padded_length as usize);

        for expected_cid_vec in entry.chunk_cids.iter() {
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
                        path: entry.relative_path,
                        chunk_cid: hex::encode(expected_cid),
                    });
                }
            };

            let chunk_aad = chunk.compute_aad();
            let decrypted = decrypt_chunk(&file_version_key, &chunk.payload, &chunk_aad)?;
            assembled_padded.extend_from_slice(&decrypted);
        }

        // Strip padding down to raw length
        if (assembled_padded.len() as u64) < entry.raw_length {
            return Err(SnapshotError::IntegrityMismatch {
                path: entry.relative_path,
                expected: format!("{} bytes", entry.raw_length),
                actual: format!("{} bytes", assembled_padded.len()),
            });
        }
        let plaintext = assembled_padded[0..entry.raw_length as usize].to_vec();

        // Verify SHA-256
        let actual_sha256 = compute_digest(&plaintext);
        if actual_sha256.as_slice() != entry.plaintext_sha256.as_slice() {
            return Err(SnapshotError::IntegrityMismatch {
                path: entry.relative_path,
                expected: hex::encode(&entry.plaintext_sha256),
                actual: hex::encode(actual_sha256),
            });
        }

        verified_files.push(VerifiedFile {
            rel_path,
            plaintext,
        });
    }

    // 3. Phase 2: All files passed verification! Now publish atomically to target directory.
    fs::create_dir_all(target_dir)?;
    let mut restored_paths = Vec::new();

    for vf in verified_files {
        let out_path = target_dir.join(&vf.rel_path);

        // Symlink / junction defense: check target and its parent chain
        let mut check_path = out_path.clone();
        while check_path != target_dir {
            if let Ok(meta) = fs::symlink_metadata(&check_path) {
                if meta.file_type().is_symlink() {
                    return Err(SnapshotError::UnsafePath(format!(
                        "Refusing to restore through symlink or junction: {}",
                        check_path.display()
                    )));
                }
            }
            if let Some(parent) = check_path.parent() {
                check_path = parent.to_path_buf();
            } else {
                break;
            }
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Cryptographically unpredictable staging filename with cleanup guard
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let staging_path = target_dir.join(format!(
            ".tmp_stage_{}_{}",
            std::process::id(),
            hex::encode(nonce)
        ));

        let write_res = (|| -> Result<(), std::io::Error> {
            #[cfg(unix)]
            let mut f = {
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&staging_path)?
            };
            #[cfg(not(unix))]
            let mut f = File::create(&staging_path)?;

            f.write_all(&vf.plaintext)?;
            f.sync_all()?;
            fs::rename(&staging_path, &out_path)?;
            Ok(())
        })();

        if let Err(e) = write_res {
            let _ = fs::remove_file(&staging_path);
            return Err(SnapshotError::IoError(e));
        }

        restored_paths.push(out_path);
    }

    Ok(restored_paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::generate_signing_key;

    #[test]
    fn test_atomic_all_or_nothing_restore_on_corruption() {
        let temp_dir =
            std::env::temp_dir().join(format!("cv_atomic_restore_{}", rand::random::<u64>()));
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
}
