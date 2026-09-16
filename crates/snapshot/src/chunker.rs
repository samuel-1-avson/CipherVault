use ciphervault_crypto::{
    derive_chunk_nonce, derive_file_version_id, encrypt_chunk_with_nonce, FileVersionKey,
    VaultEpochKey,
};
use ciphervault_format::{compute_digest, ChunkWireObject, PROTOCOL_VERSION};

use crate::error::SnapshotError;
use crate::fastcdc::{
    config_from_env, fastcdc_chunk, DEFAULT_AVG_SIZE, DEFAULT_MAX_SIZE, DEFAULT_MIN_SIZE,
};

pub const MIN_CHUNK_SIZE: usize = DEFAULT_MIN_SIZE; // 4 KiB
pub const AVG_CHUNK_SIZE: usize = DEFAULT_AVG_SIZE; // 16 KiB
pub const MAX_CHUNK_SIZE: usize = DEFAULT_MAX_SIZE; // 64 KiB
pub const CHUNK_SIZE: usize = AVG_CHUNK_SIZE;
pub const MIN_PADDING_SIZE: usize = 4096; // 4 KiB bucket for small files
pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB MVP limit

pub struct ChunkedFile {
    pub file_version_id: [u8; 32],
    pub file_version_key: FileVersionKey,
    pub raw_length: u64,
    pub padded_length: u64,
    pub plaintext_sha256: [u8; 32],
    pub chunks: Vec<ChunkWireObject>,
}

/// Chunks and encrypts a plaintext buffer according to CipherVault specifications.
/// Uses deterministic convergent chunking keyed by VaultEpochKey to enable cross-snapshot deduplication
/// while preventing cross-vault equality leakage.
pub fn chunk_and_encrypt_file(
    vault_id: &[u8; 32],
    key_epoch: u64,
    epoch_key: &VaultEpochKey,
    plaintext: &[u8],
) -> Result<ChunkedFile, SnapshotError> {
    let raw_length = plaintext.len() as u64;
    if raw_length > MAX_FILE_SIZE {
        return Err(SnapshotError::FileTooLarge {
            path: "in-memory".into(),
            size: raw_length,
        });
    }

    let plaintext_sha256 = compute_digest(plaintext);

    let file_version_id = derive_file_version_id(vault_id, key_epoch, &plaintext_sha256);
    let file_version_key = epoch_key.derive_file_version_key(key_epoch, &plaintext_sha256)?;

    // Determine padding for small files to mitigate size leakage
    let (padded_bytes, padded_length) = if raw_length < MIN_PADDING_SIZE as u64 {
        let mut padded = plaintext.to_vec();
        padded.resize(MIN_PADDING_SIZE, 0u8);
        let len = padded.len() as u64;
        (padded, len)
    } else {
        (plaintext.to_vec(), raw_length)
    };

    let config = config_from_env();
    let raw_chunks: Vec<&[u8]> = fastcdc_chunk(&padded_bytes, &config);
    let total_chunks = raw_chunks.len() as u32;

    let mut chunks = Vec::with_capacity(raw_chunks.len());

    for (i, raw_chunk) in raw_chunks.into_iter().enumerate() {
        let chunk_index = i as u32;

        let dummy_chunk = ChunkWireObject {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            file_version_id: file_version_id.to_vec(),
            chunk_index,
            total_chunks,
            declared_padded_length: raw_chunk.len() as u32,
            key_epoch,
            payload: Vec::new(),
        };

        let aad = dummy_chunk.compute_aad();
        let chunk_digest = compute_digest(raw_chunk);
        let nonce = derive_chunk_nonce(file_version_key.as_bytes(), chunk_index, &chunk_digest);
        let payload =
            encrypt_chunk_with_nonce(file_version_key.as_bytes(), &nonce, raw_chunk, &aad)?;

        chunks.push(ChunkWireObject {
            payload,
            ..dummy_chunk
        });
    }

    Ok(ChunkedFile {
        file_version_id,
        file_version_key,
        raw_length,
        padded_length,
        plaintext_sha256,
        chunks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::decrypt_chunk;

    #[test]
    fn test_chunking_small_file_padding() {
        let vault_id = [0x11u8; 32];
        let epoch_key = VaultEpochKey::generate();
        let content = b"SECRET=true\nPORT=8080";
        let chunked = chunk_and_encrypt_file(&vault_id, 1, &epoch_key, content).unwrap();

        assert_eq!(chunked.raw_length, content.len() as u64);
        assert_eq!(chunked.padded_length, MIN_PADDING_SIZE as u64);
        assert_eq!(chunked.chunks.len(), 1);
        assert_eq!(chunked.chunks[0].chunk_index, 0);
        assert_eq!(chunked.chunks[0].total_chunks, 1);
    }

    #[test]
    fn test_content_defined_chunk_deduplication_and_isolation() {
        let vault_id_a = [0x11u8; 32];
        let vault_id_b = [0x22u8; 32];
        let epoch_key_a = VaultEpochKey::generate();
        let epoch_key_b = VaultEpochKey::generate();

        let content =
            b"CONFIG_ENDPOINT=https://cluster.local:8443/secrets\nSERVICE_TOKEN=synthetic_token_123456789";

        // Snapshot 1 capture
        let chunked_snap1 = chunk_and_encrypt_file(&vault_id_a, 1, &epoch_key_a, content).unwrap();
        // Snapshot 2 capture with unchanged file
        let chunked_snap2 = chunk_and_encrypt_file(&vault_id_a, 1, &epoch_key_a, content).unwrap();

        // 1. Same vault & epoch produces IDENTICAL chunk CIDs (F12 resolved)
        assert_eq!(chunked_snap1.file_version_id, chunked_snap2.file_version_id);
        assert_eq!(
            chunked_snap1.file_version_key.as_bytes(),
            chunked_snap2.file_version_key.as_bytes()
        );
        assert_eq!(chunked_snap1.chunks.len(), chunked_snap2.chunks.len());
        for (c1, c2) in chunked_snap1.chunks.iter().zip(chunked_snap2.chunks.iter()) {
            assert_eq!(c1.payload, c2.payload);
            assert_eq!(c1.compute_cid().unwrap(), c2.compute_cid().unwrap());
        }

        // 2. Decrypt roundtrip matches padded plaintext
        let aad = chunked_snap1.chunks[0].compute_aad();
        let decrypted = decrypt_chunk(
            chunked_snap1.file_version_key.as_bytes(),
            &chunked_snap1.chunks[0].payload,
            &aad,
        )
        .unwrap();
        assert_eq!(&decrypted[..content.len()], content);

        // 3. Different vault or different epoch key prevents cross-vault equality leakage
        let chunked_other_vault =
            chunk_and_encrypt_file(&vault_id_b, 1, &epoch_key_b, content).unwrap();
        assert_ne!(
            chunked_snap1.file_version_id,
            chunked_other_vault.file_version_id
        );
        assert_ne!(
            chunked_snap1.file_version_key.as_bytes(),
            chunked_other_vault.file_version_key.as_bytes()
        );
        assert_ne!(
            chunked_snap1.chunks[0].compute_cid().unwrap(),
            chunked_other_vault.chunks[0].compute_cid().unwrap()
        );
    }
}
