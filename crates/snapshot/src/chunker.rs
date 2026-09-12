use ciphervault_crypto::{encrypt_chunk, FileVersionKey};
use ciphervault_format::{compute_digest, ChunkWireObject, PROTOCOL_VERSION};
use rand::RngCore;

use crate::error::SnapshotError;

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
pub const MIN_PADDING_SIZE: usize = 4096;   // 4 KiB bucket for small files
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
pub fn chunk_and_encrypt_file(
    vault_id: &[u8; 32],
    key_epoch: u64,
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

    let mut file_version_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut file_version_id);
    let file_version_key = FileVersionKey::generate();

    // Determine padding for small files to mitigate size leakage
    let (padded_bytes, padded_length) = if raw_length < MIN_PADDING_SIZE as u64 {
        let mut padded = plaintext.to_vec();
        padded.resize(MIN_PADDING_SIZE, 0u8);
        let len = padded.len() as u64;
        (padded, len)
    } else {
        (plaintext.to_vec(), raw_length)
    };

    let raw_chunks: Vec<&[u8]> = padded_bytes.chunks(CHUNK_SIZE).collect();
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
        let payload = encrypt_chunk(file_version_key.as_bytes(), raw_chunk, &aad)?;

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

    #[test]
    fn test_chunking_small_file_padding() {
        let vault_id = [0x11u8; 32];
        let content = b"SECRET=true\nPORT=8080";
        let chunked = chunk_and_encrypt_file(&vault_id, 1, content).unwrap();

        assert_eq!(chunked.raw_length, content.len() as u64);
        assert_eq!(chunked.padded_length, MIN_PADDING_SIZE as u64);
        assert_eq!(chunked.chunks.len(), 1);
        assert_eq!(chunked.chunks[0].chunk_index, 0);
        assert_eq!(chunked.chunks[0].total_chunks, 1);
    }
}
