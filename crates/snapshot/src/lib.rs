//! # CipherVault Snapshot Engine
//!
//! Handles coherent file capture, content-defined chunking with padding, encrypted
//! manifests, cryptographic DAG linkage, and journaled file restoration.

pub mod chunker;
pub mod engine;
pub mod error;
pub mod fastcdc;
mod restore;
pub use restore::recover_interrupted_restore;

pub use chunker::{
    chunk_and_encrypt_file, chunk_and_encrypt_file_v2, ChunkedFile, AVG_CHUNK_SIZE, CHUNK_SIZE,
    MAX_CHUNK_SIZE, MAX_FILE_SIZE, MIN_CHUNK_SIZE, MIN_PADDING_SIZE,
};
pub use engine::{
    create_snapshot, create_snapshot_with_signer, create_snapshot_with_signer_and_write_version,
    create_snapshot_with_write_version, decrypt_snapshot, restore_snapshot,
    validate_safe_relative_path, ChunkWriteVersion, DecryptedFile, DeviceSigner, SnapshotOutput,
};
pub use error::SnapshotError;
pub use fastcdc::{
    fastcdc_chunk, FastCdcConfig, DEFAULT_AVG_SIZE, DEFAULT_MAX_SIZE, DEFAULT_MIN_SIZE,
};
