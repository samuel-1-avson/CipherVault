//! # CipherVault Snapshot Engine
//!
//! Handles coherent file capture, 1 MiB chunking with padding, manifest construction,
//! cryptographic DAG linkage, and atomic safe clean-machine file restoration.

pub mod chunker;
pub mod engine;
pub mod error;
pub mod fastcdc;

pub use chunker::{
    chunk_and_encrypt_file, ChunkedFile, AVG_CHUNK_SIZE, CHUNK_SIZE, MAX_CHUNK_SIZE, MAX_FILE_SIZE,
    MIN_CHUNK_SIZE, MIN_PADDING_SIZE,
};
pub use engine::{
    create_snapshot, create_snapshot_with_signer, restore_snapshot, validate_safe_relative_path,
    DeviceSigner, SnapshotOutput,
};
pub use error::SnapshotError;
pub use fastcdc::{
    fastcdc_chunk, FastCdcConfig, DEFAULT_AVG_SIZE, DEFAULT_MAX_SIZE, DEFAULT_MIN_SIZE,
};
