//! # CipherVault Snapshot Engine
//!
//! Handles coherent file capture, 1 MiB chunking with padding, manifest construction,
//! cryptographic DAG linkage, and atomic safe clean-machine file restoration.

pub mod chunker;
pub mod engine;
pub mod error;

pub use chunker::{chunk_and_encrypt_file, ChunkedFile, CHUNK_SIZE, MAX_FILE_SIZE, MIN_PADDING_SIZE};
pub use engine::{create_snapshot, restore_snapshot, validate_safe_relative_path, SnapshotOutput};
pub use error::SnapshotError;

