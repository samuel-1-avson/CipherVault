use thiserror::Error;

#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("File modified during capture: {0}")]
    ConcurrentModification(String),

    #[error("Path traversal or unsafe path rejected: {0}")]
    UnsafePath(String),

    #[error("File exceeds MVP size limit (256 MiB): {path} ({size} bytes)")]
    FileTooLarge { path: String, size: u64 },

    #[error("Plaintext SHA-256 mismatch for {path}: expected {expected}, actual {actual}")]
    IntegrityMismatch { path: String, expected: String, actual: String },

    #[error("Missing chunk {chunk_cid} for file {path}")]
    MissingChunk { path: String, chunk_cid: String },

    #[error("Crypto error: {0}")]
    CryptoError(#[from] ciphervault_crypto::CryptoError),

    #[error("Format error: {0}")]
    FormatError(#[from] ciphervault_format::FormatError),
}
