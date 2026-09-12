use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Server returned error {status}: {message}")]
    ServerError { status: u16, message: String },

    #[error("Digest mismatch for object {cid}: expected {expected}, got {actual}")]
    DigestMismatch { cid: String, expected: String, actual: String },

    #[error("Invalid signature on operator receipt")]
    InvalidReceiptSignature,

    #[error("Format error: {0}")]
    FormatError(#[from] ciphervault_format::FormatError),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] ciphervault_crypto::CryptoError),

    #[error("Quorum deficit: required {required} operators, only {successful} succeeded")]
    QuorumDeficit { required: usize, successful: usize },

    #[error("Operator unreachable: {endpoint} ({details})")]
    OperatorUnreachable { endpoint: String, details: String },
}
