use thiserror::Error;

#[derive(Error, Debug)]
pub enum FormatError {
    #[error("CBOR serialization failed: {0}")]
    SerializationError(String),

    #[error("CBOR deserialization failed: {0}")]
    DeserializationError(String),

    #[error("Malformed record: {0}")]
    MalformedRecord(String),

    #[error("Size limit exceeded: expected at most {limit} bytes, got {actual} bytes")]
    SizeLimitExceeded { limit: usize, actual: usize },

    #[error("Crypto error during format validation: {0}")]
    CryptoError(#[from] ciphervault_crypto::CryptoError),
}
