use thiserror::Error;

#[derive(Error, Debug)]
pub enum LocalStoreError {
    #[error("Database error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("Vault not initialized at path")]
    VaultNotInitialized,

    #[error("Vault already initialized at path")]
    VaultAlreadyInitialized,

    #[error("Format error: {0}")]
    FormatError(#[from] ciphervault_format::FormatError),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] ciphervault_crypto::CryptoError),

    #[error("Record not found: {0}")]
    NotFound(String),

    #[error("Key protection error: {0}")]
    KeyProtectionError(String),

    #[error("Corrupted database record: {0}")]
    CorruptedRecord(String),
}
