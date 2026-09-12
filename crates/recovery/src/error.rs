use thiserror::Error;

#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("Checksum validation failed: expected {expected:#x}, calculated {calculated:#x}")]
    ChecksumMismatch { expected: u32, calculated: u32 },

    #[error("Invalid hex encoding in recovery kit: {0}")]
    HexDecodeError(#[from] hex::FromHexError),

    #[error("Invalid recovery key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Crypto error during recovery: {0}")]
    CryptoError(#[from] ciphervault_crypto::CryptoError),

    #[error("Format error: {0}")]
    FormatError(#[from] ciphervault_format::FormatError),

    #[error("Invalid recovery kit format: {0}")]
    InvalidKitFormat(String),
}
