use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Authentication tag verification failed: ciphertext or AAD tampered")]
    AuthTagVerificationFailed,

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("KDF context must be exactly 8 bytes")]
    InvalidKdfContext,

    #[error("Cryptographic signature verification failed")]
    SignatureVerificationFailed,

    #[error("Sealed box payload too short: minimum length {min_len}")]
    SealedBoxPayloadTooShort { min_len: usize },

    #[error("Argon2 password hashing error: {0}")]
    PasswordHashError(String),

    #[error("Randomness generation error: {0}")]
    RngError(String),

    #[error("Hardware Security Module error: {0}")]
    HsmError(String),

    #[error("Threshold secret sharing error: {0}")]
    ThresholdError(String),
}
