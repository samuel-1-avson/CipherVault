//! Account service error type.

#[derive(Debug, thiserror::Error)]
pub enum AccountServiceError {
    #[error("account database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("account service I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid request: {0}")]
    Invalid(String),
}
