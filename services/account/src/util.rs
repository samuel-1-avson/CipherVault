//! Shared account-service helpers (hashing, audit, encoding).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::{error::AccountServiceError, state::now_utc};

pub(crate) fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub(crate) fn audit_event(
    db: &Connection,
    account_id: &str,
    event: &str,
    details: serde_json::Value,
) -> Result<(), rusqlite::Error> {
    db.execute(
        "INSERT INTO audit_events(account_id, event, details_json, created_at_utc)
         VALUES(?1, ?2, ?3, ?4)",
        params![account_id, event, details.to_string(), now_utc()],
    )?;
    Ok(())
}

pub(crate) fn prune_expired(db: &Connection, now: u64) -> Result<(), rusqlite::Error> {
    db.execute(
        "DELETE FROM challenges WHERE expires_at_utc <= ?1 OR used_at_utc IS NOT NULL",
        params![now],
    )?;
    db.execute(
        "DELETE FROM sessions WHERE expires_at_utc <= ?1 OR revoked_at_utc IS NOT NULL",
        params![now],
    )?;
    Ok(())
}

pub(crate) fn random_hex(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

pub(crate) fn b64_encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

pub(crate) fn b64_decode(value: &str, field: &str) -> Result<Vec<u8>, AccountServiceError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .map_err(|_| AccountServiceError::Invalid(format!("{field} must be base64url")))
}

pub(crate) fn challenge_signing_bytes(
    account_id: &str,
    device_id_hex: Option<&str>,
    public_key_hex: Option<&str>,
    challenge_id: &str,
    nonce_hex: &str,
) -> Vec<u8> {
    serde_json::to_vec(&(
        account_id,
        device_id_hex,
        public_key_hex,
        challenge_id,
        nonce_hex,
    ))
    .expect("challenge signing tuple is serializable")
}
