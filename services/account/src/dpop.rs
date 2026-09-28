//! Opt-in DPoP-lite key binding for scope tokens (T-902).
//!
//! Bearer tokens [REDACTED] relayed; a token minted with
//! `bind_pubkey_ed25519_hex` carries a `cnf` (confirmation) key and is
//! useless without a `DPoP` proof on every use:
//!
//! ```text
//! DPoP: <base64url(sig)>.<unix_secs>.<base64url(nonce)>
//! ```
//!
//! `sig` is an ed25519 signature (domain `dpop-v1`, via the shared
//! [`sign_with_domain`](ciphervault_crypto::signatures::sign_with_domain)
//! construction) over `timestamp_be ‖ nonce ‖ jti ‖ tenant_id`, binding the
//! proof to one token, one tenant, and one instant. The client nonce makes
//! every proof unique, and proofs are single-use (replay cache), so a
//! captured proof replays nowhere — unlike method/URI binding, this needs
//! no handler-signature churn and survives legitimate same-second bursts.
//!
//! Timestamps must fall within ±[`DPOP_WINDOW_SECONDS`] of server time.
//! Failures are 401s (`DPOP_REQUIRED` when absent, `DPOP_INVALID`
//! otherwise); a store error fails closed with 503. mTLS remains deferred:
//! it needs a TLS-termination dependency the `--locked` build does not have.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::scope_tokens::ScopeClaims;
use crate::util::b64_decode;

/// Request header carrying the proof.
pub(crate) const DPOP_HEADER: &str = "dpop";

/// Acceptable clock skew in both directions (seconds).
pub(crate) const DPOP_WINDOW_SECONDS: u64 = 60;

/// Replay-cache retention past the proof timestamp (covers window + skew).
const DPOP_RETENTION_SECONDS: u64 = 300;

const DPOP_CONTEXT: &[u8] = b"dpop-v1";

/// Proof verification outcome.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DpopError {
    /// Bound token used without a `DPoP` header.
    #[error("DPoP proof required")]
    Missing,
    /// Malformed header, bad signature, or bad key encoding.
    #[error("invalid DPoP proof")]
    Invalid,
    /// Timestamp outside the ±window.
    #[error("expired DPoP proof")]
    Expired,
    /// Proof hash already consumed (single-use).
    #[error("replayed DPoP proof")]
    Replay,
    /// Replay store unavailable (fail-closed 503).
    #[error("proof store unavailable")]
    Db(#[from] rusqlite::Error),
}

/// Domain-separated message a proof signs: timestamp, client nonce, the
/// token's `jti`, and tenant. `jti`/tenant come from the MAC'd claims, so
/// only timestamp + nonce arrive over the wire.
pub(crate) fn dpop_message(
    timestamp_secs: u64,
    nonce: &[u8],
    jti: &str,
    tenant_id: &str,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + nonce.len() + jti.len() + tenant_id.len());
    msg.extend_from_slice(&timestamp_secs.to_be_bytes());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(jti.as_bytes());
    msg.extend_from_slice(tenant_id.as_bytes());
    msg
}

/// Enforces key binding for `claims`. Unbound tokens (`cnf: None`) pass
/// untouched; bound tokens must present a fresh, valid, single-use proof.
pub(crate) fn verify_dpop(
    db: &Connection,
    claims: &ScopeClaims,
    headers: &HeaderMap,
    now: u64,
) -> Result<(), DpopError> {
    let Some(cnf) = claims.cnf.as_deref() else {
        return Ok(());
    };
    let raw = headers
        .get(DPOP_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if raw.trim().is_empty() {
        return Err(DpopError::Missing);
    }
    let mut parts = raw.trim().split('.');
    let (sig_b64, ts_raw, nonce_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(sig), Some(ts), Some(nonce), None) => (sig, ts, nonce),
            _ => return Err(DpopError::Invalid),
        };
    let timestamp: u64 = ts_raw.parse().map_err(|_| DpopError::Invalid)?;
    if now.abs_diff(timestamp) > DPOP_WINDOW_SECONDS {
        return Err(DpopError::Expired);
    }
    let signature: [u8; 64] = b64_decode(sig_b64, "dpop signature")
        .map_err(|_| DpopError::Invalid)?
        .try_into()
        .map_err(|_| DpopError::Invalid)?;
    let nonce = b64_decode(nonce_b64, "dpop nonce").map_err(|_| DpopError::Invalid)?;
    if nonce.is_empty() || nonce.len() > 64 {
        return Err(DpopError::Invalid);
    }
    let key: [u8; 32] = hex::decode(cnf)
        .map_err(|_| DpopError::Invalid)?
        .try_into()
        .map_err(|_| DpopError::Invalid)?;
    let message = dpop_message(timestamp, &nonce, &claims.jti, &claims.tenant_id);
    ciphervault_crypto::signatures::verify_with_domain(&key, DPOP_CONTEXT, &message, &signature)
        .map_err(|_| DpopError::Invalid)?;
    // Single-use: the first presentation wins; prune the retention tail.
    let proof_hash = hex::encode(Sha256::digest(raw.trim().as_bytes()));
    db.execute(
        "DELETE FROM dpop_proofs WHERE expires_at_utc <= ?1",
        params![now as i64],
    )
    .map_err(DpopError::Db)?;
    let inserted = db
        .execute(
            "INSERT INTO dpop_proofs(proof_hash_hex, expires_at_utc) VALUES(?1, ?2)
             ON CONFLICT(proof_hash_hex) DO NOTHING",
            params![proof_hash, (timestamp + DPOP_RETENTION_SECONDS) as i64],
        )
        .map_err(DpopError::Db)?;
    if inserted == 0 {
        return Err(DpopError::Replay);
    }
    Ok(())
}

/// Maps a [`DpopError`] to its HTTP response. Missing vs invalid stay
/// distinct codes (the caller owns the key, so no oracle is created);
/// replays and forgeries share `DPOP_INVALID`.
pub(crate) fn dpop_error_response(error: &DpopError) -> Response {
    match error {
        DpopError::Missing => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "status": "error",
                "code": "DPOP_REQUIRED",
                "error": "This token is key-bound; present a DPoP proof",
            })),
        )
            .into_response(),
        DpopError::Db(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "error",
                "code": "DPOP_UNAVAILABLE",
                "error": "Proof replay store unavailable",
            })),
        )
            .into_response(),
        DpopError::Invalid | DpopError::Expired | DpopError::Replay => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "status": "error",
                "code": "DPOP_INVALID",
                "error": "Invalid, expired, or replayed DPoP proof",
            })),
        )
            .into_response(),
    }
}

/// Validates a mint-time binding key: 64 lowercase-hex characters that parse
/// as an ed25519 public key. Returns the normalized encoding.
pub(crate) fn validate_binding_key(hex_key: &str) -> Result<String, String> {
    let trimmed = hex_key.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|_| "bind_pubkey_ed25519_hex must be 64 hex characters".to_string())?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "bind_pubkey_ed25519_hex must be 32 bytes".to_string())?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| "bind_pubkey_ed25519_hex is not an ed25519 public key".to_string())?;
    // Small-order keys admit signature malleability under non-strict
    // verification; binding is self-chosen, so reject weak keys outright.
    if verifying.is_weak() {
        return Err("bind_pubkey_ed25519_hex is a weak public key".to_string());
    }
    Ok(hex::encode(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    use crate::test_support::{cleanup, test_app};

    const TEST_KEY: [u8; 32] = [0x33; 32];

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_KEY)
    }

    fn bound_claims() -> ScopeClaims {
        let verifying = signing_key().verifying_key();
        ScopeClaims::new("tenant-a", "project-a", "account:ci", 1000, 9_999_999_999)
            .with_cnf(&hex::encode(verifying.to_bytes()))
    }

    fn proof_header(claims: &ScopeClaims, key: &SigningKey, now: u64, nonce: &[u8]) -> String {
        let message = dpop_message(now, nonce, &claims.jti, &claims.tenant_id);
        let signature =
            ciphervault_crypto::signatures::sign_with_domain(key, DPOP_CONTEXT, &message);
        format!(
            "{}.{now}.{}",
            crate::util::b64_encode(&signature),
            crate::util::b64_encode(nonce)
        )
    }

    fn headers_with_proof(proof: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(DPOP_HEADER, proof.parse().unwrap());
        headers
    }

    #[test]
    fn unbound_tokens_skip_proof() {
        let (root, state, _app) = test_app("dpop-unbound");
        let db = state.connection().unwrap();
        let claims = ScopeClaims::new("t", "p", "alice", 1000, 2000);
        assert!(claims.cnf.is_none());
        verify_dpop(&db, &claims, &HeaderMap::new(), 1500).unwrap();
        cleanup(root);
    }

    #[test]
    fn missing_proof_rejected() {
        let (root, state, _app) = test_app("dpop-missing");
        let db = state.connection().unwrap();
        let claims = bound_claims();
        assert!(matches!(
            verify_dpop(&db, &claims, &HeaderMap::new(), 1500).unwrap_err(),
            DpopError::Missing
        ));
        cleanup(root);
    }

    #[test]
    fn valid_proof_accepted_once_then_replay_rejected() {
        let (root, state, _app) = test_app("dpop-replay");
        let db = state.connection().unwrap();
        let claims = bound_claims();
        let key = signing_key();
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let proof = proof_header(&claims, &key, 1500, &nonce);
        let headers = headers_with_proof(&proof);
        verify_dpop(&db, &claims, &headers, 1500).unwrap();
        assert!(matches!(
            verify_dpop(&db, &claims, &headers, 1501).unwrap_err(),
            DpopError::Replay
        ));
        // A fresh nonce is a fresh proof (same-second bursts work).
        let mut nonce2 = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce2);
        assert_ne!(nonce, nonce2);
        let proof2 = proof_header(&claims, &key, 1501, &nonce2);
        verify_dpop(&db, &claims, &headers_with_proof(&proof2), 1501).unwrap();
        cleanup(root);
    }

    #[test]
    fn tampered_proof_rejected() {
        let (root, state, _app) = test_app("dpop-tamper");
        let db = state.connection().unwrap();
        let claims = bound_claims();
        let key = signing_key();
        // Proof minted for another tenant must not verify here.
        let mut foreign = claims.clone();
        foreign.tenant_id = "tenant-b".to_string();
        let proof = proof_header(&foreign, &key, 1500, b"nonce-12345678");
        assert!(matches!(
            verify_dpop(&db, &claims, &headers_with_proof(&proof), 1500).unwrap_err(),
            DpopError::Invalid
        ));
        // Wrong key.
        let other = SigningKey::from_bytes(&[0x44; 32]);
        let proof = proof_header(&claims, &other, 1500, b"nonce-12345678");
        assert!(matches!(
            verify_dpop(&db, &claims, &headers_with_proof(&proof), 1500).unwrap_err(),
            DpopError::Invalid
        ));
        // Malformed shapes.
        for bad in ["", "abc", "a.b", "a.b.c.d", "!!!.1500.bm9uY2U"] {
            assert!(
                matches!(
                    verify_dpop(&db, &claims, &headers_with_proof(bad), 1500).unwrap_err(),
                    DpopError::Missing | DpopError::Invalid
                ),
                "{bad}"
            );
        }
        cleanup(root);
    }

    #[test]
    fn expired_proof_rejected() {
        let (root, state, _app) = test_app("dpop-expired");
        let db = state.connection().unwrap();
        let claims = bound_claims();
        let key = signing_key();
        let proof = proof_header(&claims, &key, 1000, b"nonce-12345678");
        assert!(matches!(
            verify_dpop(&db, &claims, &headers_with_proof(&proof), 1200).unwrap_err(),
            DpopError::Expired
        ));
        // Window edge: exactly ±60s is accepted.
        let edge = proof_header(&claims, &key, 1140, b"nonce-edge-00001");
        verify_dpop(&db, &claims, &headers_with_proof(&edge), 1200).unwrap();
        cleanup(root);
    }

    #[test]
    fn binding_key_validation() {
        let verifying = signing_key().verifying_key();
        let good = hex::encode(verifying.to_bytes());
        assert_eq!(validate_binding_key(&good).unwrap(), good);
        assert_eq!(validate_binding_key(&good.to_uppercase()).unwrap(), good);
        // Empty, non-hex, short, and the small-order identity point.
        for bad in ["", "zz", &"ab".repeat(16), &"00".repeat(32)] {
            assert!(validate_binding_key(bad).is_err(), "{bad}");
        }
    }
}
