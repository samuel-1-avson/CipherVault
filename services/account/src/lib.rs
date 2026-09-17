//! Durable CipherVault control-plane account service.
//!
//! This service stores account metadata, enrolled device records, vault links,
//! and revocable sessions. Vault plaintext and vault private keys never enter
//! the service. Browser WebAuthn registration and assertion verification are
//! supported for `none` attestation with Ed25519 and ES256 credentials, and
//! successful logins can use an HttpOnly managed-session cookie. The
//! account-key ceremony remains the explicit bootstrap/recovery path.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciphervault_crypto::signatures::verify_with_domain;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use rand::RngCore;
use ring::{
    aead,
    signature::{self, UnparsedPublicKey},
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use tower_http::cors::{AllowOrigin, CorsLayer};

mod error;
mod state;
mod totp;

pub use error::AccountServiceError;
use state::*;
pub use state::{
    sqlite_busy_retries, AccountState, AccountView, AuditEventView, ChallengeView,
    CreateAccountRequest, DeviceChallengeRequest, DeviceEnrollmentRequest, DeviceView, ErrorBody,
    InvitationAcceptRequest, InvitationRequest, InvitationView, LinkVaultRequest,
    LoginChallengeRequest, MembershipView, RecoveryCodesRequest, RecoveryRedeemRequest,
    RevocationResponse, SessionHandoffConsumeRequest, SessionHandoffResponse, SessionLoginRequest,
    SessionResponse, SessionView, TotpAuthenticationOptionsRequest, TotpAuthenticationOptionsView,
    TotpAuthenticationVerifyRequest, TotpCodeRequest, TotpEnrollmentView, VaultLinkView,
    WebAuthnAuthenticationOptionsRequest, WebAuthnAuthenticationVerifyRequest,
    WebAuthnCredentialView, WebAuthnOptionsView, WebAuthnRegistrationVerifyRequest,
};

fn normalize_vault_role(value: &str) -> Result<String, AccountServiceError> {
    let role = value.trim().to_ascii_lowercase();
    match role.as_str() {
        "owner" | "admin" | "editor" | "viewer" | "recovery" => Ok(role),
        _ => Err(AccountServiceError::Invalid(
            "role must be one of owner, admin, editor, viewer, or recovery".into(),
        )),
    }
}

fn role_rank(role: &str) -> u8 {
    match role {
        "owner" => 4,
        "admin" => 3,
        "editor" => 2,
        "viewer" => 1,
        "recovery" => 0,
        _ => 0,
    }
}

fn active_membership_role(
    db: &Connection,
    account_id: &str,
    member_account_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    if account_id == member_account_id {
        return Ok(Some("owner".into()));
    }
    db.query_row(
        "SELECT role FROM memberships
         WHERE account_id = ?1 AND member_account_id = ?2
           AND status = 'active' AND accepted_at_utc IS NOT NULL
           AND revoked_at_utc IS NULL",
        params![account_id, member_account_id],
        |row| row.get(0),
    )
    .optional()
}

/// Authorize a session against an account's active membership. Owners are
/// implicit; invited accounts must have an accepted, non-revoked membership.
#[allow(clippy::result_large_err)]
fn account_role_for(
    state: &AccountState,
    headers: &HeaderMap,
    account_id: &str,
    minimum_role: &str,
) -> Result<(SessionView, String), Box<Response>> {
    let session = authenticated_session(state, headers).map_err(Box::new)?;
    let db = state
        .connection()
        .map_err(|error| Box::new(service_error(error)))?;
    let role = active_membership_role(&db, account_id, &session.account_id)
        .map_err(|error| Box::new(service_error(error.into())))?;
    let Some(role) = role else {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_MEMBERSHIP_REQUIRED",
            "Session is not an active member of this account",
        )));
    };
    if role_rank(&role) < role_rank(minimum_role) {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_ROLE_REQUIRED",
            format!("This action requires the {minimum_role} role"),
        )));
    }
    Ok((session, role))
}

/// Mutations require a strong (non-recovery) session even when the role gate
/// passes: recovery sessions read as their account's implicit owner, but must
/// enroll a device before changing account state.
fn require_strong_session(session: &SessionView) -> Result<(), Box<Response>> {
    if session.auth_method == "recovery" {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "RECOVERY_STEP_UP_REQUIRED",
            "Recovery sessions must enroll a device before account changes",
        )));
    }
    Ok(())
}

fn decode_32(value: &str, field: &str) -> Result<[u8; 32], AccountServiceError> {
    let bytes = hex::decode(value.trim())
        .map_err(|_| AccountServiceError::Invalid(format!("{field} must be 32-byte hex")))?;
    bytes
        .try_into()
        .map_err(|_| AccountServiceError::Invalid(format!("{field} must be 32-byte hex")))
}

fn normalize_account_id(value: &str) -> Result<String, AccountServiceError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 39
        || !value.starts_with("cvacct_")
        || hex::decode(&value[7..]).map(|bytes| bytes.len()) != Ok(16)
    {
        return Err(AccountServiceError::Invalid(
            "account_id must use cvacct_<32 hex characters>".into(),
        ));
    }
    Ok(value)
}

fn derive_account_id(public_key_hex: &str) -> Result<String, AccountServiceError> {
    let public_key = decode_32(public_key_hex, "account_public_key_hex")?;
    Ok(format!(
        "cvacct_{}",
        hex::encode(&Sha256::digest(public_key)[..16])
    ))
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// The TOTP seed is an authentication secret and must not be persisted in
/// plaintext. Production supplies a 32-byte hex wrapping key through a
/// read-only secret file; a direct environment value remains available only
/// for local development and existing deployments. The database stores only an
/// AEAD envelope.
pub(crate) fn totp_wrapping_key() -> Result<[u8; 32], AccountServiceError> {
    let raw = match std::env::var(TOTP_KEY_FILE_ENV) {
        Ok(path) if !path.trim().is_empty() => fs::read_to_string(path.trim()).map_err(|_| {
            AccountServiceError::Invalid(format!(
                "{TOTP_KEY_FILE_ENV} must reference a readable 32-byte hex key file"
            ))
        })?,
        _ => std::env::var(TOTP_KEY_ENV).map_err(|_| {
            AccountServiceError::Invalid(format!(
                "{TOTP_KEY_FILE_ENV} or {TOTP_KEY_ENV} must be configured before enabling authenticator MFA"
            ))
        })?,
    };
    let bytes = hex::decode(raw.trim()).map_err(|_| {
        AccountServiceError::Invalid("TOTP wrapping key must be 32-byte hex".into())
    })?;
    bytes
        .try_into()
        .map_err(|_| AccountServiceError::Invalid("TOTP wrapping key must be 32-byte hex".into()))
}

fn encrypt_totp_secret(secret: &[u8]) -> Result<String, AccountServiceError> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &totp_wrapping_key()?)
        .map_err(|_| AccountServiceError::Invalid("unable to initialize TOTP key".into()))?;
    let key = aead::LessSafeKey::new(key);
    let mut nonce = [0u8; TOTP_NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut payload = secret.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut payload,
    )
    .map_err(|_| AccountServiceError::Invalid("unable to encrypt TOTP secret".into()))?;
    let mut envelope = nonce.to_vec();
    envelope.extend_from_slice(&payload);
    Ok(b64_encode(&envelope))
}

fn decrypt_totp_secret(value: &str) -> Result<Vec<u8>, AccountServiceError> {
    let envelope = b64_decode(value, "TOTP secret envelope")?;
    if envelope.len() <= TOTP_NONCE_BYTES {
        return Err(AccountServiceError::Invalid(
            "TOTP secret envelope is invalid".into(),
        ));
    }
    let mut nonce = [0u8; TOTP_NONCE_BYTES];
    nonce.copy_from_slice(&envelope[..TOTP_NONCE_BYTES]);
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &totp_wrapping_key()?)
        .map_err(|_| AccountServiceError::Invalid("unable to initialize TOTP key".into()))?;
    let key = aead::LessSafeKey::new(key);
    let mut payload = envelope[TOTP_NONCE_BYTES..].to_vec();
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut payload,
        )
        .map_err(|_| AccountServiceError::Invalid("TOTP secret could not be decrypted".into()))?;
    Ok(plaintext.to_vec())
}

fn audit_event(
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

fn prune_expired(db: &Connection, now: u64) -> Result<(), rusqlite::Error> {
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

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

fn b64_encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn b64_decode(value: &str, field: &str) -> Result<Vec<u8>, AccountServiceError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .map_err(|_| AccountServiceError::Invalid(format!("{field} must be base64url")))
}

fn webauthn_rp_id() -> String {
    std::env::var("CIPHERVAULT_WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".into())
}

fn webauthn_origin() -> String {
    std::env::var("CIPHERVAULT_WEBAUTHN_ORIGIN").unwrap_or_else(|_| "http://localhost:8300".into())
}

fn webauthn_user_id(account_id: &str) -> Vec<u8> {
    Sha256::digest(account_id.as_bytes())[..16].to_vec()
}

fn cbor_map_value(
    map: &[(ciborium::Value, ciborium::Value)],
    key: i128,
) -> Option<&ciborium::Value> {
    map.iter().find_map(|(candidate, value)| {
        (candidate
            .as_integer()
            .is_some_and(|integer| i128::from(integer) == key))
        .then_some(value)
    })
}

fn cbor_text_value<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a str> {
    map.iter().find_map(|(candidate, value)| {
        (candidate.as_text() == Some(key))
            .then(|| value.as_text())
            .flatten()
    })
}

fn cbor_bytes_value(map: &[(ciborium::Value, ciborium::Value)], key: i128) -> Option<&[u8]> {
    cbor_map_value(map, key)
        .and_then(ciborium::Value::as_bytes)
        .map(Vec::as_slice)
}

fn cbor_bytes_text_value<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [u8]> {
    map.iter().find_map(|(candidate, value)| {
        (candidate.as_text() == Some(key))
            .then(|| value.as_bytes())
            .flatten()
            .map(Vec::as_slice)
    })
}

#[derive(Debug)]
struct ParsedAuthenticatorData {
    sign_count: u32,
    credential_id: Option<Vec<u8>>,
    algorithm: Option<i64>,
    public_key: Option<Vec<u8>>,
}

fn parse_authenticator_data(
    bytes: &[u8],
    registration: bool,
) -> Result<ParsedAuthenticatorData, AccountServiceError> {
    if bytes.len() < 37 {
        return Err(AccountServiceError::Invalid(
            "authenticator_data is shorter than the WebAuthn minimum".into(),
        ));
    }
    let rp_hash = Sha256::digest(webauthn_rp_id().as_bytes());
    if bytes[..32] != rp_hash[..] {
        return Err(AccountServiceError::Invalid(
            "WebAuthn RP ID hash does not match the configured RP ID".into(),
        ));
    }
    let flags = bytes[32];
    if flags & 0x01 == 0 {
        return Err(AccountServiceError::Invalid(
            "WebAuthn user presence flag is not set".into(),
        ));
    }
    if std::env::var("CIPHERVAULT_WEBAUTHN_REQUIRE_UV")
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        && flags & 0x04 == 0
    {
        return Err(AccountServiceError::Invalid(
            "WebAuthn user verification flag is required".into(),
        ));
    }
    let sign_count = u32::from_be_bytes(bytes[33..37].try_into().expect("length checked"));
    if !registration {
        return Ok(ParsedAuthenticatorData {
            sign_count,
            credential_id: None,
            algorithm: None,
            public_key: None,
        });
    }
    if flags & 0x40 == 0 {
        return Err(AccountServiceError::Invalid(
            "registration authenticator data does not contain attested credential data".into(),
        ));
    }
    if bytes.len() < 55 {
        return Err(AccountServiceError::Invalid(
            "registration authenticator data is truncated".into(),
        ));
    }
    let credential_len =
        u16::from_be_bytes(bytes[53..55].try_into().expect("length checked")) as usize;
    let credential_start: usize = 55;
    let credential_end = credential_start
        .checked_add(credential_len)
        .ok_or_else(|| AccountServiceError::Invalid("credential ID length overflow".into()))?;
    if credential_end > bytes.len() {
        return Err(AccountServiceError::Invalid(
            "registration credential ID is truncated".into(),
        ));
    }
    let credential_id = bytes[credential_start..credential_end].to_vec();
    let cose: ciborium::Value = ciborium::from_reader(Cursor::new(&bytes[credential_end..]))
        .map_err(|_| {
            AccountServiceError::Invalid("credential public key CBOR is invalid".into())
        })?;
    let cose_map = cose.as_map().ok_or_else(|| {
        AccountServiceError::Invalid("credential public key must be a CBOR map".into())
    })?;
    let kty = cbor_map_value(cose_map, 1)
        .and_then(ciborium::Value::as_integer)
        .map(i128::from)
        .ok_or_else(|| {
            AccountServiceError::Invalid("credential public key has no key type".into())
        })?;
    let algorithm = cbor_map_value(cose_map, 3)
        .and_then(ciborium::Value::as_integer)
        .map(i128::from)
        .ok_or_else(|| {
            AccountServiceError::Invalid("credential public key has no algorithm".into())
        })?;
    let curve = cbor_map_value(cose_map, -1)
        .and_then(ciborium::Value::as_integer)
        .map(i128::from);
    let (algorithm, public_key) = match (kty, algorithm, curve) {
        (1, -8, Some(6)) => {
            let key = cbor_bytes_value(cose_map, -2).ok_or_else(|| {
                AccountServiceError::Invalid("Ed25519 credential public key has no x value".into())
            })?;
            if key.len() != 32 {
                return Err(AccountServiceError::Invalid(
                    "Ed25519 credential public key must be 32 bytes".into(),
                ));
            }
            (-8, key.to_vec())
        }
        (2, -7, Some(1)) => {
            let x = cbor_bytes_value(cose_map, -2).ok_or_else(|| {
                AccountServiceError::Invalid("ES256 credential public key has no x value".into())
            })?;
            let y = cbor_bytes_value(cose_map, -3).ok_or_else(|| {
                AccountServiceError::Invalid("ES256 credential public key has no y value".into())
            })?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AccountServiceError::Invalid(
                    "ES256 credential coordinates must be 32 bytes each".into(),
                ));
            }
            let mut key = Vec::with_capacity(65);
            key.push(0x04);
            key.extend_from_slice(x);
            key.extend_from_slice(y);
            (-7, key)
        }
        _ => {
            return Err(AccountServiceError::Invalid(
                "only Ed25519 (-8) and ES256 (-7) WebAuthn credentials are supported".into(),
            ))
        }
    };
    Ok(ParsedAuthenticatorData {
        sign_count,
        credential_id: Some(credential_id),
        algorithm: Some(algorithm),
        public_key: Some(public_key),
    })
}

fn parse_attestation_object(value: &[u8]) -> Result<ParsedAuthenticatorData, AccountServiceError> {
    let attestation: ciborium::Value = ciborium::from_reader(Cursor::new(value))
        .map_err(|_| AccountServiceError::Invalid("attestation_object CBOR is invalid".into()))?;
    let map = attestation.as_map().ok_or_else(|| {
        AccountServiceError::Invalid("attestation_object must be a CBOR map".into())
    })?;
    let format = cbor_text_value(map, "fmt")
        .ok_or_else(|| AccountServiceError::Invalid("attestation_object has no format".into()))?;
    if format != "none" {
        return Err(AccountServiceError::Invalid(
            "only WebAuthn fmt=none attestation is accepted; packed and enterprise attestation require an explicit policy".into(),
        ));
    }
    let attestation_statement = map
        .iter()
        .find_map(|(key, value)| (key.as_text() == Some("attStmt")).then_some(value))
        .ok_or_else(|| AccountServiceError::Invalid("attestation_object has no attStmt".into()))?;
    if !matches!(attestation_statement, ciborium::Value::Map(values) if values.is_empty()) {
        return Err(AccountServiceError::Invalid(
            "fmt=none attestation must contain an empty attStmt".into(),
        ));
    }
    let auth_data = cbor_bytes_text_value(map, "authData")
        .ok_or_else(|| AccountServiceError::Invalid("attestation_object has no authData".into()))?;
    parse_authenticator_data(auth_data, true)
}

fn validate_client_data(
    bytes: &[u8],
    expected_type: &str,
    expected_challenge: &str,
) -> Result<(), AccountServiceError> {
    let client_data: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| AccountServiceError::Invalid("client_data_json is invalid JSON".into()))?;
    if client_data.get("type").and_then(serde_json::Value::as_str) != Some(expected_type) {
        return Err(AccountServiceError::Invalid(
            "WebAuthn client data type does not match the ceremony".into(),
        ));
    }
    if client_data
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        != Some(expected_challenge)
    {
        return Err(AccountServiceError::Invalid(
            "WebAuthn challenge does not match the issued challenge".into(),
        ));
    }
    if client_data
        .get("origin")
        .and_then(serde_json::Value::as_str)
        != Some(webauthn_origin().as_str())
    {
        return Err(AccountServiceError::Invalid(
            "WebAuthn origin does not match the configured origin".into(),
        ));
    }
    Ok(())
}

fn verify_webauthn_signature(
    algorithm: i64,
    public_key: &[u8],
    signed_data: &[u8],
    signature_bytes: &[u8],
) -> Result<(), AccountServiceError> {
    match algorithm {
        -8 => {
            let key: [u8; 32] = public_key.try_into().map_err(|_| {
                AccountServiceError::Invalid("Ed25519 credential public key is invalid".into())
            })?;
            let key = VerifyingKey::from_bytes(&key).map_err(|_| {
                AccountServiceError::Invalid("Ed25519 credential public key is invalid".into())
            })?;
            let signature = Ed25519Signature::from_slice(signature_bytes).map_err(|_| {
                AccountServiceError::Invalid("Ed25519 WebAuthn signature is invalid".into())
            })?;
            key.verify(signed_data, &signature).map_err(|_| {
                AccountServiceError::Invalid("WebAuthn assertion signature is invalid".into())
            })
        }
        -7 => UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key)
            .verify(signed_data, signature_bytes)
            .map_err(|_| {
                AccountServiceError::Invalid("WebAuthn assertion signature is invalid".into())
            }),
        _ => Err(AccountServiceError::Invalid(
            "unsupported WebAuthn algorithm".into(),
        )),
    }
}

fn error_response(status: StatusCode, code: &'static str, error: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            status: "error",
            code,
            error: error.into(),
        }),
    )
        .into_response()
}

fn request_source(headers: &HeaderMap) -> String {
    // Forwarded headers are caller-controlled unless the service is explicitly
    // deployed behind a trusted proxy. Keep direct deployments on one stable
    // source key so an attacker cannot evade the limiter by spoofing XFF.
    let trust_proxy_headers = std::env::var("CIPHERVAULT_ACCOUNT_TRUST_PROXY_HEADERS")
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    if !trust_proxy_headers {
        return "direct".into();
    }
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .chars()
        .take(128)
        .collect()
}

fn auth_rate_key(headers: &HeaderMap, account_id: &str, ceremony: &str) -> String {
    format!("{ceremony}:{account_id}:{}", request_source(headers))
}

fn auth_rate_allowed(state: &AccountState, key: &str) -> Result<(), Box<Response>> {
    let now = now_utc();
    let db = state.connection().map_err(|_| {
        Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTH_RATE_UNAVAILABLE",
            "Authentication rate limiter unavailable",
        ))
    })?;
    db.execute(
        "DELETE FROM auth_rate_limits
         WHERE blocked_until_utc <= ?1
           AND (?1 - window_started_at_utc) > ?2",
        params![now as i64, AUTH_RATE_WINDOW_SECONDS as i64],
    )
    .map_err(|_| {
        Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTH_RATE_UNAVAILABLE",
            "Authentication rate limiter unavailable",
        ))
    })?;
    let current = db
        .query_row(
            "SELECT window_started_at_utc, failures, blocked_until_utc
             FROM auth_rate_limits WHERE rate_key = ?1",
            params![key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u32,
                    row.get::<_, i64>(2)? as u64,
                ))
            },
        )
        .optional()
        .map_err(|_| {
            Box::new(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_RATE_UNAVAILABLE",
                "Authentication rate limiter unavailable",
            ))
        })?;
    let Some((window_started, failures, blocked_until)) = current else {
        let active_keys: i64 = db
            .query_row("SELECT COUNT(*) FROM auth_rate_limits", [], |row| {
                row.get(0)
            })
            .map_err(|_| {
                Box::new(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "AUTH_RATE_UNAVAILABLE",
                    "Authentication rate limiter unavailable",
                ))
            })?;
        if active_keys >= AUTH_RATE_MAX_KEYS as i64 {
            return Err(Box::new(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "AUTH_RATE_LIMITED",
                "Too many authentication sources are active; try again later",
            )));
        }
        db.execute(
            "INSERT INTO auth_rate_limits(rate_key, window_started_at_utc, failures, blocked_until_utc, updated_at_utc)
             VALUES(?1, ?2, 0, 0, ?2)",
            params![key, now as i64],
        )
        .map_err(|_| {
            Box::new(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_RATE_UNAVAILABLE",
                "Authentication rate limiter unavailable",
            ))
        })?;
        return Ok(());
    };
    if blocked_until > now {
        return Err(Box::new(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "AUTH_RATE_LIMITED",
            "Too many failed authentication attempts; try again later",
        )));
    }
    if now.saturating_sub(window_started) > AUTH_RATE_WINDOW_SECONDS {
        db.execute(
            "UPDATE auth_rate_limits
             SET window_started_at_utc = ?2, failures = 0, blocked_until_utc = 0, updated_at_utc = ?2
             WHERE rate_key = ?1",
            params![key, now as i64],
        )
        .map_err(|_| {
            Box::new(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_RATE_UNAVAILABLE",
                "Authentication rate limiter unavailable",
            ))
        })?;
        return Ok(());
    }
    if failures >= AUTH_RATE_MAX_FAILURES {
        db.execute(
            "UPDATE auth_rate_limits SET blocked_until_utc = ?2, updated_at_utc = ?3 WHERE rate_key = ?1",
            params![key, (now + AUTH_RATE_LOCK_SECONDS) as i64, now as i64],
        )
        .map_err(|_| {
            Box::new(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_RATE_UNAVAILABLE",
                "Authentication rate limiter unavailable",
            ))
        })?;
        return Err(Box::new(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "AUTH_RATE_LIMITED",
            "Too many failed authentication attempts; try again later",
        )));
    }
    Ok(())
}

fn auth_rate_failure_with_db(db: &Connection, key: &str) {
    let now = now_utc();
    let current = db
        .query_row(
            "SELECT window_started_at_utc, failures FROM auth_rate_limits WHERE rate_key = ?1",
            params![key],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u32)),
        )
        .optional()
        .ok()
        .flatten();
    let (window_started, failures) = current.unwrap_or((now, 0));
    let (window_started, failures) =
        if now.saturating_sub(window_started) > AUTH_RATE_WINDOW_SECONDS {
            (now, 1)
        } else {
            (window_started, failures.saturating_add(1))
        };
    let blocked_until = if failures >= AUTH_RATE_MAX_FAILURES {
        now + AUTH_RATE_LOCK_SECONDS
    } else {
        0
    };
    let _ = db.execute(
        "INSERT INTO auth_rate_limits(rate_key, window_started_at_utc, failures, blocked_until_utc, updated_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(rate_key) DO UPDATE SET
           window_started_at_utc = excluded.window_started_at_utc,
           failures = excluded.failures,
           blocked_until_utc = excluded.blocked_until_utc,
           updated_at_utc = excluded.updated_at_utc",
        params![key, window_started as i64, failures as i64, blocked_until as i64, now as i64],
    );
    if failures == AUTH_RATE_MAX_FAILURES {
        auth_rate_lockout_alert(db, key, now);
    }
}

/// Alert sink for fresh authentication lockouts: a queryable audit event plus a
/// stderr line for log aggregation. The rate key carries `ceremony:account:source`;
/// only the ceremony and source reach the alert trail, never secrets.
fn auth_rate_lockout_alert(db: &Connection, key: &str, now: u64) {
    let mut parts = key.splitn(3, ':');
    let ceremony = parts.next().unwrap_or("unknown");
    let account_id = parts.next().unwrap_or("");
    let source = parts.next().unwrap_or("unknown");
    eprintln!(
        "account auth rate lockout: ceremony={ceremony} source={source} blocked_until_utc={}",
        now + AUTH_RATE_LOCK_SECONDS
    );
    if account_id.trim().is_empty() {
        return;
    }
    // audit_events.account_id is FK-bound: lockouts for unknown accounts
    // (probing, typos) keep the stderr alert above but have no account row
    // to hang a queryable event on.
    if !account_exists(db, account_id).unwrap_or(false) {
        return;
    }
    let _ = audit_event(
        db,
        account_id,
        "auth_rate_lockout",
        serde_json::json!({
            "ceremony": ceremony,
            "source": source,
            "failures": AUTH_RATE_MAX_FAILURES,
            "blocked_until_utc": now + AUTH_RATE_LOCK_SECONDS,
        }),
    );
}

#[cfg(test)]
fn auth_rate_failure(state: &AccountState, key: &str) {
    if let Ok(db) = state.connection() {
        auth_rate_failure_with_db(&db, key);
    }
}

fn auth_rate_success(state: &AccountState, key: &str) {
    if let Ok(db) = state.connection() {
        let _ = db.execute(
            "DELETE FROM auth_rate_limits WHERE rate_key = ?1",
            params![key],
        );
    }
}

fn service_error(error: AccountServiceError) -> Response {
    match error {
        AccountServiceError::Invalid(message) => {
            error_response(StatusCode::BAD_REQUEST, "INVALID_REQUEST", message)
        }
        AccountServiceError::Database(message) => {
            eprintln!("account database error: {message}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ACCOUNT_DATABASE_ERROR",
                "Account service database failure",
            )
        }
        AccountServiceError::Io(message) => {
            eprintln!("account service I/O error: {message}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ACCOUNT_STORAGE_ERROR",
                "Account service storage failure",
            )
        }
    }
}

async fn csrf_origin_guard(request: Request<Body>, next: Next) -> Response {
    if request.method() == axum::http::Method::POST {
        if let Some(origin) = request.headers().get(axum::http::header::ORIGIN) {
            let origin = origin.to_str().unwrap_or_default();
            let configured = std::env::var("CIPHERVAULT_ACCOUNT_ALLOWED_ORIGINS")
                .ok()
                .into_iter()
                .flat_map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let allowed = configured.iter().any(|item| item == origin)
                || (configured.is_empty() && origin == webauthn_origin());
            if !allowed {
                return error_response(
                    StatusCode::FORBIDDEN,
                    "CSRF_ORIGIN_REJECTED",
                    "Request origin is not allowed",
                );
            }
        }
    }
    next.run(request).await
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    bearer_token(headers).map(ToOwned::to_owned).or_else(|| {
        headers
            .get("Cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';').find_map(|cookie| {
                    let (name, value) = cookie.trim().split_once('=')?;
                    (name == SESSION_COOKIE_NAME && !value.is_empty()).then(|| value.to_string())
                })
            })
    })
}

fn attach_session_cookie(response: &mut Response, token: &str) {
    let secure = std::env::var("CIPHERVAULT_ACCOUNT_COOKIE_SECURE")
        .map(|value| !value.eq_ignore_ascii_case("false"))
        .unwrap_or_else(|_| !webauthn_origin().starts_with("http://localhost"));
    let secure_attribute = if secure { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Lax{secure_attribute}"
    );
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie)
            .expect("generated account session cookie must be valid"),
    );
}

fn clear_session_cookie(response: &mut Response) {
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_static(
            "ciphervault_account_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        ),
    );
}

#[allow(clippy::result_large_err)]
fn authenticated_session(
    state: &AccountState,
    headers: &HeaderMap,
) -> Result<SessionView, Response> {
    let db = state.connection().map_err(service_error)?;
    authenticated_session_with_db(&db, headers)
}

/// Session lookup against an already-held connection. Callers that hold the
/// [`AccountState`] database guard (e.g. device enrollment's recovery branch)
/// must use this variant: `authenticated_session` would deadlock re-locking
/// the non-reentrant guard on the same thread.
#[allow(clippy::result_large_err)]
fn authenticated_session_with_db(
    db: &Connection,
    headers: &HeaderMap,
) -> Result<SessionView, Response> {
    let token = session_token(headers).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "SESSION_REQUIRED",
            "Missing bearer token",
        )
    })?;
    let token_hash = hash_token(&token);
    let now = now_utc();
    if let Err(error) = prune_expired(db, now) {
        return Err(service_error(error.into()));
    }
    let session = db
        .query_row(
            "SELECT account_id, device_id_hex, session_kind, issued_at_utc, expires_at_utc
             FROM sessions WHERE token_hash_hex = ?1 AND revoked_at_utc IS NULL AND expires_at_utc > ?2",
            params![token_hash, now],
            |row| {
                Ok(SessionView {
                    account_id: row.get(0)?,
                    device_id_hex: row.get(1)?,
                    auth_method: row.get(2)?,
                    issued_at_utc: row.get::<_, i64>(3)? as u64,
                    expires_at_utc: row.get::<_, i64>(4)? as u64,
                })
            },
        )
        .optional()
        .map_err(|error| service_error(error.into()))?;
    session.ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "SESSION_INVALID",
            "Session is missing, expired, or revoked",
        )
    })
}

fn account_exists(db: &Connection, account_id: &str) -> Result<bool, rusqlite::Error> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE account_id = ?1)",
        params![account_id],
        |row| row.get(0),
    )
}

fn account_view(db: &Connection, account_id: &str) -> Result<Option<AccountView>, rusqlite::Error> {
    let Some(account) = db
        .query_row(
            "SELECT display_name, account_public_key_hex, created_at_utc FROM accounts WHERE account_id = ?1",
            params![account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            },
        )
        .optional()? else {
        return Ok(None);
    };
    let mut devices = Vec::new();
    let mut device_statement = db.prepare(
        "SELECT device_id_hex, public_key_hex, label, enrolled_at_utc, last_seen_at_utc, revoked_at_utc
         FROM devices WHERE account_id = ?1 ORDER BY enrolled_at_utc",
    )?;
    let mut rows = device_statement.query(params![account_id])?;
    while let Some(row) = rows.next()? {
        devices.push(DeviceView {
            device_id_hex: row.get(0)?,
            public_key_hex: row.get(1)?,
            label: row.get(2)?,
            enrolled_at_utc: row.get::<_, i64>(3)? as u64,
            last_seen_at_utc: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
            revoked_at_utc: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
        });
    }
    let mut vaults = Vec::new();
    let mut vault_statement = db.prepare(
        "SELECT vault_id_hex, alias, role, linked_at_utc
         FROM vault_links WHERE account_id = ?1 ORDER BY linked_at_utc",
    )?;
    let mut rows = vault_statement.query(params![account_id])?;
    while let Some(row) = rows.next()? {
        vaults.push(VaultLinkView {
            vault_id_hex: row.get(0)?,
            alias: row.get(1)?,
            role: row.get(2)?,
            linked_at_utc: row.get::<_, i64>(3)? as u64,
        });
    }
    let mut webauthn_credentials = Vec::new();
    let mut credential_statement = db.prepare(
        "SELECT credential_id_hex, device_id_hex, algorithm, sign_count, created_at_utc, last_used_at_utc, revoked_at_utc
         FROM webauthn_credentials WHERE account_id = ?1 ORDER BY created_at_utc",
    )?;
    let mut rows = credential_statement.query(params![account_id])?;
    while let Some(row) = rows.next()? {
        let credential_id_hex: String = row.get(0)?;
        let credential_id = hex::decode(&credential_id_hex).unwrap_or_default();
        webauthn_credentials.push(WebAuthnCredentialView {
            credential_id_b64: b64_encode(&credential_id),
            device_id_hex: row.get(1)?,
            algorithm: row.get(2)?,
            sign_count: row.get::<_, i64>(3)? as u32,
            created_at_utc: row.get::<_, i64>(4)? as u64,
            last_used_at_utc: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
            revoked_at_utc: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
        });
    }
    let (totp_enabled, totp_last_used_at_utc) = db
        .query_row(
            "SELECT enabled, last_used_at_utc FROM totp_credentials
             WHERE account_id = ?1 AND revoked_at_utc IS NULL",
            params![account_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? != 0,
                    row.get::<_, Option<i64>>(1)?.map(|value| value as u64),
                ))
            },
        )
        .optional()?
        .unwrap_or((false, None));
    let mut memberships = Vec::new();
    let mut membership_statement = db.prepare(
        "SELECT account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc, revoked_at_utc
         FROM memberships WHERE account_id = ?1 OR member_account_id = ?1 ORDER BY invited_at_utc",
    )?;
    let mut rows = membership_statement.query(params![account_id])?;
    while let Some(row) = rows.next()? {
        memberships.push(MembershipView {
            account_id: row.get(0)?,
            member_account_id: row.get(1)?,
            role: row.get(2)?,
            status: row.get(3)?,
            invited_at_utc: row.get::<_, i64>(4)? as u64,
            accepted_at_utc: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
            revoked_at_utc: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
        });
    }
    Ok(Some(AccountView {
        account_id: account_id.to_string(),
        display_name: account.0,
        account_public_key_hex: account.1,
        created_at_utc: account.2,
        devices,
        vaults,
        webauthn_credentials,
        totp_enabled,
        totp_last_used_at_utc,
        memberships,
    }))
}

fn challenge_signing_bytes(
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

pub async fn post_account(
    State(state): State<AccountState>,
    Json(request): Json<CreateAccountRequest>,
) -> Response {
    let account_id = match derive_account_id(&request.account_public_key_hex) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let public_key = match decode_32(&request.account_public_key_hex, "account_public_key_hex") {
        Ok(key) => key,
        Err(error) => return service_error(error),
    };
    let display_name: String = request.display_name.trim().chars().take(120).collect();
    if display_name.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_DISPLAY_NAME",
            "display_name is required",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let result = db.execute(
        "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
         VALUES(?1, ?2, ?3, ?4)",
        params![account_id, display_name, hex::encode(public_key), now_utc()],
    );
    if let Err(error) = result {
        if matches!(error, rusqlite::Error::SqliteFailure(_, _)) {
            return error_response(
                StatusCode::CONFLICT,
                "ACCOUNT_EXISTS",
                "Account public key is already registered",
            );
        }
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "account_created",
        serde_json::json!({"display_name": display_name}),
    ) {
        return service_error(error.into());
    }
    match account_view(&db, &account_id) {
        Ok(Some(view)) => (StatusCode::CREATED, Json(view)).into_response(),
        Ok(None) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ACCOUNT_CREATE_FAILED",
            "Account was not persisted",
        ),
        Err(error) => service_error(error.into()),
    }
}

pub async fn get_capabilities() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "ciphervault-account",
        "protocol_version": 1,
        "account_key_login": true,
        "account_signed_device_enrollment": true,
        "webauthn": true,
        "webauthn_status": "ed25519_es256_fmt_none",
        "totp": true,
        "totp_status": "rfc6238_sha1_6_digit_30_second",
        "totp_configured": totp_wrapping_key().is_ok(),
        "managed_session_cookie": true,
        "session_cookie_name": SESSION_COOKIE_NAME,
        "invitations": true,
        "membership_roles": ["owner", "admin", "editor", "viewer", "recovery"],
        "recovery_codes": true,
        "vault_plaintext_storage": false,
    }))
}

pub async fn get_account(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.account_id != account_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match account_view(&db, &account_id) {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "ACCOUNT_NOT_FOUND",
            "Account does not exist",
        ),
        Err(error) => service_error(error.into()),
    }
}

pub async fn get_account_audit(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.account_id != account_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let mut statement = match db.prepare(
        "SELECT event_id, event, details_json, created_at_utc
         FROM audit_events WHERE account_id = ?1 ORDER BY event_id DESC LIMIT 200",
    ) {
        Ok(statement) => statement,
        Err(error) => return service_error(error.into()),
    };
    let mut rows = match statement.query(params![account_id]) {
        Ok(rows) => rows,
        Err(error) => return service_error(error.into()),
    };
    let mut events = Vec::new();
    while let Some(row) = match rows.next() {
        Ok(row) => row,
        Err(error) => return service_error(error.into()),
    } {
        let details_json: String = match row.get(2) {
            Ok(value) => value,
            Err(error) => return service_error(error.into()),
        };
        let details = serde_json::from_str(&details_json)
            .unwrap_or_else(|_| serde_json::json!({"raw": details_json}));
        events.push(AuditEventView {
            event_id: match row.get::<_, i64>(0) {
                Ok(value) => value as u64,
                Err(error) => return service_error(error.into()),
            },
            event: match row.get(1) {
                Ok(value) => value,
                Err(error) => return service_error(error.into()),
            },
            details,
            created_at_utc: match row.get::<_, i64>(3) {
                Ok(value) => value as u64,
                Err(error) => return service_error(error.into()),
            },
        });
    }
    Json(serde_json::json!({"account_id": account_id, "events": events})).into_response()
}

pub async fn post_device_challenge(
    State(state): State<AccountState>,
    Path(account_id): Path<String>,
    Json(request): Json<DeviceChallengeRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if let Err(error) = decode_32(&request.device_id_hex, "device_id_hex")
        .and(decode_32(&request.public_key_hex, "public_key_hex"))
    {
        return service_error(error);
    }
    let challenge_id = random_hex(16);
    let nonce_hex = random_hex(32);
    let expires_at = now_utc() + CHALLENGE_TTL_SECONDS;
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if let Err(error) = prune_expired(&db, now_utc()) {
        return service_error(error.into());
    }
    match account_exists(&db, &account_id) {
        Ok(false) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "ACCOUNT_NOT_FOUND",
                "Account does not exist",
            )
        }
        Err(error) => return service_error(error.into()),
        Ok(true) => {}
    }
    if let Err(error) = db.execute(
        "INSERT INTO challenges(challenge_id, kind, account_id, device_id_hex, public_key_hex, nonce_hex, expires_at_utc)
         VALUES(?1, 'device_enrollment', ?2, ?3, ?4, ?5, ?6)",
        params![challenge_id, account_id, request.device_id_hex.to_ascii_lowercase(), request.public_key_hex.to_ascii_lowercase(), nonce_hex, expires_at],
    ) {
        return service_error(error.into());
    }
    (
        StatusCode::OK,
        Json(ChallengeView {
            challenge_id,
            nonce_hex,
            expires_at_utc: expires_at,
            ceremony: "account_signed_device_enrollment_v1".into(),
        }),
    )
        .into_response()
}

pub async fn post_device_enrollment(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<DeviceEnrollmentRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if let Err(error) = decode_32(&request.device_id_hex, "device_id_hex")
        .and(decode_32(&request.public_key_hex, "public_key_hex"))
    {
        return service_error(error);
    }
    let signature_bytes = match hex::decode(&request.proof_signature_hex) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_SIGNATURE",
                "proof_signature_hex must be 64-byte hex",
            )
        }
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let account_key_hex: Option<String> = match db
        .query_row(
            "SELECT account_public_key_hex FROM accounts WHERE account_id = ?1",
            params![account_id],
            |row| row.get(0),
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return service_error(error.into()),
    };
    let Some(account_key_hex) = account_key_hex else {
        return error_response(
            StatusCode::NOT_FOUND,
            "ACCOUNT_NOT_FOUND",
            "Account does not exist",
        );
    };
    let challenge = match db
        .query_row(
            "SELECT nonce_hex, device_id_hex, public_key_hex, expires_at_utc, used_at_utc
             FROM challenges WHERE challenge_id = ?1 AND kind = 'device_enrollment' AND account_id = ?2",
            params![request.challenge_id, account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(value)) => value,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "CHALLENGE_INVALID", "Enrollment challenge is unknown"),
        Err(error) => return service_error(error.into()),
    };
    if challenge.3 <= now_utc() || challenge.4.is_some() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_EXPIRED",
            "Enrollment challenge is expired or already used",
        );
    }
    if !challenge.1.eq_ignore_ascii_case(&request.device_id_hex)
        || !challenge.2.eq_ignore_ascii_case(&request.public_key_hex)
    {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_BINDING_MISMATCH",
            "Enrollment proof does not match the challenge",
        );
    }
    let account_key = match decode_32(&account_key_hex, "account public key").and_then(|key| {
        VerifyingKey::from_bytes(&key)
            .map_err(|_| AccountServiceError::Invalid("account public key is invalid".into()))
    }) {
        Ok(key) => key,
        Err(error) => return service_error(error),
    };
    let signing_bytes = challenge_signing_bytes(
        &account_id,
        Some(&request.device_id_hex.to_ascii_lowercase()),
        Some(&request.public_key_hex.to_ascii_lowercase()),
        &request.challenge_id,
        &challenge.0,
    );
    let signature: [u8; 64] = match signature_bytes.as_slice().try_into() {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_SIGNATURE",
                "Invalid proof signature length",
            )
        }
    };
    let account_proof_valid = verify_with_domain(
        account_key.as_bytes(),
        b"account_device_enrollment",
        &signing_bytes,
        &signature,
    )
    .is_ok();
    // Recovery-only holders lost the account key with their devices. A valid,
    // unexpired recovery session authorizes the account, and a proof signed by
    // the new device key itself proves possession of the enrolled keypair.
    let mut enrolled_via_recovery = false;
    if !account_proof_valid {
        let recovery_authorized = authenticated_session_with_db(&db, &headers)
            .ok()
            .is_some_and(|session| {
                session.account_id == account_id && session.auth_method == "recovery"
            });
        if !recovery_authorized {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "PROOF_INVALID",
                "Account-signed enrollment proof is invalid",
            );
        }
        let device_key_bytes = match decode_32(&request.public_key_hex, "device public key") {
            Ok(key) => key,
            Err(error) => return service_error(error),
        };
        let device_key = match VerifyingKey::from_bytes(&device_key_bytes)
            .map_err(|_| AccountServiceError::Invalid("device public key is invalid".into()))
        {
            Ok(key) => key,
            Err(error) => return service_error(error),
        };
        if verify_with_domain(
            device_key.as_bytes(),
            b"account_device_enrollment",
            &signing_bytes,
            &signature,
        )
        .is_err()
        {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "PROOF_INVALID",
                "Recovery enrollment proof is invalid",
            );
        }
        enrolled_via_recovery = true;
    }
    let now = now_utc();
    if let Err(error) = db.execute(
        "INSERT INTO devices(account_id, device_id_hex, public_key_hex, label, enrolled_at_utc, last_seen_at_utc, revoked_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?5, NULL)
         ON CONFLICT(account_id, device_id_hex) DO UPDATE SET
           public_key_hex = excluded.public_key_hex, label = excluded.label,
           last_seen_at_utc = excluded.last_seen_at_utc, revoked_at_utc = NULL",
        params![account_id, request.device_id_hex.to_ascii_lowercase(), request.public_key_hex.to_ascii_lowercase(), request.label.trim().chars().take(120).collect::<String>(), now],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "device_enrolled",
        serde_json::json!({
            "device_id_hex": request.device_id_hex.to_ascii_lowercase(),
            "label": request.label,
            "enrollment": if enrolled_via_recovery {
                "recovery_session"
            } else {
                "account_signed"
            },
        }),
    ) {
        return service_error(error.into());
    }
    if enrolled_via_recovery {
        eprintln!("account device enrolled via recovery session: account_id={account_id}");
    }
    if let Err(error) = db.execute(
        "UPDATE challenges SET used_at_utc = ?2 WHERE challenge_id = ?1",
        params![request.challenge_id, now],
    ) {
        return service_error(error.into());
    }
    match db
        .query_row(
            "SELECT device_id_hex, public_key_hex, label, enrolled_at_utc, last_seen_at_utc, revoked_at_utc
             FROM devices WHERE account_id = ?1 AND device_id_hex = ?2",
            params![account_id, request.device_id_hex.to_ascii_lowercase()],
            |row| {
                Ok(DeviceView {
                    device_id_hex: row.get(0)?,
                    public_key_hex: row.get(1)?,
                    label: row.get(2)?,
                    enrolled_at_utc: row.get::<_, i64>(3)? as u64,
                    last_seen_at_utc: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    revoked_at_utc: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                })
            },
        )
    {
        Ok(device) => (StatusCode::CREATED, Json(device)).into_response(),
        Err(error) => service_error(error.into()),
    }
}

pub async fn post_login_challenge(
    State(state): State<AccountState>,
    Json(request): Json<LoginChallengeRequest>,
) -> Response {
    let account_id = match normalize_account_id(&request.account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let device_id = match request.device_id_hex {
        Some(value) => {
            if let Err(error) = decode_32(&value, "device_id_hex") {
                return service_error(error);
            }
            Some(value.to_ascii_lowercase())
        }
        None => None,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if let Err(error) = prune_expired(&db, now_utc()) {
        return service_error(error.into());
    }
    if !matches!(account_exists(&db, &account_id), Ok(true)) {
        return error_response(
            StatusCode::NOT_FOUND,
            "ACCOUNT_NOT_FOUND",
            "Account does not exist",
        );
    }
    if let Some(device_id) = device_id.as_deref() {
        let active = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM devices WHERE account_id = ?1 AND device_id_hex = ?2 AND revoked_at_utc IS NULL)",
                params![account_id, device_id],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false);
        if !active {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "DEVICE_NOT_ENROLLED",
                "Device is not enrolled or is revoked",
            );
        }
    }
    let challenge_id = random_hex(16);
    let nonce_hex = random_hex(32);
    let expires_at = now_utc() + CHALLENGE_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO challenges(challenge_id, kind, account_id, device_id_hex, nonce_hex, expires_at_utc)
         VALUES(?1, 'login', ?2, ?3, ?4, ?5)",
        params![challenge_id, account_id, device_id, nonce_hex, expires_at],
    ) {
        return service_error(error.into());
    }
    (
        StatusCode::OK,
        Json(ChallengeView {
            challenge_id,
            nonce_hex,
            expires_at_utc: expires_at,
            ceremony: "account_key_login_v1".into(),
        }),
    )
        .into_response()
}

pub async fn post_login(
    State(state): State<AccountState>,
    Json(request): Json<SessionLoginRequest>,
) -> Response {
    let signature_bytes = match hex::decode(&request.signature_hex) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_SIGNATURE",
                "signature_hex must be 64-byte hex",
            )
        }
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let challenge = match db
        .query_row(
            "SELECT c.account_id, c.device_id_hex, c.nonce_hex, c.expires_at_utc, c.used_at_utc, a.account_public_key_hex
             FROM challenges c JOIN accounts a ON a.account_id = c.account_id
             WHERE c.challenge_id = ?1 AND c.kind = 'login'",
            params![request.challenge_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(value)) => value,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "CHALLENGE_INVALID", "Login challenge is unknown"),
        Err(error) => return service_error(error.into()),
    };
    if challenge.3 <= now_utc() || challenge.4.is_some() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_EXPIRED",
            "Login challenge is expired or already used",
        );
    }
    let account_key = match decode_32(&challenge.5, "account public key").and_then(|key| {
        VerifyingKey::from_bytes(&key)
            .map_err(|_| AccountServiceError::Invalid("account public key is invalid".into()))
    }) {
        Ok(key) => key,
        Err(error) => return service_error(error),
    };
    let signing_bytes = challenge_signing_bytes(
        &challenge.0,
        challenge.1.as_deref(),
        None,
        &request.challenge_id,
        &challenge.2,
    );
    let signature: [u8; 64] = match signature_bytes.as_slice().try_into() {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_SIGNATURE",
                "Invalid signature length",
            )
        }
    };
    if verify_with_domain(
        account_key.as_bytes(),
        b"account_login",
        &signing_bytes,
        &signature,
    )
    .is_err()
    {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "LOGIN_PROOF_INVALID",
            "Account login proof is invalid",
        );
    }
    let now = now_utc();
    let token = random_hex(32);
    let expires_at = now + SESSION_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, session_kind, issued_at_utc, expires_at_utc)
         VALUES(?1, ?2, ?3, 'device', ?4, ?5)",
        params![hash_token(&token), challenge.0, challenge.1, now, expires_at],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &challenge.0,
        "session_created",
        serde_json::json!({"device_id_hex": challenge.1}),
    ) {
        return service_error(error.into());
    }
    if let Err(error) = db.execute(
        "UPDATE challenges SET used_at_utc = ?2 WHERE challenge_id = ?1",
        params![request.challenge_id, now],
    ) {
        return service_error(error.into());
    }
    let mut response = (
        StatusCode::OK,
        Json(SessionResponse {
            token: token.clone(),
            session: SessionView {
                account_id: challenge.0,
                device_id_hex: challenge.1,
                auth_method: "device".into(),
                issued_at_utc: now,
                expires_at_utc: expires_at,
            },
        }),
    )
        .into_response();
    attach_session_cookie(&mut response, &token);
    response
}

pub async fn get_session(State(state): State<AccountState>, headers: HeaderMap) -> Response {
    match authenticated_session(&state, &headers) {
        Ok(session) => Json(session).into_response(),
        Err(response) => response,
    }
}

pub async fn post_session_revoke(
    State(state): State<AccountState>,
    headers: HeaderMap,
) -> Response {
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(token) = session_token(&headers) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "SESSION_REQUIRED",
            "Missing bearer token",
        );
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match db.execute(
        "UPDATE sessions SET revoked_at_utc = ?2 WHERE token_hash_hex = ?1",
        params![hash_token(&token), now_utc()],
    ) {
        Ok(_) => {
            if let Err(error) = audit_event(
                &db,
                &session.account_id,
                "session_revoked",
                serde_json::json!({}),
            ) {
                return service_error(error.into());
            }
            let mut response =
                Json(serde_json::json!({"revoked": true, "account_id": session.account_id}))
                    .into_response();
            clear_session_cookie(&mut response);
            response
        }
        Err(error) => service_error(error.into()),
    }
}

/// Mint a short-lived, single-use browser handoff after the CLI has
/// authenticated with the account signing key. The handoff contains no
/// account secret; it only authorizes the browser to receive a fresh managed
/// session for the already-authenticated device.
pub async fn post_session_handoff(
    State(state): State<AccountState>,
    headers: HeaderMap,
) -> Response {
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let now = now_utc();
    let handoff_code = random_hex(32);
    let expires_at = now + SESSION_HANDOFF_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO session_handoffs(handoff_hash_hex, account_id, device_id_hex, auth_method, created_at_utc, expires_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            hash_token(&handoff_code),
            session.account_id,
            session.device_id_hex,
            session.auth_method,
            now,
            expires_at
        ],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &session.account_id,
        "session_handoff_issued",
        serde_json::json!({"expires_at_utc": expires_at}),
    ) {
        return service_error(error.into());
    }
    Json(SessionHandoffResponse {
        handoff_code,
        expires_at_utc: expires_at,
    })
    .into_response()
}

/// Exchange a CLI-issued handoff for a normal HttpOnly browser session. Codes
/// are hashed at rest, expire quickly, and are consumed atomically before the
/// new session is returned.
pub async fn post_session_handoff_consume(
    State(state): State<AccountState>,
    Json(request): Json<SessionHandoffConsumeRequest>,
) -> Response {
    let handoff_code = request.handoff_code.trim();
    if handoff_code.len() != 64 || hex::decode(handoff_code).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_HANDOFF_CODE",
            "handoff_code must be a 32-byte hexadecimal value",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let now = now_utc();
    let handoff = match db
        .query_row(
            "SELECT account_id, device_id_hex, auth_method, expires_at_utc, used_at_utc
             FROM session_handoffs WHERE handoff_hash_hex = ?1",
            params![hash_token(handoff_code)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "HANDOFF_INVALID",
                "Browser handoff is unknown or expired",
            )
        }
        Err(error) => return service_error(error.into()),
    };
    if handoff.3 <= now || handoff.4.is_some() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "HANDOFF_EXPIRED",
            "Browser handoff is expired or already used",
        );
    }
    let consumed = match db.execute(
        "UPDATE session_handoffs SET used_at_utc = ?2
         WHERE handoff_hash_hex = ?1 AND used_at_utc IS NULL AND expires_at_utc > ?2",
        params![hash_token(handoff_code), now],
    ) {
        Ok(changed) => changed == 1,
        Err(error) => return service_error(error.into()),
    };
    if !consumed {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "HANDOFF_REPLAY",
            "Browser handoff was already consumed",
        );
    }
    let token = random_hex(32);
    let expires_at = now + SESSION_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc)
         VALUES(?1, ?2, ?3, NULL, ?4, ?5, ?6)",
        params![
            hash_token(&token),
            handoff.0,
            handoff.1,
            handoff.2,
            now,
            expires_at
        ],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &handoff.0,
        "session_handoff_consumed",
        serde_json::json!({}),
    ) {
        return service_error(error.into());
    }
    let mut response = Json(SessionResponse {
        token: token.clone(),
        session: SessionView {
            account_id: handoff.0,
            device_id_hex: handoff.1,
            auth_method: handoff.2,
            issued_at_utc: now,
            expires_at_utc: expires_at,
        },
    })
    .into_response();
    attach_session_cookie(&mut response, &token);
    response
}

pub async fn post_vault_link(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<LinkVaultRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let (session, _) = match account_role_for(&state, &headers, &account_id, "owner") {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if let Err(response) = require_strong_session(&session) {
        return *response;
    }
    if let Err(error) = decode_32(&request.vault_id_hex, "vault_id_hex") {
        return service_error(error);
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let alias: String = request.alias.trim().chars().take(120).collect();
    let role = match normalize_vault_role(&request.role) {
        Ok(role) => role,
        Err(error) => return service_error(error),
    };
    if alias.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_VAULT_LINK",
            "alias and role are required",
        );
    }
    match db.execute(
        "INSERT INTO vault_links(account_id, vault_id_hex, alias, role, linked_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(account_id, vault_id_hex) DO UPDATE SET alias = excluded.alias, role = excluded.role",
        params![account_id, request.vault_id_hex.to_ascii_lowercase(), alias, role, now_utc()],
    ) {
        Ok(_) => {
            if let Err(error) = audit_event(
                &db,
                &account_id,
                "vault_linked",
                serde_json::json!({
                    "vault_id_hex": request.vault_id_hex.to_ascii_lowercase(),
                    "alias": alias,
                    "role": role,
                }),
            ) {
                return service_error(error.into());
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => service_error(error.into()),
    }
}

fn invitation_view_from_row(
    row: &rusqlite::Row<'_>,
    token: Option<String>,
) -> Result<InvitationView, rusqlite::Error> {
    Ok(InvitationView {
        invitation_id: row.get(0)?,
        account_id: row.get(1)?,
        invitee_account_id: row.get(2)?,
        role: row.get(3)?,
        created_at_utc: row.get::<_, i64>(4)? as u64,
        expires_at_utc: row.get::<_, i64>(5)? as u64,
        accepted_at_utc: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
        revoked_at_utc: row.get::<_, Option<i64>>(7)?.map(|value| value as u64),
        token,
    })
}

fn membership_view_from_row(row: &rusqlite::Row<'_>) -> Result<MembershipView, rusqlite::Error> {
    Ok(MembershipView {
        account_id: row.get(0)?,
        member_account_id: row.get(1)?,
        role: row.get(2)?,
        status: row.get(3)?,
        invited_at_utc: row.get::<_, i64>(4)? as u64,
        accepted_at_utc: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
        revoked_at_utc: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
    })
}

pub async fn post_invitation(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<InvitationRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let (session, actor_role) = match account_role_for(&state, &headers, &account_id, "admin") {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if let Err(response) = require_strong_session(&session) {
        return *response;
    }
    let invitee = match normalize_account_id(&request.invitee_account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if invitee == account_id {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_INVITEE",
            "An account cannot invite itself",
        );
    }
    let role = match normalize_vault_role(&request.role) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if role == "owner" || (role == "admin" && actor_role != "owner") {
        return error_response(
            StatusCode::FORBIDDEN,
            "ROLE_GRANT_NOT_ALLOWED",
            "Only an owner can grant admin access, and owner access cannot be delegated",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let exists = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE account_id = ?1)",
            params![invitee],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    if !exists {
        return error_response(
            StatusCode::NOT_FOUND,
            "INVITEE_NOT_FOUND",
            "Invitee account does not exist",
        );
    }
    let now = now_utc();
    let expires_at = now
        + request
            .expires_in_seconds
            .unwrap_or(7 * 24 * 60 * 60)
            .clamp(5 * 60, 30 * 24 * 60 * 60);
    let invitation_id = format!("cvinv_{}", random_hex(16));
    let token = format!("cvinv_{}", random_hex(32));
    if let Err(error) = db.execute(
        "INSERT INTO invitations(invitation_id, account_id, invitee_account_id, role, token_hash_hex, created_at_utc, expires_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![invitation_id, account_id, invitee, role, hash_token(&token), now, expires_at],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "invitation_created",
        serde_json::json!({
            "invitation_id": invitation_id,
            "invitee_account_id": invitee,
            "role": role,
            "expires_at_utc": expires_at,
        }),
    ) {
        return service_error(error.into());
    }
    match db.query_row(
        "SELECT invitation_id, account_id, invitee_account_id, role, created_at_utc, expires_at_utc, accepted_at_utc, revoked_at_utc
         FROM invitations WHERE invitation_id = ?1",
        params![invitation_id],
        |row| invitation_view_from_row(row, Some(token.clone())),
    ) {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(error) => service_error(error.into()),
    }
}

pub async fn get_invitations(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if let Err(response) = account_role_for(&state, &headers, &account_id, "admin") {
        return *response;
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let mut statement = match db.prepare(
        "SELECT invitation_id, account_id, invitee_account_id, role, created_at_utc, expires_at_utc, accepted_at_utc, revoked_at_utc
         FROM invitations WHERE account_id = ?1 ORDER BY created_at_utc DESC",
    ) { Ok(statement) => statement, Err(error) => return service_error(error.into()) };
    let mut rows = match statement.query(params![account_id]) {
        Ok(rows) => rows,
        Err(error) => return service_error(error.into()),
    };
    let mut invitations = Vec::new();
    loop {
        match rows.next() {
            Ok(Some(row)) => match invitation_view_from_row(row, None) {
                Ok(view) => invitations.push(view),
                Err(error) => return service_error(error.into()),
            },
            Ok(None) => break,
            Err(error) => return service_error(error.into()),
        }
    }
    Json(serde_json::json!({"invitations": invitations})).into_response()
}

pub async fn post_invitation_accept(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(request): Json<InvitationAcceptRequest>,
) -> Response {
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let token = request.token.trim();
    if token.len() < 16 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_INVITATION_TOKEN",
            "Invitation token is invalid",
        );
    }
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let invitation = match db.query_row(
        "SELECT invitation_id, account_id, role, expires_at_utc, accepted_at_utc, revoked_at_utc
         FROM invitations WHERE token_hash_hex = ?1 AND invitee_account_id = ?2",
        params![hash_token(token), session.account_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)? as u64, row.get::<_, Option<i64>>(4)?, row.get::<_, Option<i64>>(5)?)),
    ).optional() {
        Ok(value) => value,
        Err(error) => return service_error(error.into()),
    };
    let Some((invitation_id, account_id, role, expires_at, accepted_at, revoked_at)) = invitation
    else {
        return error_response(
            StatusCode::NOT_FOUND,
            "INVITATION_NOT_FOUND",
            "Invitation is unknown or not addressed to this account",
        );
    };
    if expires_at <= now_utc() || accepted_at.is_some() || revoked_at.is_some() {
        return error_response(
            StatusCode::CONFLICT,
            "INVITATION_EXPIRED",
            "Invitation is expired, accepted, or revoked",
        );
    }
    let now = now_utc();
    let tx = match db.transaction() {
        Ok(tx) => tx,
        Err(error) => return service_error(error.into()),
    };
    let updated = match tx.execute(
        "UPDATE invitations SET accepted_at_utc = ?2
         WHERE invitation_id = ?1 AND accepted_at_utc IS NULL AND revoked_at_utc IS NULL AND expires_at_utc > ?2",
        params![invitation_id, now],
    ) {
        Ok(updated) => updated,
        Err(error) => return service_error(error.into()),
    };
    if updated == 0 {
        return error_response(
            StatusCode::CONFLICT,
            "INVITATION_ALREADY_CONSUMED",
            "Invitation was accepted or revoked by another request",
        );
    }
    if let Err(error) = tx.execute(
        "INSERT INTO memberships(account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc, revoked_at_utc)
         SELECT account_id, invitee_account_id, role, 'active', invited_at_utc, ?2, NULL FROM invitations WHERE invitation_id = ?1
         ON CONFLICT(account_id, member_account_id) DO UPDATE SET role = excluded.role, status = 'active', accepted_at_utc = excluded.accepted_at_utc, revoked_at_utc = NULL",
        params![invitation_id, now],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &tx,
        &session.account_id,
        "invitation_accepted",
        serde_json::json!({"invitation_id": invitation_id, "account_id": account_id, "role": role}),
    ) {
        return service_error(error.into());
    }
    if let Err(error) = tx.commit() {
        return service_error(error.into());
    }
    Json(serde_json::json!({"accepted": true, "account_id": account_id, "role": role}))
        .into_response()
}

pub async fn get_memberships(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if let Err(response) = account_role_for(&state, &headers, &account_id, "viewer") {
        return *response;
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let mut statement = match db.prepare("SELECT account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc, revoked_at_utc FROM memberships WHERE account_id = ?1 OR member_account_id = ?1 ORDER BY invited_at_utc") { Ok(statement) => statement, Err(error) => return service_error(error.into()) };
    let mut rows = match statement.query(params![account_id]) {
        Ok(rows) => rows,
        Err(error) => return service_error(error.into()),
    };
    let mut memberships = Vec::new();
    loop {
        match rows.next() {
            Ok(Some(row)) => match membership_view_from_row(row) {
                Ok(view) => memberships.push(view),
                Err(error) => return service_error(error.into()),
            },
            Ok(None) => break,
            Err(error) => return service_error(error.into()),
        }
    }
    Json(serde_json::json!({"memberships": memberships})).into_response()
}

pub async fn post_membership_revoke(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((account_id, member_account_id)): Path<(String, String)>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let member_account_id = match normalize_account_id(&member_account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let (session, actor_role) = match account_role_for(&state, &headers, &account_id, "admin") {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if let Err(response) = require_strong_session(&session) {
        return *response;
    }
    if session.account_id == member_account_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "SELF_MEMBERSHIP_REVOKE",
            "A session cannot revoke its own membership",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let target_role = match db
        .query_row(
            "SELECT role FROM memberships
         WHERE account_id = ?1 AND member_account_id = ?2
           AND status = 'active' AND revoked_at_utc IS NULL",
            params![account_id, member_account_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return service_error(error.into()),
    };
    let Some(target_role) = target_role else {
        return error_response(
            StatusCode::NOT_FOUND,
            "MEMBERSHIP_NOT_FOUND",
            "Membership is not active",
        );
    };
    if actor_role != "owner" && role_rank(&target_role) >= role_rank(&actor_role) {
        return error_response(
            StatusCode::FORBIDDEN,
            "ROLE_HIERARCHY",
            "An admin can revoke only lower-privilege memberships",
        );
    }
    let now = now_utc();
    match db.execute("UPDATE memberships SET status = 'revoked', revoked_at_utc = ?3 WHERE account_id = ?1 AND member_account_id = ?2 AND revoked_at_utc IS NULL", params![account_id, member_account_id, now]) {
        Ok(0) => error_response(StatusCode::NOT_FOUND, "MEMBERSHIP_NOT_FOUND", "Membership is not active"),
        Ok(_) => { if let Err(error) = audit_event(&db, &account_id, "membership_revoked", serde_json::json!({"member_account_id": member_account_id})) { return service_error(error.into()); } Json(serde_json::json!({"revoked": true})).into_response() },
        Err(error) => service_error(error.into()),
    }
}

pub async fn post_recovery_codes(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<RecoveryCodesRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let (session, _) = match account_role_for(&state, &headers, &account_id, "owner") {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if session.device_id_hex.is_none() {
        return error_response(
            StatusCode::FORBIDDEN,
            "DEVICE_STEP_UP_REQUIRED",
            "Recovery codes require an enrolled device-bound session",
        );
    }
    let count = request.count.clamp(4, 16);
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if let Err(error) = db.execute(
        "DELETE FROM recovery_codes WHERE account_id = ?1 AND used_at_utc IS NULL",
        params![account_id],
    ) {
        return service_error(error.into());
    }
    let now = now_utc();
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let code = format!("cvrc_{}", random_hex(16));
        if let Err(error) = db.execute("INSERT INTO recovery_codes(account_id, code_hash_hex, created_at_utc) VALUES(?1, ?2, ?3)", params![account_id, hash_token(&code), now]) { return service_error(error.into()); }
        codes.push(code);
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "recovery_codes_issued",
        serde_json::json!({"count": count}),
    ) {
        return service_error(error.into());
    }
    Json(serde_json::json!({"account_id": account_id, "codes": codes, "generated_at_utc": now}))
        .into_response()
}

pub async fn post_recovery_redeem(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(request): Json<RecoveryRedeemRequest>,
) -> Response {
    let account_id = match normalize_account_id(&request.account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let rate_key = auth_rate_key(&headers, &account_id, "recovery");
    if let Err(response) = auth_rate_allowed(&state, &rate_key) {
        return *response;
    }
    let code = request.code.trim();
    if code.len() < 16 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_RECOVERY_CODE",
            "Recovery code is invalid",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let now = now_utc();
    let code_hash = hash_token(code);
    let valid = db.query_row("SELECT EXISTS(SELECT 1 FROM recovery_codes WHERE account_id = ?1 AND code_hash_hex = ?2 AND used_at_utc IS NULL)", params![account_id, code_hash], |row| row.get::<_, bool>(0)).unwrap_or(false);
    if !valid {
        auth_rate_failure_with_db(&db, &rate_key);
        return error_response(
            StatusCode::UNAUTHORIZED,
            "RECOVERY_CODE_INVALID",
            "Recovery code is unknown or already used",
        );
    }
    if let Err(error) = db.execute("UPDATE recovery_codes SET used_at_utc = ?3 WHERE account_id = ?1 AND code_hash_hex = ?2 AND used_at_utc IS NULL", params![account_id, code_hash, now]) { return service_error(error.into()); }
    let token = random_hex(32);
    // Recovery sessions are deliberately short-lived; the session cookie may outlive
    // this TTL, but the server rejects the expired session on every request.
    let expires_at = now + RECOVERY_SESSION_TTL_SECONDS;
    if let Err(error) = db.execute("INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc) VALUES(?1, ?2, NULL, NULL, 'recovery', ?3, ?4)", params![hash_token(&token), account_id, now, expires_at]) { return service_error(error.into()); }
    let source = request_source(&headers);
    eprintln!("account recovery redeemed: account={account_id} source={source}");
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "recovery_code_redeemed",
        serde_json::json!({
            "source": source,
            "expires_at_utc": expires_at,
            "session_ttl_secs": RECOVERY_SESSION_TTL_SECONDS,
        }),
    ) {
        return service_error(error.into());
    }
    drop(db);
    auth_rate_success(&state, &rate_key);
    let mut response = (
        StatusCode::OK,
        Json(SessionResponse {
            token: token.clone(),
            session: SessionView {
                account_id,
                device_id_hex: None,
                auth_method: "recovery".into(),
                issued_at_utc: now,
                expires_at_utc: expires_at,
            },
        }),
    )
        .into_response();
    attach_session_cookie(&mut response, &token);
    response
}

async fn propagate_device_revocation(
    state: &AccountState,
    public_key_hex: &str,
    vault_ids: &[String],
) -> (usize, usize, usize) {
    let endpoints = std::env::var("CIPHERVAULT_OPERATOR_ENDPOINTS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.trim_end_matches('/').to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let service_token = std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN").ok();
    let targets = endpoints.len().saturating_mul(vault_ids.len());
    if targets == 0 || service_token.as_deref().unwrap_or_default().is_empty() {
        return (targets, 0, targets);
    }
    let mut successes = 0;
    let mut failures = 0;
    for endpoint in endpoints {
        for vault_id in vault_ids {
            let url = format!("{endpoint}/v1/identities/revoke");
            let request = state
                .http
                .post(url)
                .header(
                    "X-CipherVault-Service-Token",
                    service_token.as_deref().unwrap_or_default(),
                )
                .json(&serde_json::json!({
                    "vault_id_hex": vault_id,
                    "public_key_hex": public_key_hex,
                }));
            match request.send().await {
                Ok(response)
                    if response.status().is_success()
                        || response.status() == StatusCode::NOT_FOUND =>
                {
                    successes += 1
                }
                _ => failures += 1,
            }
        }
    }
    (targets, successes, failures)
}

pub async fn post_device_revoke(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((account_id, device_id_hex)): Path<(String, String)>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let device_id_hex = match decode_32(&device_id_hex, "device_id_hex") {
        Ok(_) => device_id_hex.to_ascii_lowercase(),
        Err(error) => return service_error(error),
    };
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.account_id != account_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        );
    }
    let (public_key_hex, vault_ids, changed) = {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        let public_key: Option<String> = match db
            .query_row(
                "SELECT public_key_hex FROM devices WHERE account_id = ?1 AND device_id_hex = ?2 AND revoked_at_utc IS NULL",
                params![account_id, device_id_hex],
                |row| row.get(0),
            )
            .optional()
        {
            Ok(value) => value,
            Err(error) => return service_error(error.into()),
        };
        let Some(public_key) = public_key else {
            return error_response(
                StatusCode::NOT_FOUND,
                "DEVICE_NOT_FOUND",
                "Device is not enrolled or is already revoked",
            );
        };
        let now = now_utc();
        if let Err(error) = db.execute(
            "UPDATE devices SET revoked_at_utc = ?3 WHERE account_id = ?1 AND device_id_hex = ?2",
            params![account_id, device_id_hex, now],
        ) {
            return service_error(error.into());
        }
        if let Err(error) = db.execute(
            "UPDATE sessions SET revoked_at_utc = ?3 WHERE account_id = ?1 AND device_id_hex = ?2 AND revoked_at_utc IS NULL",
            params![account_id, device_id_hex, now],
        ) {
            return service_error(error.into());
        }
        if let Err(error) = audit_event(
            &db,
            &account_id,
            "device_revoked",
            serde_json::json!({"device_id_hex": device_id_hex}),
        ) {
            return service_error(error.into());
        }
        let mut vault_ids = Vec::new();
        let mut statement =
            match db.prepare("SELECT vault_id_hex FROM vault_links WHERE account_id = ?1") {
                Ok(statement) => statement,
                Err(error) => return service_error(error.into()),
            };
        let mut rows = match statement.query(params![account_id]) {
            Ok(rows) => rows,
            Err(error) => return service_error(error.into()),
        };
        while let Ok(Some(row)) = rows.next() {
            if let Ok(vault_id) = row.get::<_, String>(0) {
                vault_ids.push(vault_id);
            }
        }
        (public_key, vault_ids, true)
    };
    let (operator_targets, operator_revocations, operator_failures) =
        propagate_device_revocation(&state, &public_key_hex, &vault_ids).await;
    Json(RevocationResponse {
        revoked: changed,
        operator_targets,
        operator_revocations,
        operator_failures,
    })
    .into_response()
}

pub async fn post_webauthn_revoke(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((account_id, credential_id_hex)): Path<(String, String)>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let credential_id = match hex::decode(&credential_id_hex) {
        Ok(value) if !value.is_empty() && value.len() <= 1024 => value,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_CREDENTIAL_ID",
                "credential_id_hex must contain between 1 and 1024 bytes",
            )
        }
    };
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.account_id != account_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let now = now_utc();
    let changed = match db.execute(
        "UPDATE webauthn_credentials SET revoked_at_utc = ?3
         WHERE account_id = ?1 AND credential_id_hex = ?2 AND revoked_at_utc IS NULL",
        params![account_id, hex::encode(&credential_id), now],
    ) {
        Ok(changed) => changed,
        Err(error) => return service_error(error.into()),
    };
    if changed == 0 {
        return error_response(
            StatusCode::NOT_FOUND,
            "CREDENTIAL_NOT_FOUND",
            "WebAuthn credential is unknown or already revoked",
        );
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "webauthn_revoked",
        serde_json::json!({"credential_id_b64": b64_encode(&credential_id)}),
    ) {
        return service_error(error.into());
    }
    if let Err(error) = db.execute(
        "UPDATE sessions SET revoked_at_utc = ?3
         WHERE account_id = ?1 AND credential_id_hex = ?2 AND revoked_at_utc IS NULL",
        params![account_id, hex::encode(&credential_id), now],
    ) {
        return service_error(error.into());
    }
    Json(serde_json::json!({
        "revoked": true,
        "account_id": account_id,
        "credential_id_b64": b64_encode(&credential_id),
    }))
    .into_response()
}

pub async fn post_webauthn_registration_options(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.account_id != account_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        );
    }
    let Some(device_id_hex) = session.device_id_hex.as_deref() else {
        return error_response(
            StatusCode::FORBIDDEN,
            "DEVICE_SESSION_REQUIRED",
            "WebAuthn credentials must be registered from an enrolled device session",
        );
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if let Err(error) = prune_expired(&db, now_utc()) {
        return service_error(error.into());
    }
    let challenge_id = random_hex(16);
    let nonce_hex = random_hex(32);
    let expires_at = now_utc() + CHALLENGE_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO challenges(challenge_id, kind, account_id, device_id_hex, nonce_hex, expires_at_utc)
         VALUES(?1, 'webauthn_registration', ?2, ?3, ?4, ?5)",
        params![challenge_id, account_id, device_id_hex, nonce_hex, expires_at],
    ) {
        return service_error(error.into());
    }
    Json(WebAuthnOptionsView {
        challenge_id,
        challenge: b64_encode(&hex::decode(&nonce_hex).expect("nonce is generated as valid hex")),
        rp_id: webauthn_rp_id(),
        user_id_b64: b64_encode(&webauthn_user_id(&account_id)),
        timeout_ms: CHALLENGE_TTL_SECONDS * 1000,
        ceremony: "webauthn.create".into(),
    })
    .into_response()
}

pub async fn post_webauthn_registration_verify(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<WebAuthnRegistrationVerifyRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.account_id != account_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        );
    }
    let credential_id = match b64_decode(&request.credential_id_b64, "credential_id_b64") {
        Ok(value) if !value.is_empty() && value.len() <= 1024 => value,
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_CREDENTIAL_ID",
                "credential_id_b64 must be between 1 and 1024 bytes",
            )
        }
        Err(error) => return service_error(error),
    };
    let client_data = match b64_decode(&request.client_data_json_b64, "client_data_json_b64") {
        Ok(value) if value.len() <= MAX_BODY_BYTES => value,
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "CLIENT_DATA_TOO_LARGE",
                "client_data_json_b64 is too large",
            )
        }
        Err(error) => return service_error(error),
    };
    let attestation = match b64_decode(&request.attestation_object_b64, "attestation_object_b64") {
        Ok(value) if value.len() <= MAX_BODY_BYTES => value,
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "ATTESTATION_TOO_LARGE",
                "attestation_object_b64 is too large",
            )
        }
        Err(error) => return service_error(error),
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let challenge = match db
        .query_row(
            "SELECT nonce_hex, device_id_hex, expires_at_utc, used_at_utc FROM challenges
             WHERE challenge_id = ?1 AND kind = 'webauthn_registration' AND account_id = ?2",
            params![request.challenge_id, account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "CHALLENGE_INVALID",
                "WebAuthn registration challenge is unknown",
            )
        }
        Err(error) => return service_error(error.into()),
    };
    if challenge.2 <= now_utc() || challenge.3.is_some() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_EXPIRED",
            "WebAuthn registration challenge is expired or already used",
        );
    }
    if challenge.1.as_deref() != session.device_id_hex.as_deref() {
        return error_response(
            StatusCode::FORBIDDEN,
            "DEVICE_SESSION_MISMATCH",
            "WebAuthn registration challenge is bound to another device",
        );
    }
    let expected_challenge = match hex::decode(&challenge.0) {
        Ok(value) => b64_encode(&value),
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CHALLENGE_INVALID",
                "Stored challenge is invalid",
            )
        }
    };
    if let Err(error) = validate_client_data(&client_data, "webauthn.create", &expected_challenge) {
        return service_error(error);
    }
    let parsed = match parse_attestation_object(&attestation) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let parsed_credential_id = parsed.credential_id.clone().unwrap_or_default();
    if parsed_credential_id != credential_id {
        return error_response(
            StatusCode::BAD_REQUEST,
            "CREDENTIAL_ID_MISMATCH",
            "credential_id_b64 does not match attested credential data",
        );
    }
    let algorithm = parsed
        .algorithm
        .expect("registration parser sets algorithm");
    let public_key = parsed.public_key.expect("registration parser sets key");
    let now = now_utc();
    if let Err(error) = db.execute(
        "INSERT INTO webauthn_credentials(account_id, credential_id_hex, device_id_hex, algorithm, public_key_hex, sign_count, created_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![account_id, hex::encode(&credential_id), session.device_id_hex.as_deref(), algorithm, hex::encode(&public_key), parsed.sign_count, now],
    ) {
        if matches!(error, rusqlite::Error::SqliteFailure(_, _)) {
            return error_response(
                StatusCode::CONFLICT,
                "CREDENTIAL_EXISTS",
                "WebAuthn credential is already registered",
            );
        }
        return service_error(error.into());
    }
    let challenge_consumed = match db.execute(
        "UPDATE challenges SET used_at_utc = ?2 WHERE challenge_id = ?1 AND used_at_utc IS NULL",
        params![request.challenge_id, now],
    ) {
        Ok(changed) => changed == 1,
        Err(error) => return service_error(error.into()),
    };
    if !challenge_consumed {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_REPLAY",
            "WebAuthn registration challenge was already consumed",
        );
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "webauthn_registered",
        serde_json::json!({
            "credential_id_b64": request.credential_id_b64,
            "algorithm": algorithm,
        }),
    ) {
        return service_error(error.into());
    }
    (
        StatusCode::CREATED,
        Json(WebAuthnCredentialView {
            credential_id_b64: b64_encode(&credential_id),
            algorithm,
            device_id_hex: session.device_id_hex.clone(),
            sign_count: parsed.sign_count,
            created_at_utc: now,
            last_used_at_utc: None,
            revoked_at_utc: None,
        }),
    )
        .into_response()
}

pub async fn post_webauthn_authentication_options(
    State(state): State<AccountState>,
    Json(request): Json<WebAuthnAuthenticationOptionsRequest>,
) -> Response {
    let account_id = match normalize_account_id(&request.account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if let Err(error) = prune_expired(&db, now_utc()) {
        return service_error(error.into());
    }
    if !matches!(account_exists(&db, &account_id), Ok(true)) {
        return error_response(
            StatusCode::NOT_FOUND,
            "ACCOUNT_NOT_FOUND",
            "Account does not exist",
        );
    }
    let has_credential = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE account_id = ?1 AND revoked_at_utc IS NULL)",
            params![account_id],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    if !has_credential {
        return error_response(
            StatusCode::NOT_FOUND,
            "WEBAUTHN_NOT_ENROLLED",
            "No active WebAuthn credential is enrolled for this account",
        );
    }
    let challenge_id = random_hex(16);
    let nonce_hex = random_hex(32);
    let expires_at = now_utc() + CHALLENGE_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO challenges(challenge_id, kind, account_id, nonce_hex, expires_at_utc)
         VALUES(?1, 'webauthn_login', ?2, ?3, ?4)",
        params![challenge_id, account_id, nonce_hex, expires_at],
    ) {
        return service_error(error.into());
    }
    Json(WebAuthnOptionsView {
        challenge_id,
        challenge: b64_encode(&hex::decode(&nonce_hex).expect("nonce is generated as valid hex")),
        rp_id: webauthn_rp_id(),
        user_id_b64: b64_encode(&webauthn_user_id(&account_id)),
        timeout_ms: CHALLENGE_TTL_SECONDS * 1000,
        ceremony: "webauthn.get".into(),
    })
    .into_response()
}

pub async fn post_webauthn_authentication_verify(
    State(state): State<AccountState>,
    Json(request): Json<WebAuthnAuthenticationVerifyRequest>,
) -> Response {
    let credential_id = match b64_decode(&request.credential_id_b64, "credential_id_b64") {
        Ok(value) if !value.is_empty() && value.len() <= 1024 => value,
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_CREDENTIAL_ID",
                "credential_id_b64 must be between 1 and 1024 bytes",
            )
        }
        Err(error) => return service_error(error),
    };
    let client_data = match b64_decode(&request.client_data_json_b64, "client_data_json_b64") {
        Ok(value) if value.len() <= MAX_BODY_BYTES => value,
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "CLIENT_DATA_TOO_LARGE",
                "client_data_json_b64 is too large",
            )
        }
        Err(error) => return service_error(error),
    };
    let authenticator_data =
        match b64_decode(&request.authenticator_data_b64, "authenticator_data_b64") {
            Ok(value) if value.len() <= MAX_BODY_BYTES => value,
            Ok(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "AUTHENTICATOR_DATA_TOO_LARGE",
                    "authenticator_data_b64 is too large",
                )
            }
            Err(error) => return service_error(error),
        };
    let assertion_signature = match b64_decode(&request.signature_b64, "signature_b64") {
        Ok(value) if value.len() <= 1024 => value,
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "SIGNATURE_TOO_LARGE",
                "signature_b64 is too large",
            )
        }
        Err(error) => return service_error(error),
    };
    let parsed_authenticator = match parse_authenticator_data(&authenticator_data, false) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let challenge = match db
        .query_row(
            "SELECT account_id, nonce_hex, expires_at_utc, used_at_utc FROM challenges
             WHERE challenge_id = ?1 AND kind = 'webauthn_login'",
            params![request.challenge_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "CHALLENGE_INVALID",
                "WebAuthn login challenge is unknown",
            )
        }
        Err(error) => return service_error(error.into()),
    };
    if challenge.2 <= now_utc() || challenge.3.is_some() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_EXPIRED",
            "WebAuthn login challenge is expired or already used",
        );
    }
    let expected_challenge = match hex::decode(&challenge.1) {
        Ok(value) => b64_encode(&value),
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CHALLENGE_INVALID",
                "Stored challenge is invalid",
            )
        }
    };
    if let Err(error) = validate_client_data(&client_data, "webauthn.get", &expected_challenge) {
        return service_error(error);
    }
    let credential = match db
        .query_row(
            "SELECT device_id_hex, algorithm, public_key_hex, sign_count, revoked_at_utc FROM webauthn_credentials
             WHERE account_id = ?1 AND credential_id_hex = ?2",
            params![challenge.0, hex::encode(&credential_id)],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u32,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "CREDENTIAL_UNKNOWN",
                "WebAuthn credential is not enrolled for this account",
            )
        }
        Err(error) => return service_error(error.into()),
    };
    if credential.4.is_some() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CREDENTIAL_REVOKED",
            "WebAuthn credential has been revoked",
        );
    }
    if let Some(device_id_hex) = credential.0.as_deref() {
        let active = db
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM devices
                     WHERE account_id = ?1 AND device_id_hex = ?2 AND revoked_at_utc IS NULL
                 )",
                params![challenge.0, device_id_hex],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false);
        if !active {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "DEVICE_REVOKED",
                "The device bound to this WebAuthn credential is revoked or missing",
            );
        }
    }
    let client_hash = Sha256::digest(&client_data);
    let mut signed_data = Vec::with_capacity(authenticator_data.len() + client_hash.len());
    signed_data.extend_from_slice(&authenticator_data);
    signed_data.extend_from_slice(&client_hash);
    let public_key = match hex::decode(&credential.2) {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CREDENTIAL_INVALID",
                "Stored WebAuthn credential is invalid",
            )
        }
    };
    if let Err(error) = verify_webauthn_signature(
        credential.1,
        &public_key,
        &signed_data,
        &assertion_signature,
    ) {
        return service_error(error);
    }
    if (credential.3 != 0 && parsed_authenticator.sign_count == 0)
        || (credential.3 != 0 && parsed_authenticator.sign_count <= credential.3)
    {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "SIGN_COUNT_REPLAY",
            "WebAuthn signature counter did not advance",
        );
    }
    let now = now_utc();
    if let Err(error) = db.execute(
        "UPDATE webauthn_credentials SET sign_count = ?3, last_used_at_utc = ?4
         WHERE account_id = ?1 AND credential_id_hex = ?2 AND revoked_at_utc IS NULL",
        params![
            challenge.0,
            hex::encode(&credential_id),
            parsed_authenticator.sign_count,
            now
        ],
    ) {
        return service_error(error.into());
    }
    let challenge_consumed = match db.execute(
        "UPDATE challenges SET used_at_utc = ?2 WHERE challenge_id = ?1 AND used_at_utc IS NULL",
        params![request.challenge_id, now],
    ) {
        Ok(changed) => changed == 1,
        Err(error) => return service_error(error.into()),
    };
    if !challenge_consumed {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_REPLAY",
            "WebAuthn authentication challenge was already consumed",
        );
    }
    let token = random_hex(32);
    let expires_at = now + SESSION_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc)
         VALUES(?1, ?2, ?3, ?4, 'webauthn', ?5, ?6)",
        params![
            hash_token(&token),
            challenge.0,
            credential.0.as_deref(),
            hex::encode(&credential_id),
            now,
            expires_at
        ],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &challenge.0,
        "webauthn_login",
        serde_json::json!({"credential_id_b64": request.credential_id_b64}),
    ) {
        return service_error(error.into());
    }
    let mut response = Json(SessionResponse {
        token: token.clone(),
        session: SessionView {
            account_id: challenge.0,
            device_id_hex: credential.0.clone(),
            auth_method: "webauthn".into(),
            issued_at_utc: now,
            expires_at_utc: expires_at,
        },
    })
    .into_response();
    attach_session_cookie(&mut response, &token);
    response
}

fn totp_not_configured() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "TOTP_NOT_CONFIGURED",
        format!("{TOTP_KEY_FILE_ENV} or {TOTP_KEY_ENV} is not configured on the account service"),
    )
}

fn account_session_for(
    state: &AccountState,
    headers: &HeaderMap,
    account_id: &str,
) -> Result<SessionView, Box<Response>> {
    let session = authenticated_session(state, headers).map_err(Box::new)?;
    if session.account_id != account_id {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        )));
    }
    if session.auth_method == "recovery" {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "RECOVERY_STEP_UP_REQUIRED",
            "Recovery sessions must enroll a device or complete a hardware/passkey step-up before account changes",
        )));
    }
    Ok(session)
}

/// Start TOTP enrollment for an already authenticated account session. The
/// secret is returned once so the user can scan it into an authenticator app;
/// the database stores only an encrypted envelope and remains disabled until
/// the first code is verified.
pub async fn post_totp_enrollment(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if let Err(response) = account_session_for(&state, &headers, &account_id) {
        return *response;
    }
    if totp_wrapping_key().is_err() {
        return totp_not_configured();
    }
    let secret = totp::generate_secret();
    let secret_base32 = totp::base32_encode(&secret);
    let ciphertext = match encrypt_totp_secret(&secret) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let now = now_utc();
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let active = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM totp_credentials
             WHERE account_id = ?1 AND enabled != 0 AND revoked_at_utc IS NULL)",
            params![account_id],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    if active {
        return error_response(
            StatusCode::CONFLICT,
            "TOTP_ALREADY_ENABLED",
            "Revoke the existing authenticator before enrolling a replacement",
        );
    }
    if let Err(error) = db.execute(
        "INSERT INTO totp_credentials(account_id, secret_ciphertext_b64, enabled, created_at_utc, revoked_at_utc)
         VALUES(?1, ?2, 0, ?3, NULL)
         ON CONFLICT(account_id) DO UPDATE SET
           secret_ciphertext_b64 = excluded.secret_ciphertext_b64,
           enabled = 0,
           created_at_utc = excluded.created_at_utc,
           last_used_step = NULL,
           last_used_at_utc = NULL,
           revoked_at_utc = NULL",
        params![account_id, ciphertext, now],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "totp_enrollment_started",
        serde_json::json!({"algorithm": "SHA1", "digits": totp::DIGITS, "period_seconds": totp::STEP_SECONDS}),
    ) {
        return service_error(error.into());
    }
    let uri = format!(
        "otpauth://totp/CipherVault:{}?secret={}&issuer=CipherVault&algorithm=SHA1&digits={}&period={}",
        account_id,
        secret_base32,
        totp::DIGITS,
        totp::STEP_SECONDS,
    );
    Json(TotpEnrollmentView {
        account_id,
        secret_base32,
        otpauth_uri: uri,
        issuer: "CipherVault".into(),
        algorithm: "SHA1".into(),
        digits: totp::DIGITS as u8,
        period_seconds: totp::STEP_SECONDS,
    })
    .into_response()
}

pub async fn post_totp_enrollment_verify(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<TotpCodeRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let rate_key = auth_rate_key(&headers, &account_id, "totp-enrollment");
    if let Err(response) = auth_rate_allowed(&state, &rate_key) {
        return *response;
    }
    if let Err(response) = account_session_for(&state, &headers, &account_id) {
        return *response;
    }
    if totp_wrapping_key().is_err() {
        return totp_not_configured();
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let row = match db
        .query_row(
            "SELECT secret_ciphertext_b64, enabled, revoked_at_utc, last_used_step
             FROM totp_credentials WHERE account_id = ?1",
            params![account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?.map(|value| value as u64),
                ))
            },
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return service_error(error.into()),
    };
    let Some((ciphertext, enabled, revoked_at, last_used_step)) = row else {
        return error_response(
            StatusCode::NOT_FOUND,
            "TOTP_NOT_ENROLLED",
            "Begin TOTP enrollment first",
        );
    };
    if enabled || revoked_at.is_some() {
        return error_response(
            StatusCode::CONFLICT,
            "TOTP_ENROLLMENT_INVALID",
            "No pending TOTP enrollment is available",
        );
    }
    let secret = match decrypt_totp_secret(&ciphertext) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let step = match totp::verify_code(&secret, &request.code, now_utc(), last_used_step) {
        Ok(step) => step,
        Err(error) => {
            auth_rate_failure_with_db(&db, &rate_key);
            return error_response(
                StatusCode::UNAUTHORIZED,
                "TOTP_CODE_INVALID",
                error.to_string(),
            );
        }
    };
    let now = now_utc();
    let changed = match db.execute(
        "UPDATE totp_credentials SET enabled = 1, last_used_step = ?2, last_used_at_utc = ?3
         WHERE account_id = ?1 AND enabled = 0 AND revoked_at_utc IS NULL",
        params![account_id, step as i64, now],
    ) {
        Ok(changed) => changed,
        Err(error) => return service_error(error.into()),
    };
    if changed != 1 {
        return error_response(
            StatusCode::CONFLICT,
            "TOTP_ENROLLMENT_INVALID",
            "The pending TOTP enrollment was already confirmed",
        );
    }
    if let Err(error) = audit_event(&db, &account_id, "totp_enabled", serde_json::json!({})) {
        return service_error(error.into());
    }
    drop(db);
    auth_rate_success(&state, &rate_key);
    Json(serde_json::json!({"status": "enabled", "account_id": account_id})).into_response()
}

pub async fn post_totp_revoke(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if let Err(response) = account_session_for(&state, &headers, &account_id) {
        return *response;
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let now = now_utc();
    let changed = match db.execute(
        "UPDATE totp_credentials SET enabled = 0, revoked_at_utc = ?2 WHERE account_id = ?1 AND revoked_at_utc IS NULL",
        params![account_id, now],
    ) {
        Ok(changed) => changed,
        Err(error) => return service_error(error.into()),
    };
    if changed == 0 {
        return error_response(
            StatusCode::NOT_FOUND,
            "TOTP_NOT_ENROLLED",
            "No active authenticator is enrolled",
        );
    }
    if let Err(error) = audit_event(&db, &account_id, "totp_revoked", serde_json::json!({})) {
        return service_error(error.into());
    }
    Json(serde_json::json!({"status": "revoked", "account_id": account_id})).into_response()
}

pub async fn post_totp_authentication_options(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(request): Json<TotpAuthenticationOptionsRequest>,
) -> Response {
    let account_id = match normalize_account_id(&request.account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let rate_key = auth_rate_key(&headers, &account_id, "totp-login");
    if let Err(response) = auth_rate_allowed(&state, &rate_key) {
        return *response;
    }
    if totp_wrapping_key().is_err() {
        return totp_not_configured();
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let enabled = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM totp_credentials
             WHERE account_id = ?1 AND enabled != 0 AND revoked_at_utc IS NULL)",
            params![account_id],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    if !enabled {
        return error_response(
            StatusCode::NOT_FOUND,
            "TOTP_NOT_ENROLLED",
            "No active authenticator is enrolled",
        );
    }
    let challenge_id = random_hex(16);
    let nonce_hex = random_hex(32);
    let expires_at = now_utc() + CHALLENGE_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO challenges(challenge_id, kind, account_id, nonce_hex, expires_at_utc)
         VALUES(?1, 'totp_login', ?2, ?3, ?4)",
        params![challenge_id, account_id, nonce_hex, expires_at],
    ) {
        return service_error(error.into());
    }
    Json(TotpAuthenticationOptionsView {
        account_id,
        challenge_id,
        expires_at_utc: expires_at,
        digits: totp::DIGITS as u8,
        period_seconds: totp::STEP_SECONDS,
        ceremony: "totp.get".into(),
    })
    .into_response()
}

pub async fn post_totp_authentication_verify(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(request): Json<TotpAuthenticationVerifyRequest>,
) -> Response {
    let account_id = match normalize_account_id(&request.account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let rate_key = auth_rate_key(&headers, &account_id, "totp-login");
    if let Err(response) = auth_rate_allowed(&state, &rate_key) {
        return *response;
    }
    if totp_wrapping_key().is_err() {
        return totp_not_configured();
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let now = now_utc();
    let challenge = match db
        .query_row(
            "SELECT nonce_hex, expires_at_utc, used_at_utc FROM challenges
             WHERE challenge_id = ?1 AND kind = 'totp_login' AND account_id = ?2",
            params![request.challenge_id, account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return service_error(error.into()),
    };
    let Some((_, expires_at, used_at)) = challenge else {
        auth_rate_failure_with_db(&db, &rate_key);
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_INVALID",
            "TOTP challenge is unknown",
        );
    };
    if expires_at <= now || used_at.is_some() {
        auth_rate_failure_with_db(&db, &rate_key);
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_EXPIRED",
            "TOTP challenge is expired or already used",
        );
    }
    let row = match db
        .query_row(
            "SELECT secret_ciphertext_b64, last_used_step FROM totp_credentials
             WHERE account_id = ?1 AND enabled != 0 AND revoked_at_utc IS NULL",
            params![account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?.map(|value| value as u64),
                ))
            },
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return service_error(error.into()),
    };
    let Some((ciphertext, last_used_step)) = row else {
        auth_rate_failure_with_db(&db, &rate_key);
        return error_response(
            StatusCode::NOT_FOUND,
            "TOTP_NOT_ENROLLED",
            "No active authenticator is enrolled",
        );
    };
    let secret = match decrypt_totp_secret(&ciphertext) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let step = match totp::verify_code(&secret, &request.code, now, last_used_step) {
        Ok(step) => step,
        Err(error) => {
            auth_rate_failure_with_db(&db, &rate_key);
            return error_response(
                StatusCode::UNAUTHORIZED,
                "TOTP_CODE_INVALID",
                error.to_string(),
            );
        }
    };
    let changed = match db.execute(
        "UPDATE totp_credentials SET last_used_step = ?2, last_used_at_utc = ?3
         WHERE account_id = ?1 AND enabled != 0 AND revoked_at_utc IS NULL
           AND (last_used_step IS NULL OR last_used_step < ?2)",
        params![account_id, step as i64, now],
    ) {
        Ok(changed) => changed,
        Err(error) => return service_error(error.into()),
    };
    if changed != 1 {
        auth_rate_failure_with_db(&db, &rate_key);
        return error_response(
            StatusCode::UNAUTHORIZED,
            "TOTP_REPLAY",
            "TOTP code was already used",
        );
    }
    let challenge_consumed = match db.execute(
        "UPDATE challenges SET used_at_utc = ?2 WHERE challenge_id = ?1 AND used_at_utc IS NULL",
        params![request.challenge_id, now],
    ) {
        Ok(changed) => changed == 1,
        Err(error) => return service_error(error.into()),
    };
    if !challenge_consumed {
        auth_rate_failure_with_db(&db, &rate_key);
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_REPLAY",
            "TOTP challenge was already consumed",
        );
    }
    let token = random_hex(32);
    let expires_at = now + SESSION_TTL_SECONDS;
    if let Err(error) = db.execute(
        "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc)
         VALUES(?1, ?2, NULL, NULL, 'totp', ?3, ?4)",
        params![hash_token(&token), account_id, now, expires_at],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(&db, &account_id, "totp_login", serde_json::json!({})) {
        return service_error(error.into());
    }
    drop(db);
    auth_rate_success(&state, &rate_key);
    let mut response = Json(SessionResponse {
        token: token.clone(),
        session: SessionView {
            account_id,
            device_id_hex: None,
            auth_method: "totp".into(),
            issued_at_utc: now,
            expires_at_utc: expires_at,
        },
    })
    .into_response();
    attach_session_cookie(&mut response, &token);
    response
}

pub fn create_router(state: AccountState) -> axum::Router {
    use axum::routing::{get, post};
    let cors = std::env::var("CIPHERVAULT_ACCOUNT_ALLOWED_ORIGINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|origin| origin.trim().parse().ok())
                .collect::<Vec<axum::http::HeaderValue>>()
        })
        .filter(|origins| !origins.is_empty())
        .map(|origins| {
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ])
                .allow_credentials(true)
        })
        .unwrap_or_default();
    axum::Router::new()
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({"status": "ready"})) }),
        )
        .route("/v1/capabilities", get(get_capabilities))
        .route("/v1/accounts", post(post_account))
        .route("/v1/accounts/:account_id", get(get_account))
        .route("/v1/accounts/:account_id/audit", get(get_account_audit))
        .route(
            "/v1/accounts/:account_id/devices/challenge",
            post(post_device_challenge),
        )
        .route(
            "/v1/accounts/:account_id/devices",
            post(post_device_enrollment),
        )
        .route(
            "/v1/accounts/:account_id/devices/:device_id_hex/revoke",
            post(post_device_revoke),
        )
        .route("/v1/sessions/challenge", post(post_login_challenge))
        .route("/v1/sessions", post(post_login).get(get_session))
        .route("/v1/sessions/revoke", post(post_session_revoke))
        .route("/v1/sessions/handoff", post(post_session_handoff))
        .route(
            "/v1/sessions/handoff/consume",
            post(post_session_handoff_consume),
        )
        .route(
            "/v1/accounts/:account_id/webauthn/registration/options",
            post(post_webauthn_registration_options),
        )
        .route(
            "/v1/accounts/:account_id/webauthn/credentials/:credential_id_hex/revoke",
            post(post_webauthn_revoke),
        )
        .route(
            "/v1/accounts/:account_id/webauthn/registration/verify",
            post(post_webauthn_registration_verify),
        )
        .route(
            "/v1/webauthn/authentication/options",
            post(post_webauthn_authentication_options),
        )
        .route(
            "/v1/webauthn/authentication/verify",
            post(post_webauthn_authentication_verify),
        )
        .route(
            "/v1/totp/authentication/options",
            post(post_totp_authentication_options),
        )
        .route(
            "/v1/totp/authentication/verify",
            post(post_totp_authentication_verify),
        )
        .route(
            "/v1/accounts/:account_id/totp/enrollment",
            post(post_totp_enrollment),
        )
        .route(
            "/v1/accounts/:account_id/totp/enrollment/verify",
            post(post_totp_enrollment_verify),
        )
        .route(
            "/v1/accounts/:account_id/totp/revoke",
            post(post_totp_revoke),
        )
        .route("/v1/accounts/:account_id/vaults", post(post_vault_link))
        .route(
            "/v1/accounts/:account_id/invitations",
            post(post_invitation).get(get_invitations),
        )
        .route("/v1/invitations/accept", post(post_invitation_accept))
        .route("/v1/accounts/:account_id/memberships", get(get_memberships))
        .route(
            "/v1/accounts/:account_id/memberships/:member_account_id/revoke",
            post(post_membership_revoke),
        )
        .route(
            "/v1/accounts/:account_id/recovery/codes",
            post(post_recovery_codes),
        )
        .route("/v1/recovery/redeem", post(post_recovery_redeem))
        .layer(cors)
        .layer(axum::middleware::from_fn(csrf_origin_guard))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
    use ed25519_dalek::Signer;
    use tower05::ServiceExt;

    async fn json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .expect("body");
        serde_json::from_slice(&body).expect("json")
    }

    #[tokio::test]
    async fn account_device_proof_login_and_revocation_lifecycle() {
        let root = std::env::temp_dir().join(format!("cv-account-service-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state);
        let capabilities = app
            .clone()
            .oneshot(
                Request::get("/v1/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(capabilities.status(), StatusCode::OK);
        let capabilities_json = json(capabilities).await;
        assert_eq!(capabilities_json["webauthn"], true);
        assert_eq!(capabilities_json["managed_session_cookie"], true);
        let account_key = generate_signing_key();
        let account_pk = hex::encode(account_key.verifying_key().as_bytes());
        let created = app
            .clone()
            .oneshot(
                Request::post("/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "display_name": "Alice",
                            "account_public_key_hex": account_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let account = json(created).await;
        let account_id = account["account_id"].as_str().unwrap().to_string();
        let unauthenticated_account = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{account_id}").as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated_account.status(), StatusCode::UNAUTHORIZED);
        let device_key = generate_signing_key();
        let device_id = "aa".repeat(32);
        let device_pk = hex::encode(device_key.verifying_key().as_bytes());
        let challenge = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices/challenge").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_id,
                            "public_key_hex": device_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_json = json(challenge).await;
        let challenge_id = challenge_json["challenge_id"].as_str().unwrap();
        let nonce = challenge_json["nonce_hex"].as_str().unwrap();
        let proof_bytes = challenge_signing_bytes(
            &account_id,
            Some(&device_id),
            Some(&device_pk),
            challenge_id,
            nonce,
        );
        let proof = hex::encode(sign_with_domain(
            &account_key,
            b"account_device_enrollment",
            &proof_bytes,
        ));
        let enrolled = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_id,
                            "public_key_hex": device_pk,
                            "challenge_id": challenge_id,
                            "proof_signature_hex": proof,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enrolled.status(), StatusCode::CREATED);
        let login_challenge = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "device_id_hex": device_id,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let login_json = json(login_challenge).await;
        let login_id = login_json["challenge_id"].as_str().unwrap();
        let login_nonce = login_json["nonce_hex"].as_str().unwrap();
        let login_bytes =
            challenge_signing_bytes(&account_id, Some(&device_id), None, login_id, login_nonce);
        let login_signature = hex::encode(sign_with_domain(
            &account_key,
            b"account_login",
            &login_bytes,
        ));
        let session = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": login_id,
                            "signature_hex": login_signature,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        assert!(session
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("ciphervault_account_session=")));
        let session_json = json(session).await;
        let token = session_json["token"].as_str().unwrap().to_string();
        let current = app
            .clone()
            .oneshot(
                Request::get("/v1/sessions")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(current.status(), StatusCode::OK);
        let cookie_current = app
            .clone()
            .oneshot(
                Request::get("/v1/sessions")
                    .header("cookie", format!("{SESSION_COOKIE_NAME}={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cookie_current.status(), StatusCode::OK);
        let handoff = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/handoff")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(handoff.status(), StatusCode::OK);
        let handoff_json = json(handoff).await;
        let handoff_code = handoff_json["handoff_code"].as_str().unwrap().to_string();
        let browser_handoff = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/handoff/consume")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "handoff_code": handoff_code,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(browser_handoff.status(), StatusCode::OK);
        assert!(browser_handoff
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("ciphervault_account_session=")));
        let replay = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/handoff/consume")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "handoff_code": handoff_code,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        let registration_options = app
            .clone()
            .oneshot(
                Request::post(
                    format!("/v1/accounts/{account_id}/webauthn/registration/options").as_str(),
                )
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registration_options.status(), StatusCode::OK);
        let registration_options_json = json(registration_options).await;
        let registration_challenge_id = registration_options_json["challenge_id"].as_str().unwrap();
        let registration_challenge = registration_options_json["challenge"].as_str().unwrap();
        let credential_id = vec![0x42; 32];
        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&Sha256::digest(b"localhost"));
        authenticator_data.push(0x41); // user present + attested credential data
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        authenticator_data.extend_from_slice(&[0u8; 16]);
        authenticator_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        authenticator_data.extend_from_slice(&credential_id);
        let cose_key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer((-8).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(6.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(device_key.verifying_key().as_bytes().to_vec()),
            ),
        ]);
        let mut cose_bytes = Vec::new();
        ciborium::ser::into_writer(&cose_key, &mut cose_bytes).unwrap();
        authenticator_data.extend_from_slice(&cose_bytes);
        let attestation_object = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".into()),
                ciborium::Value::Text("none".into()),
            ),
            (
                ciborium::Value::Text("authData".into()),
                ciborium::Value::Bytes(authenticator_data),
            ),
            (
                ciborium::Value::Text("attStmt".into()),
                ciborium::Value::Map(Vec::new()),
            ),
        ]);
        let mut attestation_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation_object, &mut attestation_bytes).unwrap();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": registration_challenge,
            "origin": "http://localhost:8300",
        });
        let registration_verify = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/webauthn/registration/verify").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": registration_challenge_id,
                            "credential_id_b64": b64_encode(&credential_id),
                            "client_data_json_b64": b64_encode(&serde_json::to_vec(&client_data).unwrap()),
                            "attestation_object_b64": b64_encode(&attestation_bytes),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registration_verify.status(), StatusCode::CREATED);
        let authentication_options = app
            .clone()
            .oneshot(
                Request::post("/v1/webauthn/authentication/options")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"account_id": account_id})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authentication_options.status(), StatusCode::OK);
        let authentication_options_json = json(authentication_options).await;
        let authentication_challenge_id = authentication_options_json["challenge_id"]
            .as_str()
            .unwrap();
        let authentication_challenge = authentication_options_json["challenge"].as_str().unwrap();
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": authentication_challenge,
            "origin": "http://localhost:8300",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let mut assertion_auth_data = Vec::new();
        assertion_auth_data.extend_from_slice(&Sha256::digest(b"localhost"));
        assertion_auth_data.push(0x01); // user present
        assertion_auth_data.extend_from_slice(&2u32.to_be_bytes());
        let mut signed_assertion = assertion_auth_data.clone();
        signed_assertion.extend_from_slice(&Sha256::digest(&client_data_bytes));
        let assertion_signature = device_key.sign(&signed_assertion);
        let authentication_verify = app
            .clone()
            .oneshot(
                Request::post("/v1/webauthn/authentication/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": authentication_challenge_id,
                            "credential_id_b64": b64_encode(&credential_id),
                            "client_data_json_b64": b64_encode(&client_data_bytes),
                            "authenticator_data_b64": b64_encode(&assertion_auth_data),
                            "signature_b64": b64_encode(&assertion_signature.to_bytes()),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authentication_verify.status(), StatusCode::OK);
        let authentication_json = json(authentication_verify).await;
        let webauthn_token = authentication_json["token"].as_str().unwrap().to_string();
        let authentication_replay = app
            .clone()
            .oneshot(
                Request::post("/v1/webauthn/authentication/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": authentication_challenge_id,
                            "credential_id_b64": b64_encode(&credential_id),
                            "client_data_json_b64": b64_encode(&client_data_bytes),
                            "authenticator_data_b64": b64_encode(&assertion_auth_data),
                            "signature_b64": b64_encode(&assertion_signature.to_bytes()),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authentication_replay.status(), StatusCode::UNAUTHORIZED);
        let credential_revoke = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/v1/accounts/{account_id}/webauthn/credentials/{}/revoke",
                    hex::encode(&credential_id)
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(credential_revoke.status(), StatusCode::OK);
        let authentication_after_credential_revoke = app
            .clone()
            .oneshot(
                Request::post("/v1/webauthn/authentication/options")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"account_id": account_id})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            authentication_after_credential_revoke.status(),
            StatusCode::NOT_FOUND
        );
        let account_view_response = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{account_id}").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(account_view_response.status(), StatusCode::OK);
        let account_view_json = json(account_view_response).await;
        assert_eq!(account_view_json["devices"].as_array().unwrap().len(), 1);
        assert_eq!(
            account_view_json["webauthn_credentials"][0]["device_id_hex"],
            device_id
        );
        let recovery_codes = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/recovery/codes").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"count":4}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovery_codes.status(), StatusCode::OK);
        let recovery_json = json(recovery_codes).await;
        let recovery_code = recovery_json["codes"][0].as_str().unwrap().to_string();
        let recovery_session = app
            .clone()
            .oneshot(
                Request::post("/v1/recovery/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "code": recovery_code,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovery_session.status(), StatusCode::OK);
        let recovery_replay = app
            .clone()
            .oneshot(
                Request::post("/v1/recovery/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "code": recovery_json["codes"][0],
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovery_replay.status(), StatusCode::UNAUTHORIZED);
        let audit_response = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{account_id}/audit").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(audit_response.status(), StatusCode::OK);
        let audit_json = json(audit_response).await;
        let events = audit_json["events"].as_array().unwrap();
        assert!(events
            .iter()
            .any(|event| event["event"] == "account_created"));
        assert!(events
            .iter()
            .any(|event| event["event"] == "device_enrolled"));
        assert!(events
            .iter()
            .any(|event| event["event"] == "session_created"));
        let revoke = app
            .clone()
            .oneshot(
                Request::post(
                    format!("/v1/accounts/{account_id}/devices/{device_id}/revoke").as_str(),
                )
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);
        let after = app
            .clone()
            .oneshot(
                Request::get("/v1/sessions")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
        let webauthn_after = app
            .oneshot(
                Request::get("/v1/sessions")
                    .header("authorization", format!("Bearer {webauthn_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(webauthn_after.status(), StatusCode::UNAUTHORIZED);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn totp_enrollment_login_and_replay_protection() {
        let previous_key = std::env::var(TOTP_KEY_ENV).ok();
        std::env::set_var(TOTP_KEY_ENV, "11".repeat(32));
        let root = std::env::temp_dir().join(format!("cv-account-totp-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state.clone());
        let account_key = generate_signing_key();
        let created = app
            .clone()
            .oneshot(
                Request::post("/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "display_name": "TOTP test",
                            "account_public_key_hex": hex::encode(account_key.verifying_key().as_bytes()),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let account = json(created).await;
        let account_id = account["account_id"].as_str().unwrap().to_string();
        let session_token = random_hex(32);
        {
            let db = state.connection().expect("db");
            let now = now_utc();
            db.execute(
                "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, issued_at_utc, expires_at_utc)
                 VALUES(?1, ?2, NULL, NULL, ?3, ?4)",
                params![hash_token(&session_token), account_id, now, now + SESSION_TTL_SECONDS],
            )
            .unwrap();
        }
        let bearer = format!("Bearer {session_token}");
        let enrollment = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/totp/enrollment").as_str())
                    .header("authorization", &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enrollment.status(), StatusCode::OK);
        let enrollment_json = json(enrollment).await;
        let secret =
            totp::base32_decode(enrollment_json["secret_base32"].as_str().unwrap()).unwrap();
        let current_step = now_utc() / totp::STEP_SECONDS;
        let code = totp::code_for_step(&secret, current_step.saturating_sub(1)).unwrap();
        let confirmed = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/totp/enrollment/verify").as_str())
                    .header("authorization", &bearer)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({"code": code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(confirmed.status(), StatusCode::OK);
        let options = app
            .clone()
            .oneshot(
                Request::post("/v1/totp/authentication/options")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"account_id": account_id}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(options.status(), StatusCode::OK);
        let options_json = json(options).await;
        let next_code = totp::code_for_step(&secret, current_step).unwrap();
        let verified = app
            .clone()
            .oneshot(
                Request::post("/v1/totp/authentication/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "account_id": account_id,
                            "challenge_id": options_json["challenge_id"],
                            "code": next_code,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verified.status(), StatusCode::OK);
        let replay = app
            .oneshot(
                Request::post("/v1/totp/authentication/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "account_id": account_id,
                            "challenge_id": options_json["challenge_id"],
                            "code": next_code,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        let _ = fs::remove_dir_all(root);
        if let Some(value) = previous_key {
            std::env::set_var(TOTP_KEY_ENV, value);
        } else {
            std::env::remove_var(TOTP_KEY_ENV);
        }
    }

    #[tokio::test]
    async fn membership_roles_and_origins_are_enforced() {
        let root = std::env::temp_dir().join(format!("cv-account-roles-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state.clone());
        let owner = format!("cvacct_{}", "11".repeat(16));
        let viewer = format!("cvacct_{}", "22".repeat(16));
        let admin = format!("cvacct_{}", "33".repeat(16));
        let invitee = format!("cvacct_{}", "44".repeat(16));
        let viewer_token = random_hex(32);
        let admin_token = random_hex(32);
        let owner_token = random_hex(32);
        {
            let db = state.connection().expect("db");
            for (account_id, key) in [
                (&owner, "aa".repeat(32)),
                (&viewer, "bb".repeat(32)),
                (&admin, "cc".repeat(32)),
                (&invitee, "dd".repeat(32)),
            ] {
                db.execute(
                    "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                     VALUES(?1, ?2, ?3, ?4)",
                    params![account_id, account_id, key, now_utc() as i64],
                )
                .unwrap();
            }
            for (token, account_id) in [
                (&owner_token, &owner),
                (&viewer_token, &viewer),
                (&admin_token, &admin),
            ] {
                db.execute(
                    "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc)
                     VALUES(?1, ?2, NULL, NULL, 'device', ?3, ?4)",
                    params![hash_token(token), account_id, now_utc() as i64, (now_utc() + SESSION_TTL_SECONDS) as i64],
                )
                .unwrap();
            }
            db.execute(
                "INSERT INTO memberships(account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc)
                 VALUES(?1, ?2, 'viewer', 'active', ?3, ?3)",
                params![owner, viewer, now_utc() as i64],
            )
            .unwrap();
            db.execute(
                "INSERT INTO memberships(account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc)
                 VALUES(?1, ?2, 'admin', 'active', ?3, ?3)",
                params![owner, admin, now_utc() as i64],
            )
            .unwrap();
        }

        let viewer_memberships = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{owner}/memberships").as_str())
                    .header("authorization", format!("Bearer {viewer_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer_memberships.status(), StatusCode::OK);

        let viewer_invite = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{owner}/invitations").as_str())
                    .header("authorization", format!("Bearer {viewer_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"invitee_account_id": invitee, "role": "viewer"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer_invite.status(), StatusCode::FORBIDDEN);

        let viewer_link = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{owner}/vaults").as_str())
                    .header("authorization", format!("Bearer {viewer_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "vault_id_hex": "55".repeat(32),
                            "alias": "shared",
                            "role": "viewer"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer_link.status(), StatusCode::FORBIDDEN);

        let admin_owner_invite = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{owner}/invitations").as_str())
                    .header("authorization", format!("Bearer {admin_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"invitee_account_id": invitee, "role": "admin"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin_owner_invite.status(), StatusCode::FORBIDDEN);

        let evil_origin = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{owner}/invitations").as_str())
                    .header("authorization", format!("Bearer {owner_token}"))
                    .header("origin", "https://evil.example")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"invitee_account_id": invitee, "role": "viewer"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(evil_origin.status(), StatusCode::FORBIDDEN);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn authentication_rate_limiter_blocks_repeated_failures() {
        let root = std::env::temp_dir().join(format!("cv-account-rate-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        // Lockout audit events are FK-bound to accounts: seed the account the
        // rate key names so the alert lands in the audit trail.
        state
            .connection()
            .expect("db")
            .execute(
                "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc) VALUES(?1, 'Test', ?2, 1)",
                params!["cvacct_test", random_hex(32)],
            )
            .expect("seed account");
        let key = "totp-login:cvacct_test:unknown";
        for _ in 0..AUTH_RATE_MAX_FAILURES {
            assert!(auth_rate_allowed(&state, key).is_ok());
            auth_rate_failure(&state, key);
        }
        assert!(auth_rate_allowed(&state, key).is_err());
        // Unknown accounts still lock out, but there is no account row to hang
        // an audit event on: the stderr alert fires, the audit count is unchanged.
        let unknown_key = "totp-login:cvacct_missing:unknown";
        for _ in 0..AUTH_RATE_MAX_FAILURES {
            assert!(auth_rate_allowed(&state, unknown_key).is_ok());
            auth_rate_failure(&state, unknown_key);
        }
        assert!(auth_rate_allowed(&state, unknown_key).is_err());
        let db = state.connection().expect("db");
        let lockouts: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE event = 'auth_rate_lockout'",
                [],
                |row| row.get(0),
            )
            .expect("count lockouts");
        assert_eq!(lockouts, 1);
        drop(db);
        drop(state);
        let reopened = AccountState::open(&root).expect("reopened state");
        assert!(auth_rate_allowed(&reopened, key).is_err());
        auth_rate_success(&reopened, key);
        assert!(auth_rate_allowed(&reopened, key).is_ok());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn recovery_session_enrolls_replacement_device() {
        let root =
            std::env::temp_dir().join(format!("cv-account-recovery-enroll-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state);
        let account_key = generate_signing_key();
        let account_pk = hex::encode(account_key.verifying_key().as_bytes());
        let created = app
            .clone()
            .oneshot(
                Request::post("/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "display_name": "Recovery",
                            "account_public_key_hex": account_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let account = json(created).await;
        let account_id = account["account_id"].as_str().unwrap().to_string();

        // Enroll device A through the standard account-signed path.
        let device_a_id = "aa".repeat(32);
        let device_a_key = generate_signing_key();
        let device_a_pk = hex::encode(device_a_key.verifying_key().as_bytes());
        let challenge_a = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices/challenge").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_a_id,
                            "public_key_hex": device_a_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_a_json = json(challenge_a).await;
        let proof_a = hex::encode(sign_with_domain(
            &account_key,
            b"account_device_enrollment",
            &challenge_signing_bytes(
                &account_id,
                Some(&device_a_id),
                Some(&device_a_pk),
                challenge_a_json["challenge_id"].as_str().unwrap(),
                challenge_a_json["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let enrolled_a = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_a_id,
                            "public_key_hex": device_a_pk,
                            "challenge_id": challenge_a_json["challenge_id"],
                            "proof_signature_hex": proof_a,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enrolled_a.status(), StatusCode::CREATED);

        // Log in device A and issue recovery codes.
        let login_challenge = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "device_id_hex": device_a_id,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let login_json = json(login_challenge).await;
        let login_proof = hex::encode(sign_with_domain(
            &account_key,
            b"account_login",
            &challenge_signing_bytes(
                &account_id,
                Some(&device_a_id),
                None,
                login_json["challenge_id"].as_str().unwrap(),
                login_json["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let session = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": login_json["challenge_id"],
                            "signature_hex": login_proof,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        let token = json(session)
            .await
            .get("token")
            .and_then(|value| value.as_str())
            .unwrap()
            .to_string();
        let codes = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/recovery/codes").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"count":4}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(codes.status(), StatusCode::OK);
        let recovery_code = json(codes)
            .await
            .get("codes")
            .and_then(|codes| codes.get(0))
            .and_then(|code| code.as_str())
            .unwrap()
            .to_string();

        // Redeem: short explicit TTL and a recovery-marked session.
        let redeemed = app
            .clone()
            .oneshot(
                Request::post("/v1/recovery/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "code": recovery_code,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redeemed.status(), StatusCode::OK);
        let redeemed_json = json(redeemed).await;
        let recovery_token = redeemed_json["token"].as_str().unwrap().to_string();
        assert_eq!(redeemed_json["session"]["auth_method"], "recovery");
        let issued = redeemed_json["session"]["issued_at_utc"].as_u64().unwrap();
        let expires = redeemed_json["session"]["expires_at_utc"].as_u64().unwrap();
        assert_eq!(expires - issued, RECOVERY_SESSION_TTL_SECONDS);

        // A device-signed proof alone (no recovery session) must fail.
        let device_c_id = "cc".repeat(32);
        let device_c_key = generate_signing_key();
        let device_c_pk = hex::encode(device_c_key.verifying_key().as_bytes());
        let challenge_c = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices/challenge").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_c_id,
                            "public_key_hex": device_c_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_c_json = json(challenge_c).await;
        let proof_c = hex::encode(sign_with_domain(
            &device_c_key,
            b"account_device_enrollment",
            &challenge_signing_bytes(
                &account_id,
                Some(&device_c_id),
                Some(&device_c_pk),
                challenge_c_json["challenge_id"].as_str().unwrap(),
                challenge_c_json["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let denied = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_c_id,
                            "public_key_hex": device_c_pk,
                            "challenge_id": challenge_c_json["challenge_id"],
                            "proof_signature_hex": proof_c,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        // With the recovery session, device B self-certifies and enrolls.
        let device_b_id = "bb".repeat(32);
        let device_b_key = generate_signing_key();
        let device_b_pk = hex::encode(device_b_key.verifying_key().as_bytes());
        let challenge_b = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices/challenge").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_b_id,
                            "public_key_hex": device_b_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_b_json = json(challenge_b).await;
        let proof_b = hex::encode(sign_with_domain(
            &device_b_key,
            b"account_device_enrollment",
            &challenge_signing_bytes(
                &account_id,
                Some(&device_b_id),
                Some(&device_b_pk),
                challenge_b_json["challenge_id"].as_str().unwrap(),
                challenge_b_json["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let enrolled_b = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices").as_str())
                    .header("authorization", format!("Bearer {recovery_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_b_id,
                            "public_key_hex": device_b_pk,
                            "challenge_id": challenge_b_json["challenge_id"],
                            "proof_signature_hex": proof_b,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enrolled_b.status(), StatusCode::CREATED);

        // The audit trail distinguishes the recovery enrollment path.
        let audit = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{account_id}/audit").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(audit.status(), StatusCode::OK);
        let events = json(audit)
            .await
            .get("events")
            .and_then(|events| events.as_array())
            .unwrap()
            .clone();
        assert!(events
            .iter()
            .any(|event| event["event"] == "recovery_code_redeemed"
                && event["details"]["session_ttl_secs"] == RECOVERY_SESSION_TTL_SECONDS));
        assert!(events
            .iter()
            .any(|event| event["event"] == "device_enrolled"
                && event["details"]["enrollment"] == "recovery_session"));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn role_matrix_covers_gated_routes() {
        // `StatusCode` is a struct with associated constants, so the terse
        // aliases used by the case matrix below are bound as local constants.
        const OK: StatusCode = StatusCode::OK;
        const CREATED: StatusCode = StatusCode::CREATED;
        const NO_CONTENT: StatusCode = StatusCode::NO_CONTENT;
        const FORBIDDEN: StatusCode = StatusCode::FORBIDDEN;
        const UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;
        let root = std::env::temp_dir().join(format!("cv-account-matrix-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state.clone());
        let owner = format!("cvacct_{}", "11".repeat(16));
        let admin = format!("cvacct_{}", "33".repeat(16));
        let editor = format!("cvacct_{}", "55".repeat(16));
        let viewer = format!("cvacct_{}", "22".repeat(16));
        let doomed_a = format!("cvacct_{}", "66".repeat(16));
        let doomed_b = format!("cvacct_{}", "77".repeat(16));
        let outsider = format!("cvacct_{}", "88".repeat(16));
        let invitee = format!("cvacct_{}", "44".repeat(16));
        let owner_token = random_hex(32);
        let admin_token = random_hex(32);
        let editor_token = random_hex(32);
        let viewer_token = random_hex(32);
        let outsider_token = random_hex(32);
        let recovery_token = random_hex(32);
        {
            let db = state.connection().expect("db");
            for (account_id, key) in [
                (&owner, "aa".repeat(32)),
                (&admin, "bb".repeat(32)),
                (&editor, "cc".repeat(32)),
                (&viewer, "dd".repeat(32)),
                (&doomed_a, "ee".repeat(32)),
                (&doomed_b, "ff".repeat(32)),
                (&outsider, "ab".repeat(32)),
                (&invitee, "cd".repeat(32)),
            ] {
                db.execute(
                    "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                     VALUES(?1, ?2, ?3, ?4)",
                    params![account_id, account_id, key, now_utc() as i64],
                )
                .unwrap();
            }
            for (token, account_id, kind, device) in [
                (&owner_token, &owner, "device", Some("99".repeat(32))),
                (&admin_token, &admin, "device", Some("99".repeat(32))),
                (&editor_token, &editor, "device", Some("99".repeat(32))),
                (&viewer_token, &viewer, "device", Some("99".repeat(32))),
                (&outsider_token, &outsider, "device", Some("99".repeat(32))),
                (&recovery_token, &owner, "recovery", None),
            ] {
                db.execute(
                    "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc)
                     VALUES(?1, ?2, ?3, NULL, ?4, ?5, ?6)",
                    params![hash_token(token), account_id, device, kind, now_utc() as i64, (now_utc() + 3600) as i64],
                )
                .unwrap();
            }
            for (member, role) in [
                (&admin, "admin"),
                (&editor, "editor"),
                (&viewer, "viewer"),
                (&doomed_a, "viewer"),
                (&doomed_b, "viewer"),
            ] {
                db.execute(
                    "INSERT INTO memberships(account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc)
                     VALUES(?1, ?2, ?3, 'active', ?4, ?4)",
                    params![owner, member, role, now_utc() as i64],
                )
                .unwrap();
            }
        }
        // Actor index: 0 owner, 1 admin, 2 editor, 3 viewer, 4 outsider, 5 recovery.
        let token_for = |actor: usize| match actor {
            0 => owner_token.clone(),
            1 => admin_token.clone(),
            2 => editor_token.clone(),
            3 => viewer_token.clone(),
            4 => outsider_token.clone(),
            _ => recovery_token.clone(),
        };
        let uri_members = format!("/v1/accounts/{owner}/memberships");
        let uri_invites = format!("/v1/accounts/{owner}/invitations");
        let uri_vaults = format!("/v1/accounts/{owner}/vaults");
        let uri_revoke_a = format!("/v1/accounts/{owner}/memberships/{doomed_a}/revoke");
        let uri_revoke_b = format!("/v1/accounts/{owner}/memberships/{doomed_b}/revoke");
        let uri_codes = format!("/v1/accounts/{owner}/recovery/codes");
        let vault_body =
            serde_json::json!({"vault_id_hex": "55".repeat(32), "alias": "x", "role": "viewer"})
                .to_string();
        let invite_body =
            serde_json::json!({"invitee_account_id": invitee, "role": "viewer"}).to_string();
        let codes_body = r#"{"count":4}"#.to_string();
        type RoleMatrixCase<'a> = (&'a str, String, Option<String>, Option<usize>, StatusCode);
        let cases: Vec<RoleMatrixCase<'_>> = vec![
            ("GET", uri_members.clone(), None, Some(0), OK),
            ("GET", uri_members.clone(), None, Some(1), OK),
            ("GET", uri_members.clone(), None, Some(2), OK),
            ("GET", uri_members.clone(), None, Some(3), OK),
            ("GET", uri_members.clone(), None, Some(4), FORBIDDEN),
            ("GET", uri_members.clone(), None, Some(5), OK),
            ("GET", uri_members.clone(), None, None, UNAUTHORIZED),
            ("GET", uri_invites.clone(), None, Some(0), OK),
            ("GET", uri_invites.clone(), None, Some(1), OK),
            ("GET", uri_invites.clone(), None, Some(2), FORBIDDEN),
            ("GET", uri_invites.clone(), None, Some(3), FORBIDDEN),
            ("GET", uri_invites.clone(), None, Some(4), FORBIDDEN),
            ("GET", uri_invites.clone(), None, Some(5), OK),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(0),
                CREATED,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(1),
                CREATED,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(2),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(3),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(4),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(5),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(0),
                NO_CONTENT,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(1),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(2),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(3),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(4),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(5),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(0),
                OK,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(1),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(2),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(3),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(4),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(5),
                FORBIDDEN,
            ),
            ("POST", uri_revoke_b.clone(), None, Some(2), FORBIDDEN),
            ("POST", uri_revoke_b.clone(), None, Some(3), FORBIDDEN),
            ("POST", uri_revoke_b.clone(), None, Some(4), FORBIDDEN),
            ("POST", uri_revoke_b.clone(), None, Some(5), FORBIDDEN),
            ("POST", uri_revoke_b.clone(), None, None, UNAUTHORIZED),
            ("POST", uri_revoke_b.clone(), None, Some(1), OK),
            ("POST", uri_revoke_a.clone(), None, Some(0), OK),
        ];
        for (method, uri, body, actor, expected) in cases {
            let mut builder = if method == "GET" {
                Request::get(uri.as_str())
            } else {
                Request::post(uri.as_str())
            };
            if let Some(index) = actor {
                let header = format!("Bearer {}", token_for(index));
                builder = builder.header("authorization", header);
            }
            let request = match body {
                Some(payload) => builder
                    .header("content-type", "application/json")
                    .body(Body::from(payload)),
                None => builder.body(Body::empty()),
            }
            .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected, "{method} {uri}");
        }
        let _ = fs::remove_dir_all(root);
    }
}
