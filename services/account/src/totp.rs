//! RFC 6238 time-based one-time passwords.
//!
//! CipherVault uses TOTP as an account-session factor. It is deliberately
//! separate from vault encryption keys and is never used to derive or expose
//! vault plaintext.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand::RngCore;
use ring::aead;
use ring::hmac;
use rusqlite::{params, OptionalExtension};
use std::fs;
use subtle::ConstantTimeEq;

use crate::{
    audit_event, b64_decode, b64_encode,
    error::AccountServiceError,
    guards::normalize_account_id,
    hash_token,
    http::{
        attach_session_cookie, auth_rate_allowed, auth_rate_failure_with_db, auth_rate_key,
        auth_rate_success, authenticated_session, error_response, service_error,
    },
    random_hex,
    state::{
        now_utc, AccountState, SessionResponse, SessionView, TotpAuthenticationOptionsRequest,
        TotpAuthenticationOptionsView, TotpAuthenticationVerifyRequest, TotpCodeRequest,
        TotpEnrollmentView, CHALLENGE_TTL_SECONDS, SESSION_TTL_SECONDS, TOTP_KEY_ENV,
        TOTP_KEY_FILE_ENV, TOTP_NONCE_BYTES,
    },
};

pub const STEP_SECONDS: u64 = 30;
pub const DIGITS: usize = 6;
const SECRET_BYTES: usize = 20;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("TOTP code must contain exactly six digits")]
    InvalidCode,
    #[error("TOTP secret is empty or malformed")]
    InvalidSecret,
    #[error("TOTP code is outside the accepted time window")]
    CodeMismatch,
    #[error("TOTP code was already used")]
    Replay,
}

pub fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}

pub fn base32_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for &byte in bytes {
        buffer = (buffer << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

#[allow(dead_code)]
pub fn base32_decode(value: &str) -> Result<Vec<u8>, TotpError> {
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut buffer = 0u16;
    let mut bits = 0u8;
    let mut saw_symbol = false;
    for byte in value.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() || byte == b'-' {
            continue;
        }
        let upper = byte.to_ascii_uppercase();
        let index = match upper {
            b'A'..=b'Z' => upper - b'A',
            b'2'..=b'7' => upper - b'2' + 26,
            _ => return Err(TotpError::InvalidSecret),
        };
        saw_symbol = true;
        buffer = (buffer << 5) | index as u16;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            if bits == 0 {
                buffer = 0;
            } else {
                buffer &= (1u16 << bits) - 1;
            }
        }
    }
    if !saw_symbol || output.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    Ok(output)
}

pub fn code_for_step(secret: &[u8], step: u64) -> Result<String, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = (bytes[bytes.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(bytes[offset]) & 0x7f) << 24)
        | (u32::from(bytes[offset + 1]) << 16)
        | (u32::from(bytes[offset + 2]) << 8)
        | u32::from(bytes[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

/// Verify a code in the current step plus or minus one 30-second step.
/// Returns the matched step so callers can persist a replay barrier.
pub fn verify_code(
    secret: &[u8],
    code: &str,
    now_seconds: u64,
    last_used_step: Option<u64>,
) -> Result<u64, TotpError> {
    let normalized = code.trim();
    if normalized.len() != DIGITS || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TotpError::InvalidCode);
    }
    let current_step = now_seconds / STEP_SECONDS;
    for candidate in [
        current_step.saturating_sub(1),
        current_step,
        current_step + 1,
    ] {
        if last_used_step.is_some_and(|last| candidate <= last) {
            continue;
        }
        let expected = code_for_step(secret, candidate)?;
        if expected.as_bytes().ct_eq(normalized.as_bytes()).into() {
            return Ok(candidate);
        }
    }
    if last_used_step.is_some_and(|last| last >= current_step.saturating_sub(1)) {
        Err(TotpError::Replay)
    } else {
        Err(TotpError::CodeMismatch)
    }
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
    let secret = generate_secret();
    let secret_base32 = base32_encode(&secret);
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
        serde_json::json!({"algorithm": "SHA1", "digits": DIGITS, "period_seconds": STEP_SECONDS}),
    ) {
        return service_error(error.into());
    }
    let uri = format!(
        "otpauth://totp/CipherVault:{}?secret={}&issuer=CipherVault&algorithm=SHA1&digits={}&period={}",
        account_id,
        secret_base32,
        DIGITS,
        STEP_SECONDS,
    );
    Json(TotpEnrollmentView {
        account_id,
        secret_base32,
        otpauth_uri: uri,
        issuer: "CipherVault".into(),
        algorithm: "SHA1".into(),
        digits: DIGITS as u8,
        period_seconds: STEP_SECONDS,
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
    let step = match verify_code(&secret, &request.code, now_utc(), last_used_step) {
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
        digits: DIGITS as u8,
        period_seconds: STEP_SECONDS,
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
    let step = match verify_code(&secret, &request.code, now, last_used_step) {
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trip() {
        let input = b"12345678901234567890";
        let encoded = base32_encode(input);
        assert_eq!(encoded, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&encoded).unwrap(), input);
        for length in 1..=32 {
            let sample: Vec<u8> = (0..length).map(|value| value as u8).collect();
            assert_eq!(base32_decode(&base32_encode(&sample)).unwrap(), sample);
        }
    }

    #[test]
    fn rfc6238_sha1_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(
            code_for_step(secret, 1_111_111_111 / STEP_SECONDS).unwrap(),
            "050471"
        );
    }

    #[test]
    fn replay_is_rejected() {
        let secret = b"test secret";
        let now = 30 * 100;
        let code = code_for_step(secret, 100).unwrap();
        assert_eq!(
            verify_code(secret, &code, now, Some(100)),
            Err(TotpError::Replay)
        );
        assert_eq!(verify_code(secret, &code, now, None), Ok(100));
    }
}
