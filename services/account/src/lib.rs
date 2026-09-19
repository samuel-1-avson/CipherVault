//! Durable CipherVault control-plane account service.
//!
//! This service stores account metadata, enrolled device records, vault links,
//! and revocable sessions. Vault plaintext and vault private keys never enter
//! the service. Browser WebAuthn registration and assertion verification are
//! supported for `none` attestation with Ed25519 and ES256 credentials, and
//! successful logins can use an HttpOnly managed-session cookie. The
//! account-key ceremony remains the explicit bootstrap/recovery path.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use ring::aead;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::fs;
use tower_http::cors::{AllowOrigin, CorsLayer};

mod accounts;
mod db;
mod devices;
mod error;
mod guards;
mod http;
mod memberships;
mod recovery;
mod sessions;
mod state;
mod totp;
mod vaults;
mod webauthn_crypto;

use accounts::*;
use db::*;
use devices::*;
pub use error::AccountServiceError;
use guards::*;
use http::*;
use memberships::*;
use recovery::*;
use sessions::*;
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
use vaults::*;
use webauthn_crypto::*;

pub(crate) fn hash_token(token: &str) -> String {
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

fn b64_decode(value: &str, field: &str) -> Result<Vec<u8>, AccountServiceError> {
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
