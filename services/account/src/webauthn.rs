//! WebAuthn credential handlers (registration, authentication, revocation).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::{
    audit_event, b64_decode, b64_encode,
    db::account_exists,
    guards::normalize_account_id,
    hash_token,
    http::{attach_session_cookie, authenticated_session, error_response, service_error},
    prune_expired, random_hex,
    state::{
        now_utc, AccountState, SessionResponse, SessionView, WebAuthnAuthenticationOptionsRequest,
        WebAuthnAuthenticationVerifyRequest, WebAuthnCredentialView, WebAuthnOptionsView,
        WebAuthnRegistrationVerifyRequest, CHALLENGE_TTL_SECONDS, MAX_BODY_BYTES,
        SESSION_TTL_SECONDS,
    },
    webauthn_crypto::{
        parse_attestation_object, parse_authenticator_data, validate_client_data,
        verify_webauthn_signature, webauthn_rp_id, webauthn_user_id,
    },
};

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
