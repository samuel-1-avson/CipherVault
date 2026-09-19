//! Login, session, and handoff handlers.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ciphervault_crypto::signatures::verify_with_domain;
use ed25519_dalek::VerifyingKey;
use rusqlite::{params, OptionalExtension};

use crate::{
    audit_event, challenge_signing_bytes,
    db::account_exists,
    error::AccountServiceError,
    guards::{decode_32, normalize_account_id},
    hash_token,
    http::{
        attach_session_cookie, authenticated_session, clear_session_cookie, error_response,
        service_error, session_token,
    },
    prune_expired, random_hex,
    state::{
        now_utc, AccountState, ChallengeView, LoginChallengeRequest, SessionHandoffConsumeRequest,
        SessionHandoffResponse, SessionLoginRequest, SessionResponse, SessionView,
        CHALLENGE_TTL_SECONDS, SESSION_HANDOFF_TTL_SECONDS, SESSION_TTL_SECONDS,
    },
};

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
