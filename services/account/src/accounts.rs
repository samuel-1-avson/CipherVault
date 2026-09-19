//! Account, capability, and audit handlers.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::params;

use crate::{
    audit_event,
    db::account_view,
    guards::{decode_32, derive_account_id, normalize_account_id},
    http::{authenticated_session, error_response, service_error},
    state::{now_utc, AccountState, AuditEventView, CreateAccountRequest, SESSION_COOKIE_NAME},
    totp_wrapping_key,
};

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
