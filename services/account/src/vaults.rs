//! Vault linking handler.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::params;

use crate::{
    audit_event,
    guards::{
        account_role_for, decode_32, normalize_account_id, normalize_vault_role,
        require_strong_session,
    },
    http::{error_response, service_error},
    state::{now_utc, AccountState, LinkVaultRequest},
};

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
