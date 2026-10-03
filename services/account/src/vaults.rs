//! Vault linking handler.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::params;

use crate::{
    audit_event,
    guards::{
        decode_32, normalize_account_id, normalize_vault_role, require_recent_account_role_with_db,
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
    if let Err(error) = decode_32(&request.vault_id_hex, "vault_id_hex") {
        return service_error(error);
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if let Err(response) = require_recent_account_role_with_db(&db, &headers, &account_id, "owner")
    {
        return *response;
    }
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
    let locator = match request.key_backup_locator_hex.as_deref() {
        None => None,
        Some(raw) => {
            if decode_32(raw, "key_backup_locator_hex").is_err() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "INVALID_VAULT_LINK",
                    "key_backup_locator_hex must be 64 hex characters",
                );
            }
            Some(raw.to_ascii_lowercase())
        }
    };
    let now = now_utc();
    let locator_at = locator.as_ref().map(|_| now);
    match db.execute(
        "INSERT INTO vault_links(account_id, vault_id_hex, alias, role, linked_at_utc, key_backup_locator_hex, key_backup_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(account_id, vault_id_hex) DO UPDATE SET alias = excluded.alias, role = excluded.role,
           key_backup_locator_hex = COALESCE(excluded.key_backup_locator_hex, vault_links.key_backup_locator_hex),
           key_backup_at_utc = CASE WHEN excluded.key_backup_locator_hex IS NOT NULL THEN excluded.key_backup_at_utc ELSE vault_links.key_backup_at_utc END",
        params![account_id, request.vault_id_hex.to_ascii_lowercase(), alias, role, now, locator, locator_at],
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
                    "key_backup_locator_hex": locator,
                }),
            ) {
                return service_error(error.into());
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => service_error(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::now_utc;
    use crate::test_support::{cleanup, test_app};
    use crate::{hash_token, random_hex};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower05::ServiceExt;

    #[tokio::test]
    async fn vault_link_records_and_preserves_key_backup_locator() {
        let (root, state, app) = test_app("vault-link-locator");
        let owner = format!("cvacct_{}", random_hex(16));
        let owner_token = random_hex(32);
        let vault_hex = "55".repeat(32);
        let locator = "ab".repeat(32);
        {
            let db = state.connection().unwrap();
            db.execute(
                "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                 VALUES(?1, ?2, ?3, ?4)",
                params![owner, owner, "aa".repeat(32), now_utc() as i64],
            )
            .unwrap();
            db.execute(
                "INSERT INTO devices(account_id, device_id_hex, label, public_key_hex, enrolled_at_utc)
                 VALUES(?1, ?2, 'test', ?2, 1)",
                params![owner, "99".repeat(32)],
            )
            .unwrap();
            db.execute(
                "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc)
                 VALUES(?1, ?2, ?3, NULL, 'device', ?4, ?5)",
                params![
                    hash_token(&owner_token),
                    owner,
                    "99".repeat(32),
                    now_utc() as i64,
                    (now_utc() + 3600) as i64
                ],
            )
            .unwrap();
        }
        let post = |body: serde_json::Value| {
            Request::post(format!("/v1/accounts/{owner}/vaults").as_str())
                .header("authorization", format!("Bearer {owner_token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        // Link with locator.
        let linked = app
            .clone()
            .oneshot(post(serde_json::json!({
                "vault_id_hex": vault_hex,
                "alias": "primary",
                "role": "owner",
                "key_backup_locator_hex": locator,
            })))
            .await
            .unwrap();
        assert_eq!(linked.status(), StatusCode::NO_CONTENT);
        // Locator appears on the account view.
        let fetched = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{owner}").as_str())
                    .header("authorization", format!("Bearer {owner_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fetched.status(), StatusCode::OK);
        let view: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(fetched.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let vaults = view.get("vaults").and_then(|v| v.as_array()).unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(
            vaults[0]
                .get("key_backup_locator_hex")
                .and_then(|v| v.as_str()),
            Some(locator.as_str())
        );
        assert!(vaults[0]
            .get("key_backup_at_utc")
            .and_then(|v| v.as_u64())
            .is_some());
        // Relink without locator preserves it.
        let relinked = app
            .clone()
            .oneshot(post(serde_json::json!({
                "vault_id_hex": vault_hex,
                "alias": "renamed",
                "role": "owner",
            })))
            .await
            .unwrap();
        assert_eq!(relinked.status(), StatusCode::NO_CONTENT);
        {
            let db = state.connection().unwrap();
            let kept: Option<String> = db
                .query_row(
                    "SELECT key_backup_locator_hex FROM vault_links WHERE account_id = ?1",
                    params![owner],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(kept, Some(locator.clone()));
        }
        // Malformed locator is rejected without touching the stored one.
        let bad = app
            .clone()
            .oneshot(post(serde_json::json!({
                "vault_id_hex": vault_hex,
                "alias": "renamed",
                "role": "owner",
                "key_backup_locator_hex": "not-hex",
            })))
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        {
            let db = state.connection().unwrap();
            let kept: Option<String> = db
                .query_row(
                    "SELECT key_backup_locator_hex FROM vault_links WHERE account_id = ?1",
                    params![owner],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(kept, Some(locator));
        }
        drop(app);
        drop(state);
        cleanup(root);
    }
}
