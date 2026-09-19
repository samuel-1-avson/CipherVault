//! Invitation and membership handlers plus row mappers.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, OptionalExtension};

use crate::{
    audit_event,
    guards::{
        account_role_for, normalize_account_id, normalize_vault_role, require_strong_session,
        role_rank,
    },
    hash_token,
    http::{authenticated_session, error_response, service_error},
    random_hex,
    state::{
        now_utc, AccountState, InvitationAcceptRequest, InvitationRequest, InvitationView,
        MembershipView,
    },
};

pub(crate) fn invitation_view_from_row(
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

pub(crate) fn membership_view_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<MembershipView, rusqlite::Error> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SESSION_TTL_SECONDS;
    use crate::test_support::{cleanup, test_app};
    use axum::body::Body;
    use axum::http::Request;
    use tower05::ServiceExt;

    #[tokio::test]
    async fn membership_roles_and_origins_are_enforced() {
        let (root, state, app) = test_app("roles");
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

        cleanup(root);
    }
}
