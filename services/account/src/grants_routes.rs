//! Dual-admin grant + invite routes (T-303 remainder).
//!
//! * `POST /v1/projects/:pid/members` with `role=admin` opens a grant
//!   request (202) instead of granting — see `post_project_member`.
//! * `GET|POST /v1/projects/:pid/members/requests[/:rid/decision]`
//!   lists and decides requests (four-eyes: approver ≠ requester).
//! * `POST|GET|DELETE /v1/projects/:pid/invites[/:iid]` manages
//!   single-use invite codes (shown once at creation).
//! * `POST /v1/invites/accept` binds the caller's session account via a
//!   code (the code is the capability; 128-bit, infeasible to brute
//!   force, so no quota bucket — failures are uniform 404).
//!
//! Every mutation is hash-chained (`membership.grant_requested`,
//! `membership.granted`, `membership.grant_rejected`,
//! `membership.invited`, `membership.invite_revoked`).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::grants::{
    accept_invite, create_invite, decide_grant_request, list_grant_requests, list_invites,
    request_admin_grant, revoke_invite, GrantError,
};
use crate::http::{authenticated_session, error_response, service_error};
use crate::policy::{scoped_denial_response, ProjectRole};
use crate::secret_routes::authenticate;
use crate::state::{now_utc, AccountState};
use crate::util::random_hex;

/// Maps [`GrantError`] to HTTP. `expired_code` names the resource
/// (requests vs invites share the `Expired` variant).
fn grant_error_response(error: GrantError, expired_code: &'static str) -> Response {
    match error {
        GrantError::Denied | GrantError::NotFound => scoped_denial_response(),
        GrantError::Invalid(detail) => {
            error_response(StatusCode::BAD_REQUEST, "INVALID_SECRET_REQUEST", detail)
        }
        GrantError::SelfApproval => error_response(
            StatusCode::FORBIDDEN,
            "SELF_APPROVAL_DENIED",
            "A grant request needs a different admin's approval",
        ),
        GrantError::Expired => error_response(StatusCode::GONE, expired_code, "No longer valid"),
        GrantError::Db(error) => service_error(error.into()),
    }
}

pub async fn list_grant_requests_route(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match list_grant_requests(&db, &auth.claims, &auth.attrs, &project_id, now_utc()) {
        Ok(requests) => Json(serde_json::json!({ "requests": requests })).into_response(),
        Err(error) => grant_error_response(error, "GRANT_REQUEST_EXPIRED"),
    }
}

#[derive(Deserialize)]
pub(crate) struct GrantDecisionBody {
    approve: bool,
}

pub async fn decide_grant_request_route(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, request_id)): Path<(String, String)>,
    Json(body): Json<GrantDecisionBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let audit_request_id = random_hex(8);
    match decide_grant_request(
        &db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        request_id.trim(),
        body.approve,
        &audit_request_id,
        now_utc(),
    ) {
        Ok(view) => Json(view).into_response(),
        Err(error) => grant_error_response(error, "GRANT_REQUEST_EXPIRED"),
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateInviteBody {
    role: String,
}

pub async fn create_invite_route(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(body): Json<CreateInviteBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let Some(role) = ProjectRole::parse(&body.role) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "role must be developer, operator, or auditor",
        );
    };
    let request_id = random_hex(8);
    match create_invite(
        &db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        role,
        &request_id,
        now_utc(),
    ) {
        Ok((invite, code)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "invite_id": invite.invite_id,
                "project_id": invite.project_id,
                "role": invite.role,
                "state": invite.state,
                "expires_at_utc": invite.expires_at_utc,
                "code": code,
            })),
        )
            .into_response(),
        Err(error) => grant_error_response(error, "INVITE_EXPIRED"),
    }
}

pub async fn list_invites_route(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match list_invites(&db, &auth.claims, &auth.attrs, &project_id, now_utc()) {
        Ok(invites) => Json(serde_json::json!({ "invites": invites })).into_response(),
        Err(error) => grant_error_response(error, "INVITE_EXPIRED"),
    }
}

pub async fn revoke_invite_route(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, invite_id)): Path<(String, String)>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let request_id = random_hex(8);
    match revoke_invite(
        &db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        invite_id.trim(),
        &request_id,
        now_utc(),
    ) {
        Ok(_) => Json(serde_json::json!({ "revoked": true })).into_response(),
        Err(error) => grant_error_response(error, "INVITE_EXPIRED"),
    }
}

#[derive(Deserialize)]
pub(crate) struct AcceptInviteBody {
    code: String,
}

pub async fn accept_invite_route(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(body): Json<AcceptInviteBody>,
) -> Response {
    // Invites bind session accounts (humans accepting out-of-band codes),
    // never scope tokens.
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = crate::guards::require_recent_strong_session(&session, now_utc()) {
        return *response;
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let principal = format!("account:{}", session.account_id);
    let request_id = random_hex(8);
    match accept_invite(&db, &principal, &body.code, &request_id, now_utc()) {
        Ok(view) => Json(serde_json::json!({
            "project_id": view.project_id,
            "role": view.role,
            "principal_id": principal,
        }))
        .into_response(),
        Err(error) => grant_error_response(error, "INVITE_EXPIRED"),
    }
}

/// Shared by `post_project_member`: admin-role grants divert into the
/// dual-admin request flow (202 + request view) instead of granting.
pub(crate) fn admin_grant_request_response(
    state: &AccountState,
    auth: &crate::secret_routes::RouteAuth,
    project_id: &str,
    principal_id: &str,
) -> Response {
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let request_id = random_hex(8);
    match request_admin_grant(
        &db,
        &auth.claims,
        &auth.attrs,
        project_id,
        principal_id,
        &request_id,
        now_utc(),
    ) {
        Ok(view) => (StatusCode::ACCEPTED, Json(view)).into_response(),
        Err(error) => grant_error_response(error, "GRANT_REQUEST_EXPIRED"),
    }
}
