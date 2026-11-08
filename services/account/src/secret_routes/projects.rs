//! Project membership and project read routes.

use super::auth::*;
use super::common::*;

#[derive(Deserialize)]
pub(crate) struct MemberBody {
    principal_id: String,
    role: String,
}

pub async fn post_project_member(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(body): Json<MemberBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let Some(role) = ProjectRole::parse(&body.role) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "role must be admin, developer, operator, or auditor",
        );
    };
    if body.principal_id.trim().is_empty() || body.principal_id.len() > 256 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "principal_id must be 1–256 characters",
        );
    }
    // Admin-role grants divert into the dual-admin request flow (four-eyes,
    // 202 + request view) instead of granting. Placed before the guard
    // opens: the diversion acquires its own connection (nesting would
    // self-deadlock the global mutex).
    if role == ProjectRole::Admin {
        return crate::grants_routes::admin_grant_request_response(
            &state,
            &auth,
            &project_id,
            body.principal_id.trim(),
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    // Membership changes require the admin action on this project.
    let tenant: Option<String> = db
        .query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            rusqlite::params![project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| service_error(err.into()))
        .unwrap_or(None);
    let Some(tenant) = tenant else {
        return scoped_denial_response();
    };
    let target = crate::policy::AuthTarget {
        tenant_id: &tenant,
        project_id: &project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    if crate::policy::authorize(
        &db,
        &auth.claims,
        crate::policy::ScopedAction::ManageMembers,
        &target,
        &auth.attrs,
    )
    .is_err()
    {
        return scoped_denial_response();
    }
    let now = now_utc();
    if let Err(error) = grant_project_role(
        &db,
        &project_id,
        body.principal_id.trim(),
        role,
        &auth.claims.principal_id,
        now,
    ) {
        return service_error(error.into());
    }
    let request_id = random_hex(8);
    if let Err(error) = audit_secret_event(
        &db,
        &SecretAuditEvent {
            event_type: AuditEventType::MembershipGranted.as_str(),
            tenant_id: &tenant,
            project_id: Some(&project_id),
            environment_id: None,
            secret_id: None,
            secret_version: None,
            principal_id: &auth.claims.principal_id,
            request_id: &request_id,
            source: "api",
            result: "success",
            reason: body.principal_id.trim(),
        },
        now,
    ) {
        return service_error(error.into());
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "principal_id": body.principal_id.trim(),
            "role": role.as_str(),
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub(crate) struct RevokeMemberQuery {
    principal_id: String,
}

pub async fn delete_project_member(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Query(query): Query<RevokeMemberQuery>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let tenant: Option<String> = db
        .query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            rusqlite::params![project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| service_error(err.into()))
        .unwrap_or(None);
    let Some(tenant) = tenant else {
        return scoped_denial_response();
    };
    let target = crate::policy::AuthTarget {
        tenant_id: &tenant,
        project_id: &project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    if crate::policy::authorize(
        &db,
        &auth.claims,
        crate::policy::ScopedAction::ManageMembers,
        &target,
        &auth.attrs,
    )
    .is_err()
    {
        return scoped_denial_response();
    }
    if let Err(error) = revoke_project_role(&db, &project_id, &query.principal_id, now_utc()) {
        return service_error(error.into());
    }
    let request_id = random_hex(8);
    if let Err(error) = audit_secret_event(
        &db,
        &SecretAuditEvent {
            event_type: AuditEventType::MembershipRevoked.as_str(),
            tenant_id: &tenant,
            project_id: Some(&project_id),
            environment_id: None,
            secret_id: None,
            secret_version: None,
            principal_id: &auth.claims.principal_id,
            request_id: &request_id,
            source: "api",
            result: "success",
            reason: query.principal_id.trim(),
        },
        now_utc(),
    ) {
        return service_error(error.into());
    }
    Json(serde_json::json!({ "revoked": true })).into_response()
}

// ---------------------------------------------------------------------------
// Project catalog (Phase 7, T-701).
// ---------------------------------------------------------------------------

fn project_error_response(err: ProjectError) -> Response {
    match err {
        ProjectError::NotFound => scoped_denial_response(),
        ProjectError::Ambiguous(message) => {
            error_response(StatusCode::BAD_REQUEST, "AMBIGUOUS_PROJECT", message)
        }
        ProjectError::Invalid(message) => {
            error_response(StatusCode::BAD_REQUEST, "INVALID_PROJECT_REQUEST", message)
        }
        ProjectError::Db(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PROJECT_STORE_UNAVAILABLE",
            "Project store unavailable",
        ),
    }
}

pub async fn get_projects(State(state): State<AccountState>, headers: HeaderMap) -> Response {
    let auth = match authenticate_loose(&state, &headers) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match list_projects(&db, &auth.principal_id, auth.project_id.as_deref()) {
        Ok(projects) => Json(serde_json::json!({ "projects": projects })).into_response(),
        Err(err) => project_error_response(err),
    }
}

pub async fn get_project(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_ref): Path<String>,
) -> Response {
    let auth = match authenticate_loose(&state, &headers) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let mut view = match show_project(
        &db,
        &auth.principal_id,
        &project_ref,
        auth.tenant_id.as_deref(),
    ) {
        Ok(view) => view,
        Err(err) => return project_error_response(err),
    };
    // Scope tokens stay confined to their own project.
    if let Some(own) = auth.project_id.as_deref() {
        if view.project_id != own {
            return scoped_denial_response();
        }
    }
    if let Some(environment) = auth.environment_id.as_deref() {
        view.environments
            .retain(|entry| entry.environment_id == environment);
    }
    Json(view).into_response()
}
