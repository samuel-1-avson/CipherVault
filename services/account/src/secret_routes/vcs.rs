//! Repository binding and webhook routes.

use super::auth::*;
use super::common::*;

// ---------------------------------------------------------------------------
// Repository bindings (Phase 6, T-601).
// ---------------------------------------------------------------------------

fn vcs_error_response(err: VcsError) -> Response {
    match err {
        VcsError::NotFound | VcsError::Denied => scoped_denial_response(),
        VcsError::Conflict => error_response(
            StatusCode::CONFLICT,
            "BINDING_CONFLICT",
            "This repository is already bound to the project",
        ),
        VcsError::Invalid(message) => {
            error_response(StatusCode::BAD_REQUEST, "INVALID_BINDING_REQUEST", message)
        }
        VcsError::Terminal => error_response(
            StatusCode::CONFLICT,
            "BINDING_REVOKED",
            "Binding is revoked; reactivate it before further transitions",
        ),
        VcsError::Unconfigured => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "VCS_WEBHOOK_UNCONFIGURED",
            "VCS webhook signing key is not configured",
        ),
        VcsError::ProviderUnavailable => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "VCS_PROVIDER_UNAVAILABLE",
            "Repository ownership verification requires a configured provider client",
        ),
        VcsError::Provider(_) => error_response(
            StatusCode::BAD_GATEWAY,
            "VCS_PROVIDER_ERROR",
            "VCS provider verification failed",
        ),
        VcsError::Db(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BINDING_STORE_UNAVAILABLE",
            "Binding store unavailable",
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct BindRepositoryBody {
    provider: String,
    external_repo_id: String,
    repo_full_name: String,
    repo_url: String,
    installation_id: Option<String>,
}

pub async fn post_repository(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(body): Json<BindRepositoryBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match bind_repository(
        &db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        &BindRepository {
            provider: &body.provider,
            external_repo_id: &body.external_repo_id,
            repo_full_name: &body.repo_full_name,
            repo_url: &body.repo_url,
            installation_id: body.installation_id.as_deref(),
            request_id: &random_hex(8),
        },
        now_utc(),
    ) {
        Ok(outcome) => (StatusCode::CREATED, Json(outcome)).into_response(),
        Err(err) => vcs_error_response(err),
    }
}

pub async fn get_repositories(
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
    match list_bindings(&db, &auth.claims, &auth.attrs, &project_id) {
        Ok(bindings) => Json(serde_json::json!({ "bindings": bindings })).into_response(),
        Err(err) => vcs_error_response(err),
    }
}

#[derive(Deserialize, Default)]
pub(crate) struct RepositoryDeleteQuery {
    mode: Option<String>,
    reason: Option<String>,
}

pub async fn delete_repository(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, binding_id)): Path<(String, String)>,
    Query(query): Query<RepositoryDeleteQuery>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let reason = query.reason.as_deref().unwrap_or("operator unbind");
    let request_id = random_hex(8);
    let outcome = match query.mode.as_deref().unwrap_or("suspend") {
        "suspend" => suspend_binding(
            &db,
            &auth.claims,
            &auth.attrs,
            &binding_id,
            reason,
            &request_id,
            now_utc(),
        ),
        "revoke" => revoke_binding(
            &db,
            &auth.claims,
            &auth.attrs,
            &binding_id,
            reason,
            &request_id,
            now_utc(),
        ),
        other => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_BINDING_REQUEST",
                format!("unknown mode '{other}'; use suspend or revoke"),
            );
        }
    };
    match outcome {
        Ok(view) => (StatusCode::ACCEPTED, Json(view)).into_response(),
        Err(err) => vcs_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct ProveRepositoryBody {
    installation_id: String,
    installation_token: String,
}

pub async fn post_repository_prove(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, binding_id)): Path<(String, String)>,
    Json(body): Json<ProveRepositoryBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if body.installation_id.trim().is_empty() || body.installation_token.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_BINDING_REQUEST",
            "installation_id and installation_token are required",
        );
    }
    // Fail-closed seam: no provider API client is wired yet, so proof
    // returns 503 until a real client replaces NoProviderClient.
    match prove_ownership(
        &db,
        &auth.claims,
        &auth.attrs,
        &binding_id,
        body.installation_id.trim(),
        &body.installation_token,
        &NoProviderClient,
        &random_hex(8),
        now_utc(),
    ) {
        Ok(view) => Json(view).into_response(),
        Err(err) => vcs_error_response(err),
    }
}

#[derive(Deserialize, Default)]
pub(crate) struct ReactivateBody {
    reason: Option<String>,
}

pub async fn post_repository_reactivate(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, binding_id)): Path<(String, String)>,
    Json(body): Json<ReactivateBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match reactivate_binding(
        &db,
        &auth.claims,
        &auth.attrs,
        &binding_id,
        body.reason.as_deref().unwrap_or("operator reactivate"),
        &random_hex(8),
        now_utc(),
    ) {
        Ok(view) => Json(view).into_response(),
        Err(err) => vcs_error_response(err),
    }
}

const MAX_WEBHOOK_BYTES: usize = 1024 * 1024;

/// Normalized provider webhook envelope. Providers post native payloads to a
/// forwarder that normalizes and re-signs with the configured secret (the
/// installer holds that secret); native GitHub/GitLab payload parsers are a
/// follow-up. The HMAC is always over the raw request bytes.
#[derive(Deserialize)]
struct WebhookEnvelope {
    event: String,
    external_repo_id: String,
    repo_full_name: String,
    repo_url: String,
}

fn webhook_signature_header(provider: VcsProvider, headers: &HeaderMap) -> Option<String> {
    let name = match provider {
        VcsProvider::Github => "x-hub-signature-256",
        VcsProvider::Gitlab => "x-gitlab-token",
        VcsProvider::Bitbucket => "x-hub-signature",
        VcsProvider::SelfHosted => "x-ciphervault-signature",
    };
    headers.get(name)?.to_str().ok().map(str::to_string)
}

pub async fn post_vcs_webhook(
    State(state): State<AccountState>,
    Path(provider_raw): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_WEBHOOK_BYTES {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "WEBHOOK_TOO_LARGE",
            "Webhook payload exceeds 1 MiB",
        );
    }
    let provider = match VcsProvider::parse(&provider_raw) {
        Ok(provider) => provider,
        Err(_) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "UNKNOWN_VCS_PROVIDER",
                "Unknown VCS provider",
            );
        }
    };
    let envelope: WebhookEnvelope = match serde_json::from_slice(&body) {
        Ok(envelope) => envelope,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_WEBHOOK_PAYLOAD",
                "Webhook body must be the normalized JSON envelope",
            );
        }
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let binding_id: Option<String> = db
        .query_row(
            "SELECT binding_id FROM repository_bindings
             WHERE provider = ?1 AND external_repo_id = ?2",
            rusqlite::params![provider.as_str(), envelope.external_repo_id.trim()],
            |row| row.get(0),
        )
        .optional()
        .unwrap_or(None);
    let master = match webhook_signing_key() {
        Ok(key) => key,
        Err(err) => return vcs_error_response(err),
    };
    // Unknown bindings verify against a dummy key (always fails): no oracle
    // distinguishes "unbound repo" from "bad signature" — both are 401.
    let key = match &binding_id {
        Some(id) => webhook_key_for(&master, id),
        None => webhook_key_for(
            &master,
            &format!("unknown:{}", envelope.external_repo_id.trim()),
        ),
    };
    let Some(signature) = webhook_signature_header(provider, &headers) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "WEBHOOK_UNAUTHORIZED",
            "Missing webhook signature",
        );
    };
    if !verify_webhook_signature(provider, &key, &body, &signature) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "WEBHOOK_UNAUTHORIZED",
            "Invalid webhook signature",
        );
    };
    match apply_webhook_event(
        &db,
        provider,
        &WebhookEvent {
            event_type: &envelope.event,
            external_repo_id: &envelope.external_repo_id,
            repo_full_name: &envelope.repo_full_name,
            repo_url: &envelope.repo_url,
        },
        &random_hex(8),
        now_utc(),
    ) {
        Ok(WebhookOutcome::Applied { binding_id, status }) => Json(serde_json::json!({
            "outcome": "applied",
            "binding_id": binding_id,
            "status": status,
        }))
        .into_response(),
        Ok(WebhookOutcome::IgnoredUnknownBinding) => {
            Json(serde_json::json!({ "outcome": "ignored" })).into_response()
        }
        Err(err) => vcs_error_response(err),
    }
}
