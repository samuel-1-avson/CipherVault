//! Scoped secret REST routes (Phase 4, T-403).
//!
//! Dual authentication: short-lived HMAC scope tokens (`cvst1.*`, CI and
//! workloads) or account sessions (humans). Token scope must cover the path
//! scope exactly for environment targets; session callers take scope from
//! the explicit path plus the project row, with identity from the session.
//! Denials and missing resources both return a uniform 404 (no oracle).
//!
//! Abuse protection (T-902): per-principal quotas (API bucket on every
//! authenticated call plus tighter read/mint/export buckets), dual-control
//! audit export, and opt-in DPoP-lite key binding for scope tokens. mTLS
//! stays deferred (needs a TLS-termination dependency).

use crate::key_lifecycle::VersionedKekService;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ciphervault_format::SecretValue;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::abuse::{
    check_quota, quota_failure_response, API_BUCKET, EXPORT_BUCKET, MINT_BUCKET, READ_VALUE_BUCKET,
};
use crate::audit_chain::{export_audit_log, verify_chain, AuditEventType};
use crate::guards::{require_recent_strong_session, STEP_UP_MAX_AGE_SECONDS};
use crate::http::{
    authenticated_session, bearer_token, error_response, service_error, session_token,
};
use crate::policy::{
    grant_project_role, project_role_of, revoke_project_role, scoped_denial_response, ProjectRole,
    RequestAttributes,
};
use crate::projects::{list_projects, show_project, ProjectError};
use crate::reconcile::NoProviderClient;
use crate::rotation::{rotate_secret, ManualReplacementVerifier, RotateSecret};
use crate::scope_tokens::{
    deny_scope_token, mint_scope_token, prune_scope_denylist, scope_token_denied,
    scope_token_signing_key, verify_scope_token, ScopeClaims, SCOPE_TOKEN_PREFIX,
};
use crate::secrets::{
    audit_secret_event, create_secret, delete_secret, get_secret_metadata, get_secret_value,
    list_secrets, move_secret, rebind_secret, update_secret_metadata, CreateSecret, MoveSecret,
    RebindSecret, SecretAuditEvent, SecretError, SecretListFilter, UpdateSecretMetadata,
};
use crate::state::{now_utc, AccountState};
use crate::util::random_hex;
use crate::vcs::{
    apply_webhook_event, bind_repository, list_bindings, prove_ownership, reactivate_binding,
    revoke_binding, suspend_binding, verify_webhook_signature, webhook_key_for,
    webhook_signing_key, BindRepository, VcsError, VcsProvider, WebhookEvent, WebhookOutcome,
};

const LOCAL_KEK_ENV: &str = "CIPHERVAULT_ACCOUNT_LOCAL_KEK";
const LOCAL_KEK_FILE_ENV: &str = "CIPHERVAULT_ACCOUNT_LOCAL_KEK_FILE";

pub(crate) struct RouteAuth {
    pub(crate) claims: ScopeClaims,
    pub(crate) attrs: RequestAttributes,
}

/// Tri-state JSON field: absent keeps, null clears, string sets.
#[derive(Clone, Debug, Default)]
pub(crate) enum JsonNullable {
    #[default]
    Keep,
    Clear,
    Set(String),
}

impl<'de> Deserialize<'de> for JsonNullable {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NullableVisitor;
        impl<'de> serde::de::Visitor<'de> for NullableVisitor {
            type Value = JsonNullable;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a string, null, or absent")
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(JsonNullable::Clear)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(JsonNullable::Clear)
            }
            fn visit_some<D2: serde::Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> Result<Self::Value, D2::Error> {
                String::deserialize(deserializer).map(JsonNullable::Set)
            }
        }
        deserializer.deserialize_option(NullableVisitor)
    }
}

pub(crate) fn authenticate(
    state: &AccountState,
    headers: &HeaderMap,
    project_id: &str,
    environment_id: Option<&str>,
) -> Result<RouteAuth, Box<Response>> {
    let token_path =
        bearer_token(headers).is_some_and(|token| token.starts_with(SCOPE_TOKEN_PREFIX));
    if token_path {
        let token = bearer_token(headers).unwrap_or_default();
        authenticate_token(state, headers, token, project_id, environment_id)
    } else {
        authenticate_session(state, headers, project_id, environment_id)
    }
}

/// Verifies a scope token (signature, expiry, denylist, DPoP binding)
/// without checking path confinement. Shared by project-scoped and
/// project-less routes. DPoP runs after the denylist so revoked tokens
/// fail before consuming replay rows.
fn verify_token_claims(
    state: &AccountState,
    headers: &HeaderMap,
    token: &str,
) -> Result<ScopeClaims, Box<Response>> {
    let key = scope_token_signing_key().map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "SCOPE_TOKENS_UNCONFIGURED",
            "Scope-token authentication is not configured",
        )
    })?;
    let claims = verify_scope_token(&key, token, now_utc()).map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "INVALID_SCOPE_TOKEN",
            "Invalid or expired scope token",
        )
    })?;
    let db = state.connection().map_err(service_error)?;
    let denied = scope_token_denied(&db, &claims.jti).map_err(|err| service_error(err.into()))?;
    if denied {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "INVALID_SCOPE_TOKEN",
            "Invalid or expired scope token",
        )));
    }
    if !crate::scope_tokens::scope_origin_active(&db, &claims, now_utc(), true)
        .map_err(|error| service_error(error.into()))?
    {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "INVALID_SCOPE_TOKEN",
            "Invalid or expired scope token",
        )));
    }
    let _ = prune_scope_denylist(&db, now_utc());
    crate::dpop::verify_dpop(&db, &claims, headers, now_utc())
        .map_err(|err| Box::new(crate::dpop::dpop_error_response(&err)))?;
    Ok(claims)
}

fn authenticate_token(
    state: &AccountState,
    headers: &HeaderMap,
    token: &str,
    project_id: &str,
    environment_id: Option<&str>,
) -> Result<RouteAuth, Box<Response>> {
    let claims = verify_token_claims(state, headers, token)?;
    if claims.project_id != project_id {
        return Err(Box::new(scoped_denial_response()));
    }
    if let Some(want_env) = environment_id {
        if claims.environment_id.as_deref() != Some(want_env) {
            return Err(Box::new(scoped_denial_response()));
        }
    }
    // Per-principal API quota (T-902): enforced post-auth so only
    // authenticated callers consume budget.
    {
        let db = state.connection().map_err(service_error)?;
        let project_valid: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM projects
            WHERE project_id = ?1 AND tenant_id = ?2 AND deleted_at_utc IS NULL)",
                rusqlite::params![project_id, claims.tenant_id],
                |row| row.get(0),
            )
            .map_err(|error| service_error(error.into()))?;
        if !project_valid
            || project_role_of(&db, project_id, &claims.principal_id)
                .map_err(|error| service_error(error.into()))?
                .is_none()
        {
            return Err(Box::new(scoped_denial_response()));
        }
        if let Err(failure) = check_quota(
            &db,
            &API_BUCKET,
            &claims.tenant_id,
            &claims.principal_id,
            now_utc(),
        ) {
            return Err(Box::new(quota_failure_response(failure)));
        }
    }
    let attrs = RequestAttributes {
        branch: claims.branch.clone(),
        elevated: claims.origin_session_hash.is_some()
            && claims
                .elevated_until_utc
                .is_some_and(|until| now_utc() < until),
        ..RequestAttributes::default()
    };
    Ok(RouteAuth { claims, attrs })
}

fn authenticate_session(
    state: &AccountState,
    headers: &HeaderMap,
    project_id: &str,
    environment_id: Option<&str>,
) -> Result<RouteAuth, Box<Response>> {
    let session = authenticated_session(state, headers)?;
    let db = state.connection().map_err(service_error)?;
    let tenant: Option<String> = db
        .query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            rusqlite::params![project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| service_error(err.into()))?;
    let Some(tenant) = tenant else {
        return Err(Box::new(scoped_denial_response()));
    };
    let mut claims =
        ScopeClaims::for_session(&tenant, project_id, environment_id, &session.account_id);
    claims.origin_session_hash =
        session_token(headers).map(|token| crate::util::hash_token(&token));
    if project_role_of(&db, project_id, &claims.principal_id)
        .map_err(|error| service_error(error.into()))?
        .is_none()
    {
        return Err(Box::new(scoped_denial_response()));
    }
    if let Err(failure) = check_quota(&db, &API_BUCKET, &tenant, &claims.principal_id, now_utc()) {
        return Err(Box::new(quota_failure_response(failure)));
    }
    let elevated = require_recent_strong_session(&session, now_utc()).is_ok();
    let attrs = RequestAttributes {
        branch: None,
        elevated,
        human_session: true,
        recent_strong_auth: elevated,
        ..RequestAttributes::default()
    };
    Ok(RouteAuth { claims, attrs })
}

/// Identity for project-less routes (`GET /v1/projects`). Tokens stay
/// confined to their own project; sessions list every membership.
struct LooseAuth {
    principal_id: String,
    project_id: Option<String>,
    tenant_id: Option<String>,
    environment_id: Option<String>,
}

fn authenticate_loose(
    state: &AccountState,
    headers: &HeaderMap,
) -> Result<LooseAuth, Box<Response>> {
    let token_path =
        bearer_token(headers).is_some_and(|token| token.starts_with(SCOPE_TOKEN_PREFIX));
    if token_path {
        let token = bearer_token(headers).unwrap_or_default();
        let claims = verify_token_claims(state, headers, token)?;
        Ok(LooseAuth {
            principal_id: claims.principal_id,
            project_id: Some(claims.project_id),
            tenant_id: Some(claims.tenant_id),
            environment_id: claims.environment_id,
        })
    } else {
        let session = authenticated_session(state, headers)?;
        Ok(LooseAuth {
            principal_id: format!("account:{}", session.account_id),
            project_id: None,
            tenant_id: None,
            environment_id: None,
        })
    }
}

/// Local KEK service bound to one project (development/small deployments;
/// KMS-backed deployments swap this constructor in Phase 10).
pub(crate) fn wrapping_for(
    state: &AccountState,
    project_id: &str,
) -> Result<(VersionedKekService, String), Box<Response>> {
    let raw = match std::env::var(LOCAL_KEK_FILE_ENV) {
        Ok(path) if !path.trim().is_empty() => {
            std::fs::read_to_string(path.trim()).map_err(|_| {
                error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "KEK_UNAVAILABLE",
                    "Local KEK file is unreadable",
                )
            })?
        }
        _ => std::env::var(LOCAL_KEK_ENV).map_err(|_| {
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "KEK_UNAVAILABLE",
                "Local KEK is not configured",
            )
        })?,
    };
    let service = VersionedKekService::from_config(project_id, &raw).map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "KEK_INVALID",
            "Local KEK configuration is invalid or its active version is unavailable",
        )
    })?;
    {
        let mut db = state.connection().map_err(service_error)?;
        service.register(&mut db, project_id).map_err(|_| error_response(StatusCode::SERVICE_UNAVAILABLE,
            "KEK_IDENTITY_MISMATCH", "Configured KEK versions do not match stored key identity; retain historical key material"))?;
    }
    let id = service.active_id().to_string();
    Ok((service, id))
}

pub(crate) fn secret_error_response(err: SecretError) -> Response {
    match err {
        SecretError::NotFound | SecretError::Denied => scoped_denial_response(),
        SecretError::RevisionMismatch => error_response(
            StatusCode::CONFLICT,
            "SCOPE_REVISION_CHANGED",
            "Scope versions changed; fetch a fresh batch",
        ),
        SecretError::MaterializationTooLarge => error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "MATERIALIZATION_TOO_LARGE",
            "Batch values exceed 128 KiB",
        ),
        SecretError::IdempotencyConflict => error_response(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_CONFLICT",
            "Use a new idempotency key for a different or legacy request",
        ),
        SecretError::Conflict => error_response(
            StatusCode::CONFLICT,
            "SECRET_NAME_CONFLICT",
            "A secret with this name already exists in this scope",
        ),
        SecretError::Invalid(message) => {
            error_response(StatusCode::BAD_REQUEST, "INVALID_SECRET_REQUEST", message)
        }
        SecretError::VerificationFailed => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ROTATION_VERIFY_FAILED",
            "The new credential failed liveness verification",
        ),
        SecretError::Crypto(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SECRET_CRYPTO_FAILURE",
            "Secret decryption failed",
        ),
        SecretError::Db(_) | SecretError::Service(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SECRET_STORE_UNAVAILABLE",
            "Secret store unavailable",
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateSecretBody {
    name: String,
    secret_type: Option<String>,
    description: Option<String>,
    value: String,
    tags: Option<Vec<String>>,
    repository_binding_id: Option<String>,
    service_id: Option<String>,
}

pub async fn post_secret(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, environment_id)): Path<(String, String)>,
    Json(body): Json<CreateSecretBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, Some(&environment_id)) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    if body.value.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "value must not be empty",
        );
    }
    let (wrap, kek_id) = match wrapping_for(&state, &project_id) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let tags = body.tags.unwrap_or_default();
    let secret_type = body.secret_type.as_deref().unwrap_or("key_value");
    let description = body.description.as_deref().unwrap_or("");
    match create_secret(
        &mut db,
        &wrap,
        &kek_id,
        &auth.claims,
        &auth.attrs,
        &CreateSecret {
            project_id: &project_id,
            environment_id: &environment_id,
            name: &body.name,
            secret_type,
            description,
            tags: &tags,
            repository_binding_id: body.repository_binding_id.as_deref(),
            service_id: body.service_id.as_deref(),
            value: &SecretValue::from(body.value.clone()),
            request_id: &random_hex(8),
        },
    ) {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(err) => secret_error_response(err),
    }
}

#[derive(Serialize)]
pub(crate) struct SecretValueBody<T: Serialize> {
    #[serde(flatten)]
    meta: T,
    version: i64,
    value: String,
}

#[derive(Deserialize)]
pub(crate) struct ValueQuery {
    metadata_only: Option<bool>,
}

pub async fn get_secret_value_route(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, environment_id, name)): Path<(String, String, String)>,
    Query(query): Query<ValueQuery>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, Some(&environment_id)) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    // Resolve name → id without leaking existence (uniform 404 either way).
    let secret_id: Option<String> = {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        match db.query_row(
            "SELECT secret_id FROM secrets
             WHERE project_id = ?1 AND environment_id = ?2 AND name = ?3
               AND deleted_at_utc IS NULL",
            rusqlite::params![project_id, environment_id, name],
            |row| row.get(0),
        ) {
            Ok(id) => Some(id),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(error) => return service_error(error.into()),
        }
    };
    let Some(secret_id) = secret_id else {
        return scoped_denial_response();
    };
    if query.metadata_only.unwrap_or(false) {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        return match get_secret_metadata(&db, &auth.claims, &auth.attrs, &secret_id) {
            Ok(view) => Json(view).into_response(),
            Err(err) => secret_error_response(err),
        };
    }
    // Plaintext reads consume the tight value bucket (metadata-only hits
    // above consume just the API bucket).
    {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        if let Err(failure) = check_quota(
            &db,
            &READ_VALUE_BUCKET,
            &auth.claims.tenant_id,
            &auth.claims.principal_id,
            now_utc(),
        ) {
            return quota_failure_response(failure);
        }
    }
    let (wrap, _) = match wrapping_for(&state, &project_id) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match get_secret_value(
        &mut db,
        &wrap,
        &auth.claims,
        &auth.attrs,
        &secret_id,
        &random_hex(8),
    ) {
        Ok(view) => Json(SecretValueBody {
            meta: view.meta,
            version: view.version,
            // Values enter through JSON (UTF-8); binary APIs arrive in Phase 7.
            value: String::from_utf8_lossy(view.value.expose()).into_owned(),
        })
        .into_response(),
        Err(err) => secret_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    environment: Option<String>,
    tag: Option<String>,
    status: Option<String>,
    q: Option<String>,
    limit: Option<i64>,
}

pub async fn get_secrets(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Response {
    // Authenticate at project level first; the effective environment is the
    // intersection of token scope and query (token scope wins on widening).
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let effective_env = match (
        auth.claims.environment_id.as_deref(),
        query.environment.as_deref(),
    ) {
        (Some(token_env), Some(query_env)) if token_env != query_env => {
            return scoped_denial_response();
        }
        (Some(token_env), _) => Some(token_env.to_string()),
        (None, query_env) => query_env.map(str::to_string),
    };
    let Some(environment_id) = effective_env else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "environment query parameter is required for project-wide tokens",
        );
    };
    if query.q.as_deref().is_some_and(|q| q.len() > 128) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "q must be at most 128 characters",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match list_secrets(
        &db,
        &auth.claims,
        &auth.attrs,
        &SecretListFilter {
            project_id: &project_id,
            environment_id: &environment_id,
            tag: query.tag.as_deref(),
            status: query.status.as_deref(),
            q: query.q.as_deref(),
            limit: query.limit.unwrap_or(50),
        },
    ) {
        Ok(views) => {
            let revision =
                crate::scoped_enhancements::scope_revision(&project_id, &environment_id, &views);
            Json(serde_json::json!({ "secrets": views, "revision": revision })).into_response()
        }
        Err(err) => secret_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct UpdateSecretBody {
    description: Option<String>,
    tags: Option<Vec<String>>,
    expires_at_utc: Option<u64>,
    status: Option<String>,
}

pub async fn patch_secret(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, secret_id)): Path<(String, String)>,
    Json(body): Json<UpdateSecretBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match update_secret_metadata(
        &mut db,
        &auth.claims,
        &auth.attrs,
        &secret_id,
        &UpdateSecretMetadata {
            description: body.description.as_deref(),
            tags: body.tags.as_deref(),
            expires_at_utc: body.expires_at_utc,
            status: body.status.as_deref(),
        },
        &random_hex(8),
    ) {
        Ok(view) => Json(view).into_response(),
        Err(err) => secret_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct MoveSecretBody {
    new_name: Option<String>,
    new_environment_id: Option<String>,
    reason: String,
}

pub async fn post_secret_move(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, secret_id)): Path<(String, String)>,
    Json(body): Json<MoveSecretBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let (wrap, kek_id) = match wrapping_for(&state, &project_id) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match move_secret(
        &mut db,
        &wrap,
        &kek_id,
        &auth.claims,
        &auth.attrs,
        &secret_id,
        &MoveSecret {
            new_name: body.new_name.as_deref(),
            new_environment_id: body.new_environment_id.as_deref(),
            reason: &body.reason,
            request_id: &random_hex(8),
        },
    ) {
        Ok(view) => Json(view).into_response(),
        Err(err) => secret_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct RebindSecretBody {
    #[serde(default)]
    repository_binding_id: JsonNullable,
    #[serde(default)]
    service_id: JsonNullable,
    reason: String,
}

fn nullable_to_opt(value: &JsonNullable) -> Option<Option<&str>> {
    match value {
        JsonNullable::Keep => None,
        JsonNullable::Clear => Some(None),
        JsonNullable::Set(value) => Some(Some(value.as_str())),
    }
}

pub async fn post_secret_rebind(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, secret_id)): Path<(String, String)>,
    Json(body): Json<RebindSecretBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match rebind_secret(
        &mut db,
        &auth.claims,
        &auth.attrs,
        &secret_id,
        &RebindSecret {
            repository_binding_id: nullable_to_opt(&body.repository_binding_id),
            service_id: nullable_to_opt(&body.service_id),
            reason: &body.reason,
            request_id: &random_hex(8),
        },
    ) {
        Ok(view) => Json(view).into_response(),
        Err(err) => secret_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct RotateSecretBody {
    new_value: String,
    idempotency_key: String,
    reason: String,
    #[serde(default)]
    verify_provider: bool,
}

pub async fn post_secret_rotate(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, secret_id)): Path<(String, String)>,
    Json(body): Json<RotateSecretBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    if body.new_value.is_empty() || body.idempotency_key.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "new_value and idempotency_key are required",
        );
    }
    let (wrap, kek_id) = match wrapping_for(&state, &project_id) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    // Authorize before exposing whether a provider integration is available.
    let view = match crate::secrets::resolve_secret(&db, &secret_id) {
        Ok(view) => view,
        Err(error) => return secret_error_response(error),
    };
    if crate::policy::authorize(
        &db,
        &auth.claims,
        crate::policy::ScopedAction::RotateSecret,
        &crate::secrets::target_from_view(&view),
        &auth.attrs,
    )
    .is_err()
    {
        return scoped_denial_response();
    }
    if body.verify_provider {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "PROVIDER_VERIFICATION_UNAVAILABLE",
            "Provider credential verification is not configured; manual replacement remains available");
    }
    match rotate_secret(
        &mut db,
        &wrap,
        &kek_id,
        &ManualReplacementVerifier,
        &auth.claims,
        &auth.attrs,
        &RotateSecret {
            secret_id: &secret_id,
            new_value: &SecretValue::from(body.new_value.clone()),
            idempotency_key: &body.idempotency_key,
            reason: &body.reason,
            request_id: &random_hex(8),
        },
    ) {
        Ok(outcome) => Json(outcome).into_response(),
        Err(err) => secret_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct DeleteQuery {
    reason: Option<String>,
}

pub async fn delete_secret_route(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, secret_id)): Path<(String, String)>,
    Query(query): Query<DeleteQuery>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let reason = query.reason.as_deref().unwrap_or("");
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match delete_secret(
        &mut db,
        &auth.claims,
        &auth.attrs,
        &secret_id,
        reason,
        &random_hex(8),
    ) {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "scheduled_deletion" })),
        )
            .into_response(),
        Err(err) => secret_error_response(err),
    }
}

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

#[derive(Deserialize)]
pub(crate) struct MintTokenBody {
    project_id: String,
    environment_id: Option<String>,
    repository_binding_id: Option<String>,
    service_id: Option<String>,
    branch: Option<String>,
    /// Human callers must explicitly opt into production elevation. The
    /// server verifies fresh signing-key/passkey proof; no branch is inferred.
    #[serde(default)]
    elevated: bool,
    ttl_seconds: Option<u64>,
    /// Opt-in DPoP-lite binding (T-902): 64-hex ed25519 public key. Bound
    /// tokens require a `DPoP` proof on every use.
    bind_pubkey_ed25519_hex: Option<String>,
}

/// Mints a narrow scope token from an account session (no token-exchange
/// chains in v1). Branch-bearing workload credentials require a real trusted
/// identity adapter, which is unavailable in this runtime.
pub async fn post_scope_token(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(body): Json<MintTokenBody>,
) -> Response {
    if bearer_token(&headers).is_some_and(|token| token.starts_with(SCOPE_TOKEN_PREFIX)) {
        return error_response(
            StatusCode::FORBIDDEN,
            "TOKEN_EXCHANGE_DENIED",
            "Scope tokens cannot mint further tokens",
        );
    }
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_recent_strong_session(&session, now_utc()) {
        return *response;
    }
    if body.branch.is_some() {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "WORKLOAD_ATTESTATION_UNAVAILABLE",
            "Branch claims require a configured trusted workload identity verifier",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let tenant: Option<String> = db
        .query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            rusqlite::params![body.project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| service_error(err.into()))
        .unwrap_or(None);
    let Some(tenant) = tenant else {
        return scoped_denial_response();
    };
    let principal_id = format!("account:{}", session.account_id);
    let grant = match project_role_of(&db, &body.project_id, &principal_id) {
        Ok(grant) => grant,
        Err(error) => return service_error(error.into()),
    };
    if grant.is_none() {
        return scoped_denial_response();
    }
    // Credential issuance is quota-tight: a stolen session mints slowly.
    if let Err(failure) = check_quota(&db, &MINT_BUCKET, &tenant, &principal_id, now_utc()) {
        return quota_failure_response(failure);
    }
    // Existence checks stay uniform-404 (no scope enumeration).
    for (table, column, value) in [
        (
            "environments",
            "environment_id",
            body.environment_id.as_deref(),
        ),
        (
            "repository_bindings",
            "binding_id",
            body.repository_binding_id.as_deref(),
        ),
        ("services", "service_id", body.service_id.as_deref()),
    ] {
        if let Some(value) = value {
            let exists: bool = match db.query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM {table} WHERE {column} = ?1
                          AND tenant_id = ?2 AND project_id = ?3)"
                ),
                rusqlite::params![value, tenant, body.project_id],
                |row| row.get(0),
            ) {
                Ok(exists) => exists,
                Err(error) => return service_error(error.into()),
            };
            if !exists {
                return scoped_denial_response();
            }
        }
    }
    let now = now_utc();
    let ttl = body
        .ttl_seconds
        .unwrap_or(900)
        .clamp(60, 900)
        .min(session.expires_at_utc.saturating_sub(now));
    let Some(source_token) = session_token(&headers) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "SESSION_REQUIRED",
            "Account session required",
        );
    };
    let mut claims = ScopeClaims::new(&tenant, &body.project_id, &principal_id, now, now + ttl);
    claims.origin_session_hash = Some(crate::util::hash_token(&source_token));
    match crate::scope_tokens::scope_origin_active(&db, &claims, now, true) {
        Ok(true) => {}
        Ok(false) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "SESSION_INVALID",
                "Issuer session is no longer active",
            )
        }
        Err(error) => return service_error(error.into()),
    }
    if body.elevated {
        let until = session
            .issued_at_utc
            .saturating_add(STEP_UP_MAX_AGE_SECONDS)
            .min(claims.expires_at_utc);
        if until <= now {
            return error_response(
                StatusCode::FORBIDDEN,
                "AUTHENTICATION_STEP_UP_REQUIRED",
                "Authenticate again before requesting production elevation",
            );
        }
        claims.elevated_until_utc = Some(until);
    }
    if let Some(env) = body.environment_id.as_deref() {
        claims = claims.with_environment(env);
    }
    if let Some(binding) = body.repository_binding_id.as_deref() {
        claims = claims.with_repository_binding(binding);
    }
    if let Some(service) = body.service_id.as_deref() {
        claims = claims.with_service(service);
    }
    if let Some(bind) = body.bind_pubkey_ed25519_hex.as_deref() {
        match crate::dpop::validate_binding_key(bind) {
            Ok(normalized) => claims = claims.with_cnf(&normalized),
            Err(detail) => {
                return error_response(StatusCode::BAD_REQUEST, "INVALID_SECRET_REQUEST", detail);
            }
        }
    }
    if let Some(environment) = body.environment_id.as_deref() {
        let tier: i64 = match db.query_row(
            "SELECT tier FROM environments WHERE environment_id = ?1",
            [environment],
            |row| row.get(0),
        ) {
            Ok(tier) => tier,
            Err(error) => return service_error(error.into()),
        };
        if tier >= 2 && claims.elevated_until_utc.is_none() {
            return error_response(
                StatusCode::FORBIDDEN,
                "PRODUCTION_ELEVATION_REQUIRED",
                "Request explicit elevation after fresh signing-key or passkey authentication",
            );
        }
    }
    if let Some(binding) = body.repository_binding_id.as_deref() {
        let active: bool = match db.query_row(
            "SELECT EXISTS(SELECT 1 FROM repository_bindings
            WHERE binding_id = ?1 AND status = 'active' AND ownership_verified_at_utc IS NOT NULL)",
            [binding],
            |row| row.get(0),
        ) {
            Ok(active) => active,
            Err(error) => return service_error(error.into()),
        };
        if !active {
            return scoped_denial_response();
        }
    }
    let key = match scope_token_signing_key() {
        Ok(key) => key,
        Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "SCOPE_TOKENS_UNCONFIGURED",
                "Scope-token authentication is not configured",
            );
        }
    };
    let token = match mint_scope_token(&key, &claims) {
        Ok(token) => token,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "TOKEN_MINT_FAILED",
                "Could not mint scope token",
            );
        }
    };
    // Credential issuance is audited (jti + scope columns, never the token
    // itself — the scrubber would redact it anyway, but audit must not rely
    // on last-chance filters for values it never receives).
    let request_id = random_hex(8);
    let reason = serde_json::json!({
        "jti": claims.jti,
        "expires_in": ttl,
        "bound": claims.cnf.is_some(),
        "elevated_until_utc": claims.elevated_until_utc,
    })
    .to_string();
    if let Err(error) = audit_secret_event(
        &db,
        &SecretAuditEvent {
            event_type: AuditEventType::TokenMinted.as_str(),
            tenant_id: &tenant,
            project_id: Some(&body.project_id),
            environment_id: body.environment_id.as_deref(),
            secret_id: None,
            secret_version: None,
            principal_id: &principal_id,
            request_id: &request_id,
            source: "api",
            result: "success",
            reason: &reason,
        },
        now,
    ) {
        return service_error(error.into());
    }
    Json(serde_json::json!({
        "token": token,
        "expires_in": ttl,
        "scope": {
            "project_id": claims.project_id,
            "environment_id": claims.environment_id,
            "repository_binding_id": claims.repository_binding_id,
            "service_id": claims.service_id,
        },
    }))
    .into_response()
}

#[derive(Deserialize)]
pub(crate) struct RevokeTokenBody {
    jti: String,
}

/// Revokes a scope token id (session-authenticated logout).
pub async fn delete_scope_token(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(body): Json<RevokeTokenBody>,
) -> Response {
    if bearer_token(&headers).is_some_and(|token| token.starts_with(SCOPE_TOKEN_PREFIX)) {
        return error_response(
            StatusCode::FORBIDDEN,
            "TOKEN_EXCHANGE_DENIED",
            "Scope tokens cannot manage revocation",
        );
    }
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_recent_strong_session(&session, now_utc()) {
        return *response;
    }
    if body.jti.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "jti is required",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    // Retain past the maximum token TTL so any live token stays denied.
    match deny_scope_token(&db, body.jti.trim(), now_utc() + 3600) {
        Ok(()) => Json(serde_json::json!({ "revoked": true })).into_response(),
        Err(error) => service_error(error.into()),
    }
}

/// Exports the tenant's audit chain as JSONL for off-host append-only cold
/// storage (T-901). Admins and auditors only; the chain is verified first
/// and a broken chain fails closed (500, no partial ship). The export
/// itself is not audited: it carries digests and metadata, never values
/// (reads are only audited for value access).
///
/// Dual control (T-902): bulk export additionally requires a second
/// credential — `x-step-up-authorization: Bearer <token>` holding a valid
/// scope token for the same project from a DIFFERENT ViewAudit-authorized
/// principal. Step-up tokens must be unbound (no `cnf`): the step-up is a
/// presence factor, key-binding applies to the primary credential.
pub async fn get_audit_export(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    // NOTE: `AccountState` guards a single global `Mutex<Connection>`.
    // Every block below acquires and releases it; nothing here may hold
    // the guard across `verify_token_claims` (which acquires its own) —
    // nesting self-deadlocks (non-reentrant mutex, caught by the export
    // lifecycle test hanging).
    let tenant: Option<String> = {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        db.query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            rusqlite::params![project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| service_error(err.into()))
        .unwrap_or(None)
    };
    let Some(tenant) = tenant else {
        return scoped_denial_response();
    };
    {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
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
            crate::policy::ScopedAction::ViewAudit,
            &target,
            &auth.attrs,
        )
        .is_err()
        {
            return scoped_denial_response();
        }
    }
    // Dual control: a second, distinct, ViewAudit-authorized principal for
    // the same project must co-sign via the step-up header. Single code for
    // every step-up failure (no oracle on the second credential).
    let step_up = headers
        .get("x-step-up-authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .strip_prefix("Bearer ")
        .unwrap_or_default()
        .trim()
        .to_string();
    if step_up.is_empty() {
        return error_response(
            StatusCode::FORBIDDEN,
            "DUAL_CONTROL_REQUIRED",
            "Bulk export requires a second authorized principal (x-step-up-authorization)",
        );
    }
    let second = match verify_token_claims(&state, &headers, &step_up) {
        Ok(claims) => claims,
        Err(_) => {
            return error_response(
                StatusCode::FORBIDDEN,
                "DUAL_CONTROL_REQUIRED",
                "Bulk export requires a second authorized principal (x-step-up-authorization)",
            );
        }
    };
    {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        let second_role = project_role_of(&db, &project_id, &second.principal_id).unwrap_or(None);
        let second_ok = second.tenant_id == tenant
            && second.project_id == project_id
            && second.principal_id != auth.claims.principal_id
            && second.cnf.is_none()
            && second_role.is_some_and(|role| {
                crate::policy::role_allows(role, crate::policy::ScopedAction::ViewAudit)
            });
        if !second_ok {
            return error_response(
                StatusCode::FORBIDDEN,
                "DUAL_CONTROL_REQUIRED",
                "Bulk export requires a second authorized principal (x-step-up-authorization)",
            );
        }
        // Bulk export + full-chain recompute per call: quota-tight.
        if let Err(failure) = check_quota(
            &db,
            &EXPORT_BUCKET,
            &tenant,
            &auth.claims.principal_id,
            now_utc(),
        ) {
            return quota_failure_response(failure);
        }
    }
    let report = {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        match verify_chain(&db, &tenant) {
            Ok(report) => report,
            Err(error) => return service_error(error.into()),
        }
    };
    if !report.valid {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AUDIT_CHAIN_BROKEN",
            format!(
                "Audit chain verification failed at event {}",
                report.first_bad_event_id.as_deref().unwrap_or("unknown")
            ),
        );
    }
    let jsonl = {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        match export_audit_log(&db, &tenant) {
            Ok(jsonl) => jsonl,
            Err(error) => return service_error(error.into()),
        }
    };
    let mut out_headers = HeaderMap::new();
    out_headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(count) = axum::http::HeaderValue::from_str(&report.event_count.to_string()) {
        out_headers.insert("x-audit-events", count);
    }
    if let Ok(head) = axum::http::HeaderValue::from_str(&hex::encode(&report.head_hash)) {
        out_headers.insert("x-audit-head", head);
    }
    (StatusCode::OK, out_headers, jsonl).into_response()
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ciphervault_format::{EnvironmentId, ProjectId, TenantId};
    use tower05::ServiceExt;

    use crate::policy::{grant_project_role, ProjectRole};
    use crate::scope_tokens::mint_scope_token;
    use crate::test_support::{cleanup, json, test_app};
    use crate::util::hash_token;

    const TEST_SIGNING_KEY: [u8; 32] = [0x11; 32];

    /// Fixed env values shared by all route tests (idempotent under parallel runs).
    fn test_env() {
        std::env::set_var("CIPHERVAULT_ACCOUNT_SCOPE_TOKEN_KEY", "11".repeat(32));
        std::env::set_var("CIPHERVAULT_ACCOUNT_LOCAL_KEK", "22".repeat(32));
        std::env::set_var("CIPHERVAULT_VCS_WEBHOOK_KEY", "11".repeat(32));
    }

    struct ProjectFixture {
        project: String,
        env: String,
    }

    fn seed_project(
        db: &rusqlite::Connection,
        tenant: &str,
        slug: &str,
        account: &str,
        role: ProjectRole,
    ) -> ProjectFixture {
        let project = ProjectId::generate().to_hex();
        let env = EnvironmentId::generate().to_hex();
        db.execute(
            "INSERT INTO workspaces(workspace_id, tenant_id, name, created_at_utc)
             VALUES(?1, ?2, ?3, 1)",
            rusqlite::params![format!("w-{slug}"), tenant, slug],
        )
        .unwrap();
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
             VALUES(?1, ?2, ?3, ?4, ?4, 1)",
            rusqlite::params![project, tenant, format!("w-{slug}"), slug],
        )
        .unwrap();
        db.execute(
            "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier,
                                       created_at_utc)
             VALUES(?1, ?2, ?3, 'staging', 1, 1)",
            rusqlite::params![env, tenant, project],
        )
        .unwrap();
        grant_project_role(db, &project, account, role, "root", 1).unwrap();
        ProjectFixture { project, env }
    }

    fn seed_org(db: &rusqlite::Connection) -> String {
        let tenant = TenantId::generate().to_hex();
        db.execute(
            "INSERT INTO organizations(tenant_id, name, created_at_utc) VALUES(?1, 'Acme', 1)",
            rusqlite::params![tenant],
        )
        .unwrap();
        tenant
    }

    fn mint(tenant: &str, project: &str, env: Option<&str>, principal: &str) -> String {
        let mut claims = ScopeClaims::new(tenant, project, principal, 1000, 9_999_999_999);
        if let Some(env) = env {
            claims = claims.with_environment(env);
        }
        mint_scope_token(&TEST_SIGNING_KEY, &claims).unwrap()
    }

    async fn call(
        app: axum::Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = match method {
            "GET" => Request::get(uri),
            "POST" => Request::post(uri),
            "PATCH" => Request::patch(uri),
            "DELETE" => Request::delete(uri),
            _ => panic!("method {method}"),
        };
        builder = builder.header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let body = body.map_or_else(Body::empty, |value| {
            Body::from(serde_json::to_vec(&value).unwrap())
        });
        let response = app.oneshot(builder.body(body).unwrap()).await.unwrap();
        let status = response.status();
        (status, json(response).await)
    }

    async fn call_headers(
        app: axum::Router,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = match method {
            "GET" => Request::get(uri),
            "POST" => Request::post(uri),
            "PATCH" => Request::patch(uri),
            "DELETE" => Request::delete(uri),
            _ => panic!("method {method}"),
        };
        builder = builder.header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, value.as_str());
        }
        let body = body.map_or_else(Body::empty, |value| {
            Body::from(serde_json::to_vec(&value).unwrap())
        });
        let response = app.oneshot(builder.body(body).unwrap()).await.unwrap();
        let status = response.status();
        (status, json(response).await)
    }

    #[tokio::test]
    async fn http_lifecycle() {
        test_env();
        let (root, state, app) = test_app("routes-lifecycle");
        let tenant = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            seed_project(
                &db,
                &tenant,
                "payments",
                "account:alice",
                ProjectRole::Admin,
            );
            tenant
        };
        let (project, env): (String, String) = {
            let db = state.connection().unwrap();
            let project: String = db
                .query_row(
                    "SELECT project_id FROM projects WHERE slug = 'payments'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let env: String = db
                .query_row(
                    "SELECT environment_id FROM environments WHERE project_id = ?1",
                    rusqlite::params![project],
                    |row| row.get(0),
                )
                .unwrap();
            (project, env)
        };
        let token = mint(&tenant, &project, Some(&env), "account:alice");

        // Create.
        let (status, created) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/environments/{env}/secrets"),
            Some(&token),
            Some(serde_json::json!({
                "name": "DATABASE_URL",
                "value": "postgres://localhost/db",
                "tags": ["database"],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let secret_id = created["secret_id"].as_str().unwrap().to_string();

        // Read value + metadata-only.
        let (status, got) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/environments/{env}/secrets/DATABASE_URL"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["value"], "postgres://localhost/db");
        let (status, meta) = call(
            app.clone(),
            "GET",
            &format!(
                "/v1/projects/{project}/environments/{env}/secrets/DATABASE_URL?metadata_only=true"
            ),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(meta.get("value").is_none());

        // List + patch + rotate.
        let (status, list) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/secrets?environment={env}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list["secrets"].as_array().unwrap().len(), 1);
        let (status, _) = call(
            app.clone(),
            "PATCH",
            &format!("/v1/projects/{project}/secrets/{secret_id}"),
            Some(&token),
            Some(serde_json::json!({ "description": "primary" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, rotated) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/secrets/{secret_id}/rotate"),
            Some(&token),
            Some(serde_json::json!({
                "new_value": "postgres://localhost/db2",
                "idempotency_key": "idem-1",
                "reason": "scheduled",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rotated["current_version"], 2);

        // Move + rebind + delete.
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/secrets/{secret_id}/move"),
            Some(&token),
            Some(serde_json::json!({ "new_name": "PRIMARY_DB_URL", "reason": "rename" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/secrets/{secret_id}/rebind"),
            Some(&token),
            Some(serde_json::json!({ "reason": "noop" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, deleted) = call(
            app.clone(),
            "DELETE",
            &format!("/v1/projects/{project}/secrets/{secret_id}?reason=retired"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(deleted["status"], "scheduled_deletion");
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/environments/{env}/secrets/PRIMARY_DB_URL"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup(root);
    }

    #[tokio::test]
    async fn bola_matrix_denies_cross_project() {
        test_env();
        let (root, state, app) = test_app("routes-bola");
        let (tenant, project_a, env_a, project_b, env_b) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let a = seed_project(&db, &tenant, "proj-a", "account:alice", ProjectRole::Admin);
            let b = seed_project(&db, &tenant, "proj-b", "account:alice", ProjectRole::Admin);
            // Alice's B grant is revoked: B is out of scope for her A token.
            crate::policy::revoke_project_role(&db, &b.project, "account:alice", 2).unwrap();
            (tenant, a.project, a.env, b.project, b.env)
        };
        // Seed one secret in B directly (bypassing HTTP, as the B admin would).
        let secret_b = {
            let mut db = state.connection().unwrap();
            crate::policy::grant_project_role(
                &db,
                &project_b,
                "account:root",
                ProjectRole::Admin,
                "root",
                1,
            )
            .unwrap();
            let claims = ScopeClaims::new(&tenant, &project_b, "account:root", 1000, 9_999_999_999)
                .with_environment(&env_b);
            let wrap = ciphervault_crypto::LocalKekService::new("local:test", [0x22; 32]);
            crate::secrets::create_secret(
                &mut db,
                &wrap,
                "local:test",
                &claims,
                &crate::policy::RequestAttributes::default(),
                &crate::secrets::CreateSecret {
                    project_id: &project_b,
                    environment_id: &env_b,
                    name: "B_SECRET",
                    secret_type: "key_value",
                    description: "",
                    tags: &[],
                    repository_binding_id: None,
                    service_id: None,
                    value: &ciphervault_format::SecretValue::from("b-value"),
                    request_id: "seed",
                },
            )
            .unwrap()
            .secret_id
        };
        let token_a = mint(&tenant, &project_a, Some(&env_a), "account:alice");

        // Every route: A-token × B-path ⇒ uniform 404.
        let cases: Vec<(&str, String, Option<serde_json::Value>)> = vec![
            (
                "POST",
                format!("/v1/projects/{project_b}/environments/{env_b}/secrets"),
                Some(serde_json::json!({"name": "X", "value": "x"})),
            ),
            (
                "GET",
                format!("/v1/projects/{project_b}/environments/{env_b}/secrets/B_SECRET"),
                None,
            ),
            (
                "GET",
                format!("/v1/projects/{project_b}/secrets?environment={env_b}"),
                None,
            ),
            (
                "PATCH",
                format!("/v1/projects/{project_b}/secrets/{secret_b}"),
                Some(serde_json::json!({ "description": "x" })),
            ),
            (
                "POST",
                format!("/v1/projects/{project_b}/secrets/{secret_b}/move"),
                Some(serde_json::json!({ "new_name": "Y", "reason": "x" })),
            ),
            (
                "POST",
                format!("/v1/projects/{project_b}/secrets/{secret_b}/rebind"),
                Some(serde_json::json!({ "reason": "x" })),
            ),
            (
                "POST",
                format!("/v1/projects/{project_b}/secrets/{secret_b}/rotate"),
                Some(serde_json::json!({
                    "new_value": "x",
                    "idempotency_key": "k",
                    "reason": "x",
                })),
            ),
            (
                "DELETE",
                format!("/v1/projects/{project_b}/secrets/{secret_b}?reason=x"),
                None,
            ),
        ];
        for (method, uri, body) in cases {
            let (status, _) = call(app.clone(), method, &uri, Some(&token_a), body).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
        }
        // Unknown project ids are indistinguishable from forbidden ones.
        let ghost = "ff".repeat(16);
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{ghost}/secrets?environment={env_b}"),
            Some(&token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup(root);
    }

    #[tokio::test]
    async fn token_auth_failures() {
        test_env();
        let (root, state, app) = test_app("routes-authfail");
        let (tenant, project, env) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(
                &db,
                &tenant,
                "shop",
                "account:alice",
                ProjectRole::Developer,
            );
            (tenant, fixture.project, fixture.env)
        };
        let uri = format!("/v1/projects/{project}/secrets?environment={env}");
        // No credentials at all.
        let (status, _) = call(app.clone(), "GET", &uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Tampered token.
        let mut token = mint(&tenant, &project, Some(&env), "account:alice");
        token.push('x');
        let (status, _) = call(app.clone(), "GET", &uri, Some(&token), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Expired token.
        let claims = ScopeClaims::new(&tenant, &project, "account:alice", 100, 200);
        let expired = mint_scope_token(&TEST_SIGNING_KEY, &claims).unwrap();
        let (status, _) = call(app.clone(), "GET", &uri, Some(&expired), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Revoked token.
        let claims = ScopeClaims::new(&tenant, &project, "account:alice", 1000, 9_999_999_999)
            .with_environment(&env);
        let jti = claims.jti.clone();
        let token = mint_scope_token(&TEST_SIGNING_KEY, &claims).unwrap();
        {
            let db = state.connection().unwrap();
            crate::scope_tokens::deny_scope_token(&db, &jti, 9_999_999_999).unwrap();
        }
        let (status, _) = call(app.clone(), "GET", &uri, Some(&token), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        cleanup(root);
    }

    #[tokio::test]
    async fn roles_and_members() {
        test_env();
        let (root, state, app) = test_app("routes-roles");
        let (tenant, project, env) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "shop", "account:alice", ProjectRole::Admin);
            (tenant, fixture.project, fixture.env)
        };
        let admin = mint(&tenant, &project, Some(&env), "account:alice");
        // Create a secret, then downgrade alice to auditor for read checks.
        let (_, created) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/environments/{env}/secrets"),
            Some(&admin),
            Some(serde_json::json!({ "name": "K", "value": "v" })),
        )
        .await;
        assert_eq!(created["name"], "K");
        {
            let db = state.connection().unwrap();
            grant_project_role(
                &db,
                &project,
                "account:alice",
                ProjectRole::Auditor,
                "root",
                2,
            )
            .unwrap();
            grant_project_role(
                &db,
                &project,
                "account:bob",
                ProjectRole::Developer,
                "root",
                2,
            )
            .unwrap();
        }
        // Auditor: values denied, metadata allowed, writes denied.
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/environments/{env}/secrets/K"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/environments/{env}/secrets/K?metadata_only=true"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/environments/{env}/secrets"),
            Some(&admin),
            Some(serde_json::json!({ "name": "K2", "value": "v" })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Member management requires admin: bob (developer) is denied.
        let bob = mint(&tenant, &project, Some(&env), "account:bob");
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/members"),
            Some(&bob),
            Some(serde_json::json!({ "principal_id": "account:mallory", "role": "developer" })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Restore alice to admin: member add + revoke roundtrip.
        {
            let db = state.connection().unwrap();
            grant_project_role(
                &db,
                &project,
                "account:alice",
                ProjectRole::Admin,
                "root",
                3,
            )
            .unwrap();
        }
        // Project-wide membership changes use a separate administration token.
        let management = mint(&tenant, &project, None, "account:alice");
        let (status, member) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/members"),
            Some(&management),
            Some(serde_json::json!({ "principal_id": "account:carol", "role": "operator" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(member["role"], "operator");
        let (status, _) = call(
            app.clone(),
            "DELETE",
            &format!("/v1/projects/{project}/members?principal_id=account:carol"),
            Some(&management),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        cleanup(root);
    }

    #[tokio::test]
    async fn session_mint_and_revoke() {
        test_env();
        let (root, state, app) = test_app("routes-mint");
        let (_tenant, project, env) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(
                &db,
                &tenant,
                "shop",
                "account:acct-alice",
                ProjectRole::Developer,
            );
            db.execute(
                "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                 VALUES('acct-alice', 'Alice', 'aa', 1)",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO sessions(token_hash_hex, account_id, session_kind, issued_at_utc,
                                      expires_at_utc)
                 VALUES(?1, 'acct-alice', 'device', ?2, 9999999999)",
                rusqlite::params![hash_token("session-token-alice"), now_utc()],
            )
            .unwrap();
            (tenant, fixture.project, fixture.env)
        };
        // Mint requires the session; wrong credentials fail.
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            None,
            Some(serde_json::json!({ "project_id": project })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, minted) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            Some("session-token-alice"),
            Some(serde_json::json!({
                "project_id": project,
                "environment_id": env,
                "ttl_seconds": 600,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(minted["expires_in"], 600);
        let token = minted["token"].as_str().unwrap().to_string();
        // Minted token reads within its scope.
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/secrets?environment={env}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Tokens cannot mint further tokens.
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            Some(&token),
            Some(serde_json::json!({ "project_id": project })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Revoke via session, then the token is dead.
        let claims =
            crate::scope_tokens::verify_scope_token(&[0x11; 32], &token, crate::state::now_utc())
                .unwrap();
        let (status, _) = call(
            app.clone(),
            "DELETE",
            "/v1/scope-tokens",
            Some("session-token-alice"),
            Some(serde_json::json!({ "jti": claims.jti })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/secrets?environment={env}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        cleanup(root);
    }

    #[tokio::test]
    async fn secret_list_search_filters_and_caps_length() {
        test_env();
        let (root, state, app) = test_app("routes-search");
        let tenant = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            seed_project(
                &db,
                &tenant,
                "payments",
                "account:alice",
                ProjectRole::Admin,
            );
            tenant
        };
        let (project, env): (String, String) = {
            let db = state.connection().unwrap();
            let project: String = db
                .query_row(
                    "SELECT project_id FROM projects WHERE slug = 'payments'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let env: String = db
                .query_row(
                    "SELECT environment_id FROM environments WHERE project_id = ?1",
                    rusqlite::params![project],
                    |row| row.get(0),
                )
                .unwrap();
            (project, env)
        };
        let token = mint(&tenant, &project, Some(&env), "account:alice");
        for name in ["STRIPE_KEY", "DATABASE_URL"] {
            let (status, _) = call(
                app.clone(),
                "POST",
                &format!("/v1/projects/{project}/environments/{env}/secrets"),
                Some(&token),
                Some(serde_json::json!({ "name": name, "value": "v" })),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }
        // Substring filter returns only the match, metadata shape unchanged.
        let (status, body) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/secrets?environment={env}&q=stripe"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let names: Vec<&str> = body["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["STRIPE_KEY"]);
        assert!(body["secrets"][0].get("value").is_none());
        // Overlong queries are rejected before touching the database.
        let (status, body) = call(
            app.clone(),
            "GET",
            &format!(
                "/v1/projects/{project}/secrets?environment={env}&q={}",
                "x".repeat(129)
            ),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "INVALID_SECRET_REQUEST");
        cleanup(root);
    }

    #[tokio::test]
    async fn migration_http_lifecycle_with_denial_and_validation() {
        test_env();
        let (root, state, app) = test_app("routes-migration");
        let (tenant, project, env): (String, String, String) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(
                &db,
                &tenant,
                "payments",
                "account:alice",
                ProjectRole::Admin,
            );
            grant_project_role(
                &db,
                &fixture.project,
                "account:bob",
                ProjectRole::Developer,
                "root",
                1,
            )
            .unwrap();
            (tenant, fixture.project, fixture.env)
        };
        let admin = mint(&tenant, &project, None, "account:alice");
        let environment_token = mint(&tenant, &project, Some(&env), "account:alice");
        let dev = mint(&tenant, &project, Some(&env), "account:bob");
        let digest_hex = "07".repeat(32);

        // Non-admin sees uniform 404 (no migration oracle).
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/migrations"),
            Some(&dev),
            Some(serde_json::json!({
                "source_vault_id": "vault-1",
                "source_snapshot_hex": "ab".repeat(32),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Start + submit (one valid, one quarantined by name rules).
        let (status, body) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/migrations"),
            Some(&admin),
            Some(serde_json::json!({
                "source_vault_id": "vault-1",
                "source_snapshot_hex": "ab".repeat(32),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let mid = body["migration_id"].as_str().unwrap().to_string();
        let (status, body) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/migrations/{mid}/entries"),
            Some(&admin),
            Some(serde_json::json!({ "entries": [
                { "source_path": ".env", "source_line": 2, "name": "MIG_KEY",
                  "target_environment_id": env, "source_digest_hex": digest_hex,
                  "idempotency_key": "k1" },
                { "source_path": ".env", "source_line": 3, "name": "bad name",
                  "target_environment_id": env, "source_digest_hex": digest_hex,
                  "idempotency_key": "k2" },
            ] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["entries"][0]["state"], "VALIDATED");
        assert_eq!(body["entries"][1]["state"], "QUARANTINED");
        let ledger_id = body["entries"][0]["ledger_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Non-hex digests rejected before touching the ledger.
        let (status, body) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/migrations/{mid}/entries"),
            Some(&admin),
            Some(serde_json::json!({ "entries": [
                { "source_path": ".env", "source_line": 9, "name": "K2",
                  "target_environment_id": env, "source_digest_hex": "zz",
                  "idempotency_key": "k9" },
            ] })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "INVALID_MIGRATION_REQUEST");

        // Apply via the normal secret API, mark, verify, disable.
        let (status, created) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/environments/{env}/secrets"),
            Some(&environment_token),
            Some(serde_json::json!({ "name": "MIG_KEY", "value": "v" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let secret_id = created["secret_id"].as_str().unwrap();
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/migrations/{mid}/entries/{ledger_id}/migrated"),
            Some(&admin),
            Some(serde_json::json!({
                "secret_id": secret_id, "target_digest_hex": digest_hex,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/migrations/{mid}/verify"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["verified"], 1);
        // Quarantined k2 keeps the run out of `complete`.
        assert_eq!(body["run_state"], "verifying");
        let (status, body) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/migrations/{mid}/disable-legacy"),
            Some(&admin),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["disabled"], 1);

        // Run detail + list carry counts; shred gate reads them.
        let (status, body) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/migrations/{mid}"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["migration"]["state"], "verifying");
        assert_eq!(body["migration"]["entry_counts"]["LEGACY_PATH_DISABLED"], 1);
        let (status, body) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/migrations"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["migrations"].as_array().unwrap().len(), 1);
        cleanup(root);
    }

    #[tokio::test]
    async fn repositories_bind_list_suspend_revoke_reactivate() {
        test_env();
        let (root, state, app) = test_app("routes-repositories");
        let (tenant, project) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "shop", "account:alice", ProjectRole::Admin);
            (tenant, fixture.project)
        };
        let admin = mint(&tenant, &project, None, "account:alice");
        let bind_body = serde_json::json!({
            "provider": "github",
            "external_repo_id": "84920194",
            "repo_full_name": "acme/payments-service",
            "repo_url": "https://github.com/acme/payments-service",
            "installation_id": "install-7",
        });

        // Bind (admin only) starts suspended with challenge + webhook secret.
        let (status, created) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/repositories"),
            Some(&admin),
            Some(bind_body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let binding_id = created["binding"]["binding_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(created["binding"]["status"], "suspended");
        assert!(created["ownership_challenge"].is_string());
        assert!(created["webhook_secret"].is_string());

        // Duplicate bind conflicts.
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/repositories"),
            Some(&admin),
            Some(bind_body),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // List shows the binding.
        let (status, listed) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/repositories"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["bindings"].as_array().unwrap().len(), 1);

        // Unconfigured provider verification is explicit and never falsely accepts.
        let (status, prove) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/repositories/{binding_id}/prove"),
            Some(&admin),
            Some(serde_json::json!({
                "installation_id": "install-7",
                "installation_token": "tok",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(prove["code"], "VCS_PROVIDER_UNAVAILABLE");

        // Suspend (default mode) is idempotent; secrets kept.
        let (status, view) = call(
            app.clone(),
            "DELETE",
            &format!("/v1/projects/{project}/repositories/{binding_id}"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(view["status"], "suspended");

        // Revoke mode is terminal; reactivate returns to suspended.
        let (status, view) = call(
            app.clone(),
            "DELETE",
            &format!("/v1/projects/{project}/repositories/{binding_id}?mode=revoke"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(view["status"], "revoked");
        let (status, view) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/repositories/{binding_id}/reactivate"),
            Some(&admin),
            Some(serde_json::json!({ "reason": "restore" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["status"], "suspended");

        // Non-admin bind denies with the uniform 404.
        {
            let db = state.connection().unwrap();
            grant_project_role(
                &db,
                &project,
                "account:dev",
                ProjectRole::Developer,
                "account:alice",
                1,
            )
            .unwrap();
        }
        let dev = mint(&tenant, &project, None, "account:dev");
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/repositories"),
            Some(&dev),
            Some(serde_json::json!({
                "provider": "github",
                "external_repo_id": "84920195",
                "repo_full_name": "acme/other",
                "repo_url": "https://github.com/acme/other",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup(root);
    }

    #[tokio::test]
    async fn webhook_hmac_accepts_rejects_without_oracle() {
        test_env();
        let (root, state, app) = test_app("routes-webhook");
        let (tenant, project) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "hooks", "account:alice", ProjectRole::Admin);
            (tenant, fixture.project)
        };
        let admin = mint(&tenant, &project, None, "account:alice");
        let (_, created) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/repositories"),
            Some(&admin),
            Some(serde_json::json!({
                "provider": "github",
                "external_repo_id": "84920194",
                "repo_full_name": "acme/payments-service",
                "repo_url": "https://github.com/acme/payments-service",
            })),
        )
        .await;
        let secret = created["webhook_secret"].as_str().unwrap().to_string();

        let envelope = serde_json::json!({
            "event": "renamed",
            "external_repo_id": "84920194",
            "repo_full_name": "acme/payments-v2",
            "repo_url": "https://github.com/acme/payments-v2",
        });
        // Providers HMAC with the hex-secret bytes (what the installer pasted).
        let raw = serde_json::to_vec(&envelope).unwrap();
        let signing = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let tag = hex::encode(ring::hmac::sign(&signing, &raw));
        let header = format!("sha256={tag}");
        let (status, applied) = call_headers(
            app.clone(),
            "POST",
            "/v1/webhooks/vcs/github",
            &[("x-hub-signature-256", header.clone())],
            Some(envelope),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(applied["outcome"], "applied");
        let (status, listed) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/repositories"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["bindings"][0]["repo_full_name"], "acme/payments-v2");

        // Tampered payload with the old signature → 401.
        let tampered = serde_json::json!({
            "event": "renamed",
            "external_repo_id": "84920194",
            "repo_full_name": "acme/evil",
            "repo_url": "https://github.com/acme/evil",
        });
        let (status, _) = call_headers(
            app.clone(),
            "POST",
            "/v1/webhooks/vcs/github",
            &[("x-hub-signature-256", header)],
            Some(tampered),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Unknown repo id is indistinguishable from a bad signature (401).
        let ghost = serde_json::json!({
            "event": "renamed",
            "external_repo_id": "00000000",
            "repo_full_name": "ghost/repo",
            "repo_url": "https://github.com/ghost/repo",
        });
        let (status, _) = call_headers(
            app.clone(),
            "POST",
            "/v1/webhooks/vcs/github",
            &[("x-hub-signature-256", "sha256=00".to_string())],
            Some(ghost),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Missing signature → 401; unknown provider → 404.
        let (status, _) = call_headers(
            app.clone(),
            "POST",
            "/v1/webhooks/vcs/github",
            &[],
            Some(serde_json::json!({
                "event": "renamed",
                "external_repo_id": "84920194",
                "repo_full_name": "acme/x",
                "repo_url": "https://github.com/acme/x",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = call_headers(
            app.clone(),
            "POST",
            "/v1/webhooks/vcs/gitea",
            &[],
            Some(serde_json::json!({
                "event": "renamed",
                "external_repo_id": "84920194",
                "repo_full_name": "acme/x",
                "repo_url": "https://github.com/acme/x",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup(root);
    }

    #[tokio::test]
    async fn project_catalog_lists_and_resolves() {
        test_env();
        let (root, state, app) = test_app("routes-projects");
        let (tenant, shop, blog) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let shop = seed_project(
                &db,
                &tenant,
                "shop",
                "account:acct-alice",
                ProjectRole::Admin,
            );
            let blog = seed_project(
                &db,
                &tenant,
                "blog",
                "account:acct-alice",
                ProjectRole::Developer,
            );
            db.execute(
                "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                 VALUES('acct-alice', 'Alice', 'aa', 1)",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO sessions(token_hash_hex, account_id, session_kind, issued_at_utc,
                                      expires_at_utc)
                 VALUES(?1, 'acct-alice', 'device', ?2, 9999999999)",
                rusqlite::params![hash_token("session-token-alice"), now_utc()],
            )
            .unwrap();
            (tenant, shop.project, blog.project)
        };

        // Session lists every membership with roles.
        let (status, listed) = call(
            app.clone(),
            "GET",
            "/v1/projects",
            Some("session-token-alice"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["projects"].as_array().unwrap().len(), 2);

        // Slug resolves with environments and the caller's role.
        let (status, view) = call(
            app.clone(),
            "GET",
            "/v1/projects/shop",
            Some("session-token-alice"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["project_id"], shop);
        assert_eq!(view["role"], "admin");
        assert_eq!(view["environments"].as_array().unwrap().len(), 1);

        // Unknown refs are a uniform 404.
        let (status, _) = call(
            app.clone(),
            "GET",
            "/v1/projects/ghost",
            Some("session-token-alice"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Scope tokens stay confined to their own project.
        let token = mint(&tenant, &shop, None, "account:acct-alice");
        let (status, listed) = call(app.clone(), "GET", "/v1/projects", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["projects"].as_array().unwrap().len(), 1);
        assert_eq!(listed["projects"][0]["project_id"], shop);
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{blog}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // No credential at all is a 401.
        let (status, _) = call(app.clone(), "GET", "/v1/projects", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        cleanup(root);
    }

    /// Raw export call (the 200 body is JSONL text, not the JSON envelope
    /// the `call` helper parses).
    async fn export_raw(
        app: axum::Router,
        uri: &str,
        auth: &str,
        step_up: Option<&str>,
        dpop: Option<&str>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut builder = Request::get(uri).header("authorization", format!("Bearer {auth}"));
        if let Some(second) = step_up {
            builder = builder.header("x-step-up-authorization", format!("Bearer {second}"));
        }
        if let Some(proof) = dpop {
            builder = builder.header("dpop", proof);
        }
        let response = app
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec();
        (status, headers, body)
    }

    #[tokio::test]
    async fn audit_export_lifecycle_with_authz_and_fail_closed() {
        test_env();
        let (root, state, app) = test_app("audit-export-http");
        let (tenant, fixture) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "shop", "account:alice", ProjectRole::Admin);
            grant_project_role(
                &db,
                &fixture.project,
                "account:bob",
                ProjectRole::Developer,
                "root",
                2,
            )
            .unwrap();
            grant_project_role(
                &db,
                &fixture.project,
                "account:aud",
                ProjectRole::Auditor,
                "root",
                2,
            )
            .unwrap();
            grant_project_role(
                &db,
                &fixture.project,
                "account:dave",
                ProjectRole::Admin,
                "root",
                2,
            )
            .unwrap();
            (tenant, fixture)
        };
        let admin = mint(&tenant, &fixture.project, None, "account:alice");
        let dev = mint(&tenant, &fixture.project, Some(&fixture.env), "account:bob");
        let auditor = mint(&tenant, &fixture.project, None, "account:aud");
        let second_admin = mint(&tenant, &fixture.project, None, "account:dave");
        let uri = format!("/v1/projects/{}/audit/export", fixture.project);

        // Seed chain activity through the audited member API.
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{}/members", fixture.project),
            Some(&admin),
            Some(serde_json::json!({ "principal_id": "account:carol", "role": "operator" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Dual control: no step-up, same principal, or weak second role → 403.
        for (label, step_up) in [
            ("missing", None),
            ("same-principal", Some(admin.as_str())),
            ("developer", Some(dev.as_str())),
        ] {
            let (status, _, body) = export_raw(app.clone(), &uri, &admin, step_up, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["code"], "DUAL_CONTROL_REQUIRED", "{label}");
        }

        // Admins export JSONL with chain headers once co-signed.
        let (status, headers, body) =
            export_raw(app.clone(), &uri, &admin, Some(&second_admin), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["x-audit-events"], "1");
        assert_eq!(headers["x-audit-head"].to_str().unwrap().len(), 64);
        let text = String::from_utf8(body).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("membership.granted"));

        // Auditors may export (no values cross this surface).
        let (status, _, _) = export_raw(app.clone(), &uri, &auditor, Some(&admin), None).await;
        assert_eq!(status, StatusCode::OK);

        // Bound (cnf) tokens cannot co-sign even with a valid proof for
        // their own jti: step-up is a presence factor, key-binding applies
        // to the primary credential.
        let dave_key = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]);
        let bound = {
            let claims = ScopeClaims::new(
                &tenant,
                &fixture.project,
                "account:dave",
                1000,
                9_999_999_999,
            )
            .with_cnf(&hex::encode(dave_key.verifying_key().to_bytes()));
            mint_scope_token(&TEST_SIGNING_KEY, &claims).unwrap()
        };
        let (status, _, _) = export_raw(app.clone(), &uri, &admin, Some(&bound), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let bound_claims = verify_scope_token(&TEST_SIGNING_KEY, &bound, now_utc()).unwrap();
        let nonce = crate::util::random_hex(8);
        let proof_now = now_utc();
        let proof_message = crate::dpop::dpop_message(
            proof_now,
            nonce.as_bytes(),
            &bound_claims.jti,
            &bound_claims.tenant_id,
        );
        let proof_sig =
            ciphervault_crypto::signatures::sign_with_domain(&dave_key, b"dpop-v1", &proof_message);
        let proof = format!(
            "{}.{proof_now}.{}",
            crate::util::b64_encode(&proof_sig),
            crate::util::b64_encode(nonce.as_bytes())
        );
        let (status, _, _) =
            export_raw(app.clone(), &uri, &admin, Some(&bound), Some(&proof)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Developers get the uniform 404 (no export oracle).
        let (status, _) = call(app.clone(), "GET", &uri, Some(&dev), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Tamper fails closed: no partial ship, 500 names the event.
        {
            let db = state.connection().unwrap();
            db.execute("DROP TRIGGER secret_access_events_no_update", [])
                .unwrap();
            db.execute("UPDATE secret_access_events SET reason = 'forged'", [])
                .unwrap();
        }
        let (status, _, body) =
            export_raw(app.clone(), &uri, &admin, Some(&second_admin), None).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["code"], "AUDIT_CHAIN_BROKEN");
        cleanup(root);
    }

    #[tokio::test]
    async fn quota_prefill_drives_429_with_retry_after() {
        test_env();
        let (root, state, app) = test_app("quota-http");
        let (tenant, project, env) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "shop", "account:alice", ProjectRole::Admin);
            (tenant, fixture.project, fixture.env)
        };
        let token = mint(&tenant, &project, Some(&env), "account:alice");
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/environments/{env}/secrets"),
            Some(&token),
            Some(serde_json::json!({ "name": "K", "value": "v" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let uri = format!("/v1/projects/{project}/environments/{env}/secrets/K");

        // Exhaust the read-value bucket directly (fast, deterministic, no
        // env-var races under parallel tests); the route must then 429.
        {
            let db = state.connection().unwrap();
            for _ in 0..READ_VALUE_BUCKET.max_requests {
                let _ = check_quota(&db, &READ_VALUE_BUCKET, &tenant, "account:alice", now_utc());
            }
        }
        let request = Request::get(uri.as_str())
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key("retry-after"));
        assert_eq!(
            response.headers()["x-ratelimit-remaining"],
            "0",
            "remaining header present"
        );
        let body = json(response).await;
        assert_eq!(body["code"], "QUOTA_EXCEEDED");

        // Metadata reads ride the API bucket only: unaffected.
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("{uri}?metadata_only=true"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Exhaust the API bucket: every scoped call 429s.
        {
            let db = state.connection().unwrap();
            for _ in 0..API_BUCKET.max_requests {
                let _ = check_quota(&db, &API_BUCKET, &tenant, "account:alice", now_utc());
            }
        }
        let (status, _) = call(app.clone(), "GET", &uri, Some(&token), None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        cleanup(root);
    }

    /// Builds a fresh `DPoP` proof for `claims` (random nonce per call, so
    /// every proof is single-use distinct).
    fn dpop_proof(key: &ed25519_dalek::SigningKey, claims: &ScopeClaims) -> String {
        let nonce = crate::util::random_hex(16);
        let now = now_utc();
        let message =
            crate::dpop::dpop_message(now, nonce.as_bytes(), &claims.jti, &claims.tenant_id);
        let signature = ciphervault_crypto::signatures::sign_with_domain(key, b"dpop-v1", &message);
        format!(
            "{}.{now}.{}",
            crate::util::b64_encode(&signature),
            crate::util::b64_encode(nonce.as_bytes())
        )
    }

    #[tokio::test]
    async fn dpop_bound_token_lifecycle_over_http() {
        test_env();
        let (root, state, app) = test_app("dpop-http");
        let (tenant, project) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "shop", "account:ci", ProjectRole::Admin);
            (tenant, fixture.project)
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x66; 32]);
        let claims = ScopeClaims::new(&tenant, &project, "account:ci", 1000, 9_999_999_999)
            .with_cnf(&hex::encode(key.verifying_key().to_bytes()));
        let bound = mint_scope_token(&TEST_SIGNING_KEY, &claims).unwrap();
        // Round-trip the claims the server will see (jti is minted inside).
        let bound_claims = verify_scope_token(&TEST_SIGNING_KEY, &bound, now_utc()).unwrap();

        // No proof: 401 DPOP_REQUIRED on both loose and project paths.
        for uri in [
            "/v1/projects".to_string(),
            format!("/v1/projects/{project}"),
        ] {
            let (status, body) = call(app.clone(), "GET", &uri, Some(&bound), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(body["code"], "DPOP_REQUIRED", "{uri}");
        }

        // Fresh proof per request: 200.
        let request = Request::get("/v1/projects")
            .header("authorization", format!("Bearer {bound}"))
            .header("dpop", dpop_proof(&key, &bound_claims))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Same proof replayed: 401 DPOP_INVALID (single-use).
        let proof = dpop_proof(&key, &bound_claims);
        let request = Request::get("/v1/projects")
            .header("authorization", format!("Bearer {bound}"))
            .header("dpop", &proof)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let request = Request::get("/v1/projects")
            .header("authorization", format!("Bearer {bound}"))
            .header("dpop", &proof)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = json(response).await;
        assert_eq!(body["code"], "DPOP_INVALID");

        // Unbound tokens are unaffected by all of this.
        let plain = mint(&tenant, &project, None, "account:ci");
        let (status, _) = call(app.clone(), "GET", "/v1/projects", Some(&plain), None).await;
        assert_eq!(status, StatusCode::OK);
        cleanup(root);
    }

    #[tokio::test]
    async fn mint_bound_token_requires_proof() {
        test_env();
        let (root, state, app) = test_app("mint-bound");
        let (tenant, project) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(
                &db,
                &tenant,
                "shop",
                "account:acct-alice",
                ProjectRole::Developer,
            );
            db.execute(
                "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                 VALUES('acct-alice', 'Alice', 'aa', 1)",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO sessions(token_hash_hex, account_id, session_kind, issued_at_utc,
                                      expires_at_utc)
                 VALUES(?1, 'acct-alice', 'device', ?2, 9999999999)",
                rusqlite::params![hash_token("session-token-alice"), now_utc()],
            )
            .unwrap();
            (tenant, fixture.project)
        };
        // Invalid binding keys are a 400, not a mint.
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            Some("session-token-alice"),
            Some(serde_json::json!({
                "project_id": project,
                "bind_pubkey_ed25519_hex": "zz",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Valid binding mints a cnf-carrying token, audited as bound.
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
        let bind_hex = hex::encode(key.verifying_key().to_bytes());
        let (status, minted) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            Some("session-token-alice"),
            Some(serde_json::json!({
                "project_id": project,
                "bind_pubkey_ed25519_hex": bind_hex,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = minted["token"].as_str().unwrap().to_string();
        let claims = verify_scope_token(&TEST_SIGNING_KEY, &token, now_utc()).unwrap();
        assert_eq!(claims.cnf.as_deref(), Some(bind_hex.as_str()));
        {
            let db = state.connection().unwrap();
            let reason: String = db
                .query_row(
                    "SELECT reason FROM secret_access_events
                     WHERE tenant_id = ?1 AND event_type = 'token.minted'",
                    rusqlite::params![tenant],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(reason.contains("\"bound\":true"), "{reason}");
        }
        // Bound token without proof: 401; with proof: 200.
        let (status, body) = call(app.clone(), "GET", "/v1/projects", Some(&token), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "DPOP_REQUIRED");
        let request = Request::get("/v1/projects")
            .header("authorization", format!("Bearer {token}"))
            .header("dpop", dpop_proof(&key, &claims))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        cleanup(root);
    }

    /// Scoped-secrets load gate (T-903, ignored by default). Seeds `N`
    /// secrets, then hammers value reads with `C` concurrent workers and
    /// asserts zero failures, p99 under budget, and no SQLite busy retries
    /// (durability stays FULL; contention is a failure, not a tuning knob).
    ///
    /// Knobs: `CIPHERVAULT_LOAD_SECRETS` (50), `CIPHERVAULT_LOAD_READS`
    /// (200), `CIPHERVAULT_LOAD_CONCURRENCY` (8), `CIPHERVAULT_LOAD_P99_MS`
    /// (250). Knobs must respect quotas (read-value 300/60s, api
    /// 1000/60s): a 429 fails the gate by design (harness-sizing failure,
    /// like the push_bench limiter lesson in LOAD_SOAK_VALIDATION.md).
    ///
    /// ```powershell
    /// cargo test -p ciphervault-account --release --lib -- --ignored --nocapture scoped_load_gate
    /// ```
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore]
    async fn scoped_load_gate() {
        fn knob(name: &str, fallback: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|raw| raw.parse().ok())
                .unwrap_or(fallback)
                .max(1)
        }
        test_env();
        let (root, state, app) = test_app("load-gate");
        let (tenant, project, env) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "shop", "account:loader", ProjectRole::Admin);
            (tenant, fixture.project, fixture.env)
        };
        let token = mint(&tenant, &project, Some(&env), "account:loader");
        let secrets = knob("CIPHERVAULT_LOAD_SECRETS", 50);
        let reads = knob("CIPHERVAULT_LOAD_READS", 200);
        let concurrency = knob("CIPHERVAULT_LOAD_CONCURRENCY", 8).min(32);
        let p99_budget_ms = knob("CIPHERVAULT_LOAD_P99_MS", 250) as u128;
        let mut names = Vec::with_capacity(secrets);
        for index in 0..secrets {
            let name = format!("LOAD_{index:05}");
            let (status, _) = call(
                app.clone(),
                "POST",
                &format!("/v1/projects/{project}/environments/{env}/secrets"),
                Some(&token),
                Some(serde_json::json!({ "name": name, "value": "synthetic-load-value" })),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "seed {name}");
            names.push(name);
        }
        let names = std::sync::Arc::new(names);
        let per_worker = reads.div_ceil(concurrency);
        let busy_before = crate::state::sqlite_busy_retries();
        let started = std::time::Instant::now();
        let mut tasks = Vec::with_capacity(concurrency);
        for worker in 0..concurrency {
            let app = app.clone();
            let token = token.clone();
            let names = names.clone();
            let project = project.clone();
            let env = env.clone();
            tasks.push(tokio::spawn(async move {
                let mut latencies = Vec::with_capacity(per_worker);
                let mut failures = 0usize;
                for round in 0..per_worker {
                    // Deterministic stride spreads reads across secrets.
                    let name = &names[(worker + round * concurrency) % names.len()];
                    let uri = format!("/v1/projects/{project}/environments/{env}/secrets/{name}");
                    let begin = std::time::Instant::now();
                    let request = Request::get(uri.as_str())
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap();
                    match app.clone().oneshot(request).await {
                        Ok(response) if response.status() == StatusCode::OK => {}
                        _ => failures += 1,
                    }
                    latencies.push(begin.elapsed());
                }
                (latencies, failures)
            }));
        }
        let mut latencies = Vec::with_capacity(per_worker * concurrency);
        let mut failures = 0usize;
        for task in tasks {
            let (mut worker_latencies, worker_failures) = task.await.unwrap();
            failures += worker_failures;
            latencies.append(&mut worker_latencies);
        }
        let wall = started.elapsed();
        latencies.sort_unstable();
        let percentile = |pct: usize| -> u128 {
            latencies[((latencies.len() * pct).saturating_sub(1) / 100).min(latencies.len() - 1)]
                .as_millis()
        };
        let (p50, p99) = (percentile(50), percentile(99));
        let busy_delta = crate::state::sqlite_busy_retries().saturating_sub(busy_before);
        println!(
            "load: {} reads across {} secrets ({} workers) in {:?} ({:.0} reads/s); \
             p50={p50}ms p99={p99}ms failures={failures} sqlite_busy_retries={busy_delta}",
            latencies.len(),
            names.len(),
            concurrency,
            wall,
            latencies.len() as f64 / wall.as_secs_f64().max(0.001),
        );
        assert_eq!(failures, 0, "every paced read must succeed");
        assert!(
            p99 <= p99_budget_ms,
            "p99 {p99}ms exceeds budget {p99_budget_ms}ms"
        );
        assert_eq!(busy_delta, 0, "no SQLite busy retries under paced load");
        cleanup(root);
    }

    #[tokio::test]
    async fn grant_invite_http_lifecycle() {
        test_env();
        let (root, state, app) = test_app("grant-invite-http");
        let (tenant, project) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "shop", "account:alice", ProjectRole::Admin);
            grant_project_role(
                &db,
                &fixture.project,
                "account:dave",
                ProjectRole::Admin,
                "root",
                2,
            )
            .unwrap();
            grant_project_role(
                &db,
                &fixture.project,
                "account:bob",
                ProjectRole::Developer,
                "root",
                2,
            )
            .unwrap();
            db.execute(
                "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                 VALUES('erin', 'Erin', 'ee', 1)",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO sessions(token_hash_hex, account_id, session_kind, issued_at_utc,
                                      expires_at_utc)
                 VALUES(?1, 'erin', 'device', ?2, 9999999999)",
                rusqlite::params![hash_token("session-token-erin"), now_utc()],
            )
            .unwrap();
            (tenant, fixture.project)
        };
        let alice = mint(&tenant, &project, None, "account:alice");
        let dave = mint(&tenant, &project, None, "account:dave");
        let dev = mint(&tenant, &project, None, "account:bob");

        // Admin grants divert into requests (202), not direct grants.
        let (status, opened) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/members"),
            Some(&alice),
            Some(serde_json::json!({ "principal_id": "account:carol", "role": "admin" })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let request_id = opened["request_id"].as_str().unwrap().to_string();
        assert_eq!(opened["state"], "pending");
        // Developer attempts read as uniform 404 (no request oracle).
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/members"),
            Some(&dev),
            Some(serde_json::json!({ "principal_id": "account:mallory", "role": "admin" })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, listed) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/members/requests"),
            Some(&alice),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["requests"].as_array().unwrap().len(), 1);

        // Self-approval is a 403; a distinct admin applies the grant.
        let decision_uri = format!("/v1/projects/{project}/members/requests/{request_id}/decision");
        let (status, body) = call(
            app.clone(),
            "POST",
            &decision_uri,
            Some(&alice),
            Some(serde_json::json!({ "approve": true })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "SELF_APPROVAL_DENIED");
        let (status, decided) = call(
            app.clone(),
            "POST",
            &decision_uri,
            Some(&dave),
            Some(serde_json::json!({ "approve": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decided["state"], "approved");
        // Carol is admin now: her token lists requests.
        let carol = mint(&tenant, &project, None, "account:carol");
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/members/requests"),
            Some(&carol),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Invites: admin role rejected, code shown once, list omits codes.
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/invites"),
            Some(&alice),
            Some(serde_json::json!({ "role": "admin" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, created) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/invites"),
            Some(&alice),
            Some(serde_json::json!({ "role": "developer" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let code = created["code"].as_str().unwrap().to_string();
        let (status, listed) = call(
            app.clone(),
            "GET",
            &format!("/v1/projects/{project}/invites"),
            Some(&alice),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let invites = listed["invites"].as_array().unwrap();
        assert_eq!(invites.len(), 1);
        assert!(invites[0].get("code").is_none());
        assert!(invites[0].get("code_hash_hex").is_none());

        // Erin accepts over her session; replay reads as 404.
        let (status, accepted) = call(
            app.clone(),
            "POST",
            "/v1/invites/accept",
            Some("session-token-erin"),
            Some(serde_json::json!({ "code": code })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(accepted["principal_id"], "account:erin");
        assert_eq!(accepted["role"], "developer");
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v1/invites/accept",
            Some("session-token-erin"),
            Some(serde_json::json!({ "code": code })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Revoke-then-accept reads as 404; developers cannot manage invites.
        let (status, second) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/invites"),
            Some(&alice),
            Some(serde_json::json!({ "role": "operator" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let second_id = second["invite_id"].as_str().unwrap().to_string();
        let (status, _) = call(
            app.clone(),
            "DELETE",
            &format!("/v1/projects/{project}/invites/{second_id}"),
            Some(&alice),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v1/invites/accept",
            Some("session-token-erin"),
            Some(serde_json::json!({ "code": second["code"].as_str().unwrap() })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/projects/{project}/invites"),
            Some(&dev),
            Some(serde_json::json!({ "role": "developer" })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup(root);
    }
    fn seed_human_session(db: &rusqlite::Connection, method: &str, issued_at: u64) {
        db.execute(
            "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
            VALUES('acct-alice', 'Alice', 'aa', 1) ON CONFLICT DO NOTHING",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO sessions(token_hash_hex, account_id, session_kind, issued_at_utc, expires_at_utc)
            VALUES(?1, 'acct-alice', ?2, ?3, ?4)",
            rusqlite::params![hash_token(method), method, issued_at, now_utc() + 1800]).unwrap();
    }

    #[tokio::test]
    async fn token_issuance_rejects_recovery_stale_totp_and_self_declared_branch() {
        test_env();
        let (root, state, app) = test_app("mint-strength");
        let fixture = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(
                &db,
                &tenant,
                "scope",
                "account:acct-alice",
                ProjectRole::Admin,
            );
            for method in ["recovery", "totp", "device", "webauthn"] {
                seed_human_session(&db, method, now_utc());
            }
            fixture
        };
        for method in ["recovery", "totp"] {
            let (status, _) = call(
                app.clone(),
                "POST",
                "/v1/scope-tokens",
                Some(method),
                Some(serde_json::json!({"project_id": fixture.project})),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method}");
        }
        let (status, error) = call(app.clone(), "POST", "/v1/scope-tokens", Some("device"),
            Some(serde_json::json!({"project_id": fixture.project, "environment_id": fixture.env, "branch": "main"}))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error["code"], "WORKLOAD_ATTESTATION_UNAVAILABLE");
        {
            let db = state.connection().unwrap();
            db.execute(
                "UPDATE sessions SET issued_at_utc = ?1 WHERE token_hash_hex = ?2",
                rusqlite::params![
                    now_utc() - STEP_UP_MAX_AGE_SECONDS - 1,
                    hash_token("device")
                ],
            )
            .unwrap();
        }
        let (status, body) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            Some("device"),
            Some(serde_json::json!({"project_id": fixture.project})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "AUTHENTICATION_STEP_UP_REQUIRED");
        cleanup(root);
    }

    #[tokio::test]
    async fn recent_human_elevation_works_and_source_revocation_invalidates_token() {
        test_env();
        let (root, state, app) = test_app("mint-human-production");
        let fixture = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(
                &db,
                &tenant,
                "prod",
                "account:acct-alice",
                ProjectRole::Admin,
            );
            db.execute(
                "UPDATE environments SET tier = 2 WHERE environment_id = ?1",
                [&fixture.env],
            )
            .unwrap();
            seed_human_session(&db, "device", now_utc());
            seed_human_session(&db, "webauthn", now_utc());
            fixture
        };
        for method in ["device", "webauthn"] {
            let body =
                serde_json::json!({"project_id": fixture.project, "environment_id": fixture.env});
            let (status, response) = call(
                app.clone(),
                "POST",
                "/v1/scope-tokens",
                Some(method),
                Some(body.clone()),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(response["code"], "PRODUCTION_ELEVATION_REQUIRED");
            let mut body = body;
            body["elevated"] = true.into();
            let (status, minted) = call(
                app.clone(),
                "POST",
                "/v1/scope-tokens",
                Some(method),
                Some(body),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let token = minted["token"].as_str().unwrap();
            let claims = verify_scope_token(&TEST_SIGNING_KEY, token, now_utc()).unwrap();
            assert_eq!(claims.origin_session_hash, Some(hash_token(method)));
            assert!(claims.branch.is_none());
            assert!(claims.elevated_until_utc.unwrap() <= now_utc() + STEP_UP_MAX_AGE_SECONDS);
            let uri = format!(
                "/v1/projects/{}/environments/{}/secrets",
                fixture.project, fixture.env
            );
            let (status, _) = call(app.clone(), "POST", &uri, Some(token),
                Some(serde_json::json!({"name": format!("KEY_{}", method.to_uppercase()), "value": "synthetic"}))).await;
            assert_eq!(status, StatusCode::CREATED);
            let (status, _) = call(
                app.clone(),
                "POST",
                "/v1/sessions/revoke",
                Some(method),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (status, _) = call(
                app.clone(),
                "GET",
                &format!(
                    "/v1/projects/{}/secrets?environment={}",
                    fixture.project, fixture.env
                ),
                Some(token),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        cleanup(root);
    }

    #[tokio::test]
    async fn narrowed_admin_tokens_fail_all_project_administration_routes() {
        test_env();
        let (root, state, app) = test_app("narrow-admin-routes");
        let (tenant, fixture) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "admin", "account:alice", ProjectRole::Admin);
            (tenant, fixture)
        };
        let broad = ScopeClaims::new(
            &tenant,
            &fixture.project,
            "account:alice",
            now_utc(),
            now_utc() + 300,
        );
        for claims in [
            broad.clone().with_environment(&fixture.env),
            broad.clone().with_repository_binding("binding"),
            broad.clone().with_service("service"),
        ] {
            let token = mint_scope_token(&TEST_SIGNING_KEY, &claims).unwrap();
            let pid = &fixture.project;
            let cases = [
                (
                    "POST",
                    format!("/v1/projects/{pid}/members"),
                    Some(serde_json::json!({"principal_id":"account:new", "role":"developer"})),
                ),
                (
                    "DELETE",
                    format!("/v1/projects/{pid}/members?principal_id=account:alice"),
                    None,
                ),
                ("GET", format!("/v1/projects/{pid}/members/requests"), None),
                (
                    "POST",
                    format!("/v1/projects/{pid}/members/requests/unknown/decision"),
                    Some(serde_json::json!({"approve":true})),
                ),
                (
                    "POST",
                    format!("/v1/projects/{pid}/invites"),
                    Some(serde_json::json!({"role":"developer"})),
                ),
                ("GET", format!("/v1/projects/{pid}/invites"), None),
                (
                    "DELETE",
                    format!("/v1/projects/{pid}/invites/unknown"),
                    None,
                ),
                ("GET", format!("/v1/projects/{pid}/repositories"), None),
                (
                    "POST",
                    format!("/v1/projects/{pid}/repositories"),
                    Some(
                        serde_json::json!({"provider":"github", "external_repo_id":"7", "repo_full_name":"org/repo", "repo_url":"https://github.com/org/repo", "installation_id":"1"}),
                    ),
                ),
                ("GET", format!("/v1/projects/{pid}/migrations"), None),
                (
                    "POST",
                    format!("/v1/projects/{pid}/migrations"),
                    Some(
                        serde_json::json!({"source_vault_id":"v1", "source_snapshot_hex":"ab".repeat(32)}),
                    ),
                ),
            ];
            for (method, uri, body) in cases {
                let (status, _) = call(app.clone(), method, &uri, Some(&token), body).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
            }
        }
        let db = state.connection().unwrap();
        assert_eq!(
            project_role_of(&db, &fixture.project, "account:alice").unwrap(),
            Some(ProjectRole::Admin)
        );
        assert!(project_role_of(&db, &fixture.project, "account:new")
            .unwrap()
            .is_none());
        cleanup(root);
    }

    #[tokio::test]
    async fn challenge_issuance_is_bounded_without_failed_authentication() {
        test_env();
        let (root, state, app) = test_app("challenge-quota");
        let account = format!("cvacct_{}", "a1".repeat(16));
        {
            let db = state.connection().unwrap();
            db.execute("INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                VALUES(?1, 'Test', ?2, 1)", rusqlite::params![account, "a1".repeat(32)]).unwrap();
        }
        for _ in 0..30 {
            let (status, _) = call(
                app.clone(),
                "POST",
                "/v1/sessions/challenge",
                None,
                Some(serde_json::json!({"account_id":account})),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        // Switching to enrollment cannot reset the shared account budget.
        let (status, response) = call(app.clone(), "POST", &format!("/v1/accounts/{account}/devices/challenge"), None,
            Some(serde_json::json!({"device_id_hex":"22".repeat(32), "public_key_hex":"33".repeat(32)}))).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response["code"], "QUOTA_EXCEEDED");
        let db = state.connection().unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM challenges", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 30);
        cleanup(root);
    }

    #[tokio::test]
    async fn handoff_preserves_authentication_age_and_expiry() {
        test_env();
        let (root, state, app) = test_app("handoff-step-up");
        let fixture = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(
                &db,
                &tenant,
                "handoff",
                "account:acct-alice",
                ProjectRole::Admin,
            );
            seed_human_session(&db, "device", now_utc() - STEP_UP_MAX_AGE_SECONDS - 60);
            fixture
        };
        let (status, handoff) = call(
            app.clone(),
            "POST",
            "/v1/sessions/handoff",
            Some("device"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, consumed) = call(
            app.clone(),
            "POST",
            "/v1/sessions/handoff/consume",
            None,
            Some(serde_json::json!({"handoff_code":handoff["handoff_code"]})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            consumed["session"]["issued_at_utc"].as_u64().unwrap()
                < now_utc() - STEP_UP_MAX_AGE_SECONDS
        );
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            consumed["token"].as_str(),
            Some(serde_json::json!({"project_id":fixture.project})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        cleanup(root);
    }
    #[tokio::test]
    async fn legacy_self_declared_main_token_does_not_unlock_production() {
        test_env();
        let (root, state, app) = test_app("legacy-main-denied");
        let (tenant, fixture) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "prod", "account:alice", ProjectRole::Admin);
            db.execute(
                "UPDATE environments SET tier = 2 WHERE environment_id = ?1",
                [&fixture.env],
            )
            .unwrap();
            (tenant, fixture)
        };
        let mut claims = ScopeClaims::new(
            &tenant,
            &fixture.project,
            "account:alice",
            now_utc(),
            now_utc() + 600,
        )
        .with_environment(&fixture.env);
        claims.branch = Some("main".into());
        let token = mint_scope_token(&TEST_SIGNING_KEY, &claims).unwrap();
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!(
                "/v1/projects/{}/secrets?environment={}",
                fixture.project, fixture.env
            ),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup(root);
    }

    #[tokio::test]
    async fn source_device_revocation_invalidates_issued_scope_credential() {
        test_env();
        let (root, state, app) = test_app("source-device-revoke");
        let fixture = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(
                &db,
                &tenant,
                "scope",
                "account:acct-alice",
                ProjectRole::Admin,
            );
            seed_human_session(&db, "device", now_utc());
            db.execute("INSERT INTO devices(account_id, device_id_hex, public_key_hex, label, enrolled_at_utc)
                VALUES('acct-alice', 'test-device', 'pubkey', 'Test', 1)", []).unwrap();
            db.execute(
                "UPDATE sessions SET device_id_hex = 'test-device' WHERE token_hash_hex = ?1",
                [hash_token("device")],
            )
            .unwrap();
            fixture
        };
        let (status, minted) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            Some("device"),
            Some(serde_json::json!({"project_id":fixture.project,"environment_id":fixture.env})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        {
            let db = state.connection().unwrap();
            db.execute("UPDATE devices SET revoked_at_utc = ?1", [now_utc()])
                .unwrap();
        }
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!(
                "/v1/projects/{}/secrets?environment={}",
                fixture.project, fixture.env
            ),
            minted["token"].as_str(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        cleanup(root);
    }

    #[tokio::test]
    async fn batch_route_accepts_listing_revision_and_exposes_manual_rotation_status() {
        test_env();
        let (root, state, app) = test_app("batch-http");
        let (tenant, fixture) = {
            let db = state.connection().unwrap();
            let tenant = seed_org(&db);
            let fixture = seed_project(&db, &tenant, "batch", "account:alice", ProjectRole::Admin);
            (tenant, fixture)
        };
        let token = mint(
            &tenant,
            &fixture.project,
            Some(&fixture.env),
            "account:alice",
        );
        let (status, secret) = call(
            app.clone(),
            "POST",
            &format!(
                "/v1/projects/{}/environments/{}/secrets",
                fixture.project, fixture.env
            ),
            Some(&token),
            Some(serde_json::json!({"name":"KEY", "value":"synthetic"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, list) = call(
            app.clone(),
            "GET",
            &format!(
                "/v1/projects/{}/secrets?environment={}",
                fixture.project, fixture.env
            ),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let uri = format!(
            "/v1/projects/{}/environments/{}/materialize",
            fixture.project, fixture.env
        );
        let (status, batch) = call(
            app.clone(),
            "POST",
            &uri,
            Some(&token),
            Some(serde_json::json!({"names":["KEY"],"expected_revision":list["revision"]})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(batch["revision"], list["revision"]);
        assert_eq!(batch["values"][0]["value"], "synthetic");
        let rotate_uri = format!(
            "/v1/projects/{}/secrets/{}/rotate",
            fixture.project,
            secret["secret_id"].as_str().unwrap()
        );
        let (status, unavailable) = call(app.clone(), "POST", &rotate_uri, Some(&token),
            Some(serde_json::json!({"new_value":"new", "reason":"provider check", "idempotency_key":"provider", "verify_provider":true}))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable["code"], "PROVIDER_VERIFICATION_UNAVAILABLE");
        let (status, outcome) = call(app.clone(), "POST", &rotate_uri, Some(&token),
            Some(serde_json::json!({"new_value":"new", "reason":"manual", "idempotency_key":"manual"}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome["provider_verified"], false);
        let (status, stale) = call(
            app.clone(),
            "POST",
            &uri,
            Some(&token),
            Some(serde_json::json!({"names":["KEY"],"expected_revision":list["revision"]})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(stale["code"], "SCOPE_REVISION_CHANGED");
        cleanup(root);
    }
    #[tokio::test]
    async fn recovery_enrollment_device_proof_login_then_scoped_issuance() {
        use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
        test_env();
        let (root, state, app) = test_app("recovery-device-login-mint");
        let lost_root = generate_signing_key();
        let (status, account) = call(app.clone(), "POST", "/v1/accounts", None,
            Some(serde_json::json!({"display_name":"Recovering", "account_public_key_hex":hex::encode(lost_root.verifying_key().as_bytes())}))).await;
        assert_eq!(status, StatusCode::CREATED);
        let account_id = account["account_id"].as_str().unwrap();
        let code = format!("cvrc_{}", "55".repeat(16));
        let fixture = {
            let db = state.connection().unwrap();
            db.execute("INSERT INTO recovery_codes(account_id, code_hash_hex, created_at_utc) VALUES(?1, ?2, ?3)",
                rusqlite::params![account_id, hash_token(&code), now_utc()]).unwrap();
            let tenant = seed_org(&db);
            seed_project(
                &db,
                &tenant,
                "recovered",
                &format!("account:{account_id}"),
                ProjectRole::Admin,
            )
        };
        let (status, recovery) = call(
            app.clone(),
            "POST",
            "/v1/recovery/redeem",
            None,
            Some(serde_json::json!({"account_id":account_id,"code":code})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let recovery_token = recovery["token"].as_str().unwrap();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            Some(recovery_token),
            Some(serde_json::json!({"project_id":fixture.project, "environment_id":fixture.env})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let new_device = generate_signing_key();
        let device_id = "66".repeat(32);
        let public_key = hex::encode(new_device.verifying_key().as_bytes());
        let (status, challenge) = call(
            app.clone(),
            "POST",
            &format!("/v1/accounts/{account_id}/devices/challenge"),
            None,
            Some(serde_json::json!({"device_id_hex":device_id,"public_key_hex":public_key})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let proof = sign_with_domain(
            &new_device,
            b"account_device_enrollment",
            &crate::util::challenge_signing_bytes(
                account_id,
                Some(&device_id),
                Some(&public_key),
                challenge["challenge_id"].as_str().unwrap(),
                challenge["nonce_hex"].as_str().unwrap(),
            ),
        );
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/accounts/{account_id}/devices"),
            Some(recovery_token),
            Some(
                serde_json::json!({"device_id_hex":device_id,"public_key_hex":public_key,
                "challenge_id":challenge["challenge_id"],"proof_signature_hex":hex::encode(proof)}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        // Recovery remains restricted. A separate device-key proof establishes
        // fresh signing-key authentication, without needing the account root.
        let (status, challenge) = call(
            app.clone(),
            "POST",
            "/v1/sessions/challenge",
            None,
            Some(serde_json::json!({"account_id":account_id,"device_id_hex":device_id})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let proof = sign_with_domain(
            &new_device,
            b"account_login",
            &crate::util::challenge_signing_bytes(
                account_id,
                Some(&device_id),
                None,
                challenge["challenge_id"].as_str().unwrap(),
                challenge["nonce_hex"].as_str().unwrap(),
            ),
        );
        let (status, login) = call(app.clone(), "POST", "/v1/sessions", None,
            Some(serde_json::json!({"challenge_id":challenge["challenge_id"],"signature_hex":hex::encode(proof)}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(login["session"]["auth_method"], "device");
        assert_eq!(login["session"]["device_id_hex"], device_id);
        let (status, issued) = call(
            app.clone(),
            "POST",
            "/v1/scope-tokens",
            login["token"].as_str(),
            Some(serde_json::json!({"project_id":fixture.project, "environment_id":fixture.env})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(app.clone(), "POST", "/v1/sessions", None,
            Some(serde_json::json!({"challenge_id":challenge["challenge_id"],"signature_hex":hex::encode(proof)}))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Changing the enrolled key under the same identity invalidates all
        // credentials whose proof was established under its previous key.
        let replacement = generate_signing_key();
        let replacement_public = hex::encode(replacement.verifying_key().as_bytes());
        let (status, challenge) = call(
            app.clone(),
            "POST",
            &format!("/v1/accounts/{account_id}/devices/challenge"),
            None,
            Some(
                serde_json::json!({"device_id_hex":device_id,"public_key_hex":replacement_public}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let proof = sign_with_domain(
            &lost_root,
            b"account_device_enrollment",
            &crate::util::challenge_signing_bytes(
                account_id,
                Some(&device_id),
                Some(&replacement_public),
                challenge["challenge_id"].as_str().unwrap(),
                challenge["nonce_hex"].as_str().unwrap(),
            ),
        );
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/v1/accounts/{account_id}/devices"),
            None,
            Some(
                serde_json::json!({"device_id_hex":device_id,"public_key_hex":replacement_public,
                "challenge_id":challenge["challenge_id"],"proof_signature_hex":hex::encode(proof)}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = call(
            app.clone(),
            "GET",
            &format!(
                "/v1/projects/{}/secrets?environment={}",
                fixture.project, fixture.env
            ),
            issued["token"].as_str(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        cleanup(root);
    }

    #[tokio::test]
    async fn weak_or_stale_sessions_cannot_change_recovery_or_credentials() {
        test_env();
        let (root, state, app) = test_app("account-security-step-up");
        let account_id = format!("cvacct_{}", "77".repeat(16));
        {
            let db = state.connection().unwrap();
            db.execute("INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                VALUES(?1, 'Test', ?2, 1)", rusqlite::params![account_id, "88".repeat(32)]).unwrap();
            for (token, method, age) in [
                ("weak", "totp", 0),
                ("stale", "device", STEP_UP_MAX_AGE_SECONDS + 60),
                ("recovery", "recovery", 0),
            ] {
                db.execute("INSERT INTO sessions(token_hash_hex, account_id, session_kind, issued_at_utc, expires_at_utc)
                    VALUES(?1, ?2, ?3, ?4, ?5)", rusqlite::params![hash_token(token), account_id, method, now_utc() - age, now_utc() + 900]).unwrap();
            }
        }
        for token in ["weak", "stale", "recovery"] {
            let cases = [
                (
                    format!("/v1/accounts/{account_id}/recovery/codes"),
                    Some(serde_json::json!({"count":4})),
                ),
                (
                    format!(
                        "/v1/accounts/{account_id}/devices/{}/revoke",
                        "99".repeat(32)
                    ),
                    None,
                ),
                (
                    format!("/v1/accounts/{account_id}/webauthn/credentials/aa/revoke"),
                    None,
                ),
                (
                    format!("/v1/accounts/{account_id}/webauthn/registration/options"),
                    None,
                ),
                (format!("/v1/accounts/{account_id}/totp/enrollment"), None),
            ];
            for (uri, body) in cases {
                let (status, _) = call(app.clone(), "POST", &uri, Some(token), body).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{token}: {uri}");
            }
        }
        cleanup(root);
    }
}
