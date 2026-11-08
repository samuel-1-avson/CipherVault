//! Scoped secret CRUD, move/rebind/rotate routes.

use super::auth::*;
use super::common::*;

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
