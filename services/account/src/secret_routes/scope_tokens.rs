//! Scope token mint/revoke routes.

use super::common::*;

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
    claims.mfa_proof_id = session.mfa_proof_id.clone();
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
    if session.mfa_required {
        let until = session
            .issued_at_utc
            .saturating_add(STEP_UP_MAX_AGE_SECONDS)
            .min(
                session
                    .mfa_verified_at_utc
                    .unwrap_or(0)
                    .saturating_add(STEP_UP_MAX_AGE_SECONDS),
            );
        claims.expires_at_utc = claims.expires_at_utc.min(until);
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
