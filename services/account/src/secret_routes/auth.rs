//! Token/session authentication and KEK wrapping.

use super::common::*;

const LOCAL_KEK_ENV: &str = "CIPHERVAULT_ACCOUNT_LOCAL_KEK";
const LOCAL_KEK_FILE_ENV: &str = "CIPHERVAULT_ACCOUNT_LOCAL_KEK_FILE";

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
pub(crate) fn verify_token_claims(
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
    claims.mfa_proof_id = session.mfa_proof_id.clone();
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
pub(crate) struct LooseAuth {
    pub(crate) principal_id: String,
    pub(crate) project_id: Option<String>,
    pub(crate) tenant_id: Option<String>,
    pub(crate) environment_id: Option<String>,
}

pub(crate) fn authenticate_loose(
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
