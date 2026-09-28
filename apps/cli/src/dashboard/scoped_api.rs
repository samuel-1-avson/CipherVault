//! Scoped explorer APIs for the private dashboard (Phase 7, T-703).
//!
//! Authenticated, scope-filtered project/secret reads that replace disk-walk
//! discovery for the scoped inventory. All handlers run behind the private
//! loopback guard and use the dashboard operator's own credential
//! (`CIPHERVAULT_SCOPE_TOKEN` in the server process env), so the browser
//! never handles scope tokens. Upstream is the operator's account service
//! (`CIPHERVAULT_ACCOUNT_ENDPOINT`, env-only — never the legacy hosted
//! default, which serves a different API).
//!
//! The legacy `/api/workspaces` disk walk stays for snapshot-vault
//! management until migration cutover (T-801); new scoped UI reads these
//! routes instead.

use axum::response::IntoResponse;

use crate::commands::dpop::maybe_dpop;
use crate::commands::scope::{http_client, resolve_scope};
use crate::dashboard::account_proxy::account_proxy_http_client;

/// Project/environment refs arrive caller-controlled and are embedded in an
/// upstream path, so they are normalized before use (mirrors the
/// `normalize_proxied_account_id` guard): 1–128 chars, alphanumeric first,
/// `[A-Za-z0-9._-]` after. Slugs, UUIDs, and opaque IDs pass; `/`, `%`,
/// whitespace, and leading `.`/`-` (including `..`) never reach upstream.
pub(crate) fn normalize_proxied_scope_ref(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return None,
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return None;
    }
    Some(value.to_string())
}

fn invalid_scope_ref_response() -> axum::response::Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": "INVALID_SCOPE_REF",
            "error": "project/environment refs must be 1-128 chars of [A-Za-z0-9._-] starting alphanumeric",
        })),
    )
        .into_response()
}

/// Env-only account endpoint for scoped upstream calls. Unlike the hosted
/// proxy default this never falls back to a hosted URL or the account
/// store: scoped paths exist only on the operator's account service.
pub(crate) fn scoped_account_endpoint() -> Option<String> {
    let raw = std::env::var("CIPHERVAULT_ACCOUNT_ENDPOINT").ok()?;
    let endpoint = raw.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return None;
    }
    let parsed = reqwest::Url::parse(endpoint).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(endpoint.to_string())
}

fn scoped_token() -> Option<String> {
    std::env::var("CIPHERVAULT_SCOPE_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn not_configured_response() -> axum::response::Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": "ACCOUNT_SERVICE_NOT_CONFIGURED",
            "error": "Set CIPHERVAULT_ACCOUNT_ENDPOINT to the operator account service for scoped explorer routes.",
        })),
    )
        .into_response()
}

fn dpop_key_invalid_response(error: anyhow::Error) -> axum::response::Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": "DPOP_KEY_INVALID",
            "error": error.to_string(),
        })),
    )
        .into_response()
}

fn missing_token_response() -> axum::response::Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": "SCOPED_TOKEN_MISSING",
            "error": "Set CIPHERVAULT_SCOPE_TOKEN in the dashboard server environment.",
        })),
    )
        .into_response()
}

/// Transparent upstream GET: forwards status + body, marks `no-store`.
async fn forward_scoped_get(endpoint: &str, token: &str, path: &str) -> axum::response::Response {
    let client = account_proxy_http_client();
    let builder = match maybe_dpop(client.get(format!("{endpoint}{path}")), token) {
        Ok(builder) => builder,
        // Fail closed: a set-but-bad DPoP key must never send unproven.
        Err(error) => return dpop_key_invalid_response(error),
    };
    let response = match builder.bearer_auth(token).send().await {
        Ok(response) => response,
        Err(error) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "code": "ACCOUNT_SERVICE_UNAVAILABLE",
                    "error": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let status = axum::http::StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let payload = response.bytes().await.unwrap_or_default();
    let mut proxied = (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        payload,
    )
        .into_response();
    proxied.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    proxied
}

/// Operator scope banner data: resolves `CIPHERVAULT_PROJECT` /
/// `CIPHERVAULT_ENV` (full precedence via the shared resolver) against the
/// account service. Always 200 — the UI renders `unconfigured` and
/// `unresolved` as banner states, not page failures.
pub(crate) async fn api_scoped_context_handler() -> axum::response::Response {
    let Some(endpoint) = scoped_account_endpoint() else {
        return axum::Json(serde_json::json!({
            "status": "unconfigured",
            "hint": "Set CIPHERVAULT_ACCOUNT_ENDPOINT for scoped explorer routes.",
        }))
        .into_response();
    };
    let Some(token) = scoped_token() else {
        return axum::Json(serde_json::json!({
            "status": "unconfigured",
            "hint": "Set CIPHERVAULT_SCOPE_TOKEN in the dashboard server environment.",
        }))
        .into_response();
    };
    let client = match http_client() {
        Ok(client) => client,
        Err(error) => {
            return axum::Json(serde_json::json!({
                "status": "unresolved",
                "error": error.to_string(),
            }))
            .into_response();
        }
    };
    match resolve_scope(&client, &endpoint, &token, None, None, false).await {
        Ok(scope) => axum::Json(serde_json::json!({
            "status": "ok",
            "project_id": scope.project_id,
            "project_slug": scope.project_slug,
            "project_source": scope.project_source.as_str(),
            "environment_id": scope.env_id,
            "environment_slug": scope.env_slug,
            "environment_source": scope.env_source.map(|source| source.as_str()),
        }))
        .into_response(),
        Err(error) => axum::Json(serde_json::json!({
            "status": "unresolved",
            "error": format!("{error:#}"),
        }))
        .into_response(),
    }
}

/// Proxy: operator project catalog (`GET /v1/projects`).
pub(crate) async fn api_scoped_projects_handler() -> axum::response::Response {
    let Some(endpoint) = scoped_account_endpoint() else {
        return not_configured_response();
    };
    let Some(token) = scoped_token() else {
        return missing_token_response();
    };
    forward_scoped_get(&endpoint, &token, "/v1/projects").await
}

/// Proxy: one project with environments (`GET /v1/projects/:ref`, slug or ID).
pub(crate) async fn api_scoped_project_handler(
    axum::extract::Path(project_ref): axum::extract::Path<String>,
) -> axum::response::Response {
    let Some(project_ref) = normalize_proxied_scope_ref(&project_ref) else {
        return invalid_scope_ref_response();
    };
    let Some(endpoint) = scoped_account_endpoint() else {
        return not_configured_response();
    };
    let Some(token) = scoped_token() else {
        return missing_token_response();
    };
    forward_scoped_get(&endpoint, &token, &format!("/v1/projects/{project_ref}")).await
}

#[derive(serde::Deserialize)]
pub(crate) struct ScopedSecretsQuery {
    project: Option<String>,
    environment: Option<String>,
    q: Option<String>,
    limit: Option<String>,
}

/// Proxy: secret metadata search (`GET /v1/projects/:id/secrets`). Refs
/// resolve to stable IDs first (the upstream list path is ID-only); `q`
/// filters server-side (§19). Metadata only — upstream list rows never
/// carry values.
pub(crate) async fn api_scoped_secrets_handler(
    axum::extract::Query(query): axum::extract::Query<ScopedSecretsQuery>,
) -> axum::response::Response {
    let (Some(project_raw), Some(env_raw)) =
        (query.project.as_deref(), query.environment.as_deref())
    else {
        return invalid_scope_ref_response();
    };
    let (Some(project_ref), Some(env_ref)) = (
        normalize_proxied_scope_ref(project_raw),
        normalize_proxied_scope_ref(env_raw),
    ) else {
        return invalid_scope_ref_response();
    };
    if query.q.as_deref().is_some_and(|q| q.len() > 128) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "INVALID_SECRET_REQUEST",
                "error": "q must be at most 128 characters",
            })),
        )
            .into_response();
    }
    if query
        .limit
        .as_deref()
        .is_some_and(|limit| limit.parse::<i64>().is_err())
    {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "INVALID_SECRET_REQUEST",
                "error": "limit must be an integer",
            })),
        )
            .into_response();
    }
    let Some(endpoint) = scoped_account_endpoint() else {
        return not_configured_response();
    };
    let Some(token) = scoped_token() else {
        return missing_token_response();
    };
    // Resolve refs to stable IDs via the project view (slug renames keep
    // working; unknown refs fail here, never as upstream path smuggling).
    let client = account_proxy_http_client();
    let builder = match maybe_dpop(
        client.get(format!("{endpoint}/v1/projects/{project_ref}")),
        &token,
    ) {
        Ok(builder) => builder,
        // Fail closed: a set-but-bad DPoP key must never send unproven.
        Err(error) => return dpop_key_invalid_response(error),
    };
    let view: serde_json::Value = match builder.bearer_auth(&token).send().await {
        Ok(response) if response.status().is_success() => match response.json().await {
            Ok(view) => view,
            Err(_) => {
                return (
                    axum::http::StatusCode::BAD_GATEWAY,
                    axum::Json(serde_json::json!({
                        "status": "error",
                        "code": "ACCOUNT_SERVICE_RESPONSE_INVALID",
                        "error": "project view was not valid JSON",
                    })),
                )
                    .into_response();
            }
        },
        Ok(response) => {
            let status = axum::http::StatusCode::from_u16(response.status().as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            let payload = response.bytes().await.unwrap_or_default();
            return (status, payload).into_response();
        }
        Err(error) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "code": "ACCOUNT_SERVICE_UNAVAILABLE",
                    "error": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let project_id = view["project_id"].as_str().unwrap_or_default();
    let env_id = view["environments"]
        .as_array()
        .and_then(|envs| {
            envs.iter().find_map(|entry| {
                let slug = entry["slug"].as_str().unwrap_or_default();
                let id = entry["environment_id"].as_str().unwrap_or_default();
                if slug == env_ref || id == env_ref {
                    Some(id.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default();
    if project_id.is_empty() || env_id.is_empty() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "UNKNOWN_SCOPE",
                "error": "unknown project or environment ref",
            })),
        )
            .into_response();
    }
    let mut path = format!(
        "/v1/projects/{project_id}/secrets?environment={env_id}&limit={}",
        query.limit.as_deref().unwrap_or("100")
    );
    if let Some(q) = query.q.as_deref() {
        path.push_str("&q=");
        // Refs are pre-validated; `q` is free text, so percent-encode it.
        for byte in q.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                path.push(byte as char);
            } else {
                path.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    forward_scoped_get(&endpoint, &token, &path).await
}

#[cfg(test)]
mod tests {
    use super::normalize_proxied_scope_ref;

    #[test]
    fn scope_ref_normalizer_accepts_slugs_uuids_and_ids() {
        for raw in [
            "s",
            "shop",
            "payments-service_v2",
            "proj-1",
            "p1",
            "9f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d",
            "  shop  ",
        ] {
            assert!(
                normalize_proxied_scope_ref(raw).is_some(),
                "rejected {raw:?}"
            );
        }
        assert_eq!(
            normalize_proxied_scope_ref("  shop  ").as_deref(),
            Some("shop")
        );
    }

    #[test]
    fn scope_ref_normalizer_rejects_smuggling_and_junk() {
        for raw in [
            "",
            "   ",
            ".",
            "..",
            "../secrets",
            "shop/staging",
            "shop%2Fstaging",
            "shop staging",
            "-shop",
            ".shop",
            // ("shop\n" trims to "shop" and is accepted — covered by the
            // surrounding-whitespace accept case.)
        ] {
            assert!(
                normalize_proxied_scope_ref(raw).is_none(),
                "accepted {raw:?}"
            );
        }
        assert!(normalize_proxied_scope_ref(&"a".repeat(128)).is_some());
        assert!(normalize_proxied_scope_ref(&"a".repeat(129)).is_none());
    }
}
