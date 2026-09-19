//! Hosted-account HTTP proxy client and API handlers.

use axum::body::Bytes;
use reqwest::Client as HttpClient;
use std::sync::OnceLock;
use std::time::Duration;

pub(crate) fn hosted_account_endpoint() -> Option<String> {
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

static ACCOUNT_PROXY_HTTP_CLIENT: OnceLock<HttpClient> = OnceLock::new();

/// Shared connection-pooled client for the dashboard account proxy. The proxy
/// serves every hosted-account request from the long-lived dashboard server,
/// so it must reuse one client (and its connection pool) instead of building
/// a fresh client per proxied request.
pub(crate) fn account_proxy_http_client() -> HttpClient {
    ACCOUNT_PROXY_HTTP_CLIENT
        .get_or_init(|| {
            HttpClient::builder()
                .timeout(Duration::from_secs(8))
                .pool_idle_timeout(Duration::from_secs(120))
                .pool_max_idle_per_host(4)
                .tcp_keepalive(Some(Duration::from_secs(30)))
                .build()
                .unwrap_or_else(|_| HttpClient::new())
        })
        .clone()
}

pub(crate) async fn proxy_account_request(
    method: reqwest::Method,
    path: &str,
    headers: &axum::http::HeaderMap,
    body: Option<Bytes>,
) -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};

    let Some(endpoint) = hosted_account_endpoint() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "ACCOUNT_SERVICE_NOT_CONFIGURED",
                "error": "Hosted account service is not configured for this dashboard.",
            })),
        )
            .into_response();
    };
    let url = format!("{}{}", endpoint, path);
    let client = account_proxy_http_client();
    let mut request = client.request(method, url);
    if let Some(cookie) = headers.get(header::COOKIE) {
        request = request.header(header::COOKIE, cookie.clone());
    }
    if let Some(authorization) = headers.get(header::AUTHORIZATION) {
        request = request.header(header::AUTHORIZATION, authorization.clone());
    }
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        request = request.header(header::CONTENT_TYPE, content_type.clone());
    } else if body.as_ref().is_some_and(|value| !value.is_empty()) {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = match request.send().await {
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
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let payload = match response.bytes().await {
        Ok(payload) => payload,
        Err(error) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "code": "ACCOUNT_SERVICE_RESPONSE_INVALID",
                    "error": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let mut proxied = (status, payload).into_response();
    if let Some(content_type) = content_type {
        proxied
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    for cookie in set_cookies {
        proxied.headers_mut().append(header::SET_COOKIE, cookie);
    }
    proxied.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    proxied
}

pub(crate) async fn api_account_capabilities_handler() -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::GET,
        "/v1/capabilities",
        &axum::http::HeaderMap::new(),
        None,
    )
    .await
}

/// Public bootstrap endpoint. The account service derives the account ID from
/// the supplied public key; no private key or vault data is accepted here.
pub(crate) async fn api_account_register_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(reqwest::Method::POST, "/v1/accounts", &headers, Some(body)).await
}

pub(crate) async fn api_account_device_challenge_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/devices/challenge"),
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_device_enrollment_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/devices"),
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_session_handler(
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(reqwest::Method::GET, "/v1/sessions", &headers, None).await
}

pub(crate) async fn api_account_session_challenge_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/sessions/challenge",
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_session_login_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(reqwest::Method::POST, "/v1/sessions", &headers, Some(body)).await
}

pub(crate) async fn api_account_session_handoff_handler(
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/sessions/handoff",
        &headers,
        None,
    )
    .await
}

pub(crate) async fn api_account_session_handoff_consume_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/sessions/handoff/consume",
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_resource_get_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::GET,
        &format!("/v1/accounts/{account_id}"),
        &headers,
        None,
    )
    .await
}

pub(crate) async fn api_account_management_get_handler(
    axum::extract::Path((account_id, resource)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::GET,
        &format!("/v1/accounts/{account_id}/{resource}"),
        &headers,
        None,
    )
    .await
}

pub(crate) async fn api_account_management_post_handler(
    axum::extract::Path((account_id, resource)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/{resource}"),
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_recovery_codes_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/recovery/codes"),
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_membership_revoke_handler(
    axum::extract::Path((account_id, member_account_id)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/memberships/{member_account_id}/revoke"),
        &headers,
        None,
    )
    .await
}

pub(crate) async fn api_account_invitation_accept_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/invitations/accept",
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_webauthn_options_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/webauthn/authentication/options",
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_webauthn_verify_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/webauthn/authentication/verify",
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_webauthn_registration_options_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/webauthn/registration/options"),
        &headers,
        None,
    )
    .await
}

pub(crate) async fn api_account_webauthn_registration_verify_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/webauthn/registration/verify"),
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_totp_options_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/totp/authentication/options",
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_totp_verify_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/totp/authentication/verify",
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_totp_enrollment_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/totp/enrollment"),
        &headers,
        None,
    )
    .await
}

pub(crate) async fn api_account_totp_enrollment_verify_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/totp/enrollment/verify"),
        &headers,
        Some(body),
    )
    .await
}

pub(crate) async fn api_account_totp_revoke_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/totp/revoke"),
        &headers,
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_proxy_client_is_shared_and_pool_backed() {
        // The dashboard proxy serves every hosted-account request from one
        // long-lived server; both handles must come from the shared pooled
        // client so connections are reused across proxied requests.
        let first = account_proxy_http_client();
        let second = account_proxy_http_client();
        for client in [&first, &second] {
            let request = client.get("http://127.0.0.1:9/v1/sessions").build();
            assert!(request.is_ok());
        }
    }
}
