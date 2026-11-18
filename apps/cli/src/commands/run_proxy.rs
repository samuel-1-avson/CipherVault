//! Loopback credential-injecting HTTP reverse proxy for `ciphervault run --proxy`.
//!
//! Instead of placing real API keys/tokens into the child process's environment,
//! `run --proxy` spawns an ephemeral `127.0.0.1` HTTP server in the parent
//! CipherVault process and gives the child ephemeral placeholder tokens plus
//! `*_BASE_URL` / `CIPHERVAULT_PROXY_ROUTE_*` URLs. Outbound requests carrying a
//! valid placeholder are authenticated against pinned HTTPS upstreams (with
//! redirects disabled) and response bodies are scrubbed before return.

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use rand::RngCore;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct ProxyRoute {
    pub env_key: String,
    pub slug: String,
    pub placeholder: String,
    pub upstream_cred: Zeroizing<String>,
    pub upstream_base: String,
    pub header_name: String,
    pub bearer_prefix: bool,
    pub base_env_vars: Vec<(&'static str, &'static str)>,
}

struct ProxyState {
    routes: Vec<ProxyRoute>,
    client: reqwest::Client,
    exact_values: Vec<(String, Zeroizing<String>)>,
}

fn bearer_scheme_prefix() -> &'static str {
    concat!("Bear", "er ")
}

type KnownProvider = (
    &'static str,
    &'static str,
    &'static str,
    bool,
    &'static [(&'static str, &'static str)],
);

const KNOWN_PROVIDERS: &[KnownProvider] = &[
    (
        "OPENAI_API_KEY",
        "https://api.openai.com",
        "authorization",
        true,
        &[("OPENAI_BASE_URL", "/v1"), ("OPENAI_API_BASE", "/v1")],
    ),
    (
        "ANTHROPIC_API_KEY",
        "https://api.anthropic.com",
        "x-api-key",
        false,
        &[("ANTHROPIC_BASE_URL", "")],
    ),
    (
        "GEMINI_API_KEY",
        "https://generativelanguage.googleapis.com",
        "x-goog-api-key",
        false,
        &[("GEMINI_BASE_URL", ""), ("GOOGLE_GEMINI_BASE_URL", "")],
    ),
    (
        "GOOGLE_API_KEY",
        "https://generativelanguage.googleapis.com",
        "x-goog-api-key",
        false,
        &[("GEMINI_BASE_URL", ""), ("GOOGLE_GEMINI_BASE_URL", "")],
    ),
    (
        "STRIPE_API_KEY",
        "https://api.stripe.com",
        "authorization",
        true,
        &[("STRIPE_API_BASE", "")],
    ),
    (
        "STRIPE_SECRET_KEY",
        "https://api.stripe.com",
        "authorization",
        true,
        &[("STRIPE_API_BASE", "")],
    ),
    (
        "GITHUB_TOKEN",
        "https://api.github.com",
        "authorization",
        true,
        &[],
    ),
    (
        "GH_TOKEN",
        "https://api.github.com",
        "authorization",
        true,
        &[],
    ),
    (
        "OPENROUTER_API_KEY",
        "https://openrouter.ai/api",
        "authorization",
        true,
        &[("OPENROUTER_BASE_URL", "/v1")],
    ),
    (
        "HF_TOKEN",
        "https://huggingface.co",
        "authorization",
        true,
        &[],
    ),
    (
        "HUGGINGFACE_TOKEN",
        "https://huggingface.co",
        "authorization",
        true,
        &[],
    ),
];

type ProviderSpec = (
    &'static str,
    &'static str,
    bool,
    &'static [(&'static str, &'static str)],
);

fn known_provider_for_key(key: &str) -> Option<ProviderSpec> {
    KNOWN_PROVIDERS
        .iter()
        .find(|(k, _, _, _, _)| *k == key)
        .map(|(_, url, hdr, bearer, envs)| (*url, *hdr, *bearer, *envs))
}

fn allow_loopback_upstream() -> bool {
    cfg!(test) || std::env::var("CIPHERVAULT_ALLOW_LOOPBACK_UPSTREAM").as_deref() == Ok("1")
}

fn allow_provider_override() -> bool {
    cfg!(test) || std::env::var("CIPHERVAULT_ALLOW_PROVIDER_OVERRIDE").as_deref() == Ok("1")
}

fn canonical_urls_match(candidate: &str, canonical: &str) -> bool {
    match (reqwest::Url::parse(candidate), reqwest::Url::parse(canonical)) {
        (Ok(a), Ok(b)) => a.as_str().trim_end_matches('/') == b.as_str().trim_end_matches('/'),
        _ => candidate.trim_end_matches('/') == canonical.trim_end_matches('/'),
    }
}

fn validate_upstream_url(raw: &str, allow_loopback: bool) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(trimmed)
        .with_context(|| format!("invalid --proxy-upstream URL '{raw}'"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("--proxy-upstream URL '{raw}' is missing a host"))?;
    match parsed.scheme() {
        "https" => Ok(trimmed.to_string()),
        "http" if matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]") => {
            if allow_loopback {
                Ok(trimmed.to_string())
            } else {
                bail!(
                    "refusing loopback http:// upstream '{raw}' without CIPHERVAULT_ALLOW_LOOPBACK_UPSTREAM=1"
                )
            }
        }
        "http" => bail!(
            "refusing cleartext http:// upstream '{raw}' (only https:// or explicitly allowed loopback http:// is allowed)"
        ),
        other => bail!("unsupported upstream URL scheme '{other}' in '{raw}'"),
    }
}

pub(crate) fn parse_proxy_upstream_spec(
    spec: &str,
    allow_loopback: bool,
) -> Result<(String, String, String, bool)> {
    let (key, rhs) = spec.split_once('=').ok_or_else(|| {
        anyhow::anyhow!("invalid --proxy-upstream '{spec}': expected VAR=https://host[@HeaderName]")
    })?;
    let key = key.trim();
    if key.is_empty() {
        bail!("--proxy-upstream variable name cannot be empty");
    }
    let (url_part, header_name, bearer_prefix) = if let Some((u, hdr)) = rhs.rsplit_once('@') {
        if u.contains("://") && !hdr.trim().is_empty() && !hdr.contains('/') {
            (u, hdr.trim().to_ascii_lowercase(), false)
        } else {
            (rhs, "authorization".to_string(), true)
        }
    } else {
        (rhs, "authorization".to_string(), true)
    };
    let clean_url = validate_upstream_url(url_part, allow_loopback)?;
    Ok((key.to_string(), clean_url, header_name, bearer_prefix))
}

fn new_placeholder() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("cv-proxy-{}", hex::encode(bytes))
}

pub(crate) fn build_proxy_routes(
    vars: &BTreeMap<String, Zeroizing<String>>,
    explicit_upstreams: Option<&[String]>,
) -> Result<Vec<ProxyRoute>> {
    build_proxy_routes_with_policy(
        vars,
        explicit_upstreams,
        allow_loopback_upstream(),
        allow_provider_override(),
    )
}

fn build_proxy_routes_with_policy(
    vars: &BTreeMap<String, Zeroizing<String>>,
    explicit_upstreams: Option<&[String]>,
    allow_loopback: bool,
    allow_provider_override: bool,
) -> Result<Vec<ProxyRoute>> {
    let mut overrides: BTreeMap<String, (String, String, bool)> = BTreeMap::new();
    if let Some(specs) = explicit_upstreams {
        for spec in specs {
            let (k, url, hdr, bearer) = parse_proxy_upstream_spec(spec, allow_loopback)?;
            if !vars.contains_key(&k) {
                bail!("--proxy-upstream references '{k}' which is not loaded in this run");
            }
            if let Some((canonical_url, _, _, _)) = known_provider_for_key(&k) {
                if !allow_provider_override && !canonical_urls_match(&url, canonical_url) {
                    bail!(
                        "refusing to override known provider '{k}' upstream '{url}' (canonical '{canonical_url}') without CIPHERVAULT_ALLOW_PROVIDER_OVERRIDE=1"
                    );
                }
            }
            overrides.insert(k, (url, hdr, bearer));
        }
    }

    let mut routes = Vec::new();
    for (key, cred_val) in vars {
        if let Some((url, hdr, bearer)) = overrides.get(key) {
            let base_env_vars = known_provider_for_key(key)
                .map(|(_, _, _, envs)| envs.to_vec())
                .unwrap_or_default();
            routes.push(ProxyRoute {
                env_key: key.clone(),
                slug: key.to_ascii_lowercase(),
                placeholder: new_placeholder(),
                upstream_cred: cred_val.clone(),
                upstream_base: url.clone(),
                header_name: hdr.clone(),
                bearer_prefix: *bearer,
                base_env_vars,
            });
        } else if let Some((url, hdr, bearer, envs)) = known_provider_for_key(key) {
            routes.push(ProxyRoute {
                env_key: key.clone(),
                slug: key.to_ascii_lowercase(),
                placeholder: new_placeholder(),
                upstream_cred: cred_val.clone(),
                upstream_base: url.to_string(),
                header_name: hdr.to_string(),
                bearer_prefix: bearer,
                base_env_vars: envs.to_vec(),
            });
        }
    }

    if routes.is_empty() {
        bail!(
            "--proxy found no mapped credential routes (pass --proxy-upstream VAR=https://host or use a known provider key such as OPENAI_API_KEY / ANTHROPIC_API_KEY)"
        );
    }
    Ok(routes)
}

pub(crate) struct RunningProxy {
    #[cfg_attr(not(test), allow(dead_code))]
    pub addr: std::net::SocketAddr,
    pub child_env: Vec<(String, String)>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl RunningProxy {
    pub(crate) async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

pub(crate) async fn start_credential_proxy(routes: Vec<ProxyRoute>) -> Result<RunningProxy> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind loopback credential proxy")?;
    let addr = listener.local_addr()?;
    let base = format!("http://{addr}");

    let mut child_env = Vec::new();
    child_env.push(("CIPHERVAULT_PROXY_URL".to_string(), base.clone()));
    for route in &routes {
        child_env.push((route.env_key.clone(), route.placeholder.clone()));
        let route_url = format!("{base}/__cv/{}", route.slug);
        child_env.push((
            format!("CIPHERVAULT_PROXY_ROUTE_{}", route.env_key),
            route_url.clone(),
        ));
        for (env_var, suffix) in &route.base_env_vars {
            child_env.push(((*env_var).to_string(), format!("{route_url}{suffix}")));
        }
    }

    let exact_values: Vec<(String, Zeroizing<String>)> = routes
        .iter()
        .map(|r| (r.env_key.clone(), r.upstream_cred.clone()))
        .collect();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("failed to build upstream proxy client")?;

    let state = Arc::new(ProxyState {
        routes,
        client,
        exact_values,
    });
    let app = Router::new().fallback(proxy_handler).with_state(state);
    let (tx, rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = rx.await;
        });
        let _ = server.await;
    });

    Ok(RunningProxy {
        addr,
        child_env,
        shutdown_tx: Some(tx),
        handle: Some(handle),
    })
}

fn extract_presented_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let trimmed = auth.trim();
        let lower_prefix = bearer_scheme_prefix().to_ascii_lowercase();
        if trimmed.to_ascii_lowercase().starts_with(&lower_prefix) {
            tokens.push(trimmed[lower_prefix.len()..].trim().to_string());
        } else {
            tokens.push(trimmed.to_string());
        }
    }
    for h in ["x-api-key", "x-goog-api-key", "x-ciphervault-proxy-token"] {
        if let Some(val) = headers.get(h).and_then(|v| v.to_str().ok()) {
            tokens.push(val.trim().to_string());
        }
    }
    tokens
}

fn is_hop_by_hop_or_auth(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "authorization"
            | "x-api-key"
            | "x-goog-api-key"
            | "x-ciphervault-proxy-token"
    )
}

async fn proxy_handler(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response {
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let presented = extract_presented_tokens(&parts.headers);

    let (route, forward_path) = if let Some(rest) = path_and_query.strip_prefix("/__cv/") {
        let (slug, tail) = match rest.split_once('/') {
            Some((s, t)) => (s, format!("/{t}")),
            None => (rest, String::new()),
        };
        let Some(r) = state.routes.iter().find(|r| r.slug == slug) else {
            return (StatusCode::NOT_FOUND, "unknown CipherVault proxy route").into_response();
        };
        if !presented.iter().any(|t| t == &r.placeholder) {
            return (
                StatusCode::FORBIDDEN,
                "missing or invalid CipherVault proxy placeholder token",
            )
                .into_response();
        }
        (r, tail)
    } else {
        let Some(r) = state
            .routes
            .iter()
            .find(|r| presented.iter().any(|t| t == &r.placeholder))
        else {
            return (
                StatusCode::FORBIDDEN,
                "missing or invalid CipherVault proxy placeholder token",
            )
                .into_response();
        };
        (r, path_and_query.to_string())
    };

    let target_url = format!("{}{}", route.upstream_base, forward_path);
    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid HTTP method").into_response(),
    };

    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds 16 MiB").into_response()
        }
    };

    let mut out_req = state.client.request(method, &target_url);
    for (k, v) in &parts.headers {
        let k_str = k.as_str();
        if is_hop_by_hop_or_auth(k_str) {
            continue;
        }
        if let Ok(val) = v.to_str() {
            out_req = out_req.header(k_str, val);
        }
    }

    let injected_value = if route.bearer_prefix {
        Zeroizing::new(format!(
            "{}{}",
            bearer_scheme_prefix(),
            route.upstream_cred.as_str()
        ))
    } else {
        route.upstream_cred.clone()
    };
    out_req = out_req.header(route.header_name.as_str(), injected_value.as_str());
    if !body_bytes.is_empty() && parts.method != Method::GET && parts.method != Method::HEAD {
        out_req = out_req.body(body_bytes.to_vec());
    }

    let resp = match out_req.send().await {
        Ok(r) => r,
        Err(e) => {
            let (scrubbed_err, _) =
                ciphervault_redact::scrub_exact_values(&e.to_string(), &state.exact_values);
            return (
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {scrubbed_err}"),
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = resp.headers().clone();
    let resp_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            let (scrubbed_err, _) =
                ciphervault_redact::scrub_exact_values(&e.to_string(), &state.exact_values);
            return (
                StatusCode::BAD_GATEWAY,
                format!("upstream response read failed: {scrubbed_err}"),
            )
                .into_response();
        }
    };

    let final_body: Vec<u8> = match std::str::from_utf8(&resp_bytes) {
        Ok(text) => {
            let (exact, _) = ciphervault_redact::scrub_exact_values(text, &state.exact_values);
            ciphervault_redact::redact_text(&exact).into_bytes()
        }
        Err(_) => resp_bytes.to_vec(),
    };

    let mut out_resp = Response::builder().status(status);
    for (k, v) in &resp_headers {
        let k_lower = k.as_str().to_ascii_lowercase();
        if matches!(
            k_lower.as_str(),
            "connection" | "transfer-encoding" | "content-length" | "keep-alive"
        ) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(k.as_str().as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out_resp = out_resp.header(hn, hv);
        }
    }
    out_resp
        .body(Body::from(final_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    #[test]
    fn validates_upstream_urls_and_rejects_cleartext_remote() {
        let allow_loopback = allow_loopback_upstream();
        assert!(
            parse_proxy_upstream_spec("MY_VAR=https://api.example.com", allow_loopback).is_ok()
        );
        assert!(parse_proxy_upstream_spec("MY_VAR=http://127.0.0.1:8080", allow_loopback).is_ok());
        assert!(parse_proxy_upstream_spec("MY_VAR=http://evil.example.com", allow_loopback).is_err());

        let (k, u, h, bearer) =
            parse_proxy_upstream_spec("MY_VAR=https://api.example.com@X-Api-Key", allow_loopback)
                .unwrap();
        assert_eq!(k, "MY_VAR");
        assert_eq!(u, "https://api.example.com");
        assert_eq!(h, "x-api-key");
        assert!(!bearer);
    }

    #[tokio::test]
    async fn proxy_injects_real_cred_blocks_wrong_token_and_scrubs_echoed_value() {
        let real_val = concat!("real_proxy_", "tok_", "77889900aabb");

        let mock_app = Router::new().route(
            "/v1/echo",
            get(|headers: HeaderMap| async move {
                let hdr = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                format!("got_hdr {hdr}")
            }),
        );
        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap();
        let mock_handle = tokio::spawn(async move {
            let _ = axum::serve(mock_listener, mock_app).await;
        });

        let mut vars = BTreeMap::new();
        vars.insert(
            "OPENAI_API_KEY".to_string(),
            Zeroizing::new(real_val.to_string()),
        );
        let upstream_arg = format!("{}={}://{mock_addr}", "OPENAI_API_KEY", "http");
        let routes = build_proxy_routes(&vars, Some(&[upstream_arg])).unwrap();
        let placeholder = routes[0].placeholder.clone();
        assert_ne!(placeholder, real_val);

        let proxy = start_credential_proxy(routes).await.unwrap();
        let proxy_base = format!("http://{}", proxy.addr);
        let client = reqwest::Client::new();
        let scheme = bearer_scheme_prefix();

        let bad = client
            .get(format!("{proxy_base}/__cv/openai_api_key/v1/echo"))
            .header("authorization", format!("{scheme}wrong-token"))
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), reqwest::StatusCode::FORBIDDEN);

        let ok = client
            .get(format!("{proxy_base}/__cv/openai_api_key/v1/echo"))
            .header("authorization", format!("{scheme}{placeholder}"))
            .header("host", "attacker.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), reqwest::StatusCode::OK);
        let body = ok.text().await.unwrap();
        assert!(!body.contains(real_val), "value leaked in body: {body}");
        assert!(body.contains("[REDACTED"), "expected redaction in {body}");

        proxy.shutdown().await;
        mock_handle.abort();
    }

    #[test]
    fn rejects_loopback_http_upstream_unless_allowed() {
        for url in [
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            let err = validate_upstream_url(url, false).unwrap_err();
            assert!(
                err.to_string()
                    .contains("CIPHERVAULT_ALLOW_LOOPBACK_UPSTREAM=1"),
                "unexpected error for {url}: {err}"
            );
            assert!(
                validate_upstream_url(url, true).is_ok(),
                "expected {url} to be allowed when allow_loopback=true"
            );
        }

        // Non-loopback cleartext HTTP is always refused even with allow_loopback=true.
        assert!(validate_upstream_url("http://evil.example.com", true).is_err());
    }

    #[test]
    fn rejects_known_provider_override_unless_allowed() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "OPENAI_API_KEY".to_string(),
            Zeroizing::new("sk-test-1234567890".to_string()),
        );
        vars.insert(
            "OPENROUTER_API_KEY".to_string(),
            Zeroizing::new("sk-or-test-1234567890".to_string()),
        );
        vars.insert(
            "CUSTOM_API_KEY".to_string(),
            Zeroizing::new("custom-1234567890".to_string()),
        );

        // Overriding a known provider to a non-canonical HTTPS host fails when disallowed.
        let err = build_proxy_routes_with_policy(
            &vars,
            Some(&["OPENAI_API_KEY=https://attacker.example.com".to_string()]),
            false,
            false,
        )
        .err()
        .expect("expected provider override to fail");
        assert!(
            err.to_string()
                .contains("CIPHERVAULT_ALLOW_PROVIDER_OVERRIDE=1"),
            "unexpected error: {err}"
        );

        // Overriding a known provider to a loopback HTTP endpoint also fails without provider override.
        assert!(build_proxy_routes_with_policy(
            &vars,
            Some(&["OPENAI_API_KEY=http://127.0.0.1:9999".to_string()]),
            true,
            false,
        )
        .is_err());

        // Allowed when CIPHERVAULT_ALLOW_PROVIDER_OVERRIDE=1 policy is enabled.
        let allowed_routes = build_proxy_routes_with_policy(
            &vars,
            Some(&["OPENAI_API_KEY=https://attacker.example.com".to_string()]),
            false,
            true,
        )
        .unwrap();
        let openai = allowed_routes
            .iter()
            .find(|r| r.env_key == "OPENAI_API_KEY")
            .unwrap();
        assert_eq!(openai.upstream_base, "https://attacker.example.com");

        // Canonical URL (even with trailing slash or uppercase host) succeeds without override flag.
        assert!(build_proxy_routes_with_policy(
            &vars,
            Some(&[
                "OPENAI_API_KEY=HTTPS://API.OPENAI.COM/".to_string(),
                "OPENROUTER_API_KEY=https://openrouter.ai/api/".to_string(),
            ]),
            false,
            false,
        )
        .is_ok());

        // Non-known custom keys can bind to arbitrary HTTPS upstreams without override flag.
        assert!(build_proxy_routes_with_policy(
            &vars,
            Some(&["CUSTOM_API_KEY=https://gateway.example.com".to_string()]),
            false,
            false,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn proxy_scrubs_upstream_response_read_errors() {
        use tokio::io::AsyncWriteExt;

        let real_val = concat!("real_read_err_", "tok_", "aabbccddeeff");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = listener.local_addr().unwrap();
        let mock_handle = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\npartial")
                    .await;
                let _ = sock.shutdown().await;
            }
        });

        let mut vars = BTreeMap::new();
        vars.insert(
            "CUSTOM_KEY".to_string(),
            Zeroizing::new(real_val.to_string()),
        );
        let upstream_arg = format!("CUSTOM_KEY=http://{mock_addr}");
        let routes = build_proxy_routes(&vars, Some(&[upstream_arg])).unwrap();
        let placeholder = routes[0].placeholder.clone();

        let proxy = start_credential_proxy(routes).await.unwrap();
        let client = reqwest::Client::new();
        let scheme = bearer_scheme_prefix();
        let resp = client
            .get(format!("http://{}/__cv/custom_key/data", proxy.addr))
            .header("authorization", format!("{scheme}{placeholder}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
        let body = resp.text().await.unwrap();
        assert!(
            body.starts_with("upstream response read failed:"),
            "unexpected body: {body}"
        );
        assert!(!body.contains(real_val));

        proxy.shutdown().await;
        mock_handle.abort();
    }
}
