//! # CipherVault Operator Service
//!
//! Provides the immutable ciphertext object store, lease commitments, challenge-response
//! authentication, and append-only recovery logs for CipherVault.

pub mod handlers;
pub mod metrics;
pub mod state;
pub mod swarm;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;

pub use state::OperatorState;

/// Classifies a request path into a stable low-cardinality route label for
/// request spans. Dynamic segments (CIDs, locators) collapse to the route.
fn classify_route(path: &str) -> &'static str {
    if path == "/metrics" || path == "/healthz" || path == "/v1/info" {
        return "meta";
    }
    if path.starts_with("/v1/objects/") && path.ends_with("/challenge") {
        return "pos_challenge";
    }
    if path.starts_with("/v1/objects/") {
        return "object";
    }
    if path.starts_with("/v1/leases") {
        return "lease";
    }
    if path.starts_with("/v1/recovery/") {
        return "recovery";
    }
    if path.starts_with("/v1/challenges") || path.starts_with("/v1/sessions") {
        return "auth";
    }
    if path.starts_with("/v1/relayer/") {
        return "relayer";
    }
    if path.starts_with("/v1/peers") {
        return "peers";
    }
    if path.starts_with("/v1/auth/") {
        return "approvals";
    }
    if path.starts_with("/v1/identities") {
        return "identities";
    }
    if path.starts_with("/v1/vouchers") {
        return "vouchers";
    }
    "other"
}

/// Error-envelope middleware: rewrites text/plain error responses into the
/// standard JSON `{"code","error"}` shape (`ApiErrorBody`) so every
/// operator failure has one parseable contract. Success, redirect, and
/// already-structured bodies pass through untouched.
async fn json_error_envelope(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();
    if status.is_success() || status.is_redirection() {
        return response;
    }
    let is_text = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| content_type.starts_with("text/plain"));
    if !is_text {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .unwrap_or_default();
    let message = String::from_utf8_lossy(&bytes).into_owned();
    let envelope = serde_json::json!({ "code": status.as_u16(), "error": message });
    parts.headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    Response::from_parts(parts, axum::body::Body::from(envelope.to_string()))
}

/// Trace middleware (R11): extracts the client trace ID, echoes it back so
/// CLI/fleet callers can verify propagation, and records one request span.
async fn trace_middleware(
    State(state): State<Arc<OperatorState>>,
    request: Request,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let route = classify_route(request.uri().path());
    let trace_id = request
        .headers()
        .get("x-ciphervault-trace-id")
        .and_then(|value| value.to_str().ok())
        .and_then(metrics::parse_trace_id);
    let mut response = next.run(request).await;
    if let Some(id) = trace_id.as_deref() {
        if let Ok(value) = axum::http::HeaderValue::from_str(id) {
            response
                .headers_mut()
                .insert("x-ciphervault-trace-id", value);
        }
    }
    state.metrics.observe_request(
        route,
        response.status().as_u16(),
        started.elapsed(),
        trace_id.as_deref(),
    );
    response
}

/// Default HTTP rate limit (requests per 60 s sliding window, per client
/// key) when `CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN` is unset. Sized for
/// bursty CLI pushes (challenge+put+verify per object at concurrency 8)
/// while capping floods; 0 disables the limiter.
pub const DEFAULT_HTTP_RATE_LIMIT_PER_MIN: u32 = 600;
/// Sliding window for the HTTP rate limiter.
const HTTP_RATE_WINDOW: Duration = Duration::from_secs(60);
/// Upper bound on tracked client keys. Past this, untracked keys fail
/// closed (429) so the tracker itself cannot be memory-DoSed.
const MAX_HTTP_RATE_TRACKED_KEYS: usize = 4096;

fn http_rate_limit_per_min() -> u32 {
    match std::env::var("CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN")
        .ok()
        .map(|value| value.trim().to_string())
    {
        Some(value) if !value.is_empty() => match value.parse::<u32>() {
            Ok(limit) => limit,
            Err(_) => {
                eprintln!(
                    "operator limit CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN={value} invalid; using default {DEFAULT_HTTP_RATE_LIMIT_PER_MIN}"
                );
                DEFAULT_HTTP_RATE_LIMIT_PER_MIN
            }
        },
        _ => DEFAULT_HTTP_RATE_LIMIT_PER_MIN,
    }
}

/// Per-client sliding-window HTTP limiter. Mirrors the P2P `rpc_allowed`
/// posture: bounded tracker, opportunistic hygiene, 429 before auth/serve.
#[derive(Clone)]
struct HttpRateLimiter {
    hits: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    limit: u32,
}

impl HttpRateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            hits: Arc::new(Mutex::new(HashMap::new())),
            limit,
        }
    }

    fn allowed(&self, key: &str) -> bool {
        Self::allowed_at(
            &mut state::lock_or_recover(&self.hits, "http_rate_limit"),
            key,
            self.limit,
            Instant::now(),
        )
    }

    fn allowed_at(
        hits: &mut HashMap<String, VecDeque<Instant>>,
        key: &str,
        limit: u32,
        now: Instant,
    ) -> bool {
        let window_start = now.checked_sub(HTTP_RATE_WINDOW);
        // Opportunistic hygiene past half capacity: evict keys with no
        // in-window hits so growth stays proportional to ACTUAL recent
        // requesters, not to every key ever seen.
        if hits.len() > MAX_HTTP_RATE_TRACKED_KEYS / 2 {
            hits.retain(|_, times| {
                while window_start.is_some_and(|start| times.front().is_some_and(|t| *t <= start)) {
                    times.pop_front();
                }
                !times.is_empty()
            });
        }
        if !hits.contains_key(key) && hits.len() >= MAX_HTTP_RATE_TRACKED_KEYS {
            return false;
        }
        let times = hits.entry(key.to_string()).or_default();
        while window_start.is_some_and(|start| times.front().is_some_and(|t| *t <= start)) {
            times.pop_front();
        }
        if times.len() >= limit as usize {
            return false;
        }
        times.push_back(now);
        true
    }
}

/// Client key for HTTP rate limiting. The fleet runs behind Caddy on the
/// same host, so the socket IP is always loopback: prefer the first
/// `X-Forwarded-For` entry when present. Direct-exposure operators accept
/// that clients can rotate that header; front with L7 if that matters
/// (runbook §11).
fn http_client_key(request: &Request) -> String {
    if let Some(forwarded) = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        if let Some(first) = forwarded.split(',').next().map(str::trim) {
            if !first.is_empty() {
                return first.to_string();
            }
        }
    }
    if let Some(ConnectInfo(addr)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip().to_string();
    }
    "unknown".to_string()
}

/// HTTP flood guard: over-limit callers get a pre-shaped 429 JSON envelope
/// before trace/auth/serve burn any real work. Outermost route layer so
/// spans still record the rejection.
async fn http_rate_limit(
    State(limiter): State<HttpRateLimiter>,
    request: Request,
    next: Next,
) -> Response {
    if limiter.limit == 0 {
        return next.run(request).await;
    }
    if limiter.allowed(&http_client_key(&request)) {
        return next.run(request).await;
    }
    let body = serde_json::json!({"code": 429, "error": "http rate limit exceeded"});
    (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response()
}

/// Last-resort panic catcher (outermost layer): a panicking handler or
/// middleware becomes a 500 JSON envelope in the standard `{"code","error"}`
/// shape instead of a dropped connection. A panic also poisons any mutex
/// the panicking task held; those recover via `lock_or_recover`.
fn panic_response(_: Box<dyn std::any::Any + Send>) -> Response {
    let body = serde_json::json!({ "code": 500, "error": "INTERNAL_PANIC_CAUGHT" });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}

#[cfg(test)]
async fn test_panic_handler() -> &'static str {
    panic!("intentional test panic for CatchPanicLayer verification");
}

/// Constructs the Axum application router for the operator service.
pub fn create_router(state: Arc<OperatorState>) -> Router {
    let router = Router::new()
        .route("/v1/info", get(handlers::get_info))
        .route("/healthz", get(handlers::get_health))
        .route("/metrics", get(handlers::get_metrics))
        .route("/v1/challenges", post(handlers::post_challenge))
        .route("/v1/sessions", post(handlers::post_session))
        .route("/v1/sessions/revoke", post(handlers::post_revoke_session))
        .route(
            "/v1/identities",
            get(handlers::get_enrolled_identities).post(handlers::post_enroll_identity),
        )
        .route(
            "/v1/identities/revoke",
            post(handlers::post_revoke_identity),
        )
        .route("/v1/vouchers", post(handlers::post_issue_voucher))
        .route(
            "/v1/objects/:cid",
            put(handlers::put_object).get(handlers::get_object),
        )
        .route(
            "/v1/objects/:cid/challenge",
            post(handlers::post_object_challenge),
        )
        .route(
            "/v1/leases",
            post(handlers::post_lease).get(handlers::list_leases),
        )
        .route("/v1/leases/:id/renew", post(handlers::post_renew_lease))
        .route(
            "/v1/recovery/:locator/records",
            post(handlers::post_recovery_record).get(handlers::get_recovery_records),
        )
        .route(
            "/v1/relayer/checkpoints",
            post(handlers::post_relayer_checkpoint),
        )
        .route(
            "/v1/relayer/checkpoints/:commitment",
            get(handlers::get_relayer_checkpoint),
        )
        // Dynamic P2P Peer Gossip routes
        .route("/v1/peers/announce", post(handlers::post_peer_announce))
        .route("/v1/peers", get(handlers::get_peers))
        .route("/v1/peers/self", get(handlers::get_self_peer))
        .route("/v1/peers/p2p", get(handlers::get_p2p_info))
        // Verified community join routes: join + refresh are public (the
        // ticket / node-key signature is the authorization); membership
        // and graduation are control-plane administration.
        .route("/v1/peers/join", post(handlers::post_peer_join))
        .route(
            "/v1/peers/join/refresh",
            post(handlers::post_peer_join_refresh),
        )
        .route("/v1/peers/membership", get(handlers::get_peer_membership))
        .route("/v1/peers/admissions", get(handlers::get_peer_admissions))
        .route("/v1/peers/:id/graduate", post(handlers::post_peer_graduate))
        // Out-of-Band Cryptographic Approval routes
        .route(
            "/v1/auth/challenges",
            post(handlers::post_approval_challenge),
        )
        .route(
            "/v1/auth/challenges/pending",
            get(handlers::get_pending_challenges),
        )
        .route(
            "/v1/auth/challenges/:id",
            get(handlers::get_challenge_status),
        )
        .route(
            "/v1/auth/challenges/:id/approve",
            post(handlers::post_submit_approval),
        );
    #[cfg(test)]
    let router = router.route("/__test_panic", get(test_panic_handler));
    router
        // Operator APIs are consumed by the dashboard backend and authenticated clients.
        // Do not grant arbitrary browser origins access to operator responses.
        // Envelope first (inner): trace stays outermost so spans and the
        // trace-ID echo cover the rewritten body too.
        .route_layer(middleware::from_fn(json_error_envelope))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            trace_middleware,
        ))
        // Flood guard outermost of the route layers (inside CORS/body
        // limit): 429s still get trace spans, but no auth/serve work.
        .route_layer(middleware::from_fn_with_state(
            HttpRateLimiter::new(http_rate_limit_per_min()),
            http_rate_limit,
        ))
        .layer(
            CorsLayer::new()
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderName::from_static("x-ciphervault-id"),
                    axum::http::HeaderName::from_static("x-ciphervault-account-id"),
                    axum::http::HeaderName::from_static("x-ciphervault-device-id"),
                    axum::http::HeaderName::from_static("x-ciphervault-service-token"),
                    axum::http::HeaderName::from_static("x-ciphervault-trace-id"),
                ]),
        )
        .layer(DefaultBodyLimit::max(state::max_object_size()))
        // Outermost: added last so a panic anywhere below — handlers,
        // envelope, trace, CORS, body limit — becomes a 500 JSON envelope.
        .layer(CatchPanicLayer::custom(panic_response))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower05::ServiceExt;

    #[tokio::test]
    async fn p2p_info_reports_unavailable_without_swarm() {
        let root = std::env::temp_dir().join(format!("cv-p2pinfo-{}", rand::random::<u128>()));
        let state = Arc::new(OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        ));
        let response = create_router(state)
            .oneshot(Request::get("/v1/peers/p2p").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn panic_in_handler_returns_500_json_envelope() {
        let root = std::env::temp_dir().join(format!("cv-panic-{}", rand::random::<u128>()));
        let state = Arc::new(OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        ));
        let response = create_router(state)
            .oneshot(Request::get("/__test_panic").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], 500);
        assert_eq!(value["error"], "INTERNAL_PANIC_CAUGHT");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn http_limiter_admits_up_to_limit_then_rejects() {
        let mut hits = HashMap::new();
        let now = Instant::now();
        for _ in 0..3 {
            assert!(HttpRateLimiter::allowed_at(&mut hits, "k", 3, now));
        }
        assert!(!HttpRateLimiter::allowed_at(&mut hits, "k", 3, now));
    }

    #[test]
    fn http_limiter_window_expiry_readmits() {
        let mut hits = HashMap::new();
        let start = Instant::now();
        assert!(HttpRateLimiter::allowed_at(&mut hits, "k", 1, start));
        assert!(!HttpRateLimiter::allowed_at(&mut hits, "k", 1, start));
        let later = start + HTTP_RATE_WINDOW + Duration::from_secs(1);
        assert!(HttpRateLimiter::allowed_at(&mut hits, "k", 1, later));
    }

    #[test]
    fn http_limiter_isolates_keys_and_caps_tracker() {
        let mut hits = HashMap::new();
        let now = Instant::now();
        assert!(HttpRateLimiter::allowed_at(&mut hits, "a", 1, now));
        // Independent key unaffected by a's exhaustion.
        assert!(HttpRateLimiter::allowed_at(&mut hits, "b", 1, now));
        assert!(!HttpRateLimiter::allowed_at(&mut hits, "a", 1, now));
        // Tracker cap fails closed for brand-new keys.
        for i in 0..MAX_HTTP_RATE_TRACKED_KEYS {
            hits.insert(format!("fill-{i}"), VecDeque::from([now]));
        }
        assert!(!HttpRateLimiter::allowed_at(
            &mut hits,
            "new-key",
            u32::MAX,
            now
        ));
    }

    /// End to end through the real router: with a tiny limit, the fourth
    /// same-key request gets a pre-shaped 429 JSON envelope while a
    /// different client key sails through.
    #[tokio::test]
    async fn http_flood_gets_429_json_per_client_key() {
        std::env::set_var("CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN", "3");
        let root = std::env::temp_dir().join(format!("cv-httplimit-{}", rand::random::<u128>()));
        let state = Arc::new(OperatorState::new(
            "test".into(),
            root.clone(),
            ciphervault_crypto::generate_signing_key(),
        ));
        let router = create_router(state);
        let get = |xff: &str| {
            Request::builder()
                .uri("/v1/info")
                .header("x-forwarded-for", xff)
                .body(Body::empty())
                .unwrap()
        };
        // Router clones share the Arc limiter state, so hits accumulate.
        for _ in 0..3 {
            let response = router.clone().oneshot(get("198.51.100.7")).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = router.clone().oneshot(get("198.51.100.7")).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], 429);
        // A different client key is unaffected.
        let response = router.clone().oneshot(get("203.0.113.9")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        std::env::remove_var("CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN");
        std::fs::remove_dir_all(root).unwrap();
    }
}
