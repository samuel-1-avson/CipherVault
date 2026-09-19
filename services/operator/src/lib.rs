//! # CipherVault Operator Service
//!
//! Provides the immutable ciphertext object store, lease commitments, challenge-response
//! authentication, and append-only recovery logs for CipherVault.

pub mod handlers;
pub mod metrics;
pub mod state;
pub mod swarm;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::Router;
use std::sync::Arc;
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

/// Constructs the Axum application router for the operator service.
pub fn create_router(state: Arc<OperatorState>) -> Router {
    Router::new()
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
        .route("/v1/leases", post(handlers::post_lease))
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
        )
        // Operator APIs are consumed by the dashboard backend and authenticated clients.
        // Do not grant arbitrary browser origins access to operator responses.
        // Envelope first (inner): trace stays outermost so spans and the
        // trace-ID echo cover the rewritten body too.
        .route_layer(middleware::from_fn(json_error_envelope))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            trace_middleware,
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
        .with_state(state)
}
