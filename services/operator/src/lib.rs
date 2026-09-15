//! # CipherVault Operator Service
//!
//! Provides the immutable ciphertext object store, lease commitments, challenge-response
//! authentication, and append-only recovery logs for CipherVault.

pub mod handlers;
pub mod state;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use axum::Router;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub use state::OperatorState;

/// Constructs the Axum application router for the operator service.
pub fn create_router(state: Arc<OperatorState>) -> Router {
    Router::new()
        .route("/v1/info", get(handlers::get_info))
        .route("/healthz", get(handlers::get_health))
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
                ]),
        )
        .layer(DefaultBodyLimit::max(state::MAX_OBJECT_SIZE))
        .with_state(state)
}
