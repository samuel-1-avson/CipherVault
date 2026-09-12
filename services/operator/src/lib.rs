//! # CipherVault Operator Service
//!
//! Provides the immutable ciphertext object store, lease commitments, challenge-response
//! authentication, and append-only recovery logs for CipherVault.

pub mod handlers;
pub mod state;

use axum::routing::{get, post, put};
use axum::Router;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub use state::OperatorState;

/// Constructs the Axum application router for the operator service.
pub fn create_router(state: Arc<OperatorState>) -> Router {
    Router::new()
        .route("/v1/info", get(handlers::get_info))
        .route("/v1/challenges", post(handlers::post_challenge))
        .route("/v1/sessions", post(handlers::post_session))
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
        .layer(CorsLayer::permissive())
        .with_state(state)
}
