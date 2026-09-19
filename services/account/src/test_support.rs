//! Shared harness for router-level account tests.

use std::path::PathBuf;

use axum::body::to_bytes;
use axum::response::Response;
use axum::Router;

use crate::{
    create_router,
    state::{AccountState, MAX_BODY_BYTES},
    util::random_hex,
};

pub(crate) async fn json(response: Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("json")
}

pub(crate) fn test_app(name: &str) -> (PathBuf, AccountState, Router) {
    let root = std::env::temp_dir().join(format!("cv-account-{name}-{}", random_hex(8)));
    let state = AccountState::open(&root).expect("state");
    let app = create_router(state.clone());
    (root, state, app)
}

pub(crate) fn cleanup(root: PathBuf) {
    let _ = std::fs::remove_dir_all(root);
}
