use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};
use std::sync::Arc;
use tower05::ServiceExt;

/// Recovery reads are intentionally anonymous: the 32-byte locator is a
/// KDF-derived capability, and clean-machine recovery has no session by
/// definition (see `get_recovery_records` docs). This locks the decision:
/// an unauthenticated GET must return 200 (possibly with zero records),
/// never 401.
#[tokio::test]
async fn recovery_read_requires_no_authorization() {
    let root = std::env::temp_dir().join(format!("cv-recovery-anon-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "recovery-anon-test".into(),
        root.clone(),
        generate_signing_key(),
    ));
    let app = create_router(Arc::clone(&state));

    let locator_hex = "ab".repeat(32);
    let response = app
        .oneshot(
            Request::get(format!("/v1/recovery/{locator_hex}/records"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["records_hex"], serde_json::Value::Array(vec![]));

    let _ = std::fs::remove_dir_all(&root);
}
