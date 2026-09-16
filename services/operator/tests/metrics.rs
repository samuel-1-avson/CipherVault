use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};
use std::sync::Arc;
use tower05::ServiceExt;

/// R11: /metrics serves Prometheus exposition, and the trace middleware
/// echoes valid client trace IDs back to the caller.
#[tokio::test]
async fn metrics_endpoint_and_trace_echo() {
    let root = std::env::temp_dir().join(format!("cv-metrics-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "metrics-test".into(),
        root.clone(),
        generate_signing_key(),
    ));
    let app = create_router(Arc::clone(&state));

    // Seed one operation so op counters are non-zero.
    let payload = b"metrics-seeded-object";
    let cid_hex = hex::encode(ciphervault_format::compute_digest(payload));
    state.put_object(&cid_hex, payload).unwrap();

    // Valid trace IDs echo back on the response.
    let trace_id = "ab".repeat(16);
    let echoed = app
        .clone()
        .oneshot(
            Request::get("/healthz")
                .header("x-ciphervault-trace-id", trace_id.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        echoed
            .headers()
            .get("x-ciphervault-trace-id")
            .unwrap()
            .to_str()
            .unwrap(),
        trace_id.as_str()
    );

    // Invalid trace IDs are dropped, never echoed.
    let dropped = app
        .clone()
        .oneshot(
            Request::get("/healthz")
                .header("x-ciphervault-trace-id", "not-a-valid-trace-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(dropped
        .headers()
        .get("x-ciphervault-trace-id")
        .is_none());

    let response = app
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let exposition = String::from_utf8(body.to_vec()).unwrap();
    // The two /healthz requests above passed through the middleware; this
    // /metrics scrape itself is observed only after rendering.
    assert!(exposition.contains("ciphervault_operator_requests_total 2"));
    assert!(exposition.contains("ciphervault_operator_objects_put_total 1"));
    assert!(exposition.contains("ciphervault_operator_objects_put_bytes_total 21"));
    assert!(exposition.contains("# TYPE ciphervault_operator_put_latency_ms histogram"));
}
