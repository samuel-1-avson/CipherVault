use std::sync::Arc;

use axum::{
    http::StatusCode,
    routing::{get, post, put},
    Router,
};
use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{handlers, OperatorState};
use ciphervault_storage::MultiOperatorPool;

#[tokio::test]
async fn unavailable_operator_key_prevents_receipt_acceptance() {
    let root = std::env::temp_dir().join(format!("cv-key-failure-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "test".into(),
        root.clone(),
        generate_signing_key(),
    ));
    let app = Router::new()
        .route(
            "/v1/info",
            get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        )
        .route("/v1/challenges", post(handlers::post_challenge))
        .route("/v1/sessions", post(handlers::post_session))
        .route(
            "/v1/objects/:cid",
            put(handlers::put_object).get(handlers::get_object),
        )
        .route("/v1/leases", post(handlers::post_lease))
        .route(
            "/v1/recovery/:locator/records",
            post(handlers::post_recovery_record).get(handlers::get_recovery_records),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let pool = MultiOperatorPool::new(vec![endpoint]);
    let bytes = b"synthetic ciphertext".to_vec();
    let objects = vec![(ciphervault_format::compute_digest(&bytes), bytes)];
    let result = pool
        .replicate_and_verify(
            &[1; 32],
            &generate_signing_key(),
            &objects,
            &[2; 32],
            20,
            90,
            &[3; 32],
            b"head",
            &[],
            1,
        )
        .await;
    assert!(
        result.is_err(),
        "An unverifiable receipt must never count as durable"
    );
    task.abort();
    let _ = task.await;
    std::fs::remove_dir_all(root).unwrap();
}
