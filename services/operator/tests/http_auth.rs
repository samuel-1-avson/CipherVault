use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
use ciphervault_operator::{create_router, OperatorState};
use serde_json::json;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;
use tower05::ServiceExt;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

#[tokio::test]
async fn challenge_and_object_routes_enforce_vault_scope() {
    let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    // Explicitly exercise the legacy migration mode; production defaults to
    // strict authorization when the variable is absent.
    std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");
    std::env::remove_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN");
    let root = std::env::temp_dir().join(format!("cv-http-auth-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "http-auth".into(),
        root.clone(),
        generate_signing_key(),
    ));
    let app = create_router(state);
    let device_key = generate_signing_key();
    let vault_id = "11".repeat(32);
    let public_key = hex::encode(device_key.verifying_key().as_bytes());

    let challenge_response = app
        .clone()
        .oneshot(
            Request::post("/v1/challenges")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "vault_id_hex": vault_id.clone(),
                        "public_key_hex": public_key.clone(),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge = response_json(challenge_response).await;
    let nonce = hex::decode(challenge["nonce_hex"].as_str().unwrap()).unwrap();
    let signature = hex::encode(sign_with_domain(&device_key, b"operator_challenge", &nonce));
    let session_response = app
        .clone()
        .oneshot(
            Request::post("/v1/sessions")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "challenge_id": challenge["challenge_id"],
                        "public_key_hex": public_key.clone(),
                        "signature_hex": signature,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_response.status(), StatusCode::OK);
    let session = response_json(session_response).await;
    let token = session["token"].as_str().unwrap();
    let cid = hex::encode(ciphervault_format::compute_digest(b"bound-object"));

    let missing_scope = app
        .clone()
        .oneshot(
            Request::put(format!("/v1/objects/{cid}").as_str())
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from("bound-object"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_scope.status(), StatusCode::BAD_REQUEST);

    let wrong_scope = app
        .clone()
        .oneshot(
            Request::put(format!("/v1/objects/{cid}").as_str())
                .header("authorization", format!("Bearer {token}"))
                .header("x-ciphervault-id", "22".repeat(32))
                .body(Body::from("bound-object"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_scope.status(), StatusCode::UNAUTHORIZED);

    let valid = app
        .oneshot(
            Request::put(format!("/v1/objects/{cid}").as_str())
                .header("authorization", format!("Bearer {token}"))
                .header("x-ciphervault-id", vault_id)
                .body(Body::from("bound-object"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);
    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn strict_control_routes_require_a_session_or_service_token() {
    let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "true");
    let root = std::env::temp_dir().join(format!("cv-http-control-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "http-control".into(),
        root.clone(),
        generate_signing_key(),
    ));
    let app = create_router(state);

    let unauthorized = app
        .clone()
        .oneshot(Request::get("/v1/peers").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    std::env::set_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", "test-service-token");
    let authorized = app
        .oneshot(
            Request::get("/v1/peers")
                .header("x-ciphervault-service-token", "test-service-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    std::env::remove_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn strict_challenges_require_persisted_enrollment() {
    let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "true");
    std::env::set_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", "identity-admin-token");
    let root = std::env::temp_dir().join(format!("cv-http-enrollment-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "http-enrollment".into(),
        root.clone(),
        generate_signing_key(),
    ));
    let app = create_router(state);
    let device_key = generate_signing_key();
    let vault_id = "33".repeat(32);
    let public_key = hex::encode(device_key.verifying_key().as_bytes());
    let account_id = format!("cvacct_{}", "44".repeat(16));
    let device_id = "55".repeat(32);
    let challenge_body = serde_json::to_vec(&json!({
        "vault_id_hex": vault_id.clone(),
        "public_key_hex": public_key.clone(),
    }))
    .unwrap();

    let rejected = app
        .clone()
        .oneshot(
            Request::post("/v1/challenges")
                .header("content-type", "application/json")
                .body(Body::from(challenge_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let enrolled = app
        .clone()
        .oneshot(
            Request::post("/v1/identities")
                .header("content-type", "application/json")
                .header("x-ciphervault-service-token", "identity-admin-token")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "vault_id_hex": vault_id.clone(),
                        "public_key_hex": public_key.clone(),
                        "account_id": account_id.clone(),
                        "device_id_hex": device_id.clone(),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enrolled.status(), StatusCode::NO_CONTENT);

    let still_rejected_without_binding = app
        .clone()
        .oneshot(
            Request::post("/v1/challenges")
                .header("content-type", "application/json")
                .body(Body::from(challenge_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        still_rejected_without_binding.status(),
        StatusCode::BAD_REQUEST
    );

    let challenge = app
        .clone()
        .oneshot(
            Request::post("/v1/challenges")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "vault_id_hex": vault_id.clone(),
                        "public_key_hex": public_key.clone(),
                        "account_id": account_id.clone(),
                        "device_id_hex": device_id.clone(),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge_json = response_json(challenge).await;
    let nonce = hex::decode(challenge_json["nonce_hex"].as_str().unwrap()).unwrap();
    let signature = hex::encode(sign_with_domain(&device_key, b"operator_challenge", &nonce));
    let session = app
        .clone()
        .oneshot(
            Request::post("/v1/sessions")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "challenge_id": challenge_json["challenge_id"],
                        "public_key_hex": public_key.clone(),
                        "signature_hex": signature,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    let session_json = response_json(session).await;
    let session_token = session_json["token"].as_str().unwrap().to_string();

    let revoked = app
        .clone()
        .oneshot(
            Request::post("/v1/identities/revoke")
                .header("content-type", "application/json")
                .header("x-ciphervault-service-token", "identity-admin-token")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "vault_id_hex": vault_id,
                        "public_key_hex": public_key,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let cid = hex::encode(ciphervault_format::compute_digest(b"revoked-device"));
    let revoked_session = app
        .oneshot(
            Request::put(format!("/v1/objects/{cid}").as_str())
                .header("authorization", format!("Bearer {session_token}"))
                .header("x-ciphervault-id", "33".repeat(32))
                .body(Body::from("revoked-device"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked_session.status(), StatusCode::UNAUTHORIZED);

    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    std::env::remove_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn error_bodies_use_json_envelope() {
    let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    std::env::remove_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN");
    let root = std::env::temp_dir().join(format!("cv-http-envelope-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "http-envelope".into(),
        root.clone(),
        generate_signing_key(),
    ));
    let app = create_router(state);

    let denied = app
        .oneshot(
            Request::get(format!("/v1/objects/{}", "ab".repeat(32)).as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let content_type = denied
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("application/json"),
        "error content-type: {content_type}"
    );
    let body = to_bytes(denied.into_body(), 64 * 1024).await.unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&body).expect("error body is JSON");
    assert_eq!(envelope["code"], 401);
    assert!(
        envelope["error"].as_str().is_some_and(|m| !m.is_empty()),
        "envelope carries the human message: {envelope}"
    );
    let _ = std::fs::remove_dir_all(root);
}
