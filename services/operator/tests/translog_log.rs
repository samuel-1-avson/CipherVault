//! ADR-014 Phase 2 acceptance: a fleet of operator logs accepts
//! authenticated submissions, serves checkpoints/tiles/proofs that
//! verify with the Phase 1 client, survives restart without losing or
//! reordering entries, and rejects unauthenticated or over-limit
//! submissions.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
use ciphervault_operator::{
    create_router,
    log_store::LogConfig,
    state::{OperatorSecurityConfig, PERMISSION_VAULT_DEFAULT},
    OperatorState,
};
use ciphervault_translog::{open_checkpoint, Ed25519NoteVerifier, LogEntry};
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use tower::ServiceExt;

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("cv-tlog-{tag}-{}", rand::random::<u128>()))
}

fn state_with_log(
    root: &std::path::Path,
    operator_id: &str,
    operator_key: &SigningKey,
    origin: &str,
    limit: u32,
) -> Arc<OperatorState> {
    Arc::new(OperatorState::new_with_options(
        operator_id.into(),
        root.to_path_buf(),
        operator_key.clone(),
        OperatorSecurityConfig::from_flags(None, None),
        LogConfig {
            origin: Some(origin.into()),
            add_limit_per_min: limit,
        },
    ))
}

/// Enrolls one device and returns its session token.
fn session(state: &OperatorState, key: &SigningKey, vault: &str) -> String {
    let pk = hex::encode(key.verifying_key().as_bytes());
    state
        .enroll_identity_with_binding(vault, &pk, PERMISSION_VAULT_DEFAULT, None, None)
        .unwrap();
    let (challenge, nonce, _) = state
        .issue_challenge_with_binding(vault, &pk, None, None)
        .unwrap();
    state
        .verify_and_create_session(
            &challenge,
            &pk,
            &hex::encode(sign_with_domain(
                key,
                b"operator_challenge",
                &hex::decode(nonce).unwrap(),
            )),
        )
        .unwrap()
        .unwrap()
}

async fn submit(
    router: axum::Router,
    token: Option<&str>,
    vault: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/log/add")
        .header("content-type", "application/json")
        .header("x-ciphervault-id", vault);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = router
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn get_bytes(router: axum::Router, path: &str) -> (StatusCode, Vec<u8>) {
    let response = router
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

async fn get_json(router: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let (status, bytes) = get_bytes(router, path).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn hex32(value: &serde_json::Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// Opens the served checkpoint with the log key from `/v1/log/info`.
async fn verified_checkpoint(router: axum::Router) -> (String, Vec<u8>, u64, [u8; 32]) {
    let (status, info) = get_json(router.clone(), "/v1/log/info").await;
    assert_eq!(status, StatusCode::OK);
    let verifier = Ed25519NoteVerifier::from_vkey(info["verifier_key"].as_str().unwrap()).unwrap();
    let (status, checkpoint_bytes) = get_bytes(router, "/v1/log/checkpoint").await;
    assert_eq!(status, StatusCode::OK);
    let verified = open_checkpoint(
        &checkpoint_bytes,
        info["origin"].as_str().unwrap(),
        &verifier,
        &[],
    )
    .unwrap();
    (
        info["origin"].as_str().unwrap().to_string(),
        checkpoint_bytes,
        verified.checkpoint().size(),
        *verified.checkpoint().root(),
    )
}

#[tokio::test]
async fn fleet_of_three_logs_accepts_and_proves_submissions() {
    let device = generate_signing_key();
    let vault = "aa".repeat(32);
    for op in 0..3u8 {
        let root = fresh_dir(&format!("fleet{op}"));
        let state = state_with_log(
            &root,
            &format!("op{}", op + 1),
            &generate_signing_key(),
            &format!("log{}.example/log", op + 1),
            0,
        );
        let token = session(&state, &device, &vault);
        let router = create_router(state);
        let commitment = [10 + op; 32];

        let (status, receipt) = submit(
            router.clone(),
            Some(&token),
            &vault,
            serde_json::json!({"commitment": hex::encode(commitment)}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["index"], 0);
        assert_eq!(receipt["tree_size"], 1);
        assert_eq!(
            hex32(&receipt["leaf_hash"]),
            LogEntry::untagged(commitment).leaf_hash()
        );

        let (_, _, size, root_hash) = verified_checkpoint(router.clone()).await;
        assert_eq!(size, 1);
        assert_eq!(hex32(&receipt["root"]), root_hash);

        let (status, proof) = get_json(router.clone(), "/v1/log/inclusion/0").await;
        assert_eq!(status, StatusCode::OK, "{proof}");
        let proof_hashes: Vec<[u8; 32]> = proof["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(hex32)
            .collect();
        ciphervault_translog::verify_inclusion(
            &hex32(&proof["leaf_hash"]),
            0,
            size,
            &proof_hashes,
            &root_hash,
        )
        .unwrap();

        // Level-0 partial tile is exactly the leaf hash; the entry
        // bundle is exactly the submitted entry bytes.
        let (status, tile) = get_bytes(router.clone(), "/v1/log/tile/0/000.p/1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tile, LogEntry::untagged(commitment).leaf_hash().to_vec());
        let (status, bundle) = get_bytes(router.clone(), "/v1/log/tile/entries/000.p/1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bundle, LogEntry::untagged(commitment).to_bytes().to_vec());
        // A full-width request for a partial tile does not exist.
        let (status, _) = get_bytes(router.clone(), "/v1/log/tile/0/000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, lookup) = get_json(
            router,
            &format!("/v1/log/lookup/{}", hex::encode(commitment)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(lookup["indices"], serde_json::json!([0]));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn unauthenticated_malformed_and_tagged_submissions_are_rejected() {
    let root = fresh_dir("auth");
    let device = generate_signing_key();
    let vault = "bb".repeat(32);
    let state = state_with_log(
        &root,
        "op-auth",
        &generate_signing_key(),
        "auth.example/log",
        0,
    );
    let token = session(&state, &device, &vault);
    let router = create_router(state);
    let commitment = hex::encode([7u8; 32]);

    // No session at all.
    let (status, _) = submit(
        router.clone(),
        None,
        &vault,
        serde_json::json!({"commitment": commitment}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A bogus token.
    let (status, _) = submit(
        router.clone(),
        Some("bogus"),
        &vault,
        serde_json::json!({"commitment": commitment}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Authenticated but malformed commitment.
    let (status, _) = submit(
        router.clone(),
        Some(&token),
        &vault,
        serde_json::json!({"commitment": "zz"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Non-zero monitor tags are reserved for Phase 5.
    let (status, _) = submit(
        router.clone(),
        Some(&token),
        &vault,
        serde_json::json!({
            "commitment": commitment,
            "monitor_tag": hex::encode([1u8; 32]),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // None of the rejections consumed an index.
    let (status, receipt) = submit(
        router.clone(),
        Some(&token),
        &vault,
        serde_json::json!({"commitment": commitment}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["index"], 0);

    // Proofs fail closed for positions the tree does not have.
    let (status, _) = get_json(router, "/v1/log/inclusion/5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn per_device_rate_limit_rejects_the_third_submission() {
    let root = fresh_dir("rate");
    let device = generate_signing_key();
    let other_device = generate_signing_key();
    let vault = "cc".repeat(32);
    let state = state_with_log(
        &root,
        "op-rate",
        &generate_signing_key(),
        "rate.example/log",
        2,
    );
    let token = session(&state, &device, &vault);
    let other_token = session(&state, &other_device, &vault);
    let router = create_router(state);

    for index in 0..2u8 {
        let (status, receipt) = submit(
            router.clone(),
            Some(&token),
            &vault,
            serde_json::json!({"commitment": hex::encode([index; 32])}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
    }
    let (status, _) = submit(
        router.clone(),
        Some(&token),
        &vault,
        serde_json::json!({"commitment": hex::encode([9u8; 32])}),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // The limit is per device: the second device still submits, and the
    // rejected attempt consumed no index.
    let (status, receipt) = submit(
        router.clone(),
        Some(&other_token),
        &vault,
        serde_json::json!({"commitment": hex::encode([9u8; 32])}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["index"], 2);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn restart_preserves_order_root_and_proofs() {
    let root = fresh_dir("restart");
    let operator_key = generate_signing_key();
    let device = generate_signing_key();
    let vault = "dd".repeat(32);
    let root_after_two: [u8; 32];
    let root_after_four: [u8; 32];
    {
        let state = state_with_log(&root, "op-re", &operator_key, "re.example/log", 0);
        let token = session(&state, &device, &vault);
        let router = create_router(state);
        for byte in 1..=2u8 {
            let (status, _) = submit(
                router.clone(),
                Some(&token),
                &vault,
                serde_json::json!({"commitment": hex::encode([byte; 32])}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        root_after_two = verified_checkpoint(router.clone()).await.3;
        for byte in 3..=4u8 {
            let (status, _) = submit(
                router.clone(),
                Some(&token),
                &vault,
                serde_json::json!({"commitment": hex::encode([byte; 32])}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        root_after_four = verified_checkpoint(router).await.3;
    }
    // Restart: same data dir, same operator key. Entries, order and
    // roots are identical, and the size-2 tree is still provably a
    // prefix of the size-4 tree after the restart.
    let state = state_with_log(&root, "op-re", &operator_key, "re.example/log", 0);
    let router = create_router(state);
    let (_, _, size, root_hash) = verified_checkpoint(router.clone()).await;
    assert_eq!(size, 4);
    assert_eq!(root_hash, root_after_four);

    let (status, consistency) = get_json(router.clone(), "/v1/log/consistency?from=2&to=4").await;
    assert_eq!(status, StatusCode::OK, "{consistency}");
    let proof: Vec<[u8; 32]> = consistency["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(hex32)
        .collect();
    ciphervault_translog::verify_consistency(2, 4, &proof, &root_after_two, &root_after_four)
        .unwrap();

    for byte in 1..=4u8 {
        let (status, inclusion) =
            get_json(router.clone(), &format!("/v1/log/inclusion/{}", byte - 1)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            hex32(&inclusion["leaf_hash"]),
            LogEntry::untagged([byte; 32]).leaf_hash()
        );
        let (status, lookup) = get_json(
            router.clone(),
            &format!("/v1/log/lookup/{}", hex::encode([byte; 32])),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(lookup["indices"], serde_json::json!([byte - 1]));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn damaged_log_key_takes_only_the_log_endpoints_down() {
    let root = fresh_dir("damaged");
    let operator_key = generate_signing_key();
    {
        let _state = state_with_log(&root, "op-bad", &operator_key, "bad.example/log", 0);
    }
    std::fs::write(root.join("log").join("log.key"), b"too short").unwrap();
    let state = state_with_log(&root, "op-bad", &operator_key, "bad.example/log", 0);
    assert!(state.transparency_log().is_err());
    let router = create_router(state);
    let (status, _) = get_bytes(router.clone(), "/v1/log/checkpoint").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = get_json(router, "/v1/log/info").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    std::fs::remove_dir_all(root).unwrap();
}
