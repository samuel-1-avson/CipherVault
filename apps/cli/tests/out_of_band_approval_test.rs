use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};
use ciphervault_recovery::{ApprovalAction, ApprovalChallenge, SignedApprovalReceipt};
use std::sync::Arc;

async fn spawn_operator() -> (String, Arc<OperatorState>, tokio::task::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!("cv-oob-auth-{}", rand::random::<u64>()));
    let signing_key = generate_signing_key();
    let state = Arc::new(OperatorState::new(
        "operator-gatekeeper".to_string(),
        dir,
        signing_key,
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);

    let router = create_router(state.clone());
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (endpoint, state, handle)
}

#[tokio::test]
async fn test_out_of_band_approval_challenge_lifecycle() {
    let (endpoint, state, _handle) = spawn_operator().await;
    let client = reqwest::Client::new();

    let vault_id = [0x42u8; 32];
    let session_nonce = [0x11u8; 32];
    let details = "Emergency recovery requested by ops-lead-01".to_string();

    // 1. Create a 600-second approval challenge
    let challenge = ApprovalChallenge::new(
        &vault_id,
        ApprovalAction::EmergencyRecovery,
        &session_nonce,
        details.clone(),
        600,
    );
    let challenge_id = challenge.challenge_id.clone();

    // 2. Register challenge with operator node
    let post_url = format!("{}/v1/auth/challenges", endpoint);
    let resp = client
        .post(&post_url)
        .json(&challenge)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to register challenge");

    // 3. Query pending challenges
    let pending_url = format!("{}/v1/auth/challenges/pending", endpoint);
    let resp = client.get(&pending_url).send().await.unwrap();
    assert!(resp.status().is_success());
    let pending: Vec<ApprovalChallenge> = resp.json().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].challenge_id, challenge_id);
    assert_eq!(pending[0].details, details);

    // 4. Query individual challenge status before approval
    let status_url = format!("{}/v1/auth/challenges/{}", endpoint, challenge_id);
    let resp = client.get(&status_url).send().await.unwrap();
    assert!(resp.status().is_success());
    let status_json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status_json["approved"], false);
    assert_eq!(status_json["receipt_count"], 0);

    // 5. Team Lead / Guardian signs the approval receipt
    let approver_key = generate_signing_key();
    let receipt =
        SignedApprovalReceipt::sign(&challenge, "Alice Guardian Lead".to_string(), &approver_key);

    // 6. Submit valid approval receipt
    let approve_url = format!("{}/v1/auth/challenges/{}/approve", endpoint, challenge_id);
    let resp = client
        .post(&approve_url)
        .json(&receipt)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Failed to submit valid approval receipt"
    );

    // 7. Verify challenge is now approved
    let resp = client.get(&status_url).send().await.unwrap();
    let status_json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status_json["approved"], true);
    assert_eq!(status_json["receipt_count"], 1);
    let receipts = status_json["receipts"].as_array().unwrap();
    assert_eq!(receipts[0]["approver_name"], "Alice Guardian Lead");

    // 8. Test invalid signature rejection: tampered receipt
    let mut bad_receipt = receipt.clone();
    bad_receipt.approver_name = "Mallory Hacker".to_string(); // Modifying name invalidates Ed25519 signature
    let resp = client
        .post(&approve_url)
        .json(&bad_receipt)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Tampered signature should be rejected"
    );

    // 9. Verify pending list no longer includes approved challenge (since it is already approved)
    let resp = client.get(&pending_url).send().await.unwrap();
    let pending: Vec<ApprovalChallenge> = resp.json().await.unwrap();
    assert_eq!(
        pending.len(),
        0,
        "Approved challenge should not remain in pending list"
    );

    // Clean up
    let _ = std::fs::remove_dir_all(&state.data_dir);
}
