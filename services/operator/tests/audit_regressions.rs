use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
use ciphervault_format::{to_canonical_cbor, GenesisRecord, PROTOCOL_VERSION};
use ciphervault_operator::{
    create_router,
    state::{OperatorSecurityConfig, PERMISSION_READ, PERMISSION_VAULT_DEFAULT},
    OperatorState,
};
use ciphervault_storage::{types::RecoveryRecordsResponse, OperatorClient};
use ed25519_dalek::SigningKey;
use std::{io::Write, sync::Arc};
use tower05::ServiceExt;

fn strict_state(root: &std::path::Path, key: &SigningKey) -> OperatorState {
    OperatorState::new_with_security(
        "audit-operator".into(),
        root.to_path_buf(),
        key.clone(),
        OperatorSecurityConfig::from_flags(None, None),
    )
}

fn session(
    state: &OperatorState,
    key: &SigningKey,
    vault: &str,
    binding: Option<(&str, &str)>,
) -> String {
    let pk = hex::encode(key.verifying_key().as_bytes());
    let (account, device) = binding
        .map(|(account, device)| (Some(account), Some(device)))
        .unwrap_or_default();
    state
        .enroll_identity_with_binding(vault, &pk, PERMISSION_VAULT_DEFAULT, account, device)
        .unwrap();
    let (challenge, nonce, _) = state
        .issue_challenge_with_binding(vault, &pk, account, device)
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

fn authorized(method: &str, path: &str, token: &str, vault: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-ciphervault-id", vault)
        .body(body)
        .unwrap()
}

#[test]
fn security_default_matrix_fails_closed() {
    let default = OperatorSecurityConfig::from_flags(None, None);
    assert!(default.strict_auth && default.require_enrollment);
    let migration = OperatorSecurityConfig::from_flags(Some("false"), None);
    assert!(!migration.strict_auth && !migration.require_enrollment);
    assert!(OperatorSecurityConfig::from_flags(Some("false"), Some("true")).require_enrollment);
    assert!(OperatorSecurityConfig::from_flags(Some("typo"), Some("false")).require_enrollment);
}

#[tokio::test]
async fn bound_login_put_get_restart_permissions_and_revocation() {
    let root = std::env::temp_dir().join(format!("cv-audit-binding-{}", rand::random::<u128>()));
    let operator = generate_signing_key();
    let key = generate_signing_key();
    let vault = "12".repeat(32);
    let account = format!("cvacct_{}", "23".repeat(16));
    let device = "34".repeat(32);
    let state = Arc::new(strict_state(&root, &operator));
    let token = session(&state, &key, &vault, Some((&account, &device)));
    let cid = hex::encode(ciphervault_format::compute_digest(b"synthetic ciphertext"));
    let app = create_router(state.clone());
    let response = app
        .clone()
        .oneshot(authorized(
            "PUT",
            &format!("/v1/objects/{cid}"),
            &token,
            &vault,
            Body::from("synthetic ciphertext"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        app.clone()
            .oneshot(authorized(
                "GET",
                &format!("/v1/objects/{cid}"),
                &token,
                &vault,
                Body::empty()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(authorized(
                "GET",
                "/v1/peers/membership",
                &token,
                &vault,
                Body::empty()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    drop(app);
    drop(state);
    let state = Arc::new(strict_state(&root, &operator));
    let app = create_router(state.clone());
    assert_eq!(
        app.clone()
            .oneshot(authorized(
                "GET",
                &format!("/v1/objects/{cid}"),
                &token,
                &vault,
                Body::empty()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    state
        .enroll_identity(
            &vault,
            &hex::encode(key.verifying_key().as_bytes()),
            PERMISSION_READ,
        )
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(authorized(
                "PUT",
                &format!("/v1/objects/{cid}"),
                &token,
                &vault,
                Body::from("synthetic ciphertext")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    state
        .revoke_identity(&vault, &hex::encode(key.verifying_key().as_bytes()))
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(authorized(
                "GET",
                &format!("/v1/objects/{cid}"),
                &token,
                &vault,
                Body::empty()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    drop(app);
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn lease_owner_cannot_be_reassigned_or_renewed_by_another_vault() {
    let root = std::env::temp_dir().join(format!("cv-audit-owner-{}", rand::random::<u128>()));
    let key = generate_signing_key();
    let state = strict_state(&root, &key);
    let owner = "45".repeat(32);
    let attacker = "56".repeat(32);
    let receipt = state.create_lease(&"67".repeat(32), 100, 30).unwrap();
    state.record_lease_owner(&receipt.lease_id, &owner).unwrap();
    assert!(state
        .record_lease_owner(&receipt.lease_id, &attacker)
        .is_err());
    assert!(state
        .renew_owned_lease_with_voucher(&receipt.lease_id, 30, 100, &attacker, None)
        .is_err());
    drop(state);
    let restarted = strict_state(&root, &key);
    let renewed = restarted
        .renew_owned_lease_with_voucher(&receipt.lease_id, 30, 100, &owner, None)
        .unwrap();
    renewed.verify(&key.verifying_key().to_bytes()).unwrap();
    assert_eq!(restarted.list_leases_for_vault(&owner).len(), 1);
    assert!(restarted.list_leases_for_vault(&attacker).is_empty());
    drop(restarted);
    std::fs::remove_dir_all(root).unwrap();
}

fn genesis(key: &SigningKey, label: &str) -> Vec<u8> {
    let mut record = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![1; 32],
        recovery_signing_pk: key.verifying_key().to_bytes().to_vec(),
        recovery_encryption_pk: vec![2; 32],
        policy_digest: vec![3; 32],
        creation_nonce: label.as_bytes().to_vec(),
        created_at_utc: 1,
        signature: vec![],
    };
    record.sign(key).unwrap();
    to_canonical_cbor(&record).unwrap()
}

#[test]
fn first_genesis_is_atomic_and_torn_tail_is_recovered_before_append() {
    let root = std::env::temp_dir().join(format!("cv-audit-append-{}", rand::random::<u128>()));
    let state = Arc::new(strict_state(&root, &generate_signing_key()));
    let locator = "78".repeat(32);
    let records = [
        genesis(&generate_signing_key(), "first"),
        genesis(&generate_signing_key(), "other"),
    ];
    let gate = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = records
        .iter()
        .cloned()
        .map(|record| {
            let (state, locator, gate) = (state.clone(), locator.clone(), gate.clone());
            std::thread::spawn(move || {
                gate.wait();
                state.append_recovery_record(&locator, &record)
            })
        })
        .collect();
    let successes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
    let committed = state.get_recovery_records(&locator);
    assert_eq!(committed.len(), 1);
    let path = root.join("recovery").join(format!("{locator}.log"));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(&100u32.to_be_bytes()).unwrap();
    file.write_all(b"torn").unwrap();
    file.sync_all().unwrap();
    drop(file);
    drop(state);
    let state = strict_state(&root, &generate_signing_key());
    assert!(state.get_recovery_page(&locator, 0).is_err());
    assert_eq!(
        state
            .append_recovery_record(&locator, &committed[0])
            .unwrap(),
        2
    );
    assert_eq!(
        state.get_recovery_page(&locator, 0).unwrap().records,
        vec![committed[0].clone(), committed[0].clone()]
    );
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn http_recovery_pages_include_records_beyond_the_first_page() {
    let root = std::env::temp_dir().join(format!("cv-audit-pages-{}", rand::random::<u128>()));
    let state = Arc::new(strict_state(&root, &generate_signing_key()));
    let locator = [0x89; 32];
    let locator_hex = hex::encode(locator);
    let mut file =
        std::fs::File::create(root.join("recovery").join(format!("{locator_hex}.log"))).unwrap();
    let first = genesis(&generate_signing_key(), &"a".repeat(40_000));
    let last = genesis(&generate_signing_key(), "last-record");
    for record in std::iter::repeat_n(&first, 40).chain(std::iter::once(&last)) {
        file.write_all(&(record.len() as u32).to_be_bytes())
            .unwrap();
        file.write_all(record).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    let app = create_router(state);
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/v1/recovery/{locator_hex}/records"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 3 * 1024 * 1024)
        .await
        .unwrap();
    let page: RecoveryRecordsResponse = serde_json::from_slice(&body).unwrap();
    assert!(page.truncated && page.next_cursor.is_some());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let records = OperatorClient::new(endpoint)
        .get_recovery_records(&locator)
        .await
        .unwrap();
    assert_eq!(records.len(), 41);
    assert_eq!(records.last(), Some(&last));
    task.abort();
    let _ = task.await;
    std::fs::remove_dir_all(root).unwrap();
}
