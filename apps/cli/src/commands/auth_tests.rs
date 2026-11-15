// Copyright (c) 2026 Samuel Avornyoh and CipherVault Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::Json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const FIXTURE_CREDENTIAL: &str = "test-only-hosted-session-credential";
const FIXTURE_CODE: &str = "123456";

#[derive(Clone)]
struct Service {
    account_id: String,
    public_key: [u8; 32],
    required: bool,
    accept_code: bool,
    verified: Arc<AtomicBool>,
    paths: Arc<Mutex<Vec<String>>>,
}

async fn handle(
    State(service): State<Service>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    service.paths.lock().unwrap().push(uri.path().to_owned());
    let input: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    match uri.path() {
        "/sessions/challenge" => {
            assert!(input["device_id_hex"].is_null());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "challenge_id": "fixture-challenge", "nonce_hex": "00".repeat(32),
                })),
            )
        }
        "/sessions/login" => {
            let signing_bytes = serde_json::to_vec(&(
                &service.account_id,
                Option::<&str>::None,
                Option::<&str>::None,
                "fixture-challenge",
                "00".repeat(32),
            ))
            .unwrap();
            let signature: [u8; 64] = hex::decode(input["signature_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            assert!(
                ciphervault_crypto::signatures::verify_with_domain(
                    &service.public_key,
                    b"account_login",
                    &signing_bytes,
                    &signature,
                )
                .is_ok(),
                "hosted primary proof must use the service's exact construction"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "token": FIXTURE_CREDENTIAL, "session": {"mfa_required": service.required},
                })),
            )
        }
        "/session/mfa/totp" => {
            let authorized = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix(concat!("Bearer", " ")))
                == Some(FIXTURE_CREDENTIAL);
            assert!(authorized, "MFA must verify the same primary session");
            if service.accept_code && input["code"] == FIXTURE_CODE {
                service.verified.store(true, Ordering::SeqCst);
                (
                    StatusCode::OK,
                    Json(serde_json::json!({"status": "verified"})),
                )
            } else {
                // Even a server error that echoes input must not enter diagnostics.
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "code": "MFA_CODE_INVALID", "error": input["code"],
                    })),
                )
            }
        }
        _ => (StatusCode::NOT_FOUND, Json(serde_json::json!({}))),
    }
}

struct Fixture {
    root: PathBuf,
    account: AccountStore,
    endpoint: String,
    service: Service,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(required: bool, accept_code: bool) -> Self {
        let root =
            std::env::temp_dir().join(format!("cv-hosted-mfa-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&root).unwrap();
        let account =
            AccountStore::create(Some("Fixture account"), Some(root.join("account.json"))).unwrap();
        let service = Service {
            account_id: account.account_id().to_owned(),
            public_key: hex::decode(account.public_key_hex())
                .unwrap()
                .try_into()
                .unwrap(),
            required,
            accept_code,
            verified: Arc::new(AtomicBool::new(false)),
            paths: Arc::new(Mutex::new(Vec::new())),
        };
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(service.clone());
        let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
        let endpoint = format!("http://localhost:{}", listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            root,
            account,
            endpoint,
            service,
            server,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        std::fs::remove_dir_all(&self.root).expect("remove generated account fixture");
    }
}

#[tokio::test]
async fn required_mfa_is_verified_for_the_primary_session_before_it_is_returned() {
    let fixture = Fixture::new(true, true).await;
    let prompts = AtomicUsize::new(0);
    let result = hosted_account_login(
        &HttpClient::new(),
        &fixture.endpoint,
        &fixture.account,
        || {
            prompts.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(FIXTURE_CODE.to_owned()))
        },
    )
    .await;
    assert!(result.is_ok());
    assert!(
        fixture.service.verified.load(Ordering::SeqCst),
        "required MFA was never verified"
    );
    assert_eq!(prompts.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.service.paths.lock().unwrap().as_slice(),
        [
            "/sessions/challenge",
            "/sessions/login",
            "/session/mfa/totp"
        ]
    );
}

#[tokio::test]
async fn optional_mfa_does_not_request_an_authenticator_code() {
    let fixture = Fixture::new(false, false).await;
    let result = hosted_account_login(
        &HttpClient::new(),
        &fixture.endpoint,
        &fixture.account,
        || panic!("optional MFA must not request a code"),
    )
    .await;
    assert!(result.is_ok());
    assert!(!fixture.service.verified.load(Ordering::SeqCst));
}

#[tokio::test]
async fn rejected_mfa_does_not_release_a_session_or_echo_the_code() {
    let fixture = Fixture::new(true, false).await;
    let result = hosted_account_login(
        &HttpClient::new(),
        &fixture.endpoint,
        &fixture.account,
        || Ok(Zeroizing::new(FIXTURE_CODE.to_owned())),
    )
    .await;
    assert!(
        result.is_err(),
        "MFA rejection must stop connection before enrollment"
    );
    let message = result.err().unwrap().to_string();
    assert!(!message.contains(FIXTURE_CODE));
    assert!(!message.contains(FIXTURE_CREDENTIAL));
}

#[tokio::test]
async fn unavailable_interactive_input_stops_required_mfa() {
    let fixture = Fixture::new(true, true).await;
    let result = hosted_account_login(
        &HttpClient::new(),
        &fixture.endpoint,
        &fixture.account,
        || bail!("interactive input unavailable"),
    )
    .await;
    assert!(result.is_err());
    assert!(!fixture.service.verified.load(Ordering::SeqCst));
}
