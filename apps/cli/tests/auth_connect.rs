// Copyright (c) 2026 Samuel Avornyoh and CipherVault Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Account connection must authenticate before attempting protected enrollment.
//! All identities, responses, and session credentials below are test fixtures.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::Json;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Command;

const SESSION_CREDENTIAL: &str = "test-only-session-not-a-real-credential";
const BROWSER_CREDENTIAL: &str = "test-only-browser-session-not-a-real-credential";

#[derive(Clone, Default)]
struct Stub {
    requests: Arc<Mutex<Vec<String>>>,
    mfa_required: bool,
}

async fn account_stub(
    State(stub): State<Stub>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let path = uri.path();
    stub.requests.lock().unwrap().push(path.to_string());
    let input: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    if path == "/api/account/register" {
        return (StatusCode::CONFLICT, Json(serde_json::json!({})));
    }
    if path.ends_with("/challenge") {
        if path == "/api/account/sessions/challenge" {
            let first_login = stub
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|path| path.ends_with("/sessions/challenge"))
                .count()
                == 1;
            assert_eq!(
                input["device_id_hex"].is_null(),
                first_login,
                "bootstrap is account-only; the browser handoff must remain device-bound"
            );
        }
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "challenge_id": "test-challenge",
                "nonce_hex": "00".repeat(32),
            })),
        );
    }
    if path == "/api/account/sessions/login" {
        let first_login = stub
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with("/sessions/login"))
            .count()
            == 1;
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "token": if first_login { SESSION_CREDENTIAL } else { BROWSER_CREDENTIAL },
                "session": {"mfa_required": stub.mfa_required},
            })),
        );
    }
    let expected = if path.ends_with("/sessions/handoff") {
        BROWSER_CREDENTIAL
    } else {
        SESSION_CREDENTIAL
    };
    let authenticated = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(concat!("Bearer", " ")))
        == Some(expected);
    if path.ends_with("/devices") && !authenticated {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": "MFA_STEP_UP_REQUIRED",
                "error": "Required MFA also protects account-signed device enrollment",
            })),
        );
    }
    assert!(authenticated, "protected requests need the hosted session");
    if path.ends_with("/devices") {
        return (StatusCode::CREATED, Json(serde_json::json!({})));
    }
    if path.ends_with("/vaults") {
        return (StatusCode::OK, Json(serde_json::json!({})));
    }
    if path == "/api/account/sessions/handoff" {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"handoff_code": "00".repeat(32)})),
        );
    }
    (StatusCode::NOT_FOUND, Json(serde_json::json!({})))
}

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("cv-auth-connect-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ciphervault"));
        command
            .current_dir(&self.0)
            .env("CIPHERVAULT_ACCOUNT_DIR", self.0.join("account"))
            .env_remove("CIPHERVAULT_ACCOUNT_PATH")
            .env_remove("CIPHERVAULT_ACCOUNT_ENDPOINT")
            .env_remove("CIPHERVAULT_DPOP_REQUIRED")
            .env_remove("CIPHERVAULT_DPOP_KEY")
            .env("NO_COLOR", "1");
        command
    }

    async fn initialize(&self) {
        let account = self
            .command()
            .args(["auth", "init", "--name", "Test account"])
            .output()
            .await
            .unwrap();
        assert!(account.status.success(), "test account setup failed");
        // Capture and discard key-ceremony output: no kit material in test logs.
        let vault = self
            .command()
            .args(["init", "--operators", "http://127.0.0.1:1"])
            .output()
            .await
            .unwrap();
        assert!(vault.status.success(), "test vault setup failed");
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn connect_authenticates_before_enrollment_and_keeps_bound_browser_handoff() {
    let workspace = Workspace::new();
    workspace.initialize().await;
    let stub = Stub::default();
    let app = axum::Router::new()
        .fallback(account_stub)
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let endpoint = format!(
        "http://localhost:{}/api/account",
        listener.local_addr().unwrap().port()
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let output = workspace
        .command()
        .args([
            "auth",
            "connect",
            "--endpoint",
            &endpoint,
            "--label",
            "test device",
            "--vault-alias",
            "Test vault",
        ])
        .output()
        .await
        .unwrap();
    server.abort();
    assert!(
        output.status.success(),
        "connect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = stub.requests.lock().unwrap();
    let login = requests
        .iter()
        .position(|path| path.ends_with("/sessions/login"))
        .expect("hosted login");
    let enrollment = requests
        .iter()
        .position(|path| path.ends_with("/devices"))
        .expect("device enrollment");
    assert!(
        login < enrollment,
        "hosted authentication must precede enrollment"
    );
    let vault_link = requests
        .iter()
        .position(|path| path.ends_with("/vaults"))
        .expect("vault link");
    let final_login = requests
        .iter()
        .rposition(|path| path.ends_with("/sessions/login"))
        .unwrap();
    assert!(
        final_login > vault_link,
        "do not replace the verified bootstrap session until sensitive operations finish"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.ends_with("/sessions/login"))
            .count(),
        2
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("account connected to hosted service"));
    assert!(
        !stdout.contains(SESSION_CREDENTIAL),
        "session credentials must never be printed"
    );
    assert!(
        !stdout.contains(BROWSER_CREDENTIAL),
        "browser credentials must never be printed"
    );
}

#[tokio::test]
async fn required_mfa_with_null_stdin_exits_without_prompt_or_enrollment() {
    let workspace = Workspace::new();
    workspace.initialize().await;
    let stub = Stub {
        mfa_required: true,
        ..Stub::default()
    };
    let app = axum::Router::new()
        .fallback(account_stub)
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let endpoint = format!(
        "http://localhost:{}/api/account",
        listener.local_addr().unwrap().port()
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        workspace
            .command()
            .args(["auth", "connect", "--endpoint", &endpoint])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    server.abort();
    assert_eq!(
        stub.requests.lock().unwrap().as_slice(),
        [
            "/api/account/register",
            "/api/account/sessions/challenge",
            "/api/account/sessions/login",
        ],
        "Required MFA without a terminal must not submit a factor, enroll a device, link a vault, or create a handoff"
    );
    let output = result
        .expect("connect must reject redirected stdin promptly, not open an inherited console")
        .expect("run auth connect");
    assert!(!output.status.success(), "Required MFA must fail closed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Required MFA"), "{stderr}");
    assert!(stderr.contains("interactive terminal"), "{stderr}");
    assert!(
        stderr.contains("no interactive prompt available"),
        "{stderr}"
    );
    assert!(stderr.contains("Keep MFA enabled"), "{stderr}");
    for text in [&stdout, &stderr] {
        assert!(
            !text.contains("Authenticator code (hidden):"),
            "must reject before prompting"
        );
        assert!(
            !text.contains(SESSION_CREDENTIAL),
            "never print credentials"
        );
        assert!(
            !text.contains(BROWSER_CREDENTIAL),
            "never print credentials"
        );
    }
}
