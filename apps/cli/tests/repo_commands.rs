//! Golden tests for `ciphervault repo` (Phase 6, T-602).
//!
//! A canned axum stub stands in for the account server: it asserts request
//! formation (method, path, bearer token) and returns fixed binding JSON so
//! CLI output is byte-stable. Hermetic: no real server, no real account
//! store (`CIPHERVAULT_ACCOUNT_PATH` points at a nonexistent file).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::process::Command;

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    auth: Option<String>,
}

#[derive(Clone)]
struct Stub {
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn record(stub: &Stub, method: &str, uri: &axum::http::Uri, headers: &axum::http::HeaderMap) {
    stub.seen.lock().unwrap().push(Seen {
        method: method.to_string(),
        target: uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_default(),
        auth: headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
    });
}

fn canned_binding(
    id: &str,
    provider: &str,
    external: &str,
    name: &str,
    status: &str,
) -> serde_json::Value {
    serde_json::json!({
        "binding_id": id,
        "tenant_id": "t1",
        "project_id": "proj-1",
        "provider": provider,
        "external_repo_id": external,
        "repo_full_name": name,
        "repo_url": format!("https://example.invalid/{name}"),
        "installation_id": null,
        "status": status,
        "ownership_verified_at_utc": null,
        "last_reconciled_at_utc": null,
        "created_at_utc": 1,
    })
}

async fn post_repositories(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "POST", &uri, &headers);
    let mut binding = canned_binding(
        "0123456789abcdef0123456789abcdef",
        body["provider"].as_str().unwrap_or("?"),
        body["external_repo_id"].as_str().unwrap_or("?"),
        body["repo_full_name"].as_str().unwrap_or("?"),
        "suspended",
    );
    binding["installation_id"] = body["installation_id"].clone();
    (
        axum::http::StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "binding": binding,
            "ownership_challenge": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "webhook_secret": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        })),
    )
}

async fn get_projects_stub(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri, &headers);
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "projects": [
                {"project_id": "proj-1", "tenant_id": "t1", "slug": "shop",
                 "name": "Shop", "status": "active", "role": "admin"},
                {"project_id": "proj-9", "tenant_id": "t1", "slug": "ghost",
                 "name": "Ghost", "status": "active", "role": "admin"},
            ],
        })),
    )
}

async fn get_repositories(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri, &headers);
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "bindings": [
                canned_binding(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "github", "84920194", "acme/backend", "active",
                ),
                canned_binding(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "gitlab", "42", "acme/frontend", "suspended",
                ),
            ],
        })),
    )
}

async fn delete_repository(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "DELETE", &uri, &headers);
    let status = if query.get("mode").map(String::as_str) == Some("revoke") {
        "revoked"
    } else {
        "suspended"
    };
    (
        axum::http::StatusCode::ACCEPTED,
        axum::Json(serde_json::json!({ "binding_id": id, "status": status })),
    )
}

async fn start_stub() -> (String, Stub) {
    let stub = Stub {
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let app = axum::Router::new()
        .route("/v1/projects", axum::routing::get(get_projects_stub))
        .route(
            "/v1/projects/proj-1/repositories",
            axum::routing::post(post_repositories).get(get_repositories),
        )
        .route(
            "/v1/projects/proj-1/repositories/:id",
            axum::routing::delete(delete_repository),
        )
        .with_state(stub.clone());
    // Localhost by name: the CLI only accepts https or localhost endpoints.
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://localhost:{port}"), stub)
}

fn repo_command(endpoint: Option<&str>, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ciphervault"));
    cmd.env("NO_COLOR", "1");
    cmd.env(
        "CIPHERVAULT_ACCOUNT_PATH",
        std::env::temp_dir().join("ciphervault_repo_test_nonexistent_store.json"),
    );
    cmd.env_remove("CIPHERVAULT_ACCOUNT_ENDPOINT");
    cmd.env_remove("CIPHERVAULT_SCOPE_TOKEN");
    cmd.arg("repo");
    for arg in args {
        cmd.arg(arg);
    }
    if let Some(endpoint) = endpoint {
        cmd.arg("--endpoint").arg(endpoint);
    }
    cmd
}

#[tokio::test]
async fn stub_answers_reqwest_directly() {
    let (endpoint, stub) = start_stub().await;
    let body = reqwest::get(format!("{endpoint}/v1/projects/proj-1/repositories"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("acme/backend"), "body: {body}");
    assert_eq!(stub.seen.lock().unwrap().len(), 1);
    // Same request with the CLI's exact client configuration.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(concat!("ciphervault/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap();
    let response = client
        .get(format!("{endpoint}/v1/projects/proj-1/repositories"))
        .bearer_auth("test-token-2")
        .send()
        .await;
    assert!(response.is_ok(), "cli-configured send failed: {response:?}");
}

#[tokio::test]
async fn repo_bind_golden() {
    let (endpoint, stub) = start_stub().await;
    let output = repo_command(
        Some(&endpoint),
        &[
            "bind",
            "--project",
            "proj-1",
            "--provider",
            "github",
            "--repo-id",
            "84920194",
            "--name",
            "acme/backend",
            "--url",
            "https://github.com/acme/backend",
            "--installation-id",
            "install-7",
            "--token",
            "test-token-1",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "bind failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = "Bound acme/backend (github:84920194) to project shop.\n\
         \u{20}\u{20}binding_id: 0123456789abcdef0123456789abcdef\n\
         \u{20}\u{20}status: suspended\n\
         \u{20}\u{20}ownership_challenge: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
         \u{20}\u{20}webhook_secret: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb (shown once — store it now)\n";
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    let seen = stub.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].target, "/v1/projects");
    assert_eq!(seen[1].method, "POST");
    assert_eq!(seen[1].target, "/v1/projects/proj-1/repositories");
    assert_eq!(seen[1].auth.as_deref(), Some("Bearer test-token-1"));
}

#[tokio::test]
async fn repo_list_golden() {
    let (endpoint, stub) = start_stub().await;
    let output = repo_command(
        Some(&endpoint),
        &["list", "--project", "proj-1", "--token", "test-token-2"],
    )
    .output()
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = format!(
        "{:<34} {:<10} {:<12} {:<28} {:<10}\n\
         {:<34} {:<10} {:<12} {:<28} {:<10}\n\
         {:<34} {:<10} {:<12} {:<28} {:<10}\n",
        "BINDING ID",
        "PROVIDER",
        "EXTERNAL ID",
        "NAME",
        "STATUS",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "github",
        "84920194",
        "acme/backend",
        "active",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "gitlab",
        "42",
        "acme/frontend",
        "suspended",
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    let seen = stub.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].target, "/v1/projects");
    assert_eq!(seen[1].method, "GET");
    assert_eq!(seen[1].target, "/v1/projects/proj-1/repositories");
    assert_eq!(seen[1].auth.as_deref(), Some("Bearer test-token-2"));
}

#[tokio::test]
async fn repo_unbind_by_id_suspends() {
    let (endpoint, stub) = start_stub().await;
    let output = repo_command(
        Some(&endpoint),
        &[
            "unbind",
            "--project",
            "proj-1",
            "--binding",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--token",
            "test-token-3",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "unbind failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Binding aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa suspended.\n"
    );
    let seen = stub.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].target, "/v1/projects");
    assert_eq!(
        seen[1].target,
        "/v1/projects/proj-1/repositories/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?mode=suspend"
    );
}

#[tokio::test]
async fn repo_unbind_resolves_repo_id_and_revokes() {
    let (endpoint, stub) = start_stub().await;
    let output = repo_command(
        Some(&endpoint),
        &[
            "unbind",
            "--project",
            "proj-1",
            "--provider",
            "gitlab",
            "--repo-id",
            "42",
            "--revoke",
            "--reason",
            "repo deleted",
            "--token",
            "test-token-4",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "unbind failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Binding bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb revoked.\n"
    );
    let seen = stub.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].target, "/v1/projects");
    assert_eq!(seen[1].method, "GET");
    assert_eq!(seen[2].method, "DELETE");
    assert!(
        seen[2]
            .target
            .starts_with("/v1/projects/proj-1/repositories/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?"),
        "unexpected target: {}",
        seen[2].target
    );
    assert!(seen[2].target.contains("mode=revoke"), "{}", seen[2].target);
    assert!(seen[2].target.contains("reason="), "{}", seen[2].target);
}

#[tokio::test]
async fn repo_errors_guide_without_server() {
    // No endpoint anywhere (flag, env, or account store).
    let output = repo_command(None, &["list", "--project", "proj-1", "--token", "t"])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no account endpoint"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // No token anywhere.
    let (endpoint, _stub) = start_stub().await;
    let output = repo_command(Some(&endpoint), &["list", "--project", "proj-1"])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no scope token"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Unknown provider fails before any network.
    let output = repo_command(
        Some(&endpoint),
        &[
            "bind",
            "--project",
            "proj-1",
            "--provider",
            "gitea",
            "--repo-id",
            "1",
            "--name",
            "x/y",
            "--url",
            "https://example.invalid/x/y",
            "--token",
            "t",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown VCS provider"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Unknown project surfaces the server 404 without an oracle probe.
    let output = repo_command(
        Some(&endpoint),
        &["list", "--project", "proj-9", "--token", "t"],
    )
    .output()
    .await
    .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not found or access denied"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Unlisted projects fail resolution locally, never defaulting.
    let output = repo_command(
        Some(&endpoint),
        &["list", "--project", "proj-ghost", "--token", "t"],
    )
    .output()
    .await
    .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown project"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
