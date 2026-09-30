//! Golden tests for scoped `run` (Phase 7, T-702).
//!
//! Same hermetic pattern as the scope goldens: a canned axum stub records
//! request shape and returns fixed JSON. The stub models a dev token: the
//! `staging` environment lists and reads fine, while `production` answers
//! 404 (uniform denial), which the CLI must surface as an explicit denial
//! naming the scope and the missing grant (T6).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::process::Command;

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
}

#[derive(Clone)]
struct Stub {
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn record(stub: &Stub, method: &str, uri: &axum::http::Uri) {
    stub.seen.lock().unwrap().push(Seen {
        method: method.to_string(),
        target: uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_default(),
    });
}

async fn get_projects(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri);
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "projects": [
                {"project_id": "proj-1", "tenant_id": "t1", "slug": "shop",
                 "name": "shop", "status": "active", "role": "admin"},
            ],
        })),
    )
}

async fn get_project(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri);
    if id != "proj-1" && id != "shop" {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(
                serde_json::json!({"status": "error", "code": "NOT_FOUND", "error": "no such project"}),
            ),
        );
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "project_id": "proj-1", "tenant_id": "t1", "slug": "shop",
            "name": "shop", "status": "active", "role": "admin",
            "environments": [
                {"environment_id": "env-1", "slug": "staging", "tier": 1},
                {"environment_id": "env-2", "slug": "production", "tier": 2},
            ],
        })),
    )
}

fn not_found(code: &str, error: &str) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({"status": "error", "code": code, "error": error})),
    )
}

async fn get_secrets(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri);
    let target = uri.path_and_query().map(|v| v.as_str()).unwrap_or_default();
    // Dev token: staging lists fine, production is uniformly denied (T6).
    if target.contains("environment=env-2") {
        return not_found("NOT_FOUND", "not found or access denied");
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(
            serde_json::json!({ "revision": "aa".repeat(32), "secrets": [
            {
                "secret_id": "sec-1", "tenant_id": "t1", "project_id": "proj-1",
                "environment_id": "env-1", "name": "GOLDEN_ONE",
                "secret_type": "key_value", "status": "active",
                "current_version": 3,
            },
            {
                "secret_id": "sec-2", "tenant_id": "t1", "project_id": "proj-1",
                "environment_id": "env-1", "name": "GOLDEN_TWO",
                "secret_type": "key_value", "status": "deprecated",
                "current_version": 1,
            },
        ] }),
        ),
    )
}

async fn materialize(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "POST", &uri);
    assert_eq!(
        body["names"],
        serde_json::json!(["GOLDEN_ONE", "GOLDEN_TWO"])
    );
    if body["expected_revision"] != "aa".repeat(32) {
        return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(
                serde_json::json!({"code":"SCOPE_REVISION_CHANGED","error":"Scope revision changed"}),
            ),
        );
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "revision":"aa".repeat(32), "values":[
                {"name":"GOLDEN_ONE","secret_id":"sec-1","version":3,"value":"one-value"},
                {"name":"GOLDEN_TWO","secret_id":"sec-2","version":1,"value":"two-value"}
            ]
        })),
    )
}

async fn start_stub() -> (String, Stub) {
    let stub = Stub {
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let app = axum::Router::new()
        .route("/v1/projects", axum::routing::get(get_projects))
        .route("/v1/projects/:id", axum::routing::get(get_project))
        .route(
            "/v1/projects/proj-1/secrets",
            axum::routing::get(get_secrets),
        )
        .route(
            "/v1/projects/proj-1/environments/env-1/materialize",
            axum::routing::post(materialize),
        )
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://localhost:{port}"), stub)
}

fn fresh_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ciphervault_run_test_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_command(
    dir: &Path,
    endpoint: Option<&str>,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ciphervault"));
    cmd.current_dir(dir);
    cmd.stdin(std::process::Stdio::null());
    cmd.env("NO_COLOR", "1");
    cmd.env(
        "CIPHERVAULT_ACCOUNT_PATH",
        std::env::temp_dir().join("ciphervault_run_test_nonexistent_store.json"),
    );
    cmd.env_remove("CIPHERVAULT_ACCOUNT_ENDPOINT");
    cmd.env_remove("CIPHERVAULT_SCOPE_TOKEN");
    cmd.env_remove("CIPHERVAULT_PROJECT");
    cmd.env_remove("CIPHERVAULT_ENV");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    // Endpoint right after the subcommand: everything after `--` belongs
    // to the child command, and the flag is not global.
    let mut args = args.iter();
    if let Some(subcommand) = args.next() {
        cmd.arg(subcommand);
    }
    if let Some(endpoint) = endpoint {
        cmd.arg("--endpoint").arg(endpoint);
    }
    for arg in args {
        cmd.arg(arg);
    }
    cmd
}

/// Portable `echo $VAR` child: cmd on Windows, sh elsewhere.
fn echo_child(var: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec!["cmd".to_string(), "/c".to_string(), format!("echo %{var}%")]
    }
    #[cfg(not(windows))]
    {
        let _ = var;
        vec!["sh".to_string(), "-c".to_string(), format!("echo ${var}")]
    }
}

fn seen_targets(stub: &Stub) -> Vec<Seen> {
    stub.seen.lock().unwrap().clone()
}

#[tokio::test]
async fn run_scoped_dry_run_lists_names_only() {
    let dir = fresh_dir("dry-run");
    let (endpoint, stub) = start_stub().await;
    let out = run_command(
        &dir,
        Some(&endpoint),
        &[
            "run",
            "--project",
            "shop",
            "--env",
            "staging",
            "--token",
            "t",
            "--dry-run",
        ],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GOLDEN_ONE v3 [active]"), "{stdout}");
    assert!(stdout.contains("GOLDEN_TWO v1 [deprecated]"), "{stdout}");
    assert!(stdout.contains("[REDACTED]"), "{stdout}");
    assert!(!stdout.contains("one-value"), "{stdout}");
    assert!(!stdout.contains("two-value"), "{stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("scope: project=shop (flag) env=staging (flag)"),
        "{stderr}"
    );

    // List scoped to the resolved env id with the full page size; dry-run
    // must not fetch any values.
    let seen = seen_targets(&stub);
    let list = seen
        .iter()
        .find(|s| s.target.contains("/secrets?"))
        .expect("no list request");
    assert_eq!(list.method, "GET");
    assert!(list.target.contains("environment=env-1"), "{}", list.target);
    assert!(list.target.contains("limit=500"), "{}", list.target);
    assert!(
        !seen.iter().any(|s| s.target.contains("/materialize")),
        "dry-run fetched values: {seen:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn run_scoped_injects_values_into_child() {
    let dir = fresh_dir("inject");
    let (endpoint, stub) = start_stub().await;
    let mut owned = vec![
        "run".to_string(),
        "--project".to_string(),
        "shop".to_string(),
        "--env".to_string(),
        "staging".to_string(),
        "--token".to_string(),
        "t".to_string(),
        "--".to_string(),
    ];
    owned.extend(echo_child("GOLDEN_ONE"));
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let out = run_command(&dir, Some(&endpoint), &refs, &[])
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "one-value");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Injected 2 secret(s) from shop/staging"),
        "{stderr}"
    );

    let seen = seen_targets(&stub);
    assert_eq!(
        seen.iter()
            .filter(|s| s.method == "POST" && s.target.ends_with("/materialize"))
            .count(),
        1
    );
    assert!(!seen.iter().any(|s| s.target.contains("/secrets/sec-")));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn run_scoped_set_override_wins() {
    let dir = fresh_dir("override");
    let (endpoint, _stub) = start_stub().await;
    let mut owned = vec![
        "run".to_string(),
        "--project".to_string(),
        "shop".to_string(),
        "--env".to_string(),
        "staging".to_string(),
        "--token".to_string(),
        "t".to_string(),
        "--set".to_string(),
        "GOLDEN_ONE=override".to_string(),
        "--".to_string(),
    ];
    owned.extend(echo_child("GOLDEN_ONE"));
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let out = run_command(&dir, Some(&endpoint), &refs, &[])
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "override");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn run_scoped_denial_names_scope_and_grant() {
    let dir = fresh_dir("denial");
    let (endpoint, _stub) = start_stub().await;
    let mut owned = vec![
        "run".to_string(),
        "--project".to_string(),
        "shop".to_string(),
        "--env".to_string(),
        "production".to_string(),
        "--token".to_string(),
        "t".to_string(),
        "--".to_string(),
    ];
    owned.extend(echo_child("GOLDEN_ONE"));
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let out = run_command(&dir, Some(&endpoint), &refs, &[])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("shop/production"), "{stderr}");
    assert!(stderr.contains("grant"), "{stderr}");
    // Child never spawned.
    assert!(out.stdout.is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn run_scoped_rejects_snapshot_mix() {
    let dir = fresh_dir("conflict");
    let out = run_command(
        &dir,
        None,
        &[
            "run",
            "--snapshot",
            &"ab".repeat(32),
            "--project",
            "shop",
            "--env",
            "staging",
            "--dry-run",
        ],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot combine"), "{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn run_scoped_env_vars_engage_mode() {
    let dir = fresh_dir("envmode");
    let (endpoint, _stub) = start_stub().await;
    let out = run_command(
        &dir,
        Some(&endpoint),
        &["run", "--token", "t", "--dry-run"],
        &[
            ("CIPHERVAULT_PROJECT", "shop"),
            ("CIPHERVAULT_ENV", "staging"),
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GOLDEN_ONE"), "{stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("scope: project=shop (env) env=staging (env)"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn stale_revision_does_not_start_child() {
    let dir = fresh_dir("stale-revision");
    let (endpoint, _) = start_stub().await;
    let mut args = vec![
        "run".to_string(),
        "--project".into(),
        "shop".into(),
        "--env".into(),
        "staging".into(),
        "--token".into(),
        "t".into(),
        "--revision".into(),
        "bb".repeat(32),
        "--".into(),
    ];
    args.extend(echo_child("GOLDEN_ONE"));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_command(&dir, Some(&endpoint), &refs, &[])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("revision"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn cipher_control_credentials_are_absent_from_child() {
    let dir = fresh_dir("child-auth");
    let (endpoint, _) = start_stub().await;
    let mut args = vec![
        "run".to_string(),
        "--project".into(),
        "shop".into(),
        "--env".into(),
        "staging".into(),
        "--".into(),
    ];
    #[cfg(windows)]
    args.extend([
        "cmd".into(),
        "/c".into(),
        "if defined CIPHERVAULT_SCOPE_TOKEN (exit /b 19) else (echo clean)".into(),
    ]);
    #[cfg(not(windows))]
    args.extend([
        "sh".into(),
        "-c".into(),
        "test -z \"$CIPHERVAULT_SCOPE_TOKEN\" && echo clean".into(),
    ]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_command(
        &dir,
        Some(&endpoint),
        &refs,
        &[("CIPHERVAULT_SCOPE_TOKEN", "parent-secret-token")],
    )
    .output()
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "clean");
    std::fs::remove_dir_all(dir).unwrap();
}
