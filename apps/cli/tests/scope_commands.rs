//! Golden tests for `context`, `project`, and `secret` (Phase 7, T-701).
//!
//! Same hermetic pattern as the repo goldens: a canned axum stub records
//! request shape and returns fixed JSON. Every network test runs the binary
//! with a fresh empty cwd (no context file, no git repo) unless the case
//! creates them, so precedence assertions are exact.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::process::Command;

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    auth: Option<String>,
    body: Option<String>,
}

#[derive(Clone)]
struct Stub {
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn record(
    stub: &Stub,
    method: &str,
    uri: &axum::http::Uri,
    headers: &axum::http::HeaderMap,
    body: Option<&serde_json::Value>,
) {
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
        body: body.map(ToString::to_string),
    });
}

fn project_entry(id: &str, slug: &str, role: &str) -> serde_json::Value {
    serde_json::json!({
        "project_id": id, "tenant_id": "t1", "slug": slug,
        "name": slug, "status": "active", "role": role,
    })
}

async fn get_projects(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri, &headers, None);
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "projects": [
                project_entry("proj-1", "shop", "admin"),
                project_entry("proj-2", "blog", "developer"),
            ],
        })),
    )
}

async fn get_project(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri, &headers, None);
    let (slug, envs) = match id.as_str() {
        "proj-1" | "shop" => (
            "shop",
            vec![
                serde_json::json!({"environment_id": "env-1", "slug": "staging", "tier": 1}),
                serde_json::json!({"environment_id": "env-2", "slug": "production", "tier": 2}),
            ],
        ),
        "proj-2" | "blog" => (
            "blog",
            vec![serde_json::json!({"environment_id": "env-9", "slug": "dev", "tier": 0})],
        ),
        _ => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(
                    serde_json::json!({"status": "error", "code": "NOT_FOUND", "error": "no such project"}),
                ),
            );
        }
    };
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "project_id": if slug == "shop" { "proj-1" } else { "proj-2" },
            "tenant_id": "t1", "slug": slug, "name": slug,
            "status": "active", "role": "admin", "environments": envs,
        })),
    )
}

async fn get_repositories(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri, &headers, None);
    let bindings = if id == "proj-1" {
        vec![serde_json::json!({
            "binding_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "provider": "github", "external_repo_id": "11",
            "repo_full_name": "acme/shop", "status": "active",
        })]
    } else {
        vec![]
    };
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "bindings": bindings })),
    )
}

fn secret_meta() -> serde_json::Value {
    serde_json::json!({
        "secret_id": "sec-1", "tenant_id": "t1", "project_id": "proj-1",
        "environment_id": "env-1", "repository_binding_id": null, "service_id": null,
        "name": "DATABASE_URL", "secret_type": "key_value", "description": "",
        "tags": [], "status": "active", "current_version": 1,
        "created_by": "account:alice", "created_at_utc": 1, "updated_at_utc": 1,
        "last_rotated_at_utc": null, "expires_at_utc": null,
    })
}

async fn post_secret(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "POST", &uri, &headers, Some(&body));
    let mut view = secret_meta();
    view["name"] = body["name"].clone();
    view["description"] = body["description"].clone();
    (axum::http::StatusCode::CREATED, axum::Json(view))
}

async fn get_secret_value(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri, &headers, None);
    if name != "DATABASE_URL" {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(
                serde_json::json!({"status": "error", "code": "NOT_FOUND", "error": "no such secret"}),
            ),
        );
    }
    if query.get("metadata_only").map(String::as_str) == Some("true") {
        return (axum::http::StatusCode::OK, axum::Json(secret_meta()));
    }
    let mut view = secret_meta();
    view["version"] = serde_json::json!(1);
    view["value"] = serde_json::json!("s3cr3t-value");
    (axum::http::StatusCode::OK, axum::Json(view))
}

async fn get_secrets(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "GET", &uri, &headers, None);
    // Honor `q` like the server (§19): case-insensitive substring, no `q`
    // means the full page.
    let secrets = match query.get("q") {
        Some(q)
            if !secret_meta()["name"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains(&q.to_ascii_lowercase()) =>
        {
            vec![]
        }
        _ => vec![secret_meta()],
    };
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "secrets": secrets })),
    )
}

async fn patch_secret(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "PATCH", &uri, &headers, Some(&body));
    let mut view = secret_meta();
    if let Some(description) = body.get("description") {
        view["description"] = description.clone();
    }
    (axum::http::StatusCode::OK, axum::Json(view))
}

async fn delete_secret(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "DELETE", &uri, &headers, None);
    (
        axum::http::StatusCode::ACCEPTED,
        axum::Json(serde_json::json!({ "status": "scheduled_deletion" })),
    )
}

async fn rotate_secret(
    axum::extract::State(stub): axum::extract::State<Stub>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    record(&stub, "POST", &uri, &headers, Some(&body));
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "secret_id": "sec-1", "previous_version": 1, "current_version": 2,
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
            "/v1/projects/:id/repositories",
            axum::routing::get(get_repositories),
        )
        .route(
            "/v1/projects/proj-1/environments/env-1/secrets",
            axum::routing::post(post_secret),
        )
        .route(
            "/v1/projects/proj-1/environments/env-1/secrets/:name",
            axum::routing::get(get_secret_value),
        )
        .route(
            "/v1/projects/proj-1/secrets",
            axum::routing::get(get_secrets),
        )
        .route(
            "/v1/projects/proj-1/secrets/:id",
            axum::routing::patch(patch_secret).delete(delete_secret),
        )
        .route(
            "/v1/projects/proj-1/secrets/:id/rotate",
            axum::routing::post(rotate_secret),
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
        "ciphervault_scope_test_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn scoped_command(
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
        std::env::temp_dir().join("ciphervault_scope_test_nonexistent_store.json"),
    );
    cmd.env_remove("CIPHERVAULT_ACCOUNT_ENDPOINT");
    cmd.env_remove("CIPHERVAULT_SCOPE_TOKEN");
    cmd.env_remove("CIPHERVAULT_PROJECT");
    cmd.env_remove("CIPHERVAULT_ENV");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    for arg in args {
        cmd.arg(arg);
    }
    if let Some(endpoint) = endpoint {
        cmd.arg("--endpoint").arg(endpoint);
    }
    cmd
}

fn last_target_containing(stub: &Stub, needle: &str) -> Seen {
    stub.seen
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|seen| seen.target.contains(needle))
        .unwrap_or_else(|| panic!("no request to {needle}"))
        .clone()
}

#[tokio::test]
async fn context_file_lifecycle() {
    let dir = fresh_dir("ctx");
    let show_empty = scoped_command(&dir, None, &["context", "show"], &[])
        .output()
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&show_empty.stdout),
        "No context file (.ciphervault/context.json).\n"
    );

    let set = scoped_command(
        &dir,
        None,
        &["context", "set", "--project", "shop", "--env", "staging"],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(set.status.success());
    assert_eq!(String::from_utf8_lossy(&set.stdout), "Context saved.\n");
    let raw = std::fs::read_to_string(dir.join(".ciphervault").join("context.json")).unwrap();
    let file: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(file["project"], "shop");
    assert_eq!(file["env"], "staging");

    let show = scoped_command(&dir, None, &["context", "show"], &[])
        .output()
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&show.stdout),
        "project: shop\nenv: staging\n"
    );

    let clear = scoped_command(&dir, None, &["context", "clear"], &[])
        .output()
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&clear.stdout), "Context cleared.\n");
    assert!(!dir.join(".ciphervault").join("context.json").exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn project_list_show_use_goldens() {
    let dir = fresh_dir("project");
    let (endpoint, stub) = start_stub().await;
    let list = scoped_command(
        &dir,
        Some(&endpoint),
        &["project", "list", "--token", "t"],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(list.status.success());
    let expected = format!(
        "{:<34} {:<20} {:<28} {:<10}\n\
         {:<34} {:<20} {:<28} {:<10}\n\
         {:<34} {:<20} {:<28} {:<10}\n",
        "PROJECT ID",
        "SLUG",
        "NAME",
        "ROLE",
        "proj-1",
        "shop",
        "shop",
        "admin",
        "proj-2",
        "blog",
        "blog",
        "developer",
    );
    assert_eq!(String::from_utf8_lossy(&list.stdout), expected);

    let show = scoped_command(
        &dir,
        Some(&endpoint),
        &["project", "show", "shop", "--token", "t"],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&show.stdout),
        "project_id: proj-1\nslug: shop\nname: shop\nstatus: active\nrole: admin\nenvironments:\n  staging (env-1, tier 1)\n  production (env-2, tier 2)\n"
    );

    std::fs::create_dir_all(dir.join(".ciphervault")).unwrap();
    std::fs::write(
        dir.join(".ciphervault").join("context.json"),
        r#"{"project": "blog", "env": "dev"}"#,
    )
    .unwrap();
    let use_cmd = scoped_command(
        &dir,
        Some(&endpoint),
        &["project", "use", "shop", "--token", "t"],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(use_cmd.status.success());
    assert_eq!(
        String::from_utf8_lossy(&use_cmd.stdout),
        "Using project shop (environment cleared).\n"
    );
    let raw = std::fs::read_to_string(dir.join(".ciphervault").join("context.json")).unwrap();
    let file: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(file["project"], "shop");
    assert!(file.get("env").is_none());
    let _ = last_target_containing(&stub, "/v1/projects/shop");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn secret_crud_goldens() {
    let dir = fresh_dir("secret");
    let (endpoint, stub) = start_stub().await;
    let base = ["--project", "shop", "--env", "staging", "--token", "t"];

    let mut set_args = vec!["secret", "set", "DATABASE_URL", "--value", "v1"];
    set_args.extend_from_slice(&base);
    let set = scoped_command(&dir, Some(&endpoint), &set_args, &[])
        .output()
        .await
        .unwrap();
    assert!(
        set.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&set.stdout),
        "Set DATABASE_URL in shop/staging: id sec-1 version 1.\n"
    );
    let posted = last_target_containing(&stub, "/environments/env-1/secrets");
    assert_eq!(posted.method, "POST");
    assert_eq!(posted.auth.as_deref(), Some("Bearer t"));
    assert!(posted.body.as_deref().unwrap().contains("\"value\":\"v1\""));

    let mut get_args = vec!["secret", "get", "DATABASE_URL"];
    get_args.extend_from_slice(&base);
    let get = scoped_command(&dir, Some(&endpoint), &get_args, &[])
        .output()
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&get.stdout), "s3cr3t-value\n");

    let mut meta_args = vec!["secret", "get", "DATABASE_URL", "--meta"];
    meta_args.extend_from_slice(&base);
    let meta = scoped_command(&dir, Some(&endpoint), &meta_args, &[])
        .output()
        .await
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&meta.stdout)).unwrap();
    assert_eq!(parsed["secret_id"], "sec-1");
    assert!(parsed.get("value").is_none());

    let mut list_args = vec!["secret", "list"];
    list_args.extend_from_slice(&base);
    let list = scoped_command(&dir, Some(&endpoint), &list_args, &[])
        .output()
        .await
        .unwrap();
    let expected = format!(
        "{:<28} {:<12} {:<5} {:<10}\n{:<28} {:<12} {:<5} {:<10}\n",
        "NAME", "TYPE", "VER", "STATUS", "DATABASE_URL", "key_value", 1, "active",
    );
    assert_eq!(String::from_utf8_lossy(&list.stdout), expected);

    let mut update_args = vec![
        "secret",
        "update",
        "DATABASE_URL",
        "--description",
        "primary",
    ];
    update_args.extend_from_slice(&base);
    let update = scoped_command(&dir, Some(&endpoint), &update_args, &[])
        .output()
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&update.stdout),
        "Updated DATABASE_URL (status active).\n"
    );
    let patched = last_target_containing(&stub, "/secrets/sec-1");
    assert_eq!(patched.method, "PATCH");
    assert!(patched.body.as_deref().unwrap().contains("primary"));

    let mut delete_args = vec!["secret", "delete", "DATABASE_URL", "--reason", "spent"];
    delete_args.extend_from_slice(&base);
    let delete = scoped_command(&dir, Some(&endpoint), &delete_args, &[])
        .output()
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&delete.stdout),
        "Deleted DATABASE_URL: scheduled_deletion.\n"
    );
    let deleted = last_target_containing(&stub, "/secrets/sec-1");
    assert_eq!(deleted.method, "DELETE");
    assert!(deleted.target.contains("reason=spent"));

    let mut rotate_args = vec!["secret", "rotate", "DATABASE_URL", "--value", "v2"];
    rotate_args.extend_from_slice(&base);
    let rotate = scoped_command(&dir, Some(&endpoint), &rotate_args, &[])
        .output()
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&rotate.stdout),
        "Rotated DATABASE_URL to version 2.\n"
    );
    let rotated = last_target_containing(&stub, "/secrets/sec-1/rotate");
    let body: serde_json::Value = serde_json::from_str(rotated.body.as_deref().unwrap()).unwrap();
    assert_eq!(body["new_value"], "v2");
    assert!(body["idempotency_key"].is_string());
    assert_eq!(body["reason"], "operator rotate");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn scope_precedence_flags_beat_env_beat_file() {
    let dir = fresh_dir("precedence");
    let (endpoint, stub) = start_stub().await;
    std::fs::create_dir_all(dir.join(".ciphervault")).unwrap();
    std::fs::write(
        dir.join(".ciphervault").join("context.json"),
        r#"{"project": "blog", "env": "dev"}"#,
    )
    .unwrap();

    // Flags win over env and file.
    let out = scoped_command(
        &dir,
        Some(&endpoint),
        &[
            "secret",
            "list",
            "--project",
            "shop",
            "--env",
            "staging",
            "--token",
            "t",
        ],
        &[("CIPHERVAULT_PROJECT", "blog"), ("CIPHERVAULT_ENV", "dev")],
    )
    .output()
    .await
    .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("scope: project=shop (flag) env=staging (flag)"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(last_target_containing(&stub, "/v1/projects/proj-1/secrets")
        .target
        .contains("environment=env-1"));

    // Env wins over file.
    let out = scoped_command(
        &dir,
        Some(&endpoint),
        &["secret", "list", "--token", "t"],
        &[
            ("CIPHERVAULT_PROJECT", "shop"),
            ("CIPHERVAULT_ENV", "staging"),
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("scope: project=shop (env) env=staging (env)"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // File wins when nothing else is set (blog/dev has no secrets route:
    // resolution succeeds, then the stub 404s — scope echo still proves
    // the file source).
    let out = scoped_command(
        &dir,
        Some(&endpoint),
        &["secret", "list", "--token", "t"],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("scope: project=blog (file) env=dev (file)"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn scope_autodetects_git_remote_and_requires_env() {
    let dir = fresh_dir("autodetect");
    let (endpoint, _stub) = start_stub().await;
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(
        dir.join(".git").join("config"),
        "[remote \"origin\"]\n\turl = git@github.com:acme/shop.git\n",
    )
    .unwrap();

    // Project auto-detects from the remote; env still needs a source.
    let missing_env = scoped_command(
        &dir,
        Some(&endpoint),
        &["secret", "list", "--token", "t"],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(!missing_env.status.success());
    assert!(
        String::from_utf8_lossy(&missing_env.stderr).contains("no environment"),
        "stderr: {}",
        String::from_utf8_lossy(&missing_env.stderr)
    );

    let out = scoped_command(
        &dir,
        Some(&endpoint),
        &["secret", "list", "--token", "t"],
        &[("CIPHERVAULT_ENV", "staging")],
    )
    .output()
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("scope: project=shop (auto-detect) env=staging (env)"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn secret_value_prompt_and_errors() {
    let dir = fresh_dir("secret-err");
    let (endpoint, _stub) = start_stub().await;

    // No value flag and no terminal: names the flag (stdin is null).
    let out = scoped_command(
        &dir,
        Some(&endpoint),
        &[
            "secret",
            "set",
            "DATABASE_URL",
            "--project",
            "shop",
            "--env",
            "staging",
            "--token",
            "t",
        ],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--value"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Unknown env slug errors before any secret call.
    let out = scoped_command(
        &dir,
        Some(&endpoint),
        &[
            "secret",
            "list",
            "--project",
            "shop",
            "--env",
            "ghost",
            "--token",
            "t",
        ],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown environment"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn secret_find_searches_names_without_values() {
    let dir = fresh_dir("find");
    let (endpoint, stub) = start_stub().await;
    let base = ["--project", "shop", "--env", "staging", "--token", "t"];

    // Match: metadata table, never the value.
    let mut hit_args = vec!["secret", "find", "data"];
    hit_args.extend_from_slice(&base);
    let hit = scoped_command(&dir, Some(&endpoint), &hit_args, &[])
        .output()
        .await
        .unwrap();
    assert!(
        hit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&hit.stderr)
    );
    let stdout = String::from_utf8_lossy(&hit.stdout);
    assert!(stdout.contains("DATABASE_URL"), "{stdout}");
    assert!(stdout.contains("NAME"), "{stdout}");
    assert!(!stdout.contains("s3cr3t-value"), "{stdout}");
    let list = last_target_containing(&stub, "/secrets?");
    assert!(list.target.contains("q=data"), "{}", list.target);

    // Miss: friendly empty message.
    let mut miss_args = vec!["secret", "find", "zzz-no-such"];
    miss_args.extend_from_slice(&base);
    let miss = scoped_command(&dir, Some(&endpoint), &miss_args, &[])
        .output()
        .await
        .unwrap();
    assert!(miss.status.success());
    assert_eq!(
        String::from_utf8_lossy(&miss.stdout),
        "No secrets matching 'zzz-no-such' in this scope.\n"
    );

    // Empty query is rejected locally, before any network call.
    let seen_before = stub.seen.lock().unwrap().len();
    let empty = scoped_command(
        &dir,
        Some(&endpoint),
        &[
            "secret",
            "find",
            "  ",
            "--project",
            "shop",
            "--env",
            "staging",
            "--token",
            "t",
        ],
        &[],
    )
    .output()
    .await
    .unwrap();
    assert!(!empty.status.success());
    assert!(
        String::from_utf8_lossy(&empty.stderr).contains("must not be empty"),
        "stderr: {}",
        String::from_utf8_lossy(&empty.stderr)
    );
    assert_eq!(stub.seen.lock().unwrap().len(), seen_before);
    std::fs::remove_dir_all(&dir).ok();
}
