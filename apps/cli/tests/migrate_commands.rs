//! Golden tests for ledgered migration (Phase 8, T-801).
//!
//! Unlike the pure-stub suites, these build REAL vaults (`init`/`track`/
//! `push` in temp dirs, like `run_injection_test`) and drive them against a
//! canned account server with a minimal in-memory ledger that mirrors the
//! real state machine (name rules, digest-gated verify, disable, shred
//! gates). Values are synthetic (`one`, `two`, …).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::process::Command;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {}
        _ => return false,
    }
    name.len() <= 128
        && name
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

#[derive(Clone, Debug)]
struct EntryState {
    ledger_id: String,
    path: String,
    line: i64,
    name: String,
    secret_type: String,
    env_id: String,
    state: String,
    source_digest_hex: String,
    target_digest_hex: Option<String>,
    secret_id: Option<String>,
    key: String,
    reason: String,
}

#[derive(Clone, Debug)]
struct RunState {
    migration_id: String,
    state: String,
    source_vault_id: String,
    source_snapshot_hex: String,
}

#[derive(Default)]
struct StubInner {
    posts: Vec<String>,
    runs: HashMap<String, RunState>,
    entries: HashMap<String, Vec<EntryState>>,
    secrets: HashMap<String, (String, String, String)>,
    fail_create: bool,
    next_run: u32,
    next_entry: u32,
    next_secret: u32,
}

#[derive(Clone, Default)]
struct Stub {
    inner: Arc<Mutex<StubInner>>,
}

fn entry_json(entry: &EntryState, mid: &str) -> serde_json::Value {
    serde_json::json!({
        "ledger_id": entry.ledger_id,
        "migration_id": mid,
        "source_path": entry.path,
        "source_line": entry.line,
        "name": entry.name,
        "secret_type": entry.secret_type,
        "target_environment_id": entry.env_id,
        "state": entry.state,
        "source_digest_hex": entry.source_digest_hex,
        "target_digest_hex": entry.target_digest_hex,
        "secret_id": entry.secret_id,
        "idempotency_key": entry.key,
        "reason": entry.reason,
    })
}

fn run_json(run: &RunState, entries: &[EntryState]) -> serde_json::Value {
    let mut counts = serde_json::Map::new();
    for entry in entries {
        let count = counts
            .entry(entry.state.clone())
            .or_insert(serde_json::json!(0));
        *count = serde_json::json!(count.as_i64().unwrap_or(0) + 1);
    }
    serde_json::json!({
        "migration_id": run.migration_id,
        "tenant_id": "t1",
        "project_id": "proj-1",
        "source_vault_id": run.source_vault_id,
        "source_snapshot_hex": run.source_snapshot_hex,
        "created_by": "account:alice",
        "state": run.state,
        "entry_counts": counts,
    })
}

async fn get_projects() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "projects": [
            {"project_id": "proj-1", "tenant_id": "t1", "slug": "shop",
             "name": "shop", "status": "active", "role": "admin"},
        ],
    }))
}

async fn get_project(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    if id != "proj-1" && id != "shop" {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"status": "error", "code": "NOT_FOUND"})),
        );
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "project_id": "proj-1", "slug": "shop",
            "environments": [
                {"environment_id": "env-1", "slug": "staging", "tier": 1},
                {"environment_id": "env-2", "slug": "production", "tier": 2},
                {"environment_id": "env-3", "slug": "development", "tier": 0},
            ],
        })),
    )
}

async fn post_migration(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let mut inner = stub.inner.lock().unwrap();
    inner.posts.push("POST /migrations".to_string());
    inner.next_run += 1;
    let mid = format!("mig-{}", inner.next_run);
    let run = RunState {
        migration_id: mid.clone(),
        state: "planning".to_string(),
        source_vault_id: body["source_vault_id"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        source_snapshot_hex: body["source_snapshot_hex"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    };
    inner.runs.insert(mid.clone(), run.clone());
    inner.entries.insert(mid, Vec::new());
    (
        axum::http::StatusCode::CREATED,
        axum::Json(run_json(&run, &[])),
    )
}

async fn get_migrations(
    axum::extract::State(stub): axum::extract::State<Stub>,
) -> axum::Json<serde_json::Value> {
    let inner = stub.inner.lock().unwrap();
    let mut runs: Vec<serde_json::Value> = inner
        .runs
        .values()
        .map(|run| {
            run_json(
                run,
                inner
                    .entries
                    .get(&run.migration_id)
                    .cloned()
                    .unwrap_or_default()
                    .as_slice(),
            )
        })
        .collect();
    runs.sort_by(|a, b| a["migration_id"].as_str().cmp(&b["migration_id"].as_str()));
    axum::Json(serde_json::json!({ "migrations": runs }))
}

async fn get_migration(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Path((_, mid)): axum::extract::Path<(String, String)>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let inner = stub.inner.lock().unwrap();
    let Some(run) = inner.runs.get(&mid) else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"status": "error", "code": "NOT_FOUND"})),
        );
    };
    let entries = inner.entries.get(&mid).cloned().unwrap_or_default();
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "migration": run_json(run, &entries),
            "entries": entries.iter().map(|entry| entry_json(entry, &mid)).collect::<Vec<_>>(),
        })),
    )
}

async fn post_entries(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Path((_, mid)): axum::extract::Path<(String, String)>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let mut inner = stub.inner.lock().unwrap();
    inner.posts.push("POST /entries".to_string());
    if !inner.runs.contains_key(&mid) {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"status": "error", "code": "NOT_FOUND"})),
        );
    }
    let mut out = Vec::new();
    for proposal in body["entries"].as_array().cloned().unwrap_or_default() {
        inner.next_entry += 1;
        let name = proposal["name"].as_str().unwrap_or_default().to_string();
        let env_id = proposal["target_environment_id"]
            .as_str()
            .unwrap_or_default();
        // Mirror the server gates that matter here: name rules + known env.
        let known_env = ["env-1", "env-2", "env-3"].contains(&env_id);
        let (state, reason) = if !valid_name(&name) {
            ("QUARANTINED", format!("invalid secret name '{name}'"))
        } else if !known_env {
            ("QUARANTINED", format!("unknown environment '{env_id}'"))
        } else {
            ("VALIDATED", String::new())
        };
        let entry = EntryState {
            ledger_id: format!("mle-{}", inner.next_entry),
            path: proposal["source_path"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            line: proposal["source_line"].as_i64().unwrap_or(0),
            name,
            secret_type: proposal["secret_type"]
                .as_str()
                .unwrap_or("key_value")
                .to_string(),
            env_id: env_id.to_string(),
            state: state.to_string(),
            source_digest_hex: proposal["source_digest_hex"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            target_digest_hex: None,
            secret_id: None,
            key: proposal["idempotency_key"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            reason,
        };
        out.push(entry_json(&entry, &mid));
        inner.entries.get_mut(&mid).unwrap().push(entry);
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "entries": out })),
    )
}

async fn post_secret(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Path((_project, env)): axum::extract::Path<(String, String)>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let mut inner = stub.inner.lock().unwrap();
    inner.posts.push("POST /secrets".to_string());
    if inner.fail_create {
        return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(serde_json::json!({"status": "error", "code": "SECRET_CONFLICT"})),
        );
    }
    inner.next_secret += 1;
    let id = format!("sec-{}", inner.next_secret);
    inner.secrets.insert(
        id.clone(),
        (
            body["name"].as_str().unwrap_or_default().to_string(),
            body["value"].as_str().unwrap_or_default().to_string(),
            env,
        ),
    );
    (
        axum::http::StatusCode::CREATED,
        axum::Json(serde_json::json!({ "secret_id": id })),
    )
}

async fn get_secret_value(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Path((_, id)): axum::extract::Path<(String, String)>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let inner = stub.inner.lock().unwrap();
    // Accept stable IDs; names resolve by scan like the real show route.
    if let Some((_, value, _)) = inner.secrets.get(&id) {
        return (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({ "value": value })),
        );
    }
    for (name, value, _) in inner.secrets.values() {
        if name == &id {
            return (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({ "value": value })),
            );
        }
    }
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({"status": "error", "code": "NOT_FOUND"})),
    )
}

async fn get_secrets(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
) -> axum::Json<serde_json::Value> {
    let inner = stub.inner.lock().unwrap();
    let q = query
        .get("q")
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut secrets = Vec::new();
    for (id, (name, _, _)) in inner.secrets.iter() {
        if q.is_empty() || name.to_ascii_lowercase().contains(&q) {
            secrets.push(serde_json::json!({
                "secret_id": id, "name": name, "secret_type": "key_value",
                "status": "active", "current_version": 1,
            }));
        }
    }
    axum::Json(serde_json::json!({ "secrets": secrets }))
}

async fn post_migrated(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Path((_, mid, eid)): axum::extract::Path<(String, String, String)>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let mut inner = stub.inner.lock().unwrap();
    inner.posts.push("POST /migrated".to_string());
    let mut found = None;
    if let Some(entries) = inner.entries.get_mut(&mid) {
        for entry in entries.iter_mut() {
            if entry.ledger_id == eid && entry.state == "VALIDATED" {
                entry.state = "MIGRATED".to_string();
                entry.secret_id = Some(body["secret_id"].as_str().unwrap_or_default().to_string());
                entry.target_digest_hex = Some(
                    body["target_digest_hex"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
                found = Some(entry_json(entry, &mid));
            }
        }
    }
    if let Some(run) = inner.runs.get_mut(&mid) {
        if run.state == "planning" {
            run.state = "applying".to_string();
        }
    }
    match found {
        Some(entry) => (axum::http::StatusCode::OK, axum::Json(entry)),
        None => (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"status": "error", "code": "INVALID_MIGRATION_REQUEST"})),
        ),
    }
}

async fn post_resolve(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Path((_, mid, eid)): axum::extract::Path<(String, String, String)>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let mut inner = stub.inner.lock().unwrap();
    inner.posts.push("POST /resolve".to_string());
    let mut found = None;
    if let Some(entries) = inner.entries.get_mut(&mid) {
        for entry in entries.iter_mut() {
            if entry.ledger_id == eid && entry.state == "QUARANTINED" {
                if let Some(name) = body["name"].as_str() {
                    entry.name = name.to_string();
                }
                if let Some(env) = body["target_environment_id"].as_str() {
                    entry.env_id = env.to_string();
                }
                if valid_name(&entry.name)
                    && ["env-1", "env-2", "env-3"].contains(&entry.env_id.as_str())
                {
                    entry.state = "VALIDATED".to_string();
                    entry.reason.clear();
                } else {
                    entry.reason = "still invalid after resolve".to_string();
                }
                found = Some(entry_json(entry, &mid));
            }
        }
    }
    match found {
        Some(entry) => (axum::http::StatusCode::OK, axum::Json(entry)),
        None => (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"status": "error", "code": "INVALID_MIGRATION_REQUEST"})),
        ),
    }
}

async fn post_verify(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Path((_, mid)): axum::extract::Path<(String, String)>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let mut inner = stub.inner.lock().unwrap();
    inner.posts.push("POST /verify".to_string());
    let mut verified = 0i64;
    let mut quarantined = 0i64;
    if let Some(entries) = inner.entries.get_mut(&mid) {
        for entry in entries.iter_mut() {
            if entry.state == "MIGRATED" {
                if entry.target_digest_hex.as_deref() == Some(entry.source_digest_hex.as_str()) {
                    entry.state = "VERIFIED".to_string();
                    verified += 1;
                } else {
                    entry.state = "QUARANTINED".to_string();
                    entry.reason = "digest mismatch: applied bytes differ from source".to_string();
                    quarantined += 1;
                }
            }
        }
    }
    let open = inner
        .entries
        .get(&mid)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry.state != "VERIFIED" && entry.state != "LEGACY_PATH_DISABLED")
                .count()
        })
        .unwrap_or(0);
    let run_state = if open == 0 { "complete" } else { "verifying" };
    if let Some(run) = inner.runs.get_mut(&mid) {
        run.state = run_state.to_string();
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "verified": verified, "quarantined": quarantined, "run_state": run_state,
        })),
    )
}

async fn post_disable(
    axum::extract::State(stub): axum::extract::State<Stub>,
    axum::extract::Path((_, mid)): axum::extract::Path<(String, String)>,
    axum::Json(_body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let mut inner = stub.inner.lock().unwrap();
    inner.posts.push("POST /disable-legacy".to_string());
    let mut disabled = 0i64;
    if let Some(run) = inner.runs.get(&mid) {
        if run.state != "verifying" && run.state != "complete" {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(
                    serde_json::json!({"status": "error", "code": "INVALID_MIGRATION_REQUEST"}),
                ),
            );
        }
    }
    if let Some(entries) = inner.entries.get_mut(&mid) {
        for entry in entries.iter_mut() {
            if entry.state == "VERIFIED" {
                entry.state = "LEGACY_PATH_DISABLED".to_string();
                disabled += 1;
            }
        }
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "disabled": disabled })),
    )
}

async fn start_stub() -> (String, Stub) {
    start_stub_with(false).await
}

async fn start_stub_with(fail_create: bool) -> (String, Stub) {
    let stub = Stub::default();
    stub.inner.lock().unwrap().fail_create = fail_create;
    let app = axum::Router::new()
        .route("/v1/projects", axum::routing::get(get_projects))
        .route("/v1/projects/:id", axum::routing::get(get_project))
        .route(
            "/v1/projects/:id/migrations",
            axum::routing::post(post_migration).get(get_migrations),
        )
        .route(
            "/v1/projects/:id/migrations/:mid",
            axum::routing::get(get_migration),
        )
        .route(
            "/v1/projects/:id/migrations/:mid/entries",
            axum::routing::post(post_entries),
        )
        .route(
            "/v1/projects/:id/migrations/:mid/entries/:eid/migrated",
            axum::routing::post(post_migrated),
        )
        .route(
            "/v1/projects/:id/migrations/:mid/entries/:eid/resolve",
            axum::routing::post(post_resolve),
        )
        .route(
            "/v1/projects/:id/migrations/:mid/verify",
            axum::routing::post(post_verify),
        )
        .route(
            "/v1/projects/:id/migrations/:mid/disable-legacy",
            axum::routing::post(post_disable),
        )
        .route(
            "/v1/projects/:id/environments/:env/secrets",
            axum::routing::post(post_secret),
        )
        .route("/v1/projects/:id/secrets", axum::routing::get(get_secrets))
        .route(
            "/v1/projects/:id/secrets/:sid",
            axum::routing::get(get_secret_value),
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
        "ciphervault_migrate_test_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cli_command(dir: &Path, endpoint: Option<&str>, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ciphervault"));
    cmd.current_dir(dir);
    cmd.stdin(std::process::Stdio::null());
    cmd.env("NO_COLOR", "1");
    cmd.env(
        "CIPHERVAULT_ACCOUNT_PATH",
        std::env::temp_dir().join("ciphervault_migrate_test_nonexistent_store.json"),
    );
    cmd.env_remove("CIPHERVAULT_ACCOUNT_ENDPOINT");
    cmd.env_remove("CIPHERVAULT_SCOPE_TOKEN");
    cmd.env_remove("CIPHERVAULT_PROJECT");
    cmd.env_remove("CIPHERVAULT_ENV");
    // Endpoint last: `migrate` nests the flag on its subcommands (no
    // trailing child args here, so nothing swallows it).
    for arg in args {
        cmd.arg(arg);
    }
    if let Some(endpoint) = endpoint {
        cmd.arg("--endpoint").arg(endpoint);
    }
    cmd
}

/// Builds a real vault: writes files, init/track/push (offline operators).
async fn build_vault(dir: &Path, files: &[(&str, &str)]) {
    for (name, contents) in files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
    }
    let init = cli_command(dir, None, &["init", "--operators", "http://127.0.0.1:1"])
        .output()
        .await
        .unwrap();
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let mut track_args = vec!["track"];
    track_args.extend(files.iter().map(|(name, _)| *name));
    let track = cli_command(dir, None, &track_args).output().await.unwrap();
    assert!(
        track.status.success(),
        "track: {}",
        String::from_utf8_lossy(&track.stderr)
    );
    let push = cli_command(dir, None, &["push", "-m", "migration test snapshot"])
        .output()
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&push.stdout).contains("Snapshot captured and encrypted locally!"),
        "push: {} {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr)
    );
}

fn standard_files() -> Vec<(&'static str, &'static str)> {
    vec![(
        ".env",
        "MIG_ONE=one\nMIG_TWO=two\nDUP=first\nDUP=second\nlower_key=no\n",
    )]
}

fn migration_id_of(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("migration: "))
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[tokio::test]
async fn migrate_plan_dry_run_emits_diff_without_writes_or_values() {
    let dir = fresh_dir("dry-run");
    build_vault(&dir, &standard_files()).await;
    let (endpoint, stub) = start_stub().await;
    let out = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "plan",
            "--project",
            "shop",
            "--token",
            "t",
            "--dry-run",
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
    let diff: serde_json::Value = serde_json::from_str(&stdout).expect("dry-run prints JSON");
    assert_eq!(diff["project"], "shop");
    let entries = diff["entries"].as_array().unwrap();
    // Winners: MIG_ONE, MIG_TWO, DUP (last line), lower_key (server will
    // quarantine the invalid name).
    assert_eq!(entries.len(), 4);
    let dup = entries.iter().find(|entry| entry["name"] == "DUP").unwrap();
    assert_eq!(dup["line"], 4);
    assert_eq!(dup["env_guess"], "development");
    assert_eq!(dup["ambiguous"], true);
    let dropped = diff["dropped"].as_array().unwrap();
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0]["line"], 3);
    // No values or digests anywhere in the diff.
    for secret in ["\"one\"", "\"two\"", "\"second\"", "\"no\"", "\"first\""] {
        assert!(!stdout.contains(secret), "leaked {secret}: {stdout}");
    }
    assert!(!stdout.contains("digest"), "{stdout}");
    // Zero writes: only catalog + project reads.
    assert!(
        stub.inner.lock().unwrap().posts.is_empty(),
        "dry-run wrote: {:?}",
        stub.inner.lock().unwrap().posts
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn migrate_full_loop_plan_apply_verify() {
    let dir = fresh_dir("loop");
    build_vault(&dir, &standard_files()).await;
    let (endpoint, stub) = start_stub().await;

    let plan = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "plan",
            "--project",
            "shop",
            "--token",
            "t",
            "--default-env",
            "staging",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        plan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan_out = String::from_utf8_lossy(&plan.stdout);
    let mid = migration_id_of(&plan_out);
    assert!(!mid.is_empty(), "{plan_out}");
    assert!(
        plan_out.contains("quarantined: lower_key") || plan_out.contains("lower_key"),
        "{plan_out}"
    );

    // Client digests match the real value bytes (checked stub-side).
    {
        let inner = stub.inner.lock().unwrap();
        let entries = &inner.entries[&mid];
        for (name, value) in [("MIG_ONE", "one"), ("MIG_TWO", "two"), ("DUP", "second")] {
            let entry = entries.iter().find(|entry| entry.name == name).unwrap();
            assert_eq!(entry.state, "VALIDATED");
            assert_eq!(
                entry.source_digest_hex,
                sha256_hex(value.as_bytes()),
                "{name}"
            );
            assert_eq!(entry.env_id, "env-1");
            assert!(!entry.key.is_empty());
        }
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.name == "lower_key")
                .unwrap()
                .state,
            "QUARANTINED"
        );
    }

    let apply = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "apply",
            "--project",
            "shop",
            "--token",
            "t",
            "--migration-id",
            &mid,
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        apply.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let apply_out = String::from_utf8_lossy(&apply.stdout);
    assert!(apply_out.contains("migrated:  3"), "{apply_out}");
    assert!(
        apply_out.contains("skipped (not VALIDATED): 1"),
        "{apply_out}"
    );

    let verify = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "verify",
            "--project",
            "shop",
            "--token",
            "t",
            "--migration-id",
            &mid,
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        verify.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_out = String::from_utf8_lossy(&verify.stdout);
    assert!(verify_out.contains("readback ok: 3"), "{verify_out}");
    assert!(verify_out.contains("verified:    3"), "{verify_out}");
    // lower_key still quarantined ⇒ run stays verifying, never complete.
    assert!(
        verify_out.contains("run state:   verifying"),
        "{verify_out}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn migrate_resolve_rename_completes_the_run() {
    let dir = fresh_dir("resolve");
    build_vault(&dir, &standard_files()).await;
    let (endpoint, stub) = start_stub().await;

    let plan = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "plan",
            "--project",
            "shop",
            "--token",
            "t",
            "--default-env",
            "staging",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(plan.status.success());
    let mid = migration_id_of(&String::from_utf8_lossy(&plan.stdout));
    let quarantined = stub.inner.lock().unwrap().entries[&mid]
        .iter()
        .find(|entry| entry.state == "QUARANTINED")
        .unwrap()
        .ledger_id
        .clone();

    let resolve = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "resolve",
            "--project",
            "shop",
            "--token",
            "t",
            "--migration-id",
            &mid,
            "--entry",
            &quarantined,
            "--rename",
            "MIG_LOWER",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        resolve.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&resolve.stderr)
    );
    assert!(
        String::from_utf8_lossy(&resolve.stdout).contains("VALIDATED"),
        "stdout: {}",
        String::from_utf8_lossy(&resolve.stdout)
    );

    for action in ["apply", "verify"] {
        let out = cli_command(
            &dir,
            Some(&endpoint),
            &[
                "migrate",
                action,
                "--project",
                "shop",
                "--token",
                "t",
                "--migration-id",
                &mid,
            ],
        )
        .output()
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let detail = stub.inner.lock().unwrap().runs[&mid].clone();
    assert_eq!(detail.state, "complete");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn migrate_shred_guards_then_shreds() {
    let dir = fresh_dir("shred");
    build_vault(&dir, &standard_files()).await;
    let (endpoint, stub) = start_stub().await;
    let db_path = dir.join(".ciphervault").join("vault.db");

    let plan = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "plan",
            "--project",
            "shop",
            "--token",
            "t",
            "--default-env",
            "staging",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(plan.status.success());
    let mid = migration_id_of(&String::from_utf8_lossy(&plan.stdout));

    // Shred too early (nothing migrated): refused, vault intact.
    let early = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "shred-legacy",
            "--project",
            "shop",
            "--token",
            "t",
            "--confirm",
            "shop",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(!early.status.success());
    assert!(
        String::from_utf8_lossy(&early.stderr).contains("refusing to shred"),
        "stderr: {}",
        String::from_utf8_lossy(&early.stderr)
    );
    assert!(db_path.exists());

    // Wrong confirm: refused even late in the flow.
    for action in ["apply", "verify"] {
        let out = cli_command(
            &dir,
            Some(&endpoint),
            &[
                "migrate",
                action,
                "--project",
                "shop",
                "--token",
                "t",
                "--migration-id",
                &mid,
            ],
        )
        .output()
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let wrong = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "shred-legacy",
            "--project",
            "shop",
            "--token",
            "t",
            "--confirm",
            "nope",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(!wrong.status.success());
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("confirm mismatch"),
        "stderr: {}",
        String::from_utf8_lossy(&wrong.stderr)
    );
    assert!(db_path.exists());

    // Quarantined lower_key still blocks: resolve + apply + verify first.
    // (The stub's ledger id doubles as the entry handle.)
    let quarantined = stub.inner.lock().unwrap().entries[&mid]
        .iter()
        .find(|entry| entry.state == "QUARANTINED")
        .unwrap()
        .ledger_id
        .clone();
    let resolve = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "resolve",
            "--project",
            "shop",
            "--token",
            "t",
            "--migration-id",
            &mid,
            "--entry",
            &quarantined,
            "--rename",
            "MIG_LOWER",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        resolve.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&resolve.stderr)
    );
    for action in ["apply", "verify"] {
        let out = cli_command(
            &dir,
            Some(&endpoint),
            &[
                "migrate",
                action,
                "--project",
                "shop",
                "--token",
                "t",
                "--migration-id",
                &mid,
            ],
        )
        .output()
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let shred = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "shred-legacy",
            "--project",
            "shop",
            "--token",
            "t",
            "--confirm",
            "shop",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        shred.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&shred.stderr)
    );
    assert!(
        String::from_utf8_lossy(&shred.stdout).contains("shredded:"),
        "stdout: {}",
        String::from_utf8_lossy(&shred.stdout)
    );
    assert!(!db_path.exists());
    assert!(!dir.join(".ciphervault").join("vault.db-wal").exists());
    assert!(!dir.join(".ciphervault").join("vault.db-shm").exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn migrate_production_needs_explicit_ack() {
    let dir = fresh_dir("prodack");
    build_vault(&dir, &[(".env.production", "PROD_KEY=pv\n")]).await;
    let (endpoint, stub) = start_stub().await;

    let refused = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "plan",
            "--project",
            "shop",
            "--token",
            "t",
            "--dry-run",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--ack-production"),
        "stderr: {}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let acked = cli_command(
        &dir,
        Some(&endpoint),
        &[
            "migrate",
            "plan",
            "--project",
            "shop",
            "--token",
            "t",
            "--dry-run",
            "--ack-production",
        ],
    )
    .output()
    .await
    .unwrap();
    assert!(
        acked.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&acked.stderr)
    );
    let diff: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&acked.stdout)).unwrap();
    assert_eq!(diff["entries"][0]["env_guess"], "production");
    assert!(stub.inner.lock().unwrap().posts.is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn run_legacy_mode_warns_unless_acknowledged() {
    let dir = fresh_dir("legacywarn");
    build_vault(&dir, &[(".env", "K=v\n")]).await;

    let warned = cli_command(&dir, None, &["run", "--dry-run"])
        .output()
        .await
        .unwrap();
    assert!(warned.status.success());
    assert!(
        String::from_utf8_lossy(&warned.stderr).contains("LEGACY_PATH_DEPRECATED"),
        "stderr: {}",
        String::from_utf8_lossy(&warned.stderr)
    );
    let silent = cli_command(&dir, None, &["run", "--legacy", "--dry-run"])
        .output()
        .await
        .unwrap();
    assert!(silent.status.success());
    assert!(
        !String::from_utf8_lossy(&silent.stderr).contains("LEGACY_PATH_DEPRECATED"),
        "stderr: {}",
        String::from_utf8_lossy(&silent.stderr)
    );
    std::fs::remove_dir_all(&dir).ok();
}
