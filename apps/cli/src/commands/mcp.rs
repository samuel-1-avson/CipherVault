//! Model Context Protocol (MCP) stdio JSON-RPC 2.0 server for Claude Code,
//! Codex, Cursor, and other MCP-capable coding agents.
//!
//! Exposes CipherVault's zero-knowledge tools (`ciphervault_status`,
//! `ciphervault_scan`, `ciphervault_redact`, `ciphervault_run`,
//! `ciphervault_push`, `ciphervault_diff`, `ciphervault_audit`,
//! `ciphervault_env_doctor`, `ciphervault_proxy_doctor`,
//! `ciphervault_recovery_drill`, `ciphervault_secret_generate`) over
//! newline-delimited JSON-RPC without ever exposing raw secret values.

use anyhow::{Context, Result};
use ciphervault_local_store::LocalVaultStore;
use rand::RngCore;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use zeroize::Zeroize;

use super::agent_bridge::BridgeSecretCache;
use super::hook::scan_hook_violations;
use crate::util::{
    get_active_vault_path, get_configured_operators, get_vault_store, VaultContext,
    DEFAULT_PRODUCTION_OPERATORS, OPERATORS_FILE, REQUEST_VAULT_CONTEXT, VAULT_DIR, DB_FILE,
};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

const MINIMAL_ENV_KEEP: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "APPDATA",
    "LOCALAPPDATA",
    "COMSPEC",
    "PATHEXT",
];

const BLOCKED_OPERATOR_HOSTS: &[&str] = &[
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
];

const AUDIT_RECEIPT_WITHHELD_MSG: &str = "[CipherVault] run output withheld: the audit-log write failed, so there is no receipt for it. Exit code and counts are kept.";

fn default_no_net() -> bool {
    cfg!(any(
        target_os = "linux",
        target_vendor = "apple",
        target_os = "windows"
    ))
}

/// Build an allowlisted minimal environment for child CLI invocations so
/// inherited provider keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.) never
/// leak into subprocesses while OS runtime vars and `CIPHERVAULT_*` config pass.
fn build_minimal_env_from<I>(vars: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut kept: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (k, v) in vars {
        let upper = k.to_ascii_uppercase();
        if upper.starts_with("CIPHERVAULT_") || MINIMAL_ENV_KEEP.contains(&upper.as_str()) {
            kept.insert(upper, (k, v));
        }
    }
    kept.insert(
        "NO_COLOR".to_string(),
        ("NO_COLOR".to_string(), "1".to_string()),
    );
    kept.into_values().collect()
}

fn minimal_env() -> Vec<(String, String)> {
    build_minimal_env_from(std::env::vars())
}

fn tool_definitions() -> serde_json::Value {
    serde_json::json!({
        "tools": [
            {
                "name": "ciphervault_status",
                "description": "Show CipherVault vault status for the workspace: tracked file paths (never secret contents), active snapshot head, operator count, and keyring backend.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    }
                }
            },
            {
                "name": "ciphervault_scan",
                "description": "Scan workspace and staged Git diffs for confidential files, secret sprawl, and leaked credential shapes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "deep": { "type": "boolean", "default": true, "description": "Inspect staged diff lines and workspace sprawl" },
                        "fix": { "type": "boolean", "default": false, "description": "Automatically append unprotected secret files to .gitignore" },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    }
                }
            },
            {
                "name": "ciphervault_redact",
                "description": "Fail-closed exact-value (raw, base64, percent-encoded, hex, JSON-escaped) and credential-pattern scrubber. Always attests exact_values_complete: true on release.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "description": "Text to scrub before passing to an LLM or external log" },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "ciphervault_run",
                "description": "Run a command with vault secrets injected into its child environment in RAM only (nothing written to disk). Output is exact-value and shape scrubbed and recorded with a fail-closed scrubbed_result audit receipt. Supports --allow-keys scoping and --no-net network sandboxing.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "array", "items": { "type": "string" }, "description": "Command and args, e.g. [\"pytest\", \"-q\"]" },
                        "profile": { "type": "string", "description": "Optional workspace policy profile name from .ciphervault/policy.toml" },
                        "allow_keys": { "type": "array", "items": { "type": "string" }, "description": "Optional allowlist of variable names to inject" },
                        "no_net": { "type": "boolean", "description": "Block child network access (defaults true on Linux, macOS, and Windows; cannot combine with proxy)" },
                        "proxy": { "type": "boolean", "default": false, "description": "Use loopback credential proxy so real API keys stay out of child env" },
                        "env_file": { "type": "string" },
                        "project": { "type": "string" },
                        "env": { "type": "string" },
                        "dry_run": { "type": "boolean", "default": false },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "ciphervault_push",
                "description": "Create an encrypted snapshot of tracked secret files (client-side sealed before upload).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": { "type": "string", "description": "Snapshot commit message" },
                        "local_only": { "type": "boolean", "default": false },
                        "shred_working_copy": { "type": "boolean", "default": false, "description": "Zero-fill and remove tracked plaintext files from the working directory after sealing the snapshot" },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    }
                }
            },
            {
                "name": "ciphervault_diff",
                "description": "Inspect masked key-level diffs across vault snapshots or against the working tree (never reveals plaintext secret values).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from_snapshot": { "type": "string", "description": "Optional base snapshot ID (64-char hex), \"head\", or \"working\" (defaults to \"head\")" },
                        "to_snapshot": { "type": "string", "description": "Optional target snapshot ID (64-char hex), \"head\", or \"working\" (defaults to \"working\")" },
                        "file": { "type": "string", "description": "Optional relative file path filter (e.g. \".env\")" },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    }
                }
            },
            {
                "name": "ciphervault_audit",
                "description": "Read and verify the tamper-evident CipherVault agent audit log.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "default": 20, "minimum": 1, "maximum": 200 },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    }
                }
            },
            {
                "name": "ciphervault_env_doctor",
                "description": "Zero-knowledge environment diagnostics: cross-reference env vars referenced in code and .env.example against vault keys and lint .env* values in RAM without ever returning secret values.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "env_file": { "type": "string", "description": "Optional specific .env file relative to workspace cwd" },
                        "sync_env_example": { "type": "boolean", "default": false, "description": "Safely create/update .env.example with KEY= # [required] placeholders" },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    }
                }
            },
            {
                "name": "ciphervault_proxy_doctor",
                "description": "Dry-run loopback proxy diagnostic: report which vault keys map to built-in provider routes vs .ciphervault/policy.toml upstreams vs unmapped keys. Never exposes secret values.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "env_file": { "type": "string", "description": "Optional specific .env file relative to workspace cwd" },
                        "profile": { "type": "string", "description": "Optional profile name from .ciphervault/policy.toml" },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    }
                }
            },
            {
                "name": "ciphervault_recovery_drill",
                "description": "Prove a recovery kit or guardian shares restore cleanly: restores into a fresh temp directory created and deleted by the tool, returning only a SHA-256 file manifest. Accepts FILE PATHS only — never paste kit/share contents.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "kit": { "type": "string", "description": "Path to recovery kit file on disk" },
                        "shares": { "type": "array", "items": { "type": "string" }, "description": "Paths to guardian share files on disk" },
                        "via": { "type": "array", "items": { "type": "string" }, "description": "Optional configured public operator URLs to query (private, loopback, link-local, cloud-metadata, and unconfigured endpoints are blocked)" },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    }
                }
            },
            {
                "name": "ciphervault_secret_generate",
                "description": "Generate a cryptographically random secret directly inside the vault via `ciphervault vault generate --json` (preserving all existing sealed keys and never returning the secret value).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Environment variable name ([A-Za-z_][A-Za-z0-9_]*)" },
                        "format": { "type": "string", "enum": ["base64url", "hex", "uuid", "alphanumeric"], "default": "base64url" },
                        "bytes": { "type": "integer", "default": 32, "minimum": 16, "maximum": 64, "description": "Entropy length in bytes (16..64)" },
                        "env_file": { "type": "string", "default": ".env", "description": "Optional relative secret file inside workspace cwd" },
                        "seal": { "type": "boolean", "description": "Shred the plaintext working copy after committing the encrypted snapshot" },
                        "overwrite": { "type": "boolean", "default": false, "description": "Allow overwriting an existing secret key (default: false)" },
                        "cwd": { "type": "string", "description": "Optional workspace directory" }
                    },
                    "required": ["name"]
                }
            }
        ]
    })
}

fn optional_trimmed_str(args: &serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn validate_optional_cwd(args: &serde_json::Value) -> std::result::Result<Option<String>, String> {
    let Some(raw) = optional_trimmed_str(args, "cwd") else {
        return Ok(None);
    };
    if raw.contains('\0')
        || raw.starts_with("\\\\")
        || raw.starts_with("//")
        || raw.starts_with("\\??\\")
    {
        return Err("`cwd` cannot be a UNC or network share path".to_string());
    }
    let path = Path::new(&raw);
    if !path.is_dir() {
        return Err(format!("workspace directory does not exist: {raw}"));
    }
    Ok(Some(raw))
}

fn validate_relative_env_file(raw: &str) -> std::result::Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('-')
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.contains('\0')
        || trimmed.contains('\n')
        || trimmed.contains('\r')
    {
        return Err("`env_file` must be a safe relative path inside workspace cwd".to_string());
    }
    let p = Path::new(trimmed);
    if p.is_absolute() {
        return Err("`env_file` must be a relative path inside workspace cwd".to_string());
    }
    for comp in p.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("`env_file` cannot escape workspace cwd".to_string());
            }
            Component::Normal(seg)
                if seg.to_string_lossy().eq_ignore_ascii_case(VAULT_DIR) =>
            {
                return Err("`env_file` cannot target `.ciphervault`".to_string());
            }
            _ => {}
        }
    }
    Ok(trimmed.replace('\\', "/"))
}

fn is_valid_secret_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VaultLookup {
    None,
    Found(PathBuf),
    Uninspectable(String),
}

fn find_vault_db_from_dir(start: &Path) -> VaultLookup {
    let abs = if start.is_absolute() {
        start.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cur) => cur.join(start),
            Err(e) => return VaultLookup::Uninspectable(format!("cannot resolve cwd: {e}")),
        }
    };
    let mut cur: Option<&Path> = Some(abs.as_path());
    while let Some(dir) = cur {
        let candidate = dir.join(VAULT_DIR).join(DB_FILE);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => return VaultLookup::Found(candidate),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                cur = dir.parent();
            }
            Err(e) => {
                return VaultLookup::Uninspectable(format!(
                    "cannot inspect vault path '{}': {e}",
                    candidate.display()
                ));
            }
        }
    }
    VaultLookup::None
}

fn lookup_vault_db_for_cwd(cwd: Option<&str>) -> VaultLookup {
    if let Some(dir) = cwd {
        return find_vault_db_from_dir(Path::new(dir));
    }
    // Honor task-local REQUEST_VAULT_CONTEXT (used by tests and scoped contexts).
    if let Ok(path) = REQUEST_VAULT_CONTEXT.try_with(|ctx| ctx.db_path.clone()) {
        return match std::fs::symlink_metadata(&path) {
            Ok(_) => VaultLookup::Found(path),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                VaultLookup::None
            }
            Err(e) => VaultLookup::Uninspectable(format!(
                "cannot inspect active vault '{}': {e}",
                path.display()
            )),
        };
    }
    let active = get_active_vault_path();
    match std::fs::symlink_metadata(&active) {
        Ok(_) => VaultLookup::Found(active),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            match std::env::current_dir() {
                Ok(cur) => find_vault_db_from_dir(&cur),
                Err(_) => VaultLookup::None,
            }
        }
        Err(e) => VaultLookup::Uninspectable(format!(
            "cannot inspect active vault '{}': {e}",
            active.display()
        )),
    }
}

fn vault_cwd_for(cwd: Option<&str>) -> Option<String> {
    if let VaultLookup::Found(db_path) = lookup_vault_db_for_cwd(cwd) {
        if let Some(root) = db_path.parent().and_then(|p| p.parent()) {
            return Some(root.to_string_lossy().to_string());
        }
    }
    cwd.map(str::to_string)
}

fn with_vault_scope_for_cwd<T, F>(cwd: Option<&str>, f: F) -> std::result::Result<T, String>
where
    F: FnOnce() -> T,
{
    let Some(dir) = cwd else {
        return Ok(f());
    };
    match find_vault_db_from_dir(Path::new(dir)) {
        VaultLookup::None => {
            // Scope to a non-existent db inside `dir` so process-global CWD's vault
            // doesn't bleed into a vaultless `cwd` call.
            let fake_ctx = VaultContext {
                db_path: Path::new(dir).join(VAULT_DIR).join(DB_FILE),
                root_dir: Path::new(dir).to_path_buf(),
            };
            Ok(REQUEST_VAULT_CONTEXT.sync_scope(fake_ctx, f))
        }
        VaultLookup::Found(db_path) => {
            let ctx = VaultContext::from_db_path(&db_path)
                .map_err(|e| format!("cannot resolve vault context: {e}"))?;
            Ok(REQUEST_VAULT_CONTEXT.sync_scope(ctx, f))
        }
        VaultLookup::Uninspectable(err) => Err(err),
    }
}

fn scrub_fail_closed(
    text: &str,
    cwd: Option<&str>,
    cache: &mut BridgeSecretCache,
) -> std::result::Result<(String, usize, usize, bool), String> {
    with_vault_scope_for_cwd(cwd, || {
        cache.refresh_if_needed();
        if !cache.complete {
            return Err(cache
                .last_error
                .clone()
                .unwrap_or_else(|| "exact-value loading incomplete".to_string()));
        }
        let refs: Vec<(&str, &str)> = cache
            .values
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let (exact, n_exact) = ciphervault_redact::scrub_exact_values(text, &refs);
        let (scrubbed, n_shape) = ciphervault_redact::redact_text_counted(&exact);
        Ok((scrubbed, n_exact + n_shape, cache.values.len(), cache.vault))
    })?
}

fn spawn_self_json(
    args: &[String],
    cwd: Option<&str>,
    cache: &mut BridgeSecretCache,
) -> (serde_json::Value, bool) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return (
                serde_json::json!({ "ok": false, "error": format!("failed to locate ciphervault binary: {e}") }),
                true,
            )
        }
    };
    let mut cmd = Command::new(exe);
    cmd.env_clear();
    for (k, v) in minimal_env() {
        cmd.env(k, v);
    }
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return (
                serde_json::json!({ "ok": false, "error": format!("failed to spawn ciphervault subprocess: {e}") }),
                true,
            )
        }
    };

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr_raw = String::from_utf8_lossy(&output.stderr);
    let (stdout_scrubbed, _, _, _) = match scrub_fail_closed(&stdout_raw, cwd, cache) {
        Ok(res) => res,
        Err(err) => {
            return (
                serde_json::json!({
                    "ok": false,
                    "exact_values_complete": false,
                    "error": format!("subprocess output withheld (exact-value scrub unavailable): {err}"),
                }),
                true,
            );
        }
    };
    let (stderr_scrubbed, _, _, _) = match scrub_fail_closed(&stderr_raw, cwd, cache) {
        Ok(res) => res,
        Err(err) => {
            return (
                serde_json::json!({
                    "ok": false,
                    "exact_values_complete": false,
                    "error": format!("subprocess output withheld (exact-value scrub unavailable): {err}"),
                }),
                true,
            );
        }
    };

    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(stdout_scrubbed.trim()) {
        let is_err = !output.status.success();
        return (parsed, is_err);
    }

    let is_err = !output.status.success();
    (
        serde_json::json!({
            "ok": !is_err,
            "exit_code": output.status.code(),
            "stdout": stdout_scrubbed.trim(),
            "stderr": stderr_scrubbed.trim(),
        }),
        is_err,
    )
}

fn profile_omits_default_no_net(profile_name: &str, cwd: Option<&str>) -> bool {
    let VaultLookup::Found(db_path) = lookup_vault_db_for_cwd(cwd) else {
        return false;
    };
    let Some(vault_dir) = db_path.parent() else {
        return false;
    };
    let Ok(Some(policy)) = super::run::load_workspace_policy(vault_dir) else {
        return false;
    };
    let Some(prof) = policy.profiles.get(profile_name) else {
        return false;
    };
    prof.proxy == Some(true) || !prof.upstreams.is_empty() || prof.no_net == Some(false)
}

#[cfg(test)]
fn build_run_cli_args(args: &serde_json::Value) -> std::result::Result<Vec<String>, String> {
    build_run_cli_args_for_cwd(args, None)
}

fn build_run_cli_args_for_cwd(
    args: &serde_json::Value,
    cwd: Option<&str>,
) -> std::result::Result<Vec<String>, String> {
    let dry_run = args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let cmd_arr = args
        .get("command")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if cmd_arr.is_empty() && !dry_run {
        return Err("`command` non-empty array is required".to_string());
    }
    let mut cli_args = vec!["run".to_string(), "--json".to_string()];
    if dry_run {
        cli_args.push("--dry-run".to_string());
    }
    if let Some(ef) = optional_trimmed_str(args, "env_file") {
        let clean = validate_relative_env_file(&ef)?;
        cli_args.push("--env-file".to_string());
        cli_args.push(clean);
    }
    if let Some(proj) = optional_trimmed_str(args, "project") {
        if proj.starts_with('-') {
            return Err("`project` cannot start with '-'".to_string());
        }
        cli_args.push("--project".to_string());
        cli_args.push(proj);
    }
    if let Some(env) = optional_trimmed_str(args, "env") {
        if env.starts_with('-') {
            return Err("`env` cannot start with '-'".to_string());
        }
        cli_args.push("--env".to_string());
        cli_args.push(env);
    }
    let profile_opt = optional_trimmed_str(args, "profile");
    if let Some(ref profile) = profile_opt {
        if profile.starts_with('-') {
            return Err("`profile` cannot start with '-'".to_string());
        }
        cli_args.push("--profile".to_string());
        cli_args.push(profile.clone());
    }
    if let Some(allow_arr) = args.get("allow_keys").and_then(|v| v.as_array()) {
        let keys: Vec<String> = allow_arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect();
        if keys.is_empty() {
            return Err("`allow_keys` cannot be empty when provided".to_string());
        }
        cli_args.push("--allow-keys".to_string());
        cli_args.push(keys.join(","));
    }
    // Agent-supplied `proxy_upstream` is intentionally never forwarded over MCP.
    let proxy_flag = args.get("proxy").and_then(|v| v.as_bool()).unwrap_or(false);
    let no_net = args.get("no_net").and_then(|v| v.as_bool()).unwrap_or_else(|| {
        if proxy_flag {
            return false;
        }
        if let Some(ref prof_name) = profile_opt {
            if profile_omits_default_no_net(prof_name, cwd) {
                return false;
            }
        }
        default_no_net()
    });
    if proxy_flag && no_net {
        return Err("`proxy` and `no_net` cannot both be enabled".to_string());
    }
    if proxy_flag {
        cli_args.push("--proxy".to_string());
    }
    if no_net {
        cli_args.push("--no-net".to_string());
    }
    if !cmd_arr.is_empty() {
        cli_args.push("--".to_string());
        cli_args.extend(cmd_arr);
    }
    Ok(cli_args)
}

fn finalize_run_with_audit_receipt(
    mut payload: serde_json::Value,
    is_err: bool,
    args: &serde_json::Value,
    vault_lookup: VaultLookup,
) -> (serde_json::Value, bool) {
    let dry_run = args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if dry_run {
        return (payload, is_err);
    }

    let has_run_output = payload.as_object().is_some_and(|obj| {
        obj.get("stdout").is_some_and(|v| v.is_string())
            || obj.get("stderr").is_some_and(|v| v.is_string())
    });
    if !has_run_output {
        return (payload, is_err);
    }

    let db_path = match vault_lookup {
        VaultLookup::None => return (payload, is_err),
        VaultLookup::Found(p) => p,
        VaultLookup::Uninspectable(_) => {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "stdout".to_string(),
                    serde_json::Value::String(AUDIT_RECEIPT_WITHHELD_MSG.to_string()),
                );
                obj.insert("stderr".to_string(), serde_json::Value::String(String::new()));
                obj.insert("audit_receipt".to_string(), serde_json::Value::Bool(false));
            }
            return (payload, true);
        }
    };

    let program = args
        .get("command")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(64)
        .collect::<String>();
    let exit_code = payload
        .get("exit_code")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let redactions = payload
        .get("redactions")
        .cloned()
        .unwrap_or_else(|| serde_json::json!(0));
    let stdout_str = payload.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
    let rendered_text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
    let output_sha256 = hex::encode(sha2::Sha256::digest(rendered_text.as_bytes()));
    let content_sha256 = hex::encode(sha2::Sha256::digest(stdout_str.trim().as_bytes()));

    let mut detail = serde_json::json!({
        "program": program,
        "exit_code": exit_code,
        "redactions": redactions,
        "output_sha256": output_sha256,
        "content_sha256": content_sha256,
        "output_bytes": rendered_text.len(),
    });
    if let Some(profile) = optional_trimmed_str(args, "profile") {
        if let Some(obj) = detail.as_object_mut() {
            obj.insert(
                "profile".to_string(),
                serde_json::Value::String(profile.chars().take(64).collect()),
            );
        }
    }
    let detail_str = detail.to_string();

    let recorded = LocalVaultStore::open(&db_path)
        .and_then(|store| store.append_agent_audit("ciphervault_run", "scrubbed_result", "", &detail_str))
        .is_ok();

    if recorded {
        (payload, is_err)
    } else {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "stdout".to_string(),
                serde_json::Value::String(AUDIT_RECEIPT_WITHHELD_MSG.to_string()),
            );
            obj.insert("stderr".to_string(), serde_json::Value::String(String::new()));
            obj.insert("audit_receipt".to_string(), serde_json::Value::Bool(false));
        }
        (payload, true)
    }
}

fn normalize_snapshot_ref(raw: &str) -> std::result::Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('-') {
        return Err("snapshot reference cannot start with '-'".to_string());
    }
    if trimmed.eq_ignore_ascii_case("head") {
        Ok("head".to_string())
    } else if trimmed.eq_ignore_ascii_case("working") {
        Ok("working".to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn build_diff_cli_args(args: &serde_json::Value) -> std::result::Result<Vec<String>, String> {
    let mut cli_args = vec!["diff".to_string(), "--json".to_string()];

    if let Some(file) = optional_trimmed_str(args, "file") {
        if file.starts_with('-') {
            return Err("`file` filter cannot start with '-'".to_string());
        }
        cli_args.push("--file".to_string());
        cli_args.push(file);
    }

    let from_snap = match optional_trimmed_str(args, "from_snapshot") {
        Some(raw) => Some(normalize_snapshot_ref(&raw)?),
        None => None,
    };
    let to_snap = match optional_trimmed_str(args, "to_snapshot") {
        Some(raw) => Some(normalize_snapshot_ref(&raw)?),
        None => None,
    };

    match (from_snap, to_snap) {
        (None, None) => {}
        (Some(a), None) => {
            cli_args.push("--".to_string());
            cli_args.push(a);
        }
        (None, Some(b)) => {
            cli_args.push("--".to_string());
            cli_args.push("head".to_string());
            cli_args.push(b);
        }
        (Some(a), Some(b)) => {
            cli_args.push("--".to_string());
            cli_args.push(a);
            cli_args.push(b);
        }
    }

    Ok(cli_args)
}

fn build_env_doctor_cli_args(args: &serde_json::Value) -> std::result::Result<Vec<String>, String> {
    let mut cli_args = vec!["env-doctor".to_string(), "--json".to_string()];
    if let Some(ef) = optional_trimmed_str(args, "env_file") {
        let clean = validate_relative_env_file(&ef)?;
        cli_args.push("--env-file".to_string());
        cli_args.push(clean);
    }
    if args
        .get("sync_env_example")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        cli_args.push("--sync-env-example".to_string());
    }
    Ok(cli_args)
}

fn build_secret_generate_cli_args(
    args: &serde_json::Value,
) -> std::result::Result<(Vec<String>, String, String, String), String> {
    let name = optional_trimmed_str(args, "name")
        .ok_or_else(|| "invalid secret name: `name` is required".to_string())?;
    if !is_valid_secret_name(&name) {
        return Err("invalid secret name: must match [A-Za-z_][A-Za-z0-9_]*".to_string());
    }

    let fmt = optional_trimmed_str(args, "format")
        .unwrap_or_else(|| "base64url".to_string())
        .to_ascii_lowercase();
    if !matches!(fmt.as_str(), "base64url" | "hex" | "uuid" | "alphanumeric") {
        return Err(
            "invalid format: expected base64url, hex, uuid, or alphanumeric".to_string(),
        );
    }

    let nbytes: u64 = match args.get("bytes") {
        None | Some(serde_json::Value::Null) => 32,
        Some(serde_json::Value::Number(n)) => {
            let Some(val) = n.as_u64() else {
                return Err("`bytes` must be an integer between 16 and 64".to_string());
            };
            if !(16..=64).contains(&val) {
                return Err("`bytes` must be an integer between 16 and 64".to_string());
            }
            val
        }
        Some(_) => return Err("`bytes` must be an integer between 16 and 64".to_string()),
    };

    let env_file = match optional_trimmed_str(args, "env_file") {
        Some(raw) => validate_relative_env_file(&raw)?,
        None => ".env".to_string(),
    };

    let mut cli_args = vec![
        "vault".to_string(),
        "generate".to_string(),
        name.clone(),
        "--format".to_string(),
        fmt.clone(),
        "--bytes".to_string(),
        nbytes.to_string(),
        "--env-file".to_string(),
        env_file.clone(),
    ];

    if args.get("seal").and_then(|v| v.as_bool()) == Some(true) {
        cli_args.push("--seal".to_string());
    }
    if args
        .get("overwrite")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        cli_args.push("--overwrite".to_string());
    }
    cli_args.push("--json".to_string());

    Ok((cli_args, name, fmt, env_file))
}

fn classify_proxy_keys(
    secret_names: &[String],
    policy_upstreams: &BTreeMap<String, String>,
) -> serde_json::Value {
    let mut mapped_providers = Vec::new();
    let mut mapped_policy = Vec::new();
    let mut unmapped = Vec::new();

    for name in secret_names {
        if let Some(upstream) = policy_upstreams.get(name) {
            mapped_policy.push(serde_json::json!({
                "key": name,
                "upstream": upstream,
            }));
        } else if let Some((upstream, _hdr, _bearer, base_envs)) =
            super::run_proxy::known_provider_for_key(name)
        {
            let env_names: Vec<&str> = base_envs.iter().map(|(e, _)| *e).collect();
            mapped_providers.push(serde_json::json!({
                "key": name,
                "upstream": upstream,
                "injected_base_envs": env_names,
            }));
        } else {
            unmapped.push(name.clone());
        }
    }

    let proxy_ready = !mapped_providers.is_empty() || !mapped_policy.is_empty();
    serde_json::json!({
        "success": true,
        "proxy_ready": proxy_ready,
        "mapped_providers": mapped_providers,
        "mapped_policy_upstreams": mapped_policy,
        "unmapped_keys": unmapped,
        "notes": [
            "Keys in mapped_providers/mapped_policy_upstreams can run with proxy=true without entering child RAM.",
            "Keys in unmapped_keys require no_net=true (offline) or an entry in .ciphervault/policy.toml [profiles.<name>.upstreams].",
        ],
    })
}

fn collect_policy_upstreams(
    vault_dir: &Path,
    profile_name: Option<&str>,
) -> std::result::Result<BTreeMap<String, String>, String> {
    let policy_opt = super::run::load_workspace_policy(vault_dir)
        .map_err(|e| format!("failed to load .ciphervault/policy.toml: {e}"))?;
    let mut out = BTreeMap::new();
    let Some(policy) = policy_opt else {
        return Ok(out);
    };
    if let Some(prof_name) = profile_name {
        if let Some(prof) = policy.profiles.get(prof_name) {
            out.extend(prof.upstreams.clone());
        }
    } else {
        for prof in policy.profiles.values() {
            out.extend(prof.upstreams.clone());
        }
    }
    Ok(out)
}

fn normalize_operator_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return None;
    }
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let host = parsed.host_str()?.trim().to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.contains('%') {
        return None;
    }
    let host_lit = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let netloc = match parsed.port() {
        Some(port) => format!("{host_lit}:{port}"),
        None => host_lit,
    };
    let path = parsed.path().trim_end_matches('/');
    Some(format!("{scheme}://{netloc}{path}"))
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let oct = ip.octets();
    let is_cgnat = oct[0] == 100 && (64..=127).contains(&oct[1]);
    let is_ietf_protocol = oct[0] == 192 && oct[1] == 0 && oct[2] == 0;
    let is_benchmarking = oct[0] == 198 && matches!(oct[1], 18 | 19);
    let is_reserved = oct[0] >= 240;
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_cgnat
        || is_ietf_protocol
        || is_benchmarking
        || is_reserved)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_ipv4(mapped);
            }
            // IPv4-translated (::ffff:0:0:0/96) and NAT64 well-known prefix (64:ff9b::/96)
            let segs = v6.segments();
            if (segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0xffff
                && segs[5] == 0)
                || (segs[0] == 0x0064
                    && segs[1] == 0xff9b
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0
                    && segs[5] == 0)
            {
                let v4 = Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                );
                return is_public_ipv4(v4);
            }
            let is_unique_local = (segs[0] & 0xfe00) == 0xfc00;
            let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
            let is_doc = segs[0] == 0x2001 && segs[1] == 0x0db8;
            let is_global_unicast = (segs[0] & 0xe000) == 0x2000;
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local
                || is_link_local
                || is_doc
                || !is_global_unicast)
        }
    }
}

/// Unconditional SSRF floor for `via` operator endpoints: rejects private,
/// loopback, link-local (incl. 169.254.169.254), CGNAT, cloud-metadata,
/// internal hostnames, and unresolvable hosts (fail-closed on DNS errors).
fn is_public_operator_url(norm_url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(norm_url) else {
        return false;
    };
    let Some(host_raw) = parsed.host_str() else {
        return false;
    };
    let host = host_raw
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty()
        || BLOCKED_OPERATOR_HOSTS.contains(&host.as_str())
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return false;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_public_ip(ip);
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return is_public_ip(IpAddr::V6(v6));
    }

    let port = parsed
        .port_or_known_default()
        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let Ok(addrs) = (host.as_str(), port).to_socket_addrs() else {
        return false;
    };
    let resolved: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
    if resolved.is_empty() {
        return false;
    }
    resolved.into_iter().all(is_public_ip)
}

fn configured_operators_for_cwd(cwd: Option<&str>) -> BTreeSet<String> {
    let raw_list: Vec<String> = if let Ok(env_ops) = std::env::var("CIPHERVAULT_OPERATORS") {
        let items: Vec<String> = env_ops
            .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !items.is_empty() {
            items
        } else {
            return BTreeSet::new();
        }
    } else {
        match lookup_vault_db_for_cwd(cwd) {
            VaultLookup::Found(db_path) => {
                let Some(vault_dir) = db_path.parent() else {
                    return BTreeSet::new();
                };
                let ops_path = vault_dir.join(OPERATORS_FILE);
                match std::fs::symlink_metadata(&ops_path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        DEFAULT_PRODUCTION_OPERATORS
                            .iter()
                            .map(|s| (*s).to_string())
                            .collect()
                    }
                    Err(_) => return BTreeSet::new(),
                    Ok(_) => {
                        let Ok(content) = std::fs::read_to_string(&ops_path) else {
                            return BTreeSet::new();
                        };
                        let Ok(ops) = serde_json::from_str::<Vec<String>>(&content) else {
                            return BTreeSet::new();
                        };
                        if ops.is_empty() {
                            return BTreeSet::new();
                        }
                        ops
                    }
                }
            }
            VaultLookup::None | VaultLookup::Uninspectable(_) => return BTreeSet::new(),
        }
    };

    let mut out = BTreeSet::new();
    for item in raw_list {
        let Some(norm) = normalize_operator_url(&item) else {
            return BTreeSet::new();
        };
        out.insert(norm);
    }
    out
}

fn validate_via_endpoints_with_checker<F>(
    via_items: &[String],
    configured: &BTreeSet<String>,
    is_public: F,
) -> std::result::Result<Vec<String>, String>
where
    F: Fn(&str) -> bool,
{
    let mut validated = Vec::new();
    for raw in via_items {
        let Some(norm) = normalize_operator_url(raw) else {
            return Err(
                "invalid operator URL in `via`: must be a clean http(s) origin without query, fragment, or credentials"
                    .to_string(),
            );
        };
        if !is_public(&norm) {
            return Err(format!(
                "refusing `via` endpoint '{norm}': private, loopback, link-local, or cloud-metadata hosts are not allowed"
            ));
        }
        if !configured.contains(&norm) {
            return Err(format!(
                "refusing `via` endpoint '{norm}': not in this vault's configured operator list (.ciphervault/operators.json)"
            ));
        }
        if !validated.contains(&norm) {
            validated.push(norm);
        }
    }
    Ok(validated)
}

fn validate_drill_file_path(raw: &str, field: &str) -> std::result::Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 1024
        || trimmed.starts_with('-')
        || trimmed.contains('\0')
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains("-----BEGIN")
        || trimmed.starts_with("\\\\")
        || trimmed.starts_with("//")
        || trimmed.starts_with("\\??\\")
    {
        return Err(format!(
            "`{field}` must be a single-line local file path (paths only — never paste kit/share contents)"
        ));
    }
    Ok(trimmed.to_string())
}

struct TempDrillDir(PathBuf);

impl TempDrillDir {
    fn create() -> std::io::Result<Self> {
        let base = std::env::temp_dir();
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        for _ in 0..16 {
            let mut rnd = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut rnd);
            let cand = base.join(format!("cv-drill-{}-{}", std::process::id(), hex::encode(rnd)));
            match builder.create(&cand) {
                Ok(()) => return Ok(Self(cand)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate unique drill temp directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDrillDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hash_drill_directory(root: &Path) -> std::io::Result<Vec<serde_json::Value>> {
    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or_else(|_| entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        entries.push((rel, entry.path().to_path_buf()));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut manifest = Vec::with_capacity(entries.len());
    for (rel, full) in entries {
        let mut bytes = std::fs::read(&full)?;
        let size = bytes.len() as u64;
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        bytes.zeroize();
        manifest.push(serde_json::json!({
            "path": rel,
            "size": size,
            "sha256": digest,
        }));
    }
    Ok(manifest)
}

fn record_best_effort_audit(
    cwd: Option<&str>,
    tool: &str,
    decision: &str,
    path: &str,
    detail: &serde_json::Value,
) {
    if let VaultLookup::Found(db_path) = lookup_vault_db_for_cwd(cwd) {
        if let Ok(store) = LocalVaultStore::open(&db_path) {
            let _ = store.append_agent_audit(tool, decision, path, &detail.to_string());
        }
    }
}

fn call_tool(
    name: &str,
    args: &serde_json::Value,
    cache: &mut BridgeSecretCache,
) -> (serde_json::Value, bool) {
    let cwd = match validate_optional_cwd(args) {
        Ok(c) => c,
        Err(msg) => return (serde_json::json!({ "ok": false, "error": msg }), true),
    };

    match name {
        "ciphervault_status" => {
            let res = with_vault_scope_for_cwd(cwd.as_deref(), || {
                let Ok(store) = get_vault_store() else {
                    return (
                        serde_json::json!({ "initialized": false, "error": "no active CipherVault workspace" }),
                        true,
                    );
                };
                let tracked: Vec<String> = store
                    .list_tracked_files()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(p, _)| p.to_string_lossy().replace('\\', "/"))
                    .collect();
                let head = store
                    .get_active_head()
                    .ok()
                    .flatten()
                    .map(|h| hex::encode(h.snapshot_id));
                let operators = get_configured_operators().len();
                (
                    serde_json::json!({
                        "initialized": true,
                        "tracked_files": tracked,
                        "active_head": head,
                        "configured_operators": operators,
                        "keyring_backend": ciphervault_local_store::active_keyring_backend(),
                    }),
                    false,
                )
            });
            match res {
                Ok(pair) => pair,
                Err(msg) => (serde_json::json!({ "initialized": false, "error": msg }), true),
            }
        }
        "ciphervault_scan" => {
            let deep = args.get("deep").and_then(|v| v.as_bool()).unwrap_or(true);
            let fix = args.get("fix").and_then(|v| v.as_bool()).unwrap_or(false);
            if let Some(dir) = cwd.as_deref() {
                let mut cli_args = vec![
                    "hook".to_string(),
                    "check".to_string(),
                    "--json".to_string(),
                ];
                if deep {
                    cli_args.push("--deep".to_string());
                }
                if fix {
                    cli_args.push("--fix".to_string());
                }
                return spawn_self_json(&cli_args, Some(dir), cache);
            }
            let (violations, fixed_files) = scan_hook_violations(deep, fix);
            let clean = violations.is_empty();
            (
                serde_json::json!({
                    "status": if clean { "clean" } else { "violations_found" },
                    "violations_count": violations.len(),
                    "violations": violations,
                    "fixed_files": fixed_files,
                    "deep_scan": deep,
                }),
                !clean,
            )
        }
        "ciphervault_redact" => {
            let Some(text) = args.get("text").and_then(|v| v.as_str()) else {
                return (
                    serde_json::json!({ "ok": false, "error": "missing required `text` string" }),
                    true,
                );
            };
            match scrub_fail_closed(text, cwd.as_deref(), cache) {
                Ok((scrubbed, redactions, loaded, vault)) => (
                    serde_json::json!({
                        "text": scrubbed,
                        "redactions": redactions,
                        "exact_values_loaded": loaded,
                        "exact_values_complete": true,
                        "vault": vault,
                    }),
                    false,
                ),
                Err(err) => (
                    serde_json::json!({
                        "ok": false,
                        "exact_values_complete": false,
                        "error": err,
                    }),
                    true,
                ),
            }
        }
        "ciphervault_run" => {
            let cli_args = match build_run_cli_args_for_cwd(args, cwd.as_deref()) {
                Ok(a) => a,
                Err(msg) => {
                    return (serde_json::json!({ "ok": false, "error": msg }), true);
                }
            };
            let (payload, is_err) = spawn_self_json(&cli_args, cwd.as_deref(), cache);
            let vault_lookup = lookup_vault_db_for_cwd(cwd.as_deref());
            finalize_run_with_audit_receipt(payload, is_err, args, vault_lookup)
        }
        "ciphervault_push" => {
            let mut cli_args = vec!["push".to_string()];
            if let Some(msg) = args.get("message").and_then(|v| v.as_str()) {
                cli_args.push("--message".to_string());
                cli_args.push(msg.to_string());
            }
            if args
                .get("local_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                cli_args.push("--local".to_string());
            }
            if args
                .get("shred_working_copy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                cli_args.push("--shred".to_string());
            }
            let effective_cwd = vault_cwd_for(cwd.as_deref());
            spawn_self_json(&cli_args, effective_cwd.as_deref(), cache)
        }
        "ciphervault_diff" => {
            let cli_args = match build_diff_cli_args(args) {
                Ok(a) => a,
                Err(msg) => {
                    return (serde_json::json!({ "ok": false, "error": msg }), true);
                }
            };
            let effective_cwd = vault_cwd_for(cwd.as_deref());
            spawn_self_json(&cli_args, effective_cwd.as_deref(), cache)
        }
        "ciphervault_audit" => {
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(20)
                .clamp(1, 200) as usize;
            let res = with_vault_scope_for_cwd(cwd.as_deref(), || {
                let Ok(store) = get_vault_store() else {
                    return (
                        serde_json::json!({ "ok": false, "error": "no active CipherVault workspace" }),
                        true,
                    );
                };
                let report = match store.verify_agent_audit() {
                    Ok(r) => r,
                    Err(e) => {
                        return (
                            serde_json::json!({ "ok": false, "error": e.to_string() }),
                            true,
                        )
                    }
                };
                let entries = store.list_agent_audit(limit).unwrap_or_default();
                (
                    serde_json::json!({
                        "ok": report.ok,
                        "entries_total": report.entries,
                        "head_hash": report.head_hash,
                        "entries": entries,
                    }),
                    !report.ok,
                )
            });
            match res {
                Ok(pair) => pair,
                Err(msg) => (serde_json::json!({ "ok": false, "error": msg }), true),
            }
        }
        "ciphervault_env_doctor" => {
            let cli_args = match build_env_doctor_cli_args(args) {
                Ok(a) => a,
                Err(msg) => {
                    return (serde_json::json!({ "ok": false, "error": msg }), true);
                }
            };
            let effective_cwd = vault_cwd_for(cwd.as_deref());
            spawn_self_json(&cli_args, effective_cwd.as_deref(), cache)
        }
        "ciphervault_proxy_doctor" => {
            let mut dry_args = vec!["run".to_string(), "--dry-run".to_string(), "--json".to_string()];
            if let Some(ef) = optional_trimmed_str(args, "env_file") {
                let clean = match validate_relative_env_file(&ef) {
                    Ok(c) => c,
                    Err(msg) => return (serde_json::json!({ "ok": false, "error": msg }), true),
                };
                dry_args.push("--env-file".to_string());
                dry_args.push(clean);
            }
            let profile = optional_trimmed_str(args, "profile");
            if let Some(ref p) = profile {
                if p.starts_with('-') {
                    return (
                        serde_json::json!({ "ok": false, "error": "`profile` cannot start with '-'" }),
                        true,
                    );
                }
            }
            dry_args.extend(["--".to_string(), "echo".to_string(), "ok".to_string()]);

            let effective_cwd = vault_cwd_for(cwd.as_deref());
            let (dry_payload, is_err) =
                spawn_self_json(&dry_args, effective_cwd.as_deref(), cache);
            if is_err {
                return (dry_payload, true);
            }
            let secret_names: Vec<String> = dry_payload
                .get("secrets")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.get("name").and_then(|n| n.as_str()))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();

            let policy_upstreams = match lookup_vault_db_for_cwd(cwd.as_deref()) {
                VaultLookup::Found(db_path) => {
                    let vault_dir = db_path
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| PathBuf::from(VAULT_DIR));
                    match collect_policy_upstreams(&vault_dir, profile.as_deref()) {
                        Ok(u) => u,
                        Err(msg) => {
                            return (serde_json::json!({ "ok": false, "error": msg }), true);
                        }
                    }
                }
                VaultLookup::None => BTreeMap::new(),
                VaultLookup::Uninspectable(msg) => {
                    return (serde_json::json!({ "ok": false, "error": msg }), true);
                }
            };

            (classify_proxy_keys(&secret_names, &policy_upstreams), false)
        }
        "ciphervault_recovery_drill" => {
            let kit = match optional_trimmed_str(args, "kit") {
                Some(raw) => match validate_drill_file_path(&raw, "kit") {
                    Ok(p) => Some(p),
                    Err(msg) => return (serde_json::json!({ "ok": false, "error": msg }), true),
                },
                None => None,
            };
            let shares: Vec<String> = match args.get("shares") {
                None | Some(serde_json::Value::Null) => Vec::new(),
                Some(serde_json::Value::Array(arr)) => {
                    let mut out = Vec::new();
                    for item in arr {
                        let Some(raw) = item.as_str() else {
                            return (
                                serde_json::json!({ "ok": false, "error": "`shares` must be an array of file paths" }),
                                true,
                            );
                        };
                        match validate_drill_file_path(raw, "shares") {
                            Ok(p) => out.push(p),
                            Err(msg) => {
                                return (serde_json::json!({ "ok": false, "error": msg }), true)
                            }
                        }
                    }
                    out
                }
                Some(_) => {
                    return (
                        serde_json::json!({ "ok": false, "error": "`shares` must be an array of file paths" }),
                        true,
                    );
                }
            };
            if kit.is_none() && shares.is_empty() {
                return (
                    serde_json::json!({
                        "ok": false,
                        "success": false,
                        "error": "provide `kit` (path to kit file) or `shares` (list of share file paths). Paths only — never paste kit contents."
                    }),
                    true,
                );
            }

            let via_raw: Vec<String> = match args.get("via") {
                None | Some(serde_json::Value::Null) => Vec::new(),
                Some(serde_json::Value::String(s)) => vec![s.clone()],
                Some(serde_json::Value::Array(arr)) => {
                    let mut out = Vec::new();
                    for item in arr {
                        let Some(s) = item.as_str() else {
                            return (
                                serde_json::json!({ "ok": false, "error": "`via` entries must be URL strings" }),
                                true,
                            );
                        };
                        out.push(s.to_string());
                    }
                    out
                }
                Some(_) => {
                    return (
                        serde_json::json!({ "ok": false, "error": "`via` must be an array of operator URL strings" }),
                        true,
                    );
                }
            };

            let via = if via_raw.is_empty() {
                Vec::new()
            } else {
                let configured = configured_operators_for_cwd(cwd.as_deref());
                match validate_via_endpoints_with_checker(
                    &via_raw,
                    &configured,
                    is_public_operator_url,
                ) {
                    Ok(v) => v,
                    Err(msg) => {
                        record_best_effort_audit(
                            cwd.as_deref(),
                            "ciphervault_recovery_drill",
                            "blocked",
                            "",
                            &serde_json::json!({ "reason": "rejected_via_endpoint" }),
                        );
                        return (
                            serde_json::json!({ "ok": false, "success": false, "error": msg }),
                            true,
                        );
                    }
                }
            };

            // The restore target is ALWAYS a fresh temp directory created and
            // deleted by this tool — never a caller-chosen path.
            let drill_dir = match TempDrillDir::create() {
                Ok(d) => d,
                Err(e) => {
                    return (
                        serde_json::json!({ "ok": false, "success": false, "error": format!("failed to create drill temp dir: {e}") }),
                        true,
                    );
                }
            };
            let drill_path = drill_dir.path().to_path_buf();

            let mut cli_args = vec![
                "recover".to_string(),
                "--to".to_string(),
                drill_path.to_string_lossy().to_string(),
            ];
            if let Some(kit_path) = kit {
                cli_args.push("--kit".to_string());
                cli_args.push(kit_path);
            }
            if !shares.is_empty() {
                cli_args.push("--shares".to_string());
                cli_args.extend(shares);
            }
            if !via.is_empty() {
                cli_args.push("--via".to_string());
                cli_args.extend(via);
            }

            let (recover_payload, is_err) = spawn_self_json(&cli_args, cwd.as_deref(), cache);
            if is_err {
                drop(drill_dir);
                return (recover_payload, true);
            }

            let manifest = match hash_drill_directory(&drill_path) {
                Ok(m) => m,
                Err(e) => {
                    drop(drill_dir);
                    return (
                        serde_json::json!({ "ok": false, "success": false, "error": format!("failed to hash restored drill files: {e}") }),
                        true,
                    );
                }
            };
            drop(drill_dir);
            let deleted = !drill_path.exists();
            (
                serde_json::json!({
                    "success": true,
                    "files_restored": manifest.len(),
                    "manifest": manifest,
                    "drill_dir_deleted": deleted,
                    "note": "Plaintext was hashed, verified into this manifest, and the temp drill dir was deleted; it never entered chat or tool output.",
                }),
                false,
            )
        }
        "ciphervault_secret_generate" => {
            let (cli_args, key_name, fmt, env_file) = match build_secret_generate_cli_args(args) {
                Ok(parts) => parts,
                Err(msg) => {
                    return (
                        serde_json::json!({ "ok": false, "success": false, "error": msg }),
                        true,
                    );
                }
            };
            let effective_cwd = vault_cwd_for(cwd.as_deref());
            let (payload, is_err) = spawn_self_json(&cli_args, effective_cwd.as_deref(), cache);
            if !is_err {
                let sealed = payload
                    .get("sealed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                record_best_effort_audit(
                    cwd.as_deref(),
                    "ciphervault_secret_generate",
                    "generated",
                    &env_file,
                    &serde_json::json!({
                        "name": key_name,
                        "format": fmt,
                        "sealed": sealed,
                    }),
                );
            }
            (payload, is_err)
        }
        other => (
            serde_json::json!({ "ok": false, "error": format!("unknown tool: {other}") }),
            true,
        ),
    }
}

pub(crate) fn handle_mcp_request(
    line: &str,
    cache: &mut BridgeSecretCache,
) -> Option<serde_json::Value> {
    let req: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(serde_json::json!({
                "jsonrpc": "2.0",
                "id": serde_json::Value::Null,
                "error": { "code": -32700, "message": format!("Parse error: {e}") }
            }))
        }
    };

    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = req
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    // Notifications (no `id` or `notifications/*`) must not produce a JSON-RPC reply.
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let id = id.unwrap();

    let resp = match method {
        "initialize" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "ciphervault",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }
        }),
        "ping" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        }),
        "tools/list" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": tool_definitions(),
        }),
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let (payload, is_error) = call_tool(name, &args, cache);
            let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text }],
                    "isError": is_error,
                }
            })
        }
        other => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {other}") }
        }),
    };
    Some(resp)
}

pub(crate) fn cmd_mcp() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let mut cache = BridgeSecretCache::new();

    for line_res in reader.lines() {
        let line = line_res.context("failed reading MCP request from stdin")?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle_mcp_request(&line, &mut cache) {
            writeln!(writer, "{}", serde_json::to_string(&resp)?)?;
            writer.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_initialize_notifications_and_tools_list() {
        let mut cache = BridgeSecretCache::new();

        let init = handle_mcp_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
            &mut cache,
        )
        .expect("initialize replies");
        assert_eq!(init["id"], 1);
        assert_eq!(init["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(init["result"]["serverInfo"]["name"], "ciphervault");

        // Notification yields None
        assert!(handle_mcp_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &mut cache,
        )
        .is_none());

        let list = handle_mcp_request(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            &mut cache,
        )
        .expect("tools/list replies");
        let tools = list["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        for expected in [
            "ciphervault_status",
            "ciphervault_scan",
            "ciphervault_redact",
            "ciphervault_run",
            "ciphervault_push",
            "ciphervault_diff",
            "ciphervault_audit",
            "ciphervault_env_doctor",
            "ciphervault_proxy_doctor",
            "ciphervault_recovery_drill",
            "ciphervault_secret_generate",
        ] {
            assert!(names.contains(&expected), "missing MCP tool {expected}");
        }

        let run_tool = tools
            .iter()
            .find(|t| t["name"] == "ciphervault_run")
            .unwrap();
        let run_props = run_tool["inputSchema"]["properties"].as_object().unwrap();
        assert!(!run_props.contains_key("proxy_upstream"));

        let diff_tool = tools
            .iter()
            .find(|t| t["name"] == "ciphervault_diff")
            .unwrap();
        let diff_props = diff_tool["inputSchema"]["properties"].as_object().unwrap();
        assert!(diff_props.contains_key("from_snapshot"));
        assert!(diff_props.contains_key("to_snapshot"));
        assert!(diff_props.contains_key("file"));
        assert!(diff_props.contains_key("cwd"));
        assert!(!diff_props.contains_key("reveal"));
    }

    #[test]
    fn mcp_minimal_env_strips_provider_keys_and_keeps_allowlist() {
        let fake_env = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("SystemRoot".to_string(), "C:\\Windows".to_string()),
            ("HOME".to_string(), "/home/dev".to_string()),
            ("TEMP".to_string(), "/tmp".to_string()),
            ("CIPHERVAULT_PROFILE".to_string(), "test".to_string()),
            (
                "OPENAI_API_KEY".to_string(),
                "sk-parent-should-not-leak".to_string(),
            ),
            (
                "ANTHROPIC_API_KEY".to_string(),
                "sk-ant-parent-should-not-leak".to_string(),
            ),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "aws-parent-should-not-leak".to_string(),
            ),
            ("NO_COLOR".to_string(), "0".to_string()),
        ];
        let env_map: BTreeMap<String, String> = build_minimal_env_from(fake_env).into_iter().collect();
        assert!(!env_map.contains_key("OPENAI_API_KEY"));
        assert!(!env_map.contains_key("ANTHROPIC_API_KEY"));
        assert!(!env_map.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(env_map.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(
            env_map.get("SystemRoot").map(String::as_str),
            Some("C:\\Windows")
        );
        assert_eq!(
            env_map.get("CIPHERVAULT_PROFILE").map(String::as_str),
            Some("test")
        );
        assert_eq!(env_map.get("NO_COLOR").map(String::as_str), Some("1"));
    }

    #[test]
    fn mcp_tools_call_redact_emits_completeness_and_fails_closed() {
        let mut cache = BridgeSecretCache::new();
        let synthetic = concat!("sk_", "live_", "99887766554433221100aabb");
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "ciphervault_redact",
                "arguments": { "text": format!("Authorization: Bearer {synthetic}") }
            }
        });
        let resp = handle_mcp_request(&req.to_string(), &mut cache).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let parsed: serde_json::Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(parsed["exact_values_complete"], true);
        let scrubbed = parsed["text"].as_str().unwrap();
        assert!(!scrubbed.contains(synthetic));
        assert!(scrubbed.contains("[REDACTED"));

        // Fail closed when cache.complete is false (e.g. corrupt vault DB in cwd).
        let corrupt_dir = std::env::temp_dir().join(format!(
            "cv-mcp-corrupt-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(corrupt_dir.join(VAULT_DIR)).unwrap();
        std::fs::write(corrupt_dir.join(VAULT_DIR).join(DB_FILE), b"not-a-sqlite-db").unwrap();

        let fail_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "ciphervault_redact",
                "arguments": {
                    "text": "secret_value_should_never_leak",
                    "cwd": corrupt_dir.to_string_lossy(),
                }
            }
        });
        let fail_resp = handle_mcp_request(&fail_req.to_string(), &mut cache).unwrap();
        assert_eq!(fail_resp["result"]["isError"], true);
        let fail_payload: serde_json::Value =
            serde_json::from_str(fail_resp["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(fail_payload["ok"], false);
        assert_eq!(fail_payload["exact_values_complete"], false);
        assert!(
            fail_payload.get("text").is_none(),
            "must not release text when exact-value loading is incomplete: {fail_payload}"
        );
        let _ = std::fs::remove_dir_all(&corrupt_dir);

        let unknown = handle_mcp_request(
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
            &mut cache,
        )
        .unwrap();
        assert_eq!(unknown["result"]["isError"], true);
    }

    #[test]
    fn mcp_run_records_audit_receipt_and_fails_closed_when_receipt_fails() {
        let base = std::env::temp_dir().join(format!(
            "cv-mcp-run-audit-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let ctx = crate::util::tests::workspace_fixture(&base, "audit", 42);
        let run_args = serde_json::json!({
            "command": ["pytest", "-q"],
            "profile": "test",
        });
        let run_output = serde_json::json!({
            "status": "success",
            "exit_code": 0,
            "stdout": "1 passed in 0.02s\n",
            "stderr": "",
            "redactions": 1,
        });

        let (returned, is_err) = finalize_run_with_audit_receipt(
            run_output.clone(),
            false,
            &run_args,
            VaultLookup::Found(ctx.db_path.clone()),
        );
        assert!(!is_err);
        assert_eq!(returned["stdout"], "1 passed in 0.02s\n");

        let rendered = serde_json::to_string_pretty(&returned).unwrap();
        let expected_output_sha = hex::encode(sha2::Sha256::digest(rendered.as_bytes()));
        let expected_content_sha =
            hex::encode(sha2::Sha256::digest("1 passed in 0.02s".as_bytes()));

        let store = LocalVaultStore::open(&ctx.db_path).unwrap();
        let verify = store.verify_agent_audit().unwrap();
        assert!(verify.ok);
        assert_eq!(verify.entries, 1);

        let by_output = store
            .find_agent_audit_by_output_hash(&expected_output_sha)
            .unwrap()
            .expect("audit receipt indexed by output_sha256");
        assert_eq!(by_output.tool, "ciphervault_run");
        assert_eq!(by_output.decision, "scrubbed_result");
        let detail: serde_json::Value = serde_json::from_str(&by_output.detail_json).unwrap();
        assert_eq!(detail["program"], "pytest");
        assert_eq!(detail["exit_code"], 0);
        assert_eq!(detail["redactions"], 1);
        assert_eq!(detail["profile"], "test");
        assert_eq!(detail["output_sha256"], expected_output_sha);
        assert_eq!(detail["content_sha256"], expected_content_sha);

        assert!(store
            .find_agent_audit_by_output_hash(&expected_content_sha)
            .unwrap()
            .is_some());
        drop(store);

        // Corrupt DB -> receipt write fails -> stdout/stderr MUST be withheld (fail closed)!
        let bad_db = base.join("corrupt.db");
        std::fs::write(&bad_db, b"corrupt-sqlite-bytes").unwrap();
        let (withheld, withheld_err) = finalize_run_with_audit_receipt(
            serde_json::json!({
                "status": "success",
                "exit_code": 0,
                "stdout": "sensitive-but-unreceipted-stdout",
                "stderr": "sensitive-stderr",
                "redactions": 0,
            }),
            false,
            &run_args,
            VaultLookup::Found(bad_db),
        );
        assert!(withheld_err);
        assert_eq!(withheld["audit_receipt"], false);
        assert_eq!(withheld["stdout"], AUDIT_RECEIPT_WITHHELD_MSG);
        assert_eq!(withheld["stderr"], "");
        assert!(!withheld.to_string().contains("sensitive-but-unreceipted"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn mcp_run_ignores_agent_supplied_proxy_upstream_and_blocks_proxy_with_no_net() {
        let args = build_run_cli_args(&serde_json::json!({
            "command": ["python", "-c", "print('ok')"],
            "proxy_upstream": ["OPENAI_API_KEY=https://attacker.example.com"],
        }))
        .unwrap();
        assert!(!args.iter().any(|a| a == "--proxy-upstream"));
        assert!(!args.iter().any(|a| a.contains("attacker.example.com")));
        assert!(!args.iter().any(|a| a == "--proxy"));
        if default_no_net() {
            assert!(args.iter().any(|a| a == "--no-net"));
        }

        let blank_args = build_run_cli_args(&serde_json::json!({
            "command": ["pytest"],
            "proxy_upstream": [""],
        }))
        .unwrap();
        assert!(!blank_args.iter().any(|a| a == "--proxy-upstream"));
        assert!(!blank_args.iter().any(|a| a == "--proxy"));
        if default_no_net() {
            assert!(blank_args.iter().any(|a| a == "--no-net"));
        }

        let proxied_args = build_run_cli_args(&serde_json::json!({
            "command": ["pytest"],
            "proxy": true,
            "proxy_upstream": ["OPENAI_API_KEY=https://attacker.example.com"],
        }))
        .unwrap();
        assert!(proxied_args.iter().any(|a| a == "--proxy"));
        assert!(!proxied_args.iter().any(|a| a == "--proxy-upstream"));
        assert!(!proxied_args.iter().any(|a| a == "--no-net"));

        // proxy=true + no_net=true must fail closed
        assert!(build_run_cli_args(&serde_json::json!({
            "command": ["pytest"],
            "proxy": true,
            "no_net": true,
        }))
        .is_err());

        // dry_run=true allows empty command
        let dry_only = build_run_cli_args(&serde_json::json!({
            "command": [],
            "dry_run": true,
        }))
        .unwrap();
        assert!(dry_only.iter().any(|a| a == "--dry-run"));
    }

    #[test]
    fn mcp_diff_cli_args_masked_and_flag_safe() {
        assert_eq!(
            build_diff_cli_args(&serde_json::json!({})).unwrap(),
            vec!["diff", "--json"]
        );

        assert_eq!(
            build_diff_cli_args(&serde_json::json!({
                "from_snapshot": "HEAD",
                "to_snapshot": "working",
                "file": ".env",
                "reveal": true,
            }))
            .unwrap(),
            vec!["diff", "--json", "--file", ".env", "--", "head", "working"]
        );

        let snap_id = "a".repeat(64);
        assert_eq!(
            build_diff_cli_args(&serde_json::json!({
                "to_snapshot": snap_id,
            }))
            .unwrap(),
            vec!["diff", "--json", "--", "head", &snap_id]
        );

        assert!(build_diff_cli_args(&serde_json::json!({ "from_snapshot": "--reveal" })).is_err());
        assert!(build_diff_cli_args(&serde_json::json!({ "to_snapshot": "-r" })).is_err());
        assert!(build_diff_cli_args(&serde_json::json!({ "file": "--reveal" })).is_err());

        let mut cache = BridgeSecretCache::new();
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "ciphervault_diff",
                "arguments": { "from_snapshot": "--reveal" }
            }
        });
        let resp = handle_mcp_request(&req.to_string(), &mut cache).unwrap();
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn mcp_run_forwards_profile_and_rejects_flag_injection() {
        let defs = tool_definitions();
        let tools = defs["tools"].as_array().unwrap();
        let run_tool = tools
            .iter()
            .find(|t| t["name"] == "ciphervault_run")
            .unwrap();
        let run_props = run_tool["inputSchema"]["properties"].as_object().unwrap();
        assert!(run_props.contains_key("profile"));

        let args = build_run_cli_args(&serde_json::json!({
            "command": ["pytest", "-q"],
            "profile": "  test-suite  ",
        }))
        .unwrap();
        assert!(args.windows(2).any(|w| w == ["--profile", "test-suite"]));

        // Blank profile is ignored
        let blank = build_run_cli_args(&serde_json::json!({
            "command": ["pytest"],
            "profile": "   ",
        }))
        .unwrap();
        assert!(!blank.iter().any(|a| a == "--profile"));

        // '-' prefixed profile is rejected to prevent flag injection
        let err = build_run_cli_args(&serde_json::json!({
            "command": ["pytest"],
            "profile": "--no-inherit",
        }))
        .unwrap_err();
        assert!(err.contains("profile"));
    }

    #[test]
    fn mcp_env_doctor_and_secret_generate_cli_args_validate_inputs() {
        assert_eq!(
            build_env_doctor_cli_args(&serde_json::json!({})).unwrap(),
            vec!["env-doctor", "--json"]
        );
        assert_eq!(
            build_env_doctor_cli_args(&serde_json::json!({
                "env_file": ".env.local",
                "sync_env_example": true,
            }))
            .unwrap(),
            vec![
                "env-doctor",
                "--json",
                "--env-file",
                ".env.local",
                "--sync-env-example"
            ]
        );
        assert!(build_env_doctor_cli_args(&serde_json::json!({
            "env_file": "../outside.env"
        }))
        .is_err());
        assert!(build_env_doctor_cli_args(&serde_json::json!({
            "env_file": ".ciphervault/policy.toml"
        }))
        .is_err());

        // secret_generate defaults: base64url, 32 bytes, .env, no --overwrite, no --seal
        let (gen_args, name, fmt, ef) = build_secret_generate_cli_args(&serde_json::json!({
            "name": "SESSION_SECRET",
        }))
        .unwrap();
        assert_eq!(name, "SESSION_SECRET");
        assert_eq!(fmt, "base64url");
        assert_eq!(ef, ".env");
        assert_eq!(
            gen_args,
            vec![
                "vault",
                "generate",
                "SESSION_SECRET",
                "--format",
                "base64url",
                "--bytes",
                "32",
                "--env-file",
                ".env",
                "--json",
            ]
        );
        assert!(!gen_args.iter().any(|a| a == "--overwrite"));
        assert!(!gen_args.iter().any(|a| a == "--seal"));

        // Explicit seal + overwrite + hex + 48 bytes
        let (gen_full, _, _, _) = build_secret_generate_cli_args(&serde_json::json!({
            "name": "JWT_SIGNING_KEY",
            "format": "hex",
            "bytes": 48,
            "env_file": ".env.prod",
            "seal": true,
            "overwrite": true,
        }))
        .unwrap();
        assert!(gen_full.iter().any(|a| a == "--seal"));
        assert!(gen_full.iter().any(|a| a == "--overwrite"));
        assert!(gen_full.windows(2).any(|w| w == ["--format", "hex"]));
        assert!(gen_full.windows(2).any(|w| w == ["--bytes", "48"]));
        assert!(gen_full.windows(2).any(|w| w == ["--env-file", ".env.prod"]));

        // Reject bad names, formats, byte counts, and path traversal
        assert!(build_secret_generate_cli_args(&serde_json::json!({ "name": "--bad" })).is_err());
        assert!(build_secret_generate_cli_args(&serde_json::json!({ "name": "1BAD" })).is_err());
        assert!(build_secret_generate_cli_args(&serde_json::json!({
            "name": "GOOD_KEY",
            "format": "raw"
        }))
        .is_err());
        assert!(build_secret_generate_cli_args(&serde_json::json!({
            "name": "GOOD_KEY",
            "bytes": 8
        }))
        .is_err());
        assert!(build_secret_generate_cli_args(&serde_json::json!({
            "name": "GOOD_KEY",
            "bytes": true
        }))
        .is_err());
        assert!(build_secret_generate_cli_args(&serde_json::json!({
            "name": "GOOD_KEY",
            "env_file": "../escape.env"
        }))
        .is_err());
    }

    #[test]
    fn mcp_proxy_doctor_classifies_builtin_policy_and_unmapped_keys() {
        let keys = vec![
            "OPENAI_API_KEY".to_string(),
            "RESEND_API_KEY".to_string(),
            "GROQ_API_KEY".to_string(),
            "INTERNAL_SVC_TOKEN".to_string(),
            "DATABASE_URL".to_string(),
        ];
        let mut policy_upstreams = BTreeMap::new();
        policy_upstreams.insert(
            "INTERNAL_SVC_TOKEN".to_string(),
            "https://internal.example.com".to_string(),
        );
        let report = classify_proxy_keys(&keys, &policy_upstreams);
        assert_eq!(report["success"], true);
        assert_eq!(report["proxy_ready"], true);

        let providers = report["mapped_providers"].as_array().unwrap();
        let provider_keys: Vec<&str> = providers
            .iter()
            .filter_map(|p| p["key"].as_str())
            .collect();
        assert_eq!(
            provider_keys,
            vec!["OPENAI_API_KEY", "RESEND_API_KEY", "GROQ_API_KEY"]
        );

        let policy_mapped = report["mapped_policy_upstreams"].as_array().unwrap();
        assert_eq!(policy_mapped.len(), 1);
        assert_eq!(policy_mapped[0]["key"], "INTERNAL_SVC_TOKEN");
        assert_eq!(policy_mapped[0]["upstream"], "https://internal.example.com");

        let unmapped = report["unmapped_keys"].as_array().unwrap();
        assert_eq!(unmapped, &vec![serde_json::json!("DATABASE_URL")]);
    }

    #[test]
    fn mcp_recovery_drill_blocks_ssrf_via_endpoints_and_hashes_manifest_cleanly() {
        let configured: BTreeSet<String> = [
            "https://op1.cipherv.online".to_string(),
            "http://127.0.0.1:8080".to_string(),
            "http://169.254.169.254".to_string(),
        ]
        .into_iter()
        .collect();

        // Loopback, private, link-local / cloud metadata, and internal hosts must ALWAYS be refused
        // even if somehow present in configured operators.
        for bad in [
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
            "http://169.254.169.254",
            "http://10.0.0.1:8000",
            "http://192.168.1.5",
            "http://100.64.0.1",
            "http://[::ffff:127.0.0.1]:8080",
            "http://metadata.google.internal",
            "https://op1.cipherv.online/?q=1",
            "https://user:pass@op1.cipherv.online",
        ] {
            let err = validate_via_endpoints_with_checker(
                &[bad.to_string()],
                &configured,
                is_public_operator_url,
            )
            .unwrap_err();
            assert!(!err.is_empty(), "expected rejection for {bad}");
        }

        // Unconfigured public endpoint is also refused.
        let unconfigured_err = validate_via_endpoints_with_checker(
            &["https://unconfigured.example.com".to_string()],
            &configured,
            |_| true,
        )
        .unwrap_err();
        assert!(unconfigured_err.contains("not in this vault's configured operator list"));

        // Configured public endpoint passes.
        let ok = validate_via_endpoints_with_checker(
            &["https://op1.cipherv.online/".to_string()],
            &configured,
            |_| true,
        )
        .unwrap();
        assert_eq!(ok, vec!["https://op1.cipherv.online".to_string()]);

        // Calling tool with loopback `via` fails closed via MCP JSON-RPC.
        let mut cache = BridgeSecretCache::new();
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "ciphervault_recovery_drill",
                "arguments": {
                    "kit": "recovery.kit",
                    "via": ["http://169.254.169.254"]
                }
            }
        });
        let resp = handle_mcp_request(&req.to_string(), &mut cache).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("private, loopback, link-local, or cloud-metadata"));

        // TempDrillDir hashes files, restricts Unix mode to 0700, and deletes on drop.
        let dir = TempDrillDir::create().unwrap();
        let dir_path = dir.path().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "drill temp dir must be owner-only (0700)");
        }
        std::fs::write(dir_path.join(".env"), b"KEY=val\n").unwrap();
        let manifest = hash_drill_directory(&dir_path).unwrap();
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0]["path"], ".env");
        assert_eq!(manifest[0]["size"], 8);
        assert_eq!(
            manifest[0]["sha256"],
            hex::encode(sha2::Sha256::digest(b"KEY=val\n"))
        );
        drop(dir);
        assert!(!dir_path.exists(), "TempDrillDir must delete itself on drop");
    }

    #[test]
    fn mcp_run_profile_omits_default_no_net_for_proxy_or_open_profiles() {
        let base = std::env::temp_dir().join(format!(
            "cv-mcp-profile-net-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let ctx = crate::util::tests::workspace_fixture(&base, "profnet", 77);
        let vault_dir = ctx.root_dir.join(VAULT_DIR);
        std::fs::write(
            vault_dir.join("policy.toml"),
            r#"
[vault]
sealed_mode = false
default_no_net = true

[profiles.test]
commands = ["pytest"]
allow_keys = ["DATABASE_URL"]
no_net = true

[profiles.llm_eval]
commands = ["python"]
allow_keys = ["OPENAI_API_KEY"]
proxy = true

[profiles.custom_gw]
commands = ["python"]
allow_keys = ["CUSTOM_TOKEN"]
[profiles.custom_gw.upstreams]
CUSTOM_TOKEN = "https://gw.example.com"

[profiles.open_net]
commands = ["curl"]
no_net = false
"#,
        )
        .unwrap();
        let cwd_str = ctx.root_dir.to_string_lossy().to_string();

        // proxy = true profile omits default --no-net so `run --profile llm_eval` doesn't crash
        let llm_args = build_run_cli_args_for_cwd(
            &serde_json::json!({
                "command": ["python", "eval.py"],
                "profile": "llm_eval",
            }),
            Some(&cwd_str),
        )
        .unwrap();
        assert!(llm_args.windows(2).any(|w| w == ["--profile", "llm_eval"]));
        assert!(
            !llm_args.iter().any(|a| a == "--no-net"),
            "proxy=true profile must omit default --no-net: {llm_args:?}"
        );

        // non-empty upstreams profile also omits default --no-net
        let gw_args = build_run_cli_args_for_cwd(
            &serde_json::json!({
                "command": ["python", "gw.py"],
                "profile": "custom_gw",
            }),
            Some(&cwd_str),
        )
        .unwrap();
        assert!(
            !gw_args.iter().any(|a| a == "--no-net"),
            "upstreams profile must omit default --no-net: {gw_args:?}"
        );

        // no_net = false profile omits default --no-net
        let open_args = build_run_cli_args_for_cwd(
            &serde_json::json!({
                "command": ["curl", "https://example.com"],
                "profile": "open_net",
            }),
            Some(&cwd_str),
        )
        .unwrap();
        assert!(
            !open_args.iter().any(|a| a == "--no-net"),
            "no_net=false profile must omit default --no-net: {open_args:?}"
        );

        // no_net = true profile and unknown profiles keep fail-closed default --no-net
        for prof in ["test", "unknown_profile"] {
            let args = build_run_cli_args_for_cwd(
                &serde_json::json!({
                    "command": ["pytest"],
                    "profile": prof,
                }),
                Some(&cwd_str),
            )
            .unwrap();
            if default_no_net() {
                assert!(
                    args.iter().any(|a| a == "--no-net"),
                    "profile {prof} should keep default --no-net: {args:?}"
                );
            }
        }

        // Explicit no_net = true is still honored even on a proxy profile
        let forced = build_run_cli_args_for_cwd(
            &serde_json::json!({
                "command": ["python", "eval.py"],
                "profile": "llm_eval",
                "no_net": true,
            }),
            Some(&cwd_str),
        )
        .unwrap();
        assert!(forced.iter().any(|a| a == "--no-net"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn mcp_rejects_unc_cwd_paths() {
        assert!(validate_optional_cwd(&serde_json::json!({
            "cwd": "\\\\attacker.example\\share"
        }))
        .is_err());
        assert!(validate_optional_cwd(&serde_json::json!({
            "cwd": "//attacker.example/share"
        }))
        .is_err());
    }
}
