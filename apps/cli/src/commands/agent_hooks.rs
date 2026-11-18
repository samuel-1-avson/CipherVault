//! Cross-agent PreToolUse / PostToolUse hooks for Claude Code, Codex, and Cursor.
//!
//! `ciphervault hook agent-pre` reads tool-call JSON from stdin and exits 2
//! (or prints JSON decision with `--json-decision`) when the call would read a
//! vault-tracked / credential file, export secrets, commit secret sprawl, or
//! pass secret values in tool arguments.
//!
//! `ciphervault hook agent-post` reads tool-result JSON from stdin, scrubs both
//! exact vault values and credential shapes, records a tamper-evident audit log
//! entry, and prints the scrubbed response JSON.

use anyhow::{Context, Result};
use sha2::Digest;
use std::io::Read;
use std::path::Path;

use super::agent_bridge::BridgeSecretCache;
use super::hook::scan_hook_violations;
use crate::util::get_vault_store;

fn is_shell_tool(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "bash" | "sh" | "terminal" | "shell" | "execute_command" | "run_command" | "command"
    )
}

fn is_file_read_tool(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "read" | "view" | "read_file" | "view_file" | "get_file" | "open_file"
    )
}

fn is_file_write_tool(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "write"
            | "edit"
            | "multiedit"
            | "write_file"
            | "edit_file"
            | "create_file"
            | "append_file"
            | "patch"
            | "replace_file_content"
            | "multi_replace_file_content"
            | "notebookedit"
    )
}

pub(crate) fn is_protected_vault_config_path(path_str: &str) -> bool {
    let norm = path_str.replace('\\', "/").to_ascii_lowercase();
    if norm
        .split('/')
        .any(|seg| seg == ".ciphervault")
    {
        return true;
    }
    let name = Path::new(&norm)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if name.is_empty() {
        return false;
    }
    matches!(
        name,
        "policy.toml"
            | "operators.json"
            | "operator_pins.json"
            | "vault.db"
            | "vault.db-wal"
            | "vault.db-shm"
            | "audit_hmac.key"
            | "keystore"
    ) || name.starts_with("keystore.")
}

pub(crate) fn is_secret_filename(path_str: &str) -> bool {
    let norm = path_str.replace('\\', "/").to_ascii_lowercase();
    let name = Path::new(&norm)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if name.is_empty() {
        return false;
    }
    if name.ends_with(".example") || name.ends_with(".sample") || name.ends_with(".template") {
        return false;
    }
    if name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".env")
        || name == ".envrc"
        || name == ".npmrc"
        || name == ".pypirc"
        || name == "id_rsa"
        || name == "id_ed25519"
        || name == "id_ecdsa"
        || name == "credentials.json"
        || name == "secrets.json"
        || name == "secrets.yaml"
        || name == "secrets.yml"
        || name == "secrets.toml"
        || name == "vault.db"
        || name == "vault.db-wal"
        || name == "vault.db-shm"
        || name == "keystore.key"
        || name == "keystore.salt"
        || name.starts_with("keystore.")
        || name == "audit_hmac.key"
        || name == "policy.toml"
        || name.starts_with("recovery_kit")
        || name.starts_with("service_account")
        || name.starts_with("service-account")
    {
        return true;
    }
    name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
        || name.ends_with(".pfx")
        || name.ends_with(".kit")
        || (name.contains("share") && name.ends_with(".txt"))
}

fn has_shell_chain(cmd: &str) -> bool {
    cmd.contains("&&")
        || cmd.contains("||")
        || cmd.contains(';')
        || cmd.contains('|')
        || cmd.contains('\n')
        || cmd.contains('\r')
        || cmd.contains("$(")
        || cmd.contains('`')
}

fn is_allowed_vault_or_git_admin_cmd(cmd: &str) -> bool {
    let trimmed = cmd.trim();
    if has_shell_chain(trimmed) {
        return false;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 2 {
        return false;
    }
    match tokens[0] {
        "ciphervault" | "cv" => {
            let rest = &tokens[1..];
            let Some(sub_idx) = rest.iter().position(|t| !t.starts_with('-')) else {
                return false;
            };
            let sub = rest[sub_idx];
            let sub_rest = &rest[sub_idx + 1..];
            if sub == "diff" {
                return !rest
                    .iter()
                    .any(|t| *t == "--reveal" || t.starts_with("--reveal=") || *t == "-r");
            }
            if sub == "agent-log" {
                let log_sub = sub_rest.iter().find(|t| !t.starts_with('-')).copied();
                return matches!(
                    log_sub,
                    Some("show" | "verify" | "check" | "verify-remote" | "export")
                );
            }
            matches!(sub, "status" | "track" | "push" | "hook" | "audit" | "doctor")
        }
        "git" => {
            matches!(tokens[1], "status" | "check-ignore" | "ls-files")
                || (tokens[1] == "rm" && tokens.contains(&"--cached"))
        }
        _ => false,
    }
}

fn contains_loopback_host(lower: &str) -> bool {
    if lower.contains("[::1]") || lower.contains("//::1") {
        return true;
    }
    for (idx, _) in lower.match_indices("localhost") {
        let before_ok = idx == 0
            || !matches!(
                lower.as_bytes()[idx - 1],
                b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'
            );
        let after_idx = idx + "localhost".len();
        let after_ok = after_idx >= lower.len()
            || !matches!(
                lower.as_bytes()[after_idx],
                b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'
            );
        if before_ok && after_ok {
            return true;
        }
    }
    for addr in ["127.0.0.1", "0.0.0.0"] {
        for (idx, _) in lower.match_indices(addr) {
            let before_ok = idx == 0
                || !(lower.as_bytes()[idx - 1].is_ascii_digit()
                    || lower.as_bytes()[idx - 1] == b'.');
            let after_idx = idx + addr.len();
            let after_ok = after_idx >= lower.len()
                || !(lower.as_bytes()[after_idx].is_ascii_digit()
                    || lower.as_bytes()[after_idx] == b'.');
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

fn contains_dashboard_secret_endpoint(lower: &str) -> bool {
    for endpoint in ["/api/diff", "/api/snapshots/restore"] {
        for (idx, _) in lower.match_indices(endpoint) {
            let after_idx = idx + endpoint.len();
            let boundary_ok = after_idx >= lower.len()
                || matches!(
                    lower.as_bytes()[after_idx],
                    b'?' | b'#' | b'/' | b'\'' | b'"' | b')' | b'&' | b';' | b',' | b'\\' | b'`'
                )
                || lower.as_bytes()[after_idx].is_ascii_whitespace();
            if boundary_ok {
                return true;
            }
        }
    }
    false
}

fn blocked_cli_secret_command(cmd: &str) -> Option<String> {
    let lower = cmd.to_ascii_lowercase();
    if contains_loopback_host(&lower) && contains_dashboard_secret_endpoint(&lower) {
        return Some(
            "Blocked loopback private dashboard secret endpoint (`/api/diff` or `/api/snapshots/restore`): agent tools must not access local dashboard secret APIs."
                .to_string(),
        );
    }

    for segment in cmd.split([';', '|', '&', '\n', '\r']) {
        let tokens: Vec<String> = segment
            .split_whitespace()
            .map(|t| {
                t.trim_matches(|c: char| matches!(c, '\'' | '"'))
                    .to_ascii_lowercase()
            })
            .filter(|t| !t.is_empty())
            .collect();
        for (idx, tok) in tokens.iter().enumerate() {
            let file_name = tok.rsplit(['/', '\\']).next().unwrap_or(tok.as_str());
            let stem = Path::new(file_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if stem != "ciphervault" && stem != "cv" {
                continue;
            }
            let rest = &tokens[idx + 1..];
            let Some(sub_pos) = rest.iter().position(|t| !t.starts_with('-')) else {
                continue;
            };
            let sub = rest[sub_pos].as_str();
            let sub_rest = &rest[sub_pos + 1..];
            if sub == "export-env" {
                return Some(
                    "Blocked `export-env`: agent tools must never dump raw vault secret maps."
                        .to_string(),
                );
            }
            if matches!(sub, "restore" | "pull" | "recover") {
                return Some(format!(
                    "Blocked `{stem} {sub}`: agent tools must not materialize plaintext secret files onto disk."
                ));
            }
            if matches!(sub, "init" | "rekey" | "prune" | "untrack") {
                return Some(format!(
                    "Blocked `{stem} {sub}`: agent tools must not initialize, rekey, prune, or untrack vaults."
                ));
            }
            if sub == "secret" {
                let secret_sub = sub_rest
                    .iter()
                    .find(|t| !t.starts_with('-'))
                    .map(String::as_str);
                if secret_sub == Some("get") {
                    return Some(format!(
                        "Blocked `{stem} secret get`: agent tools must not print secret values; use `ciphervault_run`."
                    ));
                }
            }
            if sub == "agent-log" {
                let log_sub = sub_rest
                    .iter()
                    .find(|t| !t.starts_with('-'))
                    .map(String::as_str);
                if matches!(log_sub, Some("record" | "anchor")) {
                    return Some(format!(
                        "Blocked `{stem} agent-log {}`: agent tools must not forge or anchor audit log entries.",
                        log_sub.unwrap_or_default()
                    ));
                }
            }
            if sub == "diff"
                && rest
                    .iter()
                    .any(|a| a == "--reveal" || a.starts_with("--reveal=") || a == "-r")
            {
                return Some(format!(
                    "Blocked `{stem} diff --reveal`: masked diff is allowed, plaintext reveal is blocked for agents."
                ));
            }
        }
    }
    None
}

fn command_mentions_secret_file(cmd: &str, tracked_paths: &[String]) -> Option<String> {
    if let Some(reason) = blocked_cli_secret_command(cmd) {
        return Some(reason);
    }

    if is_allowed_vault_or_git_admin_cmd(cmd) {
        return None;
    }

    for token in cmd.split(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '=' | ',')) {
        let tok = token.trim_matches(|c: char| matches!(c, ';' | ')' | '('));
        if tok.is_empty() {
            continue;
        }
        if is_secret_filename(tok) {
            return Some(format!(
                "Blocked shell access referencing confidential file '{tok}'. Use `ciphervault run` (or MCP `ciphervault_run`) so secrets stay out of stdout."
            ));
        }
        let norm = tok.replace('\\', "/");
        if tracked_paths
            .iter()
            .any(|p| norm == *p || norm.ends_with(&format!("/{p}")))
        {
            return Some(format!(
                "Blocked shell access referencing vault-tracked secret file '{tok}'."
            ));
        }
    }
    None
}

fn split_shell_segments_and_tokens(cmd: &str) -> Vec<Vec<String>> {
    let mut segments: Vec<Vec<String>> = Vec::new();
    let mut current_tokens: Vec<String> = Vec::new();
    let mut current_tok = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in cmd.chars() {
        if escaped {
            current_tok.push(ch);
            escaped = false;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current_tok.push(ch);
            }
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                other => current_tok.push(other),
            }
            continue;
        }
        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            ';' | '|' | '&' | '\n' | '\r' => {
                if !current_tok.is_empty() {
                    current_tokens.push(std::mem::take(&mut current_tok));
                }
                if !current_tokens.is_empty() {
                    segments.push(std::mem::take(&mut current_tokens));
                }
            }
            c if c.is_whitespace() => {
                if !current_tok.is_empty() {
                    current_tokens.push(std::mem::take(&mut current_tok));
                }
            }
            other => current_tok.push(other),
        }
    }
    if !current_tok.is_empty() {
        current_tokens.push(current_tok);
    }
    if !current_tokens.is_empty() {
        segments.push(current_tokens);
    }
    segments
}

fn is_git_executable(tok: &str) -> bool {
    let file_name = tok.rsplit(['/', '\\']).next().unwrap_or(tok);
    let stem = Path::new(file_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    stem.eq_ignore_ascii_case("git")
}

fn is_git_commit_or_push(cmd: &str) -> bool {
    for tokens in split_shell_segments_and_tokens(cmd) {
        for (idx, tok) in tokens.iter().enumerate() {
            if !is_git_executable(tok) {
                continue;
            }
            let mut skip_next = false;
            for arg in &tokens[idx + 1..] {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if arg == "--" {
                    break;
                }
                if arg.starts_with('-') {
                    // Global git options that take a separate value argument
                    if matches!(
                        arg.as_str(),
                        "-C" | "-c"
                            | "--git-dir"
                            | "--work-tree"
                            | "--namespace"
                            | "--super-prefix"
                            | "--config-env"
                            | "--attr-source"
                    ) {
                        skip_next = true;
                    }
                    continue;
                }
                // First non-flag token is the git subcommand.
                if arg.eq_ignore_ascii_case("add")
                    || arg.eq_ignore_ascii_case("commit")
                    || arg.eq_ignore_ascii_case("push")
                {
                    return true;
                }
                break;
            }
        }
    }
    false
}

fn extract_tool_target_paths(tool_input: &serde_json::Value) -> Vec<String> {
    let mut paths = Vec::new();
    const PATH_KEYS: &[&str] = &[
        "file_path",
        "path",
        "file",
        "target_file",
        "TargetFile",
        "notebook_path",
        "destination",
        "dest",
    ];
    for key in PATH_KEYS {
        if let Some(s) = tool_input.get(*key).and_then(|v| v.as_str()) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                paths.push(trimmed.to_string());
            }
        }
    }
    for arr_key in ["edits", "files", "patches"] {
        if let Some(arr) = tool_input.get(arr_key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        paths.push(trimmed.to_string());
                    }
                } else {
                    for key in PATH_KEYS {
                        if let Some(s) = item.get(*key).and_then(|v| v.as_str()) {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                paths.push(trimmed.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    for patch_key in ["patch", "diff", "unified_diff", "content"] {
        if let Some(text) = tool_input.get(patch_key).and_then(|v| v.as_str()) {
            if patch_key == "content"
                && !text.contains("+++ ")
                && !text.contains("*** Update File:")
                && !text.contains("*** Add File:")
                && !text.contains("*** Delete File:")
            {
                continue;
            }
            for line in text.lines() {
                let candidate = if let Some(rest) = line.strip_prefix("+++ ") {
                    Some(
                        rest.split('\t')
                            .next()
                            .unwrap_or(rest)
                            .trim()
                            .trim_start_matches("b/"),
                    )
                } else if let Some(rest) = line.strip_prefix("--- ") {
                    Some(
                        rest.split('\t')
                            .next()
                            .unwrap_or(rest)
                            .trim()
                            .trim_start_matches("a/"),
                    )
                } else if let Some(rest) = line
                    .strip_prefix("*** Update File:")
                    .or_else(|| line.strip_prefix("*** Add File:"))
                    .or_else(|| line.strip_prefix("*** Delete File:"))
                    .or_else(|| line.strip_prefix("*** Move to:"))
                {
                    Some(rest.trim())
                } else {
                    None
                };
                if let Some(p) = candidate {
                    if !p.is_empty() && p != "/dev/null" {
                        paths.push(p.to_string());
                    }
                }
            }
        }
    }
    paths
}

fn tracked_vault_paths() -> Vec<String> {
    let Ok(store) = get_vault_store() else {
        return Vec::new();
    };
    store
        .list_tracked_files()
        .unwrap_or_default()
        .into_iter()
        .map(|(p, _)| p.to_string_lossy().replace('\\', "/"))
        .collect()
}

fn target_matches_tracked(target: &str, tracked_paths: &[String]) -> bool {
    let norm = target.replace('\\', "/");
    let norm_trim = norm.trim_start_matches("./");
    tracked_paths.iter().any(|p| {
        let p_trim = p.trim_start_matches("./");
        norm_trim == p_trim || norm_trim.ends_with(&format!("/{p_trim}"))
    })
}

fn collect_string_leaves<'a>(val: &'a serde_json::Value, out: &mut Vec<&'a str>) {
    match val {
        serde_json::Value::String(s) => out.push(s.as_str()),
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_string_leaves(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_string_leaves(v, out);
            }
        }
        _ => {}
    }
}

fn best_effort_audit(
    tool: &str,
    decision: &str,
    target: Option<&str>,
    redactions: usize,
    output_sha256: Option<&str>,
    detail: Option<serde_json::Value>,
) {
    let Ok(store) = get_vault_store() else {
        return;
    };
    let mut payload = match detail {
        Some(serde_json::Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    if redactions > 0 {
        payload.insert("redactions".to_string(), serde_json::json!(redactions));
    }
    if let Some(sha) = output_sha256 {
        payload.insert("output_sha256".to_string(), serde_json::json!(sha));
    }
    let detail_json = serde_json::Value::Object(payload).to_string();
    let _ = store.append_agent_audit(tool, decision, target.unwrap_or(""), &detail_json);
}

pub(crate) fn evaluate_agent_pre(
    req: &serde_json::Value,
    cache: &mut BridgeSecretCache,
    tracked_paths: &[String],
) -> Option<(String, String)> {
    let tool_name = req
        .get("tool_name")
        .or_else(|| req.get("tool"))
        .or_else(|| req.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tool_input = req
        .get("tool_input")
        .or_else(|| req.get("arguments"))
        .or_else(|| req.get("args"))
        .or_else(|| req.get("input"))
        .unwrap_or(req);

    // Never block CipherVault's own zero-knowledge tools.
    if tool_name.starts_with("ciphervault_") || tool_name.starts_with("mcp__ciphervault__") {
        return None;
    }

    if is_shell_tool(tool_name) || tool_input.get("command").is_some() {
        if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
            if let Some(reason) = command_mentions_secret_file(cmd, tracked_paths) {
                return Some((tool_name.to_string(), reason));
            }
            if is_git_commit_or_push(cmd) {
                let (violations, _) = scan_hook_violations(true, false);
                if !violations.is_empty() {
                    let summary = violations
                        .iter()
                        .take(3)
                        .map(|v| format!("[{}] {}", v.kind, v.path))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Some((
                        tool_name.to_string(),
                        format!("CipherVault pre-commit guard blocked `{cmd}`: {summary}"),
                    ));
                }
            }
        }
    }

    if is_file_read_tool(tool_name) {
        if let Some(path) = tool_input
            .get("file_path")
            .or_else(|| tool_input.get("path"))
            .or_else(|| tool_input.get("file"))
            .or_else(|| tool_input.get("target_file"))
            .or_else(|| tool_input.get("TargetFile"))
            .and_then(|v| v.as_str())
        {
            if is_secret_filename(path) || target_matches_tracked(path, tracked_paths) {
                return Some((
                    tool_name.to_string(),
                    format!(
                        "CipherVault blocked read of confidential/tracked file '{path}'. Use `ciphervault_run` so secrets are injected in RAM only."
                    ),
                ));
            }
        }
    }

    if is_file_write_tool(tool_name) {
        for path in extract_tool_target_paths(tool_input) {
            if is_protected_vault_config_path(&path) {
                return Some((
                    tool_name.to_string(),
                    format!(
                        "CipherVault blocked write to protected vault/policy path '{path}'. Modify vault policies and operator configs manually outside agent tools."
                    ),
                ));
            }
            if is_secret_filename(&path) || target_matches_tracked(&path, tracked_paths) {
                return Some((
                    tool_name.to_string(),
                    format!(
                        "CipherVault blocked write to confidential/tracked file '{path}'. Use `ciphervault vault set|generate` so secrets stay encrypted in the vault."
                    ),
                ));
            }
        }
    }

    let mut leaves = Vec::new();
    collect_string_leaves(tool_input, &mut leaves);
    for leaf in leaves {
        let (_, redactions, _, _) = cache.scrub_text(leaf);
        if redactions > 0 {
            return Some((
                tool_name.to_string(),
                format!(
                    "CipherVault blocked tool call '{tool_name}': arguments contain {redactions} secret value/pattern match(es)."
                ),
            ));
        }
    }

    None
}

pub(crate) fn evaluate_agent_post(
    req: &serde_json::Value,
    cache: &mut BridgeSecretCache,
) -> (serde_json::Value, usize, String) {
    let tool_name = req
        .get("tool_name")
        .or_else(|| req.get("tool"))
        .or_else(|| req.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let raw_resp = req
        .get("tool_response")
        .or_else(|| req.get("response"))
        .or_else(|| req.get("result"))
        .or_else(|| req.get("output"))
        .cloned()
        .unwrap_or(serde_json::Value::String(String::new()));

    let mut total_redactions = 0usize;
    let scrubbed = scrub_json_value(raw_resp, cache, &mut total_redactions);
    let serialized = serde_json::to_string(&scrubbed).unwrap_or_default();
    let digest = hex::encode(sha2::Sha256::digest(serialized.as_bytes()));

    let decision = if total_redactions > 0 {
        Some("scrubbed_result")
    } else if is_file_write_tool(tool_name) || is_shell_tool(tool_name) {
        Some("executed")
    } else {
        None
    };

    if let Some(dec) = decision {
        best_effort_audit(tool_name, dec, None, total_redactions, Some(&digest), None);
    }

    (scrubbed, total_redactions, digest)
}

fn scrub_json_value(
    val: serde_json::Value,
    cache: &mut BridgeSecretCache,
    total_redactions: &mut usize,
) -> serde_json::Value {
    match val {
        serde_json::Value::String(s) => {
            let (clean, n, _, _) = cache.scrub_text(&s);
            *total_redactions += n;
            serde_json::Value::String(clean)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.into_iter()
                .map(|item| scrub_json_value(item, cache, total_redactions))
                .collect(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, scrub_json_value(v, cache, total_redactions)))
                .collect(),
        ),
        other => other,
    }
}

fn apply_hook_cwd(req: &serde_json::Value) {
    if let Some(cwd) = req.get("cwd").and_then(|v| v.as_str()) {
        let p = Path::new(cwd);
        if p.is_dir() {
            let _ = std::env::set_current_dir(p);
        }
    }
}

pub(crate) fn cmd_hook_agent_pre(json_decision: bool) -> Result<()> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("failed to read agent-pre hook stdin")?;

    let req: serde_json::Value = match serde_json::from_str(raw.trim()) {
        Ok(v) => v,
        Err(e) => {
            let reason = format!("CipherVault agent-pre failed to parse hook payload: {e}");
            if get_vault_store().is_ok() {
                eprintln!("{reason}");
                if json_decision {
                    println!(
                        "{}",
                        serde_json::json!({
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "deny",
                                "permissionDecisionReason": reason,
                            }
                        })
                    );
                    return Ok(());
                }
                std::process::exit(2);
            }
            return Ok(());
        }
    };

    apply_hook_cwd(&req);
    let mut cache = BridgeSecretCache::new();
    let tracked = tracked_vault_paths();
    if let Some((tool_name, reason)) = evaluate_agent_pre(&req, &mut cache, &tracked) {
        best_effort_audit(
            if tool_name.is_empty() {
                "unknown"
            } else {
                &tool_name
            },
            "blocked",
            None,
            0,
            None,
            Some(serde_json::json!({ "reason": reason })),
        );
        let payload = serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        });
        println!("{}", serde_json::to_string(&payload)?);
        if !json_decision {
            eprintln!("{reason}");
            std::process::exit(2);
        }
        return Ok(());
    }

    println!(
        "{}",
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        })
    );
    Ok(())
}

pub(crate) fn cmd_hook_agent_post() -> Result<()> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("failed to read agent-post hook stdin")?;
    if raw.trim().is_empty() {
        println!(
            "{}",
            serde_json::json!({ "redactions": 0, "scrubbed": false })
        );
        return Ok(());
    }
    let req: serde_json::Value =
        serde_json::from_str(raw.trim()).context("invalid JSON on agent-post hook stdin")?;
    apply_hook_cwd(&req);
    let mut cache = BridgeSecretCache::new();
    let (scrubbed, redactions, digest) = evaluate_agent_post(&req, &mut cache);
    let mut out = serde_json::json!({
        "redactions": redactions,
        "scrubbed": redactions > 0,
        "output_sha256": digest,
        "output": scrubbed,
    });
    if redactions > 0 {
        out["hookSpecificOutput"] = serde_json::json!({
            "hookEventName": "PostToolUse",
            "additionalContext": format!(
                "CipherVault scrubbed {redactions} secret match(es) from the tool output."
            ),
        });
    }
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_pre_blocks_secret_file_reads_and_shell_bypasses() {
        let mut cache = BridgeSecretCache::new();
        let tracked = vec!["config/prod.yaml".to_string()];

        let read_env = serde_json::json!({
            "tool_name": "Read",
            "tool_input": { "file_path": ".env.production" }
        });
        assert!(evaluate_agent_pre(&read_env, &mut cache, &tracked).is_some());

        let read_tracked = serde_json::json!({
            "tool_name": "Read",
            "tool_input": { "file_path": "./config/prod.yaml" }
        });
        assert!(evaluate_agent_pre(&read_tracked, &mut cache, &tracked).is_some());

        let bash_cat = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": "cat .env" }
        });
        assert!(evaluate_agent_pre(&bash_cat, &mut cache, &tracked).is_some());

        let bash_chain = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": "ciphervault status && cat .env" }
        });
        assert!(evaluate_agent_pre(&bash_chain, &mut cache, &tracked).is_some());

        let bash_export = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": "cv export-env" }
        });
        assert!(evaluate_agent_pre(&bash_export, &mut cache, &tracked).is_some());

        for blocked_cli in [
            "cv diff --reveal",
            "ciphervault diff -r",
            "ciphervault restore",
            "cv pull --force",
            "ciphervault recover --kit kit.txt",
            "ciphervault secret get DB_PASS",
        ] {
            let call = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": blocked_cli }
            });
            assert!(
                evaluate_agent_pre(&call, &mut cache, &tracked).is_some(),
                "expected {blocked_cli} to be blocked"
            );
        }

        let read_vault_db = serde_json::json!({
            "tool_name": "Read",
            "tool_input": { "file_path": ".ciphervault/vault.db" }
        });
        assert!(evaluate_agent_pre(&read_vault_db, &mut cache, &tracked).is_some());

        let safe_diff = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": "ciphervault diff" }
        });
        assert!(evaluate_agent_pre(&safe_diff, &mut cache, &tracked).is_none());

        let safe_status = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": "ciphervault status" }
        });
        assert!(evaluate_agent_pre(&safe_status, &mut cache, &tracked).is_none());

        let safe_example = serde_json::json!({
            "tool_name": "Read",
            "tool_input": { "file_path": ".env.example" }
        });
        assert!(evaluate_agent_pre(&safe_example, &mut cache, &tracked).is_none());
    }

    #[test]
    fn agent_pre_blocks_secret_shaped_args_and_post_scrubs_outputs() {
        let mut cache = BridgeSecretCache::new();
        let tracked = Vec::new();
        let synthetic_tok = concat!("tok_", "demo_", "1234567890abcdef");
        cache.seed_values(vec![(
            "DEMO_KEY".to_string(),
            zeroize::Zeroizing::new("exact_val_998877".to_string()),
        )]);

        let leak_arg = serde_json::json!({
            "tool_name": "Write",
            "tool_input": { "file_path": "src/a.txt", "content": format!("Authorization: Bearer {synthetic_tok}") }
        });
        assert!(evaluate_agent_pre(&leak_arg, &mut cache, &tracked).is_some());

        let exact_arg = serde_json::json!({
            "tool_name": "Write",
            "tool_input": { "file_path": "src/a.txt", "content": "x=exact_val_998877" }
        });
        assert!(evaluate_agent_pre(&exact_arg, &mut cache, &tracked).is_some());

        let post_req = serde_json::json!({
            "tool_name": "Bash",
            "tool_response": { "stdout": format!("Authorization: Bearer {synthetic_tok} exact_val_998877") }
        });
        let (scrubbed, redactions, digest) = evaluate_agent_post(&post_req, &mut cache);
        assert!(redactions >= 1);
        assert!(!digest.is_empty());
        let stdout_s = scrubbed["stdout"].as_str().unwrap();
        assert!(!stdout_s.contains(synthetic_tok));
        assert!(!stdout_s.contains("exact_val_998877"));
        assert!(stdout_s.contains("[REDACTED"));
    }

    #[test]
    fn agent_pre_blocks_flagged_admin_audit_forgery_and_loopback_dashboard_endpoints() {
        let mut cache = BridgeSecretCache::new();
        let tracked = vec![".env".to_string()];

        for blocked_cmd in [
            "ciphervault --verbose export-env",
            "cv -q restore",
            "ciphervault --quiet secret get DB_PASS",
            "ciphervault -v diff --reveal",
            "ciphervault --flag diff --reveal=true",
            "ciphervault init",
            "cv --force init",
            "ciphervault rekey",
            "cv prune",
            "ciphervault untrack .env",
            "ciphervault agent-log record --tool t --decision d",
            "cv -v agent-log --json record --tool t --decision d",
            "ciphervault agent-log anchor",
            "cv --quiet agent-log --json anchor",
            "curl \"http://127.0.0.1:8080/api/diff?reveal=true\"",
            "curl http://localhost:8080/api/diff",
            "curl -X POST http://127.0.0.1:8080/api/snapshots/restore",
            "curl -X POST http://[::1]:8080/api/snapshots/restore",
            "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:9000/api/diff')\"",
            "BASE=http://127.0.0.1:8080 && curl \"$BASE/api/snapshots/restore\"",
        ] {
            let call = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": blocked_cmd }
            });
            assert!(
                evaluate_agent_pre(&call, &mut cache, &tracked).is_some(),
                "expected `{blocked_cmd}` to be blocked"
            );
        }

        for allowed_cmd in [
            "ciphervault -v track .env",
            "ciphervault agent-log show --json",
            "ciphervault agent-log verify --json",
            "ciphervault agent-log check --output-sha256 deadbeef",
            "ciphervault agent-log verify-remote --json",
            "ciphervault push --message init",
            "curl http://localhost:3000/api/health",
            "rg -n \"/api/diff\" apps/cli/src",
        ] {
            let call = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": allowed_cmd }
            });
            assert!(
                evaluate_agent_pre(&call, &mut cache, &tracked).is_none(),
                "expected `{allowed_cmd}` to be allowed"
            );
        }
    }

    #[test]
    fn agent_pre_blocks_file_writes_to_protected_vault_policy_and_secret_paths() {
        let mut cache = BridgeSecretCache::new();
        let tracked = vec!["config/prod.yaml".to_string()];

        for (tool, target) in [
            ("Write", ".ciphervault/policy.toml"),
            ("Edit", "./.ciphervault/operators.json"),
            ("write_file", "/repo/.ciphervault/vault.db"),
            ("replace_file_content", ".ciphervault/keystore.key"),
            ("Write", "keystore.salt"),
            ("Write", "keystore.json"),
            ("Edit", ".ciphervault/audit_hmac.key"),
            ("write_file", ".env"),
            ("Edit", ".env.production"),
            ("Write", "certs/server.pem"),
            ("replace_file_content", "config/prod.yaml"),
            ("Write", r"C:\repo\.ciphervault\policy.toml"),
        ] {
            let call = serde_json::json!({
                "tool_name": tool,
                "tool_input": { "file_path": target, "content": "benign content" }
            });
            assert!(
                evaluate_agent_pre(&call, &mut cache, &tracked).is_some(),
                "expected {tool} on '{target}' to be blocked"
            );
        }

        // Unified diff / patch targeting .ciphervault/policy.toml must be blocked
        let patch_call = serde_json::json!({
            "tool_name": "patch",
            "tool_input": {
                "patch": "--- a/.ciphervault/policy.toml\n+++ b/.ciphervault/policy.toml\n@@ -1 +1 @@\n-default_no_net = true\n+default_no_net = false\n"
            }
        });
        assert!(evaluate_agent_pre(&patch_call, &mut cache, &tracked).is_some());

        // MultiEdit with nested edits targeting operators.json must be blocked
        let multiedit_call = serde_json::json!({
            "tool_name": "MultiEdit",
            "tool_input": {
                "edits": [
                    { "path": "src/lib.rs", "content": "// ok" },
                    { "path": ".ciphervault/operators.json", "content": "[\"https://evil.example\"]" }
                ]
            }
        });
        assert!(evaluate_agent_pre(&multiedit_call, &mut cache, &tracked).is_some());

        // Safe writes to normal source files and .env.example remain allowed
        for safe_path in ["src/main.rs", ".env.example", "docs/README.md"] {
            let call = serde_json::json!({
                "tool_name": "Write",
                "tool_input": { "file_path": safe_path, "content": "PORT=8080\n" }
            });
            assert!(
                evaluate_agent_pre(&call, &mut cache, &tracked).is_none(),
                "expected safe write to '{safe_path}' to be allowed"
            );
        }
    }

    #[test]
    fn git_commit_or_push_catches_flags_between_git_and_subcommand() {
        for flagged in [
            "git add .",
            "git commit -m 'msg'",
            "git push origin main",
            "git -C repo push",
            "git -C /tmp/my-repo commit -m 'hi'",
            "git -Crepo push",
            "git --no-pager commit -am 'fix'",
            "git -c user.name=bot -c user.email=bot@example.com add -A",
            "git --git-dir=.git --work-tree=. push",
            "git --git-dir .git commit",
            "/usr/bin/git -C repo push",
            "git.exe --no-pager -C \"my repo\" add .",
            "echo ok && git -C repo push",
            "env GIT_TRACE=1 git --no-pager commit",
        ] {
            assert!(
                is_git_commit_or_push(flagged),
                "expected `{flagged}` to be detected as git add/commit/push"
            );
        }

        for benign in [
            "git status",
            "git -C repo status",
            "git --no-pager log --grep=push",
            "git --no-pager diff",
            "git -C repo branch -a",
            "git check-ignore .env",
            "echo hello",
        ] {
            assert!(
                !is_git_commit_or_push(benign),
                "expected `{benign}` NOT to trigger git add/commit/push"
            );
        }
    }
}
