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
        "write" | "edit" | "multiedit" | "write_file" | "patch" | "replace_file_content"
    )
}

fn is_secret_filename(path_str: &str) -> bool {
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
        "ciphervault" | "cv" => matches!(
            tokens[1],
            "status"
                | "track"
                | "untrack"
                | "push"
                | "hook"
                | "init"
                | "audit"
                | "agent-log"
                | "diff"
                | "rekey"
                | "prune"
                | "doctor"
        ),
        "git" => {
            matches!(tokens[1], "status" | "check-ignore" | "ls-files")
                || (tokens[1] == "rm" && tokens.contains(&"--cached"))
        }
        _ => false,
    }
}

fn command_mentions_secret_file(cmd: &str, tracked_paths: &[String]) -> Option<String> {
    let lower = cmd.to_ascii_lowercase();
    if (lower.contains("ciphervault") || lower.split_whitespace().any(|t| t == "cv"))
        && lower.contains("export-env")
    {
        return Some(
            "Blocked `export-env`: agent tools must never dump raw vault secret maps.".to_string(),
        );
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

fn is_git_commit_or_push(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    lower.contains("git add") || lower.contains("git commit") || lower.contains("git push")
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
}
