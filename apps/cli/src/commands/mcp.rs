//! Model Context Protocol (MCP) stdio JSON-RPC 2.0 server for Claude Code,
//! Codex, Cursor, and other MCP-capable coding agents.
//!
//! Exposes CipherVault's zero-knowledge tools (`ciphervault_status`,
//! `ciphervault_scan`, `ciphervault_redact`, `ciphervault_run`,
//! `ciphervault_push`, `ciphervault_diff`, `ciphervault_audit`) over newline-delimited JSON-RPC
//! without ever exposing raw secret values.

use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::process::Command;

use super::agent_bridge::BridgeSecretCache;
use super::hook::scan_hook_violations;
use crate::util::get_vault_store;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

fn default_no_net() -> bool {
    cfg!(any(target_os = "linux", target_vendor = "apple", target_os = "windows"))
}

fn tool_definitions() -> serde_json::Value {
    serde_json::json!({
        "tools": [
            {
                "name": "ciphervault_status",
                "description": "Show CipherVault vault status for the workspace: tracked file paths (never secret contents), active snapshot head, operator count, and keyring backend.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "ciphervault_scan",
                "description": "Scan workspace and staged Git diffs for confidential files, secret sprawl, and leaked credential shapes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "deep": { "type": "boolean", "default": true, "description": "Inspect staged diff lines and workspace sprawl" },
                        "fix": { "type": "boolean", "default": false, "description": "Automatically append unprotected secret files to .gitignore" }
                    }
                }
            },
            {
                "name": "ciphervault_redact",
                "description": "Scrub exact vault secret values (raw, base64, percent-encoded, hex, JSON-escaped) and credential patterns from text.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "description": "Text to scrub before passing to an LLM or external log" }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "ciphervault_run",
                "description": "Run a command with vault secrets injected into its child environment in RAM only (nothing written to disk). Output is exact-value and shape scrubbed. Supports --allow-keys scoping and --no-net network sandboxing.",
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
                        "limit": { "type": "integer", "default": 20, "minimum": 1, "maximum": 200 }
                    }
                }
            }
        ]
    })
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
    let (stdout_scrubbed, _, _, _) = cache.scrub_text(&stdout_raw);
    let (stderr_scrubbed, _, _, _) = cache.scrub_text(&stderr_raw);

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

fn optional_trimmed_str(args: &serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn build_run_cli_args(args: &serde_json::Value) -> std::result::Result<Vec<String>, String> {
    let cmd_arr = args
        .get("command")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if cmd_arr.is_empty() {
        return Err("`command` non-empty array is required".to_string());
    }
    let mut cli_args = vec!["run".to_string(), "--json".to_string()];
    if args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        cli_args.push("--dry-run".to_string());
    }
    if let Some(ef) = args.get("env_file").and_then(|v| v.as_str()) {
        cli_args.push("--env-file".to_string());
        cli_args.push(ef.to_string());
    }
    if let Some(proj) = args.get("project").and_then(|v| v.as_str()) {
        cli_args.push("--project".to_string());
        cli_args.push(proj.to_string());
    }
    if let Some(env) = args.get("env").and_then(|v| v.as_str()) {
        cli_args.push("--env".to_string());
        cli_args.push(env.to_string());
    }
    if let Some(profile) = optional_trimmed_str(args, "profile") {
        if profile.starts_with('-') {
            return Err("`profile` cannot start with '-'".to_string());
        }
        cli_args.push("--profile".to_string());
        cli_args.push(profile);
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
    if proxy_flag {
        cli_args.push("--proxy".to_string());
    }
    let no_net = args
        .get("no_net")
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| !proxy_flag && default_no_net());
    if no_net {
        cli_args.push("--no-net".to_string());
    }
    cli_args.push("--".to_string());
    cli_args.extend(cmd_arr);
    Ok(cli_args)
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

fn call_tool(
    name: &str,
    args: &serde_json::Value,
    cache: &mut BridgeSecretCache,
) -> (serde_json::Value, bool) {
    match name {
        "ciphervault_status" => {
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
            let operators = crate::util::get_configured_operators().len();
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
        }
        "ciphervault_scan" => {
            let deep = args.get("deep").and_then(|v| v.as_bool()).unwrap_or(true);
            let fix = args.get("fix").and_then(|v| v.as_bool()).unwrap_or(false);
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
            let (scrubbed, redactions, loaded, vault) = cache.scrub_text(text);
            (
                serde_json::json!({
                    "text": scrubbed,
                    "redactions": redactions,
                    "exact_values_loaded": loaded,
                    "vault": vault,
                }),
                false,
            )
        }
        "ciphervault_run" => {
            let cli_args = match build_run_cli_args(args) {
                Ok(a) => a,
                Err(msg) => {
                    return (serde_json::json!({ "ok": false, "error": msg }), true);
                }
            };
            let cwd = optional_trimmed_str(args, "cwd");
            spawn_self_json(&cli_args, cwd.as_deref(), cache)
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
            let cwd = optional_trimmed_str(args, "cwd");
            spawn_self_json(&cli_args, cwd.as_deref(), cache)
        }
        "ciphervault_diff" => {
            let cli_args = match build_diff_cli_args(args) {
                Ok(a) => a,
                Err(msg) => {
                    return (serde_json::json!({ "ok": false, "error": msg }), true);
                }
            };
            let cwd = optional_trimmed_str(args, "cwd");
            spawn_self_json(&cli_args, cwd.as_deref(), cache)
        }
        "ciphervault_audit" => {
            let Ok(store) = get_vault_store() else {
                return (
                    serde_json::json!({ "ok": false, "error": "no active CipherVault workspace" }),
                    true,
                );
            };
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(20)
                .clamp(1, 200) as usize;
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
        assert!(names.contains(&"ciphervault_status"));
        assert!(names.contains(&"ciphervault_scan"));
        assert!(names.contains(&"ciphervault_redact"));
        assert!(names.contains(&"ciphervault_run"));
        assert!(names.contains(&"ciphervault_push"));
        assert!(names.contains(&"ciphervault_diff"));
        assert!(names.contains(&"ciphervault_audit"));

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
    fn mcp_tools_call_redact_and_unknown_tool() {
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
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains(synthetic));
        assert!(text.contains("[REDACTED"));

        let unknown = handle_mcp_request(
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
            &mut cache,
        )
        .unwrap();
        assert_eq!(unknown["result"]["isError"], true);
    }

    #[test]
    fn mcp_run_ignores_agent_supplied_proxy_upstream() {
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
}
