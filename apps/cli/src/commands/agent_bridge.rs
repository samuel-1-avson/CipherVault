//! Agent-bridge commands for machine consumers (Hermes plugins, secret
//! sources, CI filters). These are NOT human UI:
//!
//! * `ciphervault redact` reads stdin and writes the same text with
//!   secret material removed — vault values by exact match (plus their
//!   percent-encoded / base64 forms) and credential shapes by pattern.
//!   It never prints a secret value. With no vault present it still
//!   applies shape redaction and exits 0.
//! * `ciphervault export-env --json` prints decrypted `{"VAR": "value"}`
//!   for secret-manager integrations (e.g. a Hermes secret source). It
//!   DOES print secret values by design, so it refuses to write to a
//!   terminal unless `--force-tty` is given. Never call it from an LLM
//!   tool or a human-facing script.

use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Read};
use zeroize::Zeroizing;

use crate::util::{get_vault_store, get_workspace_root};

/// Extract (name, value) pairs from secret-file bytes: dotenv
/// assignments, JSON string leaves, and PEM private-key blocks.
pub(crate) fn parse_secret_values(
    bytes: &[u8],
    path_hint: &str,
) -> Vec<(String, Zeroizing<String>)> {
    let mut out: Vec<(String, Zeroizing<String>)> = Vec::new();
    let text = String::from_utf8_lossy(bytes);
    if path_hint.ends_with(".json") {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            collect_json_leaves(&value, path_hint, &mut out);
        }
    }
    if let Ok(pairs) = crate::dotenv::parse_dotenv_bytes(bytes) {
        for (k, v) in pairs {
            out.push((k, Zeroizing::new(v)));
        }
    }
    if let Some(start) = text.find("-----BEGIN") {
        if text[start..].contains("PRIVATE KEY-----") {
            let block = text[start..].trim().to_string();
            out.push(("PRIVATE_KEY".to_string(), Zeroizing::new(block)));
        }
    }
    out
}

fn collect_json_leaves(
    value: &serde_json::Value,
    prefix: &str,
    out: &mut Vec<(String, Zeroizing<String>)>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                collect_json_leaves(v, &format!("{prefix}.{k}"), out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                collect_json_leaves(v, &format!("{prefix}[{i}]"), out);
            }
        }
        serde_json::Value::String(s) if s.chars().count() >= 6 => {
            out.push((prefix.to_string(), Zeroizing::new(s.clone())));
        }
        _ => {}
    }
}

/// Values from the working copies of tracked files (best effort: a
/// missing vault or unreadable file yields fewer values, never an
/// error — redaction must stay usable outside a vault).
fn working_copy_values() -> Vec<(String, Zeroizing<String>)> {
    let mut out = Vec::new();
    let Ok(store) = get_vault_store() else {
        return out;
    };
    let Ok(tracked) = store.list_tracked_files() else {
        return out;
    };
    let Ok(root) = get_workspace_root() else {
        return out;
    };
    for (rel_path, _) in &tracked {
        let full = root.join(rel_path);
        if let Ok(bytes) = std::fs::read(&full) {
            out.extend(parse_secret_values(&bytes, &rel_path.to_string_lossy()));
        }
    }
    out
}

/// `ciphervault redact [--json]`: stdin -> redacted stdout.
/// JSON mode prints `{"text": ..., "redactions": N,
/// "exact_values_loaded": N, "vault": bool}`.
pub(crate) fn cmd_redact(json: bool) -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("failed to read stdin")?;
    let text = String::from_utf8_lossy(&input);
    let values = working_copy_values();
    let vault = !values.is_empty() || get_vault_store().is_ok();
    let loaded = values.len();
    let refs: Vec<(&str, &str)> = values
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let (exact, n_exact) = ciphervault_redact::scrub_exact_values(&text, &refs);
    let scrubbed = ciphervault_redact::redact_text(&exact);
    let redactions = n_exact;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "text": scrubbed,
                "redactions": redactions,
                "exact_values_loaded": loaded,
                "vault": vault,
            }))?
        );
    } else {
        print!("{scrubbed}");
    }
    Ok(())
}

/// `ciphervault export-env`: decrypted env map for secret-manager
/// integrations. Prints SECRET VALUES — machine consumers only.
pub(crate) async fn cmd_export_env(
    env_file: Option<String>,
    snapshot: Option<String>,
    allow_working_copy: bool,
    force_tty: bool,
) -> Result<()> {
    if std::io::stdout().is_terminal() && !force_tty {
        bail!(
            "export-env prints secret values and refuses to write to a terminal. \
             Pipe stdout to the consuming program, or pass --force-tty if you really mean it."
        );
    }
    let mut map = serde_json::Map::new();
    let store = get_vault_store()?;
    let use_snapshot = store.get_active_head().ok().flatten().is_some() || snapshot.is_some();
    if use_snapshot && !allow_working_copy {
        let bundle = super::run::load_snapshot_bundle(&store, snapshot.as_deref()).await?;
        for file in &bundle.files {
            let name = file.relative_path.replace('\\', "/");
            if let Some(want) = &env_file {
                if name != *want && !name.ends_with(want.as_str()) {
                    continue;
                }
            }
            for (k, v) in parse_secret_values(&file.plaintext, &name) {
                map.insert(k, serde_json::Value::String(v.as_str().to_string()));
            }
        }
    } else {
        if !allow_working_copy {
            bail!(
                "vault has no snapshots yet; pass --allow-working-copy to export from working files instead"
            );
        }
        for (k, v) in working_copy_values() {
            map.insert(k, serde_json::Value::String(v.as_str().to_string()));
        }
    }
    if let Some(want) = &env_file {
        let _ = want;
    }
    println!(
        "{}",
        serde_json::to_string(&serde_json::Value::Object(map))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dotenv_quoted_and_export_forms() {
        let vals = parse_secret_values(
            b"API_KEY=test_value_123456\nexport QUOTED=\"my secret value\"\n# comment\nEMPTY=x\n",
            ".env",
        );
        let names: Vec<&str> = vals.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"API_KEY"));
        assert!(names.contains(&"QUOTED"));
        let quoted = vals.iter().find(|(k, _)| k == "QUOTED").unwrap();
        assert_eq!(quoted.1.as_str(), "my secret value");
    }

    #[test]
    fn parses_json_leaves_and_pem_blocks() {
        let vals = parse_secret_values(
            br#"{"db": {"password": "json_secret_value"}, "n": 42}"#,
            "config.json",
        );
        assert!(vals.iter().any(|(_, v)| v.as_str() == "json_secret_value"));
        let pem = parse_secret_values(
            b"-----BEGIN PRIVATE KEY-----\nMIIBfake\n-----END PRIVATE KEY-----\n",
            "key.pem",
        );
        assert!(pem.iter().any(|(k, _)| k == "PRIVATE_KEY"));
    }
}
