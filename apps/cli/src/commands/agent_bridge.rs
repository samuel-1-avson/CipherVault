//! Agent-bridge commands for machine consumers (Hermes plugins, secret
//! sources, CI filters). These are NOT human UI:
//!
//! * `ciphervault redact` reads stdin and writes the same text with
//!   secret material removed — vault values by exact match (plus their
//!   percent-encoded / base64 forms) and credential shapes by pattern.
//!   It never prints a secret value. With no vault present it still
//!   applies shape redaction and exits 0. An expected vault that cannot
//!   be opened/listed, or any unreadable tracked file, fails without output.
//! * `ciphervault export-env --json` prints decrypted `{"VAR": "value"}`
//!   for secret-manager integrations (e.g. a Hermes secret source). It
//!   DOES print secret values by design, so it refuses to write to a
//!   terminal unless `--force-tty` is given. Never call it from an LLM
//!   tool or a human-facing script.

use anyhow::{bail, Context, Result};
use ciphervault_format::{from_canonical_cbor, SnapshotManifest};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_snapshot::decrypt_snapshot;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use zeroize::{Zeroize, Zeroizing};

use crate::util::{get_active_vault_path, get_vault_store, get_workspace_root};

/// Extract (name, value) pairs from secret-file bytes: dotenv
/// assignments, JSON string leaves, YAML/TOML/INI assignments, PEM
/// private-key blocks, and raw single-secret tracked files.
pub(crate) fn parse_secret_values(
    bytes: &[u8],
    path_hint: &str,
) -> Vec<(String, Zeroizing<String>)> {
    let mut out: Vec<(String, Zeroizing<String>)> = Vec::new();
    let text = String::from_utf8_lossy(bytes);
    let lower_hint = path_hint.to_ascii_lowercase();
    if lower_hint.ends_with(".json") {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            collect_json_leaves(&value, path_hint, &mut out);
        }
    }
    if let Ok(pairs) = crate::dotenv::parse_dotenv_bytes(bytes) {
        for (k, v) in pairs {
            out.push((k, Zeroizing::new(v)));
        }
    }
    if lower_hint.ends_with(".yaml")
        || lower_hint.ends_with(".yml")
        || lower_hint.ends_with(".toml")
        || lower_hint.ends_with(".ini")
        || lower_hint.ends_with(".conf")
        || lower_hint.ends_with(".cfg")
    {
        collect_kv_lines(&text, path_hint, &mut out);
    }
    collect_pem_private_keys(&text, &mut out);
    // Fallback for raw tracked secret files (e.g. .npmrc, .pypirc, token files)
    // where structured parsers extracted nothing.
    if out.is_empty() && bytes.len() <= 65_536 {
        let trimmed = text.trim();
        if trimmed.chars().count() >= 6 {
            out.push((path_hint.to_string(), Zeroizing::new(trimmed.to_string())));
        }
        for (idx, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if line.chars().count() >= 12 && line != trimmed {
                out.push((
                    format!("{path_hint}[line:{}]", idx + 1),
                    Zeroizing::new(line.to_string()),
                ));
            }
        }
    }
    out
}

fn collect_pem_private_keys(text: &str, out: &mut Vec<(String, Zeroizing<String>)>) {
    const BEGIN: &str = "-----BEGIN ";
    const END_MARK: &str = "-----END ";
    let mut cursor = 0usize;
    while let Some(rel_start) = text[cursor..].find(BEGIN) {
        let start = cursor + rel_start;
        let label_start = start + BEGIN.len();
        let Some(rel_header_end) = text[label_start..].find("-----") else {
            break;
        };
        let label = &text[label_start..label_start + rel_header_end];
        if label.contains('\n') || label.contains('\r') {
            cursor = label_start;
            continue;
        }
        let header_end = label_start + rel_header_end + 5;
        if !label.to_ascii_uppercase().contains("PRIVATE KEY") {
            cursor = header_end;
            continue;
        }
        let (body_end, block_end) = if let Some(rel_end) = text[header_end..].find(END_MARK) {
            let end_mark = header_end + rel_end;
            let end_label_start = end_mark + END_MARK.len();
            let block_end = text[end_label_start..]
                .find("-----")
                .map(|p| end_label_start + p + 5)
                .unwrap_or(text.len());
            (end_mark, block_end)
        } else {
            (text.len(), text.len())
        };
        let block = text[start..block_end].trim().to_string();
        out.push(("PRIVATE_KEY".to_string(), Zeroizing::new(block)));
        for raw_line in text[header_end..body_end].lines() {
            let line = raw_line.trim();
            if line.len() >= 16
                && !line.starts_with("-----")
                && line.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
                })
            {
                out.push((
                    "PRIVATE_KEY_LINE".to_string(),
                    Zeroizing::new(line.to_string()),
                ));
            }
        }
        cursor = block_end;
    }
}

fn strip_inline_hash_comment(val: &str) -> &str {
    if val.starts_with('#') {
        return "";
    }
    let bytes = val.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#' && matches!(bytes[i - 1], b' ' | b'\t') {
            return val[..i].trim();
        }
    }
    val.trim()
}

fn collect_kv_lines(text: &str, prefix: &str, out: &mut Vec<(String, Zeroizing<String>)>) {
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('[')
        {
            continue;
        }
        let line = line.strip_prefix("- ").unwrap_or(line).trim();
        let Some((key, raw_val)) = line.split_once('=').or_else(|| line.split_once(':')) else {
            continue;
        };
        let key = key.trim().trim_matches('"').trim_matches('\'');
        if key.is_empty() {
            continue;
        }
        let val = raw_val.trim();
        let parsed = if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
            || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
        {
            val[1..val.len() - 1].to_string()
        } else {
            strip_inline_hash_comment(val).to_string()
        };
        if parsed.chars().count() >= 6 {
            out.push((format!("{prefix}.{key}"), Zeroizing::new(parsed)));
        }
    }
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

/// Best-effort local-only snapshot decryption for tracked files that are not
/// currently present on disk (never touches the network so `redact` never stalls).
fn local_snapshot_values(
    store: &LocalVaultStore,
    missing_paths: &HashSet<String>,
    covered_paths: &mut HashSet<String>,
) -> Vec<(String, Zeroizing<String>)> {
    let mut out = Vec::new();
    let Ok(vault_id) = store.get_vault_id() else {
        return out;
    };
    let Ok(Some(head)) = store.get_active_head() else {
        return out;
    };
    let Ok(snapshot_id) = <[u8; 32]>::try_from(head.snapshot_id.as_slice()) else {
        return out;
    };
    let Ok((record, encrypted_manifest)) = store.get_snapshot(&snapshot_id) else {
        return out;
    };
    if crate::util::verify_local_snapshot_record(store, &record).is_err() {
        return out;
    }
    let Ok(epoch_key) = store.get_epoch_key(record.epoch) else {
        return out;
    };
    let Ok(manifest_key) = epoch_key.derive_manifest_key(record.epoch) else {
        return out;
    };
    let manifest_key = Zeroizing::new(manifest_key);
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let Ok(manifest_bytes) =
        ciphervault_crypto::decrypt_chunk(&manifest_key, &encrypted_manifest, &aad)
    else {
        return out;
    };
    let manifest_bytes = Zeroizing::new(manifest_bytes);
    let Ok(manifest) = from_canonical_cbor::<SnapshotManifest>(&manifest_bytes) else {
        return out;
    };
    let mut needed_cids = Vec::new();
    for file in &manifest.files {
        for cid_bytes in &file.chunk_cids {
            if let Ok(arr) = <[u8; 32]>::try_from(cid_bytes.as_slice()) {
                needed_cids.push(arr);
            }
        }
    }
    needed_cids.sort();
    needed_cids.dedup();
    let Ok(chunks) = store.get_chunks(&needed_cids) else {
        return out;
    };
    if chunks.len() != needed_cids.len() {
        return out;
    }
    let Ok(mut files) = decrypt_snapshot(
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    ) else {
        return out;
    };
    for file in &mut files {
        let norm = file.relative_path.replace('\\', "/");
        if missing_paths.is_empty() || missing_paths.contains(&norm) {
            covered_paths.insert(norm.clone());
            out.extend(parse_secret_values(&file.plaintext, &norm));
        }
        file.plaintext.zeroize();
    }
    out
}

struct WorkingCopyValues {
    values: Vec<(String, Zeroizing<String>)>,
    vault: bool,
}

/// Load every tracked working copy (falling back to locally cached active
/// snapshot bytes only when a tracked file is absent on disk and present in the
/// local snapshot). Only absence of `.ciphervault/vault.db` is shape-only mode;
/// any store or tracked file that cannot be read fails closed so
/// `exact_values_complete: true` is never reported on partial data.
fn working_copy_values() -> Result<WorkingCopyValues> {
    match std::fs::symlink_metadata(get_active_vault_path()) {
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(WorkingCopyValues {
                values: Vec::new(),
                vault: false,
            });
        }
        result => {
            result.context("Cannot inspect vault for complete exact-value loading")?;
        }
    }
    let store = get_vault_store().context("Cannot open vault for complete exact-value loading")?;
    let tracked = store
        .list_tracked_files()
        .context("Cannot list tracked files for complete exact-value loading")?;
    let root = get_workspace_root().context("Cannot resolve exact-value workspace")?;
    let mut out = Vec::new();
    let mut missing = HashSet::new();
    for (rel_path, _) in &tracked {
        let norm = rel_path.to_string_lossy().replace('\\', "/");
        let full = root.join(rel_path);
        match std::fs::read(&full) {
            Ok(mut bytes) => {
                out.extend(parse_secret_values(&bytes, &norm));
                bytes.zeroize();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.insert(norm);
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "Cannot read tracked file '{}' for complete exact-value loading",
                        rel_path.display()
                    )
                });
            }
        }
    }
    if !missing.is_empty() {
        let mut covered = HashSet::new();
        let snap_vals = local_snapshot_values(&store, &missing, &mut covered);
        if let Some(uncovered) = missing.difference(&covered).next() {
            bail!(
                "Cannot read tracked file '{}' from disk or local snapshot for complete exact-value loading",
                uncovered
            );
        }
        out.extend(snap_vals);
    } else if tracked.is_empty() {
        let mut ignored = HashSet::new();
        out.extend(local_snapshot_values(&store, &missing, &mut ignored));
    }
    Ok(WorkingCopyValues {
        values: out,
        vault: true,
    })
}

/// `ciphervault redact [--json] [--stdio]`: stdin -> redacted stdout.
/// JSON mode prints `{"text": ..., "redactions": N,
/// "exact_values_loaded": N, "exact_values_complete": true, "vault": bool}`.
/// Completeness attests that every tracked working copy was loaded, not
/// merely that the response is valid JSON. `--stdio` runs a persistent
/// JSON-lines bridge (`redact` / `audit` / `ping`) over stdin/stdout so agent
/// hooks avoid per-call process spawn overhead.
pub(crate) fn cmd_redact(json: bool, stdio: bool) -> Result<()> {
    if stdio {
        return run_stdio_bridge();
    }
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("failed to read stdin")?;
    let text = String::from_utf8_lossy(&input);
    let WorkingCopyValues { values, vault } = working_copy_values()?;
    let loaded = values.len();
    let refs: Vec<(&str, &str)> = values
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let (exact, n_exact) = ciphervault_redact::scrub_exact_values(&text, &refs);
    let (scrubbed, n_shape) = ciphervault_redact::redact_text_counted(&exact);
    // Count shape-only rewrites too; receipts must not under-report.
    let redactions = n_exact + n_shape;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "text": scrubbed,
                "redactions": redactions,
                "exact_values_loaded": loaded,
                "exact_values_complete": true,
                "vault": vault,
            }))?
        );
    } else {
        print!("{scrubbed}");
    }
    Ok(())
}

type CacheFingerprint = Vec<(String, Option<std::time::SystemTime>, u64)>;

pub(crate) struct BridgeSecretCache {
    pub(crate) values: Vec<(String, Zeroizing<String>)>,
    pub(crate) vault: bool,
    pub(crate) complete: bool,
    pub(crate) last_error: Option<String>,
    fingerprint: Option<CacheFingerprint>,
}

impl BridgeSecretCache {
    pub(crate) fn new() -> Self {
        Self {
            values: Vec::new(),
            vault: false,
            complete: true,
            last_error: None,
            fingerprint: None,
        }
    }

    fn current_fingerprint() -> CacheFingerprint {
        let mut fp = Vec::new();
        let db_path = crate::util::get_active_vault_path();
        let db_meta = std::fs::metadata(&db_path).ok();
        fp.push((
            db_path.to_string_lossy().to_string(),
            db_meta.as_ref().and_then(|m| m.modified().ok()),
            db_meta.as_ref().map(|m| m.len()).unwrap_or(0),
        ));
        let wal_path = db_path.with_extension("db-wal");
        let wal_meta = std::fs::metadata(&wal_path).ok();
        fp.push((
            wal_path.to_string_lossy().to_string(),
            wal_meta.as_ref().and_then(|m| m.modified().ok()),
            wal_meta.as_ref().map(|m| m.len()).unwrap_or(0),
        ));
        if let Ok(store) = get_vault_store() {
            if let Ok(tracked) = store.list_tracked_files() {
                let root = get_workspace_root().ok();
                for (rel_path, _) in tracked {
                    let meta = root
                        .as_ref()
                        .and_then(|r| std::fs::metadata(r.join(&rel_path)).ok());
                    fp.push((
                        rel_path.to_string_lossy().to_string(),
                        meta.as_ref().and_then(|m| m.modified().ok()),
                        meta.as_ref().map(|m| m.len()).unwrap_or(0),
                    ));
                }
            }
        }
        fp
    }

    pub(crate) fn refresh_if_needed(&mut self) {
        let fp = Self::current_fingerprint();
        if self.fingerprint.as_ref() == Some(&fp) {
            return;
        }
        self.clear();
        match working_copy_values() {
            Ok(wc) => {
                self.values = wc.values;
                self.vault = wc.vault;
                self.complete = true;
                self.last_error = None;
                self.fingerprint = Some(fp);
            }
            Err(e) => {
                self.vault = true;
                self.complete = false;
                self.last_error = Some(e.to_string());
                self.fingerprint = None;
            }
        }
    }

    pub(crate) fn scrub_text(&mut self, text: &str) -> (String, usize, usize, bool) {
        self.refresh_if_needed();
        let refs: Vec<(&str, &str)> = self
            .values
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let (exact, n_exact) = ciphervault_redact::scrub_exact_values(text, &refs);
        let (scrubbed, n_shape) = ciphervault_redact::redact_text_counted(&exact);
        (scrubbed, n_exact + n_shape, self.values.len(), self.vault)
    }

    #[cfg(test)]
    pub(crate) fn seed_values(&mut self, vals: Vec<(String, Zeroizing<String>)>) {
        self.values = vals;
        self.vault = true;
        self.fingerprint = Some(Self::current_fingerprint());
    }

    fn clear(&mut self) {
        for (_, v) in &mut self.values {
            v.zeroize();
        }
        self.values.clear();
    }
}

impl Drop for BridgeSecretCache {
    fn drop(&mut self) {
        self.clear();
    }
}

fn handle_stdio_line(line: &str, cache: &mut BridgeSecretCache) -> serde_json::Value {
    let Ok(req) = serde_json::from_str::<serde_json::Value>(line) else {
        return serde_json::json!({ "ok": false, "error": "invalid JSON request" });
    };
    match req.get("op").and_then(|v| v.as_str()) {
        Some("ping") => serde_json::json!({ "ok": true }),
        Some("redact") => {
            let text = req.get("text").and_then(|v| v.as_str()).unwrap_or("");
            cache.refresh_if_needed();
            if !cache.complete {
                return serde_json::json!({
                    "ok": false,
                    "exact_values_complete": false,
                    "error": cache.last_error.as_deref().unwrap_or("exact-value loading incomplete"),
                });
            }
            let refs: Vec<(&str, &str)> = cache
                .values
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let (exact, n_exact) = ciphervault_redact::scrub_exact_values(text, &refs);
            let (scrubbed, n_shape) = ciphervault_redact::redact_text_counted(&exact);
            serde_json::json!({
                "ok": true,
                "text": scrubbed,
                "redactions": n_exact + n_shape,
                "exact_values_loaded": cache.values.len(),
                "exact_values_complete": true,
                "vault": cache.vault,
            })
        }
        Some("audit") => {
            let tool = req.get("tool").and_then(|v| v.as_str()).unwrap_or("");
            let decision = req.get("decision").and_then(|v| v.as_str()).unwrap_or("");
            let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let detail = match req.get("detail") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => "{}".to_string(),
            };
            let hmac_hex = req.get("hmac").and_then(|v| v.as_str());
            if let Err(e) = super::agent_log::verify_audit_caller_hmac(
                tool, decision, path, &detail, hmac_hex,
            ) {
                return serde_json::json!({ "ok": false, "error": e.to_string() });
            }
            match get_vault_store() {
                Ok(store) => match store.append_agent_audit(tool, decision, path, &detail) {
                    Ok(_) => serde_json::json!({ "ok": true }),
                    Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
                },
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        Some(other) => {
            serde_json::json!({ "ok": false, "error": format!("unsupported op: {other}") })
        }
        None => serde_json::json!({ "ok": false, "error": "missing op" }),
    }
}

fn run_stdio_bridge() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let mut cache = BridgeSecretCache::new();
    for line_res in reader.lines() {
        let line = line_res.context("failed reading stdio bridge request")?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = handle_stdio_line(&line, &mut cache);
        writeln!(writer, "{}", serde_json::to_string(&resp)?)?;
        writer.flush()?;
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
        for (k, v) in working_copy_values()?.values {
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
        let pem_str = format!(
            "{1} {0}-----\nZmFrZQ==\n{2} {0}-----\n",
            "PRIVATE KEY", "-----BEGIN", "-----END"
        );
        let pem = parse_secret_values(pem_str.as_bytes(), "key.pem");
        assert!(pem.iter().any(|(k, _)| k == "PRIVATE_KEY"));
    }

    #[test]
    fn parses_yaml_toml_and_raw_secret_files() {
        let yaml_bytes = format!("{}: \"{}\"\n", "db_pass", "yaml_secret_987").into_bytes();
        let yaml_vals = parse_secret_values(&yaml_bytes, "secrets.yaml");
        assert!(yaml_vals
            .iter()
            .any(|(_, v)| v.as_str() == "yaml_secret_987"));

        let toml_bytes = format!("{} = \"{}\"\n", "signing_key", "toml_secret_654").into_bytes();
        let toml_vals = parse_secret_values(&toml_bytes, "config.toml");
        assert!(toml_vals
            .iter()
            .any(|(_, v)| v.as_str() == "toml_secret_654"));

        let raw_vals = parse_secret_values(b"raw_opaque_credential_blob_321\n", ".npmrc");
        assert!(raw_vals
            .iter()
            .any(|(_, v)| v.as_str() == "raw_opaque_credential_blob_321"));
    }

    #[test]
    fn stdio_bridge_handles_ping_redact_and_errors() {
        let mut cache = BridgeSecretCache::new();
        cache.values = vec![(
            "TOKEN".to_string(),
            Zeroizing::new("stdio_canary_value_777".to_string()),
        )];
        cache.vault = true;
        cache.fingerprint = Some(BridgeSecretCache::current_fingerprint());

        let ping = handle_stdio_line(r#"{"op":"ping"}"#, &mut cache);
        assert_eq!(ping["ok"], true);

        let red = handle_stdio_line(
            r#"{"op":"redact","text":"out=stdio_canary_value_777"}"#,
            &mut cache,
        );
        assert_eq!(red["ok"], true);
        assert_eq!(red["text"], "out=[REDACTED:TOKEN]");
        assert_eq!(red["redactions"], 1);

        let bad = handle_stdio_line(r#"{"op":"unknown"}"#, &mut cache);
        assert_eq!(bad["ok"], false);
    }

    #[test]
    fn parses_multi_pem_blocks_and_body_lines() {
        let line1 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";
        let line2 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4";
        let line3 = "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1u";
        let pem_bundle = format!(
            "{begin} CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n{end} CERTIFICATE-----\n\
             {begin} RSA {pk}-----\nProc-Type: 4,ENCRYPTED\n{line1}\n{line2}\n{end} RSA {pk}-----\n\
             {begin} EC {pk}-----\n{line3}\nshortline==\n{end} EC {pk}-----\n",
            begin = "-----BEGIN",
            end = "-----END",
            pk = "PRIVATE KEY",
        );

        let vals = parse_secret_values(pem_bundle.as_bytes(), "bundle.pem");
        let blocks: Vec<&str> = vals
            .iter()
            .filter(|(k, _)| k == "PRIVATE_KEY")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(blocks.len(), 2, "expected both private PEM blocks: {blocks:?}");
        assert!(blocks[0].contains(line1));
        assert!(blocks[1].contains(line3));

        let lines: Vec<&str> = vals
            .iter()
            .filter(|(k, _)| k == "PRIVATE_KEY_LINE")
            .map(|(_, v)| v.as_str())
            .collect();
        assert!(lines.contains(&line1));
        assert!(lines.contains(&line2));
        assert!(lines.contains(&line3));
        assert!(!lines.contains(&"shortline=="));
        assert!(!lines.contains(&"Proc-Type: 4,ENCRYPTED"));

        // Partial PEM dump (body line only, no BEGIN/END headers) must scrub cleanly.
        let refs: Vec<(&str, &str)> = vals.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let (scrubbed, n) =
            ciphervault_redact::scrub_exact_values(&format!("leaked line: {line2}"), &refs);
        assert_eq!(n, 1);
        assert_eq!(scrubbed, "leaked line: [REDACTED:PRIVATE_KEY_LINE]");
    }

    #[test]
    fn parses_unquoted_kv_with_hash_without_truncation() {
        let yaml = concat!(
            "db_pass: abc#def123\n",
            "api_pass: p@ss#word12 # trailing comment\n",
            "tab_pass: t@b#secret9\t# tab comment\n",
            "only_comment: # ignore_this_comment\n",
        );
        let vals = parse_secret_values(yaml.as_bytes(), "secrets.yaml");
        let find_val = |key: &str| -> Option<String> {
            vals.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str().to_string())
        };
        assert_eq!(find_val("secrets.yaml.db_pass").as_deref(), Some("abc#def123"));
        assert_eq!(
            find_val("secrets.yaml.api_pass").as_deref(),
            Some("p@ss#word12")
        );
        assert_eq!(
            find_val("secrets.yaml.tab_pass").as_deref(),
            Some("t@b#secret9")
        );
        assert!(find_val("secrets.yaml.only_comment").is_none());
    }

    #[test]
    fn fingerprint_tracks_sqlite_wal_changes() {
        let base = std::env::temp_dir().join(format!(
            "cv-bridge-wal-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let ctx = crate::util::tests::workspace_fixture(&base, "wal", 7);
        let wal_path = ctx.db_path.with_extension("db-wal");

        crate::util::REQUEST_VAULT_CONTEXT.sync_scope(ctx.clone(), || {
            let mut cache = BridgeSecretCache::new();
            cache.refresh_if_needed();
            assert!(cache.complete);
            let fp1 = cache.fingerprint.clone().unwrap();
            assert!(
                fp1.iter().any(|(p, _, _)| p.ends_with("vault.db-wal")),
                "fingerprint must include vault.db-wal: {fp1:?}"
            );

            // Simulate a WAL write while vault.db itself is untouched.
            std::fs::write(&wal_path, b"wal-commit-frame-1").unwrap();
            let fp2 = BridgeSecretCache::current_fingerprint();
            assert_ne!(fp1, fp2, "WAL creation must invalidate fingerprint");

            // Seed a stale sentinel so we verify refresh_if_needed reloads when WAL grows.
            cache.values = vec![("STALE".to_string(), Zeroizing::new("stale_sentinel_99".to_string()))];
            cache.fingerprint = Some(fp2.clone());
            std::fs::write(&wal_path, b"wal-commit-frame-1-and-frame-2").unwrap();
            cache.refresh_if_needed();
            assert!(
                !cache.values.iter().any(|(k, _)| k == "STALE"),
                "cache must reload after WAL growth"
            );
        });

        let _ = std::fs::remove_dir_all(&base);
    }
}
