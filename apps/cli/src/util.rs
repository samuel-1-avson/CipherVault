//! Shared CLI leaves: vault paths, device identity, operator config, gitignore, UI helpers.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use colored::Colorize;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use ciphervault_local_store::{AccountStore, LocalVaultStore};
use ciphervault_storage::MultiOperatorPool;

pub(crate) const VAULT_DIR: &str = ".ciphervault";
pub(crate) const DB_FILE: &str = "vault.db";
pub(crate) const OPERATORS_FILE: &str = "operators.json";
pub(crate) const RECOVERY_FILE: &str = "recovery_kit_backup.txt";

static ACTIVE_VAULT_PATH: std::sync::RwLock<Option<PathBuf>> = std::sync::RwLock::new(None);

pub fn set_active_vault_path(path: Option<PathBuf>) {
    if let Ok(mut guard) = ACTIVE_VAULT_PATH.write() {
        *guard = path;
    }
}

pub fn get_active_vault_path() -> PathBuf {
    if let Ok(guard) = ACTIVE_VAULT_PATH.read() {
        if let Some(ref p) = *guard {
            return p.clone();
        }
    }
    Path::new(VAULT_DIR).join(DB_FILE)
}

pub fn get_vault_store() -> Result<LocalVaultStore> {
    let path = get_active_vault_path();
    if !path.exists() {
        bail!(
            "No CipherVault found at '{}'. Run '{}' first.",
            path.display(),
            "ciphervault init".cyan()
        );
    }
    LocalVaultStore::open(&path).context("Failed to open local vault database")
}

pub(crate) fn current_device_identity() -> Result<(String, String, String)> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (device_id, device_key, _, _) = store.get_device_state()?;
    Ok((
        hex::encode(vault_id),
        hex::encode(device_id),
        hex::encode(device_key.verifying_key().as_bytes()),
    ))
}

/// Resolves `--replicas` to the count `replicate_and_verify` must reach.
/// Absent means the documented 3-operator default; 0 is rejected (it would
/// trivially "succeed" with zero receipts). Larger-than-fleet values are
/// passed through so replication fails honestly with `QuorumDeficit`.
pub(crate) fn resolve_required_replicas(replicas: Option<usize>) -> Result<usize> {
    match replicas {
        None => Ok(ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS),
        Some(0) => bail!("--replicas must be at least 1"),
        Some(n) => Ok(n),
    }
}

/// Creates an operator pool and, when this vault is linked to the optional
/// account registry, propagates the same account/device identifiers into every
/// operator client. Accountless vaults retain the legacy protocol.
pub(crate) fn configured_operator_pool(endpoints: Vec<String>) -> MultiOperatorPool {
    let pool = MultiOperatorPool::new(endpoints);
    if let (Ok(account), Ok((vault_id, device_id, device_pk))) =
        (AccountStore::open(None), current_device_identity())
    {
        if account.is_vault_linked(&vault_id) && account.is_device_active(&device_id, &device_pk) {
            pool.set_account_identity(account.account_id(), &device_id);
        }
    }
    pool
}

pub fn resolve_hardware_token(
    reader_arg: Option<&str>,
    pin_arg: Option<&str>,
    headless: bool,
) -> Result<ciphervault_crypto::PcscHardwareToken> {
    let saved_reader = get_saved_token_reader();
    let reader_filter = reader_arg.or(saved_reader.as_deref());

    let tokens = ciphervault_crypto::probe_all()?;
    if tokens.is_empty() {
        bail!(
            "Hardware token required (--hardware-token, --touch, or hardware-bound vault), but no physical YubiKey or PIV smartcard token was detected in PC/SC readers."
        );
    }

    let selected_token = if let Some(filter) = reader_filter {
        let f_lower = filter.to_lowercase();
        tokens
            .into_iter()
            .find(|t| t.reader_name().to_lowercase().contains(&f_lower))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No attached hardware token matched reader filter '{}'",
                    filter
                )
            })?
    } else if tokens.len() == 1 {
        tokens.into_iter().next().unwrap()
    } else {
        if !headless && std::io::stdin().is_terminal() {
            println!(
                "\n{}",
                "Multiple PIV hardware security tokens detected:"
                    .bold()
                    .cyan()
            );
            for (idx, t) in tokens.iter().enumerate() {
                println!("  [{}] {}", idx + 1, t.reader_name().green().bold());
            }
            print!("Select hardware token [1-{}]: ", tokens.len());
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let choice: usize = input.trim().parse().unwrap_or(1);
            let idx = if choice >= 1 && choice <= tokens.len() {
                choice - 1
            } else {
                0
            };
            tokens[idx].clone()
        } else {
            let best = tokens
                .iter()
                .find(|t| t.reader_name().to_lowercase().contains("yubi"))
                .unwrap_or(&tokens[0])
                .clone();
            eprintln!(
                "{} Headless token resolution: auto-selected '{}'",
                "[ciphervault]".bold().cyan(),
                best.reader_name().yellow()
            );
            best
        }
    };

    let resolved_pin = if let Some(p) = pin_arg {
        Some(p.as_bytes().to_vec())
    } else if let Some(cached) = selected_token.get_pin() {
        Some(cached)
    } else if let Some(cached) = ciphervault_crypto::get_cached_pin() {
        Some(cached)
    } else if !headless && std::io::stdin().is_terminal() {
        if let Ok(prompted) =
            rpassword::prompt_password("Enter hardware token PIN (or press Enter to skip): ")
        {
            let trimmed = prompted.trim();
            if !trimmed.is_empty() {
                Some(trimmed.as_bytes().to_vec())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Some(pin) = resolved_pin {
        selected_token.set_pin(&pin);
        if let Err(e) = selected_token.verify_pin(&pin) {
            bail!("Hardware token PIN authentication failed: {}", e);
        }
    }

    Ok(selected_token)
}

pub(crate) fn ensure_gitignore() -> Result<()> {
    let gitignore_path = Path::new(".gitignore");
    let entry = "\n# CipherVault local keys, database, and cache\n.ciphervault/\n";

    if gitignore_path.exists() {
        let content = fs::read_to_string(gitignore_path)?;
        if !content.contains(".ciphervault") {
            let mut file = OpenOptions::new().append(true).open(gitignore_path)?;
            file.write_all(entry.as_bytes())?;
        }
    } else {
        fs::write(gitignore_path, entry.trim_start())?;
    }
    Ok(())
}

pub(crate) fn ensure_file_in_gitignore(rel_path: &Path) -> Result<bool> {
    let gitignore_path = Path::new(".gitignore");
    let norm = rel_path.to_string_lossy().replace('\\', "/");
    let target = norm.trim_start_matches("./");

    let existing = if gitignore_path.exists() {
        fs::read_to_string(gitignore_path)?
    } else {
        String::new()
    };

    for line in existing.lines() {
        let trimmed = line.trim().replace('\\', "/");
        if trimmed == target || trimmed == format!("/{}", target) {
            return Ok(false);
        }
        if trimmed.ends_with('*') {
            let prefix = trimmed.trim_end_matches('*');
            if target.starts_with(prefix) {
                return Ok(false);
            }
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(gitignore_path)?;

    if !existing.ends_with('\n') && !existing.is_empty() {
        file.write_all(b"\n")?;
    }
    writeln!(file, "{}", target)?;
    Ok(true)
}

pub(crate) fn is_secret_pattern(pattern: &str) -> bool {
    let lower = pattern.to_lowercase();
    let name = pattern.rsplit('/').next().unwrap_or(pattern).to_lowercase();

    if lower.contains("node_modules")
        || lower.contains("target")
        || lower.contains("dist")
        || lower.contains("build")
        || lower.contains("vendor")
        || lower.contains(".next")
        || lower.contains(".cache")
        || lower.contains(".git")
        || lower.contains(".ciphervault")
        || lower.contains("coverage")
        || lower.contains("__pycache__")
        || lower.ends_with(".log")
        || lower.ends_with(".lock")
        || lower == ".ds_store"
        || lower == "thumbs.db"
    {
        return false;
    }

    if name.ends_with(".key")
        || name.ends_with(".pem")
        || name.ends_with(".crt")
        || name.ends_with(".pfx")
        || name.ends_with(".p12")
        || name.ends_with(".asc")
    {
        return true;
    }

    if name.starts_with(".env") || name.contains(".env.") || name == ".env" {
        return true;
    }

    if name.contains("secret")
        || name.contains("credential")
        || name.contains("token")
        || name.contains("password")
        || name.contains("seed")
        || name.contains("id_rsa")
        || name.contains("id_ed25519")
        || name.contains("keystore")
    {
        return true;
    }

    false
}

pub(crate) fn scan_gitignore_for_secrets(root_dir: &Path) -> Result<Vec<PathBuf>> {
    let gitignore_path = root_dir.join(".gitignore");
    if !gitignore_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(gitignore_path)?;
    let mut candidate_patterns = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let clean = trimmed.trim_start_matches('/').trim_start_matches("./");
        if is_secret_pattern(clean) {
            candidate_patterns.push(clean.to_string());
        }
    }

    let mut discovered = std::collections::BTreeSet::new();

    for pat in &candidate_patterns {
        if !pat.contains('*') {
            let p = PathBuf::from(pat);
            let full = root_dir.join(&p);
            if full.is_file() || (!full.exists() && is_secret_pattern(pat)) {
                discovered.insert(p);
            }
        }
    }

    for entry in walkdir::WalkDir::new(root_dir)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_dir() {
            continue;
        }
        let rel = match entry.path().strip_prefix(root_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rel_norm = rel.to_string_lossy().replace('\\', "/");

        if rel_norm.starts_with(".ciphervault")
            || rel_norm.starts_with(".git")
            || rel_norm.starts_with("target")
            || rel_norm.starts_with("node_modules")
            || rel_norm.starts_with("dist")
        {
            continue;
        }

        for pat in &candidate_patterns {
            let pat_norm = pat.replace('\\', "/");
            let is_match = if pat_norm.contains('*') {
                let parts: Vec<&str> = pat_norm.split('*').collect();
                if parts.len() == 2 {
                    rel_norm.starts_with(parts[0]) && rel_norm.ends_with(parts[1])
                } else {
                    rel_norm.contains(pat_norm.trim_matches('*'))
                }
            } else {
                rel_norm == pat_norm
            };

            if is_match {
                discovered.insert(rel.to_path_buf());
            }
        }
    }

    Ok(discovered.into_iter().collect())
}

pub const DEFAULT_PRODUCTION_OPERATORS: &[&str] = &[
    "https://vault.cipherv.online/op/1",
    "https://vault.cipherv.online/op/2",
    "https://vault.cipherv.online/op/3",
];

pub fn mask_operator_endpoint(endpoint: &str) -> String {
    let ep = endpoint.trim_end_matches('/');
    if ep.ends_with("/op/1") || ep.contains("136.65.43.84") || ep.contains("10.128.0.39") {
        "https://vault.cipherv.online/op/1".to_string()
    } else if ep.ends_with("/op/2") || ep.contains("34.9.157.167") || ep.contains("10.128.0.40") {
        "https://vault.cipherv.online/op/2".to_string()
    } else if ep.ends_with("/op/3") || ep.contains("34.73.53.40") || ep.contains("10.142.0.2") {
        "https://vault.cipherv.online/op/3".to_string()
    } else if let Some(stripped) = ep
        .strip_prefix("http://")
        .or_else(|| ep.strip_prefix("https://"))
    {
        let host_port = stripped.split('/').next().unwrap_or(stripped);
        let host = host_port.split(':').next().unwrap_or(host_port);
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        {
            let port_suffix = if host_port.contains(':') {
                format!(":{}", host_port.split(':').nth(1).unwrap_or(""))
            } else {
                String::new()
            };
            format!(
                "Operator ({}.***.***.{}){}",
                parts[0], parts[3], port_suffix
            )
        } else {
            endpoint.to_string()
        }
    } else {
        endpoint.to_string()
    }
}

pub(crate) fn get_configured_operators() -> Vec<String> {
    if let Ok(env_ops) = std::env::var("CIPHERVAULT_OPERATORS") {
        let list: Vec<String> = env_ops
            .split([',', ';', ' '])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    let config_path = Path::new(VAULT_DIR).join(OPERATORS_FILE);
    if config_path.exists() {
        if let Ok(content) = fs::read_to_string(config_path) {
            if let Ok(ops) = serde_json::from_str::<Vec<String>>(&content) {
                return ops;
            }
        }
    }
    DEFAULT_PRODUCTION_OPERATORS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Returns the public collector's endpoint/region pairs. Operators can be
/// grouped with `CIPHERVAULT_OPERATOR_REGIONS` using
/// `region=url1,url2;other-region=url3`. When unset, the legacy operator list
/// remains in a single `default` region.
pub(crate) fn get_configured_operator_regions() -> Vec<(String, String)> {
    if let Ok(raw) = std::env::var("CIPHERVAULT_OPERATOR_REGIONS") {
        let mut pairs = Vec::new();
        for entry in raw.split(';') {
            let Some((region, endpoints)) = entry.split_once('=') else {
                continue;
            };
            let region = region.trim();
            if region.is_empty() {
                continue;
            }
            for endpoint in endpoints
                .split([',', ' '])
                .map(str::trim)
                .filter(|endpoint| !endpoint.is_empty())
            {
                pairs.push((endpoint.to_string(), region.to_string()));
            }
        }
        if !pairs.is_empty() {
            return pairs;
        }
    }
    get_configured_operators()
        .into_iter()
        .map(|endpoint| (endpoint, "default".to_string()))
        .collect()
}

pub(crate) fn operator_service_request(
    request: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    match std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
        Ok(token) if !token.is_empty() => request.header("X-CipherVault-Service-Token", token),
        _ => request,
    }
}

pub(crate) fn parse_ui_host(host: &str) -> Result<std::net::IpAddr> {
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    host.parse::<std::net::IpAddr>().with_context(|| {
        format!(
            "Invalid UI bind address '{}'. Use a literal IP address or localhost.",
            host
        )
    })
}

pub(crate) fn ui_browser_url(host: std::net::IpAddr, port: u16) -> String {
    let browser_host = if host.is_unspecified() {
        if host.is_ipv4() {
            "127.0.0.1".to_string()
        } else {
            "[::1]".to_string()
        }
    } else if host.is_ipv6() {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    format!("http://{}:{}", browser_host, port)
}

pub(crate) fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("powershell")
            .args(["-Command", &format!("Start-Process '{}'", url)])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

pub(crate) fn get_saved_token_reader() -> Option<String> {
    let cfg_path = Path::new(VAULT_DIR).join("token_config.json");
    if cfg_path.exists() {
        if let Ok(text) = fs::read_to_string(&cfg_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                return val
                    .get("reader")
                    .and_then(|r| r.as_str())
                    .map(|s| s.to_string());
            }
        }
    }
    None
}

pub(crate) fn save_token_reader_preference(reader: &str) -> Result<()> {
    let vault_dir = Path::new(VAULT_DIR);
    if vault_dir.exists() {
        let cfg_path = vault_dir.join("token_config.json");
        let payload = serde_json::json!({
            "reader": reader,
            "updated_at": Utc::now().to_rfc3339(),
        });
        fs::write(&cfg_path, serde_json::to_string_pretty(&payload)?)?;
    }
    Ok(())
}

pub(crate) const DEFAULT_REKEY_WARN_DAYS: u64 = 90;

/// Returns (age in days, stale) for an epoch key. Unknown-age (0) keys report
/// `(None, true)` so pre-migration keys always prompt one baseline rotation.
pub(crate) fn epoch_key_status(
    created_at_utc: u64,
    warn_days: u64,
    now_utc: u64,
) -> (Option<u64>, bool) {
    if created_at_utc == 0 {
        return (None, true);
    }
    let age_days = now_utc.saturating_sub(created_at_utc) / 86_400;
    (Some(age_days), age_days >= warn_days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replicas_flag_resolution() {
        use ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS;
        assert_eq!(
            resolve_required_replicas(None).unwrap(),
            DEFAULT_REQUIRED_REPLICAS
        );
        assert_eq!(resolve_required_replicas(Some(1)).unwrap(), 1);
        assert_eq!(resolve_required_replicas(Some(5)).unwrap(), 5);
        assert!(resolve_required_replicas(Some(0)).is_err());
    }

    #[test]
    fn epoch_key_status_flags_stale_and_unknown() {
        let now = 2_000_000_000u64;
        assert_eq!(
            epoch_key_status(now - 10 * 86_400, 90, now),
            (Some(10), false)
        );
        assert_eq!(
            epoch_key_status(now - 90 * 86_400, 90, now),
            (Some(90), true)
        );
        assert_eq!(
            epoch_key_status(now - 200 * 86_400, 90, now),
            (Some(200), true)
        );
        assert_eq!(epoch_key_status(0, 90, now), (None, true));
        // Future timestamps saturate to age 0, never stale.
        assert_eq!(epoch_key_status(now + 86_400, 90, now), (Some(0), false));
    }
}
