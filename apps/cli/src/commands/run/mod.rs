//! Run command: execute a child process with secrets injected as environment.
//!
//! Two sources (Phase 7, T-702): legacy snapshot mode decrypts `.env` files
//! from the local vault; scoped mode (`--project`/`--env` or the
//! `CIPHERVAULT_PROJECT`/`CIPHERVAULT_ENV` variables) fetches secret values
//! for one project environment from the account service. The sources are
//! mutually exclusive; scoped dry-run prints names + versions only, never
//! values (T10).

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

use ciphervault_format::{from_canonical_cbor, ChunkWireObject, SnapshotManifest};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_snapshot::{decrypt_snapshot, DecryptedFile};

use super::scope::{
    api_get, checked_json, echo_scope, http_client, resolve_endpoint, resolve_scope, resolve_token,
};
use crate::dotenv;
use crate::util::{configured_operator_pool, get_configured_operators, get_vault_store};

mod policy;
mod sandbox;
#[cfg(test)]
mod tests;

pub(crate) use policy::*;
#[cfg(not(target_os = "windows"))]
pub(crate) use sandbox::apply_no_net_sandbox;
pub(crate) use sandbox::validate_sandbox_read_path;
#[cfg(target_os = "windows")]
use sandbox::windows_no_net;

/// Page size for scoped secret fetch. The list API has no cursor, so a full
/// page means the scope *may* hold more secrets and `run` fails closed
/// rather than executing with a partial environment.
const SCOPED_RUN_PAGE_LIMIT: usize = 500;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn cmd_run(
    snapshot_hex_opt: Option<String>,
    env_file_opt: Option<String>,
    project_opt: Option<String>,
    env_opt: Option<String>,
    endpoint_opt: Option<String>,
    token_opt: Option<String>,
    legacy: bool,
    revision_opt: Option<String>,
    no_inherit: bool,
    dry_run: bool,
    quiet: bool,
    json: bool,
    set_overrides: Option<Vec<String>>,
    allow_keys: Option<Vec<String>>,
    mut no_net: bool,
    mut proxy: bool,
    mut proxy_upstream: Vec<String>,
    profile_opt: Option<String>,
    command: Vec<String>,
) -> Result<()> {
    let mut allow_filter = AllowKeysFilter::default();
    let mut sandbox_read_paths: Vec<String> = Vec::new();

    if let Some(profile_name_raw) = profile_opt {
        let profile_name = profile_name_raw.trim();
        if profile_name.is_empty() {
            bail!("--profile requires a non-empty profile name");
        }
        let vault_dir = crate::util::get_vault_directory();
        let policy = load_workspace_policy(&vault_dir)?.with_context(|| {
            format!(
                "--profile '{}' requested, but '{}' does not exist",
                profile_name,
                vault_dir.join("policy.toml").display()
            )
        })?;
        let profile = policy.profiles.get(profile_name).with_context(|| {
            format!(
                "Profile '{}' not found in '{}'",
                profile_name,
                vault_dir.join("policy.toml").display()
            )
        })?;
        enforce_profile_command_allowlist(&command, profile_name, &profile.commands)?;

        allow_filter = build_profile_allow_keys_filter(
            allow_keys,
            &profile.allow_keys,
            &profile.require_keys,
            profile_name,
        )?;

        for path in policy
            .sandbox_read_paths
            .iter()
            .chain(profile.sandbox_read_paths.iter())
        {
            if !sandbox_read_paths.contains(path) {
                sandbox_read_paths.push(path.clone());
            }
        }

        if let Some(profile_proxy) = profile.proxy {
            proxy = proxy || profile_proxy;
        }
        if !profile.upstreams.is_empty() {
            let mut merged_upstreams: Vec<String> = profile
                .upstreams
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            merged_upstreams.extend(proxy_upstream);
            proxy_upstream = merged_upstreams;
        }
        let profile_proxy_enabled = proxy || !proxy_upstream.is_empty();
        let policy_no_net = profile.no_net.unwrap_or_else(|| {
            if profile_proxy_enabled {
                false
            } else {
                policy.default_no_net.unwrap_or(false)
            }
        });
        no_net = no_net || policy_no_net;
    } else {
        if let Some(cli_keys) = allow_keys {
            let normalized = normalize_allow_keys(Some(&cli_keys))?
                .expect("normalize_allow_keys returns Some for Some input");
            allow_filter.cli_patterns = Some(normalized.into_iter().collect());
        }
        let vault_dir = crate::util::get_vault_directory();
        if let Some(policy) = load_workspace_policy(&vault_dir)? {
            for path in &policy.sandbox_read_paths {
                if !sandbox_read_paths.contains(path) {
                    sandbox_read_paths.push(path.clone());
                }
            }
            if !no_net && !proxy && proxy_upstream.is_empty() && policy.default_no_net == Some(true)
            {
                no_net = true;
            }
        }
    }

    let proxy_enabled = proxy || !proxy_upstream.is_empty();
    if proxy_enabled && no_net {
        bail!("--proxy and --no-net cannot be combined");
    }
    if command.is_empty() && !dry_run {
        bail!("No command specified to execute. Usage: ciphervault run [OPTIONS] -- <COMMAND> [ARGS]... (or pass --dry-run with no command to only list secret keys)");
    }
    let snapshot_source = snapshot_hex_opt.is_some() || env_file_opt.is_some();
    let scoped_source = has_scope_signal(project_opt.as_deref(), env_opt.as_deref());
    if revision_opt.is_some() && (!scoped_source || dry_run) {
        bail!("--revision requires scoped execution; it is checked when secret values are materialized");
    }
    if let Some(revision) = &revision_opt {
        if revision.len() != 64 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("--revision must be 64 hex characters");
        }
    }
    let revision_opt = revision_opt.map(|revision| revision.to_ascii_lowercase());
    if snapshot_source && scoped_source {
        bail!("cannot combine snapshot source (--snapshot/--env-file) with scoped source (--project/--env)");
    }
    if scoped_source {
        // U-M: a stale CIPHERVAULT_PROJECT/CIPHERVAULT_ENV export silently
        // flips run into a different mode (different secrets, network
        // calls). Say so when flags didn't ask for it.
        if project_opt.is_none() && env_opt.is_none() {
            eprintln!(
                "{}",
                "Scoped mode via $CIPHERVAULT_PROJECT/$CIPHERVAULT_ENV (not flags). Unset them or pass snapshot flags for local-snapshot mode."
                    .yellow()
            );
        }
        return cmd_run_scoped(
            project_opt.as_deref(),
            env_opt.as_deref(),
            endpoint_opt.as_deref(),
            token_opt.as_deref(),
            revision_opt.as_deref(),
            no_inherit,
            dry_run,
            quiet,
            json,
            set_overrides,
            &allow_filter,
            no_net,
            proxy_enabled,
            proxy_upstream,
            &sandbox_read_paths,
            command,
        )
        .await;
    }
    cmd_run_snapshot(
        snapshot_hex_opt,
        env_file_opt,
        legacy,
        no_inherit,
        dry_run,
        quiet,
        json,
        set_overrides,
        &allow_filter,
        no_net,
        proxy_enabled,
        proxy_upstream,
        &sandbox_read_paths,
        command,
    )
    .await
}

/// Scoped mode engages only on explicit precedence levels 1–2 (flags or
/// `CIPHERVAULT_*` variables). The context file and git auto-detection never
/// flip modes on their own, so plain `run` keeps legacy snapshot behavior;
/// once scoped, they can still fill the missing half via `resolve_scope`.
fn has_scope_signal(project_flag: Option<&str>, env_flag: Option<&str>) -> bool {
    fn present(value: Option<&str>) -> bool {
        value.is_some_and(|raw| !raw.trim().is_empty())
    }
    present(project_flag)
        || present(env_flag)
        || present(std::env::var("CIPHERVAULT_PROJECT").ok().as_deref())
        || present(std::env::var("CIPHERVAULT_ENV").ok().as_deref())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_run_scoped(
    project_flag: Option<&str>,
    env_flag: Option<&str>,
    endpoint_flag: Option<&str>,
    token_flag: Option<&str>,
    expected_revision: Option<&str>,
    no_inherit: bool,
    dry_run: bool,
    quiet: bool,
    json: bool,
    set_overrides: Option<Vec<String>>,
    allow_filter: &AllowKeysFilter,
    no_net: bool,
    proxy: bool,
    proxy_upstream: Vec<String>,
    sandbox_read_paths: &[String],
    command: Vec<String>,
) -> Result<()> {
    let endpoint = resolve_endpoint(endpoint_flag)?;
    let token = resolve_token(token_flag)?;
    let client = http_client()?;
    let scope = resolve_scope(&client, &endpoint, &token, project_flag, env_flag, true).await?;
    if !json {
        echo_scope(&scope);
    }
    let scope_label = format!(
        "{}/{}",
        scope.project_slug,
        scope.env_slug.as_deref().unwrap_or("?")
    );
    let grant_hint =
        format!("fetching secrets for {scope_label} (check the token grant for this scope)");

    let body = api_get(
        &client,
        &endpoint,
        &token,
        &format!(
            "/v1/projects/{}/secrets?environment={}&limit={SCOPED_RUN_PAGE_LIMIT}",
            scope.project_id,
            scope.env_id.as_deref().unwrap_or_default(),
        ),
        "secret list",
    )
    .await
    .with_context(|| grant_hint.clone())?;
    let entries = body["secrets"]
        .as_array()
        .context("server returned a malformed secret list")?;
    if entries.len() >= SCOPED_RUN_PAGE_LIMIT {
        bail!(
            "scope {scope_label} returned a full page of {SCOPED_RUN_PAGE_LIMIT} secrets; refusing to run with a possibly partial environment"
        );
    }

    // Dry-run uses metadata only. Execution obtains all values at one revision.
    let mut names: Vec<(String, i64, String)> = Vec::with_capacity(entries.len());
    let mut loaded_vars: Vec<(String, Zeroizing<String>)> = Vec::new();
    for entry in entries {
        let (Some(_secret_id), Some(name)) = (entry["secret_id"].as_str(), entry["name"].as_str())
        else {
            bail!("server returned a malformed secret entry");
        };
        // Client-side name check: `Command::env` panics on `=`/NUL keys, so
        // a misbehaving server must produce an error, never a panic. Names
        // are `^[A-Z][A-Z0-9_]*$` (§T-101), always valid env keys.
        ciphervault_format::scope::validate_secret_name(name)
            .map_err(|err| anyhow::anyhow!("server returned an invalid secret name: {err}"))?;
        let version = entry["current_version"].as_i64().unwrap_or(0);
        let status = entry["status"].as_str().unwrap_or("active").to_string();
        names.push((name.to_string(), version, status));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    filter_scoped_names_with_policy(&mut names, allow_filter, &scope_label)?;

    if dry_run {
        if json {
            let res = serde_json::json!({
                "status": "dry_run",
                "mode": "scoped",
                "scope": scope_label,
                "secrets_count": names.len(),
                "secrets": names.iter().map(|(n, v, s)| serde_json::json!({
                    "name": n,
                    "version": v,
                    "status": s
                })).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&res)?);
            return Ok(());
        }
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!(
            "  {}",
            "CipherVault Scoped Secret Injection (Dry Run)"
                .bold()
                .green()
        );
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!("Scope:   {}", scope_label.yellow());
        println!("Secrets: {} variable(s) ready for injection", names.len());
        println!();
        for (name, version, status) in &names {
            println!(
                "  • {} v{} [{}] = [REDACTED]",
                name.bold().white(),
                version,
                status
            );
        }
        println!();
        println!(
            "{}",
            "✓ Zero secrets written to disk. Exiting without execution.".green()
        );
        return Ok(());
    }

    {
        if names.len() > 100 {
            bail!("Scoped execution supports at most 100 secrets in one atomic materialization");
        }
        let requested: Vec<&str> = names.iter().map(|entry| entry.0.as_str()).collect();
        let expected_revision = expected_revision.or_else(|| body["revision"].as_str());
        let response = super::dpop::maybe_dpop(
            client.post(format!(
                "{endpoint}/v1/projects/{}/environments/{}/materialize",
                scope.project_id,
                scope.env_id.as_deref().unwrap_or_default()
            )),
            &token,
        )?
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "names": requested, "expected_revision": expected_revision,
        }))
        .send()
        .await
        .context("materializing scoped secrets")?;
        let mut batch = checked_json(response, "scope materialize")
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "Could not materialize revision-pinned secrets for {scope_label}: {error}"
                )
            })?;
        let revision = batch["revision"]
            .as_str()
            .context("Missing scope revision")?
            .to_string();
        if revision.len() != 64
            || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            || expected_revision.is_some_and(|expected| !revision.eq_ignore_ascii_case(expected))
        {
            bail!("Server returned an invalid or mismatched scope revision");
        }
        let mut remaining: std::collections::BTreeSet<String> =
            requested.into_iter().map(str::to_owned).collect();
        let values = batch["values"]
            .as_array_mut()
            .context("Malformed materialization values")?;
        let mut total_bytes = 0usize;
        for entry in values {
            let name = entry["name"]
                .as_str()
                .context("Malformed materialized name")?
                .to_string();
            let serde_json::Value::String(value) = entry["value"].take() else {
                bail!("Malformed materialized value");
            };
            let value = Zeroizing::new(value);
            total_bytes = total_bytes.saturating_add(value.len());
            if !remaining.remove(&name) || total_bytes > 128 * 1024 {
                bail!("Materialization returned an unexpected, duplicate, or oversized value");
            }
            loaded_vars.push((name, value));
        }
        if !remaining.is_empty() {
            bail!("Materialization returned a partial environment; command was not started");
        }
        if !quiet {
            eprintln!("Scope revision: {revision}");
        }
    }

    // `--set` wins over fetched values; BTreeMap keeps last definition.
    let deduped_vars = apply_overrides(loaded_vars, set_overrides)?;
    spawn_with_env(
        &command,
        deduped_vars,
        no_inherit,
        no_net,
        proxy,
        &proxy_upstream,
        sandbox_read_paths,
        quiet,
        json,
        &scope_label,
    )
    .await
}

/// Applies `--set KEY=VALUE` overrides over loaded vars, last wins.
fn apply_overrides(
    mut loaded_vars: Vec<(String, Zeroizing<String>)>,
    set_overrides: Option<Vec<String>>,
) -> Result<std::collections::BTreeMap<String, Zeroizing<String>>> {
    if let Some(overrides) = set_overrides {
        for item in overrides {
            if let Some((k, v)) = item.split_once('=') {
                let key = k.trim();
                // U-M: validate --set keys up front (server naming rules),
                // not after secrets were fetched/materialized.
                if let Err(error) = ciphervault_format::validate_secret_name(key) {
                    bail!("Invalid --set '{key}': {error}");
                }
                loaded_vars.push((key.to_string(), Zeroizing::new(v.to_string())));
            } else {
                bail!("Invalid --set format: expected KEY=VALUE, got '{}'", item);
            }
        }
    }
    let mut deduped_vars: std::collections::BTreeMap<String, Zeroizing<String>> =
        std::collections::BTreeMap::new();
    for (k, v) in loaded_vars {
        deduped_vars.insert(k, v);
    }
    Ok(deduped_vars)
}

/// Decrypted snapshot contents (volatile memory only).
pub(crate) struct SnapshotBundle {
    pub snapshot_id: [u8; 32],
    pub files: Vec<DecryptedFile>,
}

/// Synchronous local-only head snapshot decryption (zero network calls; Send-safe
/// for callers holding `&LocalVaultStore`).
pub(crate) fn load_local_snapshot_bundle_sync(store: &LocalVaultStore) -> Result<SnapshotBundle> {
    let vault_id = store.get_vault_id()?;
    let head = store
        .get_active_head()?
        .context("Vault has no snapshots committed yet")?;
    let snapshot_id: [u8; 32] = head
        .snapshot_id
        .as_slice()
        .try_into()
        .context("Invalid snapshot ID in active head")?;
    let (record, encrypted_manifest) = store.get_snapshot(&snapshot_id)?;
    crate::util::verify_local_snapshot_record(store, &record)?;
    let epoch_key = store.get_epoch_key(record.epoch)?;
    let manifest_key = Zeroizing::new(epoch_key.derive_manifest_key(record.epoch)?);
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes = Zeroizing::new(ciphervault_crypto::decrypt_chunk(
        &manifest_key,
        &encrypted_manifest,
        &aad,
    )?);
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;
    let mut needed_cids = Vec::new();
    for file in &manifest.files {
        for cid_bytes in &file.chunk_cids {
            let arr: [u8; 32] = cid_bytes
                .as_slice()
                .try_into()
                .context("Invalid manifest chunk CID")?;
            needed_cids.push(arr);
        }
    }
    needed_cids.sort();
    needed_cids.dedup();
    let chunks = store.get_chunks(&needed_cids)?;
    if chunks.len() != needed_cids.len() {
        bail!("Local store is missing chunks for active head snapshot");
    }
    let files = decrypt_snapshot(
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    )?;
    Ok(SnapshotBundle { snapshot_id, files })
}

/// Loads and decrypts a snapshot's files (head unless pinned). Shared by
/// `run` (snapshot mode) and `migrate` (plan/apply/verify); callers zeroize
/// `files` plaintext after use. Works on read-only stores.
pub(crate) async fn load_snapshot_bundle(
    store: &LocalVaultStore,
    snapshot_hex_opt: Option<&str>,
) -> Result<SnapshotBundle> {
    let vault_id = store.get_vault_id()?;

    let snapshot_id = match snapshot_hex_opt {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim())?;
            if bytes.len() != 32 {
                bail!("Snapshot ID must be 32 bytes hex string (64 characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            let head = store
                .get_active_head()?
                .context("Vault has no snapshots committed yet. Create a snapshot first with 'ciphervault push'")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

    let (record, encrypted_manifest) = store.get_snapshot(&snapshot_id)?;
    crate::util::verify_local_snapshot_record(store, &record)?;
    let epoch_key = store.get_epoch_key(record.epoch).with_context(|| {
        format!(
            "Epoch {} key is required to read this snapshot",
            record.epoch
        )
    })?;

    let manifest_key = Zeroizing::new(epoch_key.derive_manifest_key(record.epoch)?);
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes = Zeroizing::new(ciphervault_crypto::decrypt_chunk(
        &manifest_key,
        &encrypted_manifest,
        &aad,
    )?);
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;

    let mut needed_cids = Vec::new();
    for file in &manifest.files {
        for cid_bytes in &file.chunk_cids {
            let arr: [u8; 32] = cid_bytes
                .as_slice()
                .try_into()
                .context("Invalid manifest chunk CID")?;
            needed_cids.push(arr);
        }
    }
    needed_cids.sort();
    needed_cids.dedup();

    let mut chunks = store.get_chunks(&needed_cids)?;
    if chunks.len() != needed_cids.len() {
        // Attempt to fetch missing chunks from configured operators
        let existing_cids: std::collections::HashSet<[u8; 32]> =
            chunks.iter().filter_map(|c| c.compute_cid().ok()).collect();
        let missing_cids: Vec<[u8; 32]> = needed_cids
            .iter()
            .copied()
            .filter(|cid| !existing_cids.contains(cid))
            .collect();

        let operators = get_configured_operators();
        if !operators.is_empty() {
            let pool = configured_operator_pool(operators);
            for cid in &missing_cids {
                if let Ok(bytes) = pool.fetch_object_from_any(cid).await {
                    if let Ok(chunk) = from_canonical_cbor::<ChunkWireObject>(&bytes) {
                        chunks.push(chunk);
                    }
                }
            }
        }

        if chunks.len() != needed_cids.len() {
            bail!(
                "Cannot execute: missing {} encrypted chunk(s) across local store and operators",
                needed_cids.len() - chunks.len()
            );
        }
    }

    // Decrypt snapshot files strictly in volatile memory (zero disk exposure)
    let files = decrypt_snapshot(
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    )?;
    Ok(SnapshotBundle { snapshot_id, files })
}

#[allow(clippy::too_many_arguments)]
async fn cmd_run_snapshot(
    snapshot_hex_opt: Option<String>,
    env_file_opt: Option<String>,
    legacy: bool,
    no_inherit: bool,
    dry_run: bool,
    quiet: bool,
    json: bool,
    set_overrides: Option<Vec<String>>,
    allow_filter: &AllowKeysFilter,
    no_net: bool,
    proxy: bool,
    proxy_upstream: Vec<String>,
    sandbox_read_paths: &[String],
    command: Vec<String>,
) -> Result<()> {
    let store = get_vault_store()?;
    let bundle = load_snapshot_bundle(&store, snapshot_hex_opt.as_deref()).await?;
    let snapshot_id = bundle.snapshot_id;
    let mut decrypted_files = bundle.files;
    // Snapshot mode is the legacy path (§F-§4): it keeps working behind the
    // `--legacy` compat flag. Warn at most once per day per vault (marker
    // file) so scripts aren't spammed; CIPHERVAULT_LEGACY_WARN=0 opts out.
    if !legacy && !quiet && !json && std::env::var("CIPHERVAULT_LEGACY_WARN").as_deref() != Ok("0")
    {
        use std::io::Write;
        let marker = std::env::temp_dir().join(format!(
            "ciphervault-legacy-warn-{}",
            hex::encode(&snapshot_id[..8])
        ));
        let show = match std::fs::metadata(&marker) {
            Ok(meta) => match meta.modified() {
                Ok(modified) => std::time::SystemTime::now()
                    .duration_since(modified)
                    .map(|age| age.as_secs() > 86_400)
                    .unwrap_or(true),
                Err(_) => true,
            },
            Err(_) => true,
        };
        if show {
            eprintln!(
                "{} LEGACY_PATH_DEPRECATED: snapshot-mode `run` is deprecated; migrate with `ciphervault migrate plan` (pass --legacy to silence, CIPHERVAULT_LEGACY_WARN=0 to disable)",
                "[ciphervault]".bold().yellow(),
            );
            if let Ok(mut file) = std::fs::File::create(&marker) {
                let _ = writeln!(file, "warned");
            }
        }
    }

    // Select which file(s) to load environment variables from
    let mut loaded_vars: Vec<(String, Zeroizing<String>)> = Vec::new();
    let mut loaded_from_files: Vec<String> = Vec::new();

    if let Some(target_file) = env_file_opt {
        let norm_target = target_file.replace('\\', "/");
        let matched = decrypted_files
            .iter()
            .find(|f| f.relative_path.replace('\\', "/") == norm_target);

        match matched {
            Some(file) => {
                let parsed = dotenv::parse_dotenv_bytes(&file.plaintext).map_err(|e| {
                    anyhow::anyhow!("Failed to parse '{}': {}", file.relative_path, e)
                })?;
                loaded_from_files.push(file.relative_path.clone());
                loaded_vars.extend(
                    parsed
                        .into_iter()
                        .map(|(name, value)| (name, Zeroizing::new(value))),
                );
            }
            None => {
                bail!(
                    "Specified env file '{}' not found in snapshot {}",
                    target_file,
                    &hex::encode(snapshot_id)[..12]
                );
            }
        }
    } else {
        // Auto-detect .env files: load .env first, then other .env.* files
        let mut env_files: Vec<&ciphervault_snapshot::DecryptedFile> = decrypted_files
            .iter()
            .filter(|f| {
                let p = f.relative_path.replace('\\', "/");
                let name = p.rsplit('/').next().unwrap_or(&p);
                name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
            })
            .collect();

        // Sort so that .env is base and .env.local / .env.production override earlier keys
        env_files.sort_by_key(|f| {
            let p = f.relative_path.replace('\\', "/");
            let name = p.rsplit('/').next().unwrap_or(&p);
            if name == ".env" {
                0
            } else {
                1
            }
        });

        if env_files.is_empty() {
            if !quiet && !json {
                eprintln!(
                    "{}",
                    "⚠️  No .env files found in snapshot; running with existing environment only."
                        .yellow()
                );
            }
        } else {
            for file in env_files {
                let parsed = dotenv::parse_dotenv_bytes(&file.plaintext).map_err(|e| {
                    anyhow::anyhow!("Failed to parse '{}': {}", file.relative_path, e)
                })?;
                loaded_from_files.push(file.relative_path.clone());
                loaded_vars.extend(
                    parsed
                        .into_iter()
                        .map(|(name, value)| (name, Zeroizing::new(value))),
                );
            }
        }
    }

    // Apply least-privilege allowlist before --set overrides, zeroizing filtered-out values.
    filter_loaded_vars_with_policy(&mut loaded_vars, allow_filter)?;

    // Apply additional --set overrides, then deduplicate (last wins).
    let deduped_vars = apply_overrides(loaded_vars, set_overrides)?;

    // Dry Run Mode
    if dry_run {
        if json {
            let res = serde_json::json!({
                "status": "dry_run",
                "mode": "snapshot",
                "snapshot_id": hex::encode(snapshot_id),
                "sources": loaded_from_files,
                "secrets_count": deduped_vars.len(),
                "secrets": deduped_vars.keys().map(|k| serde_json::json!({
                    "name": k,
                    "status": "active"
                })).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&res)?);
            for f in &mut decrypted_files {
                f.plaintext.zeroize();
            }
            return Ok(());
        }

        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!(
            "  {}",
            "CipherVault Zero-Disk Secret Injection (Dry Run)"
                .bold()
                .green()
        );
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!("Snapshot: {}", hex::encode(snapshot_id)[..12].yellow());
        println!("Sources:  {}", loaded_from_files.join(", ").cyan());
        println!(
            "Secrets:  {} variable(s) ready for injection",
            deduped_vars.len()
        );
        println!();
        for k in deduped_vars.keys() {
            println!("  • {} = [REDACTED]", k.bold().white());
        }
        println!();
        println!(
            "{}",
            "✓ Zero secrets written to disk. Exiting without execution.".green()
        );

        // Zeroize memory buffers
        for f in &mut decrypted_files {
            f.plaintext.zeroize();
        }
        return Ok(());
    }

    // Zeroize decrypted memory buffers prior to child process execution
    for f in &mut decrypted_files {
        f.plaintext.zeroize();
    }

    let label = format!("snapshot {}", &hex::encode(snapshot_id)[..8]);
    spawn_with_env(
        &command,
        deduped_vars,
        no_inherit,
        no_net,
        proxy,
        &proxy_upstream,
        sandbox_read_paths,
        quiet,
        json,
        &label,
    )
    .await
}

/// Shared child spawn: injects `vars` (or starts loopback credential proxy when `proxy` is true),
/// honors `--no-inherit`/`--no-net`/`--quiet`/`--json`, and propagates the child exit code.
#[allow(clippy::too_many_arguments)]
async fn spawn_with_env(
    command: &[String],
    vars: std::collections::BTreeMap<String, Zeroizing<String>>,
    no_inherit: bool,
    no_net: bool,
    proxy: bool,
    proxy_upstream: &[String],
    sandbox_read_paths: &[String],
    quiet: bool,
    json: bool,
    label: &str,
) -> Result<()> {
    let start_time = std::time::Instant::now();
    let num_secrets = vars.len();
    let proxy_enabled = proxy || !proxy_upstream.is_empty();
    if proxy_enabled && no_net {
        bail!("--proxy and --no-net cannot be combined");
    }

    // Configure Child Command
    let exe = &command[0];
    let raw_args = &command[1..];

    #[cfg(target_os = "windows")]
    let (resolved_bin, resolved_prefix) = resolve_windows_command(exe);
    #[cfg(not(target_os = "windows"))]
    let (resolved_bin, resolved_prefix): (String, Vec<String>) = (exe.clone(), Vec::new());

    // Preflight and apply `--no-net` BEFORE placing secrets into the child env
    // so unsupported/restricted hosts fail closed without populating secrets.
    #[cfg(target_os = "windows")]
    let win_no_net: Option<windows_no_net::AppContainerContext>;

    let (target_bin, full_args) = if no_net {
        #[cfg(target_os = "windows")]
        {
            let ctx = windows_no_net::AppContainerContext::new()?;
            ctx.ensure_winsta_desktop_access()?;
            ctx.preflight()?;
            if !sandbox_read_paths.is_empty() {
                let workspace_root = crate::util::get_workspace_root()
                    .or_else(|_| std::env::current_dir().map_err(anyhow::Error::from))?;
                let tracked_paths: Vec<String> = crate::util::get_vault_store()
                    .ok()
                    .and_then(|s| s.list_tracked_files().ok())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(p, _)| p.to_string_lossy().replace('\\', "/"))
                    .collect();
                windows_no_net::grant_sandbox_read_paths(
                    &workspace_root,
                    sandbox_read_paths,
                    &tracked_paths,
                )?;
            }
            let prepared =
                windows_no_net::prepare_command(&resolved_bin, &resolved_prefix, raw_args)?;
            win_no_net = Some(ctx);
            prepared
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = sandbox_read_paths;
            apply_no_net_sandbox(&resolved_bin, &resolved_prefix, raw_args)?
        }
    } else {
        #[cfg(target_os = "windows")]
        {
            win_no_net = None;
        }
        let mut combined = resolved_prefix;
        combined.extend(raw_args.iter().cloned());
        (resolved_bin, combined)
    };

    if proxy_enabled {
        let explicit_opt = (!proxy_upstream.is_empty()).then_some(proxy_upstream);
        let routes = super::run_proxy::build_proxy_routes(&vars, explicit_opt)?;
        let num_proxied = routes.len();
        let exact_values: Vec<(String, Zeroizing<String>)> = vars
            .iter()
            .map(|(k, v)| (k.clone(), Zeroizing::new(v.as_str().to_string())))
            .collect();
        drop(vars);

        let running_proxy = super::run_proxy::start_credential_proxy(routes).await?;

        let mut cmd = tokio::process::Command::new(&target_bin);
        if !full_args.is_empty() {
            cmd.args(&full_args);
        }
        if no_inherit {
            cmd.env_clear();
            for (k, v) in std::env::vars() {
                let k_upper = k.to_uppercase();
                if k_upper == "PATH"
                    || k_upper == "SYSTEMROOT"
                    || k_upper == "TEMP"
                    || k_upper == "TMP"
                    || k_upper == "USERPROFILE"
                    || k_upper == "HOME"
                    || k_upper == "COMSPEC"
                    || k_upper == "PATHEXT"
                {
                    cmd.env(k, v);
                }
            }
        }
        for (key, _) in std::env::vars_os() {
            if is_control_credential(&key.to_string_lossy()) {
                cmd.env_remove(key);
            }
        }
        for (k, v) in &running_proxy.child_env {
            cmd.env(k, v);
        }

        if json {
            let output = cmd
                .output()
                .await
                .with_context(|| format!("Failed to spawn command '{}'", exe))?;
            running_proxy.shutdown().await;
            let duration_ms = start_time.elapsed().as_millis() as u64;
            let raw_stdout = String::from_utf8_lossy(&output.stdout);
            let raw_stderr = String::from_utf8_lossy(&output.stderr);
            let (exact_stdout, n_out) =
                ciphervault_redact::scrub_exact_values(&raw_stdout, &exact_values);
            let (exact_stderr, n_err) =
                ciphervault_redact::scrub_exact_values(&raw_stderr, &exact_values);
            let (redacted_stdout, n_out_shape) =
                ciphervault_redact::redact_text_counted(&exact_stdout);
            let (redacted_stderr, n_err_shape) =
                ciphervault_redact::redact_text_counted(&exact_stderr);
            let redactions = n_out + n_out_shape + n_err + n_err_shape;
            let exit_code = output.status.code().unwrap_or(1);
            let payload = serde_json::json!({
                "status": if exit_code == 0 { "success" } else { "failed" },
                "exit_code": exit_code,
                "command": command,
                "source": label,
                "no_net": false,
                "proxy": true,
                "secrets_injected_count": 0,
                "secrets_proxied_count": num_proxied,
                "stdout": redacted_stdout,
                "stderr": redacted_stderr,
                "redactions": redactions,
                "duration_ms": duration_ms
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            return Ok(());
        }

        if !quiet {
            eprintln!(
                "{} Proxied {} secret(s) from {} via 127.0.0.1 for '{}' (zero real secrets in child env)",
                "[ciphervault]".bold().cyan(),
                num_proxied.to_string().bold().green(),
                label.yellow(),
                exe.white()
            );
        }

        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn command '{}'", exe))?;
        drop(cmd);
        let status = child
            .wait()
            .await
            .with_context(|| format!("Failed to wait on child process '{}'", exe))?;
        running_proxy.shutdown().await;
        let exit_code = status.code().unwrap_or(1);
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }

    // Wait: on Windows `--no-net`, execute directly inside a zero-capability AppContainer
    // using CreateProcessW + STARTUPINFOEXW + anonymous pipes (AppContainer cannot attach
    // to inherited Win32 console pseudo-handles).
    #[cfg(target_os = "windows")]
    if let Some(ac) = win_no_net {
        let mut child_env: std::collections::BTreeMap<String, (String, Zeroizing<String>)> =
            std::collections::BTreeMap::new();
        for (k, v) in std::env::vars() {
            let k_upper = k.to_ascii_uppercase();
            if no_inherit {
                let keep = matches!(
                    k_upper.as_str(),
                    "PATH"
                        | "SYSTEMROOT"
                        | "TEMP"
                        | "TMP"
                        | "USERPROFILE"
                        | "LOCALAPPDATA"
                        | "HOME"
                        | "COMSPEC"
                        | "PATHEXT"
                );
                if !keep {
                    continue;
                }
            }
            if is_control_credential(&k) {
                continue;
            }
            child_env.insert(k_upper, (k, Zeroizing::new(v)));
        }
        for (key, value) in &vars {
            if is_control_credential(key) {
                bail!("'{key}' is reserved for CipherVault authentication and cannot be injected into a workload");
            }
            if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
                bail!("Invalid child environment entry '{key}'");
            }
            child_env.insert(
                key.to_ascii_uppercase(),
                (key.clone(), Zeroizing::new(value.as_str().to_string())),
            );
        }

        if json {
            let exact_values: Vec<(String, Zeroizing<String>)> = vars
                .iter()
                .map(|(k, v)| (k.clone(), Zeroizing::new(v.as_str().to_string())))
                .collect();
            drop(vars);
            let (raw_code, out_bytes, err_bytes) =
                ac.execute(&target_bin, &full_args, &child_env, false)?;
            drop(child_env);
            drop(ac);
            let duration_ms = start_time.elapsed().as_millis() as u64;
            let raw_stdout = String::from_utf8_lossy(&out_bytes);
            let raw_stderr = String::from_utf8_lossy(&err_bytes);
            let (exact_stdout, n_out) =
                ciphervault_redact::scrub_exact_values(&raw_stdout, &exact_values);
            let (exact_stderr, n_err) =
                ciphervault_redact::scrub_exact_values(&raw_stderr, &exact_values);
            let (redacted_stdout, n_out_shape) =
                ciphervault_redact::redact_text_counted(&exact_stdout);
            let (redacted_stderr, n_err_shape) =
                ciphervault_redact::redact_text_counted(&exact_stderr);
            let redactions = n_out + n_out_shape + n_err + n_err_shape;
            let exit_code = raw_code as i32;
            let mut payload = serde_json::json!({
                "status": if exit_code == 0 { "success" } else { "failed" },
                "exit_code": exit_code,
                "command": command,
                "source": label,
                "no_net": true,
                "secrets_injected_count": num_secrets,
                "stdout": redacted_stdout,
                "stderr": redacted_stderr,
                "redactions": redactions,
                "duration_ms": duration_ms
            });
            attach_appcontainer_hint(&mut payload, exit_code);
            println!("{}", serde_json::to_string_pretty(&payload)?);
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            return Ok(());
        }

        if !quiet {
            eprintln!(
                "{} Injected {} secret(s) from {} into '{}' (Windows AppContainer --no-net)",
                "[ciphervault]".bold().cyan(),
                vars.len().to_string().bold().green(),
                label.yellow(),
                exe.white()
            );
        }
        drop(vars);
        let (raw_code, _, _) = ac.execute(&target_bin, &full_args, &child_env, true)?;
        drop(child_env);
        drop(ac);
        let exit_code = raw_code as i32;
        if let Some(hint) = appcontainer_dll_hint(exit_code) {
            eprintln!("{} {}", "[ciphervault]".bold().yellow(), hint);
        }
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }

    let mut cmd = std::process::Command::new(&target_bin);
    if !full_args.is_empty() {
        cmd.args(&full_args);
    }

    if no_inherit {
        cmd.env_clear();
        // Retain essential operating system paths so standard binaries and runtimes function
        for (k, v) in std::env::vars() {
            let k_upper = k.to_uppercase();
            if k_upper == "PATH"
                || k_upper == "SYSTEMROOT"
                || k_upper == "TEMP"
                || k_upper == "TMP"
                || k_upper == "USERPROFILE"
                || k_upper == "HOME"
                || k_upper == "COMSPEC"
                || k_upper == "PATHEXT"
            {
                cmd.env(k, v);
            }
        }
    }

    // Never pass CipherVault control credentials to the workload.
    for (key, _) in std::env::vars_os() {
        if is_control_credential(&key.to_string_lossy()) {
            cmd.env_remove(key);
        }
    }
    for (key, value) in &vars {
        if is_control_credential(key) {
            bail!("'{key}' is reserved for CipherVault authentication and cannot be injected into a workload");
        }
        if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
            bail!("Invalid child environment entry '{key}'");
        }
        cmd.env(key, value.as_str());
    }

    if json {
        // AI Agent Bridge: capture stdout and stderr, scrub outputs.
        // Exact-value scrubbing first (the child may echo an injected
        // value bare, in a shape no pattern recognises), then shape
        // redaction. Values are kept in Zeroizing storage only until
        // the child has finished and its output is scrubbed.
        let exact_values: Vec<(String, Zeroizing<String>)> = vars
            .iter()
            .map(|(k, v)| (k.clone(), Zeroizing::new(v.as_str().to_string())))
            .collect();
        drop(vars);
        let output = cmd
            .output()
            .with_context(|| format!("Failed to spawn command '{}'", exe))?;
        let duration_ms = start_time.elapsed().as_millis() as u64;

        let raw_stdout = String::from_utf8_lossy(&output.stdout);
        let raw_stderr = String::from_utf8_lossy(&output.stderr);

        let (exact_stdout, n_out) =
            ciphervault_redact::scrub_exact_values(&raw_stdout, &exact_values);
        let (exact_stderr, n_err) =
            ciphervault_redact::scrub_exact_values(&raw_stderr, &exact_values);
        let (redacted_stdout, n_out_shape) = ciphervault_redact::redact_text_counted(&exact_stdout);
        let (redacted_stderr, n_err_shape) = ciphervault_redact::redact_text_counted(&exact_stderr);
        // Count shape-only rewrites too; receipts must not under-report.
        let redactions = n_out + n_out_shape + n_err + n_err_shape;

        let exit_code = output.status.code().unwrap_or(1);
        let payload = serde_json::json!({
            "status": if exit_code == 0 { "success" } else { "failed" },
            "exit_code": exit_code,
            "command": command,
            "source": label,
            "no_net": no_net,
            "secrets_injected_count": num_secrets,
            "stdout": redacted_stdout,
            "stderr": redacted_stderr,
            "redactions": redactions,
            "duration_ms": duration_ms
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }

    if !quiet {
        eprintln!(
            "{} Injected {} secret(s) from {} into '{}'",
            "[ciphervault]".bold().cyan(),
            vars.len().to_string().bold().green(),
            label.yellow(),
            exe.white()
        );
    }

    // Spawn child process with inherited stdio
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn command '{}'", exe))?;

    // Release application-owned values before waiting. Command and OS
    // environment copies remain outside application zeroization guarantees.
    drop(vars);
    drop(cmd);
    let status = child
        .wait()
        .with_context(|| format!("Failed to wait on child process '{}'", exe))?;

    let exit_code = status.code().unwrap_or(1);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn appcontainer_dll_hint(exit_code: i32) -> Option<String> {
    if exit_code == -1073741515 || exit_code == -1073741502 {
        Some(format!(
            "Child process exited with Windows DLL initialization status 0x{:08X} inside --no-net AppContainer. \
             Ensure required runtime DLLs and working directory allow ALL APPLICATION PACKAGES (S-1-15-2-1) read/execute access, or use --proxy.",
            exit_code as u32
        ))
    } else {
        None
    }
}

#[cfg(any(target_os = "windows", test))]
fn attach_appcontainer_hint(payload: &mut serde_json::Value, exit_code: i32) {
    if let Some(hint) = appcontainer_dll_hint(exit_code) {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "appcontainer_hint".to_string(),
                serde_json::Value::String(hint),
            );
        }
    }
}

fn is_control_credential(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name.starts_with("CIPHERVAULT_")
        && (name.contains("TOKEN")
            || name.contains("SECRET")
            || name.contains("KEY")
            || name.ends_with("_PIN")
            || name.contains("PASSWORD"))
}

#[cfg(target_os = "windows")]
pub(crate) fn resolve_windows_command(exe: &str) -> (String, Vec<String>) {
    let p = Path::new(exe);
    if p.extension().is_some() || exe.contains('\\') || exe.contains('/') {
        return (exe.to_string(), Vec::new());
    }

    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    let extensions: Vec<&str> = pathext.split(';').filter(|s| !s.is_empty()).collect();

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            // Skip packaged-app payload dirs (e.g. the Hermes desktop
            // bundle's tools): those executables are ACL-denied to
            // arbitrary child processes, so resolving to them makes
            // every spawn fail with "Access is denied".
            if dir.to_string_lossy().contains("WindowsApps") {
                continue;
            }
            for ext in &extensions {
                let candidate = dir.join(format!("{}{}", exe, ext));
                if candidate.is_file() {
                    let ext_upper = ext.to_uppercase();
                    if ext_upper == ".CMD" || ext_upper == ".BAT" {
                        return (
                            "cmd.exe".to_string(),
                            vec!["/c".to_string(), candidate.to_string_lossy().to_string()],
                        );
                    }
                    return (candidate.to_string_lossy().to_string(), Vec::new());
                }
            }
        }
    }

    // Unresolved by PATHEXT (e.g. extensionless MSYS shims like
    // /mingw64/bin/git, which CreateProcess cannot launch directly):
    // route through the shell so `cv run` matches what works in the
    // user's terminal. Genuinely-missing commands still fail, via the
    // shell's "not recognized" exit instead of a spawn error.
    (
        "cmd.exe".to_string(),
        vec!["/c".to_string(), exe.to_string()],
    )
}

/// Glob matching for secret variable names where `*` matches zero or more characters.
pub(crate) fn key_matches_pattern(key: &str, pattern: &str) -> bool {
    let k = key.as_bytes();
    let p = pattern.as_bytes();
    let (mut ki, mut pi) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ki: usize = 0;

    while ki < k.len() {
        if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ki = ki;
        } else if pi < p.len() && p[pi] == k[ki] {
            pi += 1;
            ki += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ki += 1;
            ki = star_ki;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Returns true iff there exists at least one string matched by both `*`-glob patterns.
fn patterns_can_overlap(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let (n, m) = (ab.len(), bb.len());
    let mut dp = vec![vec![false; m + 1]; n + 1];
    dp[n][m] = true;
    for i in (0..=n).rev() {
        for j in (0..=m).rev() {
            if i == n && j == m {
                continue;
            }
            if i < n && ab[i] == b'*' {
                dp[i][j] = dp[i + 1][j] || (j < m && dp[i][j + 1]);
            } else if j < m && bb[j] == b'*' {
                dp[i][j] = dp[i][j + 1] || (i < n && dp[i + 1][j]);
            } else if i < n && j < m && ab[i] == bb[j] {
                dp[i][j] = dp[i + 1][j + 1];
            }
        }
    }
    dp[0][0]
}

fn validate_allow_pattern(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("allow_keys pattern cannot be empty");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '*')
    {
        bail!(
            "Invalid allow_keys pattern '{trimmed}': only ASCII letters, digits, '_', and '*' are allowed"
        );
    }
    Ok(trimmed.to_string())
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AllowKeysFilter {
    /// Upper-bound patterns from `[profiles.<name>].allow_keys` (optional matches;
    /// injects all matching keys that exist in the vault, errors only if zero match).
    pub(crate) profile_patterns: Option<Vec<String>>,
    /// Explicit CLI `--allow-keys` patterns (narrows profile if present; non-wildcard
    /// entries MUST exist in the vault).
    pub(crate) cli_patterns: Option<Vec<String>>,
    /// Keys from `[profiles.<name>].require_keys` that MUST exist and remain allowed.
    pub(crate) require_keys: Vec<String>,
    /// Profile name for diagnostics.
    pub(crate) profile_name: Option<String>,
}

fn normalize_allow_keys(
    allow_keys: Option<&[String]>,
) -> Result<Option<std::collections::BTreeSet<String>>> {
    let Some(raw) = allow_keys else {
        return Ok(None);
    };
    let mut set = std::collections::BTreeSet::new();
    for item in raw {
        let key = item.trim();
        if !key.is_empty() {
            set.insert(validate_allow_pattern(key)?);
        }
    }
    if set.is_empty() {
        bail!("--allow-keys requires at least one non-empty variable name");
    }
    Ok(Some(set))
}

fn key_permitted_by_filter(key: &str, filter: &AllowKeysFilter) -> bool {
    if let Some(ref prof_pats) = filter.profile_patterns {
        if !prof_pats.iter().any(|p| key_matches_pattern(key, p)) {
            return false;
        }
    }
    if let Some(ref cli_pats) = filter.cli_patterns {
        if !cli_pats.iter().any(|p| key_matches_pattern(key, p)) {
            return false;
        }
    }
    true
}

fn validate_filter_against_keys(
    present: &std::collections::HashSet<&str>,
    retained: &std::collections::HashSet<&str>,
    filter: &AllowKeysFilter,
    source_label: &str,
) -> Result<()> {
    if let Some(ref cli_pats) = filter.cli_patterns {
        let missing_exact: Vec<&str> = cli_pats
            .iter()
            .map(String::as_str)
            .filter(|p| !p.contains('*') && !present.contains(*p))
            .collect();
        if !missing_exact.is_empty() {
            bail!(
                "--allow-keys requested variable(s) not present in {source_label}: {}",
                missing_exact.join(", ")
            );
        }
    }

    if (filter.profile_patterns.is_some() || filter.cli_patterns.is_some()) && retained.is_empty() {
        if let Some(ref prof_name) = filter.profile_name {
            if let Some(ref cli_pats) = filter.cli_patterns {
                bail!(
                    "--allow-keys ({}) matched 0 variables permitted by profile '{prof_name}' in {source_label}",
                    cli_pats.join(", ")
                );
            }
            let pats = filter.profile_patterns.as_deref().unwrap_or(&[]).join(", ");
            bail!(
                "Profile '{prof_name}' allow_keys matched 0 variables in {source_label} (patterns: {pats})"
            );
        }
        let pats = filter.cli_patterns.as_deref().unwrap_or(&[]).join(", ");
        bail!("--allow-keys matched 0 variables in {source_label} (patterns: {pats})");
    }

    if !filter.require_keys.is_empty() {
        let missing_req: Vec<&str> = filter
            .require_keys
            .iter()
            .map(String::as_str)
            .filter(|req| !retained.contains(*req))
            .collect();
        if !missing_req.is_empty() {
            let prof_label = filter.profile_name.as_deref().unwrap_or("default");
            bail!(
                "Profile '{prof_label}' require_keys missing from {source_label} or active allowlist: {}",
                missing_req.join(", ")
            );
        }
    }
    Ok(())
}

fn filter_loaded_vars_with_policy(
    loaded_vars: &mut Vec<(String, Zeroizing<String>)>,
    filter: &AllowKeysFilter,
) -> Result<()> {
    if filter.profile_patterns.is_none()
        && filter.cli_patterns.is_none()
        && filter.require_keys.is_empty()
    {
        return Ok(());
    }
    let check_res = {
        let present: std::collections::HashSet<&str> =
            loaded_vars.iter().map(|(k, _)| k.as_str()).collect();
        let retained: std::collections::HashSet<&str> = loaded_vars
            .iter()
            .map(|(k, _)| k.as_str())
            .filter(|k| key_permitted_by_filter(k, filter))
            .collect();
        validate_filter_against_keys(&present, &retained, filter, "vault snapshot")
    };
    if let Err(err) = check_res {
        loaded_vars.clear();
        return Err(err);
    }
    loaded_vars.retain(|(k, _)| key_permitted_by_filter(k, filter));
    Ok(())
}

fn filter_scoped_names_with_policy(
    names: &mut Vec<(String, i64, String)>,
    filter: &AllowKeysFilter,
    scope_label: &str,
) -> Result<()> {
    if filter.profile_patterns.is_none()
        && filter.cli_patterns.is_none()
        && filter.require_keys.is_empty()
    {
        return Ok(());
    }
    let check_res = {
        let present: std::collections::HashSet<&str> =
            names.iter().map(|(n, _, _)| n.as_str()).collect();
        let retained: std::collections::HashSet<&str> = names
            .iter()
            .map(|(n, _, _)| n.as_str())
            .filter(|n| key_permitted_by_filter(n, filter))
            .collect();
        validate_filter_against_keys(&present, &retained, filter, scope_label)
    };
    if let Err(err) = check_res {
        names.clear();
        return Err(err);
    }
    names.retain(|(n, _, _)| key_permitted_by_filter(n, filter));
    Ok(())
}

#[cfg(test)]
fn filter_loaded_vars_by_allow_keys(
    loaded_vars: &mut Vec<(String, Zeroizing<String>)>,
    allow_keys: Option<&[String]>,
) -> Result<()> {
    let Some(allowed) = normalize_allow_keys(allow_keys)? else {
        return Ok(());
    };
    let filter = AllowKeysFilter {
        profile_patterns: None,
        cli_patterns: Some(allowed.into_iter().collect()),
        require_keys: Vec::new(),
        profile_name: None,
    };
    filter_loaded_vars_with_policy(loaded_vars, &filter)
}
