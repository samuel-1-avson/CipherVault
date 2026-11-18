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
    mut allow_keys: Option<Vec<String>>,
    mut no_net: bool,
    mut proxy: bool,
    mut proxy_upstream: Vec<String>,
    profile_opt: Option<String>,
    command: Vec<String>,
) -> Result<()> {
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
        allow_keys = merge_profile_allow_keys(allow_keys, &profile.allow_keys, profile_name)?;
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
    } else if !no_net && !proxy && proxy_upstream.is_empty() {
        let vault_dir = crate::util::get_vault_directory();
        if let Some(policy) = load_workspace_policy(&vault_dir)? {
            if policy.default_no_net == Some(true) {
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
            allow_keys,
            no_net,
            proxy_enabled,
            proxy_upstream,
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
        allow_keys,
        no_net,
        proxy_enabled,
        proxy_upstream,
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
    allow_keys: Option<Vec<String>>,
    no_net: bool,
    proxy: bool,
    proxy_upstream: Vec<String>,
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
    if let Some(allowed) = normalize_allow_keys(allow_keys.as_deref())? {
        let present: std::collections::HashSet<&str> =
            names.iter().map(|(n, _, _)| n.as_str()).collect();
        let missing: Vec<&str> = allowed
            .iter()
            .map(String::as_str)
            .filter(|k| !present.contains(*k))
            .collect();
        if !missing.is_empty() {
            bail!(
                "--allow-keys requested variable(s) not present in {scope_label}: {}",
                missing.join(", ")
            );
        }
        names.retain(|(n, _, _)| allowed.contains(n));
    }

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
    allow_keys: Option<Vec<String>>,
    no_net: bool,
    proxy: bool,
    proxy_upstream: Vec<String>,
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
    filter_loaded_vars_by_allow_keys(&mut loaded_vars, allow_keys.as_deref())?;

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
            let prepared =
                windows_no_net::prepare_command(&resolved_bin, &resolved_prefix, raw_args)?;
            win_no_net = Some(ctx);
            prepared
        }
        #[cfg(not(target_os = "windows"))]
        {
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
            set.insert(key.to_string());
        }
    }
    if set.is_empty() {
        bail!("--allow-keys requires at least one non-empty variable name");
    }
    Ok(Some(set))
}

fn filter_loaded_vars_by_allow_keys(
    loaded_vars: &mut Vec<(String, Zeroizing<String>)>,
    allow_keys: Option<&[String]>,
) -> Result<()> {
    let Some(allowed) = normalize_allow_keys(allow_keys)? else {
        return Ok(());
    };
    let present: std::collections::HashSet<&str> =
        loaded_vars.iter().map(|(k, _)| k.as_str()).collect();
    let missing: Vec<&str> = allowed
        .iter()
        .map(String::as_str)
        .filter(|k| !present.contains(*k))
        .collect();
    if !missing.is_empty() {
        loaded_vars.clear();
        bail!(
            "--allow-keys requested variable(s) not present in vault snapshot: {}",
            missing.join(", ")
        );
    }
    loaded_vars.retain(|(k, _)| allowed.contains(k));
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_no_net_sandbox(
    resolved_bin: &str,
    resolved_prefix: &[String],
    raw_args: &[String],
) -> Result<(String, Vec<String>)> {
    let mut last_err = String::new();
    for flag_set in [
        &["--user", "--map-root-user", "--net"][..],
        &["-r", "-n"][..],
    ] {
        let mut preflight = std::process::Command::new("unshare");
        preflight.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            preflight.env("PATH", path);
        }
        let mut test_args: Vec<&str> = flag_set.to_vec();
        test_args.extend(["--", "true"]);
        let output = preflight
            .args(&test_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .context(
                "--no-net requires `unshare` (util-linux or busybox) on Linux, which could not be executed",
            )?;
        if output.status.success() {
            let mut args: Vec<String> = flag_set.iter().map(|s| (*s).to_string()).collect();
            args.push("--".to_string());
            args.push(resolved_bin.to_string());
            args.extend(resolved_prefix.iter().cloned());
            args.extend(raw_args.iter().cloned());
            return Ok(("unshare".to_string(), args));
        }
        last_err = String::from_utf8_lossy(&output.stderr).trim().to_string();
    }
    bail!(
        "--no-net sandbox preflight failed (unprivileged user/network namespaces may be restricted): {}",
        last_err
    );
}

#[cfg(target_vendor = "apple")]
const MACOS_NO_NET_SANDBOX_PROFILE: &str = "(version 1)(allow default)\
(deny network-outbound (remote ip))\
(deny network-inbound (local ip))\
(deny network-bind (local ip))\
(deny network-outbound (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))\
(deny network-outbound (remote unix-socket (path-literal \"/var/run/mDNSResponder\")))";

#[cfg(target_vendor = "apple")]
fn apply_no_net_sandbox(
    resolved_bin: &str,
    resolved_prefix: &[String],
    raw_args: &[String],
) -> Result<(String, Vec<String>)> {
    let mut preflight = std::process::Command::new("/usr/bin/sandbox-exec");
    preflight.env_clear();
    let status = preflight
        .args(["-p", MACOS_NO_NET_SANDBOX_PROFILE, "/usr/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("--no-net requires /usr/bin/sandbox-exec on macOS, which could not be executed")?;
    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        bail!(
            "--no-net sandbox preflight failed on macOS: {}",
            stderr.trim()
        );
    }
    let mut args = vec![
        "-p".to_string(),
        MACOS_NO_NET_SANDBOX_PROFILE.to_string(),
        resolved_bin.to_string(),
    ];
    args.extend(resolved_prefix.iter().cloned());
    args.extend(raw_args.iter().cloned());
    Ok(("/usr/bin/sandbox-exec".to_string(), args))
}

#[cfg(target_os = "windows")]
mod windows_no_net {
    use anyhow::{bail, Context, Result};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::sync::OnceLock;
    use walkdir::WalkDir;
    use zeroize::Zeroizing;

    const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    const INFINITE: u32 = 0xFFFF_FFFF;
    const SE_WINDOW_OBJECT: u32 = 7;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GRANT_ACCESS: u32 = 1;
    const NO_INHERITANCE: u32 = 0;
    const NO_MULTIPLE_TRUSTEE: u32 = 0;
    const TRUSTEE_IS_SID: u32 = 0;
    const TRUSTEE_IS_WELL_KNOWN_GROUP: u32 = 5;
    const E_ALREADY_EXISTS: i32 = -2147024713; // 0x800700B7

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct SecurityCapabilities {
        app_container_sid: *mut c_void,
        capabilities: *mut c_void,
        capability_count: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        lp_reserved: *mut u16,
        lp_desktop: *mut u16,
        lp_title: *mut u16,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: isize,
        h_std_output: isize,
        h_std_error: isize,
    }

    #[repr(C)]
    struct StartupInfoExW {
        startup_info: StartupInfoW,
        lp_attribute_list: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        h_process: isize,
        h_thread: isize,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    #[repr(C)]
    struct TrusteeW {
        p_multiple_trustee: *mut c_void,
        multiple_trustee_operation: u32,
        trustee_form: u32,
        trustee_type: u32,
        ptstr_name: *mut c_void,
    }

    #[repr(C)]
    struct ExplicitAccessW {
        grf_access_permissions: u32,
        grf_access_mode: u32,
        grf_inheritance: u32,
        trustee: TrusteeW,
    }

    #[link(name = "userenv")]
    extern "system" {
        fn CreateAppContainerProfile(
            psz_app_container_name: *const u16,
            psz_display_name: *const u16,
            psz_description: *const u16,
            p_capabilities: *const c_void,
            dw_capability_count: u32,
            pp_sid_app_container_sid: *mut *mut c_void,
        ) -> i32;

        fn DeriveAppContainerSidFromAppContainerName(
            psz_app_container_name: *const u16,
            ppsid_app_container_sid: *mut *mut c_void,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn FreeSid(p_sid: *mut c_void) -> *mut c_void;
        fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
        fn GetSecurityInfo(
            handle: isize,
            object_type: u32,
            security_info: u32,
            ppsid_owner: *mut *mut c_void,
            ppsid_group: *mut *mut c_void,
            pp_dacl: *mut *mut c_void,
            pp_sacl: *mut *mut c_void,
            pp_security_descriptor: *mut *mut c_void,
        ) -> u32;
        fn SetSecurityInfo(
            handle: isize,
            object_type: u32,
            security_info: u32,
            psid_owner: *mut c_void,
            psid_group: *mut c_void,
            p_dacl: *mut c_void,
            p_sacl: *mut c_void,
        ) -> u32;
        fn SetEntriesInAclW(
            c_count_of_explicit_entries: u32,
            p_list_of_explicit_entries: *const ExplicitAccessW,
            old_acl: *mut c_void,
            new_acl: *mut *mut c_void,
        ) -> u32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetProcessWindowStation() -> isize;
        fn GetThreadDesktop(dw_thread_id: u32) -> isize;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThreadId() -> u32;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        fn CreatePipe(
            h_read_pipe: *mut isize,
            h_write_pipe: *mut isize,
            lp_pipe_attributes: *const SecurityAttributes,
            n_size: u32,
        ) -> i32;
        fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
        fn InitializeProcThreadAttributeList(
            lp_attribute_list: *mut c_void,
            dw_attribute_count: u32,
            dw_flags: u32,
            lp_size: *mut usize,
        ) -> i32;
        fn UpdateProcThreadAttribute(
            lp_attribute_list: *mut c_void,
            dw_flags: u32,
            attribute: usize,
            lp_value: *const c_void,
            cb_size: usize,
            lp_previous_value: *mut c_void,
            lp_return_size: *mut usize,
        ) -> i32;
        fn DeleteProcThreadAttributeList(lp_attribute_list: *mut c_void);
        fn CreateProcessW(
            lp_application_name: *const u16,
            lp_command_line: *mut u16,
            lp_process_attributes: *const c_void,
            lp_thread_attributes: *const c_void,
            b_inherit_handles: i32,
            dw_creation_flags: u32,
            lp_environment: *const c_void,
            lp_current_directory: *const u16,
            lp_startup_info: *const StartupInfoExW,
            lp_process_information: *mut ProcessInformation,
        ) -> i32;
        fn ReadFile(
            h_file: isize,
            lp_buffer: *mut u8,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn WaitForSingleObject(h_handle: isize, dw_milliseconds: u32) -> u32;
        fn GetExitCodeProcess(h_process: isize, lp_exit_code: *mut u32) -> i32;
        fn CloseHandle(h_object: isize) -> i32;
    }

    fn wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn quote_windows_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
            return arg.to_string();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0usize;
        for ch in arg.chars() {
            if ch == '\\' {
                backslashes += 1;
            } else if ch == '"' {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            } else {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(ch);
            }
        }
        for _ in 0..(backslashes * 2) {
            out.push('\\');
        }
        out.push('"');
        out
    }

    fn build_windows_cmdline(bin: &str, args: &[String]) -> Vec<u16> {
        let mut cmd = quote_windows_arg(bin);
        for arg in args {
            cmd.push(' ');
            cmd.push_str(&quote_windows_arg(arg));
        }
        wide_nul(&cmd)
    }

    fn build_windows_env_block(
        env_map: &BTreeMap<String, (String, Zeroizing<String>)>,
    ) -> Zeroizing<Vec<u16>> {
        let mut entries = env_map.clone();
        if !entries.contains_key("SYSTEMROOT") {
            let sr = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            entries.insert(
                "SYSTEMROOT".to_string(),
                ("SystemRoot".to_string(), Zeroizing::new(sr)),
            );
        }
        if !entries.contains_key("COMSPEC") {
            let cs = std::env::var("COMSPEC")
                .unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".to_string());
            entries.insert(
                "COMSPEC".to_string(),
                ("COMSPEC".to_string(), Zeroizing::new(cs)),
            );
        }
        if !entries.contains_key("LOCALAPPDATA") {
            if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
                entries.insert(
                    "LOCALAPPDATA".to_string(),
                    ("LOCALAPPDATA".to_string(), Zeroizing::new(local_app)),
                );
            }
        }
        let mut block: Vec<u16> = Vec::new();
        for (_upper, (k, v)) in entries {
            block.extend(k.encode_utf16());
            block.push('=' as u16);
            block.extend(v.as_str().encode_utf16());
            block.push(0);
        }
        block.push(0);
        Zeroizing::new(block)
    }

    pub(crate) struct AppContainerContext {
        sid: *mut c_void,
        caps: SecurityCapabilities,
    }

    impl Drop for AppContainerContext {
        fn drop(&mut self) {
            if !self.sid.is_null() {
                unsafe {
                    FreeSid(self.sid);
                }
                self.sid = std::ptr::null_mut();
            }
        }
    }

    impl AppContainerContext {
        pub fn new() -> Result<Self> {
            let name = wide_nul("ciphervault.no-net.v1");
            let display = wide_nul("CipherVault No-Net Sandbox");
            let desc = wide_nul("Zero-capability network-isolated execution container");
            let mut psid: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                CreateAppContainerProfile(
                    name.as_ptr(),
                    display.as_ptr(),
                    desc.as_ptr(),
                    std::ptr::null(),
                    0,
                    &mut psid,
                )
            };
            if hr == E_ALREADY_EXISTS || (hr < 0 && psid.is_null()) {
                let hr_derive = unsafe {
                    DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut psid)
                };
                if hr_derive < 0 || psid.is_null() {
                    bail!(
                        "--no-net Windows AppContainer setup failed (CreateAppContainerProfile=0x{:08X}, Derive=0x{:08X})",
                        hr as u32,
                        hr_derive as u32
                    );
                }
            }
            Ok(Self {
                sid: psid,
                caps: SecurityCapabilities {
                    app_container_sid: psid,
                    capabilities: std::ptr::null_mut(),
                    capability_count: 0,
                    reserved: 0,
                },
            })
        }

        /// Grants `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) access to this
        /// process's in-memory WindowStation and Desktop so `user32.dll!DllMain`
        /// initializes cleanly in zero-capability AppContainers (no disk ACL changes).
        pub fn ensure_winsta_desktop_access(&self) -> Result<()> {
            static WINSTA_READY: OnceLock<std::result::Result<(), String>> = OnceLock::new();
            let res = WINSTA_READY.get_or_init(|| {
                let sid_str = wide_nul("S-1-15-2-1");
                let mut ac_sid: *mut c_void = std::ptr::null_mut();
                let ok = unsafe { ConvertStringSidToSidW(sid_str.as_ptr(), &mut ac_sid) };
                if ok == 0 || ac_sid.is_null() {
                    return Err("ConvertStringSidToSidW(S-1-15-2-1) failed".to_string());
                }
                let ea = ExplicitAccessW {
                    grf_access_permissions: GENERIC_ALL,
                    grf_access_mode: GRANT_ACCESS,
                    grf_inheritance: NO_INHERITANCE,
                    trustee: TrusteeW {
                        p_multiple_trustee: std::ptr::null_mut(),
                        multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
                        trustee_form: TRUSTEE_IS_SID,
                        trustee_type: TRUSTEE_IS_WELL_KNOWN_GROUP,
                        ptstr_name: ac_sid,
                    },
                };
                let hwinsta = unsafe { GetProcessWindowStation() };
                let hdesk = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
                let mut err_msg: Option<String> = None;
                for (label, handle) in [("WindowStation", hwinsta), ("Desktop", hdesk)] {
                    if handle == 0 {
                        continue;
                    }
                    let mut old_dacl: *mut c_void = std::ptr::null_mut();
                    let mut sd: *mut c_void = std::ptr::null_mut();
                    let rc_get = unsafe {
                        GetSecurityInfo(
                            handle,
                            SE_WINDOW_OBJECT,
                            DACL_SECURITY_INFORMATION,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            &mut old_dacl,
                            std::ptr::null_mut(),
                            &mut sd,
                        )
                    };
                    if rc_get == 0 {
                        let mut new_dacl: *mut c_void = std::ptr::null_mut();
                        let rc_acl = unsafe { SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl) };
                        if rc_acl == 0 && !new_dacl.is_null() {
                            let rc_set = unsafe {
                                SetSecurityInfo(
                                    handle,
                                    SE_WINDOW_OBJECT,
                                    DACL_SECURITY_INFORMATION,
                                    std::ptr::null_mut(),
                                    std::ptr::null_mut(),
                                    new_dacl,
                                    std::ptr::null_mut(),
                                )
                            };
                            if rc_set != 0 {
                                err_msg = Some(format!(
                                    "SetSecurityInfo({label}) failed with code {rc_set}"
                                ));
                            }
                            unsafe {
                                LocalFree(new_dacl);
                            }
                        } else {
                            err_msg = Some(format!(
                                "SetEntriesInAclW({label}) failed with code {rc_acl}"
                            ));
                        }
                        if !sd.is_null() {
                            unsafe {
                                LocalFree(sd);
                            }
                        }
                    }
                }
                unsafe {
                    LocalFree(ac_sid);
                }
                match err_msg {
                    Some(msg) => Err(msg),
                    None => Ok(()),
                }
            });
            if let Err(e) = res {
                bail!("--no-net WindowStation setup failed: {e}");
            }
            Ok(())
        }

        pub fn execute(
            &self,
            bin: &str,
            args: &[String],
            env_map: &BTreeMap<String, (String, Zeroizing<String>)>,
            stream_to_stdio: bool,
        ) -> Result<(u32, Vec<u8>, Vec<u8>)> {
            let sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: std::ptr::null_mut(),
                b_inherit_handle: 1,
            };

            let (mut in_read, mut in_write): (isize, isize) = (0, 0);
            let (mut out_read, mut out_write): (isize, isize) = (0, 0);
            let (mut err_read, mut err_write): (isize, isize) = (0, 0);
            if unsafe { CreatePipe(&mut in_read, &mut in_write, &sa, 0) } == 0
                || unsafe { CreatePipe(&mut out_read, &mut out_write, &sa, 0) } == 0
                || unsafe { CreatePipe(&mut err_read, &mut err_write, &sa, 0) } == 0
            {
                for h in [in_read, in_write, out_read, out_write, err_read, err_write] {
                    if h != 0 {
                        unsafe { CloseHandle(h) };
                    }
                }
                bail!("--no-net CreatePipe failed while preparing sandboxed stdio");
            }
            unsafe {
                SetHandleInformation(in_write as *mut c_void, HANDLE_FLAG_INHERIT, 0);
                SetHandleInformation(out_read as *mut c_void, HANDLE_FLAG_INHERIT, 0);
                SetHandleInformation(err_read as *mut c_void, HANDLE_FLAG_INHERIT, 0);
                CloseHandle(in_write);
            }

            let mut attr_size: usize = 0;
            unsafe {
                InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
            }
            let mut attr_buf = vec![0u8; attr_size.max(64)];
            let attr_ptr = attr_buf.as_mut_ptr() as *mut c_void;
            if unsafe { InitializeProcThreadAttributeList(attr_ptr, 1, 0, &mut attr_size) } == 0 {
                unsafe {
                    CloseHandle(in_read);
                    CloseHandle(out_read);
                    CloseHandle(out_write);
                    CloseHandle(err_read);
                    CloseHandle(err_write);
                }
                bail!("--no-net InitializeProcThreadAttributeList failed");
            }

            let ok_attr = unsafe {
                UpdateProcThreadAttribute(
                    attr_ptr,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    (&self.caps as *const SecurityCapabilities) as *const c_void,
                    std::mem::size_of::<SecurityCapabilities>(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok_attr == 0 {
                unsafe {
                    DeleteProcThreadAttributeList(attr_ptr);
                    CloseHandle(in_read);
                    CloseHandle(out_read);
                    CloseHandle(out_write);
                    CloseHandle(err_read);
                    CloseHandle(err_write);
                }
                bail!("--no-net UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed");
            }

            let si_ex = StartupInfoExW {
                startup_info: StartupInfoW {
                    cb: std::mem::size_of::<StartupInfoExW>() as u32,
                    lp_reserved: std::ptr::null_mut(),
                    lp_desktop: std::ptr::null_mut(),
                    lp_title: std::ptr::null_mut(),
                    dw_x: 0,
                    dw_y: 0,
                    dw_x_size: 0,
                    dw_y_size: 0,
                    dw_x_count_chars: 0,
                    dw_y_count_chars: 0,
                    dw_fill_attribute: 0,
                    dw_flags: STARTF_USESTDHANDLES,
                    w_show_window: 0,
                    cb_reserved2: 0,
                    lp_reserved2: std::ptr::null_mut(),
                    h_std_input: in_read,
                    h_std_output: out_write,
                    h_std_error: err_write,
                },
                lp_attribute_list: attr_ptr,
            };

            let mut pi = ProcessInformation {
                h_process: 0,
                h_thread: 0,
                dw_process_id: 0,
                dw_thread_id: 0,
            };

            let mut cmd_line = build_windows_cmdline(bin, args);
            let env_block = build_windows_env_block(env_map);
            let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
            let created = unsafe {
                CreateProcessW(
                    std::ptr::null(),
                    cmd_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1,
                    flags,
                    env_block.as_ptr() as *const c_void,
                    std::ptr::null(),
                    &si_ex,
                    &mut pi,
                )
            };
            drop(env_block);

            unsafe {
                DeleteProcThreadAttributeList(attr_ptr);
                CloseHandle(in_read);
                CloseHandle(out_write);
                CloseHandle(err_write);
            }

            if created == 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    CloseHandle(out_read);
                    CloseHandle(err_read);
                }
                return Err(err).with_context(|| {
                    format!("--no-net CreateProcessW failed for command '{bin}'")
                });
            }

            fn read_pipe(handle: isize, is_stderr: bool, stream_to_stdio: bool) -> Vec<u8> {
                let mut acc = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let mut read_bytes: u32 = 0;
                    let ok = unsafe {
                        ReadFile(
                            handle,
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                            &mut read_bytes,
                            std::ptr::null_mut(),
                        )
                    };
                    if ok == 0 || read_bytes == 0 {
                        break;
                    }
                    let slice = &buf[..read_bytes as usize];
                    if stream_to_stdio {
                        if is_stderr {
                            let _ = std::io::stderr().write_all(slice);
                            let _ = std::io::stderr().flush();
                        } else {
                            let _ = std::io::stdout().write_all(slice);
                            let _ = std::io::stdout().flush();
                        }
                    } else {
                        acc.extend_from_slice(slice);
                    }
                }
                unsafe {
                    CloseHandle(handle);
                }
                acc
            }

            let t_out = std::thread::spawn(move || read_pipe(out_read, false, stream_to_stdio));
            let t_err = std::thread::spawn(move || read_pipe(err_read, true, stream_to_stdio));

            unsafe {
                WaitForSingleObject(pi.h_process, INFINITE);
            }
            let mut exit_code: u32 = 1;
            unsafe {
                GetExitCodeProcess(pi.h_process, &mut exit_code);
                CloseHandle(pi.h_process);
                CloseHandle(pi.h_thread);
            }

            let stdout_buf = t_out.join().unwrap_or_default();
            let stderr_buf = t_err.join().unwrap_or_default();
            Ok((exit_code, stdout_buf, stderr_buf))
        }

        pub fn preflight(&self) -> Result<()> {
            let mut env_map = BTreeMap::new();
            let sr = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            env_map.insert(
                "SYSTEMROOT".to_string(),
                ("SystemRoot".to_string(), Zeroizing::new(sr)),
            );
            let args = vec!["/c".to_string(), "exit".to_string(), "0".to_string()];
            let (code, _, _) = self
                .execute("C:\\Windows\\System32\\cmd.exe", &args, &env_map, false)
                .context("--no-net AppContainer preflight could not launch cmd.exe")?;
            if code != 0 {
                bail!("--no-net AppContainer preflight exited with code 0x{code:08X}");
            }
            Ok(())
        }
    }

    fn is_windows_system_path(path: &Path) -> bool {
        let lower = path.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
        lower.contains("\\windows\\system32\\")
            || lower.contains("\\windows\\syswow64\\")
            || lower.eq_ignore_ascii_case("cmd.exe")
    }

    fn grant_appcontainer_rx(path: &Path, is_dir: bool) {
        if is_windows_system_path(path) {
            return;
        }
        let mut cmd = std::process::Command::new("C:\\Windows\\System32\\icacls.exe");
        cmd.arg(path).arg("/grant");
        if is_dir {
            if let Ok(user) = std::env::var("USERNAME") {
                if !user.trim().is_empty() {
                    cmd.arg(format!("{user}:(OI)(CI)(F)"));
                }
            }
            cmd.arg("*S-1-15-2-1:(OI)(CI)(RX)");
        } else {
            if let Ok(user) = std::env::var("USERNAME") {
                if !user.trim().is_empty() {
                    cmd.arg(format!("{user}:(F)"));
                }
            }
            cmd.arg("*S-1-15-2-1:(RX)");
        }
        let _ = cmd
            .arg("/Q")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }

    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    /// Packs Python's standard library (`Lib/` excluding `site-packages`, `test`,
    /// UI toolkits, and `__pycache__`) into an uncompressed STORED zip archive so
    /// CPython's built-in zipimport resolves stdlib inside the staged cache dir.
    fn write_python_stdlib_zip(lib_dir: &Path, zip_dest: &Path) -> Result<()> {
        let skip_dirs = [
            "site-packages",
            "test",
            "idlelib",
            "tkinter",
            "turtledemo",
            "pydoc_data",
            "ensurepip",
            "__pycache__",
        ];
        struct CentralEntry {
            name: Vec<u8>,
            crc: u32,
            size: u32,
            offset: u32,
        }
        let mut file = std::fs::File::create(zip_dest)
            .with_context(|| format!("create {}", zip_dest.display()))?;
        let mut central = Vec::new();
        let mut offset: u32 = 0;
        let walker = WalkDir::new(lib_dir).into_iter().filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                return !skip_dirs.iter().any(|skip| name.eq_ignore_ascii_case(skip));
            }
            true
        });
        for entry in walker.filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("py") {
                continue;
            }
            let Ok(rel) = path.strip_prefix(lib_dir) else {
                continue;
            };
            let rel_name = rel.to_string_lossy().replace('\\', "/");
            let name_bytes = rel_name.as_bytes();
            let data = std::fs::read(path)?;
            if data.len() > u32::MAX as usize || name_bytes.len() > u16::MAX as usize {
                continue;
            }
            let size = data.len() as u32;
            let crc = crc32_ieee(&data);

            // Local file header (30 bytes + name)
            let mut lfh = Vec::with_capacity(30 + name_bytes.len());
            lfh.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
            lfh.extend_from_slice(&20u16.to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(&crc.to_le_bytes());
            lfh.extend_from_slice(&size.to_le_bytes());
            lfh.extend_from_slice(&size.to_le_bytes());
            lfh.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(name_bytes);
            file.write_all(&lfh)?;
            file.write_all(&data)?;

            central.push(CentralEntry {
                name: name_bytes.to_vec(),
                crc,
                size,
                offset,
            });
            offset = offset
                .checked_add(lfh.len() as u32 + size)
                .context("stdlib zip exceeded 4 GiB limit")?;
        }

        let cd_offset = offset;
        let mut cd_size: u32 = 0;
        for c in &central {
            let mut cdfh = Vec::with_capacity(46 + c.name.len());
            cdfh.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
            cdfh.extend_from_slice(&20u16.to_le_bytes());
            cdfh.extend_from_slice(&20u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&c.crc.to_le_bytes());
            cdfh.extend_from_slice(&c.size.to_le_bytes());
            cdfh.extend_from_slice(&c.size.to_le_bytes());
            cdfh.extend_from_slice(&(c.name.len() as u16).to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u32.to_le_bytes());
            cdfh.extend_from_slice(&c.offset.to_le_bytes());
            cdfh.extend_from_slice(&c.name);
            file.write_all(&cdfh)?;
            cd_size += cdfh.len() as u32;
        }
        let count = central.len() as u16;
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&cd_size.to_le_bytes());
        eocd.extend_from_slice(&cd_offset.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        file.write_all(&eocd)?;
        file.sync_all()?;
        Ok(())
    }

    fn stage_runtime_executable(exe_path: &Path) -> Result<String> {
        if is_windows_system_path(exe_path) || !exe_path.is_file() {
            return Ok(exe_path.to_string_lossy().to_string());
        }
        let canonical = std::fs::canonicalize(exe_path).unwrap_or_else(|_| exe_path.to_path_buf());
        let meta = std::fs::metadata(&canonical)?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut hasher = Sha256::new();
        hasher.update(b"cv-ac-v2:");
        hasher.update(canonical.to_string_lossy().as_bytes());
        hasher.update(meta.len().to_le_bytes());
        hasher.update(mtime.to_le_bytes());
        let cache_id = &hex::encode(hasher.finalize())[..16];

        let cache_root = std::env::temp_dir().join("ciphervault-ac-cache");
        let _ = std::fs::create_dir_all(&cache_root);
        grant_appcontainer_rx(&cache_root, true);
        let cache_dir = cache_root.join(cache_id);
        let file_name = canonical
            .file_name()
            .context("executable has no filename")?;
        let staged_exe = cache_dir.join(file_name);

        if staged_exe.is_file() {
            return Ok(staged_exe.to_string_lossy().to_string());
        }

        let tmp_dir = cache_root.join(format!("{cache_id}.tmp.{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir)?;
        grant_appcontainer_rx(&tmp_dir, true);

        let parent = canonical.parent().context("executable has no parent dir")?;
        std::fs::copy(&canonical, tmp_dir.join(file_name))?;
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                        if ext.eq_ignore_ascii_case("dll") {
                            if let Some(fname) = p.file_name() {
                                let _ = std::fs::copy(&p, tmp_dir.join(fname));
                            }
                        }
                    }
                }
            }
        }

        // Python runtime support: stage DLLs/*.pyd + *.dll and pack Lib/ into python3XX.zip.
        let lib_dir = parent.join("Lib");
        let dlls_dir = parent.join("DLLs");
        if lib_dir.is_dir() && dlls_dir.is_dir() {
            let staged_dlls = tmp_dir.join("DLLs");
            let _ = std::fs::create_dir_all(&staged_dlls);
            if let Ok(entries) = std::fs::read_dir(&dlls_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let p = entry.path();
                    if p.is_file() {
                        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                            if ext.eq_ignore_ascii_case("pyd") || ext.eq_ignore_ascii_case("dll") {
                                if let Some(fname) = p.file_name() {
                                    let _ = std::fs::copy(&p, staged_dlls.join(fname));
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let fname = entry.file_name().to_string_lossy().to_ascii_lowercase();
                    if fname.starts_with("python3") && fname.ends_with(".dll") {
                        let stem = fname.trim_end_matches(".dll");
                        let zip_name = format!("{stem}.zip");
                        if !tmp_dir.join(&zip_name).exists() {
                            let _ = write_python_stdlib_zip(&lib_dir, &tmp_dir.join(&zip_name));
                        }
                    }
                }
            }
        }

        grant_appcontainer_rx(&tmp_dir, true);
        if std::fs::rename(&tmp_dir, &cache_dir).is_err() && !staged_exe.is_file() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            bail!(
                "Failed to populate AppContainer runtime cache for {}",
                exe_path.display()
            );
        }
        grant_appcontainer_rx(&cache_dir, true);
        Ok(staged_exe.to_string_lossy().to_string())
    }

    pub(crate) fn prepare_command(
        resolved_bin: &str,
        resolved_prefix: &[String],
        raw_args: &[String],
    ) -> Result<(String, Vec<String>)> {
        let staged_bin = stage_runtime_executable(Path::new(resolved_bin))?;
        let mut combined = resolved_prefix.to_vec();
        // Grant AppContainer read access to existing script/batch files in prefix/args
        // and temp working directories so temp-dir scripts and .cmd shims run cleanly.
        if let Ok(cwd) = std::env::current_dir() {
            let temp_root = std::env::temp_dir();
            if cwd.starts_with(&temp_root) {
                grant_appcontainer_rx(&cwd, true);
            }
        }
        for arg in resolved_prefix.iter().chain(raw_args.iter()) {
            if !arg.starts_with('-') && arg.len() <= 512 {
                let p = Path::new(arg);
                if p.is_file() && !is_windows_system_path(p) {
                    grant_appcontainer_rx(p, false);
                }
            }
        }
        let stem = Path::new(&staged_bin)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if (stem == "node" || stem == "node.exe")
            && !raw_args.iter().any(|a| a == "--preserve-symlinks-main")
        {
            combined.push("--preserve-symlinks-main".to_string());
        }
        combined.extend(raw_args.iter().cloned());
        Ok((staged_bin, combined))
    }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "windows")))]
fn apply_no_net_sandbox(
    _resolved_bin: &str,
    _resolved_prefix: &[String],
    _raw_args: &[String],
) -> Result<(String, Vec<String>)> {
    bail!(
        "--no-net network sandboxing is not supported without unprivileged network namespaces on this OS \
         (supported on Linux via `unshare`, macOS via `sandbox-exec`, and Windows via AppContainer). Refusing to run with unrestricted network access."
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WorkspacePolicy {
    pub(crate) sealed_mode: bool,
    pub(crate) default_no_net: Option<bool>,
    pub(crate) profiles: BTreeMap<String, RunProfile>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RunProfile {
    pub(crate) commands: Vec<String>,
    pub(crate) allow_keys: Vec<String>,
    pub(crate) no_net: Option<bool>,
    pub(crate) proxy: Option<bool>,
    pub(crate) upstreams: BTreeMap<String, String>,
}

pub(crate) fn load_workspace_policy(vault_dir: &Path) -> Result<Option<WorkspacePolicy>> {
    let policy_path = vault_dir.join("policy.toml");
    let raw = match std::fs::read_to_string(&policy_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| {
                format!("Failed to read workspace policy '{}'", policy_path.display())
            })
        }
    };
    let parsed = parse_workspace_policy(&raw).with_context(|| {
        format!(
            "Failed to parse workspace policy '{}'",
            policy_path.display()
        )
    })?;
    Ok(Some(parsed))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicySection {
    Vault,
    Profile(String),
    ProfileUpstreams(String),
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '#' => return &line[..idx],
                _ => {}
            }
        }
    }
    line
}

fn delimiter_balance(s: &str) -> Result<(i32, i32)> {
    let mut brackets = 0i32;
    let mut braces = 0i32;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for ch in s.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '[' => brackets += 1,
                ']' => brackets -= 1,
                '{' => braces += 1,
                '}' => braces -= 1,
                _ => {}
            }
        }
    }
    if in_double || in_single {
        bail!("unterminated string literal");
    }
    if brackets < 0 || braces < 0 {
        bail!("unexpected closing delimiter");
    }
    Ok((brackets, braces))
}

fn parse_toml_string(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => bail!("unsupported escape '\\{other}' in string"),
                    None => bail!("trailing backslash in string"),
                }
            } else {
                out.push(ch);
            }
        }
        return Ok(out);
    }
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        return Ok(s[1..s.len() - 1].to_string());
    }
    bail!("expected quoted string, got '{s}'")
}

fn parse_toml_bool(raw: &str) -> Result<bool> {
    match raw.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => bail!("expected boolean (true/false), got '{other}'"),
    }
}

fn split_top_level_commas(inner: &str) -> Result<Vec<String>> {
    let mut items = Vec::new();
    let mut start = 0usize;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut depth = 0i32;

    for (idx, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    let item = inner[start..idx].trim();
                    if !item.is_empty() {
                        items.push(item.to_string());
                    }
                    start = idx + 1;
                }
                _ => {}
            }
        }
    }
    let tail = inner[start..].trim();
    if !tail.is_empty() {
        items.push(tail.to_string());
    }
    Ok(items)
}

fn parse_toml_string_array(raw: &str) -> Result<Vec<String>> {
    let s = raw.trim();
    if !s.starts_with('[') || !s.ends_with(']') {
        bail!("expected array '[...]', got '{s}'");
    }
    let inner = s[1..s.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let items = split_top_level_commas(inner)?;
    items.into_iter().map(|item| parse_toml_string(&item)).collect()
}

fn split_key_value(line: &str) -> Result<(&str, &str)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '=' => return Ok((line[..idx].trim(), line[idx + 1..].trim())),
                _ => {}
            }
        }
    }
    bail!("expected 'key = value', got '{line}'")
}

fn parse_toml_key(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("empty key");
    }
    if s.starts_with('"') || s.starts_with('\'') {
        return parse_toml_string(s);
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Ok(s.to_string());
    }
    bail!("invalid key '{s}'")
}

fn parse_toml_inline_string_table(raw: &str) -> Result<BTreeMap<String, String>> {
    let s = raw.trim();
    if !s.starts_with('{') || !s.ends_with('}') {
        bail!("expected inline table '{{...}}', got '{s}'");
    }
    let inner = s[1..s.len() - 1].trim();
    let mut map = BTreeMap::new();
    if inner.is_empty() {
        return Ok(map);
    }
    for entry in split_top_level_commas(inner)? {
        let (k_raw, v_raw) = split_key_value(&entry)?;
        let key = parse_toml_key(k_raw)?;
        let val = parse_toml_string(v_raw)?;
        map.insert(key, val);
    }
    Ok(map)
}

fn parse_section_header(header: &str) -> Result<PolicySection> {
    let inner = header
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
        .context("malformed section header")?;
    if inner == "vault" {
        return Ok(PolicySection::Vault);
    }
    if let Some(rest) = inner.strip_prefix("profiles.") {
        let rest = rest.trim();
        if let Some(name_part) = rest.strip_suffix(".upstreams") {
            let name = parse_toml_key(name_part.trim())?;
            return Ok(PolicySection::ProfileUpstreams(name));
        }
        let name = parse_toml_key(rest)?;
        return Ok(PolicySection::Profile(name));
    }
    bail!("unknown policy section '[{inner}]'")
}

fn parse_workspace_policy(raw: &str) -> Result<WorkspacePolicy> {
    let mut policy = WorkspacePolicy::default();
    let mut current_section: Option<PolicySection> = None;
    let mut pending_stmt = String::new();
    let mut pending_start_line = 0usize;

    let mut logical_statements: Vec<(usize, String)> = Vec::new();
    for (idx, raw_line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let clean = strip_toml_comment(raw_line).trim();
        if clean.is_empty() && pending_stmt.is_empty() {
            continue;
        }
        if pending_stmt.is_empty() {
            pending_start_line = line_no;
            pending_stmt.push_str(clean);
        } else if !clean.is_empty() {
            pending_stmt.push(' ');
            pending_stmt.push_str(clean);
        }
        let (brackets, braces) = delimiter_balance(&pending_stmt)
            .with_context(|| format!("line {pending_start_line}"))?;
        if brackets == 0 && braces == 0 {
            let stmt = std::mem::take(&mut pending_stmt);
            logical_statements.push((pending_start_line, stmt));
        }
    }
    if !pending_stmt.is_empty() {
        bail!("line {pending_start_line}: unclosed '[' or '{{' in policy.toml");
    }

    for (line_no, stmt) in logical_statements {
        if stmt.starts_with('[') && stmt.ends_with(']') {
            let section =
                parse_section_header(&stmt).with_context(|| format!("line {line_no}"))?;
            match &section {
                PolicySection::Profile(name) | PolicySection::ProfileUpstreams(name) => {
                    policy.profiles.entry(name.clone()).or_default();
                }
                PolicySection::Vault => {}
            }
            current_section = Some(section);
            continue;
        }

        let section = current_section
            .as_ref()
            .with_context(|| format!("line {line_no}: key-value pair outside any [section]"))?;
        let (k_raw, v_raw) = split_key_value(&stmt).with_context(|| format!("line {line_no}"))?;
        let key = parse_toml_key(k_raw).with_context(|| format!("line {line_no}"))?;

        match section {
            PolicySection::Vault => match key.as_str() {
                "sealed_mode" => {
                    policy.sealed_mode =
                        parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?;
                }
                "default_no_net" => {
                    policy.default_no_net =
                        Some(parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?);
                }
                other => bail!("line {line_no}: unknown [vault] key '{other}'"),
            },
            PolicySection::Profile(name) => {
                let profile = policy.profiles.entry(name.clone()).or_default();
                match key.as_str() {
                    "commands" => {
                        profile.commands = parse_toml_string_array(v_raw)
                            .with_context(|| format!("line {line_no}"))?;
                    }
                    "allow_keys" => {
                        profile.allow_keys = parse_toml_string_array(v_raw)
                            .with_context(|| format!("line {line_no}"))?;
                    }
                    "no_net" => {
                        profile.no_net = Some(
                            parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?,
                        );
                    }
                    "proxy" => {
                        profile.proxy = Some(
                            parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?,
                        );
                    }
                    "upstreams" => {
                        let parsed = parse_toml_inline_string_table(v_raw)
                            .with_context(|| format!("line {line_no}"))?;
                        profile.upstreams.extend(parsed);
                    }
                    other => bail!("line {line_no}: unknown [profiles.{name}] key '{other}'"),
                }
            }
            PolicySection::ProfileUpstreams(name) => {
                let profile = policy.profiles.entry(name.clone()).or_default();
                let val = parse_toml_string(v_raw).with_context(|| format!("line {line_no}"))?;
                profile.upstreams.insert(key, val);
            }
        }
    }

    Ok(policy)
}

fn command_matches_allowlist(cmd0: &str, allowed_commands: &[String]) -> bool {
    let cmd_trimmed = cmd0.trim();
    if cmd_trimmed.is_empty() {
        return false;
    }
    let basename = Path::new(cmd_trimmed)
        .file_name()
        .and_then(|s| s.to_str());

    allowed_commands.iter().any(|entry| {
        let allowed = entry.trim();
        if allowed.is_empty() {
            return false;
        }
        if allowed.contains('/') || allowed.contains('\\') {
            return cmd_trimmed == allowed || Path::new(cmd_trimmed) == Path::new(allowed);
        }
        if cmd_trimmed == allowed || basename == Some(allowed) {
            return true;
        }
        #[cfg(target_os = "windows")]
        if !allowed.to_ascii_lowercase().ends_with(".exe") {
            let exe_name = format!("{allowed}.exe");
            if basename.is_some_and(|b| b.eq_ignore_ascii_case(&exe_name)) {
                return true;
            }
        }
        false
    })
}

fn enforce_profile_command_allowlist(
    command: &[String],
    profile_name: &str,
    allowed_commands: &[String],
) -> Result<()> {
    if allowed_commands.is_empty() || command.is_empty() {
        return Ok(());
    }
    if !command_matches_allowlist(&command[0], allowed_commands) {
        bail!(
            "Command '{}' is not permitted by profile '{}' (allowed: {})",
            command[0],
            profile_name,
            allowed_commands.join(", ")
        );
    }
    Ok(())
}

fn merge_profile_allow_keys(
    caller: Option<Vec<String>>,
    profile_keys: &[String],
    profile_name: &str,
) -> Result<Option<Vec<String>>> {
    if profile_keys.is_empty() {
        return Ok(caller);
    }
    let profile_set: BTreeSet<String> = profile_keys
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if profile_set.is_empty() {
        bail!("Profile '{profile_name}' has an empty allow_keys list");
    }
    match caller {
        Some(caller_vec) => {
            let caller_set = normalize_allow_keys(Some(&caller_vec))?
                .expect("normalize_allow_keys returns Some for Some input");
            let intersected: Vec<String> = caller_set
                .intersection(&profile_set)
                .cloned()
                .collect();
            if intersected.is_empty() {
                bail!(
                    "--allow-keys has no keys permitted by profile '{profile_name}'"
                );
            }
            Ok(Some(intersected))
        }
        None => Ok(Some(profile_set.into_iter().collect())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_keys_filters_and_rejects_missing_or_empty() {
        let mut vars = vec![
            ("PORT".to_string(), Zeroizing::new("8080".to_string())),
            (
                "DB_PASS".to_string(),
                Zeroizing::new("val_db_99".to_string()),
            ),
            (
                "PROD_KEY".to_string(),
                Zeroizing::new("val_prod_88".to_string()),
            ),
        ];
        filter_loaded_vars_by_allow_keys(&mut vars, Some(&["PORT".to_string()])).unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].0, "PORT");

        let mut vars2 = vec![("PORT".to_string(), Zeroizing::new("8080".to_string()))];
        let err = filter_loaded_vars_by_allow_keys(&mut vars2, Some(&["MISSING".to_string()]))
            .unwrap_err();
        assert!(err.to_string().contains("MISSING"));
        assert!(vars2.is_empty());

        let empty_err = normalize_allow_keys(Some(&["  ".to_string()])).unwrap_err();
        assert!(empty_err.to_string().contains("at least one"));
    }

    #[test]
    fn no_net_sandbox_fails_closed_when_unsupported() {
        #[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "windows")))]
        {
            let err = apply_no_net_sandbox("echo", &[], &["hi".to_string()]).unwrap_err();
            assert!(err.to_string().contains("--no-net"));
        }
        #[cfg(target_os = "windows")]
        {
            let ctx = windows_no_net::AppContainerContext::new().unwrap();
            ctx.ensure_winsta_desktop_access().unwrap();
            ctx.preflight().unwrap();

            // 1. Child executes cleanly inside AppContainer and receives injected env.
            let mut env_map = std::collections::BTreeMap::new();
            let sr = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            env_map.insert(
                "SYSTEMROOT".to_string(),
                ("SystemRoot".to_string(), Zeroizing::new(sr)),
            );
            env_map.insert(
                "CV_TEST_VAR".to_string(),
                ("CV_TEST_VAR".to_string(), Zeroizing::new("val123".to_string())),
            );
            let ok_args = vec!["/c".to_string(), "echo SANDBOX_OK_%CV_TEST_VAR%".to_string()];
            let (ok_code, ok_out, _) = ctx
                .execute("C:\\Windows\\System32\\cmd.exe", &ok_args, &env_map, false)
                .unwrap();
            assert_eq!(ok_code, 0);
            let stdout = String::from_utf8_lossy(&ok_out);
            assert!(stdout.contains("SANDBOX_OK_val123"), "stdout was: {stdout}");

            // 2. Outbound network connection is blocked by zero-capability AppContainer.
            let net_args = vec![
                "-s".to_string(),
                "--max-time".to_string(),
                "2".to_string(),
                "http://1.1.1.1".to_string(),
            ];
            let (net_code, _, _) = ctx
                .execute("C:\\Windows\\System32\\curl.exe", &net_args, &env_map, false)
                .unwrap();
            assert_ne!(net_code, 0, "outbound network should fail inside AppContainer");
        }
        #[cfg(target_vendor = "apple")]
        {
            if std::path::Path::new("/usr/bin/sandbox-exec").exists() {
                if let Ok((bin, args)) =
                    apply_no_net_sandbox("/usr/bin/true", &[], &["arg1".to_string()])
                {
                    assert_eq!(bin, "/usr/bin/sandbox-exec");
                    assert!(args.iter().any(|a| a.contains("network-outbound")));
                    assert_eq!(args.last().map(String::as_str), Some("arg1"));
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok((bin, args)) = apply_no_net_sandbox("true", &[], &["arg1".to_string()]) {
                assert_eq!(bin, "unshare");
                assert!(args.contains(&"--net".to_string()) || args.contains(&"-n".to_string()));
                assert_eq!(args.last().map(String::as_str), Some("arg1"));
            }
        }
    }

    #[test]
    fn windows_appcontainer_json_attaches_dll_hint_on_status_codes() {
        for code in [-1073741515i32, -1073741502i32] {
            let mut payload = serde_json::json!({
                "status": "failed",
                "exit_code": code,
                "no_net": true,
            });
            attach_appcontainer_hint(&mut payload, code);
            let hint = payload["appcontainer_hint"]
                .as_str()
                .expect("appcontainer_hint should be populated");
            assert!(hint.contains("S-1-15-2-1"));
            assert!(hint.contains("--proxy"));
        }

        let mut ok_payload = serde_json::json!({
            "status": "success",
            "exit_code": 0,
            "no_net": true,
        });
        attach_appcontainer_hint(&mut ok_payload, 0);
        assert!(ok_payload.get("appcontainer_hint").is_none());
    }

    #[test]
    fn workspace_policy_parses_vault_and_profiles() {
        let dir = std::env::temp_dir().join(format!("cv-policy-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load_workspace_policy(&dir).unwrap().is_none());

        let toml = r#"
# Workspace policy
[vault]
sealed_mode = true
default_no_net = true

[profiles.test]
commands = [
  "pytest",
  "python", # inline comment
]
allow_keys = ["DB_PASS", "API_KEY"]
no_net = true

[profiles.ai]
commands = ["node"]
allow_keys = ["OPENAI_API_KEY"]
proxy = true
upstreams = { OPENAI_API_KEY = "https://api.openai.com#v1" }

[profiles."staging-deploy".upstreams]
STRIPE_KEY = "https://api.stripe.com"
"#;
        std::fs::write(dir.join("policy.toml"), toml).unwrap();

        let policy = load_workspace_policy(&dir).unwrap().unwrap();
        assert!(policy.sealed_mode);
        assert_eq!(policy.default_no_net, Some(true));

        let test_prof = &policy.profiles["test"];
        assert_eq!(test_prof.commands, vec!["pytest", "python"]);
        assert_eq!(test_prof.allow_keys, vec!["DB_PASS", "API_KEY"]);
        assert_eq!(test_prof.no_net, Some(true));
        assert_eq!(test_prof.proxy, None);
        assert!(test_prof.upstreams.is_empty());

        let ai_prof = &policy.profiles["ai"];
        assert_eq!(ai_prof.commands, vec!["node"]);
        assert_eq!(ai_prof.allow_keys, vec!["OPENAI_API_KEY"]);
        assert_eq!(ai_prof.proxy, Some(true));
        assert_eq!(
            ai_prof.upstreams.get("OPENAI_API_KEY").map(String::as_str),
            Some("https://api.openai.com#v1")
        );

        let staging = &policy.profiles["staging-deploy"];
        assert_eq!(
            staging.upstreams.get("STRIPE_KEY").map(String::as_str),
            Some("https://api.stripe.com")
        );

        // Unknown keys fail closed
        std::fs::write(dir.join("policy.toml"), "[vault]\nunknown_key = true\n").unwrap();
        assert!(load_workspace_policy(&dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn profile_command_allowlist_and_allow_keys_intersection() {
        let allowed = vec!["pytest".to_string(), "/usr/bin/python3".to_string()];
        assert!(enforce_profile_command_allowlist(
            &["pytest".to_string(), "-q".to_string()],
            "test",
            &allowed
        )
        .is_ok());
        assert!(enforce_profile_command_allowlist(
            &["/venv/bin/pytest".to_string()],
            "test",
            &allowed
        )
        .is_ok());
        assert!(enforce_profile_command_allowlist(
            &["/usr/bin/python3".to_string()],
            "test",
            &allowed
        )
        .is_ok());
        // Path-qualified allowlist entry must not match an arbitrary directory's python3
        assert!(enforce_profile_command_allowlist(
            &["/tmp/evil/python3".to_string()],
            "test",
            &allowed
        )
        .is_err());
        assert!(enforce_profile_command_allowlist(
            &["curl".to_string()],
            "test",
            &allowed
        )
        .is_err());

        let profile_keys = vec!["DB_PASS".to_string(), "API_KEY".to_string()];
        // No caller allow_keys -> uses profile keys
        let merged_none = merge_profile_allow_keys(None, &profile_keys, "test")
            .unwrap()
            .unwrap();
        assert_eq!(merged_none, vec!["API_KEY", "DB_PASS"]);

        // Caller narrows -> intersection
        let narrowed = merge_profile_allow_keys(
            Some(vec!["API_KEY".to_string(), "ADMIN_TOKEN".to_string()]),
            &profile_keys,
            "test",
        )
        .unwrap()
        .unwrap();
        assert_eq!(narrowed, vec!["API_KEY"]);

        // Disjoint -> error (never widens)
        assert!(merge_profile_allow_keys(
            Some(vec!["ADMIN_TOKEN".to_string()]),
            &profile_keys,
            "test",
        )
        .is_err());
    }
}
