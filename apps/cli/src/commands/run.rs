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
#[cfg(target_os = "windows")]
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
    command: Vec<String>,
) -> Result<()> {
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
    spawn_with_env(&command, deduped_vars, no_inherit, quiet, json, &label).await
}

/// Shared child spawn: injects `vars`, honors `--no-inherit`/`--quiet`/`--json`,
/// and propagates the child exit code. `label` names the secret source.
async fn spawn_with_env(
    command: &[String],
    vars: std::collections::BTreeMap<String, Zeroizing<String>>,
    no_inherit: bool,
    quiet: bool,
    json: bool,
    label: &str,
) -> Result<()> {
    let start_time = std::time::Instant::now();
    let num_secrets = vars.len();

    // Configure Child Command
    let exe = &command[0];
    let raw_args = &command[1..];

    #[cfg(target_os = "windows")]
    let (target_bin, prefix_args) = resolve_windows_command(exe);
    #[cfg(not(target_os = "windows"))]
    let (target_bin, prefix_args): (String, Vec<String>) = (exe.clone(), Vec::new());

    let mut cmd = std::process::Command::new(&target_bin);
    if !prefix_args.is_empty() {
        cmd.args(&prefix_args);
    }
    cmd.args(raw_args);

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
        // AI Agent Bridge: capture stdout and stderr, scrub outputs via ciphervault_redact
        drop(vars);
        let output = cmd
            .output()
            .with_context(|| format!("Failed to spawn command '{}'", exe))?;
        let duration_ms = start_time.elapsed().as_millis() as u64;

        let raw_stdout = String::from_utf8_lossy(&output.stdout);
        let raw_stderr = String::from_utf8_lossy(&output.stderr);

        let redacted_stdout = ciphervault_redact::redact_text(&raw_stdout);
        let redacted_stderr = ciphervault_redact::redact_text(&raw_stderr);

        let exit_code = output.status.code().unwrap_or(1);
        let payload = serde_json::json!({
            "status": if exit_code == 0 { "success" } else { "failed" },
            "exit_code": exit_code,
            "command": command,
            "source": label,
            "secrets_injected_count": num_secrets,
            "stdout": redacted_stdout,
            "stderr": redacted_stderr,
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
fn resolve_windows_command(exe: &str) -> (String, Vec<String>) {
    let p = Path::new(exe);
    if p.extension().is_some() || exe.contains('\\') || exe.contains('/') {
        return (exe.to_string(), Vec::new());
    }

    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    let extensions: Vec<&str> = pathext.split(';').filter(|s| !s.is_empty()).collect();

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
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
