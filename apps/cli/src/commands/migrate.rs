//! Ledgered vault migration CLI (Phase 8, T-801).
//!
//! Drives vault snapshot → scoped secrets imports through the server-side
//! ledger (`migration_ledger.rs`): `plan` classifies and submits, `apply`
//! writes values through the normal secret API, `verify` readbacks and
//! flips cutover pointers, `resolve` clears quarantine, and `shred-legacy`
//! destroys the legacy vault only when every ledgered secret is disabled.
//!
//! Invariants: legacy vaults open read-only until shred; values travel only
//! inside secret create/read bodies; dry-run and plan output never include
//! values or digests (digests enable offline brute force on weak values).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::dpop::maybe_dpop;
use super::run::load_snapshot_bundle;
use super::scope::{
    api_get, checked_json, echo_scope, http_client, resolve_endpoint, resolve_scope, resolve_token,
    ResolvedScope,
};
use crate::dotenv::parse_dotenv_with_lines;
use crate::MigrateSubcommand;
use ciphervault_local_store::LocalVaultStore;

const SUBMIT_BATCH: usize = 1000;
const DEFAULT_ENV: &str = "development";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn ledger_key(migration_id: &str, path: &str, line: i64) -> String {
    sha256_hex(format!("mig-ledger-v1|{migration_id}|{path}|{line}").as_bytes())
}

fn is_env_file(relative_path: &str) -> bool {
    let normalized = relative_path.replace('\\', "/");
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
}

/// Guesses the target environment slug from a dotenv file name (§F-§2.2).
/// Returns the guess plus whether it needs owner review (ambiguous).
fn guess_env(file_name: &str, default_env: &str) -> (String, bool) {
    if file_name == ".env" {
        return (default_env.to_string(), true);
    }
    if let Some(suffix) = file_name.strip_prefix(".env.") {
        // `.env.local` is explicitly ambiguous (§F-§2.2); other suffixes map.
        return (suffix.to_string(), suffix == "local");
    }
    if let Some(stem) = file_name.strip_suffix(".env") {
        let stem = stem.trim_end_matches('.');
        if !stem.is_empty() {
            return (stem.to_string(), true);
        }
    }
    (default_env.to_string(), true)
}

/// Sanitizes a non-env file path into a valid secret name (§T-101 rules).
/// Collisions with real keys are genuine conflicts the server quarantines.
fn sanitize_file_name(relative_path: &str) -> String {
    let mut name = String::from("FILE_");
    for ch in relative_path.chars() {
        if ch.is_ascii_alphanumeric() {
            name.push(ch.to_ascii_uppercase());
        } else {
            name.push('_');
        }
    }
    name.truncate(128);
    name
}

/// One effective (layered) secret occurrence plus dropped shadowed copies.
struct Classified {
    path: String,
    line: i64,
    name: String,
    value: Vec<u8>,
    env_guess: String,
    ambiguous: bool,
    secret_type: &'static str,
}

struct Dropped {
    path: String,
    line: i64,
    name: String,
    reason: String,
}

/// Layers dotenv occurrences (last wins: `.env` < `.env.*` < `*.env`, later
/// line wins within a file) and keeps whole files whole. Shadowed values
/// were never live, so only winners submit — losers return as evidence.
fn classify_files(
    files: &[(String, Vec<u8>)],
    default_env: &str,
) -> Result<(Vec<Classified>, Vec<Dropped>)> {
    // Rank dotenv files for layering; whole files bypass layering.
    let mut ranked: Vec<(usize, &str)> = Vec::new();
    for (path, _) in files {
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
        if !is_env_file(path) {
            continue;
        }
        let rank = if name == ".env" {
            0
        } else if name.starts_with(".env.") {
            1
        } else {
            2
        };
        ranked.push((rank, path.as_str()));
    }
    ranked.sort();
    let order: BTreeMap<&str, usize> = ranked
        .iter()
        .enumerate()
        .map(|(idx, (_, path))| (*path, idx))
        .collect();

    // Group dotenv occurrences by (env guess, key); winner = last in layer order.
    type Occurrence = (usize, usize, String, i64, Vec<u8>);
    let mut groups: BTreeMap<(String, String), Vec<Occurrence>> = BTreeMap::new();
    let mut classified = Vec::new();
    let mut dropped = Vec::new();
    for (path, bytes) in files {
        if !is_env_file(path) {
            // Whole-file secret (§F-§2.2); non-UTF8 bytes cannot ride JSON
            // values, so they quarantine server-side under the raw path.
            if String::from_utf8(bytes.clone()).is_err() {
                // Raw path fails server name rules ⇒ QUARANTINED with
                // provenance. The raw bytes stay as the digest preimage so a
                // renamed entry still fails closed at apply (from_utf8),
                // never migrates as an empty value.
                classified.push(Classified {
                    path: path.clone(),
                    line: 1,
                    name: path.clone(),
                    value: bytes.clone(),
                    env_guess: default_env.to_string(),
                    ambiguous: true,
                    secret_type: "file",
                });
            } else {
                classified.push(Classified {
                    path: path.clone(),
                    line: 1,
                    name: sanitize_file_name(path),
                    value: bytes.clone(),
                    env_guess: default_env.to_string(),
                    ambiguous: true,
                    secret_type: "file",
                });
            }
            continue;
        }
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
        let (env_guess, _) = guess_env(name, default_env);
        let parsed = parse_dotenv_with_lines(bytes)
            .map_err(|err| anyhow::anyhow!("failed to parse '{path}': {err}"))?;
        for (key, value, line) in parsed {
            let rank = order.get(path.as_str()).copied().unwrap_or(usize::MAX);
            groups
                .entry((env_guess.clone(), key.clone()))
                .or_default()
                .push((rank, line, path.clone(), line as i64, value.into_bytes()));
        }
    }
    for ((env_guess, key), mut occurrences) in groups {
        occurrences.sort();
        let total = occurrences.len();
        for (idx, (_, _, path, line, value)) in occurrences.iter().enumerate() {
            if idx + 1 == total {
                let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
                let (_, ambiguous) = guess_env(name, default_env);
                classified.push(Classified {
                    path: path.clone(),
                    line: *line,
                    name: key.clone(),
                    value: value.clone(),
                    env_guess: env_guess.clone(),
                    ambiguous,
                    secret_type: "key_value",
                });
            } else {
                dropped.push(Dropped {
                    path: path.clone(),
                    line: *line,
                    name: key.clone(),
                    reason: "shadowed by a later layered occurrence (never live)".to_string(),
                });
            }
        }
    }
    // Deterministic output: winners by (env, name), dropped by (path, line).
    classified.sort_by(|a, b| {
        (&a.env_guess, &a.name, &a.path, a.line).cmp(&(&b.env_guess, &b.name, &b.path, b.line))
    });
    dropped.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
    Ok((classified, dropped))
}

struct ProjectContext {
    client: reqwest::Client,
    endpoint: String,
    token: String,
    scope: ResolvedScope,
    /// slug → (id, tier).
    envs: BTreeMap<String, (String, i64)>,
}

async fn project_context(
    project_flag: Option<&str>,
    endpoint_flag: Option<&str>,
    token_flag: Option<&str>,
) -> Result<ProjectContext> {
    let endpoint = resolve_endpoint(endpoint_flag)?;
    let token = resolve_token(token_flag)?;
    let client = http_client()?;
    let scope = resolve_scope(&client, &endpoint, &token, project_flag, None, false).await?;
    echo_scope(&scope);
    let view = api_get(
        &client,
        &endpoint,
        &token,
        &format!("/v1/projects/{}", scope.project_id),
        "project show",
    )
    .await?;
    let mut envs = BTreeMap::new();
    for env in view["environments"]
        .as_array()
        .context("server returned a malformed environment list")?
    {
        let (Some(slug), Some(id)) = (env["slug"].as_str(), env["environment_id"].as_str()) else {
            continue;
        };
        envs.insert(
            slug.to_string(),
            (id.to_string(), env["tier"].as_i64().unwrap_or(0)),
        );
    }
    Ok(ProjectContext {
        client,
        endpoint,
        token,
        scope,
        envs,
    })
}

fn vault_db_path(vault_dir: &str) -> PathBuf {
    Path::new(vault_dir).join(".ciphervault").join("vault.db")
}

async fn post_json(
    ctx: &ProjectContext,
    path: &str,
    body: &serde_json::Value,
    action: &str,
) -> Result<serde_json::Value> {
    let response = maybe_dpop(
        ctx.client.post(format!("{}{}", ctx.endpoint, path)),
        &ctx.token,
    )?
    .bearer_auth(&ctx.token)
    .json(body)
    .send()
    .await
    .with_context(|| format!("sending {action} request"))?;
    checked_json(response, action).await
}

pub(crate) async fn cmd_migrate(sub: MigrateSubcommand) -> Result<()> {
    match sub {
        MigrateSubcommand::Plan {
            vault,
            project,
            default_env,
            ack_production,
            dry_run,
            snapshot,
            endpoint,
            token,
        } => {
            cmd_plan(
                &vault,
                project.as_deref(),
                default_env.as_deref().unwrap_or(DEFAULT_ENV),
                ack_production,
                dry_run,
                snapshot.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await
        }
        MigrateSubcommand::Apply {
            vault,
            project,
            migration_id,
            snapshot,
            endpoint,
            token,
        } => {
            cmd_apply(
                &vault,
                project.as_deref(),
                &migration_id,
                snapshot.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await
        }
        MigrateSubcommand::Verify {
            vault,
            project,
            migration_id,
            snapshot,
            endpoint,
            token,
        } => {
            cmd_verify(
                &vault,
                project.as_deref(),
                &migration_id,
                snapshot.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await
        }
        MigrateSubcommand::Resolve {
            project,
            migration_id,
            entry,
            rename,
            env,
            endpoint,
            token,
        } => {
            cmd_resolve(
                project.as_deref(),
                &migration_id,
                &entry,
                rename.as_deref(),
                env.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await
        }
        MigrateSubcommand::ShredLegacy {
            vault,
            project,
            confirm,
            endpoint,
            token,
        } => {
            cmd_shred(
                &vault,
                project.as_deref(),
                &confirm,
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_plan(
    vault_dir: &str,
    project: Option<&str>,
    default_env: &str,
    ack_production: bool,
    dry_run: bool,
    snapshot: Option<&str>,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    let ctx = project_context(project, endpoint, token).await?;
    let db_path = vault_db_path(vault_dir);
    let store = LocalVaultStore::open_read_only(&db_path).with_context(|| {
        format!(
            "no vault at '{}' (pass --vault <dir> containing .ciphervault/vault.db)",
            db_path.display()
        )
    })?;
    let vault_id_hex = hex::encode(store.get_vault_id()?);
    let mut bundle = load_snapshot_bundle(&store, snapshot).await?;
    let snapshot_hex = hex::encode(bundle.snapshot_id);
    let mut raws: Vec<(String, Vec<u8>)> = bundle
        .files
        .iter()
        .map(|file| (file.relative_path.clone(), file.plaintext.clone()))
        .collect();
    for file in &mut bundle.files {
        file.plaintext.zeroize();
    }
    raws.sort_by(|a, b| a.0.cmp(&b.0));
    let (mut classified, dropped) = classify_files(&raws, default_env)?;
    for (_, bytes) in &mut raws {
        bytes.zeroize();
    }

    // Production gate: nothing auto-assigns production scope (§F-§2.3).
    let mut prod_targets = BTreeSet::new();
    for entry in &classified {
        let tiered = ctx.envs.get(&entry.env_guess).map(|(_, tier)| *tier);
        match tiered {
            Some(tier) if tier >= 2 => {
                prod_targets.insert(format!("{} ({})", entry.name, entry.env_guess));
            }
            None if entry.env_guess == "production" => {
                prod_targets.insert(format!("{} (production?)", entry.name));
            }
            _ => {}
        }
    }
    if !prod_targets.is_empty() && !ack_production {
        bail!(
            "refusing to target production without --ack-production: {}",
            prod_targets.into_iter().collect::<Vec<_>>().join(", ")
        );
    }

    if dry_run {
        // Machine-readable diff, zero writes, no values or digests.
        let entries: Vec<serde_json::Value> = classified
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "path": entry.path,
                    "line": entry.line,
                    "name": entry.name,
                    "env_guess": entry.env_guess,
                    "env_known": ctx.envs.contains_key(&entry.env_guess),
                    "ambiguous": entry.ambiguous,
                    "secret_type": entry.secret_type,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "project": ctx.scope.project_slug,
                "vault_id": vault_id_hex,
                "snapshot": snapshot_hex,
                "default_env": default_env,
                "entries": entries,
                "dropped": dropped.iter().map(|d| serde_json::json!({
                    "path": d.path, "line": d.line, "name": d.name, "reason": d.reason,
                })).collect::<Vec<_>>(),
            })
        );
        for entry in &mut classified {
            entry.value.zeroize();
        }
        return Ok(());
    }

    let run = post_json(
        &ctx,
        &format!("/v1/projects/{}/migrations", ctx.scope.project_id),
        &serde_json::json!({
            "source_vault_id": vault_id_hex,
            "source_snapshot_hex": snapshot_hex,
        }),
        "migration start",
    )
    .await?;
    let migration_id = run["migration_id"]
        .as_str()
        .context("malformed migration run")?;

    let mut submitted = 0usize;
    for chunk in classified.chunks(SUBMIT_BATCH) {
        let proposals: Vec<serde_json::Value> = chunk
            .iter()
            .map(|entry| {
                // Known slugs ride as IDs; unknown guesses ride raw so the
                // server quarantines with the guess visible in the reason.
                let env_id = ctx
                    .envs
                    .get(&entry.env_guess)
                    .map(|(id, _)| id.as_str())
                    .unwrap_or(&entry.env_guess);
                serde_json::json!({
                    "source_path": entry.path,
                    "source_line": entry.line,
                    "name": entry.name,
                    "secret_type": entry.secret_type,
                    "target_environment_id": env_id,
                    "source_digest_hex": sha256_hex(&entry.value),
                    "idempotency_key": ledger_key(migration_id, &entry.path, entry.line),
                })
            })
            .collect();
        let out = post_json(
            &ctx,
            &format!(
                "/v1/projects/{}/migrations/{migration_id}/entries",
                ctx.scope.project_id
            ),
            &serde_json::json!({ "entries": proposals }),
            "migration submit",
        )
        .await?;
        submitted += out["entries"].as_array().map(Vec::len).unwrap_or(0);
    }
    for entry in &mut classified {
        entry.value.zeroize();
    }

    // Fresh status for the human summary.
    let detail = api_get(
        &ctx.client,
        &ctx.endpoint,
        &ctx.token,
        &format!(
            "/v1/projects/{}/migrations/{migration_id}",
            ctx.scope.project_id
        ),
        "migration status",
    )
    .await?;
    println!("migration: {migration_id}");
    println!("snapshot:  {snapshot_hex}");
    println!("submitted: {submitted}");
    let empty = Vec::new();
    let entries = detail["entries"].as_array().unwrap_or(&empty);
    let mut quarantined = 0usize;
    for entry in entries {
        if entry["state"] == "QUARANTINED" {
            quarantined += 1;
            println!(
                "quarantined: {}:{} '{}' — {}",
                entry["source_path"].as_str().unwrap_or("?"),
                entry["source_line"].as_i64().unwrap_or(0),
                entry["name"].as_str().unwrap_or("?"),
                entry["reason"].as_str().unwrap_or("?"),
            );
        }
    }
    for d in &dropped {
        println!(
            "shadowed: {}:{} '{}' — {}",
            d.path, d.line, d.name, d.reason
        );
    }
    println!("quarantined: {quarantined} (resolve with `migrate resolve`)");
    Ok(())
}

/// Rebuilds the (path, line) → value map from the vault (read-only).
async fn vault_value_map(
    vault_dir: &str,
    snapshot: Option<&str>,
    default_env: &str,
) -> Result<BTreeMap<(String, i64), Vec<u8>>> {
    let db_path = vault_db_path(vault_dir);
    let store = LocalVaultStore::open_read_only(&db_path).with_context(|| {
        format!(
            "no vault at '{}' (pass --vault <dir> containing .ciphervault/vault.db)",
            db_path.display()
        )
    })?;
    let mut bundle = load_snapshot_bundle(&store, snapshot).await?;
    let raws: Vec<(String, Vec<u8>)> = bundle
        .files
        .iter()
        .map(|file| (file.relative_path.clone(), file.plaintext.clone()))
        .collect();
    for file in &mut bundle.files {
        file.plaintext.zeroize();
    }
    let (classified, _) = classify_files(&raws, default_env)?;
    Ok(classified
        .into_iter()
        .map(|entry| ((entry.path, entry.line), entry.value))
        .collect())
}

async fn migration_detail(ctx: &ProjectContext, migration_id: &str) -> Result<serde_json::Value> {
    api_get(
        &ctx.client,
        &ctx.endpoint,
        &ctx.token,
        &format!(
            "/v1/projects/{}/migrations/{migration_id}",
            ctx.scope.project_id
        ),
        "migration status",
    )
    .await
}

/// Resolve a secret name to (id, value digest) for 409 adoption.
async fn adopted_secret(
    ctx: &ProjectContext,
    env_id: &str,
    name: &str,
) -> Result<Option<(String, String)>> {
    let list = api_get(
        &ctx.client,
        &ctx.endpoint,
        &ctx.token,
        &format!(
            "/v1/projects/{}/secrets?environment={env_id}&limit=100&q={name}",
            ctx.scope.project_id
        ),
        "secret lookup",
    )
    .await?;
    let found = list["secrets"].as_array().and_then(|secrets| {
        secrets
            .iter()
            .find(|entry| entry["name"].as_str() == Some(name) && entry["secret_id"].is_string())
    });
    let Some(found) = found else { return Ok(None) };
    let secret_id = found["secret_id"].as_str().unwrap_or_default().to_string();
    let got = api_get(
        &ctx.client,
        &ctx.endpoint,
        &ctx.token,
        &format!("/v1/projects/{}/secrets/{secret_id}", ctx.scope.project_id),
        "secret readback",
    )
    .await?;
    let value = got["value"].as_str().context("malformed secret value")?;
    Ok(Some((secret_id, sha256_hex(value.as_bytes()))))
}

async fn cmd_apply(
    vault_dir: &str,
    project: Option<&str>,
    migration_id: &str,
    snapshot: Option<&str>,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    let ctx = project_context(project, endpoint, token).await?;
    let detail = migration_detail(&ctx, migration_id).await?;
    let state = detail["migration"]["state"].as_str().unwrap_or("?");
    if !matches!(state, "planning" | "applying" | "verifying") {
        bail!("migration is {state} (apply needs planning/applying/verifying)");
    }
    // default_env is irrelevant here (coords already classified); any value
    // reproduces the same (path, line) map.
    let values = vault_value_map(vault_dir, snapshot, DEFAULT_ENV).await?;
    let empty = Vec::new();
    let entries = detail["entries"].as_array().unwrap_or(&empty);
    let mut migrated = 0usize;
    let mut skipped = 0usize;
    for entry in entries {
        if entry["state"] != "VALIDATED" {
            skipped += 1;
            continue;
        }
        let (path, line, name) = (
            entry["source_path"].as_str().unwrap_or_default(),
            entry["source_line"].as_i64().unwrap_or(0),
            entry["name"].as_str().unwrap_or_default(),
        );
        let Some(bytes) = values.get(&(path.to_string(), line)) else {
            bail!(
                "vault drift: no value for {path}:{line} ('{name}'); re-plan from the current head"
            );
        };
        let value = String::from_utf8(bytes.clone()).with_context(|| {
            format!("{path}:{line} ('{name}') is not valid UTF-8 and cannot be a JSON secret value")
        })?;
        let env_id = entry["target_environment_id"].as_str().unwrap_or_default();
        let secret_type = if entry["secret_type"].as_str().unwrap_or("key_value") == "file" {
            "file"
        } else {
            "key_value"
        };
        // Normal secret API write; 409 races adopt only on digest match.
        let response = maybe_dpop(
            ctx.client.post(format!(
                "{}/v1/projects/{}/environments/{env_id}/secrets",
                ctx.endpoint, ctx.scope.project_id
            )),
            &ctx.token,
        )?
        .bearer_auth(&ctx.token)
        .json(&serde_json::json!({
            "name": name,
            "value": value,
            "secret_type": secret_type,
            "description": format!("migrated {path}:{line} via {migration_id}"),
        }))
        .send()
        .await
        .context("sending secret create")?;
        let secret_id = if response.status() == reqwest::StatusCode::CONFLICT {
            match adopted_secret(&ctx, env_id, name).await? {
                Some((id, digest)) if digest == sha256_hex(value.as_bytes()) => id,
                _ => bail!(
                    "name '{name}' collided in target scope with different bytes; resolve the quarantine instead"
                ),
            }
        } else {
            let created = checked_json(response, "secret create").await?;
            created["secret_id"]
                .as_str()
                .context("malformed secret create")?
                .to_string()
        };
        let ledger_id = entry["ledger_id"].as_str().unwrap_or_default();
        post_json(
            &ctx,
            &format!(
                "/v1/projects/{}/migrations/{migration_id}/entries/{ledger_id}/migrated",
                ctx.scope.project_id
            ),
            &serde_json::json!({
                "secret_id": secret_id,
                "target_digest_hex": sha256_hex(value.as_bytes()),
            }),
            "migration mark",
        )
        .await?;
        migrated += 1;
    }
    println!("migration: {migration_id}");
    println!("migrated:  {migrated}");
    println!("skipped (not VALIDATED): {skipped}");
    Ok(())
}

async fn cmd_verify(
    vault_dir: &str,
    project: Option<&str>,
    migration_id: &str,
    snapshot: Option<&str>,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    let ctx = project_context(project, endpoint, token).await?;
    let detail = migration_detail(&ctx, migration_id).await?;
    let state = detail["migration"]["state"].as_str().unwrap_or("?");
    if !matches!(state, "applying" | "verifying") {
        bail!("migration is {state} (verify needs applying/verifying)");
    }
    // Two-sided readback: the decrypted server value must match BOTH the
    // ledgered source digest and the live vault bytes (catches symmetric
    // CLI digest bugs and vault drift since apply).
    let values = vault_value_map(vault_dir, snapshot, DEFAULT_ENV).await?;
    let empty = Vec::new();
    let entries = detail["entries"].as_array().unwrap_or(&empty);
    let mut checked = 0usize;
    for entry in entries {
        if entry["state"] != "MIGRATED" {
            continue;
        }
        let (path, line) = (
            entry["source_path"].as_str().unwrap_or_default(),
            entry["source_line"].as_i64().unwrap_or(0),
        );
        let secret_id = entry["secret_id"].as_str().unwrap_or_default();
        let got = api_get(
            &ctx.client,
            &ctx.endpoint,
            &ctx.token,
            &format!("/v1/projects/{}/secrets/{secret_id}", ctx.scope.project_id),
            "secret readback",
        )
        .await?;
        let value = got["value"].as_str().context("malformed secret value")?;
        let readback = sha256_hex(value.as_bytes());
        let expected = entry["source_digest_hex"].as_str().unwrap_or_default();
        let Some(local) = values.get(&(path.to_string(), line)) else {
            bail!(
                "vault drift: {path}:{line} vanished since plan; leaving MIGRATED for investigation"
            );
        };
        if readback != expected || readback != sha256_hex(local) {
            bail!(
                "readback mismatch for {path}:{line} (secret {secret_id}); leaving MIGRATED for investigation"
            );
        }
        checked += 1;
    }
    let outcome = {
        let response = maybe_dpop(
            ctx.client.post(format!(
                "{}/v1/projects/{}/migrations/{migration_id}/verify",
                ctx.endpoint, ctx.scope.project_id
            )),
            &ctx.token,
        )?
        .bearer_auth(&ctx.token)
        .send()
        .await
        .context("sending migration verify")?;
        checked_json(response, "migration verify").await?
    };
    println!("migration:   {migration_id}");
    println!("readback ok: {checked}");
    println!("verified:    {}", outcome["verified"].as_i64().unwrap_or(0));
    println!(
        "quarantined: {}",
        outcome["quarantined"].as_i64().unwrap_or(0)
    );
    println!(
        "run state:   {}",
        outcome["run_state"].as_str().unwrap_or("?")
    );
    Ok(())
}

async fn cmd_resolve(
    project: Option<&str>,
    migration_id: &str,
    ledger_id: &str,
    rename: Option<&str>,
    env_slug: Option<&str>,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    if rename.is_none() && env_slug.is_none() {
        bail!("pass --rename and/or --env");
    }
    let ctx = project_context(project, endpoint, token).await?;
    let env_id =
        match env_slug {
            Some(slug) => Some(ctx.envs.get(slug).map(|(id, _)| id.as_str()).with_context(
                || {
                    format!(
                        "unknown environment '{slug}' (known: {})",
                        ctx.envs.keys().cloned().collect::<Vec<_>>().join(", ")
                    )
                },
            )?),
            None => None,
        };
    let entry = post_json(
        &ctx,
        &format!(
            "/v1/projects/{}/migrations/{migration_id}/entries/{ledger_id}/resolve",
            ctx.scope.project_id
        ),
        &serde_json::json!({
            "name": rename,
            "target_environment_id": env_id,
        }),
        "migration resolve",
    )
    .await?;
    println!(
        "{}:{} '{}' → {} {}",
        entry["source_path"].as_str().unwrap_or("?"),
        entry["source_line"].as_i64().unwrap_or(0),
        entry["name"].as_str().unwrap_or("?"),
        entry["state"].as_str().unwrap_or("?"),
        entry["reason"].as_str().unwrap_or_default(),
    );
    Ok(())
}

async fn cmd_shred(
    vault_dir: &str,
    project: Option<&str>,
    confirm: &str,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    let ctx = project_context(project, endpoint, token).await?;
    if confirm.trim() != ctx.scope.project_slug {
        bail!(
            "confirm mismatch: pass --confirm {} to shred this project's legacy vault",
            ctx.scope.project_slug
        );
    }
    let runs = api_get(
        &ctx.client,
        &ctx.endpoint,
        &ctx.token,
        &format!("/v1/projects/{}/migrations", ctx.scope.project_id),
        "migration list",
    )
    .await?;
    let empty = Vec::new();
    let runs = runs["migrations"].as_array().unwrap_or(&empty);
    let live: Vec<&str> = runs
        .iter()
        .filter(|run| run["state"] != "aborted")
        .filter_map(|run| run["migration_id"].as_str())
        .collect();
    if live.is_empty() {
        bail!("nothing ledgered for this project: migrate before shredding (refusing to destroy unmigrated vaults)");
    }
    // Flip every VERIFIED pointer, then require the whole ledger disabled.
    let mut snapshots = BTreeSet::new();
    let mut vaults = BTreeSet::new();
    for run in runs {
        if run["state"] != "aborted" {
            vaults.insert(
                run["source_vault_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
        }
    }
    let mut flipped = 0i64;
    for migration_id in &live {
        let detail = migration_detail(&ctx, migration_id).await?;
        // Flip VERIFIED pointers once the run is ready; younger runs skip
        // the flip and fail the disabled gate below (nothing destroyed).
        if matches!(
            detail["migration"]["state"].as_str(),
            Some("verifying" | "complete")
        ) {
            let response = maybe_dpop(
                ctx.client.post(format!(
                    "{}/v1/projects/{}/migrations/{migration_id}/disable-legacy",
                    ctx.endpoint, ctx.scope.project_id
                )),
                &ctx.token,
            )?
            .bearer_auth(&ctx.token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .context("sending legacy disable")?;
            let out = checked_json(response, "legacy disable").await?;
            flipped += out["disabled"].as_i64().unwrap_or(0);
        }
        let detail = migration_detail(&ctx, migration_id).await?;
        snapshots.insert(
            detail["migration"]["source_snapshot_hex"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        );
        let entries = detail["entries"].as_array().cloned().unwrap_or_default();
        let open: Vec<String> = entries
            .iter()
            .filter(|entry| entry["state"] != "LEGACY_PATH_DISABLED")
            .map(|entry| {
                format!(
                    "{}:{} '{}' ({})",
                    entry["source_path"].as_str().unwrap_or("?"),
                    entry["source_line"].as_i64().unwrap_or(0),
                    entry["name"].as_str().unwrap_or("?"),
                    entry["state"].as_str().unwrap_or("?")
                )
            })
            .collect();
        if !open.is_empty() {
            bail!(
                "refusing to shred: {migration_id} still has {} live entries: {}",
                open.len(),
                open.join("; ")
            );
        }
    }
    // The vault on disk must be the migrated one, at a migrated snapshot.
    let db_path = vault_db_path(vault_dir);
    let store = LocalVaultStore::open_read_only(&db_path)
        .with_context(|| format!("no vault at '{}'", db_path.display()))?;
    let vault_hex = hex::encode(store.get_vault_id()?);
    let head_hex = match store.get_active_head()? {
        Some(head) => hex::encode(head.snapshot_id),
        None => bail!("vault has no snapshots; nothing to shred"),
    };
    drop(store);
    if !vaults.contains(&vault_hex) {
        bail!("vault {vault_hex} was never migrated into this project; refusing to shred a foreign vault");
    }
    if !snapshots.contains(&head_hex) {
        bail!(
            "vault advanced since migration (head {head_hex} not in ledgered snapshots); re-plan before shredding"
        );
    }
    println!("legacy pointers flipped: {flipped}");
    for suffix in ["", "-wal", "-shm"] {
        let target = match suffix {
            "" => db_path.clone(),
            _ => PathBuf::from(format!("{}{suffix}", db_path.display())),
        };
        if !target.exists() {
            continue;
        }
        let len = std::fs::metadata(&target)?.len();
        {
            use std::io::Write;
            let mut handle = std::fs::OpenOptions::new().write(true).open(&target)?;
            let mut chunk = vec![0u8; 65_536];
            let mut remaining = len;
            while remaining > 0 {
                rand::rngs::OsRng.fill_bytes(&mut chunk);
                let take = remaining.min(chunk.len() as u64) as usize;
                handle.write_all(&chunk[..take])?;
                remaining -= take as u64;
            }
            handle.sync_all()?;
        }
        std::fs::remove_file(&target)?;
        println!("shredded: {}", target.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{classify_files, guess_env, sanitize_file_name};

    #[test]
    fn env_guesses_follow_the_heuristic() {
        assert_eq!(
            guess_env(".env", "development"),
            ("development".to_string(), true)
        );
        assert_eq!(
            guess_env(".env.production", "development"),
            ("production".to_string(), false)
        );
        assert_eq!(
            guess_env(".env.local", "development"),
            ("local".to_string(), true)
        );
        assert_eq!(
            guess_env("prod.env", "development"),
            ("prod".to_string(), true)
        );
        assert_eq!(
            guess_env("notes.txt", "development"),
            ("development".to_string(), true)
        );
    }

    #[test]
    fn file_names_sanitize_to_valid_secret_names() {
        assert_eq!(sanitize_file_name("certs/tls.pem"), "FILE_CERTS_TLS_PEM");
        assert_eq!(sanitize_file_name("a b-c.json"), "FILE_A_B_C_JSON");
    }

    #[test]
    fn layering_keeps_last_occurrence_and_reports_shadowed() {
        // `.env.local` and `local.env` guess the same env: `.env.*` ranks
        // before `*.env`, so `local.env` wins and `.env.local`'s copy is
        // shadowed. (Different guesses are different scopes: both submit.)
        let files = vec![
            (".env.local".to_string(), b"K=v1\nSHARED=base\n".to_vec()),
            ("local.env".to_string(), b"K=v2\n".to_vec()),
        ];
        let (classified, dropped) = classify_files(&files, "development").unwrap();
        let winner = classified.iter().find(|entry| entry.name == "K").unwrap();
        assert_eq!(winner.value, b"v2");
        assert_eq!(winner.path, "local.env");
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].name, "K");
        assert_eq!(dropped[0].path, ".env.local");
        assert!(classified.iter().any(|entry| entry.name == "SHARED"));
    }

    #[test]
    fn same_file_duplicates_keep_last_line() {
        let files = vec![(".env".to_string(), b"DUP=first\nDUP=second\n".to_vec())];
        let (classified, dropped) = classify_files(&files, "development").unwrap();
        assert_eq!(classified.len(), 1);
        assert_eq!(classified[0].value, b"second");
        assert_eq!(classified[0].line, 2);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].line, 1);
    }

    #[test]
    fn whole_files_become_file_entries_and_binaries_quarantine() {
        let files = vec![
            ("certs/tls.pem".to_string(), b"pem-bytes".to_vec()),
            ("blob.bin".to_string(), vec![0xff, 0xfe, 0x00]),
        ];
        let (classified, _) = classify_files(&files, "development").unwrap();
        let pem = classified
            .iter()
            .find(|entry| entry.path == "certs/tls.pem")
            .unwrap();
        assert_eq!(pem.name, "FILE_CERTS_TLS_PEM");
        assert_eq!(pem.secret_type, "file");
        // Raw path fails server name rules ⇒ QUARANTINED with provenance,
        // and the raw bytes stay as the digest preimage (never empty: a
        // renamed binary must fail closed at apply, not migrate empty).
        let bin = classified
            .iter()
            .find(|entry| entry.path == "blob.bin")
            .unwrap();
        assert_eq!(bin.name, "blob.bin");
        assert_eq!(bin.value, vec![0xff, 0xfe, 0x00]);
    }
}
