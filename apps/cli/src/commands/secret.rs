//! Scoped secret commands (Phase 7, T-701).
//!
//! Thin client over the secret API. Project/environment resolve through
//! the standard precedence (flags > env > context file > auto-detect)
//! with a scope echo on stderr; the environment is always required.
//! Values travel in request bodies only and are never printed except by
//! `secret get`, which emits the bare value for piping.

use anyhow::{bail, Context, Result};
use rand::RngCore;
use std::io::{IsTerminal, Read};
use zeroize::Zeroizing;

use super::dpop::maybe_dpop;
use super::scope::{
    api_get, checked_json, http_client, resolve_endpoint, resolve_scope, resolve_token,
    ResolvedScope,
};
use crate::SecretSubcommand;

const SECRET_LIST_LIMIT: i64 = 500;

struct Session {
    client: reqwest::Client,
    endpoint: String,
    token: String,
    scope: ResolvedScope,
}

impl Session {
    fn env_id(&self) -> &str {
        self.scope.env_id.as_deref().unwrap_or_default()
    }
}

async fn session(
    project: Option<&str>,
    env: Option<&str>,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<Session> {
    let endpoint = resolve_endpoint(endpoint)?;
    let token = resolve_token(token)?;
    let client = http_client()?;
    let scope = resolve_scope(&client, &endpoint, &token, project, env, true).await?;
    Ok(Session {
        client,
        endpoint,
        token,
        scope,
    })
}

/// Returns the flag value or securely prompts. Non-interactive callers
/// must pass the flag (prompt failures name it).
fn secret_value(flag: Option<&str>, stdin: bool, what: &str) -> Result<Zeroizing<String>> {
    if stdin {
        let mut value = Zeroizing::new(String::new());
        std::io::stdin()
            .take(65_537)
            .read_to_string(&mut value)
            .context("Secret stdin must be valid UTF-8")?;
        if value.is_empty() || value.len() > 65_536 {
            bail!("Secret stdin must contain 1 to 65536 bytes");
        }
        return Ok(value);
    }
    if let Some(value) = flag.filter(|value| !value.is_empty()) {
        return Ok(Zeroizing::new(value.to_string()));
    }
    // rpassword opens the console directly (CONIN$ on Windows), bypassing
    // stdin redirection: prompting without a terminal hangs instead of
    // failing, so refuse up front like `token pin` does.
    if !std::io::stdin().is_terminal() {
        bail!("pass --value-stdin or --value (no interactive prompt available)");
    }
    rpassword::prompt_password(format!("{what}: "))
        .context("pass --value (no interactive prompt available)")
        .and_then(|value| {
            if value.is_empty() {
                bail!("value must not be empty")
            } else {
                Ok(Zeroizing::new(value))
            }
        })
}

fn random_idempotency_key() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Resolves a secret name to its ID by scanning one list page. Names are
/// unique per scope, so the first match wins; huge scopes use `--id`.
async fn resolve_secret_id(
    session: &Session,
    action: &str,
    name: Option<&str>,
    id: Option<&str>,
) -> Result<String> {
    if let Some(id) = id.map(str::trim).filter(|id| !id.is_empty()) {
        return Ok(id.to_string());
    }
    let name = name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .context("pass the secret NAME or --id")?;
    let body = api_get(
        &session.client,
        &session.endpoint,
        &session.token,
        &format!(
            "/v1/projects/{}/secrets?environment={}&limit={SECRET_LIST_LIMIT}",
            session.scope.project_id,
            session.env_id()
        ),
        action,
    )
    .await?;
    let secrets = body["secrets"]
        .as_array()
        .context("server returned a malformed secret list")?;
    if let Some(found) = secrets
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name) && entry["secret_id"].is_string())
    {
        return Ok(found["secret_id"].as_str().unwrap_or_default().to_string());
    }
    if secrets.len() >= SECRET_LIST_LIMIT as usize {
        bail!("'{name}' not found in the first {SECRET_LIST_LIMIT} secrets; pass --id");
    }
    bail!("unknown secret '{name}' in this scope")
}

pub(crate) async fn cmd_secret(sub: SecretSubcommand) -> Result<()> {
    match sub {
        SecretSubcommand::Set {
            name,
            value,
            value_stdin,
            secret_type,
            description,
            tag,
            repo_binding,
            service,
            project,
            env,
            endpoint,
            token,
        } => {
            let session = session(
                project.as_deref(),
                env.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await?;
            let value = secret_value(value.as_deref(), value_stdin, "Value")?;
            let mut payload = serde_json::json!({
                "name": name.trim(),
                "value": value.as_str(),
            });
            if let Some(kind) = secret_type
                .map(|kind| kind.trim().to_string())
                .filter(|kind| !kind.is_empty())
            {
                payload["secret_type"] = serde_json::json!(kind);
            }
            if let Some(text) = description
                .map(|text| text.trim().to_string())
                .filter(|text| !text.is_empty())
            {
                payload["description"] = serde_json::json!(text);
            }
            if !tag.is_empty() {
                payload["tags"] = serde_json::json!(tag);
            }
            if let Some(binding) = repo_binding
                .map(|binding| binding.trim().to_string())
                .filter(|binding| !binding.is_empty())
            {
                payload["repository_binding_id"] = serde_json::json!(binding);
            }
            if let Some(service) = service
                .map(|service| service.trim().to_string())
                .filter(|service| !service.is_empty())
            {
                payload["service_id"] = serde_json::json!(service);
            }
            let response = maybe_dpop(
                session.client.post(format!(
                    "{}/v1/projects/{}/environments/{}/secrets",
                    session.endpoint,
                    session.scope.project_id,
                    session.env_id()
                )),
                &session.token,
            )?
            .bearer_auth(&session.token)
            .json(&payload)
            .send()
            .await
            .context("sending set request")?;
            let view = checked_json(response, "secret set").await?;
            println!(
                "Set {} in {}/{}: id {} version {}.",
                name.trim(),
                session.scope.project_slug,
                session.scope.env_slug.as_deref().unwrap_or("?"),
                view["secret_id"].as_str().unwrap_or("?"),
                view["current_version"].as_i64().unwrap_or(0)
            );
            Ok(())
        }
        SecretSubcommand::Get {
            name,
            meta,
            project,
            env,
            endpoint,
            token,
        } => {
            let session = session(
                project.as_deref(),
                env.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await?;
            let mut path = format!(
                "/v1/projects/{}/environments/{}/secrets/{}",
                session.scope.project_id,
                session.env_id(),
                name.trim()
            );
            if meta {
                path.push_str("?metadata_only=true");
            }
            let body = api_get(
                &session.client,
                &session.endpoint,
                &session.token,
                &path,
                "secret get",
            )
            .await?;
            if meta {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                println!("{}", body["value"].as_str().unwrap_or_default());
            }
            Ok(())
        }
        SecretSubcommand::List {
            tag,
            status,
            limit,
            project,
            env,
            endpoint,
            token,
        } => {
            let session = session(
                project.as_deref(),
                env.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await?;
            let mut query = vec![
                ("environment".to_string(), session.env_id().to_string()),
                ("limit".to_string(), limit.unwrap_or(100).to_string()),
            ];
            for value in &tag {
                query.push(("tag".to_string(), value.clone()));
            }
            if let Some(value) = status {
                query.push(("status".to_string(), value));
            }
            let response = maybe_dpop(
                session.client.get(format!(
                    "{}/v1/projects/{}/secrets",
                    session.endpoint, session.scope.project_id
                )),
                &session.token,
            )?
            .bearer_auth(&session.token)
            .query(&query)
            .send()
            .await
            .context("sending list request")?;
            let body = checked_json(response, "secret list").await?;
            let secrets = body["secrets"]
                .as_array()
                .context("server returned a malformed secret list")?;
            if secrets.is_empty() {
                println!("No secrets in this scope.");
                return Ok(());
            }
            println!(
                "{:<28} {:<12} {:<5} {:<10}",
                "NAME", "TYPE", "VER", "STATUS"
            );
            for entry in secrets {
                println!(
                    "{:<28} {:<12} {:<5} {:<10}",
                    entry["name"].as_str().unwrap_or("?"),
                    entry["secret_type"].as_str().unwrap_or("?"),
                    entry["current_version"].as_i64().unwrap_or(0),
                    entry["status"].as_str().unwrap_or("?")
                );
            }
            Ok(())
        }
        SecretSubcommand::Find {
            query,
            limit,
            project,
            env,
            endpoint,
            token,
        } => {
            let query = query.trim();
            if query.is_empty() {
                bail!("query must not be empty");
            }
            if query.len() > 128 {
                bail!("query must be at most 128 characters");
            }
            let session = session(
                project.as_deref(),
                env.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await?;
            let response = maybe_dpop(
                session.client.get(format!(
                    "{}/v1/projects/{}/secrets",
                    session.endpoint, session.scope.project_id
                )),
                &session.token,
            )?
            .bearer_auth(&session.token)
            .query(&[
                ("environment", session.env_id()),
                ("q", query),
                ("limit", &limit.unwrap_or(100).to_string()),
            ])
            .send()
            .await
            .context("sending find request")?;
            let body = checked_json(response, "secret find").await?;
            let secrets = body["secrets"]
                .as_array()
                .context("server returned a malformed secret list")?;
            if secrets.is_empty() {
                println!("No secrets matching '{query}' in this scope.");
                return Ok(());
            }
            println!(
                "{:<28} {:<12} {:<5} {:<10}",
                "NAME", "TYPE", "VER", "STATUS"
            );
            for entry in secrets {
                println!(
                    "{:<28} {:<12} {:<5} {:<10}",
                    entry["name"].as_str().unwrap_or("?"),
                    entry["secret_type"].as_str().unwrap_or("?"),
                    entry["current_version"].as_i64().unwrap_or(0),
                    entry["status"].as_str().unwrap_or("?")
                );
            }
            Ok(())
        }
        SecretSubcommand::Update {
            name,
            id,
            description,
            tag,
            status,
            expires_at,
            project,
            env,
            endpoint,
            token,
        } => {
            let session = session(
                project.as_deref(),
                env.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await?;
            let secret_id =
                resolve_secret_id(&session, "secret list", name.as_deref(), id.as_deref()).await?;
            let mut payload = serde_json::json!({});
            if let Some(text) = description {
                payload["description"] = serde_json::json!(text);
            }
            if let Some(tags) = tag {
                payload["tags"] = serde_json::json!(tags);
            }
            if let Some(value) = status {
                payload["status"] = serde_json::json!(value);
            }
            if let Some(raw) = expires_at {
                let when = chrono::DateTime::parse_from_rfc3339(raw.trim())
                    .with_context(|| format!("parsing --expires-at '{raw}' (want RFC 3339)"))?;
                payload["expires_at_utc"] = serde_json::json!(when.timestamp().max(0) as u64);
            }
            if payload.as_object().is_some_and(|map| map.is_empty()) {
                bail!("nothing to update: pass --description, --tag, --status, or --expires-at");
            }
            let response = maybe_dpop(
                session.client.patch(format!(
                    "{}/v1/projects/{}/secrets/{secret_id}",
                    session.endpoint, session.scope.project_id
                )),
                &session.token,
            )?
            .bearer_auth(&session.token)
            .json(&payload)
            .send()
            .await
            .context("sending update request")?;
            let view = checked_json(response, "secret update").await?;
            println!(
                "Updated {} (status {}).",
                view["name"]
                    .as_str()
                    .unwrap_or(name.as_deref().unwrap_or("?")),
                view["status"].as_str().unwrap_or("?")
            );
            Ok(())
        }
        SecretSubcommand::Delete {
            name,
            id,
            reason,
            project,
            env,
            endpoint,
            token,
        } => {
            let session = session(
                project.as_deref(),
                env.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await?;
            let secret_id =
                resolve_secret_id(&session, "secret list", name.as_deref(), id.as_deref()).await?;
            let mut request = maybe_dpop(
                session.client.delete(format!(
                    "{}/v1/projects/{}/secrets/{secret_id}",
                    session.endpoint, session.scope.project_id
                )),
                &session.token,
            )?
            .bearer_auth(&session.token);
            if let Some(reason) = reason.filter(|reason| !reason.trim().is_empty()) {
                request = request.query(&[("reason", reason)]);
            }
            let response = request.send().await.context("sending delete request")?;
            let body = checked_json(response, "secret delete").await?;
            println!(
                "Deleted {}: {}.",
                name.as_deref().unwrap_or(secret_id.as_str()),
                body["status"].as_str().unwrap_or("?")
            );
            Ok(())
        }
        SecretSubcommand::Rotate {
            name,
            id,
            value,
            value_stdin,
            reason,
            idempotency_key,
            project,
            env,
            endpoint,
            token,
        } => {
            let session = session(
                project.as_deref(),
                env.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await?;
            let secret_id =
                resolve_secret_id(&session, "secret list", name.as_deref(), id.as_deref()).await?;
            let value = secret_value(value.as_deref(), value_stdin, "New value")?;
            let payload = serde_json::json!({
                "new_value": value.as_str(),
                "idempotency_key": idempotency_key.unwrap_or_else(random_idempotency_key),
                "reason": reason.unwrap_or_else(|| "operator rotate".to_string()),
            });
            let response = maybe_dpop(
                session.client.post(format!(
                    "{}/v1/projects/{}/secrets/{secret_id}/rotate",
                    session.endpoint, session.scope.project_id
                )),
                &session.token,
            )?
            .bearer_auth(&session.token)
            .json(&payload)
            .send()
            .await
            .context("sending rotate request")?;
            let outcome = checked_json(response, "secret rotate").await?;
            println!(
                "Rotated {} to version {}.",
                name.as_deref().unwrap_or(secret_id.as_str()),
                outcome["current_version"].as_i64().unwrap_or(0)
            );
            Ok(())
        }
    }
}
