//! Repository binding commands (Phase 6, T-602).
//!
//! Thin client over the account-server binding API: `repo bind` registers a
//! VCS repository by immutable provider id, `repo list` shows bindings, and
//! `repo unbind` suspends (or revokes) without touching secrets.
//!
//! Credentials: `--endpoint` / `CIPHERVAULT_ACCOUNT_ENDPOINT` (or the linked
//! account's hosted endpoint) plus `--token` / `CIPHERVAULT_SCOPE_TOKEN`
//! (a `cvst1.*` scope token; bind/unbind need admin membership).
//! `--project` accepts a slug or ID and resolves through the standard
//! scope precedence (T-701) with a scope echo on stderr.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use reqwest::Client as HttpClient;

use super::dpop::maybe_dpop;
use super::scope::{checked_json, http_client, resolve_endpoint, resolve_scope, resolve_token};
use crate::RepoSubcommand;

pub(crate) async fn cmd_repo(sub: RepoSubcommand) -> Result<()> {
    match sub {
        RepoSubcommand::Bind {
            project,
            provider,
            repo_id,
            name,
            url,
            installation_id,
            endpoint,
            token,
        } => {
            cmd_repo_bind(
                &project,
                &provider,
                &repo_id,
                &name,
                &url,
                installation_id.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await
        }
        RepoSubcommand::List {
            project,
            endpoint,
            token,
        } => cmd_repo_list(&project, endpoint.as_deref(), token.as_deref()).await,
        RepoSubcommand::Unbind {
            project,
            binding,
            provider,
            repo_id,
            revoke,
            reason,
            endpoint,
            token,
        } => {
            cmd_repo_unbind(
                &project,
                binding.as_deref(),
                provider.as_deref(),
                repo_id.as_deref(),
                revoke,
                reason.as_deref(),
                endpoint.as_deref(),
                token.as_deref(),
            )
            .await
        }
    }
}

fn normalize_provider(raw: &str) -> Result<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "github" => Ok("github"),
        "gitlab" => Ok("gitlab"),
        "bitbucket" => Ok("bitbucket"),
        "self-hosted" | "self_hosted" => Ok("self-hosted"),
        other => {
            bail!("unknown VCS provider '{other}': use github, gitlab, bitbucket, or self-hosted")
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_repo_bind(
    project: &str,
    provider: &str,
    repo_id: &str,
    name: &str,
    url: &str,
    installation_id: Option<&str>,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    let provider = normalize_provider(provider)?;
    let endpoint = resolve_endpoint(endpoint)?;
    let token = resolve_token(token)?;
    let client = http_client()?;
    let scope = resolve_scope(&client, &endpoint, &token, Some(project), None, false).await?;
    let mut payload = serde_json::json!({
        "provider": provider,
        "external_repo_id": repo_id.trim(),
        "repo_full_name": name.trim(),
        "repo_url": url.trim(),
    });
    if let Some(id) = installation_id.filter(|value| !value.trim().is_empty()) {
        payload["installation_id"] = serde_json::json!(id.trim());
    }
    let response = maybe_dpop(
        client.post(format!(
            "{endpoint}/v1/projects/{}/repositories",
            scope.project_id
        )),
        &token,
    )?
    .bearer_auth(token)
    .json(&payload)
    .send()
    .await
    .context("sending bind request")?;
    let body = checked_json(response, "repo bind").await?;
    let binding = &body["binding"];
    println!(
        "{} {} ({}:{}) to project {}.",
        "Bound".green().bold(),
        name.trim(),
        provider,
        repo_id.trim(),
        scope.project_slug
    );
    println!(
        "  binding_id: {}",
        binding["binding_id"].as_str().unwrap_or("?")
    );
    println!("  status: {}", binding["status"].as_str().unwrap_or("?"));
    println!(
        "  ownership_challenge: {}",
        body["ownership_challenge"].as_str().unwrap_or("?")
    );
    println!(
        "  {}: {} (shown once — store it now)",
        "webhook_secret".yellow(),
        body["webhook_secret"].as_str().unwrap_or("?")
    );
    Ok(())
}

async fn cmd_repo_list(project: &str, endpoint: Option<&str>, token: Option<&str>) -> Result<()> {
    let endpoint = resolve_endpoint(endpoint)?;
    let token = resolve_token(token)?;
    let client = http_client()?;
    let scope = resolve_scope(&client, &endpoint, &token, Some(project), None, false).await?;
    let response = maybe_dpop(
        client.get(format!(
            "{endpoint}/v1/projects/{}/repositories",
            scope.project_id
        )),
        &token,
    )?
    .bearer_auth(token)
    .send()
    .await
    .context("sending list request")?;
    let body = checked_json(response, "repo list").await?;
    let bindings = body["bindings"]
        .as_array()
        .context("server returned a malformed bindings list")?;
    if bindings.is_empty() {
        println!("No repository bindings for project {}.", scope.project_slug);
        return Ok(());
    }
    println!(
        "{:<34} {:<10} {:<12} {:<28} {:<10}",
        "BINDING ID", "PROVIDER", "EXTERNAL ID", "NAME", "STATUS"
    );
    for binding in bindings {
        println!(
            "{:<34} {:<10} {:<12} {:<28} {:<10}",
            binding["binding_id"].as_str().unwrap_or("?"),
            binding["provider"].as_str().unwrap_or("?"),
            binding["external_repo_id"].as_str().unwrap_or("?"),
            binding["repo_full_name"].as_str().unwrap_or("?"),
            binding["status"].as_str().unwrap_or("?")
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_repo_unbind(
    project: &str,
    binding: Option<&str>,
    provider: Option<&str>,
    repo_id: Option<&str>,
    revoke: bool,
    reason: Option<&str>,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    let endpoint = resolve_endpoint(endpoint)?;
    let token = resolve_token(token)?;
    let client = http_client()?;
    let scope = resolve_scope(&client, &endpoint, &token, Some(project), None, false).await?;
    let binding_id = match binding.filter(|value| !value.trim().is_empty()) {
        Some(id) => id.trim().to_string(),
        None => {
            let (provider, repo_id) = match (provider, repo_id) {
                (Some(provider), Some(repo_id)) => {
                    (normalize_provider(provider)?, repo_id.trim().to_string())
                }
                _ => bail!("pass --binding <id> or both --provider and --repo-id"),
            };
            resolve_binding_id(
                &client,
                &endpoint,
                &token,
                &scope.project_id,
                provider,
                &repo_id,
            )
            .await?
        }
    };
    let mode = if revoke { "revoke" } else { "suspend" };
    let mut request = maybe_dpop(
        client.delete(format!(
            "{endpoint}/v1/projects/{}/repositories/{binding_id}",
            scope.project_id
        )),
        &token,
    )?
    .bearer_auth(&token)
    .query(&[("mode", mode)]);
    if let Some(reason) = reason.filter(|value| !value.trim().is_empty()) {
        request = request.query(&[("reason", reason.trim())]);
    }
    let response = request.send().await.context("sending unbind request")?;
    let body = checked_json(response, "repo unbind").await?;
    println!(
        "Binding {binding_id} {}.",
        body["status"].as_str().unwrap_or("?")
    );
    Ok(())
}

async fn resolve_binding_id(
    client: &HttpClient,
    endpoint: &str,
    token: &str,
    project: &str,
    provider: &str,
    repo_id: &str,
) -> Result<String> {
    let response = maybe_dpop(
        client.get(format!(
            "{endpoint}/v1/projects/{}/repositories",
            project.trim()
        )),
        token,
    )?
    .bearer_auth(token)
    .send()
    .await
    .context("sending list request")?;
    let body = checked_json(response, "repo list").await?;
    let bindings = body["bindings"]
        .as_array()
        .context("server returned a malformed bindings list")?;
    let matches: Vec<&str> = bindings
        .iter()
        .filter(|binding| {
            binding["provider"].as_str() == Some(provider)
                && binding["external_repo_id"].as_str() == Some(repo_id)
        })
        .filter_map(|binding| binding["binding_id"].as_str())
        .collect();
    match matches.as_slice() {
        [id] => Ok(id.to_string()),
        [] => bail!(
            "no binding for {provider}:{repo_id} in project {}",
            project.trim()
        ),
        _ => bail!("multiple bindings for {provider}:{repo_id} (unexpected)"),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_provider;

    #[test]
    fn provider_names_normalize() {
        assert_eq!(normalize_provider("GitHub").unwrap(), "github");
        assert_eq!(normalize_provider("self_hosted").unwrap(), "self-hosted");
        assert!(normalize_provider("gitea").is_err());
    }
}
