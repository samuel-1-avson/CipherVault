//! Scope resolution for scoped-secret CLI commands (Phase 7, T-701).
//!
//! Precedence (§13): explicit flags > `CIPHERVAULT_PROJECT` /
//! `CIPHERVAULT_ENV` > `.ciphervault/context.json` > git-remote
//! auto-detection (project only). Unknown scope is always an error, never a
//! default; every resolution is echoed to stderr so operators see exactly
//! which scope acted. Server-side authorization still applies on every call.

use anyhow::{bail, Context, Result};
use reqwest::Client as HttpClient;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ciphervault_local_store::AccountStore;

use super::dpop::maybe_dpop;
use crate::commands::auth::hosted_endpoint_value;

pub(crate) fn resolve_endpoint(flag: Option<&str>) -> Result<String> {
    if let Some(raw) = flag.filter(|value| !value.trim().is_empty()) {
        return hosted_endpoint_value(raw);
    }
    if let Ok(raw) = std::env::var("CIPHERVAULT_ACCOUNT_ENDPOINT") {
        if !raw.trim().is_empty() {
            return hosted_endpoint_value(&raw);
        }
    }
    match AccountStore::open(None) {
        Ok(account) => match account
            .hosted_endpoint()
            .filter(|value| !value.trim().is_empty())
        {
            Some(raw) => hosted_endpoint_value(raw),
            None => {
                bail!("no account endpoint: pass --endpoint or set CIPHERVAULT_ACCOUNT_ENDPOINT")
            }
        },
        Err(_) => bail!("no account endpoint: pass --endpoint or set CIPHERVAULT_ACCOUNT_ENDPOINT"),
    }
}

pub(crate) fn resolve_token(flag: Option<&str>) -> Result<String> {
    if let Some(raw) = flag.filter(|value| !value.trim().is_empty()) {
        return Ok(raw.trim().to_string());
    }
    std::env::var("CIPHERVAULT_SCOPE_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
        .context("no scope token: pass --token or set CIPHERVAULT_SCOPE_TOKEN")
}

pub(crate) fn http_client() -> Result<HttpClient> {
    HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("ciphervault/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")
}

pub(crate) async fn checked_json(
    response: reqwest::Response,
    action: &str,
) -> Result<serde_json::Value> {
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    if status.is_success() {
        return Ok(body);
    }
    let code = body
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let error = body
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    if status == reqwest::StatusCode::NOT_FOUND {
        bail!("{action} failed (404 {code}): not found or access denied — {error}");
    }
    bail!("{action} failed ({status} {code}): {error}")
}

pub(crate) async fn api_get(
    client: &HttpClient,
    endpoint: &str,
    token: &str,
    path: &str,
    action: &str,
) -> Result<serde_json::Value> {
    let response = maybe_dpop(client.get(format!("{endpoint}{path}")), token)?
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("sending {action} request"))?;
    checked_json(response, action).await
}

/// Where one scope field resolved from (echoed with every resolution).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScopeSource {
    Flag,
    Env,
    File,
    Auto,
}

impl ScopeSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Env => "env",
            Self::File => "file",
            Self::Auto => "auto-detect",
        }
    }
}

/// Fully resolved scope: server-side IDs plus display slugs and sources.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedScope {
    pub project_id: String,
    pub project_slug: String,
    pub project_source: ScopeSource,
    pub env_id: Option<String>,
    pub env_slug: Option<String>,
    pub env_source: Option<ScopeSource>,
}

/// `.ciphervault/context.json` shape. Fields hold slugs or IDs.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub(crate) struct ContextFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
}

pub(crate) fn context_file_path(base: &Path) -> PathBuf {
    base.join(".ciphervault").join("context.json")
}

/// Reads the context file. Missing file is `Ok(None)`; malformed JSON is an
/// error (never silently ignored — it is explicit user configuration).
pub(crate) fn read_context_file_at(base: &Path) -> Result<Option<ContextFile>> {
    let path = context_file_path(base);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };
    serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} (fix or delete it)", path.display()))
        .map(Some)
}

/// Writes the context file. `None` clears that field; both `None` removes
/// the file (directory left in place).
pub(crate) fn write_context_file_at(
    base: &Path,
    project: Option<&str>,
    env: Option<&str>,
) -> Result<()> {
    let path = context_file_path(base);
    let clean = |value: Option<&str>| {
        value
            .map(str::trim)
            .filter(|trimmed| !trimmed.is_empty())
            .map(str::to_string)
    };
    let project = clean(project);
    let env = clean(env);
    if project.is_none() && env.is_none() {
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let file = ContextFile { project, env };
    let rendered = serde_json::to_string_pretty(&file).context("encoding scope context file")?;
    std::fs::write(&path, rendered).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|trimmed| !trimmed.is_empty())
        .map(str::to_string)
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|trimmed| !trimmed.is_empty())
}

/// Resolves project (ID or slug) then environment against the server.
/// `require_env` gates secret commands; project-level commands pass false.
pub(crate) async fn resolve_scope(
    client: &HttpClient,
    endpoint: &str,
    token: &str,
    project_flag: Option<&str>,
    env_flag: Option<&str>,
    require_env: bool,
) -> Result<ResolvedScope> {
    let file = read_context_file_at(Path::new("."))?;
    let (project_id, project_slug, project_source) =
        resolve_project(client, endpoint, token, project_flag, file.as_ref()).await?;
    let env_raw = non_empty(env_flag)
        .map(|raw| (raw, ScopeSource::Flag))
        .or_else(|| env_non_empty("CIPHERVAULT_ENV").map(|raw| (raw, ScopeSource::Env)))
        .or_else(|| {
            file.as_ref()
                .and_then(|file| file.env.clone())
                .map(|raw| raw.trim().to_string())
                .filter(|trimmed| !trimmed.is_empty())
                .map(|raw| (raw, ScopeSource::File))
        });
    let (env_id, env_slug, env_source) = match env_raw {
        Some((raw, source)) => {
            let (id, slug) = resolve_env_ref(client, endpoint, token, &project_id, &raw).await?;
            (Some(id), Some(slug), Some(source))
        }
        None if require_env => bail!(
            "no environment: pass --env, set CIPHERVAULT_ENV, or run `context set --env <slug>`"
        ),
        None => (None, None, None),
    };
    let scope = ResolvedScope {
        project_id,
        project_slug,
        project_source,
        env_id,
        env_slug,
        env_source,
    };
    echo_scope(&scope);
    Ok(scope)
}

async fn resolve_project(
    client: &HttpClient,
    endpoint: &str,
    token: &str,
    project_flag: Option<&str>,
    file: Option<&ContextFile>,
) -> Result<(String, String, ScopeSource)> {
    if let Some(raw) = non_empty(project_flag) {
        let (id, slug) = resolve_project_ref(client, endpoint, token, &raw).await?;
        return Ok((id, slug, ScopeSource::Flag));
    }
    if let Some(raw) = env_non_empty("CIPHERVAULT_PROJECT") {
        let (id, slug) = resolve_project_ref(client, endpoint, token, &raw).await?;
        return Ok((id, slug, ScopeSource::Env));
    }
    if let Some(raw) = file
        .and_then(|file| file.project.clone())
        .map(|raw| raw.trim().to_string())
        .filter(|trimmed| !trimmed.is_empty())
    {
        let (id, slug) = resolve_project_ref(client, endpoint, token, &raw).await?;
        return Ok((id, slug, ScopeSource::File));
    }
    match autodetect_project(client, endpoint, token).await? {
        Some((id, slug)) => Ok((id, slug, ScopeSource::Auto)),
        None => bail!(
            "no project: pass --project, set CIPHERVAULT_PROJECT, or run `project use <slug>`"
        ),
    }
}

async fn resolve_project_ref(
    client: &HttpClient,
    endpoint: &str,
    token: &str,
    raw: &str,
) -> Result<(String, String)> {
    let body = api_get(client, endpoint, token, "/v1/projects", "project list").await?;
    let entries = body["projects"]
        .as_array()
        .context("server returned a malformed project list")?;
    let matches: Vec<(&str, &str)> = entries
        .iter()
        .filter(|entry| {
            entry["project_id"].as_str() == Some(raw) || entry["slug"].as_str() == Some(raw)
        })
        .filter_map(|entry| Some((entry["project_id"].as_str()?, entry["slug"].as_str()?)))
        .collect();
    match matches.as_slice() {
        [(id, slug)] => Ok((id.to_string(), slug.to_string())),
        [] => bail!("unknown project '{raw}' (no membership or no such project)"),
        _ => bail!("ambiguous project '{raw}' across tenants; use the project ID"),
    }
}

async fn resolve_env_ref(
    client: &HttpClient,
    endpoint: &str,
    token: &str,
    project_id: &str,
    raw: &str,
) -> Result<(String, String)> {
    let body = api_get(
        client,
        endpoint,
        token,
        &format!("/v1/projects/{project_id}"),
        "project show",
    )
    .await?;
    let entries = body["environments"]
        .as_array()
        .context("server returned a malformed environment list")?;
    for entry in entries {
        if entry["environment_id"].as_str() == Some(raw) || entry["slug"].as_str() == Some(raw) {
            let id = entry["environment_id"].as_str().unwrap_or_default();
            let slug = entry["slug"].as_str().unwrap_or_default();
            return Ok((id.to_string(), slug.to_string()));
        }
    }
    bail!("unknown environment '{raw}' in this project")
}

/// Scope echo: every scoped command reports the resolved scope on stderr so
/// stdout stays parseable.
pub(crate) fn echo_scope(scope: &ResolvedScope) {
    match (&scope.env_slug, scope.env_source) {
        (Some(slug), Some(source)) => eprintln!(
            "scope: project={} ({}) env={} ({})",
            scope.project_slug,
            scope.project_source.as_str(),
            slug,
            source.as_str()
        ),
        _ => eprintln!(
            "scope: project={} ({})",
            scope.project_slug,
            scope.project_source.as_str()
        ),
    }
}

/// Priority-4 auto-detection: parse the git `origin` remote, then match
/// `(provider, full_name)` against the caller's project bindings. Returns
/// `None` when there is no git remote (caller errors with scope guidance);
/// multiple matches are an error (ambiguous candidates).
async fn autodetect_project(
    client: &HttpClient,
    endpoint: &str,
    token: &str,
) -> Result<Option<(String, String)>> {
    let Some((provider, repo_slug)) = git_origin_identity(Path::new(".")) else {
        return Ok(None);
    };
    let body = api_get(client, endpoint, token, "/v1/projects", "project list").await?;
    let entries = body["projects"]
        .as_array()
        .context("server returned a malformed project list")?;
    let mut candidates = Vec::new();
    for entry in entries {
        let (Some(id), Some(slug)) = (entry["project_id"].as_str(), entry["slug"].as_str()) else {
            continue;
        };
        let bindings = api_get(
            client,
            endpoint,
            token,
            &format!("/v1/projects/{id}/repositories"),
            "repository list",
        )
        .await?;
        let found = bindings["bindings"].as_array().is_some_and(|list| {
            list.iter().any(|binding| {
                binding["provider"].as_str() == Some(provider.as_str())
                    && binding["repo_full_name"].as_str() == Some(repo_slug.as_str())
            })
        });
        if found {
            candidates.push((id.to_string(), slug.to_string()));
        }
    }
    match candidates.as_slice() {
        [] => Ok(None),
        [(id, slug)] => Ok(Some((id.clone(), slug.clone()))),
        many => {
            let slugs: Vec<&str> = many.iter().map(|(_, slug)| slug.as_str()).collect();
            bail!(
                "git remote matches several projects ({}); pass --project",
                slugs.join(", ")
            )
        }
    }
}

/// Reads the `origin` remote URL from `.git/config` without shelling out.
fn git_origin_identity(base: &Path) -> Option<(String, String)> {
    let raw = std::fs::read_to_string(base.join(".git").join("config")).ok()?;
    let mut in_origin = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_origin = trimmed.starts_with("[remote")
                && trimmed
                    .strip_prefix("[remote")
                    .is_some_and(|rest| rest.contains("origin"));
            continue;
        }
        if in_origin {
            let Some((key, value)) = trimmed.split_once('=') else {
                continue;
            };
            if key.trim().eq_ignore_ascii_case("url") {
                return parse_remote_url(value.trim());
            }
        }
    }
    None
}

/// Parses a git remote URL into `(provider, owner/repo)`. Handles https,
/// ssh, and scp-like syntax for the known providers; unknown hosts yield
/// `None` (auto-detection skips them).
fn parse_remote_url(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim().trim_end_matches('/').trim_end_matches(".git");
    let (host, path) = if let Some(rest) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("ssh://"))
    {
        let rest = rest.split('@').next_back().unwrap_or(rest);
        let (host, path) = rest.split_once('/')?;
        (host.split(':').next()?, path)
    } else {
        let (_, rest) = trimmed.split_once('@')?;
        let (host, path) = rest.split_once(':')?;
        (host, path)
    };
    let provider = match host.to_ascii_lowercase().as_str() {
        "github.com" => "github",
        "gitlab.com" => "gitlab",
        "bitbucket.org" => "bitbucket",
        _ => return None,
    };
    // Full path (GitLab subgroups nest arbitrarily deep).
    let slug = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    if slug.split('/').count() < 2 {
        return None;
    }
    Some((provider.to_string(), slug))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_urls_parse_across_forms() {
        for raw in [
            "https://github.com/acme/payments-service.git",
            "https://github.com/acme/payments-service",
            "git@github.com:acme/payments-service.git",
            "ssh://git@github.com/acme/payments-service.git",
        ] {
            assert_eq!(
                parse_remote_url(raw),
                Some(("github".to_string(), "acme/payments-service".to_string())),
                "{raw}"
            );
        }
        assert_eq!(
            parse_remote_url("git@gitlab.com:acme/sub/payments.git"),
            Some(("gitlab".to_string(), "acme/sub/payments".to_string()))
        );
        assert_eq!(parse_remote_url("https://gitea.example/x/y.git"), None);
        assert_eq!(parse_remote_url("git@github.com:onlyone.git"), None);
        assert_eq!(parse_remote_url("not a url"), None);
    }

    fn unique_temp_base(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ciphervault_scope_test_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn context_file_roundtrip_and_clear() {
        let base = unique_temp_base("ctx");
        assert!(read_context_file_at(&base).unwrap().is_none());
        write_context_file_at(&base, Some("shop"), Some("staging")).unwrap();
        let file = read_context_file_at(&base).unwrap().unwrap();
        assert_eq!(file.project.as_deref(), Some("shop"));
        assert_eq!(file.env.as_deref(), Some("staging"));
        // Setting one field keeps the file; clearing both removes it.
        write_context_file_at(&base, Some("shop"), None).unwrap();
        let file = read_context_file_at(&base).unwrap().unwrap();
        assert!(file.env.is_none());
        write_context_file_at(&base, None, None).unwrap();
        assert!(read_context_file_at(&base).unwrap().is_none());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn malformed_context_file_errors() {
        let base = unique_temp_base("ctx-bad");
        std::fs::create_dir_all(base.join(".ciphervault")).unwrap();
        std::fs::write(context_file_path(&base), "{oops").unwrap();
        assert!(read_context_file_at(&base).is_err());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn git_origin_parses_without_subprocess() {
        let base = unique_temp_base("git");
        std::fs::create_dir_all(base.join(".git")).unwrap();
        std::fs::write(
            base.join(".git").join("config"),
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:acme/payments-service.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        )
        .unwrap();
        assert_eq!(
            git_origin_identity(&base),
            Some(("github".to_string(), "acme/payments-service".to_string()))
        );
        std::fs::remove_dir_all(&base).ok();
        assert!(git_origin_identity(&base).is_none());
    }
}
