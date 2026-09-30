//! Project catalog commands (Phase 7, T-701).
//!
//! `project list` shows the caller's memberships, `project show` resolves
//! one project (ID or slug) with its environments, and `project use`
//! pins the context file to a project. `use` always clears the pinned
//! environment: an env slug from another project must never leak across.

use anyhow::{Context, Result};

use super::scope::{api_get, http_client, resolve_endpoint, resolve_token, write_context_file_at};
use crate::ProjectSubcommand;

pub(crate) async fn cmd_project(sub: ProjectSubcommand) -> Result<()> {
    match sub {
        ProjectSubcommand::List { endpoint, token } => {
            let endpoint = resolve_endpoint(endpoint.as_deref())?;
            let token = resolve_token(token.as_deref())?;
            let client = http_client()?;
            let body = api_get(&client, &endpoint, &token, "/v1/projects", "project list").await?;
            let projects = body["projects"]
                .as_array()
                .context("server returned a malformed project list")?;
            if projects.is_empty() {
                println!("No project memberships.");
                return Ok(());
            }
            println!(
                "{:<34} {:<20} {:<28} {:<10}",
                "PROJECT ID", "SLUG", "NAME", "ROLE"
            );
            for project in projects {
                println!(
                    "{:<34} {:<20} {:<28} {:<10}",
                    project["project_id"].as_str().unwrap_or("?"),
                    project["slug"].as_str().unwrap_or("?"),
                    project["name"].as_str().unwrap_or("?"),
                    project["role"].as_str().unwrap_or("?")
                );
            }
            Ok(())
        }
        ProjectSubcommand::Show {
            project,
            endpoint,
            token,
        } => {
            let endpoint = resolve_endpoint(endpoint.as_deref())?;
            let token = resolve_token(token.as_deref())?;
            let client = http_client()?;
            let view = api_get(
                &client,
                &endpoint,
                &token,
                &format!("/v1/projects/{}", project.trim()),
                "project show",
            )
            .await?;
            println!("project_id: {}", view["project_id"].as_str().unwrap_or("?"));
            println!("slug: {}", view["slug"].as_str().unwrap_or("?"));
            println!("name: {}", view["name"].as_str().unwrap_or("?"));
            println!("status: {}", view["status"].as_str().unwrap_or("?"));
            println!("role: {}", view["role"].as_str().unwrap_or("?"));
            println!("environments:");
            let envs = view["environments"]
                .as_array()
                .context("server returned a malformed environment list")?;
            if envs.is_empty() {
                println!("  (none)");
            }
            for env in envs {
                println!(
                    "  {} ({}, tier {})",
                    env["slug"].as_str().unwrap_or("?"),
                    env["environment_id"].as_str().unwrap_or("?"),
                    env["tier"].as_i64().unwrap_or(0)
                );
            }
            Ok(())
        }
        ProjectSubcommand::Use {
            project,
            endpoint,
            token,
        } => {
            let endpoint = resolve_endpoint(endpoint.as_deref())?;
            let token = resolve_token(token.as_deref())?;
            let client = http_client()?;
            // Resolve first: only real, authorized projects enter the file.
            let view = api_get(
                &client,
                &endpoint,
                &token,
                &format!("/v1/projects/{}", project.trim()),
                "project show",
            )
            .await?;
            let slug = view["slug"].as_str().unwrap_or(project.trim());
            write_context_file_at(&crate::util::get_workspace_root()?, Some(slug), None)?;
            println!("Using project {slug} (environment cleared).");
            Ok(())
        }
    }
}
