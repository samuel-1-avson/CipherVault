//! Project catalog reads (Phase 7, T-701).
//!
//! Lookup substrate for CLI scope resolution: list the caller's member
//! projects and resolve one project (by ID or slug) with its environments.
//! Slugs are tenant-scoped (`UNIQUE(tenant_id, slug)`); session callers
//! matching one slug in several tenants must disambiguate with the ID.
//! Non-members and unknown refs both surface as `NotFound` (uniform 404).

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

/// Project-service errors. `NotFound` covers unknown refs and non-members
/// alike (no existence oracle); `Ambiguous` tells session callers to use ID.
#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("project not found")]
    NotFound,
    #[error("ambiguous project reference: {0}")]
    Ambiguous(String),
    #[error("invalid project request: {0}")]
    Invalid(String),
    #[error("project database error: {0}")]
    Db(#[from] rusqlite::Error),
}

/// One membership row for [`list_projects`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectListEntry {
    pub project_id: String,
    pub tenant_id: String,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub role: String,
}

/// Environment summary for [`show_project`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnvironmentEntry {
    pub environment_id: String,
    pub slug: String,
    pub tier: i64,
}

/// Full project view for [`show_project`], including the caller's role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectView {
    pub project_id: String,
    pub tenant_id: String,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub role: String,
    pub environments: Vec<EnvironmentEntry>,
}

/// Lists live projects where `principal_id` holds an unrevoked membership.
/// `project_filter` (scope-token callers) confines the list to one project.
pub(crate) fn list_projects(
    db: &Connection,
    principal_id: &str,
    project_filter: Option<&str>,
) -> Result<Vec<ProjectListEntry>, ProjectError> {
    let mut sql = "SELECT p.project_id, p.tenant_id, p.slug, p.name, p.status, m.role
         FROM projects p JOIN project_members m ON m.project_id = p.project_id
         WHERE m.principal_id = ?1 AND m.revoked_at_utc IS NULL
           AND p.deleted_at_utc IS NULL"
        .to_string();
    if project_filter.is_some() {
        sql.push_str(" AND p.project_id = ?2");
    }
    sql.push_str(" ORDER BY p.slug, p.project_id");
    let mut rows = db.prepare(&sql)?;
    let entries = match project_filter {
        Some(filter) => rows
            .query_map(params![principal_id, filter], |row| {
                Ok(ProjectListEntry {
                    project_id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    slug: row.get(2)?,
                    name: row.get(3)?,
                    status: row.get(4)?,
                    role: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?,
        None => rows
            .query_map(params![principal_id], |row| {
                Ok(ProjectListEntry {
                    project_id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    slug: row.get(2)?,
                    name: row.get(3)?,
                    status: row.get(4)?,
                    role: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(entries)
}

/// Resolves `project_ref` (ID or slug) for `principal_id`. Token callers
/// pass their tenant as `tenant_hint` (slug lookup stays tenant-scoped);
/// session callers match across their memberships and fail closed on
/// ambiguity. The returned view carries live environments oldest-first.
pub(crate) fn show_project(
    db: &Connection,
    principal_id: &str,
    project_ref: &str,
    tenant_hint: Option<&str>,
) -> Result<ProjectView, ProjectError> {
    let reference = project_ref.trim();
    if reference.is_empty() || reference.len() > 256 {
        return Err(ProjectError::Invalid(
            "project reference must be 1-256 characters".to_string(),
        ));
    }
    // Exact ID match first: primary keys are globally unique.
    let by_id: Option<(String, String, String, String, String, String)> = db
        .query_row(
            "SELECT p.project_id, p.tenant_id, p.slug, p.name, p.status, m.role
             FROM projects p JOIN project_members m ON m.project_id = p.project_id
             WHERE p.project_id = ?1 AND m.principal_id = ?2
               AND m.revoked_at_utc IS NULL AND p.deleted_at_utc IS NULL",
            params![reference, principal_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    if let Some(found) = by_id {
        return view_with_environments(db, found);
    }
    // Slug match: tenant-scoped for tokens, membership-scoped for sessions.
    let mut rows = db.prepare(
        "SELECT p.project_id, p.tenant_id, p.slug, p.name, p.status, m.role
         FROM projects p JOIN project_members m ON m.project_id = p.project_id
         WHERE p.slug = ?1 AND m.principal_id = ?2
           AND m.revoked_at_utc IS NULL AND p.deleted_at_utc IS NULL
           AND (?3 IS NULL OR p.tenant_id = ?3)
         ORDER BY p.project_id",
    )?;
    let matches = rows
        .query_map(params![reference, principal_id, tenant_hint], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    match matches.as_slice() {
        [] => Err(ProjectError::NotFound),
        [found] => view_with_environments(db, found.clone()),
        many => Err(ProjectError::Ambiguous(format!(
            "'{reference}' matches {} projects; use the project ID",
            many.len()
        ))),
    }
}

fn view_with_environments(
    db: &Connection,
    found: (String, String, String, String, String, String),
) -> Result<ProjectView, ProjectError> {
    let (project_id, tenant_id, slug, name, status, role) = found;
    let mut rows = db.prepare(
        "SELECT environment_id, slug, tier FROM environments
         WHERE project_id = ?1 AND deleted_at_utc IS NULL
         ORDER BY created_at_utc, environment_id",
    )?;
    let environments = rows
        .query_map(params![project_id], |row| {
            Ok(EnvironmentEntry {
                environment_id: row.get(0)?,
                slug: row.get(1)?,
                tier: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProjectView {
        project_id,
        tenant_id,
        slug,
        name,
        status,
        role,
        environments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{grant_project_role, ProjectRole};
    use crate::test_support::{cleanup, test_app};

    fn seed_tenant(db: &Connection, tenant: &str, workspace: &str) {
        db.execute(
            "INSERT INTO organizations(tenant_id, name, created_at_utc) VALUES(?1, ?1, 1)",
            params![tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO workspaces(workspace_id, tenant_id, name, created_at_utc)
             VALUES(?1, ?2, ?1, 1)",
            params![workspace, tenant],
        )
        .unwrap();
    }

    fn seed_project(db: &Connection, tenant: &str, workspace: &str, project: &str, slug: &str) {
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
             VALUES(?1, ?2, ?3, ?4, ?4, 1)",
            params![project, tenant, workspace, slug],
        )
        .unwrap();
        for (env, tier) in [("staging", 1), ("production", 2)] {
            db.execute(
                "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
                 VALUES(?1, ?2, ?3, ?4, ?5, 1)",
                params![format!("{project}-{env}"), tenant, project, env, tier],
            )
            .unwrap();
        }
    }

    #[test]
    fn list_returns_memberships_with_roles() {
        let (root, state, _app) = test_app("projects-list");
        let db = state.connection().unwrap();
        seed_tenant(&db, "t1", "w1");
        seed_project(&db, "t1", "w1", "p1", "shop");
        seed_project(&db, "t1", "w1", "p2", "blog");
        grant_project_role(
            &db,
            "p1",
            "account:alice",
            ProjectRole::Admin,
            "bootstrap",
            1,
        )
        .unwrap();
        grant_project_role(
            &db,
            "p2",
            "account:alice",
            ProjectRole::Developer,
            "bootstrap",
            1,
        )
        .unwrap();

        let entries = list_projects(&db, "account:alice", None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].slug, "blog");
        assert_eq!(entries[0].role, "developer");
        assert_eq!(entries[1].slug, "shop");
        assert_eq!(entries[1].role, "admin");
        // Token confinement: only the token's own project.
        let entries = list_projects(&db, "account:alice", Some("p1")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].project_id, "p1");
        // Strangers see nothing (no oracle).
        assert!(list_projects(&db, "account:mallory", None)
            .unwrap()
            .is_empty());
        assert!(list_projects(&db, "account:mallory", Some("p1"))
            .unwrap()
            .is_empty());
        cleanup(root);
    }

    #[test]
    fn show_resolves_id_or_slug_with_environments() {
        let (root, state, _app) = test_app("projects-show");
        let db = state.connection().unwrap();
        seed_tenant(&db, "t1", "w1");
        seed_project(&db, "t1", "w1", "p1", "shop");
        grant_project_role(
            &db,
            "p1",
            "account:alice",
            ProjectRole::Admin,
            "bootstrap",
            1,
        )
        .unwrap();

        let by_id = show_project(&db, "account:alice", "p1", None).unwrap();
        assert_eq!(by_id.slug, "shop");
        assert_eq!(by_id.role, "admin");
        assert_eq!(by_id.environments.len(), 2);
        assert_eq!(by_id.environments[0].slug, "production");
        assert_eq!(by_id.environments[1].slug, "staging");
        assert_eq!(by_id.environments[1].tier, 1);
        let by_slug = show_project(&db, "account:alice", "shop", Some("t1")).unwrap();
        assert_eq!(by_slug, by_id);
        // Non-members and ghosts share one answer.
        assert!(matches!(
            show_project(&db, "account:mallory", "p1", None),
            Err(ProjectError::NotFound)
        ));
        assert!(matches!(
            show_project(&db, "account:alice", "ghost", Some("t1")),
            Err(ProjectError::NotFound)
        ));
        // Empty refs rejected, never defaulted.
        assert!(matches!(
            show_project(&db, "account:alice", "  ", Some("t1")),
            Err(ProjectError::Invalid(_))
        ));
        cleanup(root);
    }

    #[test]
    fn show_fails_closed_on_cross_tenant_slug_collision() {
        let (root, state, _app) = test_app("projects-ambiguous");
        let db = state.connection().unwrap();
        seed_tenant(&db, "t1", "w1");
        seed_tenant(&db, "t2", "w2");
        seed_project(&db, "t1", "w1", "p1", "shop");
        seed_project(&db, "t2", "w2", "p2", "shop");
        grant_project_role(
            &db,
            "p1",
            "account:alice",
            ProjectRole::Admin,
            "bootstrap",
            1,
        )
        .unwrap();
        grant_project_role(
            &db,
            "p2",
            "account:alice",
            ProjectRole::Admin,
            "bootstrap",
            1,
        )
        .unwrap();

        // Session (no tenant hint): ambiguous across tenants.
        let err = show_project(&db, "account:alice", "shop", None).unwrap_err();
        assert!(matches!(err, ProjectError::Ambiguous(_)));
        // Token (tenant hint): scoped to one tenant.
        let view = show_project(&db, "account:alice", "shop", Some("t2")).unwrap();
        assert_eq!(view.project_id, "p2");
        // IDs stay globally unique.
        let view = show_project(&db, "account:alice", "p1", None).unwrap();
        assert_eq!(view.tenant_id, "t1");
        cleanup(root);
    }
}
