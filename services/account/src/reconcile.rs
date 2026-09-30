//! Binding reconciliation probe (Phase 6, T-601).
//!
//! Daily worker (§T8) that catches what webhooks miss: renames applied
//! while delivery was down, transferred/archived/deleted repos, and repos
//! that vanish from the provider. The worker runs server-side with full
//! scope (no caller claims); every change emits a hash-chained audit event
//! and is returned in the report so operators can page on drift.
//!
//! Provider access goes through [`ProviderClient`]. Real deployments wire
//! GitHub/GitLab API clients here; tests and offline environments use
//! [`FakeProviderClient`]. [`NoProviderClient`] is the honest seam: it fails
//! closed until a real client is configured.

#[cfg(test)]
use std::collections::{HashMap, HashSet};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::vcs::{
    audit_binding, transition, BindingEvent, BindingStatus, ProviderRepo, VcsError, VcsProvider,
};

/// Provider API surface needed for ownership proof and reconciliation.
/// Implementations must use least-scope installation tokens (report §Phase 6).
pub trait ProviderClient {
    /// Fetches the provider-side repository view. `Ok(None)` means the repo
    /// is not visible with the caller's token (deleted, transferred away,
    /// or token lost scope — the probe suspends, never revokes, on this).
    fn fetch_repo(
        &self,
        provider: VcsProvider,
        external_id: &str,
    ) -> Result<Option<ProviderRepo>, VcsError>;

    /// Verifies an installation token grants access to the repository.
    /// Must call the provider — never accept tokens offline.
    fn verify_installation(
        &self,
        provider: VcsProvider,
        installation_id: &str,
        token: &str,
        external_id: &str,
    ) -> Result<bool, VcsError>;
}

/// Test/offline provider fake backed by in-memory maps.
#[cfg(test)]
#[derive(Default)]
pub struct FakeProviderClient {
    repos: HashMap<(String, String), ProviderRepo>,
    valid_installations: HashSet<(String, String, String, String)>,
}

#[cfg(test)]
impl FakeProviderClient {
    pub fn with_repo(mut self, provider: VcsProvider, repo: ProviderRepo) -> Self {
        self.repos.insert(
            (provider.as_str().to_string(), repo.external_id.clone()),
            repo,
        );
        self
    }

    pub fn with_installation(
        mut self,
        provider: VcsProvider,
        installation_id: &str,
        token: &str,
        external_id: &str,
    ) -> Self {
        self.valid_installations.insert((
            provider.as_str().to_string(),
            installation_id.to_string(),
            token.to_string(),
            external_id.to_string(),
        ));
        self
    }
}

#[cfg(test)]
impl ProviderClient for FakeProviderClient {
    fn fetch_repo(
        &self,
        provider: VcsProvider,
        external_id: &str,
    ) -> Result<Option<ProviderRepo>, VcsError> {
        Ok(self
            .repos
            .get(&(provider.as_str().to_string(), external_id.to_string()))
            .cloned())
    }

    fn verify_installation(
        &self,
        provider: VcsProvider,
        installation_id: &str,
        token: &str,
        external_id: &str,
    ) -> Result<bool, VcsError> {
        Ok(self.valid_installations.contains(&(
            provider.as_str().to_string(),
            installation_id.to_string(),
            token.to_string(),
            external_id.to_string(),
        )))
    }
}

/// Fail-closed placeholder until a real provider API client is wired.
/// Routes use this, so ownership proof returns 503 (not a false accept)
/// when provider verification is unconfigured.
pub struct NoProviderClient;

impl ProviderClient for NoProviderClient {
    fn fetch_repo(
        &self,
        _provider: VcsProvider,
        _external_id: &str,
    ) -> Result<Option<ProviderRepo>, VcsError> {
        Err(VcsError::ProviderUnavailable)
    }

    fn verify_installation(
        &self,
        _provider: VcsProvider,
        _installation_id: &str,
        _token: &str,
        _external_id: &str,
    ) -> Result<bool, VcsError> {
        Err(VcsError::ProviderUnavailable)
    }
}

/// One probe finding. Serialized into operator reports and pages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ReconcileAction {
    Clean,
    SlugUpdated { old_slug: String, new_slug: String },
    Suspended { reason: String },
    Revoked { reason: String },
    SkippedRevoked,
}

/// Per-binding probe outcome. `dry_run` reports always have `applied: false`
/// and perform zero writes (still fetching provider state for the diff).
#[derive(Clone, Debug, Serialize)]
pub struct ReconcileReport {
    pub binding_id: String,
    pub dry_run: bool,
    pub applied: bool,
    pub actions: Vec<ReconcileAction>,
}

struct BindingRow {
    binding_id: String,
    tenant_id: String,
    project_id: String,
    provider: String,
    external_repo_id: String,
    full_name: String,
    url: String,
    status: String,
}

fn load_binding(db: &Connection, binding_id: &str) -> Result<Option<BindingRow>, VcsError> {
    db.query_row(
        "SELECT binding_id, tenant_id, project_id, provider, external_repo_id,
                repo_full_name, repo_url, status
         FROM repository_bindings WHERE binding_id = ?1",
        params![binding_id],
        |row| {
            Ok(BindingRow {
                binding_id: row.get(0)?,
                tenant_id: row.get(1)?,
                project_id: row.get(2)?,
                provider: row.get(3)?,
                external_repo_id: row.get(4)?,
                full_name: row.get(5)?,
                url: row.get(6)?,
                status: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(VcsError::Db)
}

/// Reconciles one binding against provider state.
#[allow(dead_code)] // TODO(operator): wire to the scheduled probe runner.
pub(crate) fn reconcile_binding(
    db: &Connection,
    client: &dyn ProviderClient,
    binding_id: &str,
    dry_run: bool,
    request_id: &str,
    now: u64,
) -> Result<ReconcileReport, VcsError> {
    let row = load_binding(db, binding_id)?.ok_or(VcsError::NotFound)?;
    if row.status == BindingStatus::Revoked.as_str() {
        return Ok(ReconcileReport {
            binding_id: row.binding_id,
            dry_run,
            applied: false,
            actions: vec![ReconcileAction::SkippedRevoked],
        });
    }
    let provider = VcsProvider::parse(&row.provider)?;
    let remote = client.fetch_repo(provider, &row.external_repo_id)?;
    let principal = format!("reconcile-probe:{}", provider.as_str());

    let mut actions = Vec::new();
    let mut set_status: Option<BindingStatus> = None;
    let mut set_display: Option<(String, String)> = None;
    let mut audit: Vec<(&str, String)> = Vec::new();

    match remote {
        None => {
            // Vanished: suspend (never revoke — may be a token-scope issue).
            let next = transition(
                BindingStatus::parse(&row.status)?,
                BindingEvent::Transferred,
            )?;
            if next.as_str() != row.status {
                set_status = Some(next);
            }
            let detail = "repository not visible at provider; suspended pending review";
            actions.push(ReconcileAction::Suspended {
                reason: detail.to_string(),
            });
            audit.push((
                "repository.drift",
                serde_json::json!({
                    "binding_id": row.binding_id,
                    "drift": "repo-vanished",
                    "actor": "reconcile-probe",
                })
                .to_string(),
            ));
        }
        Some(remote) => {
            if remote.deleted {
                transition(BindingStatus::parse(&row.status)?, BindingEvent::Deleted)?;
                set_status = Some(BindingStatus::Revoked);
                actions.push(ReconcileAction::Revoked {
                    reason: "provider confirms repository deleted".to_string(),
                });
                audit.push((
                    "repository.revoked",
                    serde_json::json!({
                        "binding_id": row.binding_id,
                        "actor": "reconcile-probe",
                    })
                    .to_string(),
                ));
            } else {
                if remote.archived {
                    let next =
                        transition(BindingStatus::parse(&row.status)?, BindingEvent::Archived)?;
                    if next.as_str() != row.status {
                        set_status = Some(next);
                    }
                    actions.push(ReconcileAction::Suspended {
                        reason: "provider repository archived".to_string(),
                    });
                }
                if remote.full_name != row.full_name || remote.url != row.url {
                    let old_slug = row.full_name.clone();
                    set_display = Some((remote.full_name.clone(), remote.url.clone()));
                    actions.push(ReconcileAction::SlugUpdated {
                        old_slug: old_slug.clone(),
                        new_slug: remote.full_name.clone(),
                    });
                    audit.push((
                        "repository.rebound",
                        serde_json::json!({
                            "binding_id": row.binding_id,
                            "old_slug": old_slug,
                            "new_slug": remote.full_name,
                            "actor": "reconcile-probe",
                        })
                        .to_string(),
                    ));
                }
                if !remote.archived && set_display.is_none() && set_status.is_none() {
                    actions.push(ReconcileAction::Clean);
                } else if set_display.is_some() || set_status.is_some() {
                    audit.push((
                        "repository.drift",
                        serde_json::json!({
                            "binding_id": row.binding_id,
                            "drift": "display-or-status",
                            "actor": "reconcile-probe",
                        })
                        .to_string(),
                    ));
                }
            }
        }
    }

    if !dry_run {
        if let Some((name, url)) = &set_display {
            db.execute(
                "UPDATE repository_bindings SET repo_full_name = ?2, repo_url = ?3
                 WHERE binding_id = ?1",
                params![row.binding_id, name, url],
            )?;
        }
        if let Some(next) = set_status {
            db.execute(
                "UPDATE repository_bindings SET status = ?2 WHERE binding_id = ?1",
                params![row.binding_id, next.as_str()],
            )?;
        }
        for (event_type, reason) in &audit {
            audit_binding(
                db,
                event_type,
                &row.tenant_id,
                &row.project_id,
                &principal,
                request_id,
                "reconcile-probe",
                "success",
                reason,
                now,
            )?;
        }
        db.execute(
            "UPDATE repository_bindings SET last_reconciled_at_utc = ?2 WHERE binding_id = ?1",
            params![row.binding_id, now],
        )?;
    }
    let applied = !dry_run && (!audit.is_empty() || set_display.is_some() || set_status.is_some());
    Ok(ReconcileReport {
        binding_id: row.binding_id,
        dry_run,
        applied,
        actions,
    })
}

/// Reconciles every binding of a project (revoked rows report
/// `SkippedRevoked`). Failures are per-binding: one provider error aborts
/// the run with the error (operators rerun; per-binding reports already
/// returned stay valid since each binding commits independently).
#[allow(dead_code)] // TODO(operator): wire to the scheduled probe runner.
pub(crate) fn reconcile_project(
    db: &Connection,
    client: &dyn ProviderClient,
    project_id: &str,
    dry_run: bool,
    request_id: &str,
    now: u64,
) -> Result<Vec<ReconcileReport>, VcsError> {
    let mut rows = db.prepare(
        "SELECT binding_id FROM repository_bindings WHERE project_id = ?1 ORDER BY binding_id",
    )?;
    let ids = rows
        .query_map(params![project_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut reports = Vec::with_capacity(ids.len());
    for id in &ids {
        reports.push(reconcile_binding(db, client, id, dry_run, request_id, now)?);
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{cleanup, test_app};

    fn seed_binding(db: &Connection, binding_id: &str, external_id: &str, status: &str) {
        db.execute(
            "INSERT OR IGNORE INTO organizations(tenant_id, name, created_at_utc)
             VALUES('t1', 'Acme', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT OR IGNORE INTO workspaces(workspace_id, tenant_id, name, created_at_utc)
             VALUES('w1', 't1', 'Platform', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT OR IGNORE INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
             VALUES('p1', 't1', 'w1', 'payments', 'Payments', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO repository_bindings(binding_id, tenant_id, project_id, provider,
                 external_repo_id, repo_full_name, repo_url, status, created_at_utc)
             VALUES(?1, 't1', 'p1', 'github', ?2, 'acme/payments-service',
                    'https://github.com/acme/payments-service', ?3, 1)",
            params![binding_id, external_id, status],
        )
        .unwrap();
    }

    fn binding_status(db: &Connection, binding_id: &str) -> (String, String, Option<i64>) {
        db.query_row(
            "SELECT status, repo_full_name, last_reconciled_at_utc
             FROM repository_bindings WHERE binding_id = ?1",
            params![binding_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    }

    fn audit_count(db: &Connection, event_type: &str) -> i64 {
        db.query_row(
            "SELECT COUNT(*) FROM secret_access_events WHERE event_type = ?1",
            params![event_type],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn remote_repo(external_id: &str, full_name: &str) -> ProviderRepo {
        ProviderRepo {
            external_id: external_id.to_string(),
            full_name: full_name.to_string(),
            url: format!("https://github.com/{full_name}"),
            archived: false,
            deleted: false,
        }
    }

    #[test]
    fn slug_drift_updates_display_and_audits() {
        let (root, state, _app) = test_app("reconcile-drift");
        let db = state.connection().unwrap();
        seed_binding(&db, "b1", "84920194", "active");
        let client = FakeProviderClient::default()
            .with_repo(VcsProvider::Github, remote_repo("84920194", "acme/v2"));
        let report = reconcile_binding(&db, &client, "b1", false, "req-1", 500).unwrap();
        assert!(report.applied);
        assert_eq!(report.actions.len(), 1);
        assert!(matches!(
            report.actions[0],
            ReconcileAction::SlugUpdated { .. }
        ));
        let (status, name, stamped) = binding_status(&db, "b1");
        assert_eq!(status, "active");
        assert_eq!(name, "acme/v2");
        assert_eq!(stamped, Some(500));
        assert_eq!(audit_count(&db, "repository.rebound"), 1);
        assert_eq!(audit_count(&db, "repository.drift"), 1);
        cleanup(root);
    }

    #[test]
    fn dry_run_reports_without_writes() {
        let (root, state, _app) = test_app("reconcile-dryrun");
        let db = state.connection().unwrap();
        seed_binding(&db, "b1", "84920194", "active");
        let client = FakeProviderClient::default()
            .with_repo(VcsProvider::Github, remote_repo("84920194", "acme/v2"));
        let report = reconcile_binding(&db, &client, "b1", true, "req-1", 500).unwrap();
        assert!(!report.applied);
        assert!(report.dry_run);
        assert!(!report.actions.is_empty());
        let (status, name, stamped) = binding_status(&db, "b1");
        assert_eq!(status, "active");
        assert_eq!(name, "acme/payments-service");
        assert_eq!(stamped, None);
        assert_eq!(audit_count(&db, "repository.rebound"), 0);
        cleanup(root);
    }

    #[test]
    fn vanished_repo_suspends_and_deleted_revokes() {
        let (root, state, _app) = test_app("reconcile-vanish");
        let db = state.connection().unwrap();
        seed_binding(&db, "b-vanish", "11", "active");
        seed_binding(&db, "b-del", "22", "active");
        let empty = FakeProviderClient::default();
        let report = reconcile_binding(&db, &empty, "b-vanish", false, "req-1", 500).unwrap();
        assert!(matches!(
            report.actions.as_slice(),
            [ReconcileAction::Suspended { .. }]
        ));
        assert_eq!(binding_status(&db, "b-vanish").0, "suspended");
        assert_eq!(audit_count(&db, "repository.drift"), 1);

        let deleted = ProviderRepo {
            deleted: true,
            ..remote_repo("22", "acme/payments-service")
        };
        let gone = FakeProviderClient::default().with_repo(VcsProvider::Github, deleted);
        let report = reconcile_binding(&db, &gone, "b-del", false, "req-2", 600).unwrap();
        assert!(matches!(
            report.actions.as_slice(),
            [ReconcileAction::Revoked { .. }]
        ));
        assert_eq!(binding_status(&db, "b-del").0, "revoked");
        assert_eq!(audit_count(&db, "repository.revoked"), 1);
        cleanup(root);
    }

    #[test]
    fn archived_suspends_clean_noops_revoked_skips() {
        let (root, state, _app) = test_app("reconcile-archive");
        let db = state.connection().unwrap();
        seed_binding(&db, "b-arch", "11", "active");
        seed_binding(&db, "b-clean", "22", "active");
        seed_binding(&db, "b-rev", "33", "revoked");
        let archived = ProviderRepo {
            archived: true,
            ..remote_repo("11", "acme/payments-service")
        };
        // b-arch and b-clean share the external id fixture shape, so probe
        // them in two runs: archived view first, then the clean view.
        let arch_client = FakeProviderClient::default().with_repo(VcsProvider::Github, archived);
        let report = reconcile_binding(&db, &arch_client, "b-arch", false, "req-1", 500).unwrap();
        assert!(matches!(
            report.actions.as_slice(),
            [ReconcileAction::Suspended { .. }]
        ));
        assert_eq!(binding_status(&db, "b-arch").0, "suspended");

        let clean_client = FakeProviderClient::default().with_repo(
            VcsProvider::Github,
            remote_repo("22", "acme/payments-service"),
        );
        let report = reconcile_binding(&db, &clean_client, "b-clean", false, "req-2", 600).unwrap();
        assert_eq!(report.actions, vec![ReconcileAction::Clean]);
        assert!(!report.applied);
        assert_eq!(binding_status(&db, "b-clean").2, Some(600));

        let report = reconcile_binding(&db, &clean_client, "b-rev", false, "req-3", 700).unwrap();
        assert_eq!(report.actions, vec![ReconcileAction::SkippedRevoked]);
        assert_eq!(binding_status(&db, "b-rev").2, None);
        cleanup(root);
    }

    #[test]
    fn fake_installations_verify_and_unconfigured_fails_closed() {
        let fake = FakeProviderClient::default().with_installation(
            VcsProvider::Github,
            "install-7",
            "token-abc",
            "84920194",
        );
        assert!(fake
            .verify_installation(VcsProvider::Github, "install-7", "token-abc", "84920194")
            .unwrap());
        assert!(!fake
            .verify_installation(VcsProvider::Github, "install-7", "wrong", "84920194")
            .unwrap());
        let none = NoProviderClient;
        assert!(none.fetch_repo(VcsProvider::Github, "84920194").is_err());
        assert!(none
            .verify_installation(VcsProvider::Github, "install-7", "token-abc", "84920194")
            .is_err());
    }

    #[test]
    fn project_run_covers_every_binding() {
        let (root, state, _app) = test_app("reconcile-project");
        let db = state.connection().unwrap();
        for (id, external) in [("b1", "11"), ("b2", "22")] {
            seed_binding(&db, id, external, "active");
        }
        let client = FakeProviderClient::default()
            .with_repo(
                VcsProvider::Github,
                ProviderRepo {
                    external_id: "11".to_string(),
                    full_name: "acme/payments-service".to_string(),
                    url: "https://github.com/acme/payments-service".to_string(),
                    archived: false,
                    deleted: false,
                },
            )
            .with_repo(
                VcsProvider::Github,
                ProviderRepo {
                    external_id: "22".to_string(),
                    full_name: "acme/other".to_string(),
                    url: "https://github.com/acme/other".to_string(),
                    archived: false,
                    deleted: false,
                },
            );
        let reports = reconcile_project(&db, &client, "p1", false, "req-1", 500).unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].actions, vec![ReconcileAction::Clean]);
        assert!(matches!(
            reports[1].actions.as_slice(),
            [ReconcileAction::SlugUpdated { .. }, ..]
        ));
        cleanup(root);
    }
}
