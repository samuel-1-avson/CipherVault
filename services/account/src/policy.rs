//! Project authorization engine (Phase 3, T-301).
//!
//! Single choke point for scoped-secret authorization. Every secret route
//! (Phase 4) must call [`authorize`] before touching storage. Rules:
//! - Tenant/project match between token claims and target (fail closed).
//! - Environment targets require an equal token environment (no wildcards).
//! - Repository/service confinement: bound targets require the same binding.
//! - Explicit role→action permission table (non-linear: operators rotate but
//!   cannot create; auditors read metadata only).
//! - Production-tier environments (`tier >= 2`) additionally require the
//!   `main` branch or out-of-band elevation.
//! - Denials map to a uniform 404 (no existence oracle); the [`PolicyDenial`]
//!   reason stays server-side for audit.

use axum::http::StatusCode;
use axum::response::Response;
use rusqlite::{params, Connection, OptionalExtension};

use crate::http::error_response;
use crate::scope_tokens::ScopeClaims;

/// Project roles (see Deliverable E §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectRole {
    Admin,
    Developer,
    Operator,
    Auditor,
}

impl ProjectRole {
    /// Parses a stored role string; unknown values yield `None` (deny).
    pub fn parse(role: &str) -> Option<Self> {
        match role {
            "admin" => Some(Self::Admin),
            "developer" => Some(Self::Developer),
            "operator" => Some(Self::Operator),
            "auditor" => Some(Self::Auditor),
            _ => None,
        }
    }

    /// Canonical stored form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Developer => "developer",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
        }
    }
}

/// Actions on scoped resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopedAction {
    ReadMetadata,
    ReadValue,
    CreateSecret,
    UpdateMetadata,
    RotateSecret,
    MoveSecret,
    RebindSecret,
    DeleteSecret,
    ManageMembers,
    // Phase 6 (T-601): repository bindings and custom policy routes.
    #[allow(dead_code)]
    ManageBindings,
    #[allow(dead_code)]
    ManagePolicies,
    // Phase 8 (T-801): ledgered vault migration runs.
    ManageMigrations,
    // Phase 9 (T-901): audit-chain export for off-host shipping. Auditors
    // are allowed: the export carries digests and metadata, never values.
    ViewAudit,
}

/// What the caller wants to touch. Tenant and project are always required.
pub struct AuthTarget<'a> {
    pub tenant_id: &'a str,
    pub project_id: &'a str,
    pub environment_id: Option<&'a str>,
    pub repository_binding_id: Option<&'a str>,
    pub service_id: Option<&'a str>,
}

/// Request attributes for ABAC gates.
#[derive(Default)]
pub struct RequestAttributes {
    /// VCS branch of the caller when known (CI). `None` for human/API callers.
    pub branch: Option<String>,
    /// Step-up elevation obtained out-of-band (dual control / device auth).
    pub elevated: bool,
}

/// Machine-readable denial reasons. Server-side only — never serialized to
/// clients (see [`scoped_denial_response`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDenial {
    ScopeMismatch,
    EnvironmentMismatch,
    BindingMismatch,
    ServiceMismatch,
    NoGrant,
    RoleInsufficient,
    ProductionGate,
    UnknownEnvironment,
}

/// Explicit role→action permission table. Deliberately not a rank ladder:
/// operators may rotate (break-glass) but cannot create; auditors are
/// metadata-only.
pub(crate) fn role_allows(role: ProjectRole, action: ScopedAction) -> bool {
    use ProjectRole::{Admin, Auditor, Developer, Operator};
    use ScopedAction::{
        CreateSecret, DeleteSecret, ManageBindings, ManageMembers, ManageMigrations,
        ManagePolicies, MoveSecret, ReadMetadata, ReadValue, RebindSecret, RotateSecret,
        UpdateMetadata, ViewAudit,
    };
    match action {
        ReadMetadata => matches!(role, Admin | Developer | Operator | Auditor),
        ReadValue => matches!(role, Admin | Developer | Operator),
        CreateSecret | UpdateMetadata => matches!(role, Admin | Developer),
        RotateSecret => matches!(role, Admin | Developer | Operator),
        ViewAudit => matches!(role, Admin | Auditor),
        MoveSecret | RebindSecret | DeleteSecret | ManageMembers | ManageBindings
        | ManagePolicies | ManageMigrations => matches!(role, Admin),
    }
}

/// Active (non-revoked) project role for a principal, if any.
pub(crate) fn project_role_of(
    db: &Connection,
    project_id: &str,
    principal_id: &str,
) -> Result<Option<ProjectRole>, rusqlite::Error> {
    let role: Option<String> = db
        .query_row(
            "SELECT role FROM project_members
             WHERE project_id = ?1 AND principal_id = ?2 AND revoked_at_utc IS NULL",
            params![project_id, principal_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(role.as_deref().and_then(ProjectRole::parse))
}

/// Grants (or re-grants, clearing revocation) a project role.
pub(crate) fn grant_project_role(
    db: &Connection,
    project_id: &str,
    principal_id: &str,
    role: ProjectRole,
    granted_by: &str,
    now_utc: u64,
) -> Result<(), rusqlite::Error> {
    db.execute(
        "INSERT INTO project_members(project_id, principal_id, role, granted_by, granted_at_utc,
                                      revoked_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, NULL)
         ON CONFLICT(project_id, principal_id) DO UPDATE SET role = excluded.role,
            granted_by = excluded.granted_by, granted_at_utc = excluded.granted_at_utc,
            revoked_at_utc = NULL",
        params![project_id, principal_id, role.as_str(), granted_by, now_utc],
    )?;
    Ok(())
}

/// Revokes a project grant (audit-preserving timestamp, not a delete).
pub(crate) fn revoke_project_role(
    db: &Connection,
    project_id: &str,
    principal_id: &str,
    now_utc: u64,
) -> Result<(), rusqlite::Error> {
    db.execute(
        "UPDATE project_members SET revoked_at_utc = ?3
         WHERE project_id = ?1 AND principal_id = ?2 AND revoked_at_utc IS NULL",
        params![project_id, principal_id, now_utc],
    )?;
    Ok(())
}

fn environment_tier(db: &Connection, environment_id: &str) -> Result<Option<i64>, rusqlite::Error> {
    db.query_row(
        "SELECT tier FROM environments WHERE environment_id = ?1",
        params![environment_id],
        |row| row.get(0),
    )
    .optional()
}

/// Authorizes one action. Returns the caller's role on success; every failure
/// mode denies (fail closed, including database errors and unknown rows).
pub(crate) fn authorize(
    db: &Connection,
    claims: &ScopeClaims,
    action: ScopedAction,
    target: &AuthTarget<'_>,
    attrs: &RequestAttributes,
) -> Result<ProjectRole, PolicyDenial> {
    if claims.tenant_id != target.tenant_id || claims.project_id != target.project_id {
        return Err(PolicyDenial::ScopeMismatch);
    }
    match (claims.environment_id.as_deref(), target.environment_id) {
        (_, None) => {}
        (Some(have), Some(want)) if have == want => {}
        _ => return Err(PolicyDenial::EnvironmentMismatch),
    }
    if let Some(want) = target.repository_binding_id {
        if claims.repository_binding_id.as_deref() != Some(want) {
            return Err(PolicyDenial::BindingMismatch);
        }
    }
    if let Some(want) = target.service_id {
        if claims.service_id.as_deref() != Some(want) {
            return Err(PolicyDenial::ServiceMismatch);
        }
    }
    let role = project_role_of(db, target.project_id, &claims.principal_id)
        .map_err(|_| PolicyDenial::NoGrant)?;
    let Some(role) = role else {
        return Err(PolicyDenial::NoGrant);
    };
    if !role_allows(role, action) {
        return Err(PolicyDenial::RoleInsufficient);
    }
    if let Some(env_id) = target.environment_id {
        let tier = environment_tier(db, env_id).map_err(|_| PolicyDenial::UnknownEnvironment)?;
        match tier {
            None => return Err(PolicyDenial::UnknownEnvironment),
            Some(tier) if tier >= 2 => {
                let on_main = attrs.branch.as_deref() == Some("main");
                if !(on_main || attrs.elevated) {
                    return Err(PolicyDenial::ProductionGate);
                }
            }
            _ => {}
        }
    }
    Ok(role)
}

/// Uniform denial response: 404 with no existence signal (invariant 6).
pub(crate) fn scoped_denial_response() -> Response {
    error_response(StatusCode::NOT_FOUND, "NOT_FOUND", "Not found")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{cleanup, test_app};

    fn seed_project(db: &Connection) {
        db.execute(
            "INSERT INTO organizations(tenant_id, name, created_at_utc) VALUES('t1', 'Acme', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO workspaces(workspace_id, tenant_id, name, created_at_utc)
             VALUES('w1', 't1', 'Platform', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
             VALUES('p1', 't1', 'w1', 'payments', 'Payments', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
             VALUES('e-dev', 't1', 'p1', 'development', 0, 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
             VALUES('e-prod', 't1', 'p1', 'production', 2, 1)",
            [],
        )
        .unwrap();
    }

    fn claims_for(principal: &str, env: Option<&str>) -> ScopeClaims {
        let mut claims = ScopeClaims::new("t1", "p1", principal, 1000, 1900);
        if let Some(env) = env {
            claims = claims.with_environment(env);
        }
        claims
    }

    fn target(env: Option<&'static str>) -> AuthTarget<'static> {
        AuthTarget {
            tenant_id: "t1",
            project_id: "p1",
            environment_id: env,
            repository_binding_id: None,
            service_id: None,
        }
    }

    #[test]
    fn role_action_matrix() {
        use ProjectRole::{Admin, Auditor, Developer, Operator};
        use ScopedAction::{
            CreateSecret, DeleteSecret, ManageBindings, ManageMembers, ManageMigrations,
            ManagePolicies, MoveSecret, ReadMetadata, ReadValue, RebindSecret, RotateSecret,
            UpdateMetadata, ViewAudit,
        };
        // (action, admin, developer, operator, auditor)
        let matrix = [
            (ReadMetadata, true, true, true, true),
            (ReadValue, true, true, true, false),
            (CreateSecret, true, true, false, false),
            (UpdateMetadata, true, true, false, false),
            (RotateSecret, true, true, true, false),
            (MoveSecret, true, false, false, false),
            (RebindSecret, true, false, false, false),
            (DeleteSecret, true, false, false, false),
            (ManageMembers, true, false, false, false),
            (ManageBindings, true, false, false, false),
            (ManagePolicies, true, false, false, false),
            (ManageMigrations, true, false, false, false),
            (ViewAudit, true, false, false, true),
        ];
        for (action, admin, developer, operator, auditor) in matrix {
            assert_eq!(role_allows(Admin, action), admin, "{action:?} admin");
            assert_eq!(
                role_allows(Developer, action),
                developer,
                "{action:?} developer"
            );
            assert_eq!(
                role_allows(Operator, action),
                operator,
                "{action:?} operator"
            );
            assert_eq!(role_allows(Auditor, action), auditor, "{action:?} auditor");
        }
        // Non-linear spotlight: operators rotate but cannot create.
        assert!(role_allows(Operator, RotateSecret));
        assert!(!role_allows(Operator, CreateSecret));
        assert!(ProjectRole::parse("superuser").is_none());
    }

    #[test]
    fn grant_revoke_roundtrip() {
        let (root, state, _app) = test_app("policy-grants");
        let db = state.connection().unwrap();
        seed_project(&db);
        assert!(project_role_of(&db, "p1", "account:alice")
            .unwrap()
            .is_none());
        grant_project_role(
            &db,
            "p1",
            "account:alice",
            ProjectRole::Developer,
            "root",
            1,
        )
        .unwrap();
        assert_eq!(
            project_role_of(&db, "p1", "account:alice").unwrap(),
            Some(ProjectRole::Developer)
        );
        revoke_project_role(&db, "p1", "account:alice", 2).unwrap();
        assert!(project_role_of(&db, "p1", "account:alice")
            .unwrap()
            .is_none());
        // Re-grant clears the revocation.
        grant_project_role(&db, "p1", "account:alice", ProjectRole::Admin, "root", 3).unwrap();
        assert_eq!(
            project_role_of(&db, "p1", "account:alice").unwrap(),
            Some(ProjectRole::Admin)
        );
        cleanup(root);
    }

    #[test]
    fn authorize_scope_and_confinement() {
        let (root, state, _app) = test_app("policy-scope");
        let db = state.connection().unwrap();
        seed_project(&db);
        grant_project_role(
            &db,
            "p1",
            "account:alice",
            ProjectRole::Developer,
            "root",
            1,
        )
        .unwrap();
        let attrs = RequestAttributes::default();

        // Happy path: dev reads dev value.
        let role = authorize(
            &db,
            &claims_for("account:alice", Some("e-dev")),
            ScopedAction::ReadValue,
            &target(Some("e-dev")),
            &attrs,
        )
        .unwrap();
        assert_eq!(role, ProjectRole::Developer);

        // Tenant / project mismatch.
        let mut other_tenant = target(Some("e-dev"));
        other_tenant.tenant_id = "t2";
        assert_eq!(
            authorize(
                &db,
                &claims_for("account:alice", Some("e-dev")),
                ScopedAction::ReadValue,
                &other_tenant,
                &attrs
            ),
            Err(PolicyDenial::ScopeMismatch)
        );
        // Token env differs from target env.
        assert_eq!(
            authorize(
                &db,
                &claims_for("account:alice", Some("e-dev")),
                ScopedAction::ReadValue,
                &target(Some("e-prod")),
                &attrs
            ),
            Err(PolicyDenial::EnvironmentMismatch)
        );
        // Management token (no env) cannot touch an environment target.
        assert_eq!(
            authorize(
                &db,
                &claims_for("account:alice", None),
                ScopedAction::ReadValue,
                &target(Some("e-dev")),
                &attrs
            ),
            Err(PolicyDenial::EnvironmentMismatch)
        );
        // Repo / service confinement.
        let bound = AuthTarget {
            repository_binding_id: Some("b1"),
            ..target(Some("e-dev"))
        };
        assert_eq!(
            authorize(
                &db,
                &claims_for("account:alice", Some("e-dev")),
                ScopedAction::ReadValue,
                &bound,
                &attrs
            ),
            Err(PolicyDenial::BindingMismatch)
        );
        let claims = claims_for("account:alice", Some("e-dev")).with_repository_binding("b1");
        assert!(authorize(&db, &claims, ScopedAction::ReadValue, &bound, &attrs).is_ok());
        // Service confinement.
        let svc = AuthTarget {
            service_id: Some("svc1"),
            ..target(Some("e-dev"))
        };
        assert_eq!(
            authorize(
                &db,
                &claims_for("account:alice", Some("e-dev")),
                ScopedAction::ReadValue,
                &svc,
                &attrs
            ),
            Err(PolicyDenial::ServiceMismatch)
        );
        let claims = claims_for("account:alice", Some("e-dev")).with_service("svc1");
        assert!(authorize(&db, &claims, ScopedAction::ReadValue, &svc, &attrs).is_ok());
        // No grant at all.
        assert_eq!(
            authorize(
                &db,
                &claims_for("account:mallory", Some("e-dev")),
                ScopedAction::ReadValue,
                &target(Some("e-dev")),
                &attrs
            ),
            Err(PolicyDenial::NoGrant)
        );
        // Unknown environment row fails closed.
        assert_eq!(
            authorize(
                &db,
                &claims_for("account:alice", Some("e-ghost")),
                ScopedAction::ReadValue,
                &target(Some("e-ghost")),
                &attrs
            ),
            Err(PolicyDenial::UnknownEnvironment)
        );
        cleanup(root);
    }

    #[test]
    fn authorize_production_gate() {
        let (root, state, _app) = test_app("policy-prodgate");
        let db = state.connection().unwrap();
        seed_project(&db);
        grant_project_role(
            &db,
            "p1",
            "account:alice",
            ProjectRole::Developer,
            "root",
            1,
        )
        .unwrap();
        let claims = claims_for("account:alice", Some("e-prod"));

        // Dev tier: no gate regardless of branch.
        let dev_claims = claims_for("account:alice", Some("e-dev"));
        let feature = RequestAttributes {
            branch: Some("feature/x".to_string()),
            elevated: false,
        };
        assert!(authorize(
            &db,
            &dev_claims,
            ScopedAction::ReadValue,
            &target(Some("e-dev")),
            &feature
        )
        .is_ok());
        // Prod tier + feature branch: denied.
        assert_eq!(
            authorize(
                &db,
                &claims,
                ScopedAction::ReadValue,
                &target(Some("e-prod")),
                &feature
            ),
            Err(PolicyDenial::ProductionGate)
        );
        // Prod tier + main: allowed.
        let main = RequestAttributes {
            branch: Some("main".to_string()),
            elevated: false,
        };
        assert!(authorize(
            &db,
            &claims,
            ScopedAction::ReadValue,
            &target(Some("e-prod")),
            &main
        )
        .is_ok());
        // Prod tier + elevation (human step-up): allowed.
        let elevated = RequestAttributes {
            branch: None,
            elevated: true,
        };
        assert!(authorize(
            &db,
            &claims,
            ScopedAction::RotateSecret,
            &target(Some("e-prod")),
            &elevated
        )
        .is_ok());
        // Auditor cannot read values even on main.
        grant_project_role(&db, "p1", "account:aud", ProjectRole::Auditor, "root", 1).unwrap();
        let aud = claims_for("account:aud", Some("e-prod"));
        assert_eq!(
            authorize(
                &db,
                &aud,
                ScopedAction::ReadValue,
                &target(Some("e-prod")),
                &main
            ),
            Err(PolicyDenial::RoleInsufficient)
        );
        assert!(authorize(
            &db,
            &aud,
            ScopedAction::ReadMetadata,
            &target(Some("e-prod")),
            &main
        )
        .is_ok());
        cleanup(root);
    }

    #[test]
    fn denial_response_is_uniform_404() {
        let response = scoped_denial_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
