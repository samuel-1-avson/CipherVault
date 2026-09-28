//! Dual-admin grant requests + project invite lifecycle (T-303 remainder).
//!
//! `ManageMembers` lets any admin grant directly — including the admin role
//! itself. This module closes the two gaps:
//!
//! * **Dual-admin grants.** Granting (or changing to) the admin role needs
//!   a second distinct admin's approval (four-eyes). `POST .../members`
//!   with `role=admin` opens a `grant_requests` row (202) instead of
//!   granting; `POST .../requests/:id/approve` by a *different* admin
//!   applies it. Self-approval is a 403, never a silent grant.
//! * **Invites.** Admins mint single-use, TTL-bound invite codes for
//!   principals without a grant yet. The code is shown once; only its
//!   SHA-256 is stored (mirroring account-plane invitations). Accepting
//!   binds the caller's session account. Invites cannot carry the admin
//!   role (enforced by CHECK) — newcomers earn admin through the
//!   dual-admin flow after joining.
//!
//! Expiry is lazy (no sweeper): reads flip past-TTL `pending` rows to
//! `expired`. Terminal states are never rewritten.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::policy::{
    authorize, grant_project_role, AuthTarget, ProjectRole, RequestAttributes, ScopedAction,
};
use crate::scope_tokens::ScopeClaims;
use crate::secrets::{audit_secret_event, SecretAuditEvent};
use crate::util::random_hex;

/// Grant-request TTL: 24h for the second admin to decide.
pub(crate) const GRANT_REQUEST_TTL_SECONDS: u64 = 24 * 3600;

/// Invite-code TTL: 72h for the invitee to accept.
pub(crate) const INVITE_TTL_SECONDS: u64 = 72 * 3600;

/// Grant/invite errors. `Denied`/`NotFound` surface as uniform 404 at the
/// route layer; `SelfApproval` is a 403 (the caller owns the request, so
/// hiding it would only confuse); `Expired` is a 410.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GrantError {
    #[error("access denied")]
    Denied,
    #[error("not found")]
    NotFound,
    #[error("invalid grant request: {0}")]
    Invalid(String),
    #[error("the requesting admin cannot approve their own request")]
    SelfApproval,
    #[error("request expired")]
    Expired,
    #[error("database error")]
    Db(#[from] rusqlite::Error),
}

/// One dual-admin grant request.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct GrantRequestView {
    pub request_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub principal_id: String,
    pub role: String,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub state: String,
    pub created_at_utc: u64,
    pub expires_at_utc: u64,
}

/// One project invite (never carries the code — shown once at creation).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct InviteView {
    pub invite_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub role: String,
    pub invited_by: String,
    pub state: String,
    pub created_at_utc: u64,
    pub expires_at_utc: u64,
    pub accepted_by: Option<String>,
}

fn member_target<'a>(tenant_id: &'a str, project_id: &'a str) -> AuthTarget<'a> {
    AuthTarget {
        tenant_id,
        project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    }
}

fn manage_members(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    tenant_id: &str,
    project_id: &str,
) -> Result<(), GrantError> {
    let target = member_target(tenant_id, project_id);
    authorize(db, claims, ScopedAction::ManageMembers, &target, attrs)
        .map_err(|_| GrantError::Denied)?;
    Ok(())
}

fn tenant_of(db: &Connection, project_id: &str) -> Result<Option<String>, rusqlite::Error> {
    db.query_row(
        "SELECT tenant_id FROM projects WHERE project_id = ?1",
        params![project_id],
        |row| row.get(0),
    )
    .optional()
}

#[allow(clippy::too_many_arguments)]
fn audit_grant(
    db: &Connection,
    event_type: &str,
    tenant_id: &str,
    project_id: &str,
    principal_id: &str,
    request_id: &str,
    reason: &str,
    now: u64,
) -> Result<(), GrantError> {
    audit_secret_event(
        db,
        &SecretAuditEvent {
            event_type,
            tenant_id,
            project_id: Some(project_id),
            environment_id: None,
            secret_id: None,
            secret_version: None,
            principal_id,
            request_id,
            source: "api",
            result: "success",
            reason,
        },
        now,
    )?;
    Ok(())
}

fn grant_request_from_row(row: &rusqlite::Row<'_>) -> Result<GrantRequestView, rusqlite::Error> {
    Ok(GrantRequestView {
        request_id: row.get(0)?,
        tenant_id: row.get(1)?,
        project_id: row.get(2)?,
        principal_id: row.get(3)?,
        role: row.get(4)?,
        requested_by: row.get(5)?,
        approved_by: row.get(6)?,
        state: row.get(7)?,
        created_at_utc: row.get::<_, i64>(8)? as u64,
        expires_at_utc: row.get::<_, i64>(9)? as u64,
    })
}

fn invite_from_row(row: &rusqlite::Row<'_>) -> Result<InviteView, rusqlite::Error> {
    Ok(InviteView {
        invite_id: row.get(0)?,
        tenant_id: row.get(1)?,
        project_id: row.get(2)?,
        role: row.get(3)?,
        invited_by: row.get(4)?,
        state: row.get(5)?,
        created_at_utc: row.get::<_, i64>(6)? as u64,
        expires_at_utc: row.get::<_, i64>(7)? as u64,
        accepted_by: row.get(8)?,
    })
}

/// Opens an admin-grant request (idempotent: a live `pending` request for
/// the same principal is returned instead of duplicated).
pub(crate) fn request_admin_grant(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    principal_id: &str,
    request_id: &str,
    now: u64,
) -> Result<GrantRequestView, GrantError> {
    let tenant = tenant_of(db, project_id)?.ok_or(GrantError::NotFound)?;
    manage_members(db, claims, attrs, &tenant, project_id)?;
    let principal = principal_id.trim();
    if principal.is_empty() {
        return Err(GrantError::Invalid(
            "principal_id must not be empty".to_string(),
        ));
    }
    if let Some(existing) = db
        .query_row(
            "SELECT request_id, tenant_id, project_id, principal_id, role, requested_by,
                    approved_by, state, created_at_utc, expires_at_utc
             FROM grant_requests
             WHERE project_id = ?1 AND principal_id = ?2 AND role = 'admin'
               AND state = 'pending' AND expires_at_utc > ?3
             ORDER BY created_at_utc LIMIT 1",
            params![project_id, principal, now as i64],
            grant_request_from_row,
        )
        .optional()?
    {
        return Ok(existing);
    }
    let id = format!("gr_{}", random_hex(8));
    db.execute(
        "INSERT INTO grant_requests(request_id, tenant_id, project_id, principal_id, role,
                                    requested_by, approved_by, state, created_at_utc,
                                    decided_at_utc, expires_at_utc)
         VALUES(?1, ?2, ?3, ?4, 'admin', ?5, NULL, 'pending', ?6, NULL, ?7)",
        params![
            id,
            tenant,
            project_id,
            principal,
            claims.principal_id,
            now as i64,
            (now + GRANT_REQUEST_TTL_SECONDS) as i64
        ],
    )?;
    let reason = serde_json::json!({"request_id": id, "principal_id": principal}).to_string();
    audit_grant(
        db,
        "membership.grant_requested",
        &tenant,
        project_id,
        &claims.principal_id,
        request_id,
        &reason,
        now,
    )?;
    Ok(GrantRequestView {
        request_id: id,
        tenant_id: tenant,
        project_id: project_id.to_string(),
        principal_id: principal.to_string(),
        role: "admin".to_string(),
        requested_by: claims.principal_id.clone(),
        approved_by: None,
        state: "pending".to_string(),
        created_at_utc: now,
        expires_at_utc: now + GRANT_REQUEST_TTL_SECONDS,
    })
}

/// Approves (`approve = true`, applies the grant) or rejects a request.
/// The approver must be an admin distinct from the requester.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decide_grant_request(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    request_id: &str,
    approve: bool,
    audit_request_id: &str,
    now: u64,
) -> Result<GrantRequestView, GrantError> {
    let tenant = tenant_of(db, project_id)?.ok_or(GrantError::NotFound)?;
    manage_members(db, claims, attrs, &tenant, project_id)?;
    let mut view = db
        .query_row(
            "SELECT request_id, tenant_id, project_id, principal_id, role, requested_by,
                    approved_by, state, created_at_utc, expires_at_utc
             FROM grant_requests WHERE request_id = ?1 AND project_id = ?2",
            params![request_id, project_id],
            grant_request_from_row,
        )
        .optional()?
        .ok_or(GrantError::NotFound)?;
    if view.state == "pending" && now > view.expires_at_utc {
        db.execute(
            "UPDATE grant_requests SET state = 'expired', decided_at_utc = ?2
             WHERE request_id = ?1",
            params![request_id, now as i64],
        )?;
        view.state = "expired".to_string();
        return Err(GrantError::Expired);
    }
    if view.state != "pending" {
        return Err(GrantError::Invalid(format!(
            "request is already {}",
            view.state
        )));
    }
    if claims.principal_id == view.requested_by {
        return Err(GrantError::SelfApproval);
    }
    if approve {
        db.execute(
            "UPDATE grant_requests SET state = 'approved', approved_by = ?2, decided_at_utc = ?3
             WHERE request_id = ?1",
            params![request_id, claims.principal_id, now as i64],
        )?;
        grant_project_role(
            db,
            project_id,
            &view.principal_id,
            ProjectRole::Admin,
            &claims.principal_id,
            now,
        )?;
        let reason = serde_json::json!({
            "principal_id": view.principal_id,
            "request_id": view.request_id,
            "approved_by": claims.principal_id,
        })
        .to_string();
        audit_grant(
            db,
            crate::audit_chain::AuditEventType::MembershipGranted.as_str(),
            &tenant,
            project_id,
            &claims.principal_id,
            audit_request_id,
            &reason,
            now,
        )?;
        view.state = "approved".to_string();
        view.approved_by = Some(claims.principal_id.clone());
    } else {
        db.execute(
            "UPDATE grant_requests SET state = 'rejected', approved_by = ?2, decided_at_utc = ?3
             WHERE request_id = ?1",
            params![request_id, claims.principal_id, now as i64],
        )?;
        let reason = serde_json::json!({
            "request_id": view.request_id,
            "principal_id": view.principal_id,
            "rejected_by": claims.principal_id,
        })
        .to_string();
        audit_grant(
            db,
            "membership.grant_rejected",
            &tenant,
            project_id,
            &claims.principal_id,
            audit_request_id,
            &reason,
            now,
        )?;
        view.state = "rejected".to_string();
    }
    Ok(view)
}

/// Lists a project's grant requests (lazy-expires past-TTL pendings).
pub(crate) fn list_grant_requests(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    now: u64,
) -> Result<Vec<GrantRequestView>, GrantError> {
    let tenant = tenant_of(db, project_id)?.ok_or(GrantError::NotFound)?;
    manage_members(db, claims, attrs, &tenant, project_id)?;
    db.execute(
        "UPDATE grant_requests SET state = 'expired', decided_at_utc = ?2
         WHERE project_id = ?1 AND state = 'pending' AND expires_at_utc <= ?2",
        params![project_id, now as i64],
    )?;
    let mut stmt = db.prepare(
        "SELECT request_id, tenant_id, project_id, principal_id, role, requested_by,
                approved_by, state, created_at_utc, expires_at_utc
         FROM grant_requests WHERE project_id = ?1 ORDER BY created_at_utc, rowid",
    )?;
    let rows: Vec<GrantRequestView> = stmt
        .query_map(params![project_id], grant_request_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Mints a single-use invite code (returned once; only the hash persists).
/// Admin role is rejected — newcomers join then earn admin via requests.
pub(crate) fn create_invite(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    role: ProjectRole,
    request_id: &str,
    now: u64,
) -> Result<(InviteView, String), GrantError> {
    if role == ProjectRole::Admin {
        return Err(GrantError::Invalid(
            "invites cannot carry the admin role; grant it via dual-admin request".to_string(),
        ));
    }
    let tenant = tenant_of(db, project_id)?.ok_or(GrantError::NotFound)?;
    manage_members(db, claims, attrs, &tenant, project_id)?;
    let id = format!("inv_{}", random_hex(8));
    let code = random_hex(16);
    let code_hash = hex::encode(Sha256::digest(code.as_bytes()));
    db.execute(
        "INSERT INTO project_invites(invite_id, tenant_id, project_id, role, invited_by,
                                     code_hash_hex, state, created_at_utc, expires_at_utc,
                                     accepted_by, decided_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, NULL, NULL)",
        params![
            id,
            tenant,
            project_id,
            role.as_str(),
            claims.principal_id,
            code_hash,
            now as i64,
            (now + INVITE_TTL_SECONDS) as i64
        ],
    )?;
    let reason = serde_json::json!({"invite_id": id, "role": role.as_str()}).to_string();
    audit_grant(
        db,
        "membership.invited",
        &tenant,
        project_id,
        &claims.principal_id,
        request_id,
        &reason,
        now,
    )?;
    Ok((
        InviteView {
            invite_id: id,
            tenant_id: tenant,
            project_id: project_id.to_string(),
            role: role.as_str().to_string(),
            invited_by: claims.principal_id.clone(),
            state: "pending".to_string(),
            created_at_utc: now,
            expires_at_utc: now + INVITE_TTL_SECONDS,
            accepted_by: None,
        },
        code,
    ))
}

/// Accepts an invite by code. The code is the capability (no project auth);
/// the grant binds the caller's session principal. Single-use.
pub(crate) fn accept_invite(
    db: &Connection,
    account_principal_id: &str,
    code: &str,
    request_id: &str,
    now: u64,
) -> Result<InviteView, GrantError> {
    let code_hash = hex::encode(Sha256::digest(code.trim().as_bytes()));
    let mut view = db
        .query_row(
            "SELECT invite_id, tenant_id, project_id, role, invited_by, state,
                    created_at_utc, expires_at_utc, accepted_by
             FROM project_invites WHERE code_hash_hex = ?1",
            params![code_hash],
            invite_from_row,
        )
        .optional()?
        .ok_or(GrantError::NotFound)?;
    if view.state == "pending" && now > view.expires_at_utc {
        db.execute(
            "UPDATE project_invites SET state = 'expired', decided_at_utc = ?2
             WHERE invite_id = ?1",
            params![view.invite_id, now as i64],
        )?;
        return Err(GrantError::Expired);
    }
    if view.state != "pending" {
        // Accepted/revoked codes read as not-found (no lifecycle oracle).
        return Err(GrantError::NotFound);
    }
    let role = ProjectRole::parse(&view.role)
        .ok_or_else(|| GrantError::Invalid("invite carries an unknown role".to_string()))?;
    db.execute(
        "UPDATE project_invites SET state = 'accepted', accepted_by = ?2, decided_at_utc = ?3
         WHERE invite_id = ?1",
        params![view.invite_id, account_principal_id, now as i64],
    )?;
    grant_project_role(
        db,
        &view.project_id,
        account_principal_id,
        role,
        &view.invited_by,
        now,
    )?;
    let reason = serde_json::json!({
        "principal_id": account_principal_id,
        "invite_id": view.invite_id,
    })
    .to_string();
    audit_grant(
        db,
        crate::audit_chain::AuditEventType::MembershipGranted.as_str(),
        &view.tenant_id,
        &view.project_id,
        account_principal_id,
        request_id,
        &reason,
        now,
    )?;
    view.state = "accepted".to_string();
    view.accepted_by = Some(account_principal_id.to_string());
    Ok(view)
}

/// Revokes a pending invite (accepted/revoked/expired are already terminal).
pub(crate) fn revoke_invite(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    invite_id: &str,
    request_id: &str,
    now: u64,
) -> Result<InviteView, GrantError> {
    let tenant = tenant_of(db, project_id)?.ok_or(GrantError::NotFound)?;
    manage_members(db, claims, attrs, &tenant, project_id)?;
    let mut view = db
        .query_row(
            "SELECT invite_id, tenant_id, project_id, role, invited_by, state,
                    created_at_utc, expires_at_utc, accepted_by
             FROM project_invites WHERE invite_id = ?1 AND project_id = ?2",
            params![invite_id, project_id],
            invite_from_row,
        )
        .optional()?
        .ok_or(GrantError::NotFound)?;
    if view.state != "pending" {
        return Err(GrantError::Invalid(format!(
            "invite is already {}",
            view.state
        )));
    }
    db.execute(
        "UPDATE project_invites SET state = 'revoked', decided_at_utc = ?2
         WHERE invite_id = ?1",
        params![invite_id, now as i64],
    )?;
    let reason = serde_json::json!({"invite_id": view.invite_id}).to_string();
    audit_grant(
        db,
        "membership.invite_revoked",
        &tenant,
        project_id,
        &claims.principal_id,
        request_id,
        &reason,
        now,
    )?;
    view.state = "revoked".to_string();
    Ok(view)
}

/// Lists a project's invites (views never carry codes; lazy-expires).
pub(crate) fn list_invites(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    now: u64,
) -> Result<Vec<InviteView>, GrantError> {
    let tenant = tenant_of(db, project_id)?.ok_or(GrantError::NotFound)?;
    manage_members(db, claims, attrs, &tenant, project_id)?;
    db.execute(
        "UPDATE project_invites SET state = 'expired', decided_at_utc = ?2
         WHERE project_id = ?1 AND state = 'pending' AND expires_at_utc <= ?2",
        params![project_id, now as i64],
    )?;
    let mut stmt = db.prepare(
        "SELECT invite_id, tenant_id, project_id, role, invited_by, state,
                created_at_utc, expires_at_utc, accepted_by
         FROM project_invites WHERE project_id = ?1 ORDER BY created_at_utc, rowid",
    )?;
    let rows: Vec<InviteView> = stmt
        .query_map(params![project_id], invite_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_format::{EnvironmentId, ProjectId, TenantId};

    use crate::policy::{grant_project_role, project_role_of};
    use crate::test_support::{cleanup, test_app};

    struct Fixture {
        tenant: String,
        project: String,
        #[allow(dead_code)]
        env: String,
        alice: ScopeClaims,
        dave: ScopeClaims,
        bob: ScopeClaims,
    }

    fn seed(db: &Connection) -> Fixture {
        let tenant = TenantId::generate().to_hex();
        let project = ProjectId::generate().to_hex();
        let env = EnvironmentId::generate().to_hex();
        db.execute(
            "INSERT INTO organizations(tenant_id, name, created_at_utc) VALUES(?1, 'Acme', 1)",
            params![tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO workspaces(workspace_id, tenant_id, name, created_at_utc)
             VALUES('w1', ?1, 'Platform', 1)",
            params![tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
             VALUES(?1, ?2, 'w1', 'payments', 'Payments', 1)",
            params![project, tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier,
                                       created_at_utc)
             VALUES(?1, ?2, ?3, 'staging', 1, 1)",
            params![env, tenant, project],
        )
        .unwrap();
        grant_project_role(db, &project, "account:alice", ProjectRole::Admin, "root", 1).unwrap();
        grant_project_role(db, &project, "account:dave", ProjectRole::Admin, "root", 1).unwrap();
        grant_project_role(
            db,
            &project,
            "account:bob",
            ProjectRole::Developer,
            "root",
            1,
        )
        .unwrap();
        let alice = ScopeClaims::new(&tenant, &project, "account:alice", 1000, 9_999_999_999);
        let dave = ScopeClaims::new(&tenant, &project, "account:dave", 1000, 9_999_999_999);
        let bob = ScopeClaims::new(&tenant, &project, "account:bob", 1000, 9_999_999_999);
        Fixture {
            tenant,
            project,
            env,
            alice,
            dave,
            bob,
        }
    }

    fn audit_types(db: &Connection) -> Vec<String> {
        let mut stmt = db
            .prepare("SELECT event_type FROM secret_access_events ORDER BY created_at_utc, rowid")
            .unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn admin_request_approve_applies_grant() {
        let (root, state, _app) = test_app("grants-approve");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let opened = request_admin_grant(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-1",
            100,
        )
        .unwrap();
        assert_eq!(opened.state, "pending");
        assert_eq!(opened.role, "admin");
        // Not a member until the second admin approves.
        assert!(project_role_of(&db, &fixture.project, "account:carol")
            .unwrap()
            .is_none());
        let decided = decide_grant_request(
            &db,
            &fixture.dave,
            &attrs,
            &fixture.project,
            &opened.request_id,
            true,
            "req-2",
            101,
        )
        .unwrap();
        assert_eq!(decided.state, "approved");
        assert_eq!(decided.approved_by.as_deref(), Some("account:dave"));
        assert_eq!(
            project_role_of(&db, &fixture.project, "account:carol").unwrap(),
            Some(ProjectRole::Admin)
        );
        let types = audit_types(&db);
        assert!(types.contains(&"membership.grant_requested".to_string()));
        assert!(types.contains(&"membership.granted".to_string()));
        cleanup(root);
    }

    #[test]
    fn self_approval_denied_request_survives() {
        let (root, state, _app) = test_app("grants-self");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let opened = request_admin_grant(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-1",
            100,
        )
        .unwrap();
        assert!(matches!(
            decide_grant_request(
                &db,
                &fixture.alice,
                &attrs,
                &fixture.project,
                &opened.request_id,
                true,
                "req-2",
                101,
            )
            .unwrap_err(),
            GrantError::SelfApproval
        ));
        // Still pending: the second admin can decide afterwards.
        let views = list_grant_requests(&db, &fixture.dave, &attrs, &fixture.project, 102).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].state, "pending");
        cleanup(root);
    }

    #[test]
    fn non_admin_cannot_request_or_decide() {
        let (root, state, _app) = test_app("grants-deny");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        assert!(matches!(
            request_admin_grant(
                &db,
                &fixture.bob,
                &attrs,
                &fixture.project,
                "account:carol",
                "req-1",
                100,
            )
            .unwrap_err(),
            GrantError::Denied
        ));
        let opened = request_admin_grant(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-1",
            100,
        )
        .unwrap();
        assert!(matches!(
            decide_grant_request(
                &db,
                &fixture.bob,
                &attrs,
                &fixture.project,
                &opened.request_id,
                true,
                "req-2",
                101,
            )
            .unwrap_err(),
            GrantError::Denied
        ));
        assert!(matches!(
            list_grant_requests(&db, &fixture.bob, &attrs, &fixture.project, 101).unwrap_err(),
            GrantError::Denied
        ));
        cleanup(root);
    }

    #[test]
    fn reject_is_terminal_and_allows_fresh_request() {
        let (root, state, _app) = test_app("grants-reject");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let opened = request_admin_grant(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-1",
            100,
        )
        .unwrap();
        let rejected = decide_grant_request(
            &db,
            &fixture.dave,
            &attrs,
            &fixture.project,
            &opened.request_id,
            false,
            "req-2",
            101,
        )
        .unwrap();
        assert_eq!(rejected.state, "rejected");
        assert!(matches!(
            decide_grant_request(
                &db,
                &fixture.dave,
                &attrs,
                &fixture.project,
                &opened.request_id,
                true,
                "req-3",
                102,
            )
            .unwrap_err(),
            GrantError::Invalid(_)
        ));
        // A fresh request after rejection gets a new id (no dedupe).
        let fresh = request_admin_grant(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-4",
            103,
        )
        .unwrap();
        assert_ne!(fresh.request_id, opened.request_id);
        assert!(audit_types(&db).contains(&"membership.grant_rejected".to_string()));
        cleanup(root);
    }

    #[test]
    fn pending_request_dedupes() {
        let (root, state, _app) = test_app("grants-dedupe");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let first = request_admin_grant(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-1",
            100,
        )
        .unwrap();
        let second = request_admin_grant(
            &db,
            &fixture.dave,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-2",
            101,
        )
        .unwrap();
        assert_eq!(first.request_id, second.request_id);
        cleanup(root);
    }

    #[test]
    fn expired_requests_fail_and_flip_on_list() {
        let (root, state, _app) = test_app("grants-expiry");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let opened = request_admin_grant(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-1",
            100,
        )
        .unwrap();
        let past = 100 + GRANT_REQUEST_TTL_SECONDS + 1;
        assert!(matches!(
            decide_grant_request(
                &db,
                &fixture.dave,
                &attrs,
                &fixture.project,
                &opened.request_id,
                true,
                "req-2",
                past,
            )
            .unwrap_err(),
            GrantError::Expired
        ));
        let views =
            list_grant_requests(&db, &fixture.alice, &attrs, &fixture.project, past).unwrap();
        assert_eq!(views[0].state, "expired");
        cleanup(root);
    }

    #[test]
    fn cross_project_request_ids_do_not_leak() {
        let (root, state, _app) = test_app("grants-xproject");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        // Second project in the same tenant; alice administers both.
        let project_b = ProjectId::generate().to_hex();
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
             VALUES(?1, ?2, 'w1', 'billing', 'Billing', 1)",
            params![project_b, fixture.tenant],
        )
        .unwrap();
        grant_project_role(
            &db,
            &project_b,
            "account:alice",
            ProjectRole::Admin,
            "root",
            1,
        )
        .unwrap();
        grant_project_role(
            &db,
            &project_b,
            "account:dave",
            ProjectRole::Admin,
            "root",
            1,
        )
        .unwrap();
        let opened = request_admin_grant(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            "account:carol",
            "req-1",
            100,
        )
        .unwrap();
        // Same id under another project reads as not-found (uniform 404).
        // Dave administers B too, so only the lookup (not authz) fails.
        let dave_b = ScopeClaims::new(
            &fixture.tenant,
            &project_b,
            "account:dave",
            1000,
            9_999_999_999,
        );
        assert!(matches!(
            decide_grant_request(
                &db,
                &dave_b,
                &attrs,
                &project_b,
                &opened.request_id,
                true,
                "req-2",
                101,
            )
            .unwrap_err(),
            GrantError::NotFound
        ));
        cleanup(root);
    }

    #[test]
    fn invite_create_accept_single_use() {
        let (root, state, _app) = test_app("grants-invite");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let (invite, code) = create_invite(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            ProjectRole::Developer,
            "req-1",
            100,
        )
        .unwrap();
        assert_eq!(invite.state, "pending");
        assert_eq!(code.len(), 32);
        // The code itself is never stored: only its hash persists.
        let stored: String = db
            .query_row(
                "SELECT code_hash_hex FROM project_invites WHERE invite_id = ?1",
                params![invite.invite_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(stored, code);
        assert_eq!(stored.len(), 64);
        let accepted = accept_invite(&db, "account:erin", &code, "req-2", 101).unwrap();
        assert_eq!(accepted.state, "accepted");
        assert_eq!(
            project_role_of(&db, &fixture.project, "account:erin").unwrap(),
            Some(ProjectRole::Developer)
        );
        // Single-use: replay reads as not-found; wrong codes too.
        assert!(matches!(
            accept_invite(&db, "account:mallory", &code, "req-3", 102).unwrap_err(),
            GrantError::NotFound
        ));
        assert!(matches!(
            accept_invite(
                &db,
                "account:mallory",
                "0".repeat(32).as_str(),
                "req-4",
                103
            )
            .unwrap_err(),
            GrantError::NotFound
        ));
        let types = audit_types(&db);
        assert!(types.contains(&"membership.invited".to_string()));
        assert!(types.contains(&"membership.granted".to_string()));
        cleanup(root);
    }

    #[test]
    fn invite_admin_rejected_revoke_and_expiry() {
        let (root, state, _app) = test_app("grants-invite-admin");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        assert!(matches!(
            create_invite(
                &db,
                &fixture.alice,
                &attrs,
                &fixture.project,
                ProjectRole::Admin,
                "req-1",
                100,
            )
            .unwrap_err(),
            GrantError::Invalid(_)
        ));
        let (invite, code) = create_invite(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            ProjectRole::Operator,
            "req-2",
            100,
        )
        .unwrap();
        let revoked = revoke_invite(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            &invite.invite_id,
            "req-3",
            101,
        )
        .unwrap();
        assert_eq!(revoked.state, "revoked");
        assert!(matches!(
            accept_invite(&db, "account:erin", &code, "req-4", 102).unwrap_err(),
            GrantError::NotFound
        ));
        // Non-admins cannot mint or revoke invites.
        assert!(matches!(
            create_invite(
                &db,
                &fixture.bob,
                &attrs,
                &fixture.project,
                ProjectRole::Developer,
                "req-5",
                103,
            )
            .unwrap_err(),
            GrantError::Denied
        ));
        let (invite2, _) = create_invite(
            &db,
            &fixture.alice,
            &attrs,
            &fixture.project,
            ProjectRole::Auditor,
            "req-6",
            100,
        )
        .unwrap();
        let past = 100 + INVITE_TTL_SECONDS + 1;
        assert!(matches!(
            accept_invite(&db, "account:erin", "f".repeat(32).as_str(), "req-7", past).unwrap_err(),
            GrantError::NotFound
        ));
        // Unknown code never flips anything; the real invite expires lazily.
        let views = list_invites(&db, &fixture.alice, &attrs, &fixture.project, past).unwrap();
        let expired = views
            .iter()
            .find(|view| view.invite_id == invite2.invite_id)
            .unwrap();
        assert_eq!(expired.state, "expired");
        assert!(audit_types(&db).contains(&"membership.invite_revoked".to_string()));
        cleanup(root);
    }
}
