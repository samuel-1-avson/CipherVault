//! Repository (VCS) bindings (Phase 6, T-601).
//!
//! Binds immutable provider repository IDs — never slugs — to projects, so a
//! rename or transfer never breaks secret references (Workflow E). Binding
//! lifecycle runs through the [`BindingStatus`] state machine
//! (`active → suspended → revoked` per §T8); suspended bindings deny new
//! grants but preserve reads of already-bound secrets for break-glass.
//!
//! Ownership proof is provider-mediated: whoever binds presents a provider
//! installation token, verified through [`ProviderClient`]. Real deployments
//! wire GitHub/GitLab API clients; tests use the fake in
//! [`crate::reconcile`]. Webhook payloads authenticate via per-binding keys
//! derived from one server master secret (no new columns needed).

use ring::hmac::{self, Key, HMAC_SHA256};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::audit_chain::AuditEventType;
use crate::policy::{authorize, AuthTarget, RequestAttributes, ScopedAction};
use crate::reconcile::ProviderClient;
use crate::scope_tokens::ScopeClaims;
use crate::secrets::{audit_secret_event, SecretAuditEvent};
use crate::util::random_hex;

pub(crate) const VCS_WEBHOOK_KEY_ENV: &str = "CIPHERVAULT_VCS_WEBHOOK_KEY";
pub(crate) const VCS_WEBHOOK_KEY_FILE_ENV: &str = "CIPHERVAULT_VCS_WEBHOOK_KEY_FILE";

const SQLITE_CONSTRAINT_UNIQUE: i32 = 2067;
const WEBHOOK_MAC_DOMAIN: &[u8] = b"cv-vcs-webhook-v1";
const MAX_NAME_LEN: usize = 256;
const MAX_URL_LEN: usize = 2048;
const MAX_EXTERNAL_ID_LEN: usize = 128;

/// Binding-service errors. `Denied` and `NotFound` both surface as a uniform
/// 404 at the route layer (no existence oracle).
#[derive(Debug, thiserror::Error)]
pub enum VcsError {
    #[error("repository binding not found")]
    NotFound,
    #[error("repository already bound to this project")]
    Conflict,
    #[error("access denied")]
    Denied,
    #[error("invalid binding request: {0}")]
    Invalid(String),
    #[error("binding is revoked and cannot transition")]
    Terminal,
    #[error("vcs webhook signing key is not configured")]
    Unconfigured,
    #[error("vcs provider error: {0}")]
    Provider(String),
    #[error("binding database error: {0}")]
    Db(#[from] rusqlite::Error),
}

/// Supported VCS providers. External IDs are always provider-immutable:
/// numeric repository IDs for GitHub/GitLab, `workspace/slug` for Bitbucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcsProvider {
    Github,
    Gitlab,
    Bitbucket,
    SelfHosted,
}

impl VcsProvider {
    pub fn parse(raw: &str) -> Result<Self, VcsError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "github" => Ok(Self::Github),
            "gitlab" => Ok(Self::Gitlab),
            "bitbucket" => Ok(Self::Bitbucket),
            "self-hosted" | "self_hosted" => Ok(Self::SelfHosted),
            other => Err(VcsError::Invalid(format!("unknown VCS provider '{other}'"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Bitbucket => "bitbucket",
            Self::SelfHosted => "self-hosted",
        }
    }

    /// Validates a provider-shaped immutable external ID.
    pub fn validate_external_id(self, id: &str) -> Result<(), VcsError> {
        let trimmed = id.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_EXTERNAL_ID_LEN {
            return Err(VcsError::Invalid(
                "external repository id must be 1-128 characters".to_string(),
            ));
        }
        let ok = match self {
            Self::Github | Self::Gitlab => {
                !trimmed.is_empty()
                    && trimmed.len() <= 20
                    && trimmed.bytes().all(|b| b.is_ascii_digit())
            }
            Self::Bitbucket => {
                let mut parts = trimmed.split('/');
                matches!(
                    (parts.next(), parts.next(), parts.next()),
                    (Some(workspace), Some(slug), None)
                        if !workspace.is_empty()
                            && !slug.is_empty()
                            && trimmed.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/')
                            })
                )
            }
            Self::SelfHosted => trimmed.bytes().all(|b| !b.is_ascii_whitespace()),
        };
        if ok {
            Ok(())
        } else {
            Err(VcsError::Invalid(format!(
                "malformed external repository id for provider '{}'",
                self.as_str()
            )))
        }
    }
}

/// Binding lifecycle state (§T8). `suspended` denies new grants; `revoked` is
/// terminal and absorbs further events as no-ops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingStatus {
    Active,
    Suspended,
    Revoked,
}

impl BindingStatus {
    pub fn parse(raw: &str) -> Result<Self, VcsError> {
        match raw {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "revoked" => Ok(Self::Revoked),
            other => Err(VcsError::Invalid(format!(
                "unknown binding status '{other}'"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }
}

/// Events that drive the binding state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingEvent {
    Renamed,
    Transferred,
    Archived,
    Deleted,
    OwnershipProved,
    AdminSuspend,
    AdminRevoke,
    AdminReactivate,
}

/// Pure state-machine transition. Rename never changes status (display-only
/// update); transfer/archive suspend; delete revokes; only a fresh ownership
/// proof activates a suspended binding, and admin reactivation only
/// un-revokes back to suspended (never bypasses the proof).
pub fn transition(status: BindingStatus, event: BindingEvent) -> Result<BindingStatus, VcsError> {
    use BindingEvent::{
        AdminReactivate, AdminRevoke, AdminSuspend, Archived, Deleted, OwnershipProved, Renamed,
        Transferred,
    };
    use BindingStatus::{Active, Revoked, Suspended};
    match (status, event) {
        (Revoked, AdminRevoke) => Ok(Revoked),
        (Revoked, AdminReactivate) => Ok(Suspended),
        (Revoked, _) => Err(VcsError::Terminal),
        (Active, Renamed) => Ok(Active),
        (Active, Transferred | Archived | AdminSuspend) => Ok(Suspended),
        (Active, Deleted | AdminRevoke) => Ok(Revoked),
        (Active, OwnershipProved | AdminReactivate) => Ok(Active),
        (Suspended, Renamed | Transferred | Archived | AdminSuspend | AdminReactivate) => {
            Ok(Suspended)
        }
        (Suspended, Deleted | AdminRevoke) => Ok(Revoked),
        (Suspended, OwnershipProved) => Ok(Active),
    }
}

/// Provider-side repository view returned by [`ProviderClient`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRepo {
    pub external_id: String,
    pub full_name: String,
    pub url: String,
    pub archived: bool,
    pub deleted: bool,
}

/// Public binding view (safe to serialize; no challenges or key material).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BindingView {
    pub binding_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub provider: String,
    pub external_repo_id: String,
    pub repo_full_name: String,
    pub repo_url: String,
    pub installation_id: Option<String>,
    pub status: String,
    pub ownership_verified_at_utc: Option<i64>,
    pub last_reconciled_at_utc: Option<i64>,
    pub created_at_utc: i64,
}

/// Outcome of [`bind_repository`]: the suspended binding, the single-use
/// ownership challenge the installer must prove, and the webhook secret
/// (shown once) to configure at the provider.
#[derive(Clone, Debug, Serialize)]
pub struct BindOutcome {
    pub binding: BindingView,
    pub ownership_challenge: String,
    pub webhook_secret: String,
}

/// Parameters for [`bind_repository`].
pub struct BindRepository<'a> {
    pub provider: &'a str,
    pub external_repo_id: &'a str,
    pub repo_full_name: &'a str,
    pub repo_url: &'a str,
    pub installation_id: Option<&'a str>,
    pub request_id: &'a str,
}

fn map_constraint(err: rusqlite::Error) -> VcsError {
    if let rusqlite::Error::SqliteFailure(failure, _) = &err {
        if failure.extended_code == SQLITE_CONSTRAINT_UNIQUE {
            return VcsError::Conflict;
        }
    }
    VcsError::Db(err)
}

fn validate_display_name(raw: &str) -> Result<String, VcsError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_NAME_LEN {
        return Err(VcsError::Invalid(
            "repository full name must be 1-256 characters".to_string(),
        ));
    }
    if trimmed.bytes().any(|b| b.is_ascii_control()) {
        return Err(VcsError::Invalid(
            "repository full name must not contain control characters".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_repo_url(raw: &str) -> Result<String, VcsError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LEN {
        return Err(VcsError::Invalid(
            "repository URL must be 1-2048 characters".to_string(),
        ));
    }
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return Err(VcsError::Invalid(
            "repository URL must start with http:// or https://".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn project_tenant(db: &Connection, project_id: &str) -> Result<Option<String>, VcsError> {
    db.query_row(
        "SELECT tenant_id FROM projects WHERE project_id = ?1 AND deleted_at_utc IS NULL",
        params![project_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(VcsError::Db)
}

fn view_from_row(row: &rusqlite::Row<'_>) -> Result<BindingView, rusqlite::Error> {
    Ok(BindingView {
        binding_id: row.get(0)?,
        tenant_id: row.get(1)?,
        project_id: row.get(2)?,
        provider: row.get(3)?,
        external_repo_id: row.get(4)?,
        repo_full_name: row.get(5)?,
        repo_url: row.get(6)?,
        installation_id: row.get(7)?,
        status: row.get(8)?,
        ownership_verified_at_utc: row.get(9)?,
        last_reconciled_at_utc: row.get(10)?,
        created_at_utc: row.get(11)?,
    })
}

const BINDING_COLUMNS: &str = "binding_id, tenant_id, project_id, provider,
    external_repo_id, repo_full_name, repo_url, installation_id, status,
    ownership_verified_at_utc, last_reconciled_at_utc, created_at_utc";

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_binding(
    db: &Connection,
    event_type: &str,
    tenant_id: &str,
    project_id: &str,
    principal_id: &str,
    request_id: &str,
    source: &str,
    result: &str,
    reason: &str,
    now: u64,
) -> Result<(), VcsError> {
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
            source,
            result,
            reason,
        },
        now,
    )
    .map_err(VcsError::Db)
}

/// Creates a binding in `suspended` state. The returned challenge must be
/// proven via [`prove_ownership`] before the binding gates any grants.
pub(crate) fn bind_repository(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    input: &BindRepository<'_>,
    now: u64,
) -> Result<BindOutcome, VcsError> {
    let provider = VcsProvider::parse(input.provider)?;
    provider.validate_external_id(input.external_repo_id)?;
    let full_name = validate_display_name(input.repo_full_name)?;
    let url = validate_repo_url(input.repo_url)?;
    if let Some(installation) = input.installation_id {
        if installation.trim().is_empty() || installation.len() > MAX_NAME_LEN {
            return Err(VcsError::Invalid(
                "installation id must be 1-256 characters".to_string(),
            ));
        }
    }
    let tenant = project_tenant(db, project_id)?.ok_or(VcsError::NotFound)?;
    if tenant != claims.tenant_id {
        return Err(VcsError::Denied);
    }
    let target = AuthTarget {
        tenant_id: &tenant,
        project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    authorize(db, claims, ScopedAction::ManageBindings, &target, attrs)
        .map_err(|_| VcsError::Denied)?;
    // Fail closed (§T8): a binding that cannot receive verified webhooks
    // cannot detect transfer/delete, so bind requires the master secret.
    let master = webhook_signing_key()?;

    let binding_id = random_hex(16);
    let challenge = random_hex(16);
    db.execute(
        "INSERT INTO repository_bindings(binding_id, tenant_id, project_id, provider,
             external_repo_id, repo_full_name, repo_url, installation_id, status,
             ownership_challenge, created_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'suspended', ?9, ?10)",
        params![
            binding_id,
            tenant,
            project_id,
            provider.as_str(),
            input.external_repo_id.trim(),
            full_name,
            url,
            input.installation_id.map(str::trim),
            challenge,
            now,
        ],
    )
    .map_err(map_constraint)?;
    let reason = serde_json::json!({
        "binding_id": binding_id,
        "provider": provider.as_str(),
        "external_repo_id": input.external_repo_id.trim(),
    })
    .to_string();
    audit_binding(
        db,
        AuditEventType::RepositoryBound.as_str(),
        &tenant,
        project_id,
        &claims.principal_id,
        input.request_id,
        "api",
        "success",
        &reason,
        now,
    )?;
    let binding = get_binding(db, claims, attrs, &binding_id)?;
    let webhook_secret = hex::encode(webhook_key_for(&master, &binding_id));
    Ok(BindOutcome {
        binding,
        ownership_challenge: challenge,
        webhook_secret,
    })
}

/// Completes ownership proof: the installer presents the provider
/// installation token, verified through `client`. Success activates a
/// suspended binding; revoked bindings stay terminal.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_ownership(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    binding_id: &str,
    installation_id: &str,
    installation_token: &str,
    client: &dyn ProviderClient,
    request_id: &str,
    now: u64,
) -> Result<BindingView, VcsError> {
    let view = get_binding(db, claims, attrs, binding_id)?;
    let target = AuthTarget {
        tenant_id: &view.tenant_id,
        project_id: &view.project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    authorize(db, claims, ScopedAction::ManageBindings, &target, attrs)
        .map_err(|_| VcsError::Denied)?;
    let status = BindingStatus::parse(&view.status)?;
    transition(status, BindingEvent::OwnershipProved)?;
    let provider = VcsProvider::parse(&view.provider)?;
    let verified = client
        .verify_installation(
            provider,
            installation_id.trim(),
            installation_token,
            &view.external_repo_id,
        )
        .map_err(|err| VcsError::Provider(err.to_string()))?;
    if !verified {
        let reason = serde_json::json!({"binding_id": binding_id}).to_string();
        audit_binding(
            db,
            "repository.ownership_proof_denied",
            &view.tenant_id,
            &view.project_id,
            &claims.principal_id,
            request_id,
            "api",
            "denied",
            &reason,
            now,
        )?;
        return Err(VcsError::Denied);
    }
    db.execute(
        "UPDATE repository_bindings
         SET status = 'active', installation_id = ?2,
             ownership_challenge = NULL, ownership_verified_at_utc = ?3
         WHERE binding_id = ?1",
        params![binding_id, installation_id.trim(), now],
    )?;
    let reason = serde_json::json!({
        "binding_id": binding_id,
        "provider": view.provider,
    })
    .to_string();
    audit_binding(
        db,
        "repository.ownership_proved",
        &view.tenant_id,
        &view.project_id,
        &claims.principal_id,
        request_id,
        "api",
        "success",
        &reason,
        now,
    )?;
    get_binding(db, claims, attrs, binding_id)
}

/// Resolves one binding. Tenant/project mismatches deny (no cross-project
/// oracle); unknown ids return `NotFound` (uniform 404 at the routes).
pub(crate) fn get_binding(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    binding_id: &str,
) -> Result<BindingView, VcsError> {
    let view: Option<BindingView> = db
        .query_row(
            &format!("SELECT {BINDING_COLUMNS} FROM repository_bindings WHERE binding_id = ?1"),
            params![binding_id],
            view_from_row,
        )
        .optional()?;
    let view = view.ok_or(VcsError::NotFound)?;
    if view.tenant_id != claims.tenant_id {
        return Err(VcsError::Denied);
    }
    let target = AuthTarget {
        tenant_id: &view.tenant_id,
        project_id: &view.project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    authorize(db, claims, ScopedAction::ReadMetadata, &target, attrs)
        .map_err(|_| VcsError::Denied)?;
    Ok(view)
}

/// Lists a project's bindings (all statuses; callers filter for display).
pub(crate) fn list_bindings(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
) -> Result<Vec<BindingView>, VcsError> {
    let tenant = project_tenant(db, project_id)?.ok_or(VcsError::NotFound)?;
    if tenant != claims.tenant_id {
        return Err(VcsError::Denied);
    }
    let target = AuthTarget {
        tenant_id: &tenant,
        project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    authorize(db, claims, ScopedAction::ReadMetadata, &target, attrs)
        .map_err(|_| VcsError::Denied)?;
    let mut rows = db.prepare(&format!(
        "SELECT {BINDING_COLUMNS} FROM repository_bindings
         WHERE project_id = ?1 ORDER BY created_at_utc, binding_id"
    ))?;
    let bindings = rows
        .query_map(params![project_id], view_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(bindings)
}

/// Suspends a binding (admin). Secrets keep their `repository_binding_id`
/// references and stay readable (break-glass); new grants are denied.
pub(crate) fn suspend_binding(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    binding_id: &str,
    reason_text: &str,
    request_id: &str,
    now: u64,
) -> Result<BindingView, VcsError> {
    mutate_binding(
        db,
        claims,
        attrs,
        binding_id,
        BindingEvent::AdminSuspend,
        "repository.suspended",
        reason_text,
        request_id,
        now,
    )
}

/// Revokes a binding (admin). Terminal: secret rows keep the dangling
/// reference for audit; all future transitions fail closed.
pub(crate) fn revoke_binding(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    binding_id: &str,
    reason_text: &str,
    request_id: &str,
    now: u64,
) -> Result<BindingView, VcsError> {
    mutate_binding(
        db,
        claims,
        attrs,
        binding_id,
        BindingEvent::AdminRevoke,
        AuditEventType::RepositoryRevoked.as_str(),
        reason_text,
        request_id,
        now,
    )
}

/// Reactivates a revoked binding back to `suspended` (admin, audited). The
/// binding must complete a fresh ownership proof before gating grants again;
/// suspended/active bindings are unaffected (idempotent no-op).
pub(crate) fn reactivate_binding(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    binding_id: &str,
    reason_text: &str,
    request_id: &str,
    now: u64,
) -> Result<BindingView, VcsError> {
    mutate_binding(
        db,
        claims,
        attrs,
        binding_id,
        BindingEvent::AdminReactivate,
        "repository.reactivated",
        reason_text,
        request_id,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn mutate_binding(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    binding_id: &str,
    event: BindingEvent,
    audit_type: &str,
    reason_text: &str,
    request_id: &str,
    now: u64,
) -> Result<BindingView, VcsError> {
    let view = get_binding(db, claims, attrs, binding_id)?;
    let target = AuthTarget {
        tenant_id: &view.tenant_id,
        project_id: &view.project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    authorize(db, claims, ScopedAction::ManageBindings, &target, attrs)
        .map_err(|_| VcsError::Denied)?;
    let next = transition(BindingStatus::parse(&view.status)?, event)?;
    db.execute(
        "UPDATE repository_bindings SET status = ?2 WHERE binding_id = ?1",
        params![binding_id, next.as_str()],
    )?;
    let reason = serde_json::json!({
        "binding_id": binding_id,
        "from": view.status,
        "to": next.as_str(),
        "detail": reason_text.trim(),
    })
    .to_string();
    audit_binding(
        db,
        audit_type,
        &view.tenant_id,
        &view.project_id,
        &claims.principal_id,
        request_id,
        "api",
        "success",
        &reason,
        now,
    )?;
    get_binding(db, claims, attrs, binding_id)
}

/// Requires a binding to exist, belong to the caller's scope, and be
/// `active`. This is the "suspended denies new grants" choke point used by
/// secret create/rebind; reads never call it (break-glass).
pub(crate) fn require_active_binding(
    db: &Connection,
    binding_id: &str,
    tenant_id: &str,
    project_id: &str,
) -> Result<(), VcsError> {
    let (tenant, project, status): (String, String, String) = db
        .query_row(
            "SELECT tenant_id, project_id, status FROM repository_bindings WHERE binding_id = ?1",
            params![binding_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(VcsError::NotFound)?;
    if tenant != tenant_id || project != project_id {
        return Err(VcsError::Denied);
    }
    if status != BindingStatus::Active.as_str() {
        return Err(VcsError::Denied);
    }
    Ok(())
}

/// Loads the webhook master secret (file-or-env 32-byte hex, mirroring the
/// scope-token key convention). Per-binding keys derive from it, so the
/// secret itself is never stored in the database.
pub(crate) fn webhook_signing_key() -> Result<[u8; 32], VcsError> {
    webhook_signing_key_from(VCS_WEBHOOK_KEY_FILE_ENV, VCS_WEBHOOK_KEY_ENV)
}

pub(crate) fn webhook_signing_key_from(
    file_env: &str,
    direct_env: &str,
) -> Result<[u8; 32], VcsError> {
    let raw = match std::env::var(file_env) {
        Ok(path) if !path.trim().is_empty() => {
            std::fs::read_to_string(path.trim()).map_err(|_| VcsError::Unconfigured)?
        }
        _ => std::env::var(direct_env).map_err(|_| VcsError::Unconfigured)?,
    };
    let bytes = hex::decode(raw.trim()).map_err(|_| VcsError::Unconfigured)?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| VcsError::Unconfigured)
}

/// Derives a binding's webhook HMAC key: `HMAC(master, domain ‖ binding_id)`.
pub(crate) fn webhook_key_for(master: &[u8; 32], binding_id: &str) -> [u8; 32] {
    let key = Key::new(HMAC_SHA256, master);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(WEBHOOK_MAC_DOMAIN);
    ctx.update(binding_id.as_bytes());
    let tag = ctx.sign();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Verifies a provider webhook signature. GitHub/Bitbucket/self-hosted use
/// `sha256=<hex-hmac>`; GitLab sends the configured token, which is the
/// hex-encoded derived key, compared in constant time.
pub fn verify_webhook_signature(
    provider: VcsProvider,
    key: &[u8; 32],
    payload: &[u8],
    signature_header: &str,
) -> bool {
    match provider {
        VcsProvider::Github | VcsProvider::Bitbucket | VcsProvider::SelfHosted => {
            let Some(hex_part) = signature_header.trim().strip_prefix("sha256=") else {
                return false;
            };
            let Ok(expected) = hex::decode(hex_part.trim()) else {
                return false;
            };
            // Installers configure hex(key) as the provider webhook secret, so
            // providers HMAC with the hex-string bytes; verify with the same.
            let configured = hex::encode(key);
            hmac::verify(
                &Key::new(HMAC_SHA256, configured.as_bytes()),
                payload,
                &expected,
            )
            .is_ok()
        }
        VcsProvider::Gitlab => {
            let expected_hex = hex::encode(key);
            signature_header
                .trim()
                .as_bytes()
                .ct_eq(expected_hex.as_bytes())
                .into()
        }
    }
}

/// Inbound provider event. Lookup is always by `(provider, external_repo_id)`,
/// never by slug (Workflow E).
pub struct WebhookEvent<'a> {
    pub event_type: &'a str,
    pub external_repo_id: &'a str,
    pub repo_full_name: &'a str,
    pub repo_url: &'a str,
}

/// Outcome of [`apply_webhook_event`]. Unknown bindings are ignored (the
/// HMAC already authenticated the provider; the repo simply is not tracked).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookOutcome {
    Applied { binding_id: String, status: String },
    IgnoredUnknownBinding,
}

/// Applies an authenticated webhook event. Rename performs a display-only
/// update (`binding_id` and secret references untouched); transfer/archive
/// suspend; delete revokes. Revoked bindings absorb events as no-ops so
/// provider redelivery stays idempotent.
pub(crate) fn apply_webhook_event(
    db: &Connection,
    provider: VcsProvider,
    event: &WebhookEvent<'_>,
    request_id: &str,
    now: u64,
) -> Result<WebhookOutcome, VcsError> {
    let view: Option<BindingView> = db
        .query_row(
            &format!(
                "SELECT {BINDING_COLUMNS} FROM repository_bindings
                 WHERE provider = ?1 AND external_repo_id = ?2"
            ),
            params![provider.as_str(), event.external_repo_id.trim()],
            view_from_row,
        )
        .optional()?;
    let Some(view) = view else {
        return Ok(WebhookOutcome::IgnoredUnknownBinding);
    };
    let status = BindingStatus::parse(&view.status)?;
    if status == BindingStatus::Revoked {
        return Ok(WebhookOutcome::Applied {
            binding_id: view.binding_id,
            status: view.status,
        });
    }
    let principal = format!("vcs-webhook:{}", provider.as_str());
    match event.event_type.trim().to_ascii_lowercase().as_str() {
        "renamed" => {
            let full_name = validate_display_name(event.repo_full_name)?;
            let url = validate_repo_url(event.repo_url)?;
            transition(status, BindingEvent::Renamed)?;
            db.execute(
                "UPDATE repository_bindings SET repo_full_name = ?2, repo_url = ?3
                 WHERE binding_id = ?1",
                params![view.binding_id, full_name, url],
            )?;
            let reason = serde_json::json!({
                "binding_id": view.binding_id,
                "old_slug": view.repo_full_name,
                "new_slug": full_name,
                "actor": "vcs-webhook",
            })
            .to_string();
            audit_binding(
                db,
                "repository.rebound",
                &view.tenant_id,
                &view.project_id,
                &principal,
                request_id,
                "vcs-webhook",
                "success",
                &reason,
                now,
            )?;
        }
        "transferred" | "archived" => {
            let next = transition(status, BindingEvent::Transferred)?;
            db.execute(
                "UPDATE repository_bindings SET status = ?2 WHERE binding_id = ?1",
                params![view.binding_id, next.as_str()],
            )?;
            let reason = serde_json::json!({
                "binding_id": view.binding_id,
                "event": event.event_type.trim(),
                "actor": "vcs-webhook",
            })
            .to_string();
            audit_binding(
                db,
                "repository.suspended",
                &view.tenant_id,
                &view.project_id,
                &principal,
                request_id,
                "vcs-webhook",
                "success",
                &reason,
                now,
            )?;
        }
        "deleted" => {
            transition(status, BindingEvent::Deleted)?;
            db.execute(
                "UPDATE repository_bindings SET status = 'revoked' WHERE binding_id = ?1",
                params![view.binding_id],
            )?;
            let reason = serde_json::json!({
                "binding_id": view.binding_id,
                "actor": "vcs-webhook",
            })
            .to_string();
            audit_binding(
                db,
                AuditEventType::RepositoryRevoked.as_str(),
                &view.tenant_id,
                &view.project_id,
                &principal,
                request_id,
                "vcs-webhook",
                "success",
                &reason,
                now,
            )?;
        }
        other => {
            return Err(VcsError::Invalid(format!(
                "unknown webhook event '{other}'"
            )));
        }
    }
    let status: String = db.query_row(
        "SELECT status FROM repository_bindings WHERE binding_id = ?1",
        params![view.binding_id],
        |row| row.get(0),
    )?;
    Ok(WebhookOutcome::Applied {
        binding_id: view.binding_id,
        status,
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;
    use crate::policy::{grant_project_role, ProjectRole};
    use crate::reconcile::ProviderClient;
    use crate::test_support::{cleanup, test_app};

    struct StubClient {
        verified: bool,
    }

    impl ProviderClient for StubClient {
        fn fetch_repo(
            &self,
            _provider: VcsProvider,
            _external_id: &str,
        ) -> Result<Option<ProviderRepo>, VcsError> {
            Ok(None)
        }

        fn verify_installation(
            &self,
            _provider: VcsProvider,
            _installation_id: &str,
            _token: &str,
            _external_id: &str,
        ) -> Result<bool, VcsError> {
            Ok(self.verified)
        }
    }

    fn seed_scope(db: &Connection) {
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
             VALUES('e1', 't1', 'p1', 'production', 2, 1)",
            [],
        )
        .unwrap();
        grant_project_role(
            db,
            "p1",
            "account:alice",
            ProjectRole::Admin,
            "bootstrap",
            1,
        )
        .unwrap();
        grant_project_role(
            db,
            "p1",
            "account:dev",
            ProjectRole::Developer,
            "bootstrap",
            1,
        )
        .unwrap();
    }

    fn admin_claims() -> ScopeClaims {
        ScopeClaims::new("t1", "p1", "account:alice", 1, 999_999_999)
    }

    const TEST_WEBHOOK_KEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Publish the webhook master key. Every test sets the same fixed value
    /// (never unsets), so parallel execution cannot observe a skew.
    fn webhook_test_env() {
        std::env::set_var(VCS_WEBHOOK_KEY_ENV, TEST_WEBHOOK_KEY_HEX);
    }

    fn bind_input<'a>() -> BindRepository<'a> {
        BindRepository {
            provider: "github",
            external_repo_id: "84920194",
            repo_full_name: "acme/payments-service",
            repo_url: "https://github.com/acme/payments-service",
            installation_id: Some("install-7"),
            request_id: "req-bind-1",
        }
    }

    fn audit_reasons(db: &Connection, event_type: &str) -> Vec<(String, String)> {
        let mut rows = db
            .prepare(
                "SELECT result, reason FROM secret_access_events
                 WHERE tenant_id = 't1' AND event_type = ?1 ORDER BY created_at_utc",
            )
            .unwrap();
        rows.query_map(params![event_type], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn provider_ids_validate_per_shape() {
        assert!(VcsProvider::parse("GitHub").is_ok());
        assert!(VcsProvider::parse("self_hosted").is_ok());
        assert!(VcsProvider::parse("gitea").is_err());
        assert!(VcsProvider::Github.validate_external_id("84920194").is_ok());
        assert!(VcsProvider::Github
            .validate_external_id("acme/repo")
            .is_err());
        assert!(VcsProvider::Gitlab.validate_external_id("42").is_ok());
        assert!(VcsProvider::Gitlab.validate_external_id("").is_err());
        assert!(VcsProvider::Bitbucket
            .validate_external_id("acme/payments")
            .is_ok());
        assert!(VcsProvider::Bitbucket
            .validate_external_id("payments")
            .is_err());
        assert!(VcsProvider::SelfHosted
            .validate_external_id("repo-uuid-1")
            .is_ok());
        assert!(VcsProvider::SelfHosted
            .validate_external_id("has space")
            .is_err());
    }

    #[test]
    fn state_machine_matrix() {
        use BindingEvent::*;
        use BindingStatus::{Active, Revoked, Suspended};
        // Rename is display-only in every non-terminal state.
        assert_eq!(transition(Active, Renamed).unwrap(), Active);
        assert_eq!(transition(Suspended, Renamed).unwrap(), Suspended);
        // Transfer/archive suspend; delete revokes.
        assert_eq!(transition(Active, Transferred).unwrap(), Suspended);
        assert_eq!(transition(Active, Archived).unwrap(), Suspended);
        assert_eq!(transition(Active, Deleted).unwrap(), Revoked);
        assert_eq!(transition(Suspended, Deleted).unwrap(), Revoked);
        // Proof activates suspended bindings only.
        assert_eq!(transition(Suspended, OwnershipProved).unwrap(), Active);
        assert_eq!(transition(Active, OwnershipProved).unwrap(), Active);
        // Admin flows are idempotent; revoked is terminal.
        assert_eq!(transition(Active, AdminSuspend).unwrap(), Suspended);
        assert_eq!(transition(Suspended, AdminSuspend).unwrap(), Suspended);
        assert_eq!(transition(Revoked, AdminRevoke).unwrap(), Revoked);
        assert_eq!(transition(Revoked, AdminReactivate).unwrap(), Suspended);
        assert!(matches!(
            transition(Revoked, Renamed),
            Err(VcsError::Terminal)
        ));
        assert!(matches!(
            transition(Revoked, OwnershipProved),
            Err(VcsError::Terminal)
        ));
    }

    #[test]
    fn bind_starts_suspended_and_prove_activates() {
        let (root, state, _app) = test_app("vcs-lifecycle");
        webhook_test_env();
        let db = state.connection().unwrap();
        seed_scope(&db);
        let attrs = RequestAttributes::default();
        let claims = admin_claims();

        let outcome = bind_repository(&db, &claims, &attrs, "p1", &bind_input(), 100).unwrap();
        assert_eq!(outcome.binding.status, "suspended");
        assert_eq!(outcome.ownership_challenge.len(), 32);
        assert_eq!(outcome.webhook_secret.len(), 64);
        assert!(outcome.binding.ownership_verified_at_utc.is_none());

        let client = StubClient { verified: true };
        let active = prove_ownership(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "install-7",
            "provider-token",
            &client,
            "req-prove-1",
            200,
        )
        .unwrap();
        assert_eq!(active.status, "active");
        assert_eq!(active.ownership_verified_at_utc, Some(200));

        let bound = audit_reasons(&db, "repository.bound");
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].0, "success");
        let proved = audit_reasons(&db, "repository.ownership_proved");
        assert_eq!(proved.len(), 1);
        cleanup(root);
    }

    #[test]
    fn prove_denied_without_provider_attestation() {
        let (root, state, _app) = test_app("vcs-prove-denied");
        webhook_test_env();
        let db = state.connection().unwrap();
        seed_scope(&db);
        let attrs = RequestAttributes::default();
        let claims = admin_claims();
        let outcome = bind_repository(&db, &claims, &attrs, "p1", &bind_input(), 100).unwrap();
        let client = StubClient { verified: false };
        let err = prove_ownership(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "install-7",
            "forged-token",
            &client,
            "req-prove-2",
            200,
        )
        .unwrap_err();
        assert!(matches!(err, VcsError::Denied));
        let denied = audit_reasons(&db, "repository.ownership_proof_denied");
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].0, "denied");
        let view = get_binding(&db, &claims, &attrs, &outcome.binding.binding_id).unwrap();
        assert_eq!(view.status, "suspended");
        cleanup(root);
    }

    #[test]
    fn bind_enforces_admin_and_uniqueness() {
        let (root, state, _app) = test_app("vcs-bind-gates");
        webhook_test_env();
        let db = state.connection().unwrap();
        seed_scope(&db);
        let attrs = RequestAttributes::default();
        let dev = ScopeClaims::new("t1", "p1", "account:dev", 1, 999_999_999);
        let err = bind_repository(&db, &dev, &attrs, "p1", &bind_input(), 100).unwrap_err();
        assert!(matches!(err, VcsError::Denied));

        let claims = admin_claims();
        bind_repository(&db, &claims, &attrs, "p1", &bind_input(), 100).unwrap();
        let err = bind_repository(&db, &claims, &attrs, "p1", &bind_input(), 101).unwrap_err();
        assert!(matches!(err, VcsError::Conflict));

        let other_provider = BindRepository {
            provider: "gitlab",
            ..bind_input()
        };
        let created = bind_repository(&db, &claims, &attrs, "p1", &other_provider, 102).unwrap();
        assert_eq!(created.binding.provider, "gitlab");
        let listed = list_bindings(&db, &claims, &attrs, "p1").unwrap();
        assert_eq!(listed.len(), 2);
        cleanup(root);
    }

    #[test]
    fn rename_webhook_is_display_only() {
        let (root, state, _app) = test_app("vcs-rename");
        webhook_test_env();
        let db = state.connection().unwrap();
        seed_scope(&db);
        let attrs = RequestAttributes::default();
        let claims = admin_claims();
        let outcome = bind_repository(&db, &claims, &attrs, "p1", &bind_input(), 100).unwrap();
        let client = StubClient { verified: true };
        prove_ownership(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "install-7",
            "provider-token",
            &client,
            "req-prove-1",
            200,
        )
        .unwrap();
        let renamed = apply_webhook_event(
            &db,
            VcsProvider::Github,
            &WebhookEvent {
                event_type: "renamed",
                external_repo_id: "84920194",
                repo_full_name: "acme/payments-v2",
                repo_url: "https://github.com/acme/payments-v2",
            },
            "req-hook-1",
            300,
        )
        .unwrap();
        match renamed {
            WebhookOutcome::Applied { binding_id, status } => {
                assert_eq!(binding_id, outcome.binding.binding_id);
                assert_eq!(status, "active");
            }
            WebhookOutcome::IgnoredUnknownBinding => panic!("expected applied rename"),
        }
        let view = get_binding(&db, &claims, &attrs, &outcome.binding.binding_id).unwrap();
        assert_eq!(view.repo_full_name, "acme/payments-v2");
        let rebound = audit_reasons(&db, "repository.rebound");
        assert_eq!(rebound.len(), 1);
        assert!(rebound[0].1.contains("acme/payments-service"));
        assert!(rebound[0].1.contains("acme/payments-v2"));
        cleanup(root);
    }

    #[test]
    fn webhook_transfer_suspends_delete_revokes_and_terminal_absorbs() {
        let (root, state, _app) = test_app("vcs-webhook-states");
        webhook_test_env();
        let db = state.connection().unwrap();
        seed_scope(&db);
        let attrs = RequestAttributes::default();
        let claims = admin_claims();
        let outcome = bind_repository(&db, &claims, &attrs, "p1", &bind_input(), 100).unwrap();
        let client = StubClient { verified: true };
        prove_ownership(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "install-7",
            "provider-token",
            &client,
            "req-prove-1",
            200,
        )
        .unwrap();
        let hook = |event_type: &'static str| WebhookEvent {
            event_type,
            external_repo_id: "84920194",
            repo_full_name: "acme/payments-service",
            repo_url: "https://github.com/acme/payments-service",
        };
        let bad = apply_webhook_event(&db, VcsProvider::Github, &hook("starred"), "r0", 250);
        assert!(matches!(bad, Err(VcsError::Invalid(_))));
        let transferred =
            apply_webhook_event(&db, VcsProvider::Github, &hook("transferred"), "r1", 300).unwrap();
        assert!(matches!(
            transferred,
            WebhookOutcome::Applied { ref status, .. } if status == "suspended"
        ));
        let deleted =
            apply_webhook_event(&db, VcsProvider::Github, &hook("deleted"), "r2", 400).unwrap();
        assert!(matches!(
            deleted,
            WebhookOutcome::Applied { ref status, .. } if status == "revoked"
        ));
        // Redelivery after revocation is an idempotent no-op.
        let redelivered =
            apply_webhook_event(&db, VcsProvider::Github, &hook("renamed"), "r3", 500).unwrap();
        assert!(matches!(
            redelivered,
            WebhookOutcome::Applied { ref status, .. } if status == "revoked"
        ));
        assert_eq!(audit_reasons(&db, "repository.rebound").len(), 0);

        let unknown = apply_webhook_event(
            &db,
            VcsProvider::Github,
            &WebhookEvent {
                external_repo_id: "00000000",
                ..hook("renamed")
            },
            "r4",
            600,
        )
        .unwrap();
        assert_eq!(unknown, WebhookOutcome::IgnoredUnknownBinding);
        cleanup(root);
    }

    #[test]
    fn webhook_signatures_verify_per_provider_scheme() {
        let master = [0x11u8; 32];
        let key = webhook_key_for(&master, "binding-1");
        assert_eq!(webhook_key_for(&master, "binding-1"), key);
        assert_ne!(webhook_key_for(&master, "binding-2"), key);
        assert_ne!(webhook_key_for(&[0x22u8; 32], "binding-1"), key);

        let payload = br#"{"action":"renamed"}"#;
        let signing = Key::new(HMAC_SHA256, hex::encode(key).as_bytes());
        let tag = hex::encode(hmac::sign(&signing, payload).as_ref());
        let header = format!("sha256={tag}");
        assert!(verify_webhook_signature(
            VcsProvider::Github,
            &key,
            payload,
            &header
        ));
        assert!(!verify_webhook_signature(
            VcsProvider::Github,
            &key,
            br#"{"action":"tampered"}"#,
            &header
        ));
        assert!(!verify_webhook_signature(
            VcsProvider::Github,
            &key,
            payload,
            &tag
        ));
        assert!(!verify_webhook_signature(
            VcsProvider::Github,
            &webhook_key_for(&master, "binding-2"),
            payload,
            &header
        ));

        let gitlab_token = hex::encode(key);
        assert!(verify_webhook_signature(
            VcsProvider::Gitlab,
            &key,
            payload,
            &gitlab_token
        ));
        assert!(!verify_webhook_signature(
            VcsProvider::Gitlab,
            &key,
            payload,
            "wrong-token"
        ));
    }

    #[test]
    fn active_gate_denies_suspended_and_foreign_bindings() {
        let (root, state, _app) = test_app("vcs-active-gate");
        webhook_test_env();
        let db = state.connection().unwrap();
        seed_scope(&db);
        let attrs = RequestAttributes::default();
        let claims = admin_claims();
        let outcome = bind_repository(&db, &claims, &attrs, "p1", &bind_input(), 100).unwrap();
        // Fresh bindings are suspended: no new grants until ownership proof.
        assert!(require_active_binding(&db, &outcome.binding.binding_id, "t1", "p1").is_err());
        let client = StubClient { verified: true };
        prove_ownership(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "install-7",
            "provider-token",
            &client,
            "req-prove-1",
            200,
        )
        .unwrap();
        assert!(require_active_binding(&db, &outcome.binding.binding_id, "t1", "p1").is_ok());
        assert!(require_active_binding(&db, &outcome.binding.binding_id, "t1", "other").is_err());
        assert!(require_active_binding(&db, "missing", "t1", "p1").is_err());
        suspend_binding(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "transfer detected",
            "req-suspend-1",
            300,
        )
        .unwrap();
        assert!(require_active_binding(&db, &outcome.binding.binding_id, "t1", "p1").is_err());
        cleanup(root);
    }

    #[test]
    fn admin_revoke_is_terminal_until_reactivation() {
        let (root, state, _app) = test_app("vcs-revoke");
        webhook_test_env();
        let db = state.connection().unwrap();
        seed_scope(&db);
        let attrs = RequestAttributes::default();
        let claims = admin_claims();
        let outcome = bind_repository(&db, &claims, &attrs, "p1", &bind_input(), 100).unwrap();
        let client = StubClient { verified: true };
        prove_ownership(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "install-7",
            "provider-token",
            &client,
            "req-prove-1",
            200,
        )
        .unwrap();
        let revoked = revoke_binding(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "repo deleted",
            "req-revoke-1",
            300,
        )
        .unwrap();
        assert_eq!(revoked.status, "revoked");
        // Second revoke is idempotent; proof stays terminal.
        revoke_binding(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "again",
            "req-revoke-2",
            301,
        )
        .unwrap();
        let err = prove_ownership(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "install-7",
            "provider-token",
            &client,
            "req-prove-2",
            302,
        )
        .unwrap_err();
        assert!(matches!(err, VcsError::Terminal));
        // Reactivation returns to suspended (proof still required).
        let suspended = reactivate_binding(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "restore was premature",
            "req-react-1",
            400,
        )
        .unwrap();
        assert_eq!(suspended.status, "suspended");
        assert!(require_active_binding(&db, &outcome.binding.binding_id, "t1", "p1").is_err());
        let active = prove_ownership(
            &db,
            &claims,
            &attrs,
            &outcome.binding.binding_id,
            "install-7",
            "provider-token",
            &client,
            "req-prove-3",
            500,
        )
        .unwrap();
        assert_eq!(active.status, "active");
        assert_eq!(audit_reasons(&db, "repository.reactivated").len(), 1);
        cleanup(root);
    }

    #[test]
    fn webhook_key_loading_fails_closed() {
        const MISSING_FILE: &str = "CIPHERVAULT_TEST_VCS_KEY_FILE_MISSING";
        assert!(matches!(
            webhook_signing_key_from(MISSING_FILE, "CIPHERVAULT_TEST_VCS_KEY_MISSING"),
            Err(VcsError::Unconfigured)
        ));
        std::env::set_var("CIPHERVAULT_TEST_VCS_KEY_BAD", "not-hex");
        let bad = webhook_signing_key_from(MISSING_FILE, "CIPHERVAULT_TEST_VCS_KEY_BAD");
        std::env::remove_var("CIPHERVAULT_TEST_VCS_KEY_BAD");
        assert!(matches!(bad, Err(VcsError::Unconfigured)));
        std::env::set_var("CIPHERVAULT_TEST_VCS_KEY_SHORT", "abcd");
        let short = webhook_signing_key_from(MISSING_FILE, "CIPHERVAULT_TEST_VCS_KEY_SHORT");
        std::env::remove_var("CIPHERVAULT_TEST_VCS_KEY_SHORT");
        assert!(matches!(short, Err(VcsError::Unconfigured)));
        std::env::set_var("CIPHERVAULT_TEST_VCS_KEY_OK", TEST_WEBHOOK_KEY_HEX);
        let ok = webhook_signing_key_from(MISSING_FILE, "CIPHERVAULT_TEST_VCS_KEY_OK").unwrap();
        std::env::remove_var("CIPHERVAULT_TEST_VCS_KEY_OK");
        assert_eq!(ok, [0x11u8; 32]);
    }
}
