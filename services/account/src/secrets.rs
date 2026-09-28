//! Versioned secret lifecycle (Phase 4, T-401).
//!
//! Storage engine behind the scoped secret API. Every entry point resolves
//! the target row first and authorizes via [`policy::authorize`] before
//! touching values, so routes cannot bypass the choke point. Values are
//! sealed per version under fresh DEKs with scope-bound AAD (T-501/T-502);
//! plaintext exists only in handler RAM inside `SecretValue`, and audit rows
//! carry digests, never values.

use ciphervault_crypto::{
    open_secret_value, scope_aad, seal_secret_value, DataEncryptionKey, KeyWrappingService,
    WrappedDek, NONCE_SIZE, TAG_SIZE,
};
use ciphervault_format::{
    validate_description, validate_secret_name, validate_tag, SecretId, SecretValue,
    SecretVersionId, MAX_TAGS,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::audit_chain::AuditEventType;
use crate::error::AccountServiceError;
use crate::policy::{authorize, AuthTarget, RequestAttributes, ScopedAction};
use crate::scope_tokens::ScopeClaims;
use crate::state::now_utc;
use crate::util::random_hex;

const SQLITE_CONSTRAINT_UNIQUE: i32 = 2067;
const SQLITE_CONSTRAINT_FOREIGNKEY: i32 = 787;
const MAX_LIST_LIMIT: i64 = 500;

/// Secret-service errors. `Denied` and `NotFound` both surface as a uniform
/// 404 at the route layer (no existence oracle); the distinction exists only
/// for server-side audit.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret not found")]
    NotFound,
    #[error("secret already exists in this scope")]
    Conflict,
    #[error("access denied")]
    Denied,
    #[error("invalid secret request: {0}")]
    Invalid(String),
    #[error("new credential failed liveness verification")]
    VerificationFailed,
    #[error("secret crypto error: {0}")]
    Crypto(#[from] ciphervault_crypto::CryptoError),
    #[error("secret database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("account service error: {0}")]
    Service(#[from] AccountServiceError),
}

/// Parameters for creating a secret and its first version.
pub struct CreateSecret<'a> {
    pub project_id: &'a str,
    pub environment_id: &'a str,
    pub name: &'a str,
    pub secret_type: &'a str,
    pub description: &'a str,
    pub tags: &'a [String],
    pub repository_binding_id: Option<&'a str>,
    pub service_id: Option<&'a str>,
    pub value: &'a SecretValue,
    pub request_id: &'a str,
}

/// Metadata patch (values rotate via [`crate::rotation::rotate_secret`], never here).
#[derive(Default)]
pub struct UpdateSecretMetadata<'a> {
    pub description: Option<&'a str>,
    pub tags: Option<&'a [String]>,
    pub expires_at_utc: Option<u64>,
    pub status: Option<&'a str>,
}

/// List filters (values never listed — metadata only).
pub struct SecretListFilter<'a> {
    pub project_id: &'a str,
    pub environment_id: &'a str,
    pub tag: Option<&'a str>,
    pub status: Option<&'a str>,
    /// Case-insensitive name-substring search (DB-level `LIKE`, wildcards
    /// escaped). Authorization still applies first: search never widens
    /// scope (§19, T-703). Empty means no filter.
    pub q: Option<&'a str>,
    pub limit: i64,
}

/// Secret metadata view (no value).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SecretView {
    pub secret_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub repository_binding_id: Option<String>,
    pub service_id: Option<String>,
    pub name: String,
    pub secret_type: String,
    pub description: String,
    pub tags: Vec<String>,
    pub status: String,
    pub current_version: i64,
    pub created_by: String,
    pub created_at_utc: u64,
    pub updated_at_utc: u64,
    pub last_rotated_at_utc: Option<u64>,
    pub expires_at_utc: Option<u64>,
}

/// Metadata plus one decrypted version. `Debug` is safe: the value inside
/// `SecretValue` renders redacted.
#[derive(Debug)]
pub struct SecretValueView {
    pub meta: SecretView,
    pub version: i64,
    pub value: SecretValue,
}

/// Hash-chained audit event parameters (digests only, never values).
pub(crate) struct SecretAuditEvent<'a> {
    pub event_type: &'a str,
    pub tenant_id: &'a str,
    pub project_id: Option<&'a str>,
    pub environment_id: Option<&'a str>,
    pub secret_id: Option<&'a str>,
    pub secret_version: Option<i64>,
    pub principal_id: &'a str,
    pub request_id: &'a str,
    pub source: &'a str,
    pub result: &'a str,
    pub reason: &'a str,
}

fn id16(hex_str: &str, what: &str) -> Result<[u8; 16], SecretError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| SecretError::Invalid(format!("malformed {what} id")))?;
    bytes.try_into().map_err(|raw: Vec<u8>| {
        SecretError::Invalid(format!("malformed {what} id: {} bytes", raw.len()))
    })
}

fn map_constraint(err: rusqlite::Error) -> SecretError {
    if let rusqlite::Error::SqliteFailure(failure, _) = &err {
        if failure.extended_code == SQLITE_CONSTRAINT_UNIQUE {
            return SecretError::Conflict;
        }
        if failure.extended_code == SQLITE_CONSTRAINT_FOREIGNKEY {
            return SecretError::Invalid("unknown scope reference".to_string());
        }
    }
    SecretError::Db(err)
}

fn map_binding_error(err: crate::vcs::VcsError) -> SecretError {
    match err {
        crate::vcs::VcsError::NotFound => {
            SecretError::Invalid("unknown repository binding".to_string())
        }
        crate::vcs::VcsError::Denied => SecretError::Denied,
        crate::vcs::VcsError::Db(db_err) => SecretError::Db(db_err),
        other => SecretError::Invalid(other.to_string()),
    }
}

fn require_row(
    db: &Connection,
    table: &str,
    id_col: &str,
    id: &str,
    what: &str,
) -> Result<(), SecretError> {
    let exists: bool = db
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {id_col} = ?1)"),
            params![id],
            |row| row.get(0),
        )
        .map_err(SecretError::Db)?;
    if exists {
        Ok(())
    } else {
        Err(SecretError::Invalid(format!("unknown {what}")))
    }
}

fn validate_tags(tags: &[String]) -> Result<(), SecretError> {
    if tags.len() > MAX_TAGS {
        return Err(SecretError::Invalid(format!(
            "too many tags: at most {MAX_TAGS}"
        )));
    }
    for tag in tags {
        validate_tag(tag).map_err(|err| SecretError::Invalid(err.to_string()))?;
    }
    Ok(())
}

fn secret_view_from_row(row: &rusqlite::Row<'_>) -> Result<SecretView, rusqlite::Error> {
    let tags_json: String = row.get(9)?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
    Ok(SecretView {
        secret_id: row.get(0)?,
        tenant_id: row.get(1)?,
        project_id: row.get(2)?,
        environment_id: row.get(3)?,
        repository_binding_id: row.get(4)?,
        service_id: row.get(5)?,
        name: row.get(6)?,
        secret_type: row.get(7)?,
        description: row.get(8)?,
        tags,
        status: row.get(10)?,
        current_version: row.get(11)?,
        created_by: row.get(12)?,
        created_at_utc: row.get(13)?,
        updated_at_utc: row.get(14)?,
        last_rotated_at_utc: row.get(15)?,
        expires_at_utc: row.get(16)?,
    })
}

const SECRET_COLUMNS: &str = "secret_id, tenant_id, project_id, environment_id,
    repository_binding_id, service_id, name, secret_type, description, tags_json, status,
    current_version, created_by, created_at_utc, updated_at_utc, last_rotated_at_utc,
    expires_at_utc";

pub(crate) fn resolve_secret(db: &Connection, secret_id: &str) -> Result<SecretView, SecretError> {
    db.query_row(
        &format!(
            "SELECT {SECRET_COLUMNS} FROM secrets WHERE secret_id = ?1 AND deleted_at_utc IS NULL"
        ),
        params![secret_id],
        secret_view_from_row,
    )
    .optional()
    .map_err(SecretError::Db)?
    .ok_or(SecretError::NotFound)
}

pub(crate) fn target_from_view(view: &SecretView) -> AuthTarget<'_> {
    AuthTarget {
        tenant_id: &view.tenant_id,
        project_id: &view.project_id,
        environment_id: Some(&view.environment_id),
        repository_binding_id: view.repository_binding_id.as_deref(),
        service_id: view.service_id.as_deref(),
    }
}

pub(crate) fn audit_secret_event(
    db: &Connection,
    event: &SecretAuditEvent<'_>,
    now: u64,
) -> Result<(), rusqlite::Error> {
    let prev: Vec<u8> = db
        .query_row(
            "SELECT event_hash FROM secret_access_events WHERE tenant_id = ?1
             ORDER BY created_at_utc DESC, rowid DESC LIMIT 1",
            params![event.tenant_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(vec![0u8; 32]);
    // Scrub-then-hash: the stored (scrubbed) reason is what verifiers
    // reproduce, so a credential smuggled into free text can neither
    // persist nor break the chain.
    let reason = ciphervault_redact::redact_text(event.reason);
    let digest = crate::audit_chain::chain_digest(&crate::audit_chain::ChainFields {
        prev: &prev,
        event_type: event.event_type,
        tenant_id: event.tenant_id,
        project_id: event.project_id,
        environment_id: event.environment_id,
        secret_id: event.secret_id,
        secret_version: event.secret_version,
        principal_id: event.principal_id,
        request_id: event.request_id,
        source: event.source,
        result: event.result,
        reason: &reason,
        now,
    })
    .to_vec();
    let actor = serde_json::json!({"principal_id": event.principal_id}).to_string();
    db.execute(
        "INSERT INTO secret_access_events(event_id, event_type, tenant_id, project_id,
             environment_id, secret_id, secret_version, actor_json, request_id, source, result,
             reason, prev_hash, event_hash, created_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            random_hex(16),
            event.event_type,
            event.tenant_id,
            event.project_id,
            event.environment_id,
            event.secret_id,
            event.secret_version,
            actor,
            event.request_id,
            event.source,
            event.result,
            reason,
            prev,
            digest,
            now,
        ],
    )?;
    Ok(())
}

fn ensure_kek_row(
    db: &Connection,
    kek_id: &str,
    tenant_id: &str,
    project_id: &str,
    now: u64,
) -> Result<(), rusqlite::Error> {
    // The KEK itself lives with the wrapping service; this row records the
    // reference so versions can point at it (Deliverable D §2).
    db.execute(
        "INSERT INTO encryption_keys(key_id, tenant_id, project_id, purpose, wrapped_key,
                                      status, created_at_utc)
         VALUES(?1, ?2, ?3, 'project_kek', x'', 'active', ?4)
         ON CONFLICT(key_id) DO NOTHING",
        params![kek_id, tenant_id, project_id, now],
    )?;
    Ok(())
}

/// Sealed version columns: value nonce/ciphertext plus the wrapped DEK.
struct SealedVersionParts {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    wrapped_dek: Vec<u8>,
}

fn seal_version(
    wrap: &dyn KeyWrappingService,
    tenant_raw: &[u8; 16],
    project_raw: &[u8; 16],
    env_raw: &[u8; 16],
    secret_raw: &[u8; 16],
    version: u32,
    value: &SecretValue,
) -> Result<SealedVersionParts, SecretError> {
    let aad = scope_aad(tenant_raw, project_raw, env_raw, secret_raw, version);
    let dek = DataEncryptionKey::generate();
    let sealed = seal_secret_value(&dek, value.expose(), &aad)?;
    let wrapped = wrap.wrap_dek(&dek)?;
    let mut wrapped_dek = Vec::with_capacity(NONCE_SIZE + wrapped.blob.len());
    wrapped_dek.extend_from_slice(&wrapped.nonce);
    wrapped_dek.extend_from_slice(&wrapped.blob);
    Ok(SealedVersionParts {
        nonce: sealed.nonce.to_vec(),
        ciphertext: sealed.ciphertext,
        wrapped_dek,
    })
}

/// Creates a secret with its first sealed version.
pub(crate) fn create_secret(
    db: &mut Connection,
    wrap: &dyn KeyWrappingService,
    kek_id: &str,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    input: &CreateSecret<'_>,
) -> Result<SecretView, SecretError> {
    let project_tenant: Option<String> = db
        .query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            params![input.project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(SecretError::Db)?;
    let Some(project_tenant) = project_tenant else {
        return Err(SecretError::Invalid("unknown project".to_string()));
    };
    let target = AuthTarget {
        tenant_id: &project_tenant,
        project_id: input.project_id,
        environment_id: Some(input.environment_id),
        repository_binding_id: input.repository_binding_id,
        service_id: input.service_id,
    };
    authorize(db, claims, ScopedAction::CreateSecret, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    validate_secret_name(input.name).map_err(|err| SecretError::Invalid(err.to_string()))?;
    validate_description(input.description).map_err(|err| SecretError::Invalid(err.to_string()))?;
    validate_tags(input.tags)?;
    if input.secret_type.trim().is_empty() {
        return Err(SecretError::Invalid(
            "secret_type must not be empty".to_string(),
        ));
    }
    require_row(
        db,
        "environments",
        "environment_id",
        input.environment_id,
        "environment",
    )?;
    if let Some(binding) = input.repository_binding_id {
        // Suspended/revoked bindings deny new grants (§T8); reads stay
        // available for break-glass because they never check status.
        crate::vcs::require_active_binding(db, binding, &claims.tenant_id, input.project_id)
            .map_err(map_binding_error)?;
    }
    if let Some(service) = input.service_id {
        require_row(db, "services", "service_id", service, "service")?;
    }
    let tenant_raw = id16(&claims.tenant_id, "tenant")?;
    let project_raw = id16(input.project_id, "project")?;
    let env_raw = id16(input.environment_id, "environment")?;
    let secret_id = SecretId::generate().to_hex();
    let secret_raw = id16(&secret_id, "secret")?;
    let sealed = seal_version(
        wrap,
        &tenant_raw,
        &project_raw,
        &env_raw,
        &secret_raw,
        1,
        input.value,
    )?;
    let (nonce, ciphertext, wrapped_blob) = (sealed.nonce, sealed.ciphertext, sealed.wrapped_dek);
    let digest = input.value.sha256().to_vec();
    let tags_json =
        serde_json::to_string(input.tags).map_err(|err| SecretError::Invalid(err.to_string()))?;
    let now = now_utc();
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let created = (|| {
        ensure_kek_row(&txn, kek_id, &claims.tenant_id, input.project_id, now)?;
        txn.execute(
            "INSERT INTO secrets(secret_id, tenant_id, project_id, environment_id,
                 repository_binding_id, service_id, name, secret_type, description, tags_json,
                 status, current_version, created_by, created_at_utc, updated_at_utc)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'active', 1, ?11, ?12, ?12)",
            params![
                secret_id,
                claims.tenant_id,
                input.project_id,
                input.environment_id,
                input.repository_binding_id,
                input.service_id,
                input.name,
                input.secret_type,
                input.description,
                tags_json,
                claims.principal_id,
                now,
            ],
        )
        .map_err(map_constraint)?;
        txn.execute(
            "INSERT INTO secret_versions(version_id, secret_id, version, encryption_key_id, nonce,
                 ciphertext, value_sha256, wrapped_dek, created_by, created_at_utc)
             VALUES(?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                SecretVersionId::generate().to_hex(),
                secret_id,
                kek_id,
                nonce,
                ciphertext,
                digest,
                wrapped_blob,
                claims.principal_id,
                now,
            ],
        )?;
        audit_secret_event(
            &txn,
            &SecretAuditEvent {
                event_type: AuditEventType::SecretCreated.as_str(),
                tenant_id: &claims.tenant_id,
                project_id: Some(input.project_id),
                environment_id: Some(input.environment_id),
                secret_id: Some(&secret_id),
                secret_version: Some(1),
                principal_id: &claims.principal_id,
                request_id: input.request_id,
                source: "api",
                result: "success",
                reason: "",
            },
            now,
        )?;
        Ok::<(), SecretError>(())
    })();
    match created {
        Ok(()) => {
            txn.commit()?;
            resolve_secret(db, &secret_id)
        }
        Err(err) => Err(err),
    }
}

/// Reads secret metadata (never the value).
pub(crate) fn get_secret_metadata(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    secret_id: &str,
) -> Result<SecretView, SecretError> {
    let view = resolve_secret(db, secret_id)?;
    let target = target_from_view(&view);
    authorize(db, claims, ScopedAction::ReadMetadata, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    Ok(view)
}

/// Opens the current version's plaintext (shared by read and move).
fn open_current_version(
    db: &Connection,
    wrap: &dyn KeyWrappingService,
    view: &SecretView,
) -> Result<Vec<u8>, SecretError> {
    let (kek_id, nonce, ciphertext, wrapped_blob): (String, Vec<u8>, Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT encryption_key_id, nonce, ciphertext, wrapped_dek FROM secret_versions
             WHERE secret_id = ?1 AND version = ?2",
            params![view.secret_id, view.current_version],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(SecretError::Db)?
        .ok_or(SecretError::NotFound)?;
    if wrapped_blob.len() < NONCE_SIZE + TAG_SIZE {
        return Err(SecretError::Invalid(
            "secret version predates envelope storage".to_string(),
        ));
    }
    let mut nonce24 = [0u8; NONCE_SIZE];
    nonce24.copy_from_slice(&wrapped_blob[..NONCE_SIZE]);
    let wrapped = WrappedDek {
        kek_id,
        nonce: nonce24,
        blob: wrapped_blob[NONCE_SIZE..].to_vec(),
    };
    let dek = wrap.unwrap_dek(&wrapped)?;
    let mut version_nonce = [0u8; NONCE_SIZE];
    if nonce.len() != NONCE_SIZE {
        return Err(SecretError::Invalid("malformed version nonce".to_string()));
    }
    version_nonce.copy_from_slice(&nonce);
    let aad = scope_aad(
        &id16(&view.tenant_id, "tenant")?,
        &id16(&view.project_id, "project")?,
        &id16(&view.environment_id, "environment")?,
        &id16(&view.secret_id, "secret")?,
        u32::try_from(view.current_version).unwrap_or(u32::MAX),
    );
    open_secret_value(
        &dek,
        &ciphervault_crypto::SealedSecret {
            nonce: version_nonce,
            ciphertext,
        },
        &aad,
    )
    .map_err(SecretError::Crypto)
}

/// Reads and decrypts the current version, auditing the access.
pub(crate) fn get_secret_value(
    db: &mut Connection,
    wrap: &dyn KeyWrappingService,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    secret_id: &str,
    request_id: &str,
) -> Result<SecretValueView, SecretError> {
    let view = resolve_secret(db, secret_id)?;
    let target = target_from_view(&view);
    authorize(db, claims, ScopedAction::ReadValue, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    let plaintext = open_current_version(db, wrap, &view)?;
    let now = now_utc();
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    txn.execute(
        "UPDATE secrets SET last_accessed_at_utc = ?1 WHERE secret_id = ?2",
        params![now, secret_id],
    )?;
    audit_secret_event(
        &txn,
        &SecretAuditEvent {
            event_type: AuditEventType::SecretRead.as_str(),
            tenant_id: &view.tenant_id,
            project_id: Some(&view.project_id),
            environment_id: Some(&view.environment_id),
            secret_id: Some(&view.secret_id),
            secret_version: Some(view.current_version),
            principal_id: &claims.principal_id,
            request_id,
            source: "api",
            result: "success",
            reason: "",
        },
        now,
    )?;
    txn.commit()?;
    let version = view.current_version;
    Ok(SecretValueView {
        meta: view,
        version,
        value: SecretValue::from_bytes(plaintext),
    })
}

/// Lists secret metadata in one environment (values never listed). The tag
/// filter applies in Rust after the capped SQL fetch (exact JSON match —
/// no LIKE wildcards).
pub(crate) fn list_secrets(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    filter: &SecretListFilter<'_>,
) -> Result<Vec<SecretView>, SecretError> {
    let project_tenant: Option<String> = db
        .query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            params![filter.project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(SecretError::Db)?;
    let target = AuthTarget {
        tenant_id: project_tenant.as_deref().unwrap_or(""),
        project_id: filter.project_id,
        environment_id: Some(filter.environment_id),
        repository_binding_id: None,
        service_id: None,
    };
    authorize(db, claims, ScopedAction::ReadMetadata, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    let limit = filter.limit.clamp(1, MAX_LIST_LIMIT);
    // LIKE-escape the caller's query so `%`/`_` match literally; the match
    // itself stays inside the authorized scope's SQL fetch (§19).
    let like_pattern = filter.q.map(str::trim).filter(|q| !q.is_empty()).map(|q| {
        let mut escaped = String::with_capacity(q.len() + 2);
        escaped.push('%');
        for ch in q.chars() {
            if matches!(ch, '%' | '_' | '\\') {
                escaped.push('\\');
            }
            escaped.push(ch);
        }
        escaped.push('%');
        escaped
    });
    let mut rows = db
        .prepare(&format!(
            "SELECT {SECRET_COLUMNS} FROM secrets
             WHERE project_id = ?1 AND environment_id = ?2 AND deleted_at_utc IS NULL
             AND (?3 IS NULL OR status = ?3)
             AND (?5 IS NULL OR name LIKE ?5 ESCAPE '\\')
             ORDER BY name ASC LIMIT ?4"
        ))
        .map_err(SecretError::Db)?;
    let views = rows
        .query_map(
            params![
                filter.project_id,
                filter.environment_id,
                filter.status,
                limit,
                like_pattern
            ],
            secret_view_from_row,
        )
        .map_err(SecretError::Db)?;
    let mut out = Vec::new();
    for view in views {
        let view = view.map_err(SecretError::Db)?;
        if let Some(tag) = filter.tag {
            if !view.tags.iter().any(|candidate| candidate == tag) {
                continue;
            }
        }
        out.push(view);
    }
    Ok(out)
}

/// Updates secret metadata (values rotate via rotation only).
pub(crate) fn update_secret_metadata(
    db: &mut Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    secret_id: &str,
    patch: &UpdateSecretMetadata<'_>,
    request_id: &str,
) -> Result<SecretView, SecretError> {
    let view = resolve_secret(db, secret_id)?;
    let target = target_from_view(&view);
    authorize(db, claims, ScopedAction::UpdateMetadata, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    if let Some(description) = patch.description {
        validate_description(description).map_err(|err| SecretError::Invalid(err.to_string()))?;
    }
    if let Some(tags) = patch.tags {
        validate_tags(tags)?;
    }
    if let Some(status) = patch.status {
        if !matches!(status, "active" | "deprecated") {
            return Err(SecretError::Invalid(
                "status must be 'active' or 'deprecated' (deletion is separate)".to_string(),
            ));
        }
    }
    let tags_json = patch
        .tags
        .map(serde_json::to_string)
        .transpose()
        .map_err(|err| SecretError::Invalid(err.to_string()))?;
    let now = now_utc();
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    txn.execute(
        "UPDATE secrets SET description = COALESCE(?1, description),
             tags_json = COALESCE(?2, tags_json), expires_at_utc = COALESCE(?3, expires_at_utc),
             status = COALESCE(?4, status), updated_at_utc = ?5
         WHERE secret_id = ?6",
        params![
            patch.description,
            tags_json,
            patch.expires_at_utc,
            patch.status,
            now,
            secret_id,
        ],
    )?;
    audit_secret_event(
        &txn,
        &SecretAuditEvent {
            event_type: AuditEventType::SecretUpdated.as_str(),
            tenant_id: &view.tenant_id,
            project_id: Some(&view.project_id),
            environment_id: Some(&view.environment_id),
            secret_id: Some(&view.secret_id),
            secret_version: Some(view.current_version),
            principal_id: &claims.principal_id,
            request_id,
            source: "api",
            result: "success",
            reason: "",
        },
        now,
    )?;
    txn.commit()?;
    resolve_secret(db, secret_id)
}

/// Soft-deletes a secret (status + tombstone; purge/shred is a Phase 10
/// operational workflow, never silent loss).
pub(crate) fn delete_secret(
    db: &mut Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    secret_id: &str,
    reason: &str,
    request_id: &str,
) -> Result<(), SecretError> {
    let view = resolve_secret(db, secret_id)?;
    let target = target_from_view(&view);
    authorize(db, claims, ScopedAction::DeleteSecret, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    if reason.trim().is_empty() {
        return Err(SecretError::Invalid(
            "deletion requires a reason".to_string(),
        ));
    }
    let now = now_utc();
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    txn.execute(
        "UPDATE secrets SET status = 'scheduled_deletion', deleted_at_utc = ?1, updated_at_utc = ?1
         WHERE secret_id = ?2",
        params![now, secret_id],
    )?;
    audit_secret_event(
        &txn,
        &SecretAuditEvent {
            event_type: AuditEventType::SecretDeleted.as_str(),
            tenant_id: &view.tenant_id,
            project_id: Some(&view.project_id),
            environment_id: Some(&view.environment_id),
            secret_id: Some(&view.secret_id),
            secret_version: Some(view.current_version),
            principal_id: &claims.principal_id,
            request_id,
            source: "api",
            result: "success",
            reason,
        },
        now,
    )?;
    txn.commit()?;
    Ok(())
}

/// Move parameters: rename and/or re-scope (at least one required).
pub struct MoveSecret<'a> {
    pub new_name: Option<&'a str>,
    pub new_environment_id: Option<&'a str>,
    pub reason: &'a str,
    pub request_id: &'a str,
}

/// Moves/renames a secret. A scope change re-seals the current value under
/// the new scope as a new version (old versions stay intact under their
/// original scope); pure renames touch metadata only.
pub(crate) fn move_secret(
    db: &mut Connection,
    wrap: &dyn KeyWrappingService,
    kek_id: &str,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    secret_id: &str,
    input: &MoveSecret<'_>,
) -> Result<SecretView, SecretError> {
    let view = resolve_secret(db, secret_id)?;
    let target = target_from_view(&view);
    authorize(db, claims, ScopedAction::MoveSecret, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    if input.reason.trim().is_empty() {
        return Err(SecretError::Invalid("move requires a reason".to_string()));
    }
    if let Some(name) = input.new_name {
        validate_secret_name(name).map_err(|err| SecretError::Invalid(err.to_string()))?;
    }
    if let Some(env) = input.new_environment_id {
        require_row(db, "environments", "environment_id", env, "environment")?;
    }
    if input.new_name.is_none() && input.new_environment_id.is_none() {
        return Err(SecretError::Invalid(
            "move requires a new name or environment".to_string(),
        ));
    }
    let final_name = input.new_name.unwrap_or(&view.name).to_string();
    let final_env = input
        .new_environment_id
        .unwrap_or(&view.environment_id)
        .to_string();
    let rescope = final_env != view.environment_id;
    let now = now_utc();
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if rescope {
        let plaintext = open_current_version(&txn, wrap, &view)?;
        let next_version = view.current_version + 1;
        let moved_value = SecretValue::from_bytes(plaintext);
        let digest = moved_value.sha256().to_vec();
        let sealed = seal_version(
            wrap,
            &id16(&view.tenant_id, "tenant")?,
            &id16(&view.project_id, "project")?,
            &id16(&final_env, "environment")?,
            &id16(&view.secret_id, "secret")?,
            u32::try_from(next_version).unwrap_or(u32::MAX),
            &moved_value,
        )?;
        txn.execute(
            "INSERT INTO secret_versions(version_id, secret_id, version, encryption_key_id, nonce,
                 ciphertext, value_sha256, wrapped_dek, created_by, created_at_utc)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                SecretVersionId::generate().to_hex(),
                secret_id,
                next_version,
                kek_id,
                sealed.nonce,
                sealed.ciphertext,
                digest,
                sealed.wrapped_dek,
                claims.principal_id,
                now,
            ],
        )?;
        txn.execute(
            "UPDATE secrets SET name = ?1, environment_id = ?2, current_version = ?3,
                 updated_at_utc = ?4 WHERE secret_id = ?5",
            params![final_name, final_env, next_version, now, secret_id],
        )
        .map_err(map_constraint)?;
    } else {
        txn.execute(
            "UPDATE secrets SET name = ?1, updated_at_utc = ?2 WHERE secret_id = ?3",
            params![final_name, now, secret_id],
        )
        .map_err(map_constraint)?;
    }
    let moved = resolve_secret(&txn, secret_id)?;
    audit_secret_event(
        &txn,
        &SecretAuditEvent {
            event_type: AuditEventType::SecretMoved.as_str(),
            tenant_id: &moved.tenant_id,
            project_id: Some(&moved.project_id),
            environment_id: Some(&moved.environment_id),
            secret_id: Some(&moved.secret_id),
            secret_version: Some(moved.current_version),
            principal_id: &claims.principal_id,
            request_id: input.request_id,
            source: "api",
            result: "success",
            reason: input.reason,
        },
        now,
    )?;
    txn.commit()?;
    resolve_secret(db, secret_id)
}

/// Rebind parameters: `None` keeps, `Some(None)` clears, `Some(Some)` sets.
/// Confinement is policy-only (AAD carries no binding), so no re-seal.
pub struct RebindSecret<'a> {
    pub repository_binding_id: Option<Option<&'a str>>,
    pub service_id: Option<Option<&'a str>>,
    pub reason: &'a str,
    pub request_id: &'a str,
}

/// Attaches/detaches repository/service confinement.
pub(crate) fn rebind_secret(
    db: &mut Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    secret_id: &str,
    input: &RebindSecret<'_>,
) -> Result<SecretView, SecretError> {
    let view = resolve_secret(db, secret_id)?;
    let target = target_from_view(&view);
    authorize(db, claims, ScopedAction::RebindSecret, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    if input.reason.trim().is_empty() {
        return Err(SecretError::Invalid("rebind requires a reason".to_string()));
    }
    if let Some(Some(binding)) = input.repository_binding_id {
        crate::vcs::require_active_binding(db, binding, &view.tenant_id, &view.project_id)
            .map_err(map_binding_error)?;
    }
    if let Some(Some(service)) = input.service_id {
        require_row(db, "services", "service_id", service, "service")?;
    }
    let binding = match input.repository_binding_id {
        None => view.repository_binding_id.clone(),
        Some(value) => value.map(str::to_string),
    };
    let service = match input.service_id {
        None => view.service_id.clone(),
        Some(value) => value.map(str::to_string),
    };
    let now = now_utc();
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    txn.execute(
        "UPDATE secrets SET repository_binding_id = ?1, service_id = ?2, updated_at_utc = ?3
         WHERE secret_id = ?4",
        params![binding, service, now, secret_id],
    )?;
    audit_secret_event(
        &txn,
        &SecretAuditEvent {
            event_type: AuditEventType::SecretRebound.as_str(),
            tenant_id: &view.tenant_id,
            project_id: Some(&view.project_id),
            environment_id: Some(&view.environment_id),
            secret_id: Some(&view.secret_id),
            secret_version: Some(view.current_version),
            principal_id: &claims.principal_id,
            request_id: input.request_id,
            source: "api",
            result: "success",
            reason: input.reason,
        },
        now,
    )?;
    txn.commit()?;
    resolve_secret(db, secret_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::LocalKekService;
    use ciphervault_format::{EnvironmentId, ProjectId, TenantId};

    use crate::policy::{grant_project_role, ProjectRole};
    use crate::test_support::{cleanup, test_app};

    const KEK_ID: &str = "local:test";
    const KEK: [u8; 32] = [0x44; 32];

    struct Fixture {
        project: String,
        env: String,
        env2: String,
        claims: ScopeClaims,
    }

    fn seed(db: &Connection) -> Fixture {
        let tenant = TenantId::generate().to_hex();
        let project = ProjectId::generate().to_hex();
        let env = EnvironmentId::generate().to_hex();
        let env2 = EnvironmentId::generate().to_hex();
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
        for (id, slug, tier) in [(&env, "staging", 1), (&env2, "development", 0)] {
            db.execute(
                "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier,
                                           created_at_utc)
                 VALUES(?1, ?2, ?3, ?4, ?5, 1)",
                params![id, tenant, project, slug, tier],
            )
            .unwrap();
        }
        grant_project_role(
            db,
            &project,
            "account:alice",
            ProjectRole::Developer,
            "root",
            1,
        )
        .unwrap();
        let claims = ScopeClaims::new(&tenant, &project, "account:alice", 1000, 9_999_999_999)
            .with_environment(&env);
        Fixture {
            project,
            env,
            env2,
            claims,
        }
    }

    fn create_one(
        db: &mut Connection,
        wrap: &dyn KeyWrappingService,
        fixture: &Fixture,
        env: &str,
        name: &str,
        value: &SecretValue,
    ) -> SecretView {
        let tags = vec!["database".to_string()];
        let claims = ScopeClaims::new(
            &fixture.claims.tenant_id,
            &fixture.project,
            "account:alice",
            1000,
            9_999_999_999,
        )
        .with_environment(env);
        create_secret(
            db,
            wrap,
            KEK_ID,
            &claims,
            &RequestAttributes::default(),
            &CreateSecret {
                project_id: &fixture.project,
                environment_id: env,
                name,
                secret_type: "key_value",
                description: "synthetic fixture",
                tags: &tags,
                repository_binding_id: None,
                service_id: None,
                value,
                request_id: "req-1",
            },
        )
        .unwrap()
    }

    #[test]
    fn create_get_roundtrip_with_audit() {
        let (root, state, _app) = test_app("secrets-roundtrip");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        let view = create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "DATABASE_URL",
            &SecretValue::from("s3cret"),
        );
        assert_eq!(view.current_version, 1);
        assert_eq!(view.tags, vec!["database".to_string()]);
        let meta = get_secret_metadata(
            &db,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
        )
        .unwrap();
        assert_eq!(meta.secret_id, view.secret_id);
        let got = get_secret_value(
            &mut db,
            &wrap,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            "req-2",
        )
        .unwrap();
        assert_eq!(got.value.expose(), b"s3cret");
        assert_eq!(got.version, 1);
        let events: Vec<(String, String)> = db
            .prepare(
                "SELECT event_type, result FROM secret_access_events ORDER BY created_at_utc, rowid",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(events.contains(&("secret.created".to_string(), "success".to_string())));
        assert!(events.contains(&("secret.read".to_string(), "success".to_string())));
        // Audit rows carry no plaintext.
        let dump: String = db
            .query_row(
                "SELECT GROUP_CONCAT(event_type || actor_json || reason, '|')
                 FROM secret_access_events",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!dump.contains("s3cret"));
        cleanup(root);
    }

    #[test]
    fn duplicate_name_conflicts_within_scope_only() {
        let (root, state, _app) = test_app("secrets-conflict");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "API_KEY",
            &SecretValue::from("a"),
        );
        let tags: Vec<String> = vec![];
        let err = create_secret(
            &mut db,
            &wrap,
            KEK_ID,
            &fixture.claims,
            &RequestAttributes::default(),
            &CreateSecret {
                project_id: &fixture.project,
                environment_id: &fixture.env,
                name: "API_KEY",
                secret_type: "key_value",
                description: "",
                tags: &tags,
                repository_binding_id: None,
                service_id: None,
                value: &SecretValue::from("b"),
                request_id: "req-2",
            },
        )
        .unwrap_err();
        assert!(matches!(err, SecretError::Conflict));
        // Same name in the other environment is fine.
        create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env2,
            "API_KEY",
            &SecretValue::from("b"),
        );
        cleanup(root);
    }

    #[test]
    fn invalid_inputs_rejected() {
        let (root, state, _app) = test_app("secrets-invalid");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        let tags: Vec<String> = vec![];
        let mut input = CreateSecret {
            project_id: &fixture.project,
            environment_id: &fixture.env,
            name: "bad-name",
            secret_type: "key_value",
            description: "",
            tags: &tags,
            repository_binding_id: None,
            service_id: None,
            value: &SecretValue::from("x"),
            request_id: "req-1",
        };
        assert!(matches!(
            create_secret(
                &mut db,
                &wrap,
                KEK_ID,
                &fixture.claims,
                &RequestAttributes::default(),
                &input
            )
            .unwrap_err(),
            SecretError::Invalid(_)
        ));
        input.name = "GOOD_NAME";
        let ghost_project = ProjectId::generate().to_hex();
        input.project_id = &ghost_project;
        assert!(matches!(
            create_secret(
                &mut db,
                &wrap,
                KEK_ID,
                &fixture.claims,
                &RequestAttributes::default(),
                &input
            )
            .unwrap_err(),
            SecretError::Invalid(_)
        ));
        // Unknown binding with matching claims reaches the existence check.
        input.project_id = &fixture.project;
        input.repository_binding_id = Some("b-ghost");
        let bound_claims = ScopeClaims::new(
            &fixture.claims.tenant_id,
            &fixture.project,
            "account:alice",
            1000,
            9_999_999_999,
        )
        .with_environment(&fixture.env)
        .with_repository_binding("b-ghost");
        assert!(matches!(
            create_secret(
                &mut db,
                &wrap,
                KEK_ID,
                &bound_claims,
                &RequestAttributes::default(),
                &input
            )
            .unwrap_err(),
            SecretError::Invalid(_)
        ));
        cleanup(root);
    }

    #[test]
    fn access_without_grant_denied() {
        let (root, state, _app) = test_app("secrets-denied");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        let view = create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "K",
            &SecretValue::from("v"),
        );
        let mallory = ScopeClaims::new(
            &fixture.claims.tenant_id,
            &fixture.project,
            "account:mallory",
            1000,
            9_999_999_999,
        )
        .with_environment(&fixture.env);
        assert!(matches!(
            get_secret_value(
                &mut db,
                &wrap,
                &mallory,
                &RequestAttributes::default(),
                &view.secret_id,
                "r"
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        assert!(matches!(
            list_secrets(
                &db,
                &mallory,
                &RequestAttributes::default(),
                &SecretListFilter {
                    project_id: &fixture.project,
                    environment_id: &fixture.env,
                    tag: None,
                    status: None,
                    q: None,
                    limit: 10,
                },
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        cleanup(root);
    }

    #[test]
    fn cross_scope_ciphertext_replay_fails_decrypt() {
        let (root, state, _app) = test_app("secrets-aad");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        let view = create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "K",
            &SecretValue::from("v"),
        );
        // Simulate scope confusion: repoint the row at the other environment.
        db.execute(
            "UPDATE secrets SET environment_id = ?1 WHERE secret_id = ?2",
            params![fixture.env2, view.secret_id],
        )
        .unwrap();
        // Claims matching the tampered row pass policy but must fail decrypt.
        let claims = ScopeClaims::new(
            &fixture.claims.tenant_id,
            &fixture.project,
            "account:alice",
            1000,
            9_999_999_999,
        )
        .with_environment(&fixture.env2);
        let err = get_secret_value(
            &mut db,
            &wrap,
            &claims,
            &RequestAttributes::default(),
            &view.secret_id,
            "r",
        )
        .unwrap_err();
        assert!(
            matches!(err, SecretError::Crypto(_)),
            "expected crypto failure, got {err:?}"
        );
        cleanup(root);
    }

    #[test]
    fn list_filters_and_update_delete() {
        let (root, state, _app) = test_app("secrets-list");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "A_KEY",
            &SecretValue::from("a"),
        );
        create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "B_KEY",
            &SecretValue::from("b"),
        );
        let filter = |tag: Option<&'static str>| SecretListFilter {
            project_id: &fixture.project,
            environment_id: &fixture.env,
            tag,
            status: None,
            q: None,
            limit: 10,
        };
        assert_eq!(
            list_secrets(
                &db,
                &fixture.claims,
                &RequestAttributes::default(),
                &filter(None)
            )
            .unwrap()
            .len(),
            2
        );
        assert_eq!(
            list_secrets(
                &db,
                &fixture.claims,
                &RequestAttributes::default(),
                &filter(Some("database"))
            )
            .unwrap()
            .len(),
            2
        );
        assert!(list_secrets(
            &db,
            &fixture.claims,
            &RequestAttributes::default(),
            &filter(Some("nope"))
        )
        .unwrap()
        .is_empty());
        // Update metadata.
        let view = get_secret_metadata(
            &db,
            &fixture.claims,
            &RequestAttributes::default(),
            &list_secrets(
                &db,
                &fixture.claims,
                &RequestAttributes::default(),
                &filter(None),
            )
            .unwrap()[0]
                .secret_id,
        )
        .unwrap();
        let updated = update_secret_metadata(
            &mut db,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            &UpdateSecretMetadata {
                description: Some("rotated quarterly"),
                tags: None,
                expires_at_utc: None,
                status: Some("deprecated"),
            },
            "req-9",
        )
        .unwrap();
        assert_eq!(updated.description, "rotated quarterly");
        assert_eq!(updated.status, "deprecated");
        // Developer cannot delete; admin can with a reason.
        assert!(matches!(
            delete_secret(
                &mut db,
                &fixture.claims,
                &RequestAttributes::default(),
                &view.secret_id,
                "x",
                "r"
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        grant_project_role(
            &db,
            &fixture.project,
            "account:alice",
            ProjectRole::Admin,
            "root",
            2,
        )
        .unwrap();
        assert!(matches!(
            delete_secret(
                &mut db,
                &fixture.claims,
                &RequestAttributes::default(),
                &view.secret_id,
                "  ",
                "r"
            )
            .unwrap_err(),
            SecretError::Invalid(_)
        ));
        delete_secret(
            &mut db,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            "decommissioned",
            "r",
        )
        .unwrap();
        assert!(matches!(
            get_secret_metadata(
                &db,
                &fixture.claims,
                &RequestAttributes::default(),
                &view.secret_id
            )
            .unwrap_err(),
            SecretError::NotFound
        ));
        assert_eq!(
            list_secrets(
                &db,
                &fixture.claims,
                &RequestAttributes::default(),
                &filter(None)
            )
            .unwrap()
            .len(),
            1
        );
        cleanup(root);
    }

    #[test]
    fn list_name_search_is_scoped_case_insensitive_and_escaped() {
        let (root, state, _app) = test_app("secrets-search");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        for name in ["STRIPE_KEY", "STRIPE_WEBHOOK", "DATABASE_URL", "TOKEN"] {
            create_one(
                &mut db,
                &wrap,
                &fixture,
                &fixture.env,
                name,
                &SecretValue::from("v"),
            );
        }
        // Same name in the other environment must never leak into results.
        create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env2,
            "STRIPE_KEY",
            &SecretValue::from("v"),
        );
        let search = |env: &str, q: Option<&str>| {
            list_secrets(
                &db,
                &fixture.claims,
                &RequestAttributes::default(),
                &SecretListFilter {
                    project_id: &fixture.project,
                    environment_id: env,
                    tag: None,
                    status: None,
                    q,
                    limit: 10,
                },
            )
            .unwrap()
            .into_iter()
            .map(|view| view.name)
            .collect::<Vec<_>>()
        };
        // Case-insensitive substring, scoped to env (not env2's STRIPE_KEY).
        assert_eq!(
            search(&fixture.env, Some("stripe")),
            vec!["STRIPE_KEY", "STRIPE_WEBHOOK"]
        );
        // `_` matches literally: TOKEN has no underscore and is excluded
        // (an unescaped `_` wildcard would match all four).
        assert_eq!(
            search(&fixture.env, Some("_")),
            vec!["DATABASE_URL", "STRIPE_KEY", "STRIPE_WEBHOOK"]
        );
        // `%` matches literally: no name contains it.
        assert!(search(&fixture.env, Some("STRIPE%")).is_empty());
        // Empty query means no filter.
        assert_eq!(search(&fixture.env, Some("  ")).len(), 4);
        // Search never widens scope: env-scoped claims querying env2 are
        // denied outright (zero out-of-scope rows, §19).
        assert!(matches!(
            list_secrets(
                &db,
                &fixture.claims,
                &RequestAttributes::default(),
                &SecretListFilter {
                    project_id: &fixture.project,
                    environment_id: &fixture.env2,
                    tag: None,
                    status: None,
                    q: Some("stripe"),
                    limit: 10,
                },
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        cleanup(root);
    }

    #[test]
    fn audit_chain_links_events() {
        let (root, state, _app) = test_app("secrets-chain");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        let view = create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "K",
            &SecretValue::from("v"),
        );
        get_secret_value(
            &mut db,
            &wrap,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            "r",
        )
        .unwrap();
        let chain: Vec<(Vec<u8>, Vec<u8>)> = db
            .prepare("SELECT prev_hash, event_hash FROM secret_access_events ORDER BY created_at_utc, rowid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].0, chain[0].1);
        assert_ne!(chain[0].1, chain[1].1);
        cleanup(root);
    }

    #[test]
    fn move_rename_only() {
        let (root, state, _app) = test_app("secrets-move-rename");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        grant_project_role(
            &db,
            &fixture.project,
            "account:alice",
            ProjectRole::Admin,
            "root",
            2,
        )
        .unwrap();
        let view = create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "OLD_NAME",
            &SecretValue::from("v"),
        );
        let moved = move_secret(
            &mut db,
            &wrap,
            KEK_ID,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            &MoveSecret {
                new_name: Some("NEW_NAME"),
                new_environment_id: None,
                reason: "naming convention",
                request_id: "req-9",
            },
        )
        .unwrap();
        assert_eq!(moved.name, "NEW_NAME");
        assert_eq!(moved.current_version, 1);
        assert_eq!(moved.secret_id, view.secret_id);
        let got = get_secret_value(
            &mut db,
            &wrap,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            "r",
        )
        .unwrap();
        assert_eq!(got.value.expose(), b"v");
        cleanup(root);
    }

    #[test]
    fn move_rescope_reseals_value() {
        let (root, state, _app) = test_app("secrets-move-scope");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        grant_project_role(
            &db,
            &fixture.project,
            "account:alice",
            ProjectRole::Admin,
            "root",
            2,
        )
        .unwrap();
        let view = create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "K",
            &SecretValue::from("v"),
        );
        let moved = move_secret(
            &mut db,
            &wrap,
            KEK_ID,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            &MoveSecret {
                new_name: None,
                new_environment_id: Some(&fixture.env2),
                reason: "promote to dev",
                request_id: "req-9",
            },
        )
        .unwrap();
        assert_eq!(moved.environment_id, fixture.env2);
        assert_eq!(moved.current_version, 2);
        let claims = ScopeClaims::new(
            &fixture.claims.tenant_id,
            &fixture.project,
            "account:alice",
            1000,
            9_999_999_999,
        )
        .with_environment(&fixture.env2);
        let got = get_secret_value(
            &mut db,
            &wrap,
            &claims,
            &RequestAttributes::default(),
            &view.secret_id,
            "r",
        )
        .unwrap();
        assert_eq!(got.value.expose(), b"v");
        let versions: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM secret_versions WHERE secret_id = ?1",
                params![view.secret_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(versions, 2);
        cleanup(root);
    }

    #[test]
    fn move_conflict_reason_and_role() {
        let (root, state, _app) = test_app("secrets-move-guard");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "TAKEN",
            &SecretValue::from("a"),
        );
        let view = create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "FREE",
            &SecretValue::from("b"),
        );
        // Developer cannot move.
        assert!(matches!(
            move_secret(
                &mut db,
                &wrap,
                KEK_ID,
                &fixture.claims,
                &RequestAttributes::default(),
                &view.secret_id,
                &MoveSecret {
                    new_name: Some("OTHER"),
                    new_environment_id: None,
                    reason: "x",
                    request_id: "r",
                },
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        grant_project_role(
            &db,
            &fixture.project,
            "account:alice",
            ProjectRole::Admin,
            "root",
            2,
        )
        .unwrap();
        // Rename onto an existing name conflicts.
        assert!(matches!(
            move_secret(
                &mut db,
                &wrap,
                KEK_ID,
                &fixture.claims,
                &RequestAttributes::default(),
                &view.secret_id,
                &MoveSecret {
                    new_name: Some("TAKEN"),
                    new_environment_id: None,
                    reason: "x",
                    request_id: "r",
                },
            )
            .unwrap_err(),
            SecretError::Conflict
        ));
        // Empty reason rejected.
        assert!(matches!(
            move_secret(
                &mut db,
                &wrap,
                KEK_ID,
                &fixture.claims,
                &RequestAttributes::default(),
                &view.secret_id,
                &MoveSecret {
                    new_name: Some("OTHER"),
                    new_environment_id: None,
                    reason: "  ",
                    request_id: "r",
                },
            )
            .unwrap_err(),
            SecretError::Invalid(_)
        ));
        cleanup(root);
    }

    #[test]
    fn rebind_set_clear_enforced() {
        let (root, state, _app) = test_app("secrets-rebind");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        grant_project_role(
            &db,
            &fixture.project,
            "account:alice",
            ProjectRole::Admin,
            "root",
            2,
        )
        .unwrap();
        db.execute(
            "INSERT INTO repository_bindings(binding_id, tenant_id, project_id, provider,
                 external_repo_id, repo_full_name, repo_url, created_at_utc)
             VALUES('b1', ?1, ?2, 'github', '84920194', 'acme/pay', 'https://example.invalid', 1)",
            params![fixture.claims.tenant_id, fixture.project],
        )
        .unwrap();
        let view = create_one(
            &mut db,
            &wrap,
            &fixture,
            &fixture.env,
            "K",
            &SecretValue::from("v"),
        );
        rebind_secret(
            &mut db,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            &RebindSecret {
                repository_binding_id: Some(Some("b1")),
                service_id: None,
                reason: "confine to backend repo",
                request_id: "req-9",
            },
        )
        .unwrap();
        // Unbound claims now denied.
        assert!(matches!(
            get_secret_value(
                &mut db,
                &wrap,
                &fixture.claims,
                &RequestAttributes::default(),
                &view.secret_id,
                "r"
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        // Bound claims pass.
        let bound = ScopeClaims::new(
            &fixture.claims.tenant_id,
            &fixture.project,
            "account:alice",
            1000,
            9_999_999_999,
        )
        .with_environment(&fixture.env)
        .with_repository_binding("b1");
        assert!(get_secret_value(
            &mut db,
            &wrap,
            &bound,
            &RequestAttributes::default(),
            &view.secret_id,
            "r"
        )
        .is_ok());
        // Clearing restores project-wide access (confinement binds admins too:
        // the clear itself requires bound claims).
        rebind_secret(
            &mut db,
            &bound,
            &RequestAttributes::default(),
            &view.secret_id,
            &RebindSecret {
                repository_binding_id: Some(None),
                service_id: None,
                reason: "share across repos",
                request_id: "req-10",
            },
        )
        .unwrap();
        assert!(get_secret_value(
            &mut db,
            &wrap,
            &fixture.claims,
            &RequestAttributes::default(),
            &view.secret_id,
            "r"
        )
        .is_ok());
        // Unknown binding rejected.
        assert!(matches!(
            rebind_secret(
                &mut db,
                &fixture.claims,
                &RequestAttributes::default(),
                &view.secret_id,
                &RebindSecret {
                    repository_binding_id: Some(Some("b-ghost")),
                    service_id: None,
                    reason: "x",
                    request_id: "r",
                },
            )
            .unwrap_err(),
            SecretError::Invalid(_)
        ));
        cleanup(root);
    }
}
