//! Ledgered vault-to-scope migration engine (Phase 8, T-801).
//!
//! Per-secret state machine (§F-§1), enforced server-side:
//!
//! ```text
//! DISCOVERED → CLASSIFIED → MAPPED → VALIDATED → MIGRATED → VERIFIED → LEGACY_PATH_DISABLED
//!      │            │            │          │           │           │
//!      └──── any failure ⇒ QUARANTINED (manual review); resume is idempotent ──┘
//! ```
//!
//! The CLI classifies local vault files and submits proposals; this module
//! validates names, scopes, and conflicts, records source digests, gates
//! every transition, and compares digests at verify time. Values never touch
//! the ledger — only SHA-256 digests. See `migration_routes.rs` for HTTP.

use rusqlite::{params, Connection, OptionalExtension};

use ciphervault_format::{validate_secret_name, MigrationEntryId, MigrationId};

use crate::policy::{authorize, AuthTarget, RequestAttributes, ScopedAction};
use crate::scope_tokens::ScopeClaims;
use crate::secrets::{audit_secret_event, delete_secret, SecretAuditEvent, SecretError};
use crate::state::now_utc;

// Entry states (§F-§1).
pub(crate) const ENTRY_DISCOVERED: &str = "DISCOVERED";
pub(crate) const ENTRY_CLASSIFIED: &str = "CLASSIFIED";
pub(crate) const ENTRY_MAPPED: &str = "MAPPED";
pub(crate) const ENTRY_VALIDATED: &str = "VALIDATED";
pub(crate) const ENTRY_MIGRATED: &str = "MIGRATED";
pub(crate) const ENTRY_VERIFIED: &str = "VERIFIED";
pub(crate) const ENTRY_LEGACY_DISABLED: &str = "LEGACY_PATH_DISABLED";
pub(crate) const ENTRY_QUARANTINED: &str = "QUARANTINED";

// Run states.
pub(crate) const RUN_PLANNING: &str = "planning";
pub(crate) const RUN_APPLYING: &str = "applying";
pub(crate) const RUN_VERIFYING: &str = "verifying";
pub(crate) const RUN_COMPLETE: &str = "complete";
pub(crate) const RUN_ABORTED: &str = "aborted";

pub(crate) fn init_migration_schema(
    connection: &Connection,
) -> Result<(), crate::AccountServiceError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS migration_runs (
            migration_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            source_vault_id TEXT NOT NULL,
            source_snapshot_hex TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'planning'
                CHECK (state IN ('planning', 'applying', 'verifying', 'complete', 'aborted')),
            created_at_utc INTEGER NOT NULL,
            updated_at_utc INTEGER NOT NULL,
            FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE RESTRICT
        );
        CREATE TABLE IF NOT EXISTS migration_entries (
            ledger_id TEXT PRIMARY KEY,
            migration_id TEXT NOT NULL,
            source_path TEXT NOT NULL,
            source_line INTEGER NOT NULL,
            name TEXT NOT NULL,
            secret_type TEXT NOT NULL DEFAULT 'key_value',
            target_environment_id TEXT,
            target_binding_id TEXT,
            target_service_id TEXT,
            state TEXT NOT NULL
                CHECK (state IN ('DISCOVERED', 'CLASSIFIED', 'MAPPED', 'VALIDATED',
                                 'MIGRATED', 'VERIFIED', 'LEGACY_PATH_DISABLED', 'QUARANTINED')),
            source_digest BLOB NOT NULL,
            target_digest BLOB,
            secret_id TEXT,
            idempotency_key TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            created_at_utc INTEGER NOT NULL,
            updated_at_utc INTEGER NOT NULL,
            UNIQUE (migration_id, source_path, source_line),
            UNIQUE (migration_id, idempotency_key),
            FOREIGN KEY (migration_id) REFERENCES migration_runs(migration_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_migration_entries_run_state
            ON migration_entries(migration_id, state);
        CREATE INDEX IF NOT EXISTS idx_migration_runs_project
            ON migration_runs(project_id, state);",
    )?;
    Ok(())
}

/// Migration errors. `Denied`/`NotFound` surface as uniform 404 at the
/// route layer; `Invalid` is a 400 with a structured code.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MigrationError {
    #[error("migration not found")]
    NotFound,
    #[error("access denied")]
    Denied,
    #[error("invalid migration request: {0}")]
    Invalid(String),
    #[error("migration secret error: {0}")]
    Secrets(#[from] SecretError),
    #[error("migration database error: {0}")]
    Db(#[from] rusqlite::Error),
}

/// One migration run (a vault import into a project).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct MigrationRunView {
    pub migration_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub source_vault_id: String,
    /// Head snapshot the plan was built from; shred refuses vaults that
    /// advanced past every run's snapshot (no-loss gate, §F-§3).
    pub source_snapshot_hex: String,
    pub created_by: String,
    pub state: String,
    pub created_at_utc: u64,
    pub updated_at_utc: u64,
    pub entry_counts: std::collections::BTreeMap<String, i64>,
}

/// One secret's ledgered journey. Digests are hex; values never appear.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct MigrationEntryView {
    pub ledger_id: String,
    pub migration_id: String,
    pub source_path: String,
    pub source_line: i64,
    pub name: String,
    pub secret_type: String,
    pub target_environment_id: Option<String>,
    pub target_binding_id: Option<String>,
    pub target_service_id: Option<String>,
    pub state: String,
    pub source_digest_hex: String,
    pub target_digest_hex: Option<String>,
    pub secret_id: Option<String>,
    pub idempotency_key: String,
    pub reason: String,
    pub created_at_utc: u64,
    pub updated_at_utc: u64,
}

/// Client proposal for one discovered secret (already classified locally).
pub(crate) struct SubmitEntry<'a> {
    pub source_path: &'a str,
    pub source_line: i64,
    pub name: &'a str,
    pub secret_type: &'a str,
    pub target_environment_id: &'a str,
    pub target_binding_id: Option<&'a str>,
    pub target_service_id: Option<&'a str>,
    pub source_digest: &'a [u8],
    pub idempotency_key: &'a str,
}

fn run_tenant(db: &Connection, project_id: &str) -> Result<Option<String>, MigrationError> {
    Ok(db
        .query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            params![project_id],
            |row| row.get(0),
        )
        .optional()?)
}

fn authorize_migration(
    db: &Connection,
    claims: &ScopeClaims,
    project_id: &str,
    attrs: &RequestAttributes,
) -> Result<(), MigrationError> {
    let tenant = run_tenant(db, project_id)?.unwrap_or_default();
    let target = AuthTarget {
        tenant_id: &tenant,
        project_id,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    authorize(db, claims, ScopedAction::ManageMigrations, &target, attrs)
        .map_err(|_| MigrationError::Denied)?;
    Ok(())
}

fn entry_view_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MigrationEntryView> {
    let source_digest: Vec<u8> = row.get(10)?;
    let target_digest: Option<Vec<u8>> = row.get(11)?;
    Ok(MigrationEntryView {
        ledger_id: row.get(0)?,
        migration_id: row.get(1)?,
        source_path: row.get(2)?,
        source_line: row.get(3)?,
        name: row.get(4)?,
        secret_type: row.get(5)?,
        target_environment_id: row.get(6)?,
        target_binding_id: row.get(7)?,
        target_service_id: row.get(8)?,
        state: row.get(9)?,
        source_digest_hex: hex::encode(&source_digest),
        target_digest_hex: target_digest.map(|digest| hex::encode(&digest)),
        secret_id: row.get(12)?,
        idempotency_key: row.get(13)?,
        reason: row.get(14)?,
        created_at_utc: row.get(15)?,
        updated_at_utc: row.get(16)?,
    })
}

const ENTRY_COLUMNS: &str = "ledger_id, migration_id, source_path, source_line, name,
    secret_type, target_environment_id, target_binding_id, target_service_id, state,
    source_digest, target_digest, secret_id, idempotency_key, reason,
    created_at_utc, updated_at_utc";

fn get_entry(
    db: &Connection,
    migration_id: &str,
    ledger_id: &str,
) -> Result<MigrationEntryView, MigrationError> {
    db.query_row(
        &format!("SELECT {ENTRY_COLUMNS} FROM migration_entries WHERE migration_id = ?1 AND ledger_id = ?2"),
        params![migration_id, ledger_id],
        entry_view_from_row,
    )
    .optional()?
    .ok_or(MigrationError::NotFound)
}

fn list_entries(
    db: &Connection,
    migration_id: &str,
) -> Result<Vec<MigrationEntryView>, MigrationError> {
    let mut stmt = db.prepare(&format!(
        "SELECT {ENTRY_COLUMNS} FROM migration_entries
         WHERE migration_id = ?1 ORDER BY source_path ASC, source_line ASC"
    ))?;
    let entries = stmt
        .query_map(params![migration_id], entry_view_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

fn count_entries(
    db: &Connection,
    migration_id: &str,
) -> Result<std::collections::BTreeMap<String, i64>, MigrationError> {
    let mut counts = std::collections::BTreeMap::new();
    let mut stmt = db.prepare(
        "SELECT state, COUNT(*) FROM migration_entries WHERE migration_id = ?1 GROUP BY state",
    )?;
    let rows = stmt.query_map(params![migration_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (state, count) = row?;
        counts.insert(state, count);
    }
    Ok(counts)
}

fn run_view(db: &Connection, migration_id: &str) -> Result<MigrationRunView, MigrationError> {
    let (
        migration_id,
        tenant_id,
        project_id,
        source_vault_id,
        source_snapshot_hex,
        created_by,
        state,
        created_at_utc,
        updated_at_utc,
    ): (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        u64,
        u64,
    ) = db
        .query_row(
            "SELECT migration_id, tenant_id, project_id, source_vault_id, source_snapshot_hex,
                    created_by, state, created_at_utc, updated_at_utc
             FROM migration_runs WHERE migration_id = ?1",
            params![migration_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()?
        .ok_or(MigrationError::NotFound)?;
    Ok(MigrationRunView {
        migration_id: migration_id.clone(),
        tenant_id,
        project_id,
        source_vault_id,
        source_snapshot_hex,
        created_by,
        state,
        created_at_utc,
        updated_at_utc,
        entry_counts: count_entries(db, &migration_id)?,
    })
}

/// Starts a migration run (admin only). One vault import per run; resume by ID.
pub(crate) fn start_run(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    source_vault_id: &str,
    source_snapshot_hex: &str,
    now: u64,
) -> Result<MigrationRunView, MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    let tenant = run_tenant(db, project_id)?.ok_or(MigrationError::NotFound)?;
    if source_vault_id.trim().is_empty() || source_vault_id.len() > 128 {
        return Err(MigrationError::Invalid(
            "source_vault_id must be 1-128 characters".to_string(),
        ));
    }
    let snapshot = source_snapshot_hex.trim();
    let snapshot_ok = hex::decode(snapshot).is_ok_and(|bytes| bytes.len() == 32);
    if !snapshot_ok {
        return Err(MigrationError::Invalid(
            "source_snapshot_hex must be 64 hex characters".to_string(),
        ));
    }
    let migration_id = format!("mig_{}", MigrationId::generate().to_hex());
    db.execute(
        "INSERT INTO migration_runs(migration_id, tenant_id, project_id, source_vault_id,
                                    source_snapshot_hex, created_by, state,
                                    created_at_utc, updated_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'planning', ?7, ?7)",
        params![
            migration_id,
            tenant,
            project_id,
            source_vault_id.trim(),
            snapshot,
            claims.principal_id,
            now as i64
        ],
    )?;
    let run = run_view(db, &migration_id)?;
    let reason = serde_json::json!({
        "migration_id": run.migration_id,
        "source_vault_id": run.source_vault_id,
        "source_snapshot_hex": run.source_snapshot_hex,
    })
    .to_string();
    audit_migration(
        db,
        "migration.started",
        &run,
        &claims.principal_id,
        &reason,
        now,
    )?;
    Ok(run)
}

/// Submits discovered secrets: upserts by `(source_path, source_line)` and
/// runs the DISCOVERED→CLASSIFIED→MAPPED→VALIDATED pipeline per entry.
/// Deterministic first-wins conflicts (sorted by path/line); re-submission
/// with the same idempotency keys is a no-op (crash/resume, §F-§3).
pub(crate) fn submit_entries(
    db: &mut Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    migration_id: &str,
    mut entries: Vec<SubmitEntry<'_>>,
    now: u64,
) -> Result<Vec<MigrationEntryView>, MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    let run = run_view(db, migration_id)?;
    if run.project_id != project_id {
        return Err(MigrationError::NotFound);
    }
    if !matches!(
        run.state.as_str(),
        RUN_PLANNING | RUN_APPLYING | RUN_VERIFYING
    ) {
        return Err(MigrationError::Invalid(format!(
            "run is {} (submissions need planning/applying/verifying)",
            run.state
        )));
    }
    if entries.len() > 5000 {
        return Err(MigrationError::Invalid(
            "at most 5000 entries per submission".to_string(),
        ));
    }
    entries.sort_by(|a, b| (a.source_path, a.source_line).cmp(&(b.source_path, b.source_line)));
    let txn = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in &entries {
        out.push(upsert_and_validate(&txn, &run, entry, now)?);
    }
    txn.commit()?;
    // Re-read post-commit for fresh views.
    let mut views = Vec::with_capacity(out.len());
    for ledger_id in out {
        views.push(get_entry(db, migration_id, &ledger_id)?);
    }
    Ok(views)
}

/// Upserts one entry and advances it through classify→map→validate.
/// Returns the ledger ID. Winners and error precedence are deterministic.
fn upsert_and_validate(
    txn: &rusqlite::Transaction<'_>,
    run: &MigrationRunView,
    entry: &SubmitEntry<'_>,
    now: u64,
) -> Result<String, MigrationError> {
    if entry.source_path.trim().is_empty() || entry.source_path.len() > 1024 {
        return Err(MigrationError::Invalid(
            "source_path must be 1-1024 characters".to_string(),
        ));
    }
    if entry.source_line < 1 {
        return Err(MigrationError::Invalid(
            "source_line must be >= 1".to_string(),
        ));
    }
    if entry.source_digest.len() != 32 {
        return Err(MigrationError::Invalid(
            "source_digest must be 32 bytes".to_string(),
        ));
    }
    if entry.idempotency_key.trim().is_empty() || entry.idempotency_key.len() > 128 {
        return Err(MigrationError::Invalid(
            "idempotency_key must be 1-128 characters".to_string(),
        ));
    }
    if entry.secret_type.trim().is_empty() || entry.secret_type.len() > 64 {
        return Err(MigrationError::Invalid(
            "secret_type must be 1-64 characters".to_string(),
        ));
    }
    // Idempotent resume: same natural key + same key ⇒ keep existing row.
    let existing: Option<(String, String, String)> = txn
        .query_row(
            "SELECT ledger_id, idempotency_key, state FROM migration_entries
             WHERE migration_id = ?1 AND source_path = ?2 AND source_line = ?3",
            params![run.migration_id, entry.source_path, entry.source_line],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((_, key, state)) = existing.as_ref() {
        if key != entry.idempotency_key {
            return Err(MigrationError::Invalid(format!(
                "idempotency key mismatch for {}:{}",
                entry.source_path, entry.source_line
            )));
        }
        // Terminal rows are immutable; re-validate live ones (a resolve may
        // have renamed a competitor since).
        if matches!(
            state.as_str(),
            ENTRY_MIGRATED | ENTRY_VERIFIED | ENTRY_LEGACY_DISABLED
        ) {
            let id = existing
                .as_ref()
                .map(|(id, _, _)| id.clone())
                .expect("checked above");
            return Ok(id);
        }
    }
    let ledger_id: String = existing
        .map(|(id, _, _)| id)
        .unwrap_or_else(|| format!("mle_{}", MigrationEntryId::generate().to_hex()));
    txn.execute(
        &format!(
            "INSERT INTO migration_entries(ledger_id, migration_id, source_path, source_line,
                                           name, secret_type, state, source_digest,
                                           idempotency_key, created_at_utc, updated_at_utc)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, '{ENTRY_DISCOVERED}', ?7, ?8, ?9, ?9)
             ON CONFLICT(migration_id, source_path, source_line) DO UPDATE SET
                 name = excluded.name, secret_type = excluded.secret_type,
                 source_digest = excluded.source_digest,
                 updated_at_utc = excluded.updated_at_utc"
        ),
        params![
            ledger_id,
            run.migration_id,
            entry.source_path,
            entry.source_line,
            entry.name,
            entry.secret_type,
            entry.source_digest,
            entry.idempotency_key,
            now as i64
        ],
    )?;
    // CLASSIFY: name rules.
    if let Err(err) = validate_secret_name(entry.name) {
        return quarantine(
            txn,
            &ledger_id,
            now,
            &format!("invalid secret name '{}': {err}", entry.name),
        );
    }
    set_state(txn, &ledger_id, ENTRY_CLASSIFIED, now)?;
    // MAP: attach targets (env/binding/service existence checked at validate).
    txn.execute(
        "UPDATE migration_entries SET target_environment_id = ?1, target_binding_id = ?2,
                                      target_service_id = ?3, updated_at_utc = ?4
         WHERE ledger_id = ?5",
        params![
            entry.target_environment_id,
            entry.target_binding_id,
            entry.target_service_id,
            now as i64,
            ledger_id
        ],
    )?;
    set_state(txn, &ledger_id, ENTRY_MAPPED, now)?;
    // VALIDATE: scope existence + conflicts.
    validate_mapped(txn, run, &ledger_id, entry, now)?;
    Ok(ledger_id)
}

fn set_state(
    txn: &rusqlite::Transaction<'_>,
    ledger_id: &str,
    state: &str,
    now: u64,
) -> Result<(), MigrationError> {
    txn.execute(
        "UPDATE migration_entries SET state = ?1, updated_at_utc = ?2 WHERE ledger_id = ?3",
        params![state, now as i64, ledger_id],
    )?;
    Ok(())
}

fn quarantine(
    txn: &rusqlite::Transaction<'_>,
    ledger_id: &str,
    now: u64,
    reason: &str,
) -> Result<String, MigrationError> {
    txn.execute(
        "UPDATE migration_entries SET state = 'QUARANTINED', reason = ?1, updated_at_utc = ?2
         WHERE ledger_id = ?3",
        params![reason, now as i64, ledger_id],
    )?;
    Ok(ledger_id.to_string())
}

/// VALIDATE gate for a MAPPED entry: scope existence, in-run first-wins
/// conflicts, and live-scope name collisions. Ends VALIDATED or QUARANTINED.
fn validate_mapped(
    txn: &rusqlite::Transaction<'_>,
    run: &MigrationRunView,
    ledger_id: &str,
    entry: &SubmitEntry<'_>,
    now: u64,
) -> Result<(), MigrationError> {
    let fail = |reason: String| -> Result<(), MigrationError> {
        quarantine(txn, ledger_id, now, &reason)?;
        Ok(())
    };
    // Target environment must exist in this project (QUARANTINED, never
    // auto-created — unknown owners need review, §F-§2.3).
    let env_exists: bool = txn.query_row(
        "SELECT EXISTS(SELECT 1 FROM environments
         WHERE project_id = ?1 AND environment_id = ?2 AND deleted_at_utc IS NULL)",
        params![run.project_id, entry.target_environment_id],
        |row| row.get(0),
    )?;
    if !env_exists {
        return fail(format!(
            "unknown environment '{}' in this project",
            entry.target_environment_id
        ));
    }
    if let Some(binding) = entry.target_binding_id {
        let binding_ok: bool = txn.query_row(
            "SELECT EXISTS(SELECT 1 FROM repository_bindings
             WHERE project_id = ?1 AND binding_id = ?2)",
            params![run.project_id, binding],
            |row| row.get(0),
        )?;
        if !binding_ok {
            return fail(format!("unknown repository binding '{binding}'"));
        }
    }
    if let Some(service) = entry.target_service_id {
        let service_ok: bool = txn.query_row(
            "SELECT EXISTS(SELECT 1 FROM services WHERE project_id = ?1 AND service_id = ?2)",
            params![run.project_id, service],
            |row| row.get(0),
        )?;
        if !service_ok {
            return fail(format!("unknown service '{service}'"));
        }
    }
    // In-run conflict: another live entry already claims (env, name).
    // Deterministic first-wins by (source_path, source_line); this entry
    // sorts after any earlier submission, so a match means it loses.
    let rival: Option<(String, String, i64)> = txn
        .query_row(
            "SELECT ledger_id, source_path, source_line FROM migration_entries
             WHERE migration_id = ?1 AND ledger_id != ?2
               AND target_environment_id = ?3 AND name = ?4
               AND state IN ('MAPPED', 'VALIDATED', 'MIGRATED', 'VERIFIED', 'LEGACY_PATH_DISABLED')
             ORDER BY source_path ASC, source_line ASC LIMIT 1",
            params![
                run.migration_id,
                ledger_id,
                entry.target_environment_id,
                entry.name
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((_, rival_path, rival_line)) = rival {
        return fail(format!(
            "duplicate name '{}' in target scope (first claimed by {}:{})",
            entry.name, rival_path, rival_line
        ));
    }
    // Live-scope collision: the target scope already holds this name.
    let taken: bool = txn.query_row(
        "SELECT EXISTS(SELECT 1 FROM secrets
         WHERE project_id = ?1 AND environment_id = ?2 AND name = ?3
           AND deleted_at_utc IS NULL)",
        params![run.project_id, entry.target_environment_id, entry.name],
        |row| row.get(0),
    )?;
    if taken {
        return fail(format!(
            "name '{}' already exists in target scope (rename to migrate)",
            entry.name
        ));
    }
    set_state(txn, ledger_id, ENTRY_VALIDATED, now)?;
    txn.execute(
        "UPDATE migration_entries SET reason = '' WHERE ledger_id = ?1",
        params![ledger_id],
    )?;
    Ok(())
}

/// Marks a VALIDATED entry MIGRATED after the client wrote the secret value
/// through the normal secret API (idempotent on `secret_id` match).
#[allow(clippy::too_many_arguments)]
pub(crate) fn mark_migrated(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    migration_id: &str,
    ledger_id: &str,
    secret_id: &str,
    target_digest: &[u8],
    now: u64,
) -> Result<MigrationEntryView, MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    let run = run_view(db, migration_id)?;
    if run.project_id != project_id {
        return Err(MigrationError::NotFound);
    }
    if !matches!(
        run.state.as_str(),
        RUN_PLANNING | RUN_APPLYING | RUN_VERIFYING
    ) {
        return Err(MigrationError::Invalid(format!(
            "run is {} (migration needs planning/applying/verifying)",
            run.state
        )));
    }
    let entry = get_entry(db, migration_id, ledger_id)?;
    // Idempotent resume: same secret re-marked is a no-op.
    if entry.state == ENTRY_MIGRATED && entry.secret_id.as_deref() == Some(secret_id) {
        return Ok(entry);
    }
    if entry.state != ENTRY_VALIDATED {
        return Err(MigrationError::Invalid(format!(
            "entry is {} (needs VALIDATED)",
            entry.state
        )));
    }
    if target_digest.len() != 32 {
        return Err(MigrationError::Invalid(
            "target_digest must be 32 bytes".to_string(),
        ));
    }
    // The secret must exist live in the claimed scope (no dangling pointers).
    let anchored: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM secrets
         WHERE secret_id = ?1 AND project_id = ?2 AND environment_id = ?3
           AND deleted_at_utc IS NULL)",
        params![
            secret_id,
            project_id,
            entry.target_environment_id.as_deref().unwrap_or_default()
        ],
        |row| row.get(0),
    )?;
    if !anchored {
        return Err(MigrationError::Invalid(
            "secret_id is not a live secret in the entry's target scope".to_string(),
        ));
    }
    db.execute(
        "UPDATE migration_entries SET state = 'MIGRATED', secret_id = ?1,
                                      target_digest = ?2, updated_at_utc = ?3
         WHERE ledger_id = ?4",
        params![secret_id, target_digest, now as i64, ledger_id],
    )?;
    // Newly migrated work returns the run to `applying` (resolve→apply
    // cycles after a verify are legitimate; verify flips forward again).
    if run.state != RUN_APPLYING {
        db.execute(
            "UPDATE migration_runs SET state = 'applying', updated_at_utc = ?1
             WHERE migration_id = ?2",
            params![now as i64, migration_id],
        )?;
    }
    get_entry(db, migration_id, ledger_id)
}

/// Resolves a QUARANTINED entry: optional rename/re-target, then re-runs
/// the validate gate (→ VALIDATED or back to QUARANTINED with a new reason).
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_entry(
    db: &mut Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    migration_id: &str,
    ledger_id: &str,
    name: Option<&str>,
    target_environment_id: Option<&str>,
    now: u64,
) -> Result<MigrationEntryView, MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    let run = run_view(db, migration_id)?;
    if run.project_id != project_id {
        return Err(MigrationError::NotFound);
    }
    if !matches!(
        run.state.as_str(),
        RUN_PLANNING | RUN_APPLYING | RUN_VERIFYING
    ) {
        return Err(MigrationError::Invalid(format!(
            "run is {} (resolve needs planning/applying/verifying)",
            run.state
        )));
    }
    let entry = get_entry(db, migration_id, ledger_id)?;
    if entry.state != ENTRY_QUARANTINED {
        return Err(MigrationError::Invalid(format!(
            "entry is {} (resolve needs QUARANTINED)",
            entry.state
        )));
    }
    let name = name.unwrap_or(&entry.name);
    let env = target_environment_id
        .or(entry.target_environment_id.as_deref())
        .ok_or_else(|| MigrationError::Invalid("resolve needs a target environment".to_string()))?;
    if let Err(err) = validate_secret_name(name) {
        return Err(MigrationError::Invalid(format!(
            "invalid secret name '{name}': {err}"
        )));
    }
    let txn = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    txn.execute(
        "UPDATE migration_entries SET name = ?1, target_environment_id = ?2,
                                      state = 'MAPPED', updated_at_utc = ?3
         WHERE ledger_id = ?4",
        params![name, env, now as i64, ledger_id],
    )?;
    let proposal = SubmitEntry {
        source_path: &entry.source_path,
        source_line: entry.source_line,
        name,
        secret_type: &entry.secret_type,
        target_environment_id: env,
        target_binding_id: entry.target_binding_id.as_deref(),
        target_service_id: entry.target_service_id.as_deref(),
        source_digest: &hex::decode(&entry.source_digest_hex).unwrap_or_default(),
        idempotency_key: &entry.idempotency_key,
    };
    validate_mapped(&txn, &run, ledger_id, &proposal, now)?;
    txn.commit()?;
    get_entry(db, migration_id, ledger_id)
}

/// Outcome of [`verify_run`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct VerifyOutcome {
    pub verified: i64,
    pub quarantined: i64,
    pub run_state: String,
}

/// Verifies every MIGRATED entry by comparing the recorded target digest
/// against the source digest (§F-§3 final gate). Matches flip to VERIFIED
/// (the cutover pointer: legacy file line → scoped secret); mismatches go
/// back to QUARANTINED. Completes the run when nothing is left in flight.
pub(crate) fn verify_run(
    db: &mut Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    migration_id: &str,
    now: u64,
) -> Result<VerifyOutcome, MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    let run = run_view(db, migration_id)?;
    if run.project_id != project_id {
        return Err(MigrationError::NotFound);
    }
    if !matches!(run.state.as_str(), RUN_APPLYING | RUN_VERIFYING) {
        return Err(MigrationError::Invalid(format!(
            "run is {} (verify needs applying/verifying)",
            run.state
        )));
    }
    let txn = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut stmt = txn.prepare(
        "SELECT ledger_id, source_digest, target_digest FROM migration_entries
         WHERE migration_id = ?1 AND state = 'MIGRATED'",
    )?;
    let migrated: Vec<(String, Vec<u8>, Option<Vec<u8>>)> = stmt
        .query_map(params![migration_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    let mut verified = 0i64;
    let mut quarantined = 0i64;
    for (ledger_id, source_digest, target_digest) in &migrated {
        if target_digest.as_deref() == Some(source_digest.as_slice()) {
            txn.execute(
                "UPDATE migration_entries SET state = 'VERIFIED', reason = '', updated_at_utc = ?1
                 WHERE ledger_id = ?2",
                params![now as i64, ledger_id],
            )?;
            verified += 1;
        } else {
            txn.execute(
                "UPDATE migration_entries SET state = 'QUARANTINED',
                    reason = 'digest mismatch: applied bytes differ from source', updated_at_utc = ?1
                 WHERE ledger_id = ?2",
                params![now as i64, ledger_id],
            )?;
            quarantined += 1;
        }
    }
    txn.execute(
        "UPDATE migration_runs SET state = 'verifying', updated_at_utc = ?1 WHERE migration_id = ?2",
        params![now as i64, migration_id],
    )?;
    txn.commit()?;
    maybe_complete(db, migration_id, now)?;
    let run = run_view(db, migration_id)?;
    let reason = serde_json::json!({
        "migration_id": run.migration_id,
        "verified": verified,
        "quarantined": quarantined,
        "run_state": run.state,
    })
    .to_string();
    audit_migration(
        db,
        "migration.verified",
        &run,
        &claims.principal_id,
        &reason,
        now,
    )?;
    if run.state == RUN_COMPLETE {
        // Verify only runs from applying/verifying, so `complete` here
        // means this call flipped it.
        let completed = serde_json::json!({
            "migration_id": run.migration_id,
            "via": "verify",
        })
        .to_string();
        audit_migration(
            db,
            "migration.completed",
            &run,
            &claims.principal_id,
            &completed,
            now,
        )?;
    }
    Ok(VerifyOutcome {
        verified,
        quarantined,
        run_state: run.state,
    })
}

fn maybe_complete(db: &Connection, migration_id: &str, now: u64) -> Result<(), MigrationError> {
    let open: i64 = db.query_row(
        "SELECT COUNT(*) FROM migration_entries WHERE migration_id = ?1
         AND state NOT IN ('VERIFIED', 'LEGACY_PATH_DISABLED')",
        params![migration_id],
        |row| row.get(0),
    )?;
    if open == 0 {
        db.execute(
            "UPDATE migration_runs SET state = 'complete', updated_at_utc = ?1
             WHERE migration_id = ?2 AND state != 'aborted'",
            params![now as i64, migration_id],
        )?;
    }
    Ok(())
}

/// Disables the legacy path per entry (only from VERIFIED, §F-§2.8).
/// `ledger_ids = None` disables every VERIFIED entry in the run.
pub(crate) fn disable_legacy(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    migration_id: &str,
    ledger_ids: Option<&[String]>,
    now: u64,
) -> Result<i64, MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    let run = run_view(db, migration_id)?;
    if run.project_id != project_id {
        return Err(MigrationError::NotFound);
    }
    if !matches!(run.state.as_str(), RUN_VERIFYING | RUN_COMPLETE) {
        return Err(MigrationError::Invalid(format!(
            "run is {} (disable-legacy needs verifying/complete)",
            run.state
        )));
    }
    let was_complete = run.state == RUN_COMPLETE;
    let targets: Vec<String> = match ledger_ids {
        Some(ids) => ids.to_vec(),
        None => {
            let mut stmt = db.prepare(
                "SELECT ledger_id FROM migration_entries
                 WHERE migration_id = ?1 AND state = 'VERIFIED'",
            )?;
            let ids: Vec<String> = stmt
                .query_map(params![migration_id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids
        }
    };
    let mut disabled = 0i64;
    for ledger_id in &targets {
        let changed = db.execute(
            "UPDATE migration_entries SET state = 'LEGACY_PATH_DISABLED', updated_at_utc = ?1
             WHERE migration_id = ?2 AND ledger_id = ?3 AND state = 'VERIFIED'",
            params![now as i64, migration_id, ledger_id],
        )?;
        if changed == 0 {
            let exists: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM migration_entries
                 WHERE migration_id = ?1 AND ledger_id = ?2)",
                params![migration_id, ledger_id],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(MigrationError::NotFound);
            }
            return Err(MigrationError::Invalid(format!(
                "entry {ledger_id} is not VERIFIED"
            )));
        }
        disabled += 1;
    }
    maybe_complete(db, migration_id, now)?;
    let run = run_view(db, migration_id)?;
    let reason = serde_json::json!({
        "migration_id": run.migration_id,
        "disabled": disabled,
    })
    .to_string();
    audit_migration(
        db,
        "migration.legacy_disabled",
        &run,
        &claims.principal_id,
        &reason,
        now,
    )?;
    if !was_complete && run.state == RUN_COMPLETE {
        let completed = serde_json::json!({
            "migration_id": run.migration_id,
            "via": "disable-legacy",
        })
        .to_string();
        audit_migration(
            db,
            "migration.completed",
            &run,
            &claims.principal_id,
            &completed,
            now,
        )?;
    }
    Ok(disabled)
}

/// Aborts a run (rollback, §F-§3): flips MIGRATED/VERIFIED cutover pointers
/// back to VALIDATED and soft-deletes the scoped rows created by this run
/// (retained for forensics via `scheduled_deletion`); legacy vaults intact.
pub(crate) fn abort_run(
    db: &mut Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    migration_id: &str,
    request_id: &str,
    now: u64,
) -> Result<i64, MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    let run = run_view(db, migration_id)?;
    if run.project_id != project_id {
        return Err(MigrationError::NotFound);
    }
    if matches!(run.state.as_str(), RUN_COMPLETE | RUN_ABORTED) {
        return Err(MigrationError::Invalid(format!(
            "run is already {}",
            run.state
        )));
    }
    let doomed: Vec<(String, Option<String>)> = {
        let mut stmt = db.prepare(
            "SELECT ledger_id, secret_id FROM migration_entries
             WHERE migration_id = ?1 AND state IN ('MIGRATED', 'VERIFIED')",
        )?;
        let rows: Vec<(String, Option<String>)> = stmt
            .query_map(params![migration_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let mut rolled_back = 0i64;
    for (ledger_id, secret_id) in &doomed {
        if let Some(secret_id) = secret_id {
            // Best-effort per secret: a manually deleted row must not wedge
            // the rollback; only hard failures abort.
            match delete_secret(
                db,
                claims,
                attrs,
                secret_id,
                &format!("migration {migration_id} aborted"),
                request_id,
            ) {
                Ok(()) | Err(SecretError::NotFound) => {}
                Err(err) => return Err(MigrationError::Secrets(err)),
            }
        }
        db.execute(
            "UPDATE migration_entries SET state = 'VALIDATED', secret_id = NULL,
                target_digest = NULL, reason = 'rolled back', updated_at_utc = ?1
             WHERE ledger_id = ?2",
            params![now as i64, ledger_id],
        )?;
        rolled_back += 1;
    }
    db.execute(
        "UPDATE migration_runs SET state = 'aborted', updated_at_utc = ?1 WHERE migration_id = ?2",
        params![now as i64, migration_id],
    )?;
    let run = run_view(db, migration_id)?;
    let reason = serde_json::json!({
        "migration_id": run.migration_id,
        "rolled_back": rolled_back,
    })
    .to_string();
    audit_migration(
        db,
        "migration.aborted",
        &run,
        &claims.principal_id,
        &reason,
        now,
    )?;
    Ok(rolled_back)
}

/// Full run detail (run + entries) for status/resume/dry-run display.
pub(crate) fn get_run_detail(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
    migration_id: &str,
) -> Result<(MigrationRunView, Vec<MigrationEntryView>), MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    let run = run_view(db, migration_id)?;
    if run.project_id != project_id {
        return Err(MigrationError::NotFound);
    }
    let entries = list_entries(db, migration_id)?;
    Ok((run, entries))
}

/// All runs in a project (shred gate + operator overview).
pub(crate) fn list_runs(
    db: &Connection,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project_id: &str,
) -> Result<Vec<MigrationRunView>, MigrationError> {
    authorize_migration(db, claims, project_id, attrs)?;
    if run_tenant(db, project_id)?.is_none() {
        return Err(MigrationError::NotFound);
    }
    let mut stmt = db.prepare(
        "SELECT migration_id FROM migration_runs WHERE project_id = ?1 ORDER BY created_at_utc ASC",
    )?;
    let ids: Vec<String> = stmt
        .query_map(params![project_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut runs = Vec::with_capacity(ids.len());
    for id in &ids {
        runs.push(run_view(db, id)?);
    }
    Ok(runs)
}

pub(crate) fn now_secs() -> u64 {
    now_utc()
}

/// Emits a `migration.*` lifecycle event into the hash-chained audit log
/// (Phase 8 requires admin-gated migration to write the audit chain).
/// `request_id` is the run id: a migration is one logical operation across
/// many HTTP calls, so the stable run id correlates better than per-call
/// random ids. Per-entry evidence lives in the ledger table itself.
fn audit_migration(
    db: &Connection,
    event_type: &str,
    run: &MigrationRunView,
    principal_id: &str,
    reason: &str,
    now: u64,
) -> Result<(), MigrationError> {
    audit_secret_event(
        db,
        &SecretAuditEvent {
            event_type,
            tenant_id: &run.tenant_id,
            project_id: Some(&run.project_id),
            environment_id: None,
            secret_id: None,
            secret_version: None,
            principal_id,
            request_id: &run.migration_id,
            source: "migration",
            result: "success",
            reason,
        },
        now,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::LocalKekService;
    use ciphervault_format::{EnvironmentId, ProjectId, SecretValue, TenantId};
    use rusqlite::params;

    use crate::policy::{grant_project_role, ProjectRole};
    use crate::secrets::{create_secret, get_secret_metadata, CreateSecret};
    use crate::test_support::{cleanup, test_app};

    const KEK_ID: &str = "local:test";
    const KEK: [u8; 32] = [0x22; 32];
    const SNAP_HEX: &str = "abababababababababababababababababababababababababababababababab";

    struct Fixture {
        project: String,
        env: String,
        admin: ScopeClaims,
        dev: ScopeClaims,
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
        grant_project_role(
            db,
            &project,
            "account:bob",
            ProjectRole::Developer,
            "root",
            1,
        )
        .unwrap();
        // Core calls need env-bearing claims (project-wide tokens only fan
        // out at the route layer); migration targets carry no env, so one
        // env-scoped admin identity serves both.
        let admin = ScopeClaims::new(&tenant, &project, "account:alice", 1000, 9_999_999_999)
            .with_environment(&env);
        let dev = ScopeClaims::new(&tenant, &project, "account:bob", 1000, 9_999_999_999)
            .with_environment(&env);
        Fixture {
            project,
            env,
            admin,
            dev,
        }
    }

    fn digest(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn proposal<'a>(
        path: &'a str,
        line: i64,
        name: &'a str,
        env: &'a str,
        source_digest: &'a [u8],
        key: &'a str,
    ) -> SubmitEntry<'a> {
        SubmitEntry {
            source_path: path,
            source_line: line,
            name,
            secret_type: "key_value",
            target_environment_id: env,
            target_binding_id: None,
            target_service_id: None,
            source_digest,
            idempotency_key: key,
        }
    }

    fn create_live_secret(db: &mut Connection, fixture: &Fixture, env: &str, name: &str) -> String {
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let tags: Vec<String> = vec![];
        create_secret(
            db,
            &wrap,
            KEK_ID,
            &fixture.admin,
            &RequestAttributes::default(),
            &CreateSecret {
                project_id: &fixture.project,
                environment_id: env,
                name,
                secret_type: "key_value",
                description: "migrated",
                tags: &tags,
                repository_binding_id: None,
                service_id: None,
                value: &SecretValue::from("v"),
                request_id: "req-mig",
            },
        )
        .unwrap()
        .secret_id
    }

    #[test]
    fn run_lifecycle_happy_path_to_legacy_disabled() {
        let (root, state, _app) = test_app("mig-happy");
        let mut db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let run = start_run(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            "vault-deadbeef",
            SNAP_HEX,
            100,
        )
        .unwrap();
        assert_eq!(run.source_snapshot_hex, SNAP_HEX);
        assert!(run.migration_id.starts_with("mig_"));
        assert_eq!(run.state, "planning");

        let d1 = digest(1);
        let d2 = digest(2);
        let entries = submit_entries(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            vec![
                proposal(".env", 2, "STRIPE_KEY", &fixture.env, &d1, "k1"),
                proposal(".env", 3, "DATABASE_URL", &fixture.env, &d2, "k2"),
            ],
            101,
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.state == "VALIDATED"));

        // Apply through the normal secret API, then mark migrated.
        for (entry, digest) in entries.iter().zip([&d1, &d2]) {
            let secret_id = create_live_secret(&mut db, &fixture, &fixture.env, &entry.name);
            let marked = mark_migrated(
                &db,
                &fixture.admin,
                &attrs,
                &fixture.project,
                &run.migration_id,
                &entry.ledger_id,
                &secret_id,
                digest,
                102,
            )
            .unwrap();
            assert_eq!(marked.state, "MIGRATED");
        }

        let outcome = verify_run(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            103,
        )
        .unwrap();
        assert_eq!(outcome.verified, 2);
        assert_eq!(outcome.quarantined, 0);
        assert_eq!(outcome.run_state, "complete");

        let disabled = disable_legacy(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            None,
            104,
        )
        .unwrap();
        assert_eq!(disabled, 2);
        let (run, entries) = get_run_detail(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
        )
        .unwrap();
        assert_eq!(run.state, "complete");
        assert!(entries
            .iter()
            .all(|entry| entry.state == "LEGACY_PATH_DISABLED"));
        assert_eq!(
            list_runs(&db, &fixture.admin, &attrs, &fixture.project)
                .unwrap()
                .len(),
            1
        );
        cleanup(root);
    }

    #[test]
    fn submit_detects_conflicts_and_quarantines_with_provenance() {
        let (root, state, _app) = test_app("mig-conflict");
        let mut db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let run = start_run(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            "v1",
            SNAP_HEX,
            100,
        )
        .unwrap();

        // Live secret occupies DATABASE_URL in env.
        create_live_secret(&mut db, &fixture, &fixture.env, "DATABASE_URL");
        let digest = digest(7);
        let entries = submit_entries(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            vec![
                proposal(".env", 2, "STRIPE_KEY", &fixture.env, &digest, "k1"),
                // Duplicate in the same scope: first (path, line) wins.
                proposal(".env.local", 9, "STRIPE_KEY", &fixture.env, &digest, "k2"),
                proposal(".env", 4, "bad name", &fixture.env, &digest, "k3"),
                proposal(".env", 5, "ORPHAN", "env-ghost", &digest, "k4"),
                proposal(".env", 6, "DATABASE_URL", &fixture.env, &digest, "k5"),
            ],
            101,
        )
        .unwrap();
        let by_key = |key: &str| {
            entries
                .iter()
                .find(|entry| entry.idempotency_key == key)
                .unwrap()
        };
        assert_eq!(by_key("k1").state, "VALIDATED");
        assert_eq!(by_key("k2").state, "QUARANTINED");
        assert!(
            by_key("k2").reason.contains(".env:2"),
            "missing provenance: {}",
            by_key("k2").reason
        );
        assert_eq!(by_key("k3").state, "QUARANTINED");
        assert!(by_key("k3").reason.contains("invalid secret name"));
        assert_eq!(by_key("k4").state, "QUARANTINED");
        assert!(by_key("k4").reason.contains("unknown environment"));
        assert_eq!(by_key("k5").state, "QUARANTINED");
        assert!(by_key("k5").reason.contains("already exists"));
        cleanup(root);
    }

    #[test]
    fn submit_is_idempotent_and_rejects_key_mismatch() {
        let (root, state, _app) = test_app("mig-idem");
        let mut db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let run = start_run(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            "v1",
            SNAP_HEX,
            100,
        )
        .unwrap();
        let digest = digest(3);
        let first = submit_entries(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            vec![proposal(".env", 2, "A_KEY", &fixture.env, &digest, "k1")],
            101,
        )
        .unwrap();
        let second = submit_entries(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            vec![proposal(".env", 2, "A_KEY", &fixture.env, &digest, "k1")],
            102,
        )
        .unwrap();
        assert_eq!(first[0].ledger_id, second[0].ledger_id);
        assert_eq!(second[0].state, "VALIDATED");
        // Same natural key, different idempotency key ⇒ client bug, reject.
        assert!(matches!(
            submit_entries(
                &mut db,
                &fixture.admin,
                &attrs,
                &fixture.project,
                &run.migration_id,
                vec![proposal(".env", 2, "A_KEY", &fixture.env, &digest, "k9")],
                103,
            )
            .unwrap_err(),
            MigrationError::Invalid(_)
        ));
        cleanup(root);
    }

    #[test]
    fn resolve_rename_revalidates_or_rejects() {
        let (root, state, _app) = test_app("mig-resolve");
        let mut db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let run = start_run(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            "v1",
            SNAP_HEX,
            100,
        )
        .unwrap();
        let digest = digest(4);
        let entries = submit_entries(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            vec![
                proposal(".env", 2, "DUP", &fixture.env, &digest, "k1"),
                proposal(".env.local", 2, "DUP", &fixture.env, &digest, "k2"),
            ],
            101,
        )
        .unwrap();
        let loser = entries
            .iter()
            .find(|entry| entry.idempotency_key == "k2")
            .unwrap();
        assert_eq!(loser.state, "QUARANTINED");
        // Rename to a free name ⇒ VALIDATED.
        let fixed = resolve_entry(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            &loser.ledger_id,
            Some("DUP__FROM_LOCAL"),
            None,
            102,
        )
        .unwrap();
        assert_eq!(fixed.state, "VALIDATED");
        assert_eq!(fixed.name, "DUP__FROM_LOCAL");
        // Resolving a live entry is rejected.
        assert!(matches!(
            resolve_entry(
                &mut db,
                &fixture.admin,
                &attrs,
                &fixture.project,
                &run.migration_id,
                &fixed.ledger_id,
                None,
                None,
                103,
            )
            .unwrap_err(),
            MigrationError::Invalid(_)
        ));
        cleanup(root);
    }

    #[test]
    fn verify_digest_mismatch_quarantines_and_blocks_complete() {
        let (root, state, _app) = test_app("mig-verify");
        let mut db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let run = start_run(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            "v1",
            SNAP_HEX,
            100,
        )
        .unwrap();
        let source = digest(5);
        let wrong = digest(6);
        let entries = submit_entries(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            vec![proposal(".env", 2, "K", &fixture.env, &source, "k1")],
            101,
        )
        .unwrap();
        let secret_id = create_live_secret(&mut db, &fixture, &fixture.env, "K");
        mark_migrated(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            &entries[0].ledger_id,
            &secret_id,
            &wrong,
            102,
        )
        .unwrap();
        let outcome = verify_run(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            103,
        )
        .unwrap();
        assert_eq!(outcome.verified, 0);
        assert_eq!(outcome.quarantined, 1);
        assert_eq!(outcome.run_state, "verifying");
        let (_, entries) = get_run_detail(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
        )
        .unwrap();
        assert_eq!(entries[0].state, "QUARANTINED");
        assert!(entries[0].reason.contains("digest mismatch"));
        // Resolve→apply cycles work after a verify (run returns to applying).
        let fixed = resolve_entry(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            &entries[0].ledger_id,
            Some("K_FIXED"),
            None,
            104,
        )
        .unwrap();
        assert_eq!(fixed.state, "VALIDATED");
        let secret_id = create_live_secret(&mut db, &fixture, &fixture.env, "K_FIXED");
        mark_migrated(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            &fixed.ledger_id,
            &secret_id,
            &source,
            105,
        )
        .unwrap();
        let (run, _) = get_run_detail(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
        )
        .unwrap();
        assert_eq!(run.state, "applying");
        cleanup(root);
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        let (root, state, _app) = test_app("mig-trans");
        let mut db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let run = start_run(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            "v1",
            SNAP_HEX,
            100,
        )
        .unwrap();
        let digest = digest(8);
        let entries = submit_entries(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            vec![
                proposal(".env", 2, "K", &fixture.env, &digest, "k1"),
                proposal(".env", 3, "bad name", &fixture.env, &digest, "k2"),
            ],
            101,
        )
        .unwrap();
        let quarantined = entries
            .iter()
            .find(|entry| entry.idempotency_key == "k2")
            .unwrap();
        // Mark needs VALIDATED + a live secret in scope.
        assert!(matches!(
            mark_migrated(
                &db,
                &fixture.admin,
                &attrs,
                &fixture.project,
                &run.migration_id,
                &quarantined.ledger_id,
                "sec-ghost",
                &digest,
                102,
            )
            .unwrap_err(),
            MigrationError::Invalid(_)
        ));
        assert!(matches!(
            mark_migrated(
                &db,
                &fixture.admin,
                &attrs,
                &fixture.project,
                &run.migration_id,
                &entries[0].ledger_id,
                "sec-ghost",
                &digest,
                102,
            )
            .unwrap_err(),
            MigrationError::Invalid(_)
        ));
        // Disable-legacy needs verifying/complete runs and VERIFIED entries.
        assert!(matches!(
            disable_legacy(
                &db,
                &fixture.admin,
                &attrs,
                &fixture.project,
                &run.migration_id,
                None,
                102,
            )
            .unwrap_err(),
            MigrationError::Invalid(_)
        ));
        // Verify needs applying/verifying runs.
        assert!(matches!(
            verify_run(
                &mut db,
                &fixture.admin,
                &attrs,
                &fixture.project,
                &run.migration_id,
                102,
            )
            .unwrap_err(),
            MigrationError::Invalid(_)
        ));
        cleanup(root);
    }

    #[test]
    fn abort_rolls_back_and_soft_deletes() {
        let (root, state, _app) = test_app("mig-abort");
        let mut db = state.connection().unwrap();
        let fixture = seed(&db);
        let attrs = RequestAttributes::default();
        let run = start_run(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            "v1",
            SNAP_HEX,
            100,
        )
        .unwrap();
        let digest = digest(9);
        let entries = submit_entries(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            vec![proposal(".env", 2, "K", &fixture.env, &digest, "k1")],
            101,
        )
        .unwrap();
        let secret_id = create_live_secret(&mut db, &fixture, &fixture.env, "K");
        mark_migrated(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            &entries[0].ledger_id,
            &secret_id,
            &digest,
            102,
        )
        .unwrap();
        let rolled_back = abort_run(
            &mut db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
            "req-abort",
            103,
        )
        .unwrap();
        assert_eq!(rolled_back, 1);
        // Scoped row soft-deleted (forensics retained, reads fail).
        assert!(matches!(
            get_secret_metadata(
                &db,
                &fixture.admin,
                &RequestAttributes::default(),
                &secret_id
            )
            .unwrap_err(),
            crate::secrets::SecretError::NotFound
        ));
        let (run, entries) = get_run_detail(
            &db,
            &fixture.admin,
            &attrs,
            &fixture.project,
            &run.migration_id,
        )
        .unwrap();
        assert_eq!(run.state, "aborted");
        assert_eq!(entries[0].state, "VALIDATED");
        assert!(entries[0].secret_id.is_none());
        // Double abort rejected.
        assert!(matches!(
            abort_run(
                &mut db,
                &fixture.admin,
                &attrs,
                &fixture.project,
                &run.migration_id,
                "req-abort-2",
                104,
            )
            .unwrap_err(),
            MigrationError::Invalid(_)
        ));
        cleanup(root);
    }

    #[test]
    fn non_admin_is_denied_without_oracle() {
        let (root, state, _app) = test_app("mig-deny");
        let db = state.connection().unwrap();
        let fixture = seed(&db);
        assert!(matches!(
            start_run(
                &db,
                &fixture.dev,
                &RequestAttributes::default(),
                &fixture.project,
                "v1",
                SNAP_HEX,
                100
            )
            .unwrap_err(),
            MigrationError::Denied
        ));
        // Bad snapshot binding rejected even for admins.
        assert!(matches!(
            start_run(
                &db,
                &fixture.admin,
                &RequestAttributes::default(),
                &fixture.project,
                "v1",
                "zz",
                100
            )
            .unwrap_err(),
            MigrationError::Invalid(_)
        ));
        let run = start_run(
            &db,
            &fixture.admin,
            &RequestAttributes::default(),
            &fixture.project,
            "v1",
            SNAP_HEX,
            100,
        )
        .unwrap();
        assert!(matches!(
            list_runs(
                &db,
                &fixture.dev,
                &RequestAttributes::default(),
                &fixture.project
            )
            .unwrap_err(),
            MigrationError::Denied
        ));
        assert!(matches!(
            get_run_detail(
                &db,
                &fixture.dev,
                &RequestAttributes::default(),
                &fixture.project,
                &run.migration_id
            )
            .unwrap_err(),
            MigrationError::Denied
        ));
        cleanup(root);
    }
}
