//! Scoped-secret control-plane schema (Phase 2, T-201).
//!
//! SQLite port of Deliverable D (`report/SCOPED_SECRETS_DATABASE_SPEC.md`):
//! organizations → workspaces → projects → environments → secrets → versions,
//! plus repository bindings, services, encryption-key references, access
//! policies, principals, rotation jobs, and the append-only access-event log.
//!
//! SQLite adaptations (documented deviations from the Postgres DDL):
//! - UUIDs are `TEXT` (32-char lowercase hex from `ciphervault_format::scope`).
//! - `JSONB` → `TEXT` holding JSON; `BYTEA` → `BLOB`; `BIGINT` → `INTEGER`.
//! - Single-column foreign keys only. The composite `(tenant_id, project_id)`
//!   keys from Deliverable D would need redundant unique indexes as FK targets
//!   in SQLite; tenant scoping is instead enforced at the query layer by the
//!   Phase 3 authorization choke point (see T-301).
//! - `secret_access_events` carries no foreign keys by design: events must
//!   survive the purge of the rows they describe (tombstoned scope refs).
//! - Raw key material must never be stored here: `encryption_keys` holds
//!   KMS-wrapped blobs plus a crypto-shredding marker only.

use rusqlite::Connection;

use crate::error::AccountServiceError;

/// Creates all scoped-secret tables and indexes. Idempotent: safe to run on
/// every [`crate::state::AccountState::open`], including pre-existing
/// databases that predate scoping (greenfield tables, no backfill needed).
pub(crate) fn init_scoped_schema(connection: &Connection) -> Result<(), AccountServiceError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS organizations (
             tenant_id TEXT PRIMARY KEY,
             name TEXT NOT NULL,
             created_at_utc INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS workspaces (
             workspace_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             name TEXT NOT NULL,
             created_at_utc INTEGER NOT NULL,
             UNIQUE (tenant_id, name),
             FOREIGN KEY (tenant_id) REFERENCES organizations(tenant_id) ON DELETE RESTRICT
         );
         CREATE TABLE IF NOT EXISTS projects (
             project_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             workspace_id TEXT NOT NULL,
             slug TEXT NOT NULL,
             name TEXT NOT NULL,
             status TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'scheduled_deletion', 'purged')),
             created_at_utc INTEGER NOT NULL,
             deleted_at_utc INTEGER,
             UNIQUE (tenant_id, slug),
             FOREIGN KEY (tenant_id) REFERENCES organizations(tenant_id) ON DELETE RESTRICT,
             FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE RESTRICT
         );
         CREATE TABLE IF NOT EXISTS environments (
             environment_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             project_id TEXT NOT NULL,
             slug TEXT NOT NULL,
             tier INTEGER NOT NULL DEFAULT 0,
             created_at_utc INTEGER NOT NULL,
             deleted_at_utc INTEGER,
             UNIQUE (project_id, slug),
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE RESTRICT
         );
         CREATE TABLE IF NOT EXISTS repository_bindings (
             binding_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             project_id TEXT NOT NULL,
             provider TEXT NOT NULL,
             external_repo_id TEXT NOT NULL,
             repo_full_name TEXT NOT NULL,
             repo_url TEXT NOT NULL,
             installation_id TEXT,
             status TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'suspended', 'revoked')),
             created_at_utc INTEGER NOT NULL,
             ownership_challenge TEXT,
             ownership_verified_at_utc INTEGER,
             last_reconciled_at_utc INTEGER,
             UNIQUE (project_id, provider, external_repo_id),
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS services (
             service_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             project_id TEXT NOT NULL,
             slug TEXT NOT NULL,
             created_at_utc INTEGER NOT NULL,
             UNIQUE (project_id, slug),
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS secrets (
             secret_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             project_id TEXT NOT NULL,
             environment_id TEXT NOT NULL,
             repository_binding_id TEXT,
             service_id TEXT,
             name TEXT NOT NULL,
             secret_type TEXT NOT NULL DEFAULT 'key_value',
             description TEXT NOT NULL DEFAULT '',
             tags_json TEXT NOT NULL DEFAULT '[]',
             status TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'deprecated', 'scheduled_deletion')),
             policy_id TEXT,
             current_version INTEGER NOT NULL DEFAULT 1,
             created_by TEXT NOT NULL,
             created_at_utc INTEGER NOT NULL,
             updated_at_utc INTEGER NOT NULL,
             last_rotated_at_utc INTEGER,
             expires_at_utc INTEGER,
             last_accessed_at_utc INTEGER,
             deleted_at_utc INTEGER,
             UNIQUE (project_id, environment_id, name),
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE RESTRICT,
             FOREIGN KEY (environment_id) REFERENCES environments(environment_id) ON DELETE RESTRICT,
             FOREIGN KEY (repository_binding_id) REFERENCES repository_bindings(binding_id) ON DELETE SET NULL,
             FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS secret_versions (
             version_id TEXT PRIMARY KEY,
             secret_id TEXT NOT NULL,
             version INTEGER NOT NULL,
             encryption_key_id TEXT NOT NULL,
             nonce BLOB NOT NULL,
             ciphertext BLOB NOT NULL,
             value_sha256 BLOB NOT NULL,
             wrapped_dek BLOB NOT NULL DEFAULT x'',
             created_by TEXT NOT NULL,
             created_at_utc INTEGER NOT NULL,
             UNIQUE (secret_id, version),
             FOREIGN KEY (secret_id) REFERENCES secrets(secret_id) ON DELETE RESTRICT,
             FOREIGN KEY (encryption_key_id) REFERENCES encryption_keys(key_id) ON DELETE RESTRICT
         );
         CREATE TABLE IF NOT EXISTS encryption_keys (
             key_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             project_id TEXT,
             purpose TEXT NOT NULL,
             wrapped_key BLOB NOT NULL,
             status TEXT NOT NULL DEFAULT 'active',
             created_at_utc INTEGER NOT NULL,
             destroyed_at_utc INTEGER,
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE RESTRICT
         );
         CREATE TABLE IF NOT EXISTS secret_access_policies (
             policy_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             project_id TEXT,
             name TEXT NOT NULL,
             rules_json TEXT NOT NULL,
             created_at_utc INTEGER NOT NULL,
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS secret_principals (
             principal_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             kind TEXT NOT NULL,
             display_name TEXT NOT NULL,
             revoked_at_utc INTEGER
         );
         CREATE TABLE IF NOT EXISTS secret_rotation_jobs (
             job_id TEXT PRIMARY KEY,
             secret_id TEXT NOT NULL,
             state TEXT NOT NULL
                 CHECK (state IN ('pending', 'running', 'verifying', 'committed', 'rolled_back')),
             idempotency_key TEXT NOT NULL,
             reason TEXT NOT NULL,
             created_at_utc INTEGER NOT NULL,
             updated_at_utc INTEGER NOT NULL,
             UNIQUE (secret_id, idempotency_key),
             FOREIGN KEY (secret_id) REFERENCES secrets(secret_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS secret_access_events (
             event_id TEXT PRIMARY KEY,
             event_type TEXT NOT NULL,
             tenant_id TEXT NOT NULL,
             project_id TEXT,
             environment_id TEXT,
             secret_id TEXT,
             secret_version INTEGER,
             actor_json TEXT NOT NULL,
             request_id TEXT NOT NULL,
             source TEXT NOT NULL,
             result TEXT NOT NULL CHECK (result IN ('success', 'denied', 'error')),
             reason TEXT NOT NULL DEFAULT '',
             prev_hash BLOB NOT NULL,
             event_hash BLOB NOT NULL,
             created_at_utc INTEGER NOT NULL
         );
         CREATE TRIGGER IF NOT EXISTS secret_access_events_no_update
         BEFORE UPDATE ON secret_access_events
         BEGIN
             SELECT RAISE(ABORT, 'secret_access_events is append-only');
         END;
         CREATE TRIGGER IF NOT EXISTS secret_access_events_no_delete
         BEFORE DELETE ON secret_access_events
         BEGIN
             SELECT RAISE(ABORT, 'secret_access_events is append-only');
         END;
         CREATE TABLE IF NOT EXISTS project_members (
             project_id TEXT NOT NULL,
             principal_id TEXT NOT NULL,
             role TEXT NOT NULL CHECK (role IN ('admin', 'developer', 'operator', 'auditor')),
             granted_by TEXT NOT NULL,
             granted_at_utc INTEGER NOT NULL,
             revoked_at_utc INTEGER,
             PRIMARY KEY (project_id, principal_id),
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS scope_token_denylist (
             jti TEXT PRIMARY KEY,
             expires_at_utc INTEGER NOT NULL
         );
         -- T-303 remainder: dual-admin grant requests. Admin-role grants
         -- need a second distinct admin's approval (four-eyes); other
         -- roles grant directly. Terminal states are never rewritten.
         CREATE TABLE IF NOT EXISTS grant_requests (
             request_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             project_id TEXT NOT NULL,
             principal_id TEXT NOT NULL,
             role TEXT NOT NULL CHECK (role IN ('admin', 'developer', 'operator', 'auditor')),
             requested_by TEXT NOT NULL,
             approved_by TEXT,
             state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'expired')),
             created_at_utc INTEGER NOT NULL,
             decided_at_utc INTEGER,
             expires_at_utc INTEGER NOT NULL,
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
         );
         -- T-303 remainder: project invite lifecycle. The code is shown
         -- once at creation; only its hash is stored (mirrors the
         -- account-plane invitations table). Single-use, TTL-bound.
         CREATE TABLE IF NOT EXISTS project_invites (
             invite_id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             project_id TEXT NOT NULL,
             role TEXT NOT NULL CHECK (role IN ('developer', 'operator', 'auditor')),
             invited_by TEXT NOT NULL,
             code_hash_hex TEXT NOT NULL UNIQUE,
             state TEXT NOT NULL CHECK (state IN ('pending', 'accepted', 'revoked', 'expired')),
             created_at_utc INTEGER NOT NULL,
             expires_at_utc INTEGER NOT NULL,
             accepted_by TEXT,
             decided_at_utc INTEGER,
             FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
         );",
    )?;
    // Versions created before wrapped-DEK storage (T-401) gain the column
    // here; the empty default marks rows that predate envelope storage and
    // are rejected fail-closed by the service layer. Fresh databases get the
    // column (same definition) from the CREATE TABLE above.
    let has_wrapped_dek: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('secret_versions')
             WHERE name = 'wrapped_dek')",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);
    if !has_wrapped_dek {
        connection.execute(
            "ALTER TABLE secret_versions ADD COLUMN wrapped_dek BLOB NOT NULL DEFAULT x''",
            [],
        )?;
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_abuse_quotas_window ON abuse_quotas(window_started_at_utc)",
        [],
    )?;
    let has_key_fingerprint: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('encryption_keys') WHERE name = 'key_fingerprint')",
        [], |row| row.get(0),
    )?;
    if !has_key_fingerprint {
        connection.execute(
            "ALTER TABLE encryption_keys ADD COLUMN key_fingerprint BLOB",
            [],
        )?;
    }
    // Persist exact rotation receipts. Legacy receipts lack sufficient
    // evidence to infer their original version and require a new request key.
    for (column, ddl) in [
        ("request_digest", "BLOB"),
        ("previous_version", "INTEGER"),
        ("committed_version", "INTEGER"),
        ("provider_verified", "INTEGER"),
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('secret_rotation_jobs') WHERE name = ?1)",
            [column], |row| row.get(0),
        )?;
        if !present {
            connection.execute(
                &format!("ALTER TABLE secret_rotation_jobs ADD COLUMN {column} {ddl}"),
                [],
            )?;
        }
    }
    // Bindings created before VCS lifecycle (T-601) gain ownership-proof and
    // reconciliation columns here; NULL means "never proven / never probed"
    // and fails closed (unproven bindings stay suspended). Fresh databases
    // get the columns (same definitions) from the CREATE TABLE above.
    for (column, ddl) in [
        ("ownership_challenge", "TEXT"),
        ("ownership_verified_at_utc", "INTEGER"),
        ("last_reconciled_at_utc", "INTEGER"),
    ] {
        let has_column: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('repository_bindings')
                 WHERE name = ?1)",
                [column],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_column {
            connection.execute(
                &format!("ALTER TABLE repository_bindings ADD COLUMN {column} {ddl}"),
                [],
            )?;
        }
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_environments_project ON environments(project_id)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_repository_bindings_provider
         ON repository_bindings(provider, external_repo_id)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_secrets_tenant ON secrets(tenant_id, updated_at_utc)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_secret_versions_secret
         ON secret_versions(secret_id, version DESC)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_secret_access_events_tenant
         ON secret_access_events(tenant_id, created_at_utc DESC)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_secret_access_events_secret
         ON secret_access_events(secret_id, created_at_utc DESC)",
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::{params, ErrorCode};

    use crate::test_support::{cleanup, test_app};

    fn is_constraint_violation(err: &rusqlite::Error) -> bool {
        matches!(
            err,
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == ErrorCode::ConstraintViolation
        )
    }

    fn seed_chain(db: &rusqlite::Connection) {
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
    }

    #[test]
    fn scoped_tables_exist_on_fresh_open() {
        let (root, state, _app) = test_app("scoped-schema");
        let db = state.connection().unwrap();
        for table in [
            "organizations",
            "workspaces",
            "projects",
            "environments",
            "repository_bindings",
            "services",
            "secrets",
            "secret_versions",
            "encryption_keys",
            "secret_access_policies",
            "secret_principals",
            "secret_rotation_jobs",
            "secret_access_events",
        ] {
            let exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing table {table}");
        }
        cleanup(root);
    }

    #[test]
    fn scoped_schema_open_is_idempotent() {
        let (root, _first, _app) = test_app("scoped-idempotent");
        let second = crate::state::AccountState::open(&root).expect("reopen");
        let db = second.connection().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'secret%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(count >= 5, "scoped tables survive reopen");
        cleanup(root);
    }

    #[test]
    fn insert_full_chain_ok() {
        let (root, state, _app) = test_app("scoped-chain");
        let db = state.connection().unwrap();
        seed_chain(&db);
        db.execute(
            "INSERT INTO encryption_keys(key_id, tenant_id, project_id, purpose, wrapped_key, created_at_utc)
             VALUES('k1', 't1', 'p1', 'project_kek', x'00', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO secrets(secret_id, tenant_id, project_id, environment_id, name, created_by,
                                 created_at_utc, updated_at_utc)
             VALUES('s1', 't1', 'p1', 'e1', 'DATABASE_URL', 'alice', 1, 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO secret_versions(version_id, secret_id, version, encryption_key_id, nonce,
                                          ciphertext, value_sha256, created_by, created_at_utc)
             VALUES('v1', 's1', 1, 'k1', x'00', x'01', x'02', 'alice', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO repository_bindings(binding_id, tenant_id, project_id, provider, external_repo_id,
                                             repo_full_name, repo_url, created_at_utc)
             VALUES('b1', 't1', 'p1', 'github', '84920194', 'acme/pay', 'https://example.invalid', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO services(service_id, tenant_id, project_id, slug, created_at_utc)
             VALUES('svc1', 't1', 'p1', 'api', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO secret_principals(principal_id, tenant_id, kind, display_name)
             VALUES('account:alice', 't1', 'human', 'Alice')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO secret_rotation_jobs(job_id, secret_id, state, idempotency_key, reason,
                                              created_at_utc, updated_at_utc)
             VALUES('j1', 's1', 'pending', 'idem-1', 'scheduled', 1, 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO secret_access_events(event_id, event_type, tenant_id, project_id, secret_id,
                                              actor_json, request_id, source, result, prev_hash,
                                              event_hash, created_at_utc)
             VALUES('ev1', 'secret.created', 't1', 'p1', 's1', '{}', 'req-1', 'test', 'success',
                    x'00', x'01', 1)",
            [],
        )
        .unwrap();
        let secrets: i64 = db
            .query_row("SELECT COUNT(*) FROM secrets", [], |row| row.get(0))
            .unwrap();
        assert_eq!(secrets, 1);
        cleanup(root);
    }

    #[test]
    fn duplicate_secret_name_in_scope_rejected() {
        let (root, state, _app) = test_app("scoped-unique");
        let db = state.connection().unwrap();
        seed_chain(&db);
        db.execute(
            "INSERT INTO secrets(secret_id, tenant_id, project_id, environment_id, name, created_by,
                                 created_at_utc, updated_at_utc)
             VALUES('s1', 't1', 'p1', 'e1', 'DATABASE_URL', 'alice', 1, 1)",
            [],
        )
        .unwrap();
        let err = db
            .execute(
                "INSERT INTO secrets(secret_id, tenant_id, project_id, environment_id, name, created_by,
                                     created_at_utc, updated_at_utc)
                 VALUES('s2', 't1', 'p1', 'e1', 'DATABASE_URL', 'alice', 1, 1)",
                [],
            )
            .unwrap_err();
        assert!(
            is_constraint_violation(&err),
            "expected UNIQUE violation: {err}"
        );
        // Same name in another environment is fine.
        db.execute(
            "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
             VALUES('e2', 't1', 'p1', 'staging', 1, 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO secrets(secret_id, tenant_id, project_id, environment_id, name, created_by,
                                 created_at_utc, updated_at_utc)
             VALUES('s3', 't1', 'p1', 'e2', 'DATABASE_URL', 'alice', 1, 1)",
            [],
        )
        .unwrap();
        cleanup(root);
    }

    #[test]
    fn foreign_key_violations_rejected() {
        let (root, state, _app) = test_app("scoped-fk");
        let db = state.connection().unwrap();
        let err = db
            .execute(
                "INSERT INTO secrets(secret_id, tenant_id, project_id, environment_id, name, created_by,
                                     created_at_utc, updated_at_utc)
                 VALUES('s9', 't9', 'p9', 'e9', 'X', 'alice', 1, 1)",
                [],
            )
            .unwrap_err();
        assert!(
            is_constraint_violation(&err),
            "expected FK violation: {err}"
        );
        cleanup(root);
    }

    #[test]
    fn status_check_violations_rejected() {
        let (root, state, _app) = test_app("scoped-check");
        let db = state.connection().unwrap();
        seed_chain(&db);
        let err = db
            .execute(
                "INSERT INTO secrets(secret_id, tenant_id, project_id, environment_id, name, status,
                                     created_by, created_at_utc, updated_at_utc)
                 VALUES('s9', 't1', 'p1', 'e1', 'X', 'bogus', 'alice', 1, 1)",
                [],
            )
            .unwrap_err();
        assert!(
            is_constraint_violation(&err),
            "expected CHECK violation: {err}"
        );
        let err = db
            .execute(
                "INSERT INTO secret_rotation_jobs(job_id, secret_id, state, idempotency_key, reason,
                                                  created_at_utc, updated_at_utc)
                 VALUES('j9', 's1', 'bogus', 'idem-9', 'x', 1, 1)",
                [],
            )
            .unwrap_err();
        assert!(
            is_constraint_violation(&err),
            "expected CHECK violation: {err}"
        );
        cleanup(root);
    }

    #[test]
    fn version_and_job_uniqueness_enforced() {
        let (root, state, _app) = test_app("scoped-version-unique");
        let db = state.connection().unwrap();
        seed_chain(&db);
        db.execute(
            "INSERT INTO encryption_keys(key_id, tenant_id, project_id, purpose, wrapped_key, created_at_utc)
             VALUES('k1', 't1', 'p1', 'project_kek', x'00', 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO secrets(secret_id, tenant_id, project_id, environment_id, name, created_by,
                                 created_at_utc, updated_at_utc)
             VALUES('s1', 't1', 'p1', 'e1', 'A', 'alice', 1, 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO secret_versions(version_id, secret_id, version, encryption_key_id, nonce,
                                          ciphertext, value_sha256, created_by, created_at_utc)
             VALUES('v1', 's1', 1, 'k1', x'00', x'01', x'02', 'alice', 1)",
            [],
        )
        .unwrap();
        let err = db
            .execute(
                "INSERT INTO secret_versions(version_id, secret_id, version, encryption_key_id, nonce,
                                              ciphertext, value_sha256, created_by, created_at_utc)
                 VALUES('v2', 's1', 1, 'k1', x'00', x'01', x'02', 'alice', 1)",
                [],
            )
            .unwrap_err();
        assert!(
            is_constraint_violation(&err),
            "expected version UNIQUE: {err}"
        );
        db.execute(
            "INSERT INTO secret_rotation_jobs(job_id, secret_id, state, idempotency_key, reason,
                                              created_at_utc, updated_at_utc)
             VALUES('j1', 's1', 'pending', 'idem-1', 'x', 1, 1)",
            [],
        )
        .unwrap();
        let err = db
            .execute(
                "INSERT INTO secret_rotation_jobs(job_id, secret_id, state, idempotency_key, reason,
                                                  created_at_utc, updated_at_utc)
                 VALUES('j2', 's1', 'pending', 'idem-1', 'x', 1, 1)",
                [],
            )
            .unwrap_err();
        assert!(
            is_constraint_violation(&err),
            "expected idempotency UNIQUE: {err}"
        );
        cleanup(root);
    }
}
