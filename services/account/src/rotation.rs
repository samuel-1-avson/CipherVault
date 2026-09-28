//! Secret rotation core (Phase 4, T-402).
//!
//! Verify-before-commit rotation: the new credential passes liveness
//! verification before any write transaction opens, so a failed rotation
//! leaves the current version live (fail-safe). Concurrent rotates serialize
//! on an IMMEDIATE write transaction; retries carry idempotency keys and
//! replay the original outcome instead of minting duplicate versions.

use ciphervault_crypto::{scope_aad, seal_secret_value, DataEncryptionKey, KeyWrappingService};
use ciphervault_format::{SecretValue, SecretVersionId};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::audit_chain::AuditEventType;
use crate::policy::{authorize, RequestAttributes, ScopedAction};
use crate::scope_tokens::ScopeClaims;
use crate::secrets::{
    audit_secret_event, resolve_secret, target_from_view, SecretAuditEvent, SecretError,
};
use crate::state::now_utc;
use crate::util::random_hex;

/// Liveness check for a candidate credential (provider ping, login probe).
/// Production callers must supply a real check; [`NoopVerifier`] exists for
/// tests and for secret types with no live endpoint.
pub trait RotationVerifier {
    fn verify(&self, plaintext: &[u8]) -> bool;
}

/// Always-true verifier for tests and unverifiable secret types.
pub struct NoopVerifier;

impl RotationVerifier for NoopVerifier {
    fn verify(&self, _plaintext: &[u8]) -> bool {
        true
    }
}

/// Rotation request parameters.
pub struct RotateSecret<'a> {
    pub secret_id: &'a str,
    pub new_value: &'a SecretValue,
    pub idempotency_key: &'a str,
    pub reason: &'a str,
    pub request_id: &'a str,
}

/// Rotation outcome (logical identity preserved — only the version moves).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RotateOutcome {
    pub secret_id: String,
    pub previous_version: i64,
    pub current_version: i64,
}

/// Rotates a secret to a new verified value. Idempotent per
/// `(secret_id, idempotency_key)`: replays return the recorded outcome.
pub(crate) fn rotate_secret(
    db: &mut Connection,
    wrap: &dyn KeyWrappingService,
    kek_id: &str,
    verifier: &dyn RotationVerifier,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    input: &RotateSecret<'_>,
) -> Result<RotateOutcome, SecretError> {
    let view = resolve_secret(db, input.secret_id)?;
    let target = target_from_view(&view);
    authorize(db, claims, ScopedAction::RotateSecret, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    if input.idempotency_key.trim().is_empty() {
        return Err(SecretError::Invalid(
            "idempotency_key must not be empty".to_string(),
        ));
    }
    if let Some(state) = existing_job_state(db, input.secret_id, input.idempotency_key)? {
        if state == "committed" {
            let current = resolve_secret(db, input.secret_id)?.current_version;
            return Ok(RotateOutcome {
                secret_id: input.secret_id.to_string(),
                previous_version: current - 1,
                current_version: current,
            });
        }
        db.execute(
            "DELETE FROM secret_rotation_jobs WHERE secret_id = ?1 AND idempotency_key = ?2",
            params![input.secret_id, input.idempotency_key],
        )?;
    }
    if !verifier.verify(input.new_value.expose()) {
        record_job(db, input.secret_id, "rolled_back", input, now_utc())?;
        return Err(SecretError::VerificationFailed);
    }
    let tenant_raw = id16(&view.tenant_id, "tenant")?;
    let project_raw = id16(&view.project_id, "project")?;
    let env_raw = id16(&view.environment_id, "environment")?;
    let secret_raw = id16(&view.secret_id, "secret")?;
    let next_version = view.current_version + 1;
    let aad = scope_aad(
        &tenant_raw,
        &project_raw,
        &env_raw,
        &secret_raw,
        u32::try_from(next_version).unwrap_or(u32::MAX),
    );
    let dek = DataEncryptionKey::generate();
    let sealed = seal_secret_value(&dek, input.new_value.expose(), &aad)?;
    let wrapped = wrap.wrap_dek(&dek)?;
    let mut wrapped_blob = Vec::with_capacity(wrapped.nonce.len() + wrapped.blob.len());
    wrapped_blob.extend_from_slice(&wrapped.nonce);
    wrapped_blob.extend_from_slice(&wrapped.blob);
    let digest = input.new_value.sha256().to_vec();
    let now = now_utc();
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    txn.execute(
        "INSERT INTO secret_versions(version_id, secret_id, version, encryption_key_id, nonce,
             ciphertext, value_sha256, wrapped_dek, created_by, created_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            SecretVersionId::generate().to_hex(),
            input.secret_id,
            next_version,
            kek_id,
            sealed.nonce.to_vec(),
            sealed.ciphertext,
            digest,
            wrapped_blob,
            claims.principal_id,
            now,
        ],
    )?;
    txn.execute(
        "UPDATE secrets SET current_version = ?1, last_rotated_at_utc = ?2, updated_at_utc = ?2
         WHERE secret_id = ?3",
        params![next_version, now, input.secret_id],
    )?;
    txn.execute(
        "INSERT INTO secret_rotation_jobs(job_id, secret_id, state, idempotency_key, reason,
                                           created_at_utc, updated_at_utc)
         VALUES(?1, ?2, 'committed', ?3, ?4, ?5, ?5)",
        params![
            random_hex(16),
            input.secret_id,
            input.idempotency_key,
            input.reason,
            now,
        ],
    )?;
    audit_secret_event(
        &txn,
        &SecretAuditEvent {
            event_type: AuditEventType::SecretRotated.as_str(),
            tenant_id: &view.tenant_id,
            project_id: Some(&view.project_id),
            environment_id: Some(&view.environment_id),
            secret_id: Some(&view.secret_id),
            secret_version: Some(next_version),
            principal_id: &claims.principal_id,
            request_id: input.request_id,
            source: "api",
            result: "success",
            reason: input.reason,
        },
        now,
    )?;
    txn.commit()?;
    Ok(RotateOutcome {
        secret_id: input.secret_id.to_string(),
        previous_version: view.current_version,
        current_version: next_version,
    })
}

fn id16(hex_str: &str, what: &str) -> Result<[u8; 16], SecretError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| SecretError::Invalid(format!("malformed {what} id")))?;
    bytes.try_into().map_err(|raw: Vec<u8>| {
        SecretError::Invalid(format!("malformed {what} id: {} bytes", raw.len()))
    })
}

fn existing_job_state(
    db: &Connection,
    secret_id: &str,
    idempotency_key: &str,
) -> Result<Option<String>, SecretError> {
    db.query_row(
        "SELECT state FROM secret_rotation_jobs WHERE secret_id = ?1 AND idempotency_key = ?2",
        params![secret_id, idempotency_key],
        |row| row.get(0),
    )
    .optional()
    .map_err(SecretError::Db)
}

fn record_job(
    db: &Connection,
    secret_id: &str,
    state: &str,
    input: &RotateSecret<'_>,
    now: u64,
) -> Result<(), SecretError> {
    db.execute(
        "INSERT INTO secret_rotation_jobs(job_id, secret_id, state, idempotency_key, reason,
                                           created_at_utc, updated_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![
            random_hex(16),
            secret_id,
            state,
            input.idempotency_key,
            input.reason,
            now,
        ],
    )
    .map_err(SecretError::Db)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::LocalKekService;
    use ciphervault_format::{EnvironmentId, ProjectId, TenantId};

    use crate::policy::grant_project_role;
    use crate::policy::ProjectRole;
    use crate::secrets::{create_secret, get_secret_value, CreateSecret};
    use crate::test_support::{cleanup, test_app};

    const KEK_ID: &str = "local:test";
    const KEK: [u8; 32] = [0x44; 32];

    struct Fixture {
        project: String,
        env: String,
        claims: ScopeClaims,
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
            "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
             VALUES(?1, ?2, ?3, 'staging', 1, 1)",
            params![env, tenant, project],
        )
        .unwrap();
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
            claims,
        }
    }

    fn create_one(
        db: &mut Connection,
        wrap: &dyn KeyWrappingService,
        fixture: &Fixture,
        name: &str,
        value: &SecretValue,
    ) -> String {
        let tags: Vec<String> = vec!["database".to_string()];
        create_secret(
            db,
            wrap,
            KEK_ID,
            &fixture.claims,
            &RequestAttributes::default(),
            &CreateSecret {
                project_id: &fixture.project,
                environment_id: &fixture.env,
                name,
                secret_type: "key_value",
                description: "",
                tags: &tags,
                repository_binding_id: None,
                service_id: None,
                value,
                request_id: "req-1",
            },
        )
        .unwrap()
        .secret_id
    }

    struct RejectAll;
    impl RotationVerifier for RejectAll {
        fn verify(&self, _plaintext: &[u8]) -> bool {
            false
        }
    }

    #[test]
    fn rotate_advances_version_and_preserves_history() {
        let (root, state, _app) = test_app("rotation-happy");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        let secret_id = create_one(
            &mut db,
            &wrap,
            &fixture,
            "DATABASE_URL",
            &SecretValue::from("v1"),
        );
        let outcome = rotate_secret(
            &mut db,
            &wrap,
            KEK_ID,
            &NoopVerifier,
            &fixture.claims,
            &RequestAttributes::default(),
            &RotateSecret {
                secret_id: &secret_id,
                new_value: &SecretValue::from("v2"),
                idempotency_key: "idem-1",
                reason: "scheduled",
                request_id: "req-2",
            },
        )
        .unwrap();
        assert_eq!(outcome.previous_version, 1);
        assert_eq!(outcome.current_version, 2);
        let got = get_secret_value(
            &mut db,
            &wrap,
            &fixture.claims,
            &RequestAttributes::default(),
            &secret_id,
            "req-3",
        )
        .unwrap();
        assert_eq!(got.value.expose(), b"v2");
        assert_eq!(got.version, 2);
        let versions: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM secret_versions WHERE secret_id = ?1",
                params![secret_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(versions, 2);
        cleanup(root);
    }

    #[test]
    fn failed_verification_leaves_current_version_live() {
        let (root, state, _app) = test_app("rotation-verify-fail");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        let secret_id = create_one(
            &mut db,
            &wrap,
            &fixture,
            "API_KEY",
            &SecretValue::from("v1"),
        );
        let err = rotate_secret(
            &mut db,
            &wrap,
            KEK_ID,
            &RejectAll,
            &fixture.claims,
            &RequestAttributes::default(),
            &RotateSecret {
                secret_id: &secret_id,
                new_value: &SecretValue::from("v2"),
                idempotency_key: "idem-9",
                reason: "scheduled",
                request_id: "req-2",
            },
        )
        .unwrap_err();
        assert!(matches!(err, SecretError::VerificationFailed));
        let got = get_secret_value(
            &mut db,
            &wrap,
            &fixture.claims,
            &RequestAttributes::default(),
            &secret_id,
            "req-3",
        )
        .unwrap();
        assert_eq!(got.value.expose(), b"v1");
        assert_eq!(got.version, 1);
        let state: String = db
            .query_row(
                "SELECT state FROM secret_rotation_jobs WHERE secret_id = ?1 AND idempotency_key = 'idem-9'",
                params![secret_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "rolled_back");
        cleanup(root);
    }

    #[test]
    fn idempotent_replay_returns_recorded_outcome() {
        let (root, state, _app) = test_app("rotation-idempotent");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let fixture = seed(&db);
        let secret_id = create_one(&mut db, &wrap, &fixture, "TOKEN", &SecretValue::from("v1"));
        let first = rotate_secret(
            &mut db,
            &wrap,
            KEK_ID,
            &NoopVerifier,
            &fixture.claims,
            &RequestAttributes::default(),
            &RotateSecret {
                secret_id: &secret_id,
                new_value: &SecretValue::from("v2"),
                idempotency_key: "idem-7",
                reason: "scheduled",
                request_id: "req-2",
            },
        )
        .unwrap();
        let replay = rotate_secret(
            &mut db,
            &wrap,
            KEK_ID,
            &NoopVerifier,
            &fixture.claims,
            &RequestAttributes::default(),
            &RotateSecret {
                secret_id: &secret_id,
                new_value: &SecretValue::from("v2-other"),
                idempotency_key: "idem-7",
                reason: "scheduled",
                request_id: "req-3",
            },
        )
        .unwrap();
        assert_eq!(first, replay);
        let versions: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM secret_versions WHERE secret_id = ?1",
                params![secret_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(versions, 2);
        cleanup(root);
    }
}
