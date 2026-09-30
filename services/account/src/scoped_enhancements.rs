//! Atomic scoped value materialization and audited local KEK rewrapping.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use ciphervault_crypto::{KeyWrappingService, WrappedDek, NONCE_SIZE, TAG_SIZE};
use ciphervault_format::{validate_secret_name, SecretValue};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::policy::{authorize, AuthTarget, RequestAttributes, ScopedAction};
use crate::scope_tokens::ScopeClaims;
use crate::secret_routes::{authenticate, secret_error_response, wrapping_for};
use crate::secrets::{
    audit_secret_event, ensure_kek_row, open_current_version, resolve_secret, target_from_view,
    SecretAuditEvent, SecretError, SecretView,
};
use crate::state::{now_utc, AccountState};
use crate::util::random_hex;

const MAX_BATCH_NAMES: usize = 100;
const MAX_BATCH_VALUE_BYTES: usize = 128 * 1024;

#[derive(Deserialize)]
pub(crate) struct MaterializeBody {
    names: Vec<String>,
    expected_revision: Option<String>,
}

#[derive(Debug)]
struct MaterializedValue {
    name: String,
    secret_id: String,
    version: i64,
    value: SecretValue,
}

/// Revision of the exact visible/selected metadata set; values are excluded.
pub(crate) fn scope_revision(project: &str, environment: &str, views: &[SecretView]) -> String {
    let mut selected: Vec<_> = views
        .iter()
        .map(|view| {
            (
                &view.secret_id,
                &view.name,
                view.current_version,
                &view.repository_binding_id,
                &view.service_id,
                &view.status,
            )
        })
        .collect();
    selected.sort_by(|left, right| left.1.cmp(right.1));
    let input = serde_json::json!([project, environment, selected]);
    hex::encode(Sha256::digest(input.to_string().as_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn materialize(
    db: &mut Connection,
    wrap: &dyn KeyWrappingService,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project: &str,
    environment: &str,
    names: &[String],
    expected_revision: Option<&str>,
    request_id: &str,
) -> Result<(String, Vec<MaterializedValue>), SecretError> {
    if names.len() > MAX_BATCH_NAMES {
        return Err(SecretError::Invalid(
            "names must contain at most 100 unique secret names".into(),
        ));
    }
    if expected_revision
        .is_some_and(|revision| revision.len() != 64 || hex::decode(revision).is_err())
    {
        return Err(SecretError::Invalid(
            "expected_revision must be a 32-byte hex revision".into(),
        ));
    }
    let mut unique = BTreeSet::new();
    for name in names {
        validate_secret_name(name).map_err(|error| SecretError::Invalid(error.to_string()))?;
        if !unique.insert(name) {
            return Err(SecretError::Invalid("duplicate secret name".into()));
        }
    }
    // The same transaction observes versions, decrypts the batch, and appends
    // every access event. No subset is returned or audited if any item fails.
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if names.is_empty() {
        authorize(
            &txn,
            claims,
            ScopedAction::ReadValue,
            &AuthTarget {
                tenant_id: &claims.tenant_id,
                project_id: project,
                environment_id: Some(environment),
                repository_binding_id: claims.repository_binding_id.as_deref(),
                service_id: claims.service_id.as_deref(),
            },
            attrs,
        )
        .map_err(|_| SecretError::Denied)?;
    }
    let mut views = Vec::new();
    for name in unique {
        let id: String = txn
            .query_row(
                "SELECT secret_id FROM secrets WHERE project_id = ?1
            AND environment_id = ?2 AND name = ?3 AND deleted_at_utc IS NULL",
                params![project, environment, name],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(SecretError::NotFound)?;
        let view = resolve_secret(&txn, &id)?;
        authorize(
            &txn,
            claims,
            ScopedAction::ReadValue,
            &target_from_view(&view),
            attrs,
        )
        .map_err(|_| SecretError::Denied)?;
        views.push(view);
    }
    let revision = scope_revision(project, environment, &views);
    if expected_revision.is_some_and(|expected| !expected.eq_ignore_ascii_case(&revision)) {
        return Err(SecretError::RevisionMismatch);
    }
    let mut values = Vec::new();
    let mut total_bytes = 0usize;
    for view in &views {
        let value = SecretValue::from_bytes(open_current_version(&txn, wrap, view)?);
        total_bytes = total_bytes.saturating_add(value.expose().len());
        if total_bytes > MAX_BATCH_VALUE_BYTES {
            return Err(SecretError::MaterializationTooLarge);
        }
        values.push(MaterializedValue {
            name: view.name.clone(),
            secret_id: view.secret_id.clone(),
            version: view.current_version,
            value,
        });
    }
    let now = now_utc();
    for view in &views {
        txn.execute(
            "UPDATE secrets SET last_accessed_at_utc = ?1 WHERE secret_id = ?2",
            params![now, view.secret_id],
        )?;
        audit_secret_event(
            &txn,
            &SecretAuditEvent {
                event_type: "secret.read",
                tenant_id: &view.tenant_id,
                project_id: Some(project),
                environment_id: Some(environment),
                secret_id: Some(&view.secret_id),
                secret_version: Some(view.current_version),
                principal_id: &claims.principal_id,
                request_id,
                source: "materialize",
                result: "success",
                reason: "atomic scope materialization",
            },
            now,
        )?;
    }
    txn.commit()?;
    Ok((revision, values))
}

pub(crate) async fn post_materialize(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project, environment)): Path<(String, String)>,
    Json(body): Json<MaterializeBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project, Some(&environment)) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let (wrap, _) = match wrapping_for(&state, &project) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return crate::http::service_error(error),
    };
    // Charge by values, not requests: batching must not expand exfiltration quotas.
    if body.names.len() > MAX_BATCH_NAMES {
        return crate::http::error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SECRET_REQUEST",
            "names must contain at most 100 secret names",
        );
    }
    for _ in 0..body.names.len().max(1) {
        if let Err(failure) = crate::abuse::check_quota(
            &db,
            &crate::abuse::READ_VALUE_BUCKET,
            &auth.claims.tenant_id,
            &auth.claims.principal_id,
            now_utc(),
        ) {
            return crate::abuse::quota_failure_response(failure);
        }
    }
    match materialize(
        &mut db,
        &wrap,
        &auth.claims,
        &auth.attrs,
        &project,
        &environment,
        &body.names,
        body.expected_revision.as_deref(),
        &random_hex(8),
    ) {
        Ok((revision, values)) => {
            let values: Vec<_> = values
                .into_iter()
                .map(|item| {
                    serde_json::json!({
                        "name": item.name, "secret_id": item.secret_id, "version": item.version,
                        "value": String::from_utf8_lossy(item.value.expose()),
                    })
                })
                .collect();
            let mut response =
                Json(serde_json::json!({"revision": revision, "values": values})).into_response();
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                "no-store".parse().unwrap(),
            );
            response
        }
        Err(error) => secret_error_response(error),
    }
}

#[derive(Deserialize)]
pub(crate) struct RewrapBody {
    reason: String,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct RewrapOutcome {
    active_key_id: String,
    rewrapped: usize,
    remaining: usize,
}

#[allow(clippy::too_many_arguments)]
fn rewrap_project(
    db: &mut Connection,
    wrap: &dyn KeyWrappingService,
    active_id: &str,
    claims: &ScopeClaims,
    attrs: &RequestAttributes,
    project: &str,
    reason: &str,
    limit: usize,
    request_id: &str,
) -> Result<RewrapOutcome, SecretError> {
    if reason.trim().is_empty() || reason.len() > 1024 || !(1..=1000).contains(&limit) {
        return Err(SecretError::Invalid(
            "reason is required and limit must be 1-1000".into(),
        ));
    }
    let txn = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let tenant: String = txn
        .query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            [project],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(SecretError::NotFound)?;
    let target = AuthTarget {
        tenant_id: &tenant,
        project_id: project,
        environment_id: None,
        repository_binding_id: None,
        service_id: None,
    };
    authorize(&txn, claims, ScopedAction::ManagePolicies, &target, attrs)
        .map_err(|_| SecretError::Denied)?;
    if !attrs.human_session || !attrs.recent_strong_auth {
        return Err(SecretError::Denied);
    }
    let versions = {
        let mut rows = txn.prepare(
            "SELECT v.version_id, v.encryption_key_id, v.wrapped_dek
            FROM secret_versions v JOIN secrets s ON s.secret_id = v.secret_id
            WHERE s.project_id = ?1 AND v.encryption_key_id != ?2 ORDER BY v.version_id LIMIT ?3",
        )?;
        let values = rows
            .query_map(params![project, active_id, limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        values
    };
    ensure_kek_row(&txn, active_id, &tenant, project, now_utc())?;
    for (id, old_key_id, blob) in &versions {
        if blob.len() < NONCE_SIZE + TAG_SIZE {
            return Err(SecretError::Invalid("malformed wrapped DEK".into()));
        }
        let mut nonce = [0; NONCE_SIZE];
        nonce.copy_from_slice(&blob[..NONCE_SIZE]);
        let dek = wrap.unwrap_dek(&WrappedDek {
            kek_id: old_key_id.clone(),
            nonce,
            blob: blob[NONCE_SIZE..].to_vec(),
        })?;
        let new = wrap.wrap_dek(&dek)?;
        if new.kek_id != active_id || wrap.unwrap_dek(&new)?.as_bytes() != dek.as_bytes() {
            return Err(SecretError::Invalid(
                "rewrapped key failed verification".into(),
            ));
        }
        let mut sealed = new.nonce.to_vec();
        sealed.extend_from_slice(&new.blob);
        txn.execute("UPDATE secret_versions SET encryption_key_id = ?1, wrapped_dek = ?2 WHERE version_id = ?3",
            params![active_id, sealed, id])?;
    }
    let remaining: usize = txn.query_row(
        "SELECT COUNT(*) FROM secret_versions v JOIN secrets s ON s.secret_id = v.secret_id
        WHERE s.project_id = ?1 AND v.encryption_key_id != ?2",
        params![project, active_id],
        |row| row.get(0),
    )?;
    let audit_reason = serde_json::json!({"reason":reason, "key_id":active_id, "rewrapped":versions.len(), "remaining":remaining}).to_string();
    audit_secret_event(
        &txn,
        &SecretAuditEvent {
            event_type: "encryption_key.rewrapped",
            tenant_id: &tenant,
            project_id: Some(project),
            environment_id: None,
            secret_id: None,
            secret_version: None,
            principal_id: &claims.principal_id,
            request_id,
            source: "api",
            result: "success",
            reason: &audit_reason,
        },
        now_utc(),
    )?;
    txn.commit()?;
    Ok(RewrapOutcome {
        active_key_id: active_id.to_string(),
        rewrapped: versions.len(),
        remaining,
    })
}

pub(crate) async fn post_rewrap_keys(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(body): Json<RewrapBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let (wrap, id) = match wrapping_for(&state, &project) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return crate::http::service_error(error),
    };
    match rewrap_project(
        &mut db,
        &wrap,
        &id,
        &auth.claims,
        &auth.attrs,
        &project,
        &body.reason,
        body.limit.unwrap_or(100),
        &random_hex(8),
    ) {
        Ok(outcome) => Json(outcome).into_response(),
        Err(error) => secret_error_response(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_lifecycle::VersionedKekService;
    use crate::policy::{grant_project_role, ProjectRole};
    use crate::rotation::{rotate_secret, ManualReplacementVerifier, RotateSecret};
    use crate::secrets::{create_secret, get_secret_value, move_secret, CreateSecret, MoveSecret};
    use crate::test_support::{cleanup, test_app};
    use ciphervault_format::{EnvironmentId, ProjectId, TenantId};

    struct Fixture {
        project: String,
        environment: String,
        claims: ScopeClaims,
        wrap: VersionedKekService,
    }
    fn seed(db: &mut Connection) -> Fixture {
        let tenant = TenantId::generate().to_hex();
        let project = ProjectId::generate().to_hex();
        let environment = EnvironmentId::generate().to_hex();
        db.execute(
            "INSERT INTO organizations(tenant_id, name, created_at_utc) VALUES(?1, 'Test', 1)",
            [&tenant],
        )
        .unwrap();
        db.execute("INSERT INTO workspaces(workspace_id, tenant_id, name, created_at_utc) VALUES('w1', ?1, 'Test', 1)", [&tenant]).unwrap();
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
            VALUES(?1, ?2, 'w1', 'test', 'Test', 1)",
            params![project, tenant],
        )
        .unwrap();
        db.execute("INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
            VALUES(?1, ?2, ?3, 'development', 0, 1)", params![environment, tenant, project]).unwrap();
        grant_project_role(db, &project, "account:alice", ProjectRole::Admin, "root", 1).unwrap();
        let claims = ScopeClaims::new(&tenant, &project, "account:alice", 1, u64::MAX)
            .with_environment(&environment);
        let wrap = VersionedKekService::from_config(&project, &"11".repeat(32)).unwrap();
        wrap.register(db, &project).unwrap();
        for (name, value) in [("FIRST", "one"), ("SECOND", "two")] {
            create_secret(
                db,
                &wrap,
                wrap.active_id(),
                &claims,
                &RequestAttributes::default(),
                &CreateSecret {
                    project_id: &project,
                    environment_id: &environment,
                    name,
                    secret_type: "key_value",
                    description: "",
                    tags: &[],
                    repository_binding_id: None,
                    service_id: None,
                    value: &SecretValue::from(value),
                    request_id: "create",
                },
            )
            .unwrap();
        }
        Fixture {
            project,
            environment,
            claims,
            wrap,
        }
    }
    fn read_count(db: &Connection) -> i64 {
        db.query_row(
            "SELECT COUNT(*) FROM secret_access_events WHERE event_type = 'secret.read'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }
    fn human_attrs() -> RequestAttributes {
        RequestAttributes {
            human_session: true,
            recent_strong_auth: true,
            elevated: true,
            ..RequestAttributes::default()
        }
    }
    fn rotated_wrap(project: &str, retain_legacy: bool) -> VersionedKekService {
        let mut config = serde_json::json!({"active_version":"v2", "keys":{"v2":"22".repeat(32)}});
        if retain_legacy {
            config["keys"]["legacy"] = "11".repeat(32).into();
        }
        VersionedKekService::from_config(project, &config.to_string()).unwrap()
    }
    #[test]
    fn batch_is_consistent_revision_pinned_and_all_or_none() {
        let (root, state, _) = test_app("materialize-atomic");
        let mut db = state.connection().unwrap();
        let f = seed(&mut db);
        let names = vec!["SECOND".into(), "FIRST".into()];
        let (revision, values) = materialize(
            &mut db,
            &f.wrap,
            &f.claims,
            &RequestAttributes::default(),
            &f.project,
            &f.environment,
            &names,
            None,
            "batch1",
        )
        .unwrap();
        assert_eq!(
            values.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            ["FIRST", "SECOND"]
        );
        assert_eq!(values[0].value.expose(), b"one");
        assert_eq!(read_count(&db), 2);
        let (same, _) = materialize(
            &mut db,
            &f.wrap,
            &f.claims,
            &RequestAttributes::default(),
            &f.project,
            &f.environment,
            &names,
            Some(&revision),
            "batch2",
        )
        .unwrap();
        assert_eq!(revision, same);
        assert!(matches!(
            materialize(
                &mut db,
                &f.wrap,
                &f.claims,
                &RequestAttributes::default(),
                &f.project,
                &f.environment,
                &["FIRST".into(), "MISSING".into()],
                None,
                "missing"
            )
            .unwrap_err(),
            SecretError::NotFound
        ));
        assert_eq!(read_count(&db), 4);
        rotate_secret(
            &mut db,
            &f.wrap,
            f.wrap.active_id(),
            &ManualReplacementVerifier,
            &f.claims,
            &RequestAttributes::default(),
            &RotateSecret {
                secret_id: &values[0].secret_id,
                new_value: &SecretValue::from("new"),
                idempotency_key: "update",
                reason: "test",
                request_id: "rotate",
            },
        )
        .unwrap();
        assert!(matches!(
            materialize(
                &mut db,
                &f.wrap,
                &f.claims,
                &RequestAttributes::default(),
                &f.project,
                &f.environment,
                &names,
                Some(&revision),
                "stale"
            )
            .unwrap_err(),
            SecretError::RevisionMismatch
        ));
        assert_eq!(read_count(&db), 4);
        // A bad wrapped value never returns/audits the successfully opened prefix.
        db.execute(
            "UPDATE secret_versions SET ciphertext = x'00' WHERE secret_id = ?1",
            [&values[1].secret_id],
        )
        .unwrap();
        assert!(materialize(
            &mut db,
            &f.wrap,
            &f.claims,
            &RequestAttributes::default(),
            &f.project,
            &f.environment,
            &names,
            None,
            "corrupt"
        )
        .is_err());
        assert_eq!(read_count(&db), 4);
        cleanup(root);
    }
    #[test]
    fn batch_denies_scope_widening_and_excessive_input() {
        let (root, state, _) = test_app("materialize-limits");
        let mut db = state.connection().unwrap();
        let f = seed(&mut db);
        for names in [
            vec!["FIRST".into(); 101],
            vec!["FIRST".into(), "FIRST".into()],
        ] {
            assert!(matches!(
                materialize(
                    &mut db,
                    &f.wrap,
                    &f.claims,
                    &RequestAttributes::default(),
                    &f.project,
                    &f.environment,
                    &names,
                    None,
                    "invalid"
                )
                .unwrap_err(),
                SecretError::Invalid(_)
            ));
        }
        let narrow = f.claims.clone().with_service("restricted");
        assert!(matches!(
            materialize(
                &mut db,
                &f.wrap,
                &narrow,
                &RequestAttributes::default(),
                &f.project,
                &f.environment,
                &["FIRST".into()],
                None,
                "denied"
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        let names = vec!["FIRST".into(), "SECOND".into()];
        let (_, values) = materialize(
            &mut db,
            &f.wrap,
            &f.claims,
            &RequestAttributes::default(),
            &f.project,
            &f.environment,
            &names,
            None,
            "get-ids",
        )
        .unwrap();
        rotate_secret(
            &mut db,
            &f.wrap,
            f.wrap.active_id(),
            &ManualReplacementVerifier,
            &f.claims,
            &RequestAttributes::default(),
            &RotateSecret {
                secret_id: &values[0].secret_id,
                new_value: &SecretValue::from("a".repeat(MAX_BATCH_VALUE_BYTES)),
                idempotency_key: "large",
                reason: "test",
                request_id: "rotate",
            },
        )
        .unwrap();
        let before = read_count(&db);
        assert!(matches!(
            materialize(
                &mut db,
                &f.wrap,
                &f.claims,
                &RequestAttributes::default(),
                &f.project,
                &f.environment,
                &names,
                None,
                "too-large"
            )
            .unwrap_err(),
            SecretError::MaterializationTooLarge
        ));
        assert_eq!(read_count(&db), before);
        cleanup(root);
    }
    #[test]
    fn empty_materialization_checks_scope_and_revision_without_reading_values() {
        let (root, state, _) = test_app("materialize-empty");
        let mut db = state.connection().unwrap();
        let fixture = seed(&mut db);
        let revision = scope_revision(&fixture.project, &fixture.environment, &[]);
        let (_, values) = materialize(
            &mut db,
            &fixture.wrap,
            &fixture.claims,
            &RequestAttributes::default(),
            &fixture.project,
            &fixture.environment,
            &[],
            Some(&revision.to_uppercase()),
            "empty",
        )
        .unwrap();
        assert!(values.is_empty());
        assert_eq!(read_count(&db), 0);
        assert!(matches!(
            materialize(
                &mut db,
                &fixture.wrap,
                &fixture.claims,
                &RequestAttributes::default(),
                &fixture.project,
                &fixture.environment,
                &[],
                Some(&"00".repeat(32)),
                "stale-empty"
            ),
            Err(SecretError::RevisionMismatch)
        ));
        assert!(matches!(
            materialize(
                &mut db,
                &fixture.wrap,
                &fixture.claims,
                &RequestAttributes::default(),
                &fixture.project,
                "different-environment",
                &[],
                None,
                "foreign-empty"
            ),
            Err(SecretError::Denied)
        ));
        cleanup(root);
    }
    #[test]
    fn key_rewrap_preserves_versions_ciphertext_and_values_and_is_resumable() {
        let (root, state, _) = test_app("rewrap-history");
        let mut db = state.connection().unwrap();
        let f = seed(&mut db);
        let (_, values) = materialize(
            &mut db,
            &f.wrap,
            &f.claims,
            &RequestAttributes::default(),
            &f.project,
            &f.environment,
            &["FIRST".into()],
            None,
            "get-id",
        )
        .unwrap();
        rotate_secret(
            &mut db,
            &f.wrap,
            f.wrap.active_id(),
            &ManualReplacementVerifier,
            &f.claims,
            &RequestAttributes::default(),
            &RotateSecret {
                secret_id: &values[0].secret_id,
                new_value: &SecretValue::from("new"),
                idempotency_key: "rotate",
                reason: "test",
                request_id: "rotate",
            },
        )
        .unwrap();
        let before: Vec<(String, i64, Vec<u8>)> = db
            .prepare(
                "SELECT version_id, version, ciphertext FROM secret_versions ORDER BY version_id",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let wrap = rotated_wrap(&f.project, true);
        wrap.register(&mut db, &f.project).unwrap();
        let management = ScopeClaims::new(
            &f.claims.tenant_id,
            &f.project,
            &f.claims.principal_id,
            1,
            u64::MAX,
        );
        let first = rewrap_project(
            &mut db,
            &wrap,
            wrap.active_id(),
            &management,
            &human_attrs(),
            &f.project,
            "rotation",
            1,
            "rewrap1",
        )
        .unwrap();
        assert_eq!(first.rewrapped, 1);
        assert_eq!(first.remaining, 2);
        let rest = rewrap_project(
            &mut db,
            &wrap,
            wrap.active_id(),
            &management,
            &human_attrs(),
            &f.project,
            "rotation",
            100,
            "rewrap2",
        )
        .unwrap();
        assert_eq!(rest.rewrapped, 2);
        assert_eq!(rest.remaining, 0);
        let replay = rewrap_project(
            &mut db,
            &wrap,
            wrap.active_id(),
            &management,
            &human_attrs(),
            &f.project,
            "rotation",
            100,
            "rewrap3",
        )
        .unwrap();
        assert_eq!(replay.rewrapped, 0);
        let after: Vec<(String, i64, Vec<u8>)> = db
            .prepare(
                "SELECT version_id, version, ciphertext FROM secret_versions ORDER BY version_id",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(before, after);
        let read = get_secret_value(
            &mut db,
            &wrap,
            &f.claims,
            &RequestAttributes::default(),
            &values[0].secret_id,
            "read",
        )
        .unwrap();
        assert_eq!(read.value.expose(), b"new");
        assert_eq!(read.version, 2);
        cleanup(root);
    }
    #[test]
    fn key_rewrap_missing_history_and_narrow_or_weak_auth_fail_closed() {
        let (root, state, _) = test_app("rewrap-fail");
        let mut db = state.connection().unwrap();
        let f = seed(&mut db);
        let wrap = rotated_wrap(&f.project, false);
        let management = ScopeClaims::new(
            &f.claims.tenant_id,
            &f.project,
            &f.claims.principal_id,
            1,
            u64::MAX,
        );
        assert!(rewrap_project(
            &mut db,
            &wrap,
            wrap.active_id(),
            &management,
            &human_attrs(),
            &f.project,
            "rotation",
            100,
            "missing"
        )
        .is_err());
        let old_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM secret_versions WHERE encryption_key_id = ?1",
                [f.wrap.active_id()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old_count, 2);
        for attrs in [
            RequestAttributes::default(),
            RequestAttributes {
                human_session: true,
                ..RequestAttributes::default()
            },
        ] {
            assert!(matches!(
                rewrap_project(
                    &mut db,
                    &wrap,
                    wrap.active_id(),
                    &management,
                    &attrs,
                    &f.project,
                    "rotation",
                    100,
                    "weak"
                )
                .unwrap_err(),
                SecretError::Denied
            ));
        }
        assert!(matches!(
            rewrap_project(
                &mut db,
                &wrap,
                wrap.active_id(),
                &f.claims,
                &RequestAttributes::default(),
                &f.project,
                "rotation",
                100,
                "narrow"
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        // Reusing a version label with new material is rejected before any writes.
        let wrong = VersionedKekService::from_config(&f.project, &"44".repeat(32)).unwrap();
        assert!(wrong.register(&mut db, &f.project).is_err());
        let (_, values) = materialize(
            &mut db,
            &f.wrap,
            &f.claims,
            &RequestAttributes::default(),
            &f.project,
            &f.environment,
            &["FIRST".into()],
            None,
            "still-readable",
        )
        .unwrap();
        assert_eq!(values[0].value.expose(), b"one");
        cleanup(root);
    }
    #[test]
    fn workload_cannot_move_from_development_to_production() {
        let (root, state, _) = test_app("move-production-boundary");
        let mut db = state.connection().unwrap();
        let f = seed(&mut db);
        let production = EnvironmentId::generate().to_hex();
        db.execute("INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
            VALUES(?1, ?2, ?3, 'production', 2, 1)", params![production, f.claims.tenant_id, f.project]).unwrap();
        let (_, values) = materialize(
            &mut db,
            &f.wrap,
            &f.claims,
            &RequestAttributes::default(),
            &f.project,
            &f.environment,
            &["FIRST".into()],
            None,
            "id",
        )
        .unwrap();
        let input = MoveSecret {
            new_name: None,
            new_environment_id: Some(&production),
            reason: "promote",
            request_id: "move",
        };
        assert!(matches!(
            move_secret(
                &mut db,
                &f.wrap,
                f.wrap.active_id(),
                &f.claims,
                &RequestAttributes::default(),
                &values[0].secret_id,
                &input
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        let moved = move_secret(
            &mut db,
            &f.wrap,
            f.wrap.active_id(),
            &f.claims,
            &human_attrs(),
            &values[0].secret_id,
            &input,
        )
        .unwrap();
        assert_eq!(moved.environment_id, production);
        cleanup(root);
    }
    #[test]
    fn scoped_inventory_filters_bindings_and_cannot_drop_service_confinement() {
        use crate::secrets::{list_secrets, rebind_secret, RebindSecret, SecretListFilter};
        let (root, state, _) = test_app("scope-bound-list");
        let mut db = state.connection().unwrap();
        let f = seed(&mut db);
        db.execute(
            "INSERT INTO services(service_id, tenant_id, project_id, slug, created_at_utc)
            VALUES('own-service', ?1, ?2, 'own', 1)",
            params![f.claims.tenant_id, f.project],
        )
        .unwrap();
        let bound = f.claims.clone().with_service("own-service");
        let view = create_secret(
            &mut db,
            &f.wrap,
            f.wrap.active_id(),
            &bound,
            &RequestAttributes::default(),
            &CreateSecret {
                project_id: &f.project,
                environment_id: &f.environment,
                name: "BOUND",
                secret_type: "key_value",
                description: "",
                tags: &[],
                repository_binding_id: None,
                service_id: Some("own-service"),
                value: &SecretValue::from("bound"),
                request_id: "create-bound",
            },
        )
        .unwrap();
        let filter = SecretListFilter {
            project_id: &f.project,
            environment_id: &f.environment,
            tag: None,
            status: None,
            q: None,
            limit: 100,
        };
        let visible = list_secrets(&db, &bound, &RequestAttributes::default(), &filter).unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "BOUND");
        let unbound = list_secrets(&db, &f.claims, &RequestAttributes::default(), &filter).unwrap();
        assert_eq!(unbound.len(), 2);
        assert!(unbound.iter().all(|view| view.service_id.is_none()));
        let input = RebindSecret {
            repository_binding_id: None,
            service_id: Some(None),
            reason: "unbind",
            request_id: "rebind",
        };
        assert!(matches!(
            rebind_secret(
                &mut db,
                &bound,
                &RequestAttributes::default(),
                &view.secret_id,
                &input
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        assert_eq!(
            resolve_secret(&db, &view.secret_id)
                .unwrap()
                .service_id
                .as_deref(),
            Some("own-service")
        );
        rebind_secret(&mut db, &bound, &human_attrs(), &view.secret_id, &input).unwrap();
        assert!(resolve_secret(&db, &view.secret_id)
            .unwrap()
            .service_id
            .is_none());
        cleanup(root);
    }

    #[test]
    fn service_and_environment_associations_cannot_cross_projects() {
        let (root, state, _) = test_app("scope-foreign-association");
        let mut db = state.connection().unwrap();
        let f = seed(&mut db);
        let foreign = ProjectId::generate().to_hex();
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
            VALUES(?1, ?2, 'w1', 'foreign', 'Foreign', 1)",
            params![foreign, f.claims.tenant_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO services(service_id, tenant_id, project_id, slug, created_at_utc)
            VALUES('foreign-service', ?1, ?2, 'foreign', 1)",
            params![f.claims.tenant_id, foreign],
        )
        .unwrap();
        let forged = f.claims.clone().with_service("foreign-service");
        assert!(matches!(
            create_secret(
                &mut db,
                &f.wrap,
                f.wrap.active_id(),
                &forged,
                &RequestAttributes::default(),
                &CreateSecret {
                    project_id: &f.project,
                    environment_id: &f.environment,
                    name: "BAD",
                    secret_type: "key_value",
                    description: "",
                    tags: &[],
                    repository_binding_id: None,
                    service_id: Some("foreign-service"),
                    value: &SecretValue::from("bad"),
                    request_id: "foreign-service",
                }
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        let env = EnvironmentId::generate().to_hex();
        db.execute("INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
            VALUES(?1, ?2, ?3, 'dev', 0, 1)", params![env, f.claims.tenant_id, foreign]).unwrap();
        assert!(matches!(
            create_secret(
                &mut db,
                &f.wrap,
                f.wrap.active_id(),
                &f.claims,
                &human_attrs(),
                &CreateSecret {
                    project_id: &f.project,
                    environment_id: &env,
                    name: "BAD",
                    secret_type: "key_value",
                    description: "",
                    tags: &[],
                    repository_binding_id: None,
                    service_id: None,
                    value: &SecretValue::from("bad"),
                    request_id: "foreign-environment",
                }
            )
            .unwrap_err(),
            SecretError::Denied
        ));
        cleanup(root);
    }
}
