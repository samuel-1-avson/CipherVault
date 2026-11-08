//! Audit export route.

use super::auth::*;
use super::common::*;

#[derive(Deserialize)]
pub(crate) struct ExportQuery {
    after: Option<String>,
    limit: Option<String>,
}

/// Exports the tenant's audit chain as JSONL for off-host append-only cold
/// storage (T-901). Admins and auditors only; each page is verified first
/// and a broken page fails closed (500, no partial ship). The export
/// itself is not audited: it carries digests and metadata, never values
/// (reads are only audited for value access).
///
/// Paging: `?limit=` bounds the page (default 10,000, max 50,000) and
/// `?after=<event_id>` resumes after a cursor. `x-audit-events` counts this
/// page, `x-audit-head` is this page's head hash, and `x-audit-next` carries
/// the next cursor — absent when the export is complete. Walk pages from
/// genesis for full-chain assurance; a later page only re-verifies its own
/// linkage, not the prefix before its cursor.
///
/// Dual control (T-902): bulk export additionally requires a second
/// credential — `x-step-up-authorization: Bearer <token>` holding a valid
/// scope token for the same project from a DIFFERENT ViewAudit-authorized
/// principal. Step-up tokens must be unbound (no `cnf`): the step-up is a
/// presence factor, key-binding applies to the primary credential.
pub async fn get_audit_export(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Query(query): Query<ExportQuery>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    // NOTE: `AccountState` guards a single global `Mutex<Connection>`.
    // Every block below acquires and releases it; nothing here may hold
    // the guard across `verify_token_claims` (which acquires its own) —
    // nesting self-deadlocks (non-reentrant mutex, caught by the export
    // lifecycle test hanging).
    let tenant: Option<String> = {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        db.query_row(
            "SELECT tenant_id FROM projects WHERE project_id = ?1",
            rusqlite::params![project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| service_error(err.into()))
        .unwrap_or(None)
    };
    let Some(tenant) = tenant else {
        return scoped_denial_response();
    };
    {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        let target = crate::policy::AuthTarget {
            tenant_id: &tenant,
            project_id: &project_id,
            environment_id: None,
            repository_binding_id: None,
            service_id: None,
        };
        if crate::policy::authorize(
            &db,
            &auth.claims,
            crate::policy::ScopedAction::ViewAudit,
            &target,
            &auth.attrs,
        )
        .is_err()
        {
            return scoped_denial_response();
        }
    }
    // Dual control: a second, distinct, ViewAudit-authorized principal for
    // the same project must co-sign via the step-up header. Single code for
    // every step-up failure (no oracle on the second credential).
    let step_up = headers
        .get("x-step-up-authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .strip_prefix("Bearer ")
        .unwrap_or_default()
        .trim()
        .to_string();
    if step_up.is_empty() {
        return error_response(
            StatusCode::FORBIDDEN,
            "DUAL_CONTROL_REQUIRED",
            "Bulk export requires a second authorized principal (x-step-up-authorization)",
        );
    }
    let second = match verify_token_claims(&state, &headers, &step_up) {
        Ok(claims) => claims,
        Err(_) => {
            return error_response(
                StatusCode::FORBIDDEN,
                "DUAL_CONTROL_REQUIRED",
                "Bulk export requires a second authorized principal (x-step-up-authorization)",
            );
        }
    };
    let validated_paging = {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        let second_role = project_role_of(&db, &project_id, &second.principal_id).unwrap_or(None);
        let second_ok = second.tenant_id == tenant
            && second.project_id == project_id
            && second.principal_id != auth.claims.principal_id
            && second.cnf.is_none()
            && second_role.is_some_and(|role| {
                crate::policy::role_allows(role, crate::policy::ScopedAction::ViewAudit)
            });
        if !second_ok {
            return error_response(
                StatusCode::FORBIDDEN,
                "DUAL_CONTROL_REQUIRED",
                "Bulk export requires a second authorized principal (x-step-up-authorization)",
            );
        }
        // Validate paging before quota: malformed input must not burn quota.
        let limit = match query.limit.as_deref() {
            None => AUDIT_EXPORT_DEFAULT_LIMIT,
            Some(raw) => match raw.trim().parse::<usize>() {
                Ok(n) if (1..=AUDIT_EXPORT_MAX_LIMIT).contains(&n) => n,
                _ => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "INVALID_EXPORT_LIMIT",
                        format!("limit must be an integer 1..={AUDIT_EXPORT_MAX_LIMIT}"),
                    )
                }
            },
        };
        let after = query
            .after
            .as_deref()
            .map(str::trim)
            .filter(|cursor| !cursor.is_empty());
        // Bounded page export + verify per call; a full-chain walk costs one
        // quota unit per page.
        if let Err(failure) = check_quota(
            &db,
            &EXPORT_BUCKET,
            &tenant,
            &auth.claims.principal_id,
            now_utc(),
        ) {
            return quota_failure_response(failure);
        }
        // Stash validated paging for the snapshot block below.
        (limit, after)
    };
    let (limit, after) = validated_paging;
    let page = {
        let mut db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        // Quota writes and token verification finish before this read-only
        // snapshot. Retain both the mutex and transaction through export so
        // same-process and independent writers cannot change the body after
        // its event count and head have been verified.
        let snapshot = match db.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred) {
            Ok(snapshot) => snapshot,
            Err(error) => return service_error(error.into()),
        };
        let page = match verify_and_export_audit_page(&snapshot, &tenant, after, limit) {
            Ok(page) => page,
            Err(AuditExportError::UnknownCursor) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "INVALID_EXPORT_CURSOR",
                    "unknown audit cursor; restart the export from the first page",
                )
            }
            Err(AuditExportError::Db(error)) => return service_error(error.into()),
        };
        if let Err(error) = snapshot.commit() {
            return service_error(error.into());
        }
        page
    };
    if !page.valid {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AUDIT_CHAIN_BROKEN",
            format!(
                "Audit chain verification failed at event {}",
                page.first_bad_event_id.as_deref().unwrap_or("unknown")
            ),
        );
    }
    let mut out_headers = HeaderMap::new();
    out_headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(count) = axum::http::HeaderValue::from_str(&page.event_count.to_string()) {
        out_headers.insert("x-audit-events", count);
    }
    if let Ok(head) = axum::http::HeaderValue::from_str(&hex::encode(&page.head_hash)) {
        out_headers.insert("x-audit-head", head);
    }
    if let Some(cursor) = page.next_cursor.as_deref() {
        if let Ok(next) = axum::http::HeaderValue::from_str(cursor) {
            out_headers.insert("x-audit-next", next);
        }
    }
    (StatusCode::OK, out_headers, page.jsonl).into_response()
}
