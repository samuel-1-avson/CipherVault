//! HTTP routes for ledgered vault migration (Phase 8, T-801).
//!
//! Admin-only, project-scoped, uniform-404 denials (no oracles). Digests ride
//! as hex; values never touch these endpoints (they flow through the normal
//! secret API during apply).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::http::{error_response, service_error};
use crate::migration_ledger::{
    abort_run, disable_legacy, get_run_detail, list_runs, mark_migrated, now_secs, resolve_entry,
    start_run, submit_entries, verify_run, MigrationError, SubmitEntry,
};
use crate::policy::scoped_denial_response;
use crate::secret_routes::authenticate;
use crate::state::AccountState;
use crate::util::random_hex;

fn migration_error_response(err: MigrationError) -> Response {
    match err {
        MigrationError::NotFound | MigrationError::Denied => scoped_denial_response(),
        MigrationError::Invalid(message) => error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_MIGRATION_REQUEST",
            message,
        ),
        MigrationError::Secrets(secret_err) => error_response(
            StatusCode::BAD_GATEWAY,
            "MIGRATION_SECRET_FAILED",
            secret_err.to_string(),
        ),
        MigrationError::Db(db_err) => service_error(db_err.into()),
    }
}

#[derive(Deserialize)]
pub(crate) struct StartMigrationBody {
    source_vault_id: String,
    source_snapshot_hex: String,
}

pub async fn post_migration(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(body): Json<StartMigrationBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match start_run(
        &db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        &body.source_vault_id,
        &body.source_snapshot_hex,
        now_secs(),
    ) {
        Ok(run) => (StatusCode::CREATED, Json(run)).into_response(),
        Err(err) => migration_error_response(err),
    }
}

pub async fn get_migrations(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match list_runs(&db, &auth.claims, &auth.attrs, &project_id) {
        Ok(runs) => Json(serde_json::json!({ "migrations": runs })).into_response(),
        Err(err) => migration_error_response(err),
    }
}

pub async fn get_migration(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, migration_id)): Path<(String, String)>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match get_run_detail(&db, &auth.claims, &auth.attrs, &project_id, &migration_id) {
        Ok((run, entries)) => Json(serde_json::json!({
            "migration": run,
            "entries": entries,
        }))
        .into_response(),
        Err(err) => migration_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct SubmitEntryBody {
    source_path: String,
    source_line: i64,
    name: String,
    secret_type: Option<String>,
    target_environment_id: String,
    target_binding_id: Option<String>,
    target_service_id: Option<String>,
    /// Hex-encoded SHA-256 of the source value bytes.
    source_digest_hex: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
pub(crate) struct SubmitEntriesBody {
    entries: Vec<SubmitEntryBody>,
}

pub async fn post_migration_entries(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, migration_id)): Path<(String, String)>,
    Json(body): Json<SubmitEntriesBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let mut digests: Vec<Vec<u8>> = Vec::with_capacity(body.entries.len());
    for entry in &body.entries {
        match hex::decode(entry.source_digest_hex.trim()) {
            Ok(digest) => digests.push(digest),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "INVALID_MIGRATION_REQUEST",
                    format!(
                        "source_digest_hex for {}:{} is not valid hex",
                        entry.source_path, entry.source_line
                    ),
                );
            }
        }
    }
    let proposals: Vec<SubmitEntry<'_>> = body
        .entries
        .iter()
        .zip(digests.iter())
        .map(|(entry, digest)| SubmitEntry {
            source_path: &entry.source_path,
            source_line: entry.source_line,
            name: &entry.name,
            secret_type: entry.secret_type.as_deref().unwrap_or("key_value"),
            target_environment_id: &entry.target_environment_id,
            target_binding_id: entry.target_binding_id.as_deref(),
            target_service_id: entry.target_service_id.as_deref(),
            source_digest: digest,
            idempotency_key: &entry.idempotency_key,
        })
        .collect();
    match submit_entries(
        &mut db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        &migration_id,
        proposals,
        now_secs(),
    ) {
        Ok(entries) => Json(serde_json::json!({ "entries": entries })).into_response(),
        Err(err) => migration_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct MarkMigratedBody {
    secret_id: String,
    /// Hex-encoded SHA-256 of the applied value bytes.
    target_digest_hex: String,
}

pub async fn post_migration_entry_migrated(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, migration_id, ledger_id)): Path<(String, String, String)>,
    Json(body): Json<MarkMigratedBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let target_digest = match hex::decode(body.target_digest_hex.trim()) {
        Ok(digest) => digest,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_MIGRATION_REQUEST",
                "target_digest_hex is not valid hex",
            );
        }
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match mark_migrated(
        &db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        &migration_id,
        &ledger_id,
        &body.secret_id,
        &target_digest,
        now_secs(),
    ) {
        Ok(entry) => Json(entry).into_response(),
        Err(err) => migration_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct ResolveEntryBody {
    name: Option<String>,
    target_environment_id: Option<String>,
}

pub async fn post_migration_entry_resolve(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, migration_id, ledger_id)): Path<(String, String, String)>,
    Json(body): Json<ResolveEntryBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match resolve_entry(
        &mut db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        &migration_id,
        &ledger_id,
        body.name.as_deref(),
        body.target_environment_id.as_deref(),
        now_secs(),
    ) {
        Ok(entry) => Json(entry).into_response(),
        Err(err) => migration_error_response(err),
    }
}

pub async fn post_migration_verify(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, migration_id)): Path<(String, String)>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match verify_run(
        &mut db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        &migration_id,
        now_secs(),
    ) {
        Ok(outcome) => Json(outcome).into_response(),
        Err(err) => migration_error_response(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct DisableLegacyBody {
    ledger_ids: Option<Vec<String>>,
}

pub async fn post_migration_disable_legacy(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, migration_id)): Path<(String, String)>,
    Json(body): Json<DisableLegacyBody>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match disable_legacy(
        &db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        &migration_id,
        body.ledger_ids.as_deref(),
        now_secs(),
    ) {
        Ok(disabled) => Json(serde_json::json!({ "disabled": disabled })).into_response(),
        Err(err) => migration_error_response(err),
    }
}

pub async fn post_migration_abort(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((project_id, migration_id)): Path<(String, String)>,
) -> Response {
    let auth = match authenticate(&state, &headers, &project_id, None) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    match abort_run(
        &mut db,
        &auth.claims,
        &auth.attrs,
        &project_id,
        &migration_id,
        &random_hex(8),
        now_secs(),
    ) {
        Ok(rolled_back) => Json(serde_json::json!({ "rolled_back": rolled_back })).into_response(),
        Err(err) => migration_error_response(err),
    }
}
