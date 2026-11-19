//! Transparency-log HTTP API (ADR-014 Phase 2).
//!
//! * `POST /v1/log/add` — session-authenticated submission. The caller
//!   sends a 32-byte anchor commitment (hex); the monitor tag is the
//!   reserved all-zero value until Phase 5 mint tags exist, so a
//!   non-zero tag is rejected rather than silently stored with no
//!   semantics. Rate-limited per device session key.
//! * `GET /v1/log/info` — origin, checkpoint verifier key, tree head.
//! * `GET /v1/log/checkpoint` — the current signed checkpoint (C2SP
//!   signed note, `text/plain`). Signed from live state on every call.
//! * `GET /v1/log/checkpoint/witnessed` — the latest checkpoint with a
//!   quorum of witness cosignatures (Phase 3), or 404 before the first.
//! * `GET /v1/log/tile/{*path}` — tlog-tiles hash tiles and entry
//!   bundles (`tile/<level>/<index>[.p/<width>]`,
//!   `tile/entries/<index>[.p/<width>]`), served as raw bytes. Tiles are
//!   public: every byte in them is checkable against the checkpoint.
//! * `GET /v1/log/inclusion/{index}` — convenience inclusion proof.
//! * `GET /v1/log/consistency` — convenience consistency proof
//!   (`?from=<size>&to=<size>`).
//! * `GET /v1/log/lookup/{commitment}` — indices for a commitment, so a
//!   client whose submission response was lost can recover its index
//!   instead of submitting a duplicate.
//!
//! Reads are public by design (transparency-log data is verifiable, not
//! secret); submissions are the only write and need a vault session
//! with write permission, exactly like object puts.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use ciphervault_translog::entry::LogEntry;
use ciphervault_translog::tiles::Tile;

use crate::handlers::require_session;
use crate::log_store::LogError;
use crate::state::OperatorState;

fn log_error_response(error: LogError) -> (StatusCode, String) {
    match error {
        LogError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, error.to_string()),
        LogError::Proof(_) => (StatusCode::BAD_REQUEST, error.to_string()),
        LogError::OriginMismatch { .. } | LogError::Corrupt(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
        }
        LogError::Io(_) | LogError::Checkpoint(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
        }
    }
}

fn parse_hex32(value: &str, field: &str) -> Result<[u8; 32], (StatusCode, String)> {
    let bytes = hex::decode(value).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("{field} must be 32-byte hex"),
        )
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("{field} must be 32-byte hex"),
        )
    })
}

/// Submission body for `POST /v1/log/add`.
#[derive(Debug, Deserialize)]
pub struct LogAddRequest {
    /// Anchor commitment, 32-byte hex.
    pub commitment: String,
    /// Monitor tag, 32-byte hex. Must be all zeros until Phase 5.
    #[serde(default)]
    pub monitor_tag: Option<String>,
}

/// Submission receipt for `POST /v1/log/add`.
#[derive(Debug, Serialize)]
pub struct LogAddResponse {
    pub origin: String,
    pub index: u64,
    pub leaf_hash: String,
    pub tree_size: u64,
    pub root: String,
}

/// Submits one commitment to the log. The receipt's index is durable
/// before this response is sent (see `LogStore::append`).
pub async fn post_log_add(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Json(req): Json<LogAddRequest>,
) -> Result<Json<LogAddResponse>, (StatusCode, String)> {
    let token = require_session(&state, &headers, true)?;
    // Rate-limit identity: the authenticated device key, falling back to
    // the session vault. Never a caller-supplied header alone.
    let device_key = state
        .get_session_public_key(token)
        .map(hex::encode)
        .or_else(|| state.get_session_vault_id(token))
        .unwrap_or_else(|| token.to_string());
    let commitment = parse_hex32(&req.commitment, "commitment")?;
    if let Some(tag) = &req.monitor_tag {
        let tag = parse_hex32(tag, "monitor_tag")?;
        if tag != [0u8; 32] {
            return Err((
                StatusCode::BAD_REQUEST,
                "monitor_tag is reserved and must be all zeros until Phase 5".into(),
            ));
        }
    }
    let entry = LogEntry::untagged(commitment);
    let state_for_io = state.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        state_for_io
            .transparency_log()
            .and_then(|store| store.append(&device_key, entry))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(log_error_response)?;
    let info = state.transparency_log().map_err(log_error_response)?.info();
    Ok(Json(LogAddResponse {
        origin: info.origin,
        index: receipt.index,
        leaf_hash: hex::encode(receipt.leaf_hash),
        tree_size: receipt.tree_size,
        root: hex::encode(receipt.root),
    }))
}

/// Log discovery: origin, pinning key and current head.
#[derive(Debug, Serialize)]
pub struct LogInfoResponse {
    pub origin: String,
    pub verifier_key: String,
    pub tree_size: u64,
    pub root: String,
    /// Size of the latest checkpoint with a witness quorum, if any.
    pub witnessed_tree_size: Option<u64>,
}

pub async fn get_log_info(
    State(state): State<Arc<OperatorState>>,
) -> Result<Json<LogInfoResponse>, (StatusCode, String)> {
    let info = state.transparency_log().map_err(log_error_response)?.info();
    Ok(Json(LogInfoResponse {
        origin: info.origin,
        verifier_key: info.verifier_key,
        tree_size: info.tree_size,
        root: hex::encode(info.root),
        witnessed_tree_size: info.witnessed_tree_size,
    }))
}

/// The latest checkpoint carrying a quorum of witness cosignatures
/// (ADR-014 Phase 3). It lags the live checkpoint by one witnessing
/// round; clients ask for inclusion proofs at its size.
pub async fn get_log_witnessed_checkpoint(
    State(state): State<Arc<OperatorState>>,
) -> Result<Response, (StatusCode, String)> {
    let witnessed = state
        .transparency_log()
        .map_err(log_error_response)?
        .witnessed_checkpoint()
        .ok_or((
            StatusCode::NOT_FOUND,
            "no checkpoint has a witness quorum yet".to_string(),
        ))?;
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        witnessed.note,
    )
        .into_response())
}

/// The current signed checkpoint, as a C2SP signed note.
pub async fn get_log_checkpoint(
    State(state): State<Arc<OperatorState>>,
) -> Result<Response, (StatusCode, String)> {
    let text = state
        .transparency_log()
        .map_err(log_error_response)?
        .signed_checkpoint()
        .map_err(log_error_response)?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response())
}

/// One tile or entry bundle as raw bytes. `path` is the tile path after
/// `/v1/log/tile/`, e.g. `0/000.p/5` or `entries/000`.
pub async fn get_log_tile(
    State(state): State<Arc<OperatorState>>,
    Path(path): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let tile = Tile::parse_path(&format!("tile/{path}"))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid tile path: {e}")))?;
    let bytes = state
        .transparency_log()
        .map_err(log_error_response)?
        .tile_bytes(&tile)
        .ok_or((StatusCode::NOT_FOUND, "tile not found".to_string()))?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

/// Size selection shared by the proof endpoints.
#[derive(Debug, Deserialize)]
pub struct ProofQuery {
    pub size: Option<u64>,
    pub from: Option<u64>,
    pub to: Option<u64>,
}

/// Convenience inclusion proof for one leaf.
#[derive(Debug, Serialize)]
pub struct InclusionProofResponse {
    pub index: u64,
    pub tree_size: u64,
    pub leaf_hash: String,
    pub proof: Vec<String>,
}

pub async fn get_log_inclusion(
    State(state): State<Arc<OperatorState>>,
    Path(index): Path<u64>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<InclusionProofResponse>, (StatusCode, String)> {
    let (tree_size, leaf_hash, proof) = state
        .transparency_log()
        .map_err(log_error_response)?
        .inclusion_proof(index, query.size)
        .map_err(log_error_response)?;
    Ok(Json(InclusionProofResponse {
        index,
        tree_size,
        leaf_hash: hex::encode(leaf_hash),
        proof: proof.iter().map(hex::encode).collect(),
    }))
}

/// Convenience consistency proof between two tree sizes.
#[derive(Debug, Serialize)]
pub struct ConsistencyProofResponse {
    pub from_size: u64,
    pub to_size: u64,
    pub proof: Vec<String>,
}

pub async fn get_log_consistency(
    State(state): State<Arc<OperatorState>>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<ConsistencyProofResponse>, (StatusCode, String)> {
    let from = query.from.unwrap_or(0);
    let store = state.transparency_log().map_err(log_error_response)?;
    // Fix `to` once and prove exactly that size: re-reading the head for
    // the proof would let a concurrent append make the proof disagree
    // with the `to_size` reported beside it.
    let to = query.to.unwrap_or_else(|| store.info().tree_size);
    let proof = store
        .consistency_proof(from, Some(to))
        .map_err(log_error_response)?;
    Ok(Json(ConsistencyProofResponse {
        from_size: from,
        to_size: to,
        proof: proof.iter().map(hex::encode).collect(),
    }))
}

/// Indices at which a commitment was submitted.
#[derive(Debug, Serialize)]
pub struct LookupResponse {
    pub commitment: String,
    pub indices: Vec<u64>,
}

pub async fn get_log_lookup(
    State(state): State<Arc<OperatorState>>,
    Path(commitment): Path<String>,
) -> Result<Json<LookupResponse>, (StatusCode, String)> {
    let commitment_bytes = parse_hex32(&commitment, "commitment")?;
    let indices = state
        .transparency_log()
        .map_err(log_error_response)?
        .lookup_commitment(&commitment_bytes);
    Ok(Json(LookupResponse {
        commitment,
        indices,
    }))
}
