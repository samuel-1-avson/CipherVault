//! Witness HTTP API (ADR-014 Phase 3): `c2sp.org/tlog-witness`, mounted at
//! `/v1/witness` by the operator and by the standalone
//! `ciphervault-witness` binary. The prefix is both the submission prefix
//! and the monitoring prefix.
//!
//! * `POST /v1/witness/add-checkpoint` — the spec's request and status
//!   codes: `200` with the cosignature line, `400`, `403`, `404`, `409`
//!   (body `<size>\n`, `Content-Type: text/x.tlog.size`) or `422`.
//! * `GET /v1/witness/<sha256(origin) hex>/checkpoint` — the latest
//!   checkpoint this witness cosigned for that log, with the log's
//!   signature and the witness's cosignature; `404` if it never cosigned.
//! * `GET /v1/witness/info` — the witness name, its ML-DSA-44 verifier key
//!   and the origins it cosigns.
//!
//! Requests are not authenticated, as the spec says: a witness only acts
//! on checkpoints signed by a log key it trusts.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as UrlPath, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use ciphervault_translog::witness::{encode_size, WitnessError, SIZE_CONTENT_TYPE};

use crate::witness_store::{AddCheckpointError, WitnessConfig, WitnessStore, WITNESS_MAX_BODY};

/// The witness behind the HTTP API: running, not enabled, or failed to
/// open (in which case only the witness endpoints answer 503).
pub struct WitnessService {
    store: Option<WitnessStore>,
    error: Option<String>,
}

impl WitnessService {
    /// A service with no witness: every log origin is unknown.
    pub fn disabled() -> Self {
        Self {
            store: None,
            error: None,
        }
    }

    /// A service around an already opened witness.
    pub fn running(store: WitnessStore) -> Self {
        Self {
            store: Some(store),
            error: None,
        }
    }

    /// Opens the witness, or records why it could not be opened.
    pub fn open(data_dir: &Path, config: &WitnessConfig, operator_id: &str) -> Self {
        match WitnessStore::open(data_dir, config, operator_id) {
            Ok(store) => {
                println!(
                    "  Witness: {} (key {}), cosigning {} log(s)",
                    store.name(),
                    store.verifier_key(),
                    store.trusted_origins().len()
                );
                Self {
                    store: Some(store),
                    error: None,
                }
            }
            Err(e) => {
                eprintln!("ERROR: witness unavailable (witness endpoints will 503): {e}");
                Self {
                    store: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// The running witness, if any.
    pub fn store(&self) -> Option<&WitnessStore> {
        self.store.as_ref()
    }

    /// The open error, if the witness was enabled but failed to open.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    fn require(&self) -> Result<&WitnessStore, (StatusCode, String)> {
        match (&self.store, &self.error) {
            (Some(store), _) => Ok(store),
            (None, Some(error)) => Err((StatusCode::SERVICE_UNAVAILABLE, error.clone())),
            (None, None) => Err((StatusCode::NOT_FOUND, "witness is not enabled".to_string())),
        }
    }
}

/// The witness router, to mount at `/v1/witness`.
pub fn router(service: Arc<WitnessService>) -> Router {
    Router::new()
        .route("/add-checkpoint", post(post_add_checkpoint))
        .route("/info", get(get_witness_info))
        .route("/{origin_hash}/checkpoint", get(get_witness_checkpoint))
        .layer(DefaultBodyLimit::max(WITNESS_MAX_BODY))
        .with_state(service)
}

fn text(status: StatusCode, content_type: &'static str, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, content_type)], body).into_response()
}

fn refusal(error: &WitnessError) -> Response {
    match error {
        WitnessError::Conflict { latest_size } => text(
            StatusCode::CONFLICT,
            SIZE_CONTENT_TYPE,
            encode_size(*latest_size),
        ),
        other => text(
            StatusCode::from_u16(other.status()).unwrap_or(StatusCode::BAD_REQUEST),
            "text/plain; charset=utf-8",
            other.to_string(),
        ),
    }
}

async fn post_add_checkpoint(State(service): State<Arc<WitnessService>>, body: Bytes) -> Response {
    match service.require() {
        Ok(_) => {}
        // With no witness running, every origin is unknown.
        Err((StatusCode::NOT_FOUND, _)) => return refusal(&WitnessError::UnknownLog),
        Err((status, message)) => return text(status, "text/plain; charset=utf-8", message),
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let result = tokio::task::spawn_blocking(move || {
        service
            .store()
            .map(|store| store.add_checkpoint(&body, now))
    })
    .await;
    match result {
        Ok(Some(Ok(lines))) => text(StatusCode::OK, "text/plain; charset=utf-8", lines),
        Ok(Some(Err(AddCheckpointError::Refused(error)))) => refusal(&error),
        Ok(Some(Err(AddCheckpointError::Unavailable(message)))) => text(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain; charset=utf-8",
            message,
        ),
        Ok(None) => refusal(&WitnessError::UnknownLog),
        Err(e) => text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "text/plain; charset=utf-8",
            e.to_string(),
        ),
    }
}

async fn get_witness_checkpoint(
    State(service): State<Arc<WitnessService>>,
    UrlPath(origin_hash): UrlPath<String>,
) -> Result<Response, (StatusCode, String)> {
    let store = service.require()?;
    let note = store.checkpoint_for_hash(&origin_hash).ok_or((
        StatusCode::NOT_FOUND,
        "this witness never cosigned a checkpoint for that log".to_string(),
    ))?;
    Ok(text(StatusCode::OK, "text/plain; charset=utf-8", note))
}

/// Witness discovery.
#[derive(Debug, Serialize)]
pub struct WitnessInfoResponse {
    pub name: String,
    pub verifier_key: String,
    pub trusted_logs: Vec<String>,
}

async fn get_witness_info(
    State(service): State<Arc<WitnessService>>,
) -> Result<Json<WitnessInfoResponse>, (StatusCode, String)> {
    let store = service.require()?;
    Ok(Json(WitnessInfoResponse {
        name: store.name().to_string(),
        verifier_key: store.verifier_key().to_string(),
        trusted_logs: store.trusted_origins(),
    }))
}
