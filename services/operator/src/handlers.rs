use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::Arc;

use ciphervault_storage::types::{
    AppendRecordResponse, ChallengeRequest, ChallengeResponse, LeaseReceipt, LeaseRequest,
    OperatorInfo, RecoveryRecordsResponse, SessionRequest, SessionResponse,
};

use crate::state::OperatorState;

fn extract_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

pub async fn get_info(State(state): State<Arc<OperatorState>>) -> Json<OperatorInfo> {
    let pk_hex = hex::encode(state.signing_key.verifying_key().as_bytes());
    Json(OperatorInfo {
        operator_id: state.operator_id.clone(),
        operator_signing_pk_hex: pk_hex,
        supported_version: 1,
        retention_terms: "90-day immutable retention minimum".into(),
    })
}

pub async fn post_challenge(
    State(state): State<Arc<OperatorState>>,
    Json(_req): Json<ChallengeRequest>,
) -> Json<ChallengeResponse> {
    let (challenge_id, nonce_hex, expires_at_utc) = state.issue_challenge();
    Json(ChallengeResponse {
        challenge_id,
        nonce_hex,
        expires_at_utc,
    })
}

pub async fn post_session(
    State(state): State<Arc<OperatorState>>,
    Json(req): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    if let Some(token) =
        state.verify_and_create_session(&req.challenge_id, &req.public_key_hex, &req.signature_hex)
    {
        Ok(Json(SessionResponse {
            token,
            expires_at_utc: chrono::Utc::now().timestamp() as u64 + 3600,
        }))
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "Invalid challenge response or expired".into(),
        ))
    }
}

pub async fn put_object(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(cid): Path<String>,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let token =
        extract_token(&headers).ok_or((StatusCode::UNAUTHORIZED, "Missing bearer token".into()))?;
    if !state.validate_write_session(token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or expired write session token".into(),
        ));
    }

    state
        .put_object(&cid, &body)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(StatusCode::OK.into_response())
}

pub async fn get_object(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(cid): Path<String>,
) -> Result<Bytes, (StatusCode, String)> {
    let token =
        extract_token(&headers).ok_or((StatusCode::UNAUTHORIZED, "Missing bearer token".into()))?;
    if !state.validate_read_session(token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or expired read session token".into(),
        ));
    }

    let bytes = state
        .get_object(&cid)
        .ok_or((StatusCode::NOT_FOUND, "Object not found".into()))?;
    Ok(Bytes::from(bytes))
}

pub async fn post_lease(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Json(req): Json<LeaseRequest>,
) -> Result<Json<LeaseReceipt>, (StatusCode, String)> {
    let token =
        extract_token(&headers).ok_or((StatusCode::UNAUTHORIZED, "Missing bearer token".into()))?;
    if !state.validate_write_session(token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or expired write session token".into(),
        ));
    }

    let receipt = state
        .create_lease(&req.closure_digest_hex, req.byte_count, req.term_days)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(receipt))
}

pub async fn post_renew_lease(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(lease_id): Path<String>,
    Json(req): Json<ciphervault_storage::types::LeaseRenewRequest>,
) -> Result<Json<LeaseReceipt>, (StatusCode, String)> {
    let token =
        extract_token(&headers).ok_or((StatusCode::UNAUTHORIZED, "Missing bearer token".into()))?;
    if !state.validate_write_session(token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or expired write session token".into(),
        ));
    }

    let receipt = state
        .renew_lease(&lease_id, req.additional_days, req.byte_count)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(receipt))
}

pub async fn post_recovery_record(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(locator): Path<String>,
    body: Bytes,
) -> Result<Json<AppendRecordResponse>, (StatusCode, String)> {
    let token =
        extract_token(&headers).ok_or((StatusCode::UNAUTHORIZED, "Missing bearer token".into()))?;
    if !state.validate_write_session(token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or expired write session token".into(),
        ));
    }

    let seq = state
        .append_recovery_record(&locator, &body)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(AppendRecordResponse {
        sequence: seq,
        status: "appended".into(),
    }))
}

pub async fn get_recovery_records(
    State(state): State<Arc<OperatorState>>,
    Path(locator): Path<String>,
) -> Json<RecoveryRecordsResponse> {
    let records = state.get_recovery_records(&locator);
    let records_hex = records.into_iter().map(hex::encode).collect();
    Json(RecoveryRecordsResponse { records_hex })
}
