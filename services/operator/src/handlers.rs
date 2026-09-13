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

pub async fn post_object_challenge(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(cid): Path<String>,
    Json(req): Json<ciphervault_storage::PosChallengeRequest>,
) -> Result<Json<ciphervault_storage::ProofOfStorageReceipt>, (StatusCode, String)> {
    let token =
        extract_token(&headers).ok_or((StatusCode::UNAUTHORIZED, "Missing bearer token".into()))?;
    if !state.validate_read_session(token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or expired read session token".into(),
        ));
    }

    let nonce_bytes = hex::decode(&req.nonce_hex).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid hex in nonce: {}", e),
        )
    })?;
    if nonce_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid challenge nonce length (expected 32 bytes)".into(),
        ));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);

    let receipt = state.generate_pos_proof(&cid, &nonce).map_err(|e| {
        if e == "Object not found" {
            (StatusCode::NOT_FOUND, e)
        } else {
            (StatusCode::BAD_REQUEST, e)
        }
    })?;

    Ok(Json(receipt))
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

    let caller_pk = state.get_session_public_key(token);
    let seq = state
        .append_authorized_recovery_record(&locator, &body, caller_pk.as_ref())
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

pub async fn post_relayer_checkpoint(
    State(state): State<Arc<OperatorState>>,
    Json(evidence): Json<ciphervault_format::CheckpointEvidence>,
) -> Result<Json<ciphervault_storage::RelayerReceipt>, (StatusCode, String)> {
    let receipt = state
        .relay_checkpoint(&evidence)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(receipt))
}

pub async fn get_relayer_checkpoint(
    State(state): State<Arc<OperatorState>>,
    Path(commitment): Path<String>,
) -> Result<Json<ciphervault_storage::RelayerReceipt>, StatusCode> {
    match state.get_relayed_checkpoint(&commitment) {
        Some(receipt) => Ok(Json(receipt)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// -----------------------------------------------------------------------------
// Dynamic P2P Peer Gossip Handlers
// -----------------------------------------------------------------------------

pub async fn post_peer_announce(
    State(state): State<Arc<OperatorState>>,
    Json(peer): Json<ciphervault_storage::PeerDescriptor>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let count = state
        .register_peer(peer)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({
        "status": "registered",
        "peer_count": count
    })))
}

pub async fn get_peers(
    State(state): State<Arc<OperatorState>>,
) -> Json<Vec<ciphervault_storage::PeerDescriptor>> {
    let peers = state.get_active_peers();
    Json(peers)
}

// -----------------------------------------------------------------------------
// Out-of-Band Cryptographic Approval Handlers
// -----------------------------------------------------------------------------

pub async fn post_approval_challenge(
    State(state): State<Arc<OperatorState>>,
    Json(challenge): Json<ciphervault_recovery::ApprovalChallenge>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let id = challenge.challenge_id.clone();
    state
        .register_approval_challenge(challenge)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({
        "status": "challenge_created",
        "challenge_id": id
    })))
}

pub async fn get_pending_challenges(
    State(state): State<Arc<OperatorState>>,
) -> Json<Vec<ciphervault_recovery::ApprovalChallenge>> {
    let list = state.get_pending_challenges();
    Json(list)
}

pub async fn get_challenge_status(
    State(state): State<Arc<OperatorState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.get_challenge_status(&id) {
        Some((challenge, receipts)) => Ok(Json(serde_json::json!({
            "challenge": challenge,
            "receipts": receipts,
            "approved": !receipts.is_empty(),
            "receipt_count": receipts.len()
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn post_submit_approval(
    State(state): State<Arc<OperatorState>>,
    Json(receipt): Json<ciphervault_recovery::SignedApprovalReceipt>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let count = state
        .submit_approval_receipt(receipt)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({
        "status": "receipt_accepted",
        "approval_count": count
    })))
}
