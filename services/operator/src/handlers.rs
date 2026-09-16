use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
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

fn extract_vault_id(headers: &HeaderMap) -> Option<&str> {
    headers.get("X-CipherVault-Id")?.to_str().ok()
}

fn strict_operator_auth() -> bool {
    std::env::var("CIPHERVAULT_OPERATOR_STRICT_AUTH")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        // Fail closed when an operator is launched outside the hardened
        // Compose/systemd environment. Anonymous control routes are unsafe
        // as a source default.
        .unwrap_or(true)
}

fn require_control_auth(
    state: &OperatorState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    if let Ok(expected) = std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
        if !expected.is_empty()
            && headers
                .get("X-CipherVault-Service-Token")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|provided| provided == expected)
        {
            return Ok(());
        }
    }
    if !strict_operator_auth() && extract_token(headers).is_none() {
        // Kept as an explicit migration switch for existing operator-to-operator clients.
        // Production compose enables strict mode; local legacy callers can migrate separately.
        return Ok(());
    }
    require_session(state, headers, true).map(|_| ())
}

fn require_service_token(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let expected = std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN").map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Operator identity administration is not configured".into(),
        )
    })?;
    if expected.is_empty()
        || headers
            .get("X-CipherVault-Service-Token")
            .and_then(|value| value.to_str().ok())
            .is_none_or(|provided| provided != expected)
    {
        return Err((StatusCode::UNAUTHORIZED, "Invalid service token".into()));
    }
    Ok(())
}

fn configured_anchor_client() -> Result<Option<ciphervault_storage::ArbitrumAnchorClient>, String> {
    let Some(rpc_url) = std::env::var("ARBITRUM_RPC_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let chain_id = std::env::var("ARBITRUM_CHAIN_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "ARBITRUM_CHAIN_ID must be an unsigned integer".to_string())
        })
        .transpose()?;
    let chain_id = chain_id.unwrap_or(42161);
    let contract = std::env::var("CIPHERVAULT_REGISTRY_CONTRACT")
        .ok()
        .or_else(|| std::env::var("ARBITRUM_CONTRACT_ADDRESS").ok())
        .filter(|value| !value.trim().is_empty());
    let Some(contract) = contract else {
        return Ok(None);
    };
    let bytes = hex::decode(contract.trim().trim_start_matches("0x"))
        .map_err(|_| "CIPHERVAULT_REGISTRY_CONTRACT must be 20-byte hex".to_string())?;
    if bytes.len() != 20 {
        return Err("CIPHERVAULT_REGISTRY_CONTRACT must be 20-byte hex".into());
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    if address == [0u8; 20] {
        return Err("CIPHERVAULT_REGISTRY_CONTRACT cannot be the zero address".into());
    }
    Ok(Some(ciphervault_storage::ArbitrumAnchorClient::new(
        rpc_url, chain_id, address,
    )))
}

#[derive(Debug, Deserialize)]
pub struct IdentityRequest {
    pub vault_id_hex: String,
    pub public_key_hex: String,
    #[serde(default = "default_identity_permissions")]
    pub permissions: u32,
    /// Optional control-plane account binding for this enrolled device.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Optional account device ID. Must be supplied together with account_id.
    #[serde(default)]
    pub device_id_hex: Option<String>,
}

fn default_identity_permissions() -> u32 {
    0xffff_ffff
}

fn require_session<'a>(
    state: &OperatorState,
    headers: &'a HeaderMap,
    write: bool,
) -> Result<&'a str, (StatusCode, String)> {
    let token =
        extract_token(headers).ok_or((StatusCode::UNAUTHORIZED, "Missing bearer token".into()))?;
    if !write && token == "recovery_anonymous" {
        return Ok(token);
    }
    let vault_id = extract_vault_id(headers).ok_or((
        StatusCode::BAD_REQUEST,
        "Missing X-CipherVault-Id header".into(),
    ))?;
    if hex::decode(vault_id).map(|bytes| bytes.len()) != Ok(32) {
        return Err((
            StatusCode::BAD_REQUEST,
            "X-CipherVault-Id must be 32-byte hex".into(),
        ));
    }
    let valid = state.validate_session_for_vault(token, vault_id);
    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid, expired, or out-of-scope session token".into(),
        ));
    }
    Ok(token)
}

pub async fn get_info(State(state): State<Arc<OperatorState>>) -> Json<OperatorInfo> {
    let pk_hex = hex::encode(state.signing_key.verifying_key().as_bytes());
    let mut info = OperatorInfo {
        operator_id: state.operator_id.clone(),
        operator_signing_pk_hex: pk_hex,
        supported_version: 1,
        retention_terms: "90-day immutable retention minimum".into(),
        identity_signature_hex: String::new(),
        identity_expires_at_utc: chrono::Utc::now().timestamp() as u64 + 86_400,
    };
    let signature = ciphervault_crypto::signatures::sign_with_domain(
        &state.signing_key,
        b"operator_identity",
        &info.identity_signing_bytes(),
    );
    info.identity_signature_hex = hex::encode(signature);
    Json(info)
}

pub async fn get_health(
    State(state): State<Arc<OperatorState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let required = ["objects", "recovery", "leases"];
    let storage_ready = required
        .iter()
        .all(|name| state.data_dir.join(name).is_dir());
    let key_ready = state.data_dir.join("operator.key").is_file();
    let status = if storage_ready && key_ready {
        "ready"
    } else {
        "degraded"
    };
    let body = serde_json::json!({
        "status": status,
        "operator_id": state.operator_id,
        "storage_ready": storage_ready,
        "signing_key_present": key_ready,
        "checked_at_utc": chrono::Utc::now().to_rfc3339(),
    });
    if storage_ready && key_ready {
        Ok(Json(body))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

pub async fn post_challenge(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    // Headers are accepted as a deployment-friendly fallback for clients that
    // cannot yet add the optional JSON fields. JSON values take precedence.
    let account_id = req.account_id.or_else(|| {
        headers
            .get("X-CipherVault-Account-Id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    });
    let device_id_hex = req.device_id_hex.or_else(|| {
        headers
            .get("X-CipherVault-Device-Id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    });
    let (challenge_id, nonce_hex, expires_at_utc) = state
        .issue_challenge_with_binding(
            &req.vault_id_hex,
            &req.public_key_hex,
            account_id.as_deref(),
            device_id_hex.as_deref(),
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(ChallengeResponse {
        challenge_id,
        nonce_hex,
        expires_at_utc,
    }))
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

pub async fn post_enroll_identity(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Json(req): Json<IdentityRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_service_token(&headers)?;
    state
        .enroll_identity_with_binding(
            &req.vault_id_hex,
            &req.public_key_hex,
            req.permissions,
            req.account_id.as_deref(),
            req.device_id_hex.as_deref(),
        )
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn post_revoke_identity(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Json(req): Json<IdentityRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_service_token(&headers)?;
    if state.revoke_identity(&req.vault_id_hex, &req.public_key_hex) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "Identity is not enrolled".into()))
    }
}

pub async fn get_enrolled_identities(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::state::EnrolledIdentity>>, (StatusCode, String)> {
    require_service_token(&headers)?;
    Ok(Json(state.list_enrolled_identities()))
}

pub async fn post_revoke_session(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    let token = require_session(&state, &headers, true)?;
    if state.revoke_session(token) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "Session is no longer active".into(),
        ))
    }
}

pub async fn put_object(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(cid): Path<String>,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    require_session(&state, &headers, true)?;

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
    require_session(&state, &headers, false)?;

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
    require_session(&state, &headers, false)?;

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
    require_session(&state, &headers, true)?;

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
    require_session(&state, &headers, true)?;

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
    require_session(&state, &headers, true)?;

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
    let mut records_hex = Vec::new();
    let mut encoded_bytes = 0usize;
    let mut truncated = false;
    for record in records {
        let encoded = hex::encode(record);
        let response_cap = crate::state::max_recovery_response_bytes();
        if encoded_bytes.saturating_add(encoded.len()) > response_cap {
            truncated = true;
            break;
        }
        encoded_bytes += encoded.len();
        records_hex.push(encoded);
    }
    Json(RecoveryRecordsResponse {
        records_hex,
        truncated,
    })
}

pub async fn post_relayer_checkpoint(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Json(evidence): Json<ciphervault_format::CheckpointEvidence>,
) -> Result<Json<ciphervault_storage::RelayerReceipt>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
    let receipt = state
        .relay_checkpoint(&evidence)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let Some(anchor_client) = configured_anchor_client().map_err(|error| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Invalid anchor verification configuration: {error}"),
        )
    })?
    else {
        return Ok(Json(receipt));
    };
    match anchor_client.verify_evidence(&evidence).await {
        Ok(report) if report.on_chain_confirmed && report.receipt_verified => {
            let confirmed = state
                .confirm_relayed_checkpoint(&evidence, &report)
                .map_err(|error| (StatusCode::BAD_GATEWAY, error))?;
            Ok(Json(confirmed))
        }
        Ok(_) => Ok(Json(receipt)),
        Err(_) => {
            // RPC outages and pending transactions remain queued. They must
            // never be represented as confirmed based on client-supplied data.
            Ok(Json(receipt))
        }
    }
}

pub async fn get_relayer_checkpoint(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(commitment): Path<String>,
) -> Result<Json<ciphervault_storage::RelayerReceipt>, StatusCode> {
    require_control_auth(&state, &headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
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
    headers: HeaderMap,
    Json(peer): Json<ciphervault_storage::PeerDescriptor>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
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
    headers: HeaderMap,
) -> Result<Json<Vec<ciphervault_storage::PeerDescriptor>>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
    let peers = state.get_active_peers();
    Ok(Json(peers))
}

// -----------------------------------------------------------------------------
// Out-of-Band Cryptographic Approval Handlers
// -----------------------------------------------------------------------------

pub async fn post_approval_challenge(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Json(challenge): Json<ciphervault_recovery::ApprovalChallenge>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
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
    headers: HeaderMap,
) -> Result<Json<Vec<ciphervault_recovery::ApprovalChallenge>>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
    let list = state.get_pending_challenges();
    Ok(Json(list))
}

pub async fn get_challenge_status(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_control_auth(&state, &headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
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
    headers: HeaderMap,
    Json(receipt): Json<ciphervault_recovery::SignedApprovalReceipt>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
    let count = state
        .submit_approval_receipt(receipt)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({
        "status": "receipt_accepted",
        "approval_count": count
    })))
}
