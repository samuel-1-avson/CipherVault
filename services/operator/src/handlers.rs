use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use ciphervault_storage::types::{
    AppendRecordResponse, ChallengeRequest, ChallengeResponse, LeaseReceipt, LeaseRequest,
    OperatorInfo, RecoveryRecordsResponse, SessionRequest, SessionResponse,
};

use ciphervault_storage::invites::{JoinRefreshRequest, JoinRequest, JoinResponse};
use ciphervault_storage::vouchers::WriteVoucher;
use ciphervault_storage::StorageError;

use crate::state::OperatorState;

pub(crate) fn extract_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

pub(crate) fn extract_vault_id(headers: &HeaderMap) -> Option<&str> {
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

/// Constant-time service-token comparison: mismatched lengths and
/// mismatched contents both fail without early exit.
fn service_token_matches(provided: &str, expected: &str) -> bool {
    bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
}

pub(crate) fn require_control_auth(
    state: &OperatorState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    if let Ok(expected) = std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
        if !expected.is_empty()
            && headers
                .get("X-CipherVault-Service-Token")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|provided| service_token_matches(provided, &expected))
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
            .is_none_or(|provided| !service_token_matches(provided, &expected))
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

/// Extracts the `X-CipherVault-Voucher` write voucher (JSON). Absent
/// headers yield `None` (rejected downstream only when policy requires
/// vouchers); present-but-unparseable headers are a 400.
pub(crate) fn extract_voucher(
    headers: &HeaderMap,
) -> Result<Option<WriteVoucher>, (StatusCode, String)> {
    let Some(raw) = headers.get("X-CipherVault-Voucher") else {
        return Ok(None);
    };
    let text = raw.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid voucher header encoding".into(),
        )
    })?;
    serde_json::from_str::<WriteVoucher>(text)
        .map(Some)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid voucher: {e}")))
}

/// Maps state-layer storage errors onto HTTP responses. The `_with_voucher`
/// state methods only produce `ServerError`, preserving each route's legacy
/// status for inner failures while adding 403/429 for voucher outcomes.
pub(crate) fn storage_error_response(error: StorageError) -> (StatusCode, String) {
    match error {
        StorageError::ServerError { status, message } => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            message,
        ),
        other => (StatusCode::BAD_REQUEST, other.to_string()),
    }
}

pub(crate) fn require_session<'a>(
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
    Json(build_operator_info(&state))
}

/// Builds the signed operator identity descriptor. Shared by the HTTP
/// `GET /v1/info` handler and the P2P `GetInfo` RPC so both transports
/// advertise byte-identical identities.
pub(crate) fn build_operator_info(state: &OperatorState) -> OperatorInfo {
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
    info
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
    match state.verify_and_create_session(
        &req.challenge_id,
        &req.public_key_hex,
        &req.signature_hex,
    ) {
        Ok(Some(token)) => Ok(Json(SessionResponse {
            token,
            expires_at_utc: chrono::Utc::now().timestamp() as u64 + 3600,
        })),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            "Invalid challenge response or expired".into(),
        )),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error)),
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
    match state.revoke_identity(&req.vault_id_hex, &req.public_key_hex) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err((StatusCode::NOT_FOUND, "Identity is not enrolled".into())),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error)),
    }
}

pub async fn get_enrolled_identities(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::state::EnrolledIdentity>>, (StatusCode, String)> {
    require_service_token(&headers)?;
    Ok(Json(state.list_enrolled_identities()))
}

#[derive(Debug, Deserialize)]
pub struct VoucherIssueRequest {
    pub holder_pk_hex: String,
    pub quota_bytes: u64,
    pub ttl_secs: u64,
}

/// Issues a self-signed write voucher (D4, barter model). Operator-admin
/// only: service-token auth like identity enrollment. No P2P equivalent —
/// issuance is local administration, not mesh traffic.
pub async fn post_issue_voucher(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Json(req): Json<VoucherIssueRequest>,
) -> Result<Json<WriteVoucher>, (StatusCode, String)> {
    require_service_token(&headers)?;
    let voucher = state
        .issue_voucher(req.holder_pk_hex, req.quota_bytes, req.ttl_secs)
        .map_err(storage_error_response)?;
    Ok(Json(voucher))
}

pub async fn post_revoke_session(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    let token = require_session(&state, &headers, true)?;
    match state.revoke_session(token) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err((
            StatusCode::UNAUTHORIZED,
            "Session is no longer active".into(),
        )),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error)),
    }
}

pub async fn put_object(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(cid): Path<String>,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    require_session(&state, &headers, true)?;
    let voucher = extract_voucher(&headers)?;

    state
        .put_object_with_voucher(&cid, &body, voucher.as_ref())
        .map_err(storage_error_response)?;
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
    let voucher = extract_voucher(&headers)?;

    let receipt = state
        .create_lease_with_voucher(
            &req.closure_digest_hex,
            req.byte_count,
            req.term_days,
            voucher.as_ref(),
        )
        .map_err(storage_error_response)?;
    if let Some(vault_id_hex) = extract_vault_id(&headers) {
        if let Err(err) = state.record_lease_owner(&receipt.lease_id, vault_id_hex) {
            eprintln!("lease owner sidecar failed for {}: {err}", receipt.lease_id);
        }
    }
    Ok(Json(receipt))
}

#[derive(Deserialize)]
pub struct ListLeasesQuery {
    limit: Option<String>,
}

/// Operator kill-switch for lease listing (abuse bounds): when
/// `CIPHERVAULT_DISABLE_LEASE_LIST` is 1/true/yes, both the HTTP
/// `GET /v1/leases` handler and the P2P `ListLeases` RPC fail closed
/// with 403 before touching auth, so a disabled endpoint costs no
/// session or crypto work under flood.
pub(crate) fn lease_list_disabled() -> bool {
    parse_disable_flag(&std::env::var("CIPHERVAULT_DISABLE_LEASE_LIST").unwrap_or_default())
}

fn parse_disable_flag(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Lists the calling vault's leases. Strict session auth (no anonymous
/// bypass): the vault comes from the validated session headers, never from
/// a caller-supplied filter, so vaults cannot enumerate each other.
pub async fn list_leases(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Query(query): Query<ListLeasesQuery>,
) -> Result<Json<ciphervault_storage::types::LeaseListResponse>, (StatusCode, String)> {
    if lease_list_disabled() {
        return Err((
            StatusCode::FORBIDDEN,
            "Lease listing is disabled on this operator".to_string(),
        ));
    }
    require_session(&state, &headers, true)?;
    let vault_id_hex = extract_vault_id(&headers).ok_or((
        StatusCode::BAD_REQUEST,
        "Missing X-CipherVault-Id header".to_string(),
    ))?;
    let limit: usize = match query.limit.as_deref() {
        None => 100,
        Some(raw) => raw.parse().unwrap_or(0),
    };
    if limit == 0 || limit > 1000 {
        return Err((
            StatusCode::BAD_REQUEST,
            "limit must be between 1 and 1000".to_string(),
        ));
    }
    let mut leases = state.list_leases_for_vault(vault_id_hex);
    let total = leases.len();
    leases.truncate(limit);
    Ok(Json(ciphervault_storage::types::LeaseListResponse {
        leases,
        total,
    }))
}

pub async fn post_renew_lease(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(lease_id): Path<String>,
    Json(req): Json<ciphervault_storage::types::LeaseRenewRequest>,
) -> Result<Json<LeaseReceipt>, (StatusCode, String)> {
    require_session(&state, &headers, true)?;
    let voucher = extract_voucher(&headers)?;

    let receipt = state
        .renew_lease_with_voucher(
            &lease_id,
            req.additional_days,
            req.byte_count,
            voucher.as_ref(),
        )
        .map_err(storage_error_response)?;
    if let Some(vault_id_hex) = extract_vault_id(&headers) {
        if let Err(err) = state.record_lease_owner(&receipt.lease_id, vault_id_hex) {
            eprintln!("lease owner sidecar failed for {}: {err}", receipt.lease_id);
        }
    }
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
    let voucher = extract_voucher(&headers)?;
    let seq = state
        .append_recovery_record_with_voucher(&locator, &body, caller_pk.as_ref(), voucher.as_ref())
        .map_err(storage_error_response)?;
    Ok(Json(AppendRecordResponse {
        sequence: seq,
        status: "appended".into(),
    }))
}

/// Intentionally anonymous: the 32-byte locator is a KDF-derived capability
/// (`derive_recovery_locator`, 256-bit, unenumerable without the recovery
/// secret), and clean-machine recovery has no session by definition.
/// Clients select/verify heads against the recovery signing key. Do NOT add
/// session auth here without a recovery-bootstrap story.
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

/// Returns this node's own fresh signed peer descriptor. Public like
/// `/v1/info`: a descriptor carries only public identity plus a
/// same-second signature, and only the node itself can mint one (the
/// signing key never leaves the process). Fleet tooling and the chaos
/// drill fetch this from each node and POST it to every other node's
/// `/v1/peers/announce` to mesh routing tables; without meshing,
/// heartbeats from unknown senders are ignored and repair cannot push.
pub async fn get_self_peer(
    State(state): State<Arc<OperatorState>>,
) -> Json<ciphervault_storage::PeerDescriptor> {
    let endpoint = std::env::var("CIPHERVAULT_ADVERTISE_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8201".to_string());
    Json(ciphervault_storage::PeerDescriptor::new(
        state.operator_id.clone(),
        endpoint,
        &state.signing_key,
    ))
}

/// Live P2P identity for peering: this node's PeerId plus its listen
/// and AutoNAT-observed external addresses.
#[derive(Serialize)]
pub struct P2pInfoResponse {
    peer_id: String,
    listen_addrs: Vec<String>,
    external_addrs: Vec<String>,
}

/// Reports the live P2P identity. Public like `/v1/peers/self` — peering
/// data is meant to be shared with bootstrap partners. 503 when the
/// swarm is off (HTTP-only node).
pub async fn get_p2p_info(
    State(state): State<Arc<OperatorState>>,
) -> Result<Json<P2pInfoResponse>, (StatusCode, String)> {
    let Some(handle) = state.swarm_handle() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "P2P swarm is not enabled on this node".into(),
        ));
    };
    let to_strings =
        |addrs: Vec<libp2p::Multiaddr>| addrs.into_iter().map(|addr| addr.to_string()).collect();
    Ok(Json(P2pInfoResponse {
        peer_id: handle.peer_id.to_string(),
        listen_addrs: to_strings(handle.listeners().await.unwrap_or_default()),
        external_addrs: to_strings(handle.external_addrs().await.unwrap_or_default()),
    }))
}

/// Admits a new node into probation on a fleet-signed invite. Public by
/// design (like `/v1/peers/self`): the ticket is the authorization, so
/// no service token is required. Mapping: unconfigured join, forged /
/// expired / mismatched invites → 403; spent ticket → 409 (the joiner
/// needs a fresh ticket, not a retry); descriptor problems → 400.
pub async fn post_peer_join(
    State(state): State<Arc<OperatorState>>,
    Json(req): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, (StatusCode, String)> {
    let count = state
        .join_with_invite(req.descriptor.clone(), &req.invite)
        .map_err(join_error_response)?;
    let status = if state.is_probationary(&req.descriptor.operator_id) {
        "probation"
    } else {
        "full"
    };
    Ok(Json(JoinResponse {
        status: status.to_string(),
        operator_id: req.descriptor.operator_id,
        peer_count: count,
    }))
}

fn join_error_response(error: String) -> (StatusCode, String) {
    if error.starts_with("Unable to persist") {
        (StatusCode::INTERNAL_SERVER_ERROR, error)
    } else if error == "Join invite was already spent" {
        (StatusCode::CONFLICT, error)
    } else if error == "Verified join is not configured on this node"
        || error == "Invite node key does not match the announced descriptor"
        || error.starts_with("Server returned error 403")
    {
        (StatusCode::FORBIDDEN, error)
    } else {
        (StatusCode::BAD_REQUEST, error)
    }
}

/// Re-presents a fresh self-signed descriptor for an already-known node
/// key. Public by design: the signature plus the stored key match prove
/// the presenter holds the node key. Unknown joiners → 404 (join first);
/// descriptor problems → 400.
pub async fn post_peer_join_refresh(
    State(state): State<Arc<OperatorState>>,
    Json(req): Json<JoinRefreshRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let status = state.refresh_peer_join(req.descriptor).map_err(|error| {
        if error.starts_with("Unable to persist") {
            (StatusCode::INTERNAL_SERVER_ERROR, error)
        } else if error.starts_with("Unknown joiner") {
            (StatusCode::NOT_FOUND, error)
        } else {
            (StatusCode::BAD_REQUEST, error)
        }
    })?;
    Ok(Json(serde_json::json!({
        "status": match status {
            crate::state::MembershipStatus::Full => "full",
            crate::state::MembershipStatus::Probation => "probation",
        },
    })))
}

/// Lists every active routing entry plus its membership standing.
/// Control-plane route: membership internals are fleet administration.
pub async fn get_peer_membership(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::state::MembershipView>>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
    Ok(Json(state.membership_snapshot()))
}

/// Lists the ticket admission evidence log in admission order.
/// Control-plane route: admission evidence is fleet administration.
pub async fn get_peer_admissions(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::state::AdmissionRecord>>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
    Ok(Json(state.admissions_snapshot()))
}

/// Admin graduation override: confers full membership immediately.
/// Control-plane route like `/v1/peers/announce`. Unknown ids → 404.
pub async fn post_peer_graduate(
    State(state): State<Arc<OperatorState>>,
    headers: HeaderMap,
    Path(operator_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_control_auth(&state, &headers)?;
    let graduated = state.graduate_peer(&operator_id).map_err(|error| {
        if error.starts_with("Unable to persist") {
            (StatusCode::INTERNAL_SERVER_ERROR, error)
        } else {
            (StatusCode::BAD_REQUEST, error)
        }
    })?;
    if !graduated {
        return Err((StatusCode::NOT_FOUND, "Unknown operator id".to_string()));
    }
    Ok(Json(serde_json::json!({
        "status": "full",
        "operator_id": operator_id,
    })))
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

/// Prometheus exposition for operator counters and latency histograms (R11).
/// Unauthenticated like `/healthz`; firewall it or scrape via loopback.
pub async fn get_metrics(State(state): State<Arc<OperatorState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render_prometheus(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GET /v1/peers/self` mints a fresh descriptor for this node's own
    /// identity: operator id matches, the signature verifies against the
    /// node's key, and the advertised endpoint honors
    /// `CIPHERVAULT_ADVERTISE_ENDPOINT` with a loopback default.
    #[test]
    fn service_token_comparison_has_no_early_accept() {
        assert!(service_token_matches("s3cret-token", "s3cret-token"));
        assert!(!service_token_matches("s3cret-token", "s3cret-t0ken"));
        assert!(!service_token_matches("s3cret-token", "s3cret-toke"));
        assert!(!service_token_matches("s3cret-toke", "s3cret-token"));
        assert!(!service_token_matches("", "s3cret-token"));
        assert!(!service_token_matches("s3cret-token", ""));
    }

    #[tokio::test]
    async fn self_peer_descriptor_is_fresh_and_self_signed() {
        let dir = std::env::temp_dir().join(format!("cv-selfpeer-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        let expected_pk = hex::encode(key.verifying_key().as_bytes());
        let state = Arc::new(OperatorState::new("self-1".into(), dir.clone(), key));

        let Json(desc) = get_self_peer(State(state)).await;
        assert_eq!(desc.operator_id, "self-1");
        assert_eq!(desc.signing_pk_hex, expected_pk);
        assert_eq!(desc.endpoint, "http://127.0.0.1:8201");
        desc.verify().expect("self descriptor verifies");
        let now = chrono::Utc::now().timestamp() as u64;
        assert!(now.saturating_sub(desc.timestamp_utc) <= 5);

        std::env::set_var("CIPHERVAULT_ADVERTISE_ENDPOINT", "http://chaos-n3:8201");
        let key2 = ciphervault_crypto::generate_signing_key();
        let state2 = Arc::new(OperatorState::new("self-2".into(), dir.clone(), key2));
        let Json(desc2) = get_self_peer(State(state2)).await;
        assert_eq!(desc2.endpoint, "http://chaos-n3:8201");
        desc2.verify().expect("advertised descriptor verifies");
        std::env::remove_var("CIPHERVAULT_ADVERTISE_ENDPOINT");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Highest-risk Unit 4 validation: `GET /v1/leases` never leaks
    /// across vaults. Vault A's session sees only A's leases; the same
    /// token under vault B's header, a missing token, and the anonymous
    /// recovery token are all rejected; the kill-switch fails closed.
    #[tokio::test]
    async fn lease_list_is_session_scoped_per_vault() {
        std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");
        std::env::remove_var("CIPHERVAULT_DISABLE_LEASE_LIST");
        let dir = std::env::temp_dir().join(format!("cv-leaselistauth-{}", rand::random::<u128>()));
        let state = Arc::new(OperatorState::new(
            "lease-auth".into(),
            dir.clone(),
            ciphervault_crypto::generate_signing_key(),
        ));
        let vault_a = "a".repeat(64);
        let vault_b = "b".repeat(64);
        let device_key = ciphervault_crypto::generate_signing_key();
        let device_pk = hex::encode(device_key.verifying_key().as_bytes());
        let (challenge_id, nonce_hex, _) = state.issue_challenge(&vault_a, &device_pk).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();
        let signature = ciphervault_crypto::signatures::sign_with_domain(
            &device_key,
            b"operator_challenge",
            &nonce,
        );
        let token = state
            .verify_and_create_session(&challenge_id, &device_pk, &hex::encode(signature))
            .unwrap()
            .unwrap();

        let lease_a = state.create_lease(&"c".repeat(64), 100, 90).unwrap();
        let lease_b = state.create_lease(&"d".repeat(64), 200, 30).unwrap();
        state
            .record_lease_owner(&lease_a.lease_id, &vault_a)
            .unwrap();
        state
            .record_lease_owner(&lease_b.lease_id, &vault_b)
            .unwrap();

        let headers_for = |token: Option<&str>, vault: &str| {
            let mut headers = HeaderMap::new();
            if let Some(token) = token {
                headers.insert(
                    axum::http::header::AUTHORIZATION,
                    axum::http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
                );
            }
            headers.insert(
                "X-CipherVault-Id",
                axum::http::HeaderValue::from_str(vault).unwrap(),
            );
            headers
        };
        let query = || Query(ListLeasesQuery { limit: None });

        // Happy path: vault A sees only its own lease.
        let Json(listing) = list_leases(
            State(state.clone()),
            headers_for(Some(&token), &vault_a),
            query(),
        )
        .await
        .unwrap();
        assert_eq!(listing.total, 1);
        assert_eq!(listing.leases.len(), 1);
        assert_eq!(listing.leases[0].lease_id, lease_a.lease_id);

        // Cross-vault: A's token under B's header is rejected.
        let err = list_leases(
            State(state.clone()),
            headers_for(Some(&token), &vault_b),
            query(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        // Anonymous: missing token rejected.
        let err = list_leases(State(state.clone()), headers_for(None, &vault_a), query())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        // Anonymous: recovery bypass token rejected (strict session auth).
        let err = list_leases(
            State(state.clone()),
            headers_for(Some("recovery_anonymous"), &vault_a),
            query(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        // Kill-switch fails closed before auth.
        std::env::set_var("CIPHERVAULT_DISABLE_LEASE_LIST", "true");
        let err = list_leases(
            State(state.clone()),
            headers_for(Some(&token), &vault_a),
            query(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        std::env::remove_var("CIPHERVAULT_DISABLE_LEASE_LIST");

        assert!(parse_disable_flag("1"));
        assert!(parse_disable_flag(" True "));
        assert!(parse_disable_flag("YES"));
        assert!(!parse_disable_flag(""));
        assert!(!parse_disable_flag("false"));
        assert!(!parse_disable_flag("0"));

        std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn join_errors_map_to_status() {
        assert_eq!(
            join_error_response("Verified join is not configured on this node".into()).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            join_error_response("Server returned error 403: invite expired".into()).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            join_error_response("Invite node key does not match the announced descriptor".into()).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            join_error_response("Join invite was already spent".into()).0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            join_error_response("Invalid peer signature: bad hex".into()).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            join_error_response("Unable to persist peer membership: disk full".into()).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
