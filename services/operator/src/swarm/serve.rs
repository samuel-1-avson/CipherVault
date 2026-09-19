//! P2P operator-RPC server (DON Phase 2).
//!
//! Serves [`OperatorRpcRequest`] from the live [`OperatorState`] by running
//! the SAME auth checks (`handlers::require_session`, `require_control_auth`)
//! over a rebuilt header map and the SAME state methods the HTTP handlers
//! call, with the SAME status mapping. P2P/HTTP behavioral parity holds by
//! construction; the three-leg conformance suite proves it on every run.

use axum::http::{HeaderMap, HeaderName, HeaderValue};

use super::behaviour::{OperatorRpcBody, OperatorRpcRequest, OperatorRpcResponse, P2pAuth};
use crate::handlers;
use crate::OperatorState;

static VAULT_ID_HEADER: HeaderName = HeaderName::from_static("x-ciphervault-id");
static SERVICE_TOKEN_HEADER: HeaderName = HeaderName::from_static("x-ciphervault-service-token");

/// Rebuilds the HTTP header view the `handlers` auth checks expect. Values
/// that cannot be header-encoded are dropped, failing closed exactly like a
/// missing header would.
fn auth_headers(auth: &P2pAuth) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(token) = auth.bearer_token.as_deref() {
        if let Ok(value) = format!("Bearer {token}").parse::<HeaderValue>() {
            headers.insert(axum::http::header::AUTHORIZATION, value);
        }
    }
    if let Some(vault) = auth.vault_id_hex.as_deref() {
        if let Ok(value) = vault.parse::<HeaderValue>() {
            headers.insert(VAULT_ID_HEADER.clone(), value);
        }
    }
    if let Some(token) = auth.service_token.as_deref() {
        if let Ok(value) = token.parse::<HeaderValue>() {
            headers.insert(SERVICE_TOKEN_HEADER.clone(), value);
        }
    }
    headers
}

fn fail(status: axum::http::StatusCode, message: String) -> OperatorRpcResponse {
    OperatorRpcResponse::Err {
        status: status.as_u16(),
        message,
    }
}

fn fail_auth(err: (axum::http::StatusCode, String)) -> OperatorRpcResponse {
    fail(err.0, err.1)
}

/// Maps state-layer storage errors 1:1 onto the HTTP statuses, including
/// the 403/429 voucher outcomes.
fn fail_storage(error: ciphervault_storage::StorageError) -> OperatorRpcResponse {
    match error {
        ciphervault_storage::StorageError::ServerError { status, message } => {
            OperatorRpcResponse::Err { status, message }
        }
        other => fail(axum::http::StatusCode::BAD_REQUEST, other.to_string()),
    }
}

/// Answers one operator RPC. Every arm cites the HTTP handler it mirrors;
/// success payloads AND error statuses match that handler exactly.
pub fn serve_operator_rpc(
    state: &OperatorState,
    request: &OperatorRpcRequest,
) -> OperatorRpcResponse {
    let headers = auth_headers(&request.auth);
    match &request.body {
        // mirrors post_challenge: JSON identity fields win; there is no
        // header fallback over P2P because the typed body always carries
        // the client's identity binding (see OperatorClient::authenticate).
        OperatorRpcBody::RequestChallenge(req) => {
            match state.issue_challenge_with_binding(
                &req.vault_id_hex,
                &req.public_key_hex,
                req.account_id.as_deref(),
                req.device_id_hex.as_deref(),
            ) {
                Ok((challenge_id, nonce_hex, expires_at_utc)) => {
                    OperatorRpcResponse::Challenge(ciphervault_storage::types::ChallengeResponse {
                        challenge_id,
                        nonce_hex,
                        expires_at_utc,
                    })
                }
                Err(e) => fail(axum::http::StatusCode::BAD_REQUEST, e),
            }
        }
        // mirrors post_session
        OperatorRpcBody::RedeemSession(req) => {
            match state.verify_and_create_session(
                &req.challenge_id,
                &req.public_key_hex,
                &req.signature_hex,
            ) {
                Ok(Some(token)) => {
                    OperatorRpcResponse::Session(ciphervault_storage::types::SessionResponse {
                        token,
                        expires_at_utc: chrono::Utc::now().timestamp() as u64 + 3600,
                    })
                }
                Ok(None) => fail(
                    axum::http::StatusCode::UNAUTHORIZED,
                    "Invalid challenge response or expired".to_string(),
                ),
                Err(error) => fail(axum::http::StatusCode::INTERNAL_SERVER_ERROR, error),
            }
        }
        // mirrors post_revoke_session
        OperatorRpcBody::RevokeSession => {
            let token = match handlers::require_session(state, &headers, true) {
                Ok(token) => token,
                Err(e) => return fail_auth(e),
            };
            match state.revoke_session(token) {
                Ok(true) => OperatorRpcResponse::Revoked,
                Ok(false) => fail(
                    axum::http::StatusCode::UNAUTHORIZED,
                    "Session is no longer active".to_string(),
                ),
                Err(error) => fail(axum::http::StatusCode::INTERNAL_SERVER_ERROR, error),
            }
        }
        // mirrors get_info via the shared builder (byte-identical identity)
        OperatorRpcBody::GetInfo => OperatorRpcResponse::Info(handlers::build_operator_info(state)),
        // mirrors put_object
        OperatorRpcBody::PutObject { cid, data } => {
            if let Err(e) = handlers::require_session(state, &headers, true) {
                return fail_auth(e);
            }
            match state.put_object_with_voucher(
                &hex::encode(cid),
                data,
                request.auth.voucher.as_ref(),
            ) {
                Ok(()) => OperatorRpcResponse::PutDone,
                Err(e) => fail_storage(e),
            }
        }
        // mirrors get_object
        OperatorRpcBody::GetObject { cid } => {
            if let Err(e) = handlers::require_session(state, &headers, false) {
                return fail_auth(e);
            }
            match state.get_object(&hex::encode(cid)) {
                Some(bytes) => OperatorRpcResponse::Object { bytes },
                None => fail(
                    axum::http::StatusCode::NOT_FOUND,
                    "Object not found".to_string(),
                ),
            }
        }
        // mirrors post_object_challenge (the CID arrives typed, so the hex
        // pre-checks cannot fail; proof errors keep the handler's mapping)
        OperatorRpcBody::ProveStorage { cid, nonce } => {
            if let Err(e) = handlers::require_session(state, &headers, false) {
                return fail_auth(e);
            }
            match state.generate_pos_proof(&hex::encode(cid), nonce) {
                Ok(receipt) => OperatorRpcResponse::Proof { receipt },
                Err(e) if e == "Object not found" => fail(axum::http::StatusCode::NOT_FOUND, e),
                Err(e) => fail(axum::http::StatusCode::BAD_REQUEST, e),
            }
        }
        // mirrors post_lease, including its 500 mapping for invalid params
        OperatorRpcBody::CommitLease {
            closure_digest,
            byte_count,
            term_days,
        } => {
            if let Err(e) = handlers::require_session(state, &headers, true) {
                return fail_auth(e);
            }
            match state.create_lease_with_voucher(
                &hex::encode(closure_digest),
                *byte_count,
                *term_days,
                request.auth.voucher.as_ref(),
            ) {
                Ok(receipt) => OperatorRpcResponse::Lease(receipt),
                Err(e) => fail_storage(e),
            }
        }
        // mirrors post_renew_lease
        OperatorRpcBody::RenewLease {
            lease_id,
            additional_days,
            byte_count,
        } => {
            if let Err(e) = handlers::require_session(state, &headers, true) {
                return fail_auth(e);
            }
            match state.renew_lease_with_voucher(
                lease_id,
                *additional_days,
                *byte_count,
                request.auth.voucher.as_ref(),
            ) {
                Ok(receipt) => OperatorRpcResponse::Lease(receipt),
                Err(e) => fail_storage(e),
            }
        }
        // mirrors post_recovery_record (`require_session` performs the
        // same missing-credential check first, so its 401 is identical)
        OperatorRpcBody::AppendRecovery { locator, record } => {
            let token = match handlers::require_session(state, &headers, true) {
                Ok(token) => token,
                Err(e) => return fail_auth(e),
            };
            let caller_pk = state.get_session_public_key(token);
            match state.append_recovery_record_with_voucher(
                &hex::encode(locator),
                record,
                caller_pk.as_ref(),
                request.auth.voucher.as_ref(),
            ) {
                Ok(sequence) => OperatorRpcResponse::Appended { sequence },
                Err(e) => fail_storage(e),
            }
        }
        // mirrors get_recovery_records: anonymous by design (the locator is the
        // capability; see handler docs), same hex-counted byte cap
        // (the HTTP `truncated` flag is ignored by every client; P2P omits it)
        OperatorRpcBody::GetRecovery { locator } => {
            let mut records = Vec::new();
            let mut encoded_bytes = 0usize;
            for record in state.get_recovery_records(&hex::encode(locator)) {
                if encoded_bytes.saturating_add(record.len() * 2)
                    > crate::state::max_recovery_response_bytes()
                {
                    break;
                }
                encoded_bytes += record.len() * 2;
                records.push(record);
            }
            OperatorRpcResponse::RecoveryRecords { records }
        }
        // mirrors post_peer_announce
        OperatorRpcBody::AnnouncePeer { descriptor } => {
            if let Err(e) = handlers::require_control_auth(state, &headers) {
                return fail_auth(e);
            }
            match state.register_peer(descriptor.clone()) {
                Ok(_) => OperatorRpcResponse::PeerAnnounced,
                Err(e) => fail(axum::http::StatusCode::BAD_REQUEST, e),
            }
        }
        // mirrors get_peers
        OperatorRpcBody::GetPeers => {
            if let Err(e) = handlers::require_control_auth(state, &headers) {
                return fail_auth(e);
            }
            OperatorRpcResponse::Peers {
                peers: state.get_active_peers(),
            }
        }
        // mirrors get_pending_challenges; the wire mirror converts exactly
        // like the HTTP JSON deserialization does, failing closed on drift
        OperatorRpcBody::GetPendingApprovals => {
            if let Err(e) = handlers::require_control_auth(state, &headers) {
                return fail_auth(e);
            }
            let mut challenges = Vec::new();
            for challenge in state.get_pending_challenges() {
                match serde_json::to_value(&challenge)
                    .ok()
                    .and_then(|v| serde_json::from_value(v).ok())
                {
                    Some(c) => challenges.push(c),
                    None => {
                        return fail(
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            "Approval wire-shape drift".to_string(),
                        )
                    }
                }
            }
            OperatorRpcResponse::PendingApprovals { challenges }
        }
        // Mesh repair backfill (Phase 4). NO session check by design:
        // authentication is the sender's operator signature (verified
        // against the routing table), authorization is the repair budget,
        // and integrity is the content digest. A forged or over-budget
        // push stores nothing; every outcome carries its own metric.
        OperatorRpcBody::RepairPush {
            cid,
            data,
            sender_operator_id,
            sender_pk_hex,
            recipient_operator_id,
            signature_hex,
        } => {
            if recipient_operator_id != &state.operator_id {
                state.metrics.observe_repair_failed();
                return fail(
                    axum::http::StatusCode::FORBIDDEN,
                    "Repair push misaddressed".to_string(),
                );
            }
            let table =
                crate::state::lock_or_recover(&state.peer_routing_table, "peer_routing_table");
            let known = table
                .get(sender_operator_id)
                .map(|desc| desc.signing_pk_hex.clone());
            let Some(expected_pk) = known else {
                state.metrics.observe_repair_failed();
                return fail(
                    axum::http::StatusCode::FORBIDDEN,
                    "Unknown repair sender".to_string(),
                );
            };
            if sender_pk_hex != &expected_pk
                || !verify_repair_signature(
                    &expected_pk,
                    recipient_operator_id,
                    cid,
                    data,
                    signature_hex,
                )
            {
                state.metrics.observe_repair_failed();
                return fail(
                    axum::http::StatusCode::FORBIDDEN,
                    "Bad repair signature".to_string(),
                );
            }
            if !state.try_spend_repair_budget(data.len() as u64) {
                state.metrics.observe_repair_budget_exhausted();
                return fail(
                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                    "Repair budget exhausted".to_string(),
                );
            }
            state.metrics.observe_repair_bytes(data.len() as u64);
            match state.put_repair_object(&hex::encode(cid), data) {
                Ok(stored) => {
                    state.metrics.observe_repair_completed();
                    OperatorRpcResponse::RepairDone { stored }
                }
                Err(e) => {
                    state.metrics.observe_repair_failed();
                    fail(axum::http::StatusCode::BAD_REQUEST, e)
                }
            }
        }
    }
}

/// Verifies a repair-push signature against the sender's announced key.
/// False on any decoding or crypto failure (fail closed, no panic path).
fn verify_repair_signature(
    expected_pk_hex: &str,
    recipient_operator_id: &str,
    cid: &[u8; 32],
    data: &[u8],
    signature_hex: &str,
) -> bool {
    let Ok(pk_bytes) = hex::decode(expected_pk_hex) else {
        return false;
    };
    if pk_bytes.len() != 32 {
        return false;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);
    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    let msg = super::repair::repair_signing_bytes(recipient_operator_id, cid, data);
    ciphervault_crypto::signatures::verify_with_domain(
        &pk,
        super::repair::REPAIR_PUSH_DOMAIN,
        &msg,
        &sig,
    )
    .is_ok()
}
