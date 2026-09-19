//! Private dashboard API handlers and the loopback request guard.

use anyhow::Result;
use chrono::{TimeZone, Utc};
use std::fs;
use std::path::{Path, PathBuf};

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::{
    future::join_all,
    stream::{self, Stream},
};

use ciphervault_crypto::{generate_signing_key, HardwareSecurityModule};
use ciphervault_local_store::AccountStore;
use ciphervault_maintenance::MaintenanceDb;
use ciphervault_storage::OperatorClient;

use crate::{
    audit_current, cmd_anchor, cmd_push, current_account_context, current_device_identity,
    get_configured_operators, get_vault_store, hosted_account_endpoint, mask_operator_endpoint,
    private_account_session_valid, private_ui_session_snapshot, proxy_account_request,
    public_operator_http_client, revoke_private_ui_session, ui_capabilities, ui_context,
    UiServerMode, PRIVATE_UI_SESSION_TTL,
};

pub(crate) async fn api_private_context_handler() -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};

    let session = private_ui_session_snapshot();
    let mut context = ui_context(UiServerMode::LocalPrivate);
    if let Some(object) = context.as_object_mut() {
        object.insert(
            "session".to_string(),
            serde_json::json!({
                "scheme": "http_only_cookie",
                "vault_bound": session.vault_binding.is_some(),
                "ttl_seconds": PRIVATE_UI_SESSION_TTL.as_secs(),
                "revocation_endpoint": "/api/session/revoke",
            }),
        );
        object.insert("account".to_string(), current_account_context());
    }
    let mut response = axum::Json(context).into_response();
    let cookie = format!(
        "ciphervault_private_session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict",
        session.token,
        PRIVATE_UI_SESSION_TTL.as_secs()
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie)
            .expect("generated private session cookie must be valid"),
    );
    response
}

pub(crate) async fn api_account_status_handler() -> axum::Json<serde_json::Value> {
    axum::Json(current_account_context())
}

pub(crate) async fn api_account_login_handler() -> axum::response::Response {
    use axum::response::IntoResponse;

    let account = match AccountStore::open(None) {
        Ok(account) => account,
        Err(error) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "code": "ACCOUNT_NOT_CONFIGURED",
                    "error": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let Ok((vault_id, device_id, _)) = current_device_identity() else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "VAULT_NOT_INITIALIZED",
                "error": "A local vault is required to bind an account session.",
            })),
        )
            .into_response();
    };
    if !account.is_vault_linked(&vault_id) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "VAULT_NOT_LINKED",
                "error": "Link this vault with `ciphervault vault link` before logging in here.",
            })),
        )
            .into_response();
    }
    match account.login(Some(&device_id)) {
        Ok(status) => axum::Json(serde_json::json!({
            "status": "ok",
            "account": status,
        }))
        .into_response(),
        Err(error) => (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "ACCOUNT_LOGIN_FAILED",
                "error": error.to_string(),
            })),
        )
            .into_response(),
    }
}

pub(crate) async fn api_account_logout_handler(
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let has_hosted_cookie = headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|cookies| {
            cookies
                .split(';')
                .any(|cookie| cookie.trim().starts_with("ciphervault_account_session="))
        });
    if hosted_account_endpoint().is_some() && has_hosted_cookie {
        return proxy_account_request(reqwest::Method::POST, "/v1/sessions/revoke", &headers, None)
            .await;
    }
    match AccountStore::open(None).and_then(|account| account.logout()) {
        Ok(()) => {
            revoke_private_ui_session();
            axum::Json(serde_json::json!({ "status": "ok", "authenticated": false }))
                .into_response()
        }
        Err(error) => (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "ACCOUNT_NOT_CONFIGURED",
                "error": error.to_string(),
            })),
        )
            .into_response(),
    }
}

pub(crate) async fn api_private_session_revoke_handler() -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};

    revoke_private_ui_session();
    let mut response = axum::Json(serde_json::json!({
        "status": "ok",
        "revoked": true,
        "message": "The current private dashboard session was revoked. Open /api/context to establish a new session.",
    }))
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        axum::http::HeaderValue::from_static(
            "ciphervault_private_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
        ),
    );
    response
}

pub(crate) async fn api_public_context_handler() -> axum::Json<serde_json::Value> {
    axum::Json(ui_context(UiServerMode::PublicExplorer))
}

pub(crate) async fn api_public_vault_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "mode": UiServerMode::PublicExplorer.name(),
        "access_mode": UiServerMode::PublicExplorer.access_mode(),
        "capabilities": ui_capabilities(UiServerMode::PublicExplorer),
        "service": "CipherVault public cluster explorer",
        "private_vault_access": false,
        "message": "This public explorer does not expose vault identity, files, snapshots, recovery descriptors, or private actions.",
    }))
}

pub(crate) async fn api_public_fallback_handler(uri: axum::http::Uri) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    if uri.path().starts_with("/api/") {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "PRIVATE_API_DISABLED",
                "error": "This API is available only from a loopback-bound local private workspace.",
            })),
        )
            .into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}

pub(crate) async fn api_private_fallback_handler(uri: axum::http::Uri) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    if uri.path().starts_with("/api/") {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "PRIVATE_API_NOT_FOUND",
                "error": "Unknown private dashboard API path.",
            })),
        )
            .into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}

pub(crate) fn local_host_name(value: &str) -> Option<String> {
    if value.eq_ignore_ascii_case("localhost") {
        return Some("localhost".to_string());
    }
    let address = value.parse::<std::net::IpAddr>().ok()?;
    if address.is_loopback() {
        Some(address.to_string().to_ascii_lowercase())
    } else {
        None
    }
}

pub(crate) fn local_authority(value: &str) -> Option<(String, u16)> {
    let authority = value.trim();
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|raw| raw.parse::<u16>().ok())
            .unwrap_or(80);
        (host, port)
    } else if let Some((host, raw_port)) = authority.rsplit_once(':') {
        if let Ok(port) = raw_port.parse::<u16>() {
            (host, port)
        } else {
            (authority, 80)
        }
    } else {
        (authority, 80)
    };
    Some((local_host_name(host)?, port))
}

pub(crate) async fn private_ui_request_guard(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    let headers = request.headers();
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(local_authority);
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let url = reqwest::Url::parse(value).ok()?;
            if url.scheme() != "http" || url.username() != "" || url.password().is_some() {
                return None;
            }
            let host = local_host_name(url.host_str()?)?;
            Some((host, url.port_or_known_default().unwrap_or(80)))
        });
    let origin_header_present = headers.contains_key(axum::http::header::ORIGIN);
    let is_mutation = matches!(
        request.method(),
        &axum::http::Method::POST
            | &axum::http::Method::PUT
            | &axum::http::Method::PATCH
            | &axum::http::Method::DELETE
    );
    let origin_matches_host = origin
        .as_ref()
        .zip(host.as_ref())
        .is_some_and(|(origin, host)| origin == host);

    let path = request.uri().path();
    let is_api = path.starts_with("/api/");
    let is_context = path == "/api/context";
    let is_account_bootstrap = matches!(
        path,
        "/api/account/status"
            | "/api/account/register"
            | "/api/account/login"
            | "/api/account/logout"
            | "/api/account/capabilities"
            | "/api/account/session"
            | "/api/account/session/handoff"
            | "/api/account/sessions/challenge"
            | "/api/account/sessions/login"
            | "/api/account/sessions/handoff"
            | "/api/account/webauthn/authentication/options"
            | "/api/account/webauthn/authentication/verify"
            | "/api/account/totp/authentication/options"
            | "/api/account/totp/authentication/verify"
    ) || (path.starts_with("/api/account/")
        && path.ends_with("/webauthn/registration/options"))
        || (path.starts_with("/api/account/") && path.ends_with("/webauthn/registration/verify"))
        || (path.starts_with("/api/account/") && path.ends_with("/devices/challenge"))
        || (path.starts_with("/api/account/") && path.ends_with("/devices"));
    let session_valid = if is_api && !is_context && !is_account_bootstrap {
        let session = private_ui_session_snapshot();
        let private_cookie_valid = headers
            .get(axum::http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';').find_map(|cookie| {
                    let (name, value) = cookie.trim().split_once('=')?;
                    (name == "ciphervault_private_session").then_some(value)
                })
            })
            .is_some_and(|value| value == session.token);
        private_cookie_valid && private_account_session_valid()
    } else {
        true
    };

    if host.is_none()
        || (origin_header_present && (origin.is_none() || !origin_matches_host))
        || (is_mutation && (origin.is_none() || !origin_matches_host))
    {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "LOCAL_ORIGIN_REQUIRED",
                "error": "Private dashboard requests must originate from the loopback dashboard address.",
            })),
        )
            .into_response();
    }

    if is_api && !is_context && !session_valid {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "PRIVATE_SESSION_REQUIRED",
                "error": "Open the loopback private dashboard context before calling private APIs.",
            })),
        )
            .into_response();
    }

    let mut response = next.run(request).await;
    let response_headers = response.headers_mut();
    response_headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response_headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response_headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    response
}

pub(crate) async fn api_vault_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "initialized": false,
                "message": "No vault initialized in current directory",
                "mode": UiServerMode::LocalPrivate.name(),
                "access_mode": UiServerMode::LocalPrivate.access_mode(),
                "capabilities": ui_capabilities(UiServerMode::LocalPrivate),
            }));
        }
    };

    let vault_id = store.get_vault_id().unwrap_or([0u8; 32]);
    let (device_id, _signing_key, device_counter, epoch) =
        store
            .get_device_state()
            .unwrap_or(([0u8; 32], generate_signing_key(), 0, 1));
    let tracked = store.list_tracked_files().unwrap_or_default();
    let operators = get_configured_operators();

    let mut recovery_info = serde_json::json!(null);
    if let Ok((signing_pk, encrypt_pk, locator)) = store.get_recovery_descriptors() {
        recovery_info = serde_json::json!({
            "available": true,
            "recovery_signing_pk_hex": hex::encode(signing_pk),
            "recovery_encrypt_pk_hex": hex::encode(encrypt_pk),
            "recovery_locator_hex": hex::encode(locator),
            "offline_secret_secured": true,
        });
    }

    axum::Json(serde_json::json!({
        "initialized": true,
        "mode": UiServerMode::LocalPrivate.name(),
        "access_mode": UiServerMode::LocalPrivate.access_mode(),
        "capabilities": ui_capabilities(UiServerMode::LocalPrivate),
        "vault_id_hex": hex::encode(vault_id),
        "device_id_hex": hex::encode(device_id),
        "device_counter": device_counter,
        "epoch": epoch,
        "tracked_files": tracked.iter().map(|(p, id)| {
            let full_path = Path::new(p);
            let size_bytes = fs::metadata(full_path).map(|m| m.len()).unwrap_or(0);
            serde_json::json!({
                "path": p.to_string_lossy(),
                "file_id_hex": hex::encode(id),
                "size_bytes": size_bytes,
                "chunks_count": (size_bytes as usize / (1024 * 1024)) + 1,
            })
        }).collect::<Vec<_>>(),
        "operators": operators.iter().map(|op| mask_operator_endpoint(op)).collect::<Vec<_>>(),
        "recovery": recovery_info,
    }))
}

pub(crate) async fn api_operators_handler() -> impl axum::response::IntoResponse {
    let http = public_operator_http_client();
    let probes = get_configured_operators().into_iter().map(|endpoint| {
        let http = http.clone();
        async move {
        let client = OperatorClient::with_http_client(endpoint.clone(), http);
        let start = std::time::Instant::now();
        let transport_security = if endpoint
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("https://")
        {
            "https"
        } else {
            "http_or_unknown"
        };
        match client.get_info().await {
            Ok(info) => {
                let latency_ms = start.elapsed().as_millis();
                let identity_verified = info.verify_identity_signature();
                let safe_pk = if info.operator_signing_pk_hex.len() == 64
                    && info
                        .operator_signing_pk_hex
                        .chars()
                        .all(|c| c.is_ascii_hexdigit())
                {
                    info.operator_signing_pk_hex
                } else {
                    "INVALID_KEY_FORMAT".to_string()
                };
                let safe_id = info
                    .operator_id
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .collect::<String>();
                let display_endpoint = mask_operator_endpoint(&endpoint);
                serde_json::json!({
                    "endpoint": display_endpoint,
                    "target_url": display_endpoint,
                    "status": "online",
                    "operator_id": if safe_id.is_empty() { "operator" } else { &safe_id },
                    "operator_signing_pk_hex": safe_pk,
                    "latency_ms": latency_ms,
                    "retention_terms": info.retention_terms,
                    "transport_security": transport_security,
                    "identity_verification": if identity_verified { "verified" } else { "unverified" },
                    "identity_expires_at_utc": info.identity_expires_at_utc,
                    "identity_signature_present": !info.identity_signature_hex.is_empty(),
                })
            }
            Err(_) => {
                let display_endpoint = mask_operator_endpoint(&endpoint);
                serde_json::json!({
                    "endpoint": display_endpoint,
                    "target_url": display_endpoint,
                    "status": "offline",
                    "error": "Operator did not respond",
                    "transport_security": transport_security,
                    "identity_verification": "not_observed",
                })
            }
        }
        }
    });
    let results = join_all(probes).await;

    axum::Json(serde_json::json!(results))
}

/// Private-workspace approval queue (R14): probes every configured operator
/// for pending out-of-band approval challenges. Read-only; approvals are
/// submitted through the CLI guardian ceremony, never the browser.
pub(crate) async fn api_approvals_handler() -> impl axum::response::IntoResponse {
    let http = public_operator_http_client();
    let probes = get_configured_operators().into_iter().map(|endpoint| {
        let http = http.clone();
        async move {
            let client = OperatorClient::with_http_client(endpoint.clone(), http);
            let display_endpoint = mask_operator_endpoint(&endpoint);
            match client.get_pending_approvals().await {
                Ok(challenges) => serde_json::json!({
                    "endpoint": display_endpoint,
                    "status": "online",
                    "challenges": challenges
                        .iter()
                        .map(|challenge| serde_json::json!({
                            "challenge_id": challenge.challenge_id,
                            "action": challenge.action,
                            "vault_id_hex": challenge.vault_id_hex,
                            "requester_device_id_hex": challenge.requester_device_id_hex,
                            "created_at_utc": challenge.created_at_utc,
                            "expires_at_utc": challenge.expires_at_utc,
                            "details": challenge.details,
                        }))
                        .collect::<Vec<_>>(),
                }),
                Err(error) => serde_json::json!({
                    "endpoint": display_endpoint,
                    "status": "unavailable",
                    "error": error.to_string(),
                    "challenges": [],
                }),
            }
        }
    });
    let operators = join_all(probes).await;
    axum::Json(serde_json::json!({ "operators": operators }))
}

pub(crate) async fn api_snapshots_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => return axum::Json(serde_json::json!([])),
    };

    let snapshots = store.list_snapshots().unwrap_or_default();
    let active_head = store.get_active_head().ok().flatten();

    let json_snaps: Vec<_> = snapshots.iter().map(|snap| {
        let record_cid = snap.compute_record_cid().ok();
        let is_head = active_head.as_ref().map(|h| {
            h.snapshot_id == snap.snapshot_id || record_cid.as_ref().map(|rc| rc.as_slice() == h.snapshot_id.as_slice()).unwrap_or(false)
        }).unwrap_or(false);
        serde_json::json!({
            "snapshot_id_hex": hex::encode(&snap.snapshot_id),
            "parent_ids_hex": snap.parent_snapshot_ids.iter().map(hex::encode).collect::<Vec<_>>(),
            "manifest_cid_hex": hex::encode(&snap.encrypted_manifest_cid),
            "device_id_hex": hex::encode(&snap.device_id),
            "device_counter": snap.device_counter,
            "epoch": snap.epoch,
            "timestamp_utc": snap.advisory_timestamp_utc,
            "is_head": is_head,
        })
    }).collect();

    axum::Json(serde_json::json!(json_snaps))
}

pub(crate) async fn api_anchors_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => return axum::Json(serde_json::json!([])),
    };

    let anchors = store.list_checkpoint_evidence().unwrap_or_default();
    let json_anchors: Vec<_> = anchors
        .iter()
        .map(|ev| {
            serde_json::json!({
                "commitment_hex": hex::encode(&ev.commitment),
                "salt_hex": hex::encode(&ev.salt),
                "head_record_cid_hex": hex::encode(&ev.head_record_cid),
                "chain_id": ev.chain_id,
                "contract_address_hex": format!("0x{}", hex::encode(&ev.contract_address)),
                "tx_hash_hex": format!("0x{}", hex::encode(&ev.tx_hash)),
                "block_number": ev.block_number,
                "timestamp_utc": ev.timestamp_utc,
            })
        })
        .collect();

    axum::Json(serde_json::json!(json_anchors))
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateSnapshotRequest {
    message: Option<String>,
    anchor: Option<bool>,
}

pub(crate) async fn api_create_snapshot_handler(
    axum::Json(payload): axum::Json<CreateSnapshotRequest>,
) -> impl axum::response::IntoResponse {
    match cmd_push(
        payload.message,
        false,
        false,
        payload.anchor.unwrap_or(false),
        None,
        None,
        None,
        None,
    )
    .await
    {
        Ok(_) => {
            let store_res = get_vault_store();
            let snap_id = if let Ok(store) = store_res {
                if let Ok(Some(head)) = store.get_active_head() {
                    hex::encode(&head.snapshot_id)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            axum::Json(serde_json::json!({
                "status": "ok",
                "success": true,
                "snapshot_id_hex": snap_id,
                "message": "Snapshot successfully captured, encrypted, and replicated across operators"
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

pub(crate) async fn api_create_anchor_handler() -> impl axum::response::IntoResponse {
    match cmd_anchor(None, None, None, None, None, None, false, None).await {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "message": "Snapshot head commitment successfully prepared and recorded for Arbitrum One"
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

pub(crate) async fn api_audit_handler() -> impl axum::response::IntoResponse {
    match audit_current(None).await {
        Ok(report) => axum::Json(
            serde_json::json!({ "success": report.healthy, "report": report,
            "message": if report.healthy { "Complete recovery set verified on at least three operators" } else { "Recovery set degraded or incomplete; inspect audit report" } }),
        ),
        Err(e) => axum::Json(serde_json::json!({"success": false, "error": e.to_string()})),
    }
}

pub(crate) async fn api_guardians_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "initialized": false,
                "message": "Vault not initialized in current directory"
            }));
        }
    };

    let vault_id = store.get_vault_id().unwrap_or([0u8; 32]);
    let (signing_pk, encrypt_pk, locator) = match store.get_recovery_descriptors() {
        Ok(d) => d,
        Err(_) => return axum::Json(serde_json::json!({ "initialized": false })),
    };

    let operators = get_configured_operators();

    axum::Json(serde_json::json!({
        "initialized": true,
        "vault_id_hex": hex::encode(vault_id),
        "recovery_signing_pk_hex": hex::encode(signing_pk),
        "recovery_encrypt_pk_hex": hex::encode(encrypt_pk),
        "recovery_locator_hex": hex::encode(locator),
        "operator_endpoints": operators,
        "message": "No guardian ceremony status is stored in the dashboard. Use the local CLI and approved offline procedure for guardian recovery material.",
    }))
}

pub(crate) async fn api_relayer_checkpoints_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "status": "ok",
                "relayer_status": {
                    "operational": null,
                    "status": "not_configured",
                    "target_network": null,
                    "verification_status": "unavailable"
                },
                "checkpoints": [],
                "count": 0
            }))
        }
    };

    let anchors = store.list_checkpoint_evidence().unwrap_or_default();
    let json_anchors: Vec<_> = anchors
        .iter()
        .map(|ev| {
            let tx_hex = format!("0x{}", hex::encode(&ev.tx_hash));
            let is_empty_tx = ev.tx_hash == [0u8; 32];
            let arbiscan_url = if is_empty_tx {
                String::new()
            } else if ev.chain_id == 42161 {
                format!("https://arbiscan.io/tx/{}", tx_hex)
            } else if ev.chain_id == 421614 {
                format!("https://sepolia.arbiscan.io/tx/{}", tx_hex)
            } else {
                String::new()
            };

            let status_str = if is_empty_tx { "not_submitted" } else { "submitted" };
            let verification_status = if is_empty_tx {
                "not_submitted"
            } else {
                "receipt_unverified"
            };

            serde_json::json!({
                "commitment": hex::encode(&ev.commitment),
                "commitment_hex": hex::encode(&ev.commitment),
                "salt_hex": hex::encode(&ev.salt),
                "head_record_cid_hex": hex::encode(&ev.head_record_cid),
                "chain_id": ev.chain_id,
                "contract_address_hex": format!("0x{}", hex::encode(&ev.contract_address)),
                "tx_hash": if is_empty_tx { "".to_string() } else { tx_hex.clone() },
                "tx_hash_hex": tx_hex,
                "explorer_url": arbiscan_url.clone(),
                "arbiscan_url": arbiscan_url,
                "reported_block_number": if ev.block_number > 0 { Some(ev.block_number) } else { None },
                "timestamp_utc": ev.timestamp_utc,
                "is_relayed": !is_empty_tx,
                "confirmed": false,
                "inclusion_verified": false,
                "verification_status": verification_status,
                "status": status_str,
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "status": "ok",
        "relayer_status": {
            "operational": null,
            "status": "unverified",
            "target_network": "Arbitrum checkpoint metadata",
            "verification_status": "unavailable"
        },
        "checkpoints": json_anchors,
        "count": anchors.len()
    }))
}

pub(crate) async fn api_relayer_anchor_handler() -> impl axum::response::IntoResponse {
    match cmd_anchor(None, None, None, None, None, None, true, None).await {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "verification_status": "unverified",
            "message": "Checkpoint processing completed. The dashboard has not independently verified a sequencer receipt."
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

pub(crate) async fn api_fleet_handler() -> impl axum::response::IntoResponse {
    let fleet_db_path = PathBuf::from(".ciphervault").join("fleet.db");
    if !fleet_db_path.exists() {
        return axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "fleet_summary": {
                "total_tracked_vaults": null,
                "healthy_vaults": null,
                "degraded_vaults": null,
                "total_audits_recorded": null,
                "audits_completed": null,
                "online_operators": null,
                "active_operators": null,
                "total_operators": null,
                "avg_latency_ms": null,
            },
            "vaults": [],
            "operator_nodes": [],
            "audit_history": [],
            "message": "No maintenance history is available yet. Run an explicit local audit to create it.",
        }));
    }

    let db_res = MaintenanceDb::open(&fleet_db_path);
    let db = match db_res {
        Ok(d) => d,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to open fleet database: {}", e)
            }));
        }
    };

    // This read route intentionally does not register vaults, probe operators,
    // or write maintenance state. Collection happens during an explicit audit
    // or through the maintenance service, preventing page refreshes from
    // becoming a background mutation and probe loop.
    let summary = db.get_fleet_summary().ok();

    let vaults = db.list_vaults().unwrap_or_default();
    let nodes = db.list_operator_nodes().unwrap_or_default();
    let history = db.get_recent_audits(20).unwrap_or_default();

    let avg_latency = {
        let healthy_nodes: Vec<_> = nodes.iter().filter(|n| n.is_healthy).collect();
        if !healthy_nodes.is_empty() {
            Some(
                healthy_nodes.iter().map(|n| n.latency_ms).sum::<u64>()
                    / healthy_nodes.len() as u64,
            )
        } else {
            None
        }
    };

    let fleet_summary = serde_json::json!({
        "total_tracked_vaults": summary.as_ref().map(|s| s.total_tracked_vaults),
        "healthy_vaults": summary.as_ref().map(|s| s.healthy_vaults),
        "degraded_vaults": summary.as_ref().map(|s| s.degraded_vaults),
        "total_audits_recorded": summary.as_ref().map(|s| s.total_audits_recorded),
        "audits_completed": summary.as_ref().map(|s| s.total_audits_recorded),
        "online_operators": summary.as_ref().map(|s| s.online_operators),
        "active_operators": summary.as_ref().map(|s| s.online_operators),
        "total_operators": summary.as_ref().map(|s| s.total_operators),
        "avg_latency_ms": avg_latency,
    });

    let formatted_nodes: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let last_hb = if n.last_seen_utc > 0 {
                Utc.timestamp_opt(n.last_seen_utc as i64, 0)
                    .single()
                    .map(|dt| dt.format("%H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Recent".to_string())
            } else {
                "Not reported".to_string()
            };
            serde_json::json!({
                "operator_id": format!("Operator {}", i + 1),
                "endpoint": mask_operator_endpoint(&n.endpoint),
                "status": if n.is_healthy { "Online" } else { "Offline" },
                "is_healthy": n.is_healthy,
                "latency_ms": if n.is_healthy { Some(n.latency_ms) } else { None },
                "last_heartbeat": last_hb,
                "last_seen_utc": n.last_seen_utc,
            })
        })
        .collect();

    let formatted_vaults: Vec<_> = vaults
        .iter()
        .map(|v| {
            let reg_str = if v.registered_at_utc > 0 {
                Utc.timestamp_opt(v.registered_at_utc as i64, 0)
                    .single()
                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "Recent".to_string())
            } else {
                "Not reported".to_string()
            };
            serde_json::json!({
                "vault_id": v.locator_hex,
                "locator_hex": v.locator_hex,
                "label": v.label,
                "head_cid": null,
                "status": v.last_status,
                "replica_count": v.replica_count,
                "registered_at": reg_str,
                "storage_allowance_bytes": null,
            })
        })
        .collect();

    let formatted_audits: Vec<_> = history
        .iter()
        .map(|a| {
            let audit_time = Utc
                .timestamp_opt(a.timestamp_utc as i64, 0)
                .single()
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "Recent".to_string());
            serde_json::json!({
                "id": a.id,
                "vault_id": a.locator_hex,
                "status": if a.healthy { "Healthy" } else { "Degraded" },
                "healthy": a.healthy,
                "healthy_objects": a.total_objects.saturating_sub(a.degraded_objects),
                "degraded_objects": a.degraded_objects,
                "repaired_objects": null,
                "timestamp": audit_time,
                "duration_ms": null,
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "summary": summary,
        "fleet_summary": fleet_summary,
        "vaults": formatted_vaults,
        "operator_nodes": formatted_nodes,
        "audit_history": formatted_audits,
    }))
}

pub(crate) async fn api_fleet_audit_handler() -> impl axum::response::IntoResponse {
    let audit_res = audit_current(None).await;
    let fleet_db_path = PathBuf::from(".ciphervault").join("fleet.db");
    let db = MaintenanceDb::open(&fleet_db_path).ok();

    match audit_res {
        Ok(report) => {
            if let Some(ref db) = db {
                let locator_hex = if let Ok(store) = get_vault_store() {
                    if let Ok((_, _, loc)) = store.get_recovery_descriptors() {
                        hex::encode(loc)
                    } else {
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string()
                    }
                } else {
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
                };

                let details = serde_json::to_string(&report).unwrap_or_default();
                let _ = db.register_vault(&locator_hex, Some("Active Project Vault"));
                let _ = db.record_audit(
                    &locator_hex,
                    report.healthy,
                    report.objects.total_objects,
                    report.objects.degraded_objects.len(),
                    &details,
                );
            }

            axum::Json(serde_json::json!({
                "success": report.healthy,
                "healthy": report.healthy,
                "report": report,
                "message": if report.healthy { "Fleet audit completed: All objects verified across operators" } else { "Fleet audit completed: Degraded replicas detected" }
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

pub(crate) async fn api_token_handler() -> impl axum::response::IntoResponse {
    let readers = ciphervault_crypto::list_pcsc_readers().unwrap_or_default();
    let probe_res = ciphervault_crypto::PcscHardwareToken::probe()
        .ok()
        .flatten();

    let token_info = probe_res.map(|token| {
        let info_9c = token
            .get_slot_info(ciphervault_crypto::HsmSlot::DigitalSignature)
            .ok();
        let info_9d = token
            .get_slot_info(ciphervault_crypto::HsmSlot::KeyManagement)
            .ok();
        serde_json::json!({
            "reader": token.reader_name(),
            "slot_9c": info_9c,
            "slot_9d": info_9d,
            "ready": true,
        })
    });

    axum::Json(serde_json::json!({
        "pcsc_available": true,
        "readers": readers,
        "hardware_token": token_info,
    }))
}

pub(crate) async fn api_stream_handler(
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = stream::unfold((), |_| async {
        let operators = get_configured_operators();
        let http = public_operator_http_client();
        let probes = operators.into_iter().map(|endpoint| {
            let http = http.clone();
            async move {
                let client = OperatorClient::with_http_client(endpoint.clone(), http);
                let start = std::time::Instant::now();
                let (online, latency_ms) = match client.get_info().await {
                    Ok(_) => (true, start.elapsed().as_millis() as u64),
                    Err(_) => (false, 999),
                };
                serde_json::json!({
                    "endpoint": endpoint,
                    "online": online,
                    "latency_ms": latency_ms,
                })
            }
        });
        let op_latencies = join_all(probes).await;

        let token_attached = ciphervault_crypto::PcscHardwareToken::probe()
            .ok()
            .flatten()
            .is_some();
        let timestamp = Utc::now().to_rfc3339();

        let data = serde_json::json!({
            "timestamp": timestamp,
            "operators": op_latencies,
            "token_attached": token_attached,
        });

        let event = Event::default().event("telemetry").data(data.to_string());
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Some((Ok(event), ()))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
