//! Diff, file tracking, restore, manifest, activity, and workspace endpoints.

use std::path::PathBuf;

use ciphervault_format::{from_canonical_cbor, SnapshotManifest};
use ciphervault_local_store::LocalVaultStore;

use crate::{
    cmd_restore, cmd_track, cmd_untrack, discover_workspace_vaults, generate_diff_report,
    get_active_vault_path, get_vault_store, DB_FILE, VAULT_DIR,
};

#[derive(serde::Deserialize)]
pub(crate) struct DiffQueryParams {
    snapshot_a: Option<String>,
    snapshot_b: Option<String>,
    file: Option<String>,
    reveal: Option<bool>,
}

pub(crate) async fn api_diff_handler(
    axum::extract::Query(params): axum::extract::Query<DiffQueryParams>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let reveal = params.reveal.unwrap_or(false);
    if reveal && std::env::var("CIPHERVAULT_UI_ALLOW_REVEAL").as_deref() != Ok("1") {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "status": "error",
                "success": false,
                "code": "REVEAL_DISABLED_OVER_HTTP",
                "error": "Plaintext diff reveal is disabled over the HTTP API. Run `ciphervault diff --reveal` in an interactive terminal or set CIPHERVAULT_UI_ALLOW_REVEAL=1."
            })),
        )
            .into_response();
    }

    match generate_diff_report(params.snapshot_a, params.snapshot_b, params.file, reveal) {
        Ok(report) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "report": report
        }))
        .into_response(),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        }))
        .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct FileActionPayload {
    path: String,
}

pub(crate) async fn api_files_track_handler(
    axum::Json(payload): axum::Json<FileActionPayload>,
) -> impl axum::response::IntoResponse {
    let p = PathBuf::from(payload.path.trim());
    if !crate::util::get_workspace_root().is_ok_and(|root| root.join(&p).exists()) {
        return axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": format!("File '{}' does not exist on disk", p.display())
        }));
    }
    match cmd_track(vec![p.clone()], false, false, false) {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "message": format!("Tracked file '{}' successfully and appended to .gitignore", p.display())
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

pub(crate) async fn api_files_untrack_handler(
    axum::Json(payload): axum::Json<FileActionPayload>,
) -> impl axum::response::IntoResponse {
    let p = PathBuf::from(payload.path.trim());
    match cmd_untrack(vec![p.clone()]) {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "message": format!("Untracked file '{}' successfully", p.display())
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct RestoreSnapshotPayload {
    snapshot_id: Option<String>,
    to: Option<String>,
    hardware_token: Option<bool>,
    reader: Option<String>,
    pin: Option<String>,
}

pub(crate) async fn api_snapshots_restore_handler(
    axum::Json(payload): axum::Json<RestoreSnapshotPayload>,
) -> impl axum::response::IntoResponse {
    let to_path = payload.to.clone().unwrap_or_else(|| ".".to_string());
    match cmd_restore(
        payload.snapshot_id,
        payload.to.map(PathBuf::from),
        payload.hardware_token.unwrap_or(false),
        payload.reader,
        payload.pin,
        false,
        false,
    ) {
        Ok(_) => {
            if let Ok(store) = get_vault_store() {
                let _ = store.record_activity(
                    "SNAPSHOT_RESTORE",
                    &format!("Restored snapshot into '{}'", to_path),
                    "{}",
                );
                let _ = store.append_agent_audit("dashboard_ui", "restore", &to_path, "{}");
            }
            axum::Json(serde_json::json!({
                "status": "ok",
                "success": true,
                "message": format!("Snapshot restored successfully to '{}'", to_path)
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

pub(crate) async fn api_snapshot_manifest_handler(
    axum::extract::Path(snap_id_hex): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    let clean_hex = snap_id_hex.trim().trim_start_matches("0x");
    let snap_id_bytes = match hex::decode(clean_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return axum::Json(serde_json::json!({
                "status": "error",
                "success": false,
                "error": "Invalid snapshot ID hex (must be 32 bytes / 64 characters)"
            }));
        }
    };

    let store = match get_vault_store() {
        Ok(s) => s,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "status": "error",
                "success": false,
                "error": format!("Vault store error: {}", e)
            }));
        }
    };

    let vault_id = match store.get_vault_id() {
        Ok(v) => v,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": e.to_string() }),
            );
        }
    };

    let (record, encrypted_manifest) = match store.get_snapshot(&snap_id_bytes) {
        Ok(res) => res,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": format!("Snapshot not found: {}", e) }),
            );
        }
    };

    let epoch_key = match store.get_epoch_key(record.epoch) {
        Ok(k) => k,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": format!("Failed to retrieve epoch key: {}", e) }),
            );
        }
    };

    let manifest_key = match epoch_key.derive_manifest_key(record.epoch) {
        Ok(k) => k,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": e.to_string() }),
            );
        }
    };

    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();

    let manifest_bytes = match ciphervault_crypto::decrypt_chunk(
        &manifest_key,
        &encrypted_manifest,
        &aad,
    ) {
        Ok(b) => b,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": format!("Failed to decrypt manifest: {}", e) }),
            );
        }
    };

    let manifest: SnapshotManifest = match from_canonical_cbor(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": format!("Invalid CBOR manifest: {}", e) }),
            );
        }
    };

    let file_items: Vec<_> = manifest
        .files
        .iter()
        .map(|f| {
            let chunk_cids_hex: Vec<String> = f.chunk_cids.iter().map(hex::encode).collect();
            serde_json::json!({
                "path": f.relative_path,
                "size_bytes": f.raw_length,
                "file_id_hex": hex::encode(&f.file_id),
                "chunk_count": f.chunk_cids.len(),
                "chunk_cids": chunk_cids_hex,
                "is_deleted": f.is_deleted,
            })
        })
        .collect();

    let total_bytes: u64 = manifest
        .files
        .iter()
        .filter(|f| !f.is_deleted)
        .map(|f| f.raw_length)
        .sum();

    axum::Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "snapshot_id_hex": clean_hex,
        "epoch": record.epoch,
        "device_counter": record.device_counter,
        "signature_verified": super::handlers::local_snapshot_signature_verified(&store, &record),
        "timestamp_utc": record.advisory_timestamp_utc,
        "files_count": file_items.len(),
        "total_bytes": total_bytes,
        "files": file_items
    }))
}

pub(crate) async fn api_activity_handler() -> impl axum::response::IntoResponse {
    let store = match get_vault_store() {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "status": "ok",
                "events": []
            }));
        }
    };

    let events = store.list_activity(50).unwrap_or_default();
    axum::Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "events": events
    }))
}

pub(crate) async fn api_workspaces_handler() -> impl axum::response::IntoResponse {
    let vaults = discover_workspace_vaults();
    let active_path = get_active_vault_path().display().to_string();
    axum::Json(serde_json::json!({
        "status": "ok",
        "active_workspace_db": active_path,
        "count": vaults.len(),
        "workspaces": vaults
    }))
}

#[derive(serde::Deserialize)]
pub(crate) struct SwitchWorkspaceRequest {
    db_path: Option<String>,
    workspace_path: Option<String>,
}

pub(crate) async fn api_workspaces_switch_handler(
    axum::Json(payload): axum::Json<SwitchWorkspaceRequest>,
) -> impl axum::response::IntoResponse {
    let target_db = if let Some(db) = payload.db_path {
        PathBuf::from(db)
    } else if let Some(ws) = payload.workspace_path {
        PathBuf::from(ws).join(VAULT_DIR).join(DB_FILE)
    } else {
        return axum::Json(serde_json::json!({
            "status": "error",
            "error": "Must provide either 'db_path' or 'workspace_path'"
        }));
    };

    if !target_db.exists() {
        return axum::Json(serde_json::json!({
            "status": "error",
            "error": format!("Vault database does not exist at '{}'", target_db.display())
        }));
    }

    let context = match crate::util::VaultContext::from_db_path(&target_db) {
        Ok(context) => context,
        Err(error) => {
            return axum::Json(serde_json::json!({ "status": "error", "error": error.to_string() }))
        }
    };
    let allowed = crate::util::REQUEST_VAULT_CONTEXT
        .scope(context.clone(), async {
            super::session::private_account_session_valid()
        })
        .await;
    if !allowed {
        return axum::Json(
            serde_json::json!({ "status": "error", "error": "Sign in with an active device for the selected workspace." }),
        );
    }
    match LocalVaultStore::open(&context.db_path) {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "message": format!("Selected workspace {}", context.root_dir.display()),
            "active_workspace_db": context.db_path.display().to_string(),
            "workspace_root": context.root_dir.display().to_string()
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "error": format!("Failed to open vault store: {}", e)
        })),
    }
}

pub(crate) async fn api_workspaces_scan_handler() -> impl axum::response::IntoResponse {
    let vaults = discover_workspace_vaults();
    axum::Json(serde_json::json!({
        "status": "ok",
        "message": format!("Discovered {} vault workspace(s)", vaults.len()),
        "count": vaults.len(),
        "workspaces": vaults
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    struct AllowRevealGuard {
        prior: Option<std::ffi::OsString>,
    }

    impl AllowRevealGuard {
        fn set(val: Option<&str>) -> Self {
            let prior = std::env::var_os("CIPHERVAULT_UI_ALLOW_REVEAL");
            match val {
                Some(v) => std::env::set_var("CIPHERVAULT_UI_ALLOW_REVEAL", v),
                None => std::env::remove_var("CIPHERVAULT_UI_ALLOW_REVEAL"),
            }
            Self { prior }
        }
    }

    impl Drop for AllowRevealGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var("CIPHERVAULT_UI_ALLOW_REVEAL", v),
                None => std::env::remove_var("CIPHERVAULT_UI_ALLOW_REVEAL"),
            }
        }
    }

    fn init_certified_workspace(base: &std::path::Path, name: &str) -> crate::util::VaultContext {
        use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
        use ciphervault_format::{DeviceCertificate, GenesisRecord, PROTOCOL_VERSION};

        let root = base.join(name);
        std::fs::create_dir_all(root.join(VAULT_DIR)).unwrap();
        let recovery = RecoverySecret::generate();
        let recovery_sk = recovery.derive_recovery_signing_key().unwrap();
        let (_, encryption) = recovery.derive_recovery_encryption_keys().unwrap();
        let vault_id = [0x42u8; 32];
        let device_id = [0x24u8; 32];
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            recovery_signing_pk: recovery_sk.verifying_key().to_bytes().to_vec(),
            recovery_encryption_pk: encryption.as_bytes().to_vec(),
            policy_digest: vec![0; 32],
            created_at_utc: 1,
            creation_nonce: vec![0x42u8; 32],
            signature: vec![],
        };
        genesis.sign(&recovery_sk).unwrap();
        let device_sk = generate_signing_key();
        let db_path = root.join(VAULT_DIR).join(DB_FILE);
        let store = LocalVaultStore::open(&db_path).unwrap();
        store
            .init_vault(
                &vault_id,
                &genesis,
                &device_sk,
                &device_id,
                &VaultEpochKey::generate(),
                &recovery.derive_recovery_locator().unwrap(),
            )
            .unwrap();
        let mut cert = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            certificate_id: vec![0x11u8; 32],
            device_signing_pk: device_sk.verifying_key().to_bytes().to_vec(),
            permissions: 0xFFFF_FFFF,
            authority_generation: 1,
            issued_at_utc: 1,
            signature: Vec::new(),
        };
        cert.sign(&recovery_sk).unwrap();
        store.save_device_certificate(&cert).unwrap();
        drop(store);
        crate::util::VaultContext::from_db_path(db_path).unwrap()
    }

    async fn json_body(
        response: axum::response::Response,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn api_diff_refuses_reveal_unless_explicitly_enabled() {
        let _serialized = crate::util::TEST_PROCESS_STATE.lock().await;
        let base =
            std::env::temp_dir().join(format!("cv-files-api-diff-{}", rand::random::<u64>()));
        let ws = init_certified_workspace(&base, "ws");
        std::fs::write(
            ws.root_dir.join(".env"),
            "API_KEY=initial_secret_value_abc\n",
        )
        .unwrap();

        crate::util::REQUEST_VAULT_CONTEXT
            .scope(ws.clone(), async {
                cmd_track(vec![PathBuf::from(".env")], false, false, false).unwrap();
                crate::cmd_push(
                    Some("init".to_string()),
                    false,
                    true,
                    false,
                    None,
                    None,
                    None,
                    None,
                    false,
                )
                .await
                .unwrap();
                std::fs::write(
                    ws.root_dir.join(".env"),
                    "API_KEY=rotated_secret_value_xyz\n",
                )
                .unwrap();

                // Default (unset): reveal=true must be refused.
                {
                    let _guard = AllowRevealGuard::set(None);
                    let resp = api_diff_handler(axum::extract::Query(DiffQueryParams {
                        snapshot_a: None,
                        snapshot_b: None,
                        file: None,
                        reveal: Some(true),
                    }))
                    .await;
                    let (status, body) = json_body(resp).await;
                    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
                    assert_eq!(body["success"], false);
                    assert_eq!(body["code"], "REVEAL_DISABLED_OVER_HTTP");
                    let serialized = body.to_string();
                    assert!(!serialized.contains("initial_secret_value_abc"));
                    assert!(!serialized.contains("rotated_secret_value_xyz"));
                }

                // Default (unset) with reveal=false/None: masked diff succeeds.
                {
                    let _guard = AllowRevealGuard::set(None);
                    let resp = api_diff_handler(axum::extract::Query(DiffQueryParams {
                        snapshot_a: None,
                        snapshot_b: None,
                        file: None,
                        reveal: Some(false),
                    }))
                    .await;
                    let (status, body) = json_body(resp).await;
                    assert_eq!(status, axum::http::StatusCode::OK);
                    assert_eq!(body["success"], true);
                    let serialized = body.to_string();
                    assert!(!serialized.contains("initial_secret_value_abc"));
                    assert!(!serialized.contains("rotated_secret_value_xyz"));
                }

                // Opt-in CIPHERVAULT_UI_ALLOW_REVEAL=1 allows plaintext reveal.
                {
                    let _guard = AllowRevealGuard::set(Some("1"));
                    let resp = api_diff_handler(axum::extract::Query(DiffQueryParams {
                        snapshot_a: None,
                        snapshot_b: None,
                        file: None,
                        reveal: Some(true),
                    }))
                    .await;
                    let (status, body) = json_body(resp).await;
                    assert_eq!(status, axum::http::StatusCode::OK);
                    assert_eq!(body["success"], true);
                    let serialized = body.to_string();
                    assert!(serialized.contains("initial_secret_value_abc"));
                    assert!(serialized.contains("rotated_secret_value_xyz"));
                }
            })
            .await;

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn api_snapshots_restore_records_agent_audit_entry() {
        let _serialized = crate::util::TEST_PROCESS_STATE.lock().await;
        let base =
            std::env::temp_dir().join(format!("cv-files-api-restore-{}", rand::random::<u64>()));
        let ws = init_certified_workspace(&base, "ws");
        let restore_dir = base.join("restored_out");
        let restore_str = restore_dir.display().to_string();
        std::fs::write(ws.root_dir.join(".env"), "RESTORE_KEY=secret_restore_123\n").unwrap();

        crate::util::REQUEST_VAULT_CONTEXT
            .scope(ws.clone(), async {
                cmd_track(vec![PathBuf::from(".env")], false, false, false).unwrap();
                crate::cmd_push(
                    Some("snap".to_string()),
                    false,
                    true,
                    false,
                    None,
                    None,
                    None,
                    None,
                    false,
                )
                .await
                .unwrap();

                let resp = api_snapshots_restore_handler(axum::Json(RestoreSnapshotPayload {
                    snapshot_id: None,
                    to: Some(restore_str.clone()),
                    hardware_token: None,
                    reader: None,
                    pin: None,
                }))
                .await
                .into_response();
                let (status, body) = json_body(resp).await;
                assert_eq!(status, axum::http::StatusCode::OK);
                assert_eq!(body["success"], true);
            })
            .await;

        let store = LocalVaultStore::open(&ws.db_path).unwrap();
        let activity = store.list_activity(10).unwrap();
        assert!(activity.iter().any(|a| a.event_type == "SNAPSHOT_RESTORE"));

        let audits = store.list_agent_audit(10).unwrap();
        assert!(audits.iter().any(|e| {
            e.tool == "dashboard_ui"
                && e.decision == "restore"
                && e.path == restore_str
                && e.detail_json == "{}"
        }));

        let _ = std::fs::remove_dir_all(&base);
    }
}
