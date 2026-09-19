//! Diff, file tracking, restore, manifest, activity, and workspace endpoints.

use std::path::PathBuf;

use ciphervault_format::{from_canonical_cbor, SnapshotManifest};
use ciphervault_local_store::LocalVaultStore;

use crate::{
    cmd_restore, cmd_track, cmd_untrack, discover_workspace_vaults, generate_diff_report,
    get_active_vault_path, get_vault_store, set_active_vault_path, DB_FILE, VAULT_DIR,
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
) -> impl axum::response::IntoResponse {
    let reveal = params.reveal.unwrap_or(false);
    match generate_diff_report(params.snapshot_a, params.snapshot_b, params.file, reveal) {
        Ok(report) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "report": report
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
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
    if !p.exists() {
        return axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": format!("File '{}' does not exist on disk", p.display())
        }));
    }
    match cmd_track(vec![p.clone()], false, false) {
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
    ) {
        Ok(_) => {
            if let Ok(store) = get_vault_store() {
                let _ = store.record_activity(
                    "SNAPSHOT_RESTORE",
                    &format!("Restored snapshot into '{}'", to_path),
                    "{}",
                );
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

    match LocalVaultStore::open(&target_db) {
        Ok(_) => {
            set_active_vault_path(Some(target_db.clone()));
            axum::Json(serde_json::json!({
                "status": "ok",
                "message": format!("Switched active workspace to {}", target_db.display()),
                "active_workspace_db": target_db.display().to_string()
            }))
        }
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
