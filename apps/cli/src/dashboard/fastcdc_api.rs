//! FastCDC inspection endpoints for the private dashboard.

use std::fs;
use std::path::{Path, PathBuf};

use ciphervault_snapshot::{fastcdc_chunk, FastCdcConfig};

use crate::get_vault_store;

#[derive(serde::Deserialize)]
pub(crate) struct FastCdcInspectRequest {
    content: Option<String>,
    file_path: Option<String>,
    min_size: Option<usize>,
    avg_size: Option<usize>,
    max_size: Option<usize>,
}

pub(crate) const FASTCDC_MAX_INSPECTION_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const FASTCDC_MAX_RESULT_CHUNKS: usize = 512;
pub(crate) const FASTCDC_MAX_CHUNK_SIZE: usize = 1024 * 1024;

pub(crate) fn fastcdc_workspace_root() -> std::result::Result<PathBuf, String> {
    std::env::current_dir()
        .map_err(|_| "Unable to determine the local workspace root.".to_string())?
        .canonicalize()
        .map_err(|_| "Unable to resolve the local workspace root.".to_string())
}

pub(crate) fn canonical_tracked_inspection_file(
    workspace_root: &Path,
    tracked_path: &Path,
) -> std::result::Result<PathBuf, String> {
    let candidate = if tracked_path.is_absolute() {
        tracked_path.to_path_buf()
    } else {
        workspace_root.join(tracked_path)
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|_| "The selected tracked file is unavailable.".to_string())?;

    if !canonical.starts_with(workspace_root) {
        return Err("The selected tracked file is outside the local workspace.".to_string());
    }

    let metadata = fs::metadata(&canonical)
        .map_err(|_| "The selected tracked file is unavailable.".to_string())?;
    if !metadata.is_file() {
        return Err("The selected tracked path is not a regular file.".to_string());
    }

    Ok(canonical)
}

pub(crate) fn resolve_tracked_inspection_file(
    requested_path: &str,
) -> std::result::Result<PathBuf, String> {
    let normalized_request = requested_path.trim().replace('\\', "/");
    if normalized_request.is_empty() {
        return Err("Select a tracked vault file before inspecting it.".to_string());
    }

    let store = get_vault_store()
        .map_err(|_| "No initialized local vault is available for file inspection.".to_string())?;
    let tracked = store
        .list_tracked_files()
        .map_err(|_| "Unable to read the tracked-file registry.".to_string())?;
    let selected = tracked
        .iter()
        .find(|(path, _)| path.to_string_lossy().replace('\\', "/") == normalized_request)
        .map(|(path, _)| path)
        .ok_or_else(|| {
            "Select an exact tracked vault file from the local workspace.".to_string()
        })?;

    let workspace_root = fastcdc_workspace_root()?;
    canonical_tracked_inspection_file(&workspace_root, selected)
}

pub(crate) fn fastcdc_config_from_request(
    payload: &FastCdcInspectRequest,
) -> std::result::Result<FastCdcConfig, String> {
    match (payload.min_size, payload.avg_size, payload.max_size) {
        (None, None, None) => Ok(FastCdcConfig::default()),
        (Some(min), Some(avg), Some(max))
            if min >= 64 && min <= avg && avg <= max && max <= FASTCDC_MAX_CHUNK_SIZE =>
        {
            Ok(FastCdcConfig::new(min, avg, max))
        }
        _ => Err(format!(
            "Chunk sizes must satisfy 64 <= min <= average <= max <= {} bytes.",
            FASTCDC_MAX_CHUNK_SIZE
        )),
    }
}

pub(crate) fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub(crate) fn compute_gear_fingerprint(chunk: &[u8]) -> u64 {
    use ciphervault_snapshot::fastcdc::GEAR_MATRIX;
    let mut hash = 0u64;
    let tail = if chunk.len() > 64 {
        &chunk[chunk.len() - 64..]
    } else {
        chunk
    };
    for &b in tail {
        hash = (hash << 1).wrapping_add(GEAR_MATRIX[b as usize]);
    }
    hash
}

pub(crate) async fn api_fastcdc_vault_files_handler() -> impl axum::response::IntoResponse {
    let workspace_root = fastcdc_workspace_root().ok();
    let files = match get_vault_store() {
        Ok(store) => match store.list_tracked_files() {
            Ok(list) => list
                .into_iter()
                .filter_map(|(path, file_id)| {
                    let root = workspace_root.as_ref()?;
                    let canonical = canonical_tracked_inspection_file(root, &path).ok()?;
                    let size = fs::metadata(&canonical).ok()?.len();
                    Some(serde_json::json!({
                        "path": path.to_string_lossy().replace('\\', "/"),
                        "exists": true,
                        "size_bytes": size,
                        "file_id": hex::encode(&file_id[0..4]),
                    }))
                })
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };

    axum::Json(serde_json::json!({
        "success": true,
        "files": files,
    }))
}

pub(crate) async fn api_fastcdc_inspect_handler(
    axum::Json(payload): axum::Json<FastCdcInspectRequest>,
) -> impl axum::response::IntoResponse {
    let config = match fastcdc_config_from_request(&payload) {
        Ok(config) => config,
        Err(error) => {
            return axum::Json(serde_json::json!({
                "success": false,
                "error": error,
            }));
        }
    };

    if payload.file_path.is_some() && payload.content.is_some() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "Provide either direct text or one tracked vault file, not both.",
        }));
    }

    let (raw_data, source_label) = if let Some(ref requested_path) = payload.file_path {
        let target = match resolve_tracked_inspection_file(requested_path) {
            Ok(target) => target,
            Err(error) => {
                return axum::Json(serde_json::json!({
                    "success": false,
                    "error": error,
                }));
            }
        };
        match fs::read(&target) {
            Ok(bytes) => (bytes, "Selected tracked vault file".to_string()),
            Err(_) => {
                return axum::Json(serde_json::json!({
                    "success": false,
                    "error": "The selected tracked file is unavailable.",
                }));
            }
        }
    } else if let Some(ref txt) = payload.content {
        if !txt.trim().is_empty() {
            (txt.as_bytes().to_vec(), "Direct text input".to_string())
        } else {
            return axum::Json(serde_json::json!({
                "success": false,
                "error": "Provided text input is empty. Enter text or select a tracked vault file."
            }));
        }
    } else {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "Enter text or explicitly select a tracked vault file before inspecting chunks.",
        }));
    };

    let max_input_bytes =
        FASTCDC_MAX_INSPECTION_BYTES.min(config.min_size.saturating_mul(FASTCDC_MAX_RESULT_CHUNKS));
    if raw_data.len() > max_input_bytes {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!(
                "Inspection input exceeds the {} byte limit for this chunk-size configuration.",
                max_input_bytes
            ),
        }));
    }

    let chunks = fastcdc_chunk(&raw_data, &config);
    if chunks.len() > FASTCDC_MAX_RESULT_CHUNKS {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!(
                "Inspection would return more than {} chunk records. Increase the minimum chunk size or reduce the input.",
                FASTCDC_MAX_RESULT_CHUNKS
            ),
        }));
    }

    let mut offset = 0usize;
    let mut chunk_records = Vec::new();
    let mut unique_cids = std::collections::HashSet::new();
    let mut unique_bytes = 0usize;

    for (i, chunk_slice) in chunks.iter().enumerate() {
        let cid_bytes = ciphervault_format::compute_digest(chunk_slice);
        let cid_hex = hex::encode(cid_bytes);
        let entropy = compute_shannon_entropy(chunk_slice);
        let gear = compute_gear_fingerprint(chunk_slice);
        let is_dup = !unique_cids.insert(cid_bytes);
        if !is_dup {
            unique_bytes += chunk_slice.len();
        }

        chunk_records.push(serde_json::json!({
            "index": i,
            "offset": offset,
            "length": chunk_slice.len(),
            "cid_hex": cid_hex,
            "gear_fingerprint": format!("0x{:016x}", gear),
            "entropy": (entropy * 1000.0).round() / 1000.0,
            "is_duplicate": is_dup,
            "preview": "Content previews are disabled.",
        }));

        offset += chunk_slice.len();
    }

    let total_chunks = chunks.len();
    let unique_count = unique_cids.len();
    let duplicate_count = total_chunks.saturating_sub(unique_count);
    let total_bytes = raw_data.len();
    let saved_bytes = total_bytes.saturating_sub(unique_bytes);
    let dedup_savings_pct = if total_bytes > 0 {
        (saved_bytes as f64 / total_bytes as f64) * 100.0
    } else {
        0.0
    };

    let fixed_size = config.avg_size.max(1);
    let fixed_chunks_count = total_bytes.div_ceil(fixed_size);

    axum::Json(serde_json::json!({
        "success": true,
        "source": source_label,
        "config": {
            "min_size": config.min_size,
            "avg_size": config.avg_size,
            "max_size": config.max_size,
        },
        "metrics": {
            "total_bytes": total_bytes,
            "total_chunks": total_chunks,
            "unique_chunks": unique_count,
            "duplicate_chunks": duplicate_count,
            "unique_bytes": unique_bytes,
            "saved_bytes": saved_bytes,
            "dedup_savings_pct": (dedup_savings_pct * 100.0).round() / 100.0,
            "fixed_chunks_count": fixed_chunks_count,
            "boundary_shift_resilient": true,
        },
        "chunks": chunk_records,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fastcdc_rejects_oversized_or_invalid_chunk_configuration() {
        let invalid = FastCdcInspectRequest {
            content: Some("sample".to_string()),
            file_path: None,
            min_size: Some(4_096),
            avg_size: Some(2_048),
            max_size: Some(65_536),
        };
        assert!(fastcdc_config_from_request(&invalid).is_err());

        let oversized = FastCdcInspectRequest {
            content: Some("sample".to_string()),
            file_path: None,
            min_size: Some(4_096),
            avg_size: Some(16_384),
            max_size: Some(FASTCDC_MAX_CHUNK_SIZE + 1),
        };
        assert!(fastcdc_config_from_request(&oversized).is_err());
    }

    #[test]
    fn fastcdc_rejects_files_outside_the_workspace() {
        let base = std::env::temp_dir().join(format!(
            "ciphervault-fastcdc-boundary-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let workspace = base.join("workspace");
        let outside = base.join("outside.txt");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(&outside, "private").unwrap();

        let workspace_root = workspace.canonicalize().unwrap();
        assert!(canonical_tracked_inspection_file(&workspace_root, &outside).is_err());

        let _ = std::fs::remove_dir_all(base);
    }
}
