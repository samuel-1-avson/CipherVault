//! Explorer, checkpoint feed verification, finality, and public data handlers.

use anyhow::Result;
use chrono::Utc;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::{
    future::join_all,
    stream::{self, Stream},
};

use ciphervault_storage::OperatorClient;

use crate::{
    get_configured_operators, public_operator_telemetry, PublicCheckpointFeedEnvelope,
    PublicCheckpointFeedUnsigned, PUBLIC_OPERATOR_CACHE_TTL,
};

// ---- Explorer (blockchain-style read-only browsing) ----

/// Anonymous read bearer for presence probes. CIDs are unguessable
/// capabilities, so a PoS challenge reveals only presence to someone who
/// already knows the CID; object bytes are never fetched or displayed.
pub(crate) const EXPLORER_ANON_TOKEN: &str = "recovery_anonymous";
pub(crate) const EXPLORER_PROBE_TIMEOUT_SECS: u64 = 8;
/// Explorer object-probe cache TTL: presence results are safe to reuse
/// briefly, and every uncached lookup fans out to ALL operators — without
/// a cache a single client could loop CIDs and turn the explorer into an
/// amplifier against the operator fleet.
const EXPLORER_PROBE_CACHE_TTL: Duration = Duration::from_secs(60);
const EXPLORER_PROBE_CACHE_MAX: usize = 512;
/// Bound on concurrent outbound PoS probes across all object lookups.
const EXPLORER_PROBE_MAX_CONCURRENT: usize = 16;

struct ExplorerProbeCache {
    entries: std::collections::HashMap<[u8; 32], (Instant, Vec<serde_json::Value>)>,
}

impl ExplorerProbeCache {
    fn get(&self, cid: &[u8; 32]) -> Option<Vec<serde_json::Value>> {
        self.entries
            .get(cid)
            .filter(|(probed_at, _)| probed_at.elapsed() < EXPLORER_PROBE_CACHE_TTL)
            .map(|(_, replicas)| replicas.clone())
    }

    fn insert(&mut self, cid: [u8; 32], replicas: Vec<serde_json::Value>) {
        self.entries
            .retain(|_, (probed_at, _)| probed_at.elapsed() < EXPLORER_PROBE_CACHE_TTL);
        if self.entries.len() >= EXPLORER_PROBE_CACHE_MAX {
            // Full of fresh entries (hostile CID enumeration): drop
            // everything rather than growing without bound.
            self.entries.clear();
        }
        self.entries.insert(cid, (Instant::now(), replicas));
    }

    #[cfg(test)]
    fn insert_at(&mut self, cid: [u8; 32], replicas: Vec<serde_json::Value>, probed_at: Instant) {
        self.entries.insert(cid, (probed_at, replicas));
    }
}

fn explorer_probe_cache() -> &'static tokio::sync::Mutex<ExplorerProbeCache> {
    static CACHE: OnceLock<tokio::sync::Mutex<ExplorerProbeCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        tokio::sync::Mutex::new(ExplorerProbeCache {
            entries: std::collections::HashMap::new(),
        })
    })
}

fn explorer_probe_permits() -> &'static tokio::sync::Semaphore {
    static PERMITS: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    PERMITS.get_or_init(|| tokio::sync::Semaphore::new(EXPLORER_PROBE_MAX_CONCURRENT))
}

pub(crate) async fn explorer_probe_cache_stats() -> (usize, usize) {
    let cache_len = explorer_probe_cache().lock().await.entries.len();
    let available = explorer_probe_permits().available_permits();
    let in_flight = EXPLORER_PROBE_MAX_CONCURRENT.saturating_sub(available);
    (cache_len, in_flight)
}

async fn probe_explorer_object_cached(
    cid: [u8; 32],
    endpoints: Vec<String>,
) -> Vec<serde_json::Value> {
    {
        let cache = explorer_probe_cache().lock().await;
        if let Some(replicas) = cache.get(&cid) {
            return replicas;
        }
    }
    // Permits serialize the fan-out across simultaneous lookups instead of
    // multiplying it: at most EXPLORER_PROBE_MAX_CONCURRENT outbound PoS
    // probes are ever in flight, however many clients ask at once.
    let probes = endpoints.into_iter().map(|endpoint| async move {
        let _permit = explorer_probe_permits().acquire().await;
        probe_explorer_replica(endpoint, cid).await
    });
    let replicas = join_all(probes).await;
    explorer_probe_cache()
        .lock()
        .await
        .insert(cid, replicas.clone());
    replicas
}

pub(crate) fn explorer_error_response(
    status: axum::http::StatusCode,
    code: &str,
    message: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        status,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": code,
            "error": message,
        })),
    )
        .into_response()
}

pub(crate) fn parse_explorer_cid(raw: &str) -> Option<([u8; 32], String)> {
    let normalized = raw.trim().to_lowercase();
    let bytes = hex::decode(&normalized).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut cid = [0u8; 32];
    cid.copy_from_slice(&bytes);
    Some((cid, normalized))
}

pub(crate) async fn probe_explorer_replica(endpoint: String, cid: [u8; 32]) -> serde_json::Value {
    let started = std::time::Instant::now();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let client = OperatorClient::new(endpoint.clone());
    let outcome = tokio::time::timeout(
        Duration::from_secs(EXPLORER_PROBE_TIMEOUT_SECS),
        client.challenge_object_pos(EXPLORER_ANON_TOKEN, &cid, &nonce),
    )
    .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(Ok(receipt)) if receipt.cid_hex == hex::encode(cid) => serde_json::json!({
            "endpoint": endpoint,
            "status": "present",
            "operator_id": receipt.operator_id,
            "size_bytes": receipt.size_bytes,
            "latency_ms": latency_ms,
        }),
        Ok(Ok(_)) => serde_json::json!({
            "endpoint": endpoint,
            "status": "unknown",
            "latency_ms": latency_ms,
            "error": "PoS receipt CID mismatch",
        }),
        Ok(Err(ciphervault_storage::StorageError::ServerError { status: 404, .. })) => {
            serde_json::json!({
                "endpoint": endpoint,
                "status": "absent",
                "latency_ms": latency_ms,
            })
        }
        Ok(Err(error)) => serde_json::json!({
            "endpoint": endpoint,
            "status": "unknown",
            "latency_ms": latency_ms,
            "error": error.to_string(),
        }),
        Err(_) => serde_json::json!({
            "endpoint": endpoint,
            "status": "unknown",
            "latency_ms": latency_ms,
            "error": "probe timeout",
        }),
    }
}

pub(crate) async fn api_explorer_object_handler(
    axum::extract::Path(cid_raw): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};
    let Some((cid, cid_hex)) = parse_explorer_cid(&cid_raw) else {
        return explorer_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_CID",
            format!("Not a 64-character hex content ID: {cid_raw}"),
        );
    };
    let endpoints = get_configured_operators();
    if endpoints.is_empty() {
        return explorer_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "NO_OPERATORS_CONFIGURED",
            "Explorer has no operator endpoints configured".to_string(),
        );
    }
    let replicas = probe_explorer_object_cached(cid, endpoints).await;
    let present = replicas
        .iter()
        .filter(|replica| {
            replica.get("status").and_then(|status| status.as_str()) == Some("present")
        })
        .count();
    let checked = replicas.len();
    let required = ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS;
    axum::Json(serde_json::json!({
        "cid": cid_hex,
        "checked_at_utc": Utc::now().to_rfc3339(),
        "quorum": {
            "present": present,
            "checked": checked,
            "required": required,
            "satisfied": present >= required,
        },
        "replicas": replicas,
        "note": "Presence only: the explorer proves possession via PoS challenge and never fetches object bytes.",
    }))
    .into_response()
}

pub(crate) async fn api_explorer_overview_handler() -> impl axum::response::IntoResponse {
    let telemetry = public_operator_telemetry().await;
    let total = telemetry.operators.len();
    let reachable = telemetry
        .operators
        .iter()
        .filter(|operator| {
            operator.get("status").and_then(|status| status.as_str()) == Some("reachable")
        })
        .count();
    let checkpoints = load_public_feed_with_finality()
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let head = checkpoints
        .first()
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    (
        [(axum::http::header::CACHE_CONTROL, "public, max-age=30")],
        axum::Json(serde_json::json!({
            "observed_at_utc": telemetry.observed_at.to_rfc3339(),
            "operators": {
                "total": total,
                "reachable": reachable,
            },
            "anchors": {
                "count": checkpoints.len(),
                "head": head,
            },
        })),
    )
}

/// Returns true when the feed publisher key matches the independently pinned
/// publisher key. A feed signature only proves the holder of the embedded key
/// signed it; pinning proves it is the deployment's intended publisher.
/// Unconfigured pinning (`None`) preserves the legacy verify-only behavior.
pub(crate) fn public_checkpoint_publisher_key_pinned(
    feed_key_hex: &str,
    pinned_key_hex: Option<&str>,
) -> bool {
    let Some(pinned) = pinned_key_hex.map(str::trim).filter(|key| !key.is_empty()) else {
        return true;
    };
    let normalize = |key: &str| key.trim().trim_start_matches("0x").to_ascii_lowercase();
    normalize(feed_key_hex) == normalize(pinned)
}

pub(crate) fn pinned_public_checkpoint_publisher_key() -> Option<String> {
    std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_PUBLISHER_KEY")
        .ok()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
}

pub(crate) fn verify_public_checkpoint_feed(
    feed: &PublicCheckpointFeedEnvelope,
) -> Result<Vec<serde_json::Value>, String> {
    const MAX_PUBLIC_CHECKPOINTS: usize = 1_000;
    const MAX_PUBLIC_FEED_AGE_SECS: u64 = 7 * 24 * 60 * 60;
    const MAX_PUBLIC_FEED_FUTURE_SKEW_SECS: u64 = 5 * 60;
    if feed.version != 1 {
        return Err("Unsupported public checkpoint feed version".to_string());
    }
    if feed.checkpoints.len() > MAX_PUBLIC_CHECKPOINTS {
        return Err("Public checkpoint feed exceeds the 1,000 record limit".to_string());
    }
    let now = Utc::now().timestamp().max(0) as u64;
    if feed.issued_at_utc > now.saturating_add(MAX_PUBLIC_FEED_FUTURE_SKEW_SECS) {
        return Err("Public checkpoint feed timestamp is too far in the future".to_string());
    }
    if now.saturating_sub(feed.issued_at_utc) > MAX_PUBLIC_FEED_AGE_SECS {
        return Err("Public checkpoint feed is stale".to_string());
    }

    let publisher_key = hex::decode(feed.publisher_key_hex.trim_start_matches("0x"))
        .map_err(|_| "Public checkpoint publisher key is not valid hex".to_string())?;
    if publisher_key.len() != 32 {
        return Err("Public checkpoint publisher key must be 32 bytes".to_string());
    }
    if !public_checkpoint_publisher_key_pinned(
        &feed.publisher_key_hex,
        pinned_public_checkpoint_publisher_key().as_deref(),
    ) {
        return Err("Public checkpoint publisher key is not the pinned publisher key".to_string());
    }
    let mut publisher_key_arr = [0u8; 32];
    publisher_key_arr.copy_from_slice(&publisher_key);

    let signature = hex::decode(feed.signature_hex.trim_start_matches("0x"))
        .map_err(|_| "Public checkpoint feed signature is not valid hex".to_string())?;
    if signature.len() != 64 {
        return Err("Public checkpoint feed signature must be 64 bytes".to_string());
    }
    let mut signature_arr = [0u8; 64];
    signature_arr.copy_from_slice(&signature);

    let unsigned = PublicCheckpointFeedUnsigned {
        version: feed.version,
        issued_at_utc: feed.issued_at_utc,
        checkpoints: feed.checkpoints.clone(),
    };
    let message = ciphervault_format::to_canonical_cbor(&unsigned)
        .map_err(|e| format!("Unable to canonicalize public checkpoint feed: {e}"))?;
    ciphervault_crypto::signatures::verify_with_domain(
        &publisher_key_arr,
        b"public_checkpoint_feed",
        &message,
        &signature_arr,
    )
    .map_err(|_| "Public checkpoint feed signature verification failed".to_string())?;

    feed.checkpoints
        .iter()
        .map(|checkpoint| {
            if checkpoint.network.trim().is_empty() || checkpoint.chain_id == 0 {
                return Err("Public checkpoint feed contains an incomplete network record".to_string());
            }
            for (label, value, expected_len) in [
                ("contract address", checkpoint.contract_address_hex.as_str(), 40usize),
                ("commitment", checkpoint.commitment_hex.as_str(), 64usize),
                ("head record CID", checkpoint.head_record_cid_hex.as_str(), 64usize),
            ] {
                let decoded = hex::decode(value.trim_start_matches("0x"))
                    .map_err(|_| format!("Public checkpoint {label} is not valid hex"))?;
                if decoded.len() != expected_len / 2 {
                    return Err(format!("Public checkpoint {label} has an invalid length"));
                }
            }
            if let Some(tx_hash) = checkpoint.tx_hash_hex.as_deref() {
                let decoded = hex::decode(tx_hash.trim_start_matches("0x"))
                    .map_err(|_| "Public checkpoint transaction hash is not valid hex".to_string())?;
                if decoded.len() != 32 {
                    return Err("Public checkpoint transaction hash has an invalid length".to_string());
                }
            }

            let tx_hash = checkpoint.tx_hash_hex.clone().unwrap_or_default();
            let has_transaction = !tx_hash.is_empty();
            Ok(serde_json::json!({
                "network": &checkpoint.network,
                "chain_id": checkpoint.chain_id,
                "contract_address_hex": &checkpoint.contract_address_hex,
                "commitment_hex": &checkpoint.commitment_hex,
                "head_record_cid_hex": &checkpoint.head_record_cid_hex,
                "tx_hash_hex": if has_transaction { serde_json::Value::String(tx_hash) } else { serde_json::Value::Null },
                "reported_block_number": checkpoint.block_number,
                "published_at_utc": checkpoint.published_at_utc,
                "status": if has_transaction { "Published" } else { "QueuedForRelay" },
                "verification_status": "publisher_signed",
                "finality_status": "unverified",
                "publisher_key_hex": &feed.publisher_key_hex,
            }))
        })
        .collect()
}

pub(crate) fn load_public_checkpoint_feed() -> Result<Option<Vec<serde_json::Value>>, String> {
    let path = match std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_FEED") {
        Ok(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => return Ok(None),
    };
    let contents = fs::read_to_string(&path)
        .map_err(|_| "Configured public checkpoint feed could not be read".to_string())?;
    let feed: PublicCheckpointFeedEnvelope = serde_json::from_str(&contents)
        .map_err(|_| "Configured public checkpoint feed is not valid JSON".to_string())?;
    verify_public_checkpoint_feed(&feed).map(Some)
}

/// Maximum fetched feed body: 1,000 small records never approach this.
const MAX_PUBLIC_FEED_FETCH_BYTES: u64 = 8 * 1024 * 1024;

/// Returns true when `value` may be fetched as a remote feed URL: https
/// anywhere (the feed signature, not TLS, is the trust root), http only
/// for loopback (tests and local tooling).
pub(crate) fn public_feed_url_allowed(value: &str) -> bool {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix("https://") {
        return !rest.is_empty();
    }
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("").to_ascii_lowercase();
    authority == "localhost"
        || authority == "127.0.0.1"
        || authority == "[::1]"
        || authority.starts_with("localhost:")
        || authority.starts_with("127.0.0.1:")
        || authority.starts_with("[::1]:")
}

/// Fetches a feed body with a bounded size. Content is still verified by
/// `verify_public_checkpoint_feed` before use.
async fn fetch_public_checkpoint_feed(url: &str) -> Result<String, String> {
    let response =
        reqwest::Client::new().get(url).send().await.map_err(|_| {
            "Configured public checkpoint feed URL could not be fetched".to_string()
        })?;
    if !response.status().is_success() {
        return Err("Configured public checkpoint feed URL returned an error status".to_string());
    }
    if let Some(len) = response.content_length() {
        if len > MAX_PUBLIC_FEED_FETCH_BYTES {
            return Err("Configured public checkpoint feed exceeds the size limit".to_string());
        }
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "Configured public checkpoint feed body could not be read".to_string())?;
    if bytes.len() as u64 > MAX_PUBLIC_FEED_FETCH_BYTES {
        return Err("Configured public checkpoint feed exceeds the size limit".to_string());
    }
    String::from_utf8(bytes.into())
        .map_err(|_| "Configured public checkpoint feed is not valid UTF-8".to_string())
}

/// Async loader: accepts a remote feed URL or a local file path, so the
/// dashboard no longer depends on a host-staged feed file. File paths keep
/// the synchronous loader below.
pub(crate) async fn load_public_checkpoint_feed_async(
) -> Result<Option<Vec<serde_json::Value>>, String> {
    let value = match std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_FEED") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    let trimmed = value.trim();
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return load_public_checkpoint_feed();
    }
    if !public_feed_url_allowed(trimmed) {
        return Err(
            "Configured public checkpoint feed URL is not allowed (https, or http loopback only)"
                .to_string(),
        );
    }
    let contents = fetch_public_checkpoint_feed(trimmed).await?;
    let feed: PublicCheckpointFeedEnvelope = serde_json::from_str(&contents)
        .map_err(|_| "Configured public checkpoint feed is not valid JSON".to_string())?;
    verify_public_checkpoint_feed(&feed).map(Some)
}

pub(crate) const CHECKPOINT_FINALITY_CACHE_TTL: Duration = Duration::from_secs(60);
pub(crate) const DEFAULT_CHECKPOINT_CANARY_MAX_AGE_SECS: u64 = 24 * 60 * 60;

pub(crate) fn checkpoint_canary_max_age_secs() -> u64 {
    std::env::var("CIPHERVAULT_CHECKPOINT_CANARY_MAX_AGE_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|max_age| *max_age > 0)
        .unwrap_or(DEFAULT_CHECKPOINT_CANARY_MAX_AGE_SECS)
}

/// Canary over checkpoint freshness: `ok` when the newest checkpoint is within
/// `max_age_secs`, `stale` when older, `missing` when no checkpoint exists.
pub(crate) fn checkpoint_canary_status(
    newest_published_at_utc: Option<u64>,
    now_utc: u64,
    max_age_secs: u64,
) -> &'static str {
    match newest_published_at_utc {
        None => "missing",
        Some(published) if now_utc.saturating_sub(published) <= max_age_secs => "ok",
        Some(_) => "stale",
    }
}

pub(crate) fn newest_checkpoint_published_at(checkpoints: &[serde_json::Value]) -> Option<u64> {
    checkpoints
        .iter()
        .filter_map(|checkpoint| checkpoint.get("published_at_utc")?.as_u64())
        .max()
}

pub(crate) static CHECKPOINT_FINALITY_CACHE: OnceLock<
    tokio::sync::Mutex<Option<FinalityCacheEntry>>,
> = OnceLock::new();

#[derive(Clone)]
pub(crate) struct FinalityCacheEntry {
    cached_at: Instant,
    checkpoints: Vec<serde_json::Value>,
}

/// Loads the verified publisher-signed checkpoint feed, cached briefly.
///
/// EVM receipt enrichment was removed in Phase 1 of the sovereign-chain
/// migration: this returns the feed as-is. Sovereign finality lives in the
/// local CipherChain ledger (`anchor verify-anchor`), not in this feed.
pub(crate) async fn load_public_feed_with_finality(
) -> Result<Option<Vec<serde_json::Value>>, String> {
    let checkpoints = match load_public_checkpoint_feed_async().await? {
        Some(checkpoints) => checkpoints,
        None => return Ok(None),
    };

    let cache = CHECKPOINT_FINALITY_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    {
        let cached = cache.lock().await.clone();
        if let Some(entry) = cached {
            if entry.cached_at.elapsed() < CHECKPOINT_FINALITY_CACHE_TTL {
                return Ok(Some(entry.checkpoints));
            }
        }
    }

    let entry = FinalityCacheEntry {
        cached_at: Instant::now(),
        checkpoints: checkpoints.clone(),
    };
    *cache.lock().await = Some(entry);
    Ok(Some(checkpoints))
}

pub(crate) async fn api_public_anchors_handler() -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    match load_public_feed_with_finality().await {
        Ok(Some(checkpoints)) => axum::Json(checkpoints).into_response(),
        Ok(None) => axum::Json(serde_json::json!([])).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "error",
                "verification_status": "invalid",
                "error": error,
            })),
        )
            .into_response(),
    }
}

pub(crate) async fn api_public_relayer_checkpoints_handler() -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    match load_public_feed_with_finality().await {
        Ok(Some(checkpoints)) => {
            let checkpoint_count = checkpoints.len();
            let network = checkpoints
                .first()
                .and_then(|checkpoint| checkpoint.get("network"))
                .and_then(|network| network.as_str())
                .unwrap_or("Published checkpoint feed");
            let newest_checkpoint = newest_checkpoint_published_at(&checkpoints);
            let now_utc = Utc::now().timestamp().max(0) as u64;
            let canary_max_age = checkpoint_canary_max_age_secs();
            let canary = checkpoint_canary_status(newest_checkpoint, now_utc, canary_max_age);
            let reorg_suspect_tx_hashes: Vec<String> = checkpoints
                .iter()
                .filter(|checkpoint| {
                    checkpoint.get("finality_status").and_then(|status| status.as_str())
                        == Some("reorg_suspected")
                })
                .filter_map(|checkpoint| {
                    checkpoint.get("tx_hash_hex")?.as_str().map(str::to_string)
                })
                .collect();
            axum::Json(serde_json::json!({
                "status": "ok",
                "access_mode": "public",
                "relayer_status": {
                    "public_read_only": true,
                    "target_network": network,
                    "verification_status": "publisher_signed",
                    "finality_status": "unverified",
                    "canary_status": canary,
                    "reorg_suspected": !reorg_suspect_tx_hashes.is_empty(),
                    "reorg_suspect_tx_hashes": reorg_suspect_tx_hashes,
                    "canary_max_age_secs": canary_max_age,
                    "newest_checkpoint_at_utc": newest_checkpoint,
                },
                "checkpoints": checkpoints,
                "count": checkpoint_count,
                "message": "Checkpoint records are signed by the configured publisher; sovereign CipherChain finality is reported by the local ledger, not this feed.",
            }))
            .into_response()
        }
        Ok(None) => axum::Json(serde_json::json!({
            "status": "ok",
            "access_mode": "public",
            "relayer_status": {
                "public_read_only": true,
                "target_network": "No public checkpoint feed configured",
                "verification_status": "unavailable",
                "canary_status": "missing",
                "newest_checkpoint_at_utc": serde_json::Value::Null,
            },
            "checkpoints": [],
            "count": 0,
            "message": "A signed public checkpoint feed has not been configured. Private vault checkpoint evidence remains available only in a loopback workspace.",
        }))
        .into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "error",
                "access_mode": "public",
                "relayer_status": {
                    "public_read_only": true,
                    "target_network": "Public checkpoint feed unavailable",
                    "verification_status": "invalid",
                    "canary_status": "missing",
                    "newest_checkpoint_at_utc": serde_json::Value::Null,
                },
                "checkpoints": [],
                "count": 0,
                "error": error,
            })),
        )
            .into_response(),
    }
}

pub(crate) async fn api_public_fleet_handler() -> axum::Json<serde_json::Value> {
    let operator_count = get_configured_operators().len();
    axum::Json(serde_json::json!({
        "status": "ok",
        "access_mode": "public",
        "fleet_summary": {
            "total_operators": operator_count,
        },
        "operator_nodes": [],
        "vaults": [],
        "audit_history": [],
        "message": "Vault fleet inventory and audit history are available only in a private local workspace.",
    }))
}

pub(crate) async fn api_public_stream_handler(
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = stream::unfold((), |_| async {
        let telemetry = public_operator_telemetry().await;
        let observed_at = telemetry.observed_at;
        let operators = telemetry
            .operators
            .into_iter()
            .map(|operator| {
                let reachable = operator["status"] == "reachable";
                serde_json::json!({
                    "operator": operator["operator_id"],
                    "online": reachable,
                    "identity_verification": operator["identity_verification"],
                    "latency_ms": operator["latency_ms"],
                })
            })
            .collect::<Vec<_>>();

        let event = Event::default().event("telemetry").data(
            serde_json::json!({
                "timestamp": observed_at.to_rfc3339(),
                "operators": operators,
            })
            .to_string(),
        );
        tokio::time::sleep(PUBLIC_OPERATOR_CACHE_TTL).await;
        Some((Ok(event), ()))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_public_checkpoint_feed, PublicCheckpointFeedEntry};
    use chrono::Utc;

    #[test]
    fn explorer_probe_cache_serves_fresh_and_drops_expired() {
        let mut cache = ExplorerProbeCache {
            entries: std::collections::HashMap::new(),
        };
        let cid = [7u8; 32];
        let replicas = vec![serde_json::json!({"status": "present"})];
        assert!(cache.get(&cid).is_none());
        cache.insert(cid, replicas.clone());
        assert_eq!(cache.get(&cid), Some(replicas.clone()));
        cache.insert_at(
            cid,
            replicas,
            Instant::now() - EXPLORER_PROBE_CACHE_TTL - Duration::from_secs(1),
        );
        assert!(cache.get(&cid).is_none());
    }

    #[test]
    fn explorer_probe_concurrency_is_bounded() {
        assert_eq!(
            explorer_probe_permits().available_permits(),
            EXPLORER_PROBE_MAX_CONCURRENT
        );
    }

    #[tokio::test]
    async fn explorer_object_endpoint_serves_cached_probes_without_network() {
        // Pre-populate the shared cache with a marker CID, then prove the
        // endpoint serves it: no operator contact, fully deterministic.
        let cid = rand::random::<[u8; 32]>();
        let marker = format!("test-cache-marker-{}", hex::encode(cid));
        explorer_probe_cache().lock().await.insert(
            cid,
            vec![serde_json::json!({"status": "present", "operator_id": marker})],
        );
        let response = api_explorer_object_handler(axum::extract::Path(hex::encode(cid))).await;
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["cid"], hex::encode(cid));
        assert_eq!(json["replicas"][0]["operator_id"], marker);
    }

    #[test]
    fn explorer_cid_parser_normalizes_and_validates() {
        let (bytes, normalized) = parse_explorer_cid(&"AB".repeat(32)).unwrap();
        assert_eq!(normalized, "ab".repeat(32));
        assert_eq!(bytes, [0xabu8; 32]);
        assert!(parse_explorer_cid("  ab12  ").is_none());
        assert!(parse_explorer_cid(&"ab".repeat(31)).is_none());
        assert!(parse_explorer_cid(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn public_feed_url_policy_allows_https_and_loopback_http_only() {
        assert!(public_feed_url_allowed("https://example.com/feed.json"));
        assert!(public_feed_url_allowed("https://example.com:8443/a/b?c=d"));
        assert!(public_feed_url_allowed("http://localhost:8080/feed.json"));
        assert!(public_feed_url_allowed("http://127.0.0.1/feed.json"));
        assert!(public_feed_url_allowed("http://[::1]:8080/feed.json"));
        assert!(!public_feed_url_allowed("http://example.com/feed.json"));
        assert!(!public_feed_url_allowed("http://10.0.0.1/feed.json"));
        assert!(!public_feed_url_allowed(
            "http://localhost.evil.com/feed.json"
        ));
        assert!(!public_feed_url_allowed("http://127.0.0.1.evil/feed.json"));
        assert!(!public_feed_url_allowed("ftp://example.com/feed.json"));
        assert!(!public_feed_url_allowed("/release/feed.json"));
        assert!(!public_feed_url_allowed("https://"));
        assert!(!public_feed_url_allowed(""));
    }

    #[tokio::test]
    async fn checkpoint_feed_loads_from_remote_url() {
        use axum::{routing::get, Router};
        use ciphervault_format::CheckpointEvidence;

        let now = Utc::now().timestamp().max(0) as u64;
        let signing_key = ciphervault_crypto::generate_signing_key();
        let evidence = CheckpointEvidence::new(
            [0x11u8; 32],
            [0x22u8; 32],
            421614,
            [0x33u8; 20],
            [0x44u8; 32],
            123,
            now,
        );
        let feed = build_public_checkpoint_feed(
            vec![evidence],
            "Arbitrum Sepolia".to_string(),
            &signing_key,
            now,
        )
        .unwrap();
        let body = serde_json::to_string(&feed).unwrap();
        let app = Router::new().route(
            "/feed.json",
            get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        std::env::set_var(
            "CIPHERVAULT_PUBLIC_CHECKPOINT_FEED",
            format!("http://{addr}/feed.json"),
        );
        let loaded = load_public_checkpoint_feed_async().await.unwrap().unwrap();
        std::env::remove_var("CIPHERVAULT_PUBLIC_CHECKPOINT_FEED");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0]["verification_status"], "publisher_signed");
    }

    #[test]
    fn signed_public_checkpoint_feed_is_verified_before_publication() {
        // Anchored to now: the verifier rejects feeds older than 7 days,
        // so a fixed timestamp would turn this test into a time bomb.
        let now = Utc::now().timestamp().max(0) as u64;
        let signing_key = ciphervault_crypto::generate_signing_key();
        let checkpoint = PublicCheckpointFeedEntry {
            network: "Arbitrum Sepolia".to_string(),
            chain_id: 421614,
            contract_address_hex: "11".repeat(20),
            commitment_hex: "22".repeat(32),
            head_record_cid_hex: "33".repeat(32),
            tx_hash_hex: Some(format!("0x{}", "44".repeat(32))),
            block_number: Some(123),
            published_at_utc: now,
        };
        let unsigned = PublicCheckpointFeedUnsigned {
            version: 1,
            issued_at_utc: now,
            checkpoints: vec![checkpoint.clone()],
        };
        let message = ciphervault_format::to_canonical_cbor(&unsigned).unwrap();
        let signature = ciphervault_crypto::signatures::sign_with_domain(
            &signing_key,
            b"public_checkpoint_feed",
            &message,
        );
        let feed = PublicCheckpointFeedEnvelope {
            version: unsigned.version,
            issued_at_utc: unsigned.issued_at_utc,
            checkpoints: unsigned.checkpoints,
            publisher_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            signature_hex: hex::encode(signature),
        };

        let records = verify_public_checkpoint_feed(&feed).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["verification_status"], "publisher_signed");
        assert_eq!(records[0]["finality_status"], "unverified");

        let mut tampered = feed.clone();
        tampered.checkpoints[0].block_number = Some(124);
        assert!(verify_public_checkpoint_feed(&tampered).is_err());
    }

    #[test]
    fn publisher_key_rotation_drill() {
        // Automated rotation drill (Track 4 ceremony): feed signed under key
        // A verifies while A is pinned; after the pin rotates to B the old
        // feed is rejected and only a B-signed reissue verifies. Uses fixed
        // drill seeds so the transcript is reproducible; production keys are
        // random and offline.
        use ed25519_dalek::SigningKey as DrillSigningKey;
        let now = Utc::now().timestamp().max(0) as u64;
        let key_a = DrillSigningKey::from_bytes(&[0xA5; 32]);
        let key_b = DrillSigningKey::from_bytes(&[0xB6; 32]);
        let pub_a = hex::encode(key_a.verifying_key().as_bytes());
        let pub_b = hex::encode(key_b.verifying_key().as_bytes());
        assert_ne!(pub_a, pub_b);
        let checkpoint = PublicCheckpointFeedEntry {
            network: "Drillnet".to_string(),
            chain_id: 421614,
            contract_address_hex: "11".repeat(20),
            commitment_hex: "22".repeat(32),
            head_record_cid_hex: "33".repeat(32),
            tx_hash_hex: Some(format!("0x{}", "44".repeat(32))),
            block_number: Some(123),
            published_at_utc: now,
        };
        let sign_feed = |key: &DrillSigningKey| {
            let unsigned = PublicCheckpointFeedUnsigned {
                version: 1,
                issued_at_utc: now,
                checkpoints: vec![checkpoint.clone()],
            };
            let message = ciphervault_format::to_canonical_cbor(&unsigned).unwrap();
            let signature = ciphervault_crypto::signatures::sign_with_domain(
                key,
                b"public_checkpoint_feed",
                &message,
            );
            PublicCheckpointFeedEnvelope {
                version: unsigned.version,
                issued_at_utc: unsigned.issued_at_utc,
                checkpoints: unsigned.checkpoints,
                publisher_key_hex: hex::encode(key.verifying_key().as_bytes()),
                signature_hex: hex::encode(signature),
            }
        };
        // NOTE: this drill deliberately avoids the
        // CIPHERVAULT_PUBLIC_CHECKPOINT_PUBLISHER_KEY env var: unit tests
        // share one process, so env manipulation here races parallel
        // tests that read the pin. The pin predicate takes the pin as a
        // plain argument, which exercises the identical rotation logic
        // hermetically (same predicate `verify_*` calls internally).
        // Pre-rotation: A-signed feed is valid and matches pin A.
        let feed_a = sign_feed(&key_a);
        let records = verify_public_checkpoint_feed(&feed_a).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["verification_status"], "publisher_signed");
        assert!(public_checkpoint_publisher_key_pinned(
            &feed_a.publisher_key_hex,
            Some(&pub_a)
        ));
        // Rotation: pin moves to B; the stale A-signed feed is rejected.
        assert!(!public_checkpoint_publisher_key_pinned(
            &feed_a.publisher_key_hex,
            Some(&pub_b)
        ));
        // Post-rotation: B-signed reissue verifies and matches pin B.
        let feed_b = sign_feed(&key_b);
        let records = verify_public_checkpoint_feed(&feed_b).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["verification_status"], "publisher_signed");
        assert!(public_checkpoint_publisher_key_pinned(
            &feed_b.publisher_key_hex,
            Some(&pub_b)
        ));
        assert_eq!(records[0]["publisher_key_hex"], pub_b);
        // Tampered payload still rejected at the crypto layer.
        let mut tampered = feed_b.clone();
        let bumped = tampered.checkpoints[0].block_number.unwrap_or(0) + 1;
        tampered.checkpoints[0].block_number = Some(bumped);
        assert!(verify_public_checkpoint_feed(&tampered).is_err());
    }

    #[test]
    fn checkpoint_publisher_pinning_matches_exact_key_only() {
        let key = "ab".repeat(32);
        assert!(public_checkpoint_publisher_key_pinned(&key, None));
        assert!(public_checkpoint_publisher_key_pinned(&key, Some("")));
        assert!(public_checkpoint_publisher_key_pinned(&key, Some(&key)));
        assert!(public_checkpoint_publisher_key_pinned(
            &key,
            Some(&format!("0x{key}"))
        ));
        assert!(public_checkpoint_publisher_key_pinned(
            &key,
            Some(&key.to_ascii_uppercase())
        ));
        assert!(!public_checkpoint_publisher_key_pinned(
            &key,
            Some(&"00".repeat(32))
        ));
    }

    #[test]
    fn checkpoint_canary_tracks_freshness() {
        let now = 2_000_000_000u64;
        assert_eq!(checkpoint_canary_status(None, now, 3_600), "missing");
        assert_eq!(checkpoint_canary_status(Some(now - 100), now, 3_600), "ok");
        assert_eq!(
            checkpoint_canary_status(Some(now - 3_600), now, 3_600),
            "ok"
        );
        assert_eq!(
            checkpoint_canary_status(Some(now - 3_601), now, 3_600),
            "stale"
        );
        assert_eq!(checkpoint_canary_status(Some(now + 60), now, 3_600), "ok");
    }

    #[test]
    fn newest_checkpoint_selects_max_timestamp() {
        let checkpoints = serde_json::json!([
            {"published_at_utc": 10},
            {"published_at_utc": 30},
            {"published_at_utc": 20},
        ]);
        let list = checkpoints.as_array().unwrap().clone();
        assert_eq!(newest_checkpoint_published_at(&list), Some(30));
        assert_eq!(newest_checkpoint_published_at(&[]), None);
    }

    #[test]
    fn public_feed_publisher_converts_verified_local_evidence() {
        let signing_key = ciphervault_crypto::generate_signing_key();
        let evidence = ciphervault_format::CheckpointEvidence::new(
            [1u8; 32],
            [2u8; 32],
            42161,
            [3u8; 20],
            [4u8; 32],
            987,
            Utc::now().timestamp().max(0) as u64,
        );
        let feed = build_public_checkpoint_feed(
            vec![evidence],
            "Arbitrum One".to_string(),
            &signing_key,
            Utc::now().timestamp().max(0) as u64,
        )
        .unwrap();
        let records = verify_public_checkpoint_feed(&feed).unwrap();
        assert_eq!(records[0]["status"], "Published");
        assert_eq!(records[0]["chain_id"], 42161);
        assert_eq!(records[0]["reported_block_number"], 987);
        assert_eq!(records[0]["verification_status"], "publisher_signed");
    }
}
