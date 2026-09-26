//! Explorer, checkpoint feed verification, finality, and public data handlers.

use anyhow::Result;
use chrono::Utc;
use rand::RngCore;
use reqwest::Client as HttpClient;
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

pub(crate) const CHECKPOINT_FINALITY_CACHE_TTL: Duration = Duration::from_secs(60);
pub(crate) const DEFAULT_FINALITY_CONFIRMATIONS: u64 = 12;
pub(crate) const DEFAULT_CHECKPOINT_CANARY_MAX_AGE_SECS: u64 = 24 * 60 * 60;

pub(crate) static CHECKPOINT_RPC_HTTP_CLIENT: OnceLock<HttpClient> = OnceLock::new();

/// Shared client for independent Arbitrum receipt queries. Receipt fetching is
/// read-only evidence collection; RPC failures degrade to `unknown`, never errors.
pub(crate) fn checkpoint_rpc_http_client() -> HttpClient {
    CHECKPOINT_RPC_HTTP_CLIENT
        .get_or_init(|| {
            HttpClient::builder()
                .timeout(Duration::from_secs(10))
                .pool_idle_timeout(Duration::from_secs(120))
                .pool_max_idle_per_host(4)
                .build()
                .unwrap_or_else(|_| HttpClient::new())
        })
        .clone()
}

/// Parses an Ethereum JSON-RPC quantity (`0x`-hex string or JSON number).
pub(crate) fn parse_rpc_quantity(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::String(text) => {
            let digits = text.trim().trim_start_matches("0x");
            if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(digits, 16).ok()
        }
        serde_json::Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

/// Outcome of one independent `eth_getTransactionReceipt` observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptFetch {
    /// The transaction has no receipt yet (pending or unknown to the node).
    Pending,
    /// Receipt observed; `status_ok` mirrors receipt `status` (1 = success).
    Observed { status_ok: bool, block_number: u64 },
    /// RPC failed or returned an unparseable receipt; evidence unavailable.
    Failed,
}

/// Classifies a JSON-RPC `result` for `eth_getTransactionReceipt`.
pub(crate) fn classify_receipt_result(result: &serde_json::Value) -> ReceiptFetch {
    if result.is_null() {
        return ReceiptFetch::Pending;
    }
    let receipt = match result.as_object() {
        Some(object) => object,
        None => return ReceiptFetch::Failed,
    };
    let status = receipt.get("status").and_then(parse_rpc_quantity);
    let block_number = receipt.get("blockNumber").and_then(parse_rpc_quantity);
    match (status, block_number) {
        (Some(status), Some(block_number)) => ReceiptFetch::Observed {
            status_ok: status == 1,
            block_number,
        },
        _ => ReceiptFetch::Failed,
    }
}

/// Maps one receipt observation + chain tip to
/// `(finality_status, receipt_block, confirmations)`.
pub(crate) fn checkpoint_finality(
    fetch: ReceiptFetch,
    tip_block: Option<u64>,
    required_confirmations: u64,
) -> (&'static str, Option<u64>, Option<u64>) {
    match fetch {
        ReceiptFetch::Pending => ("pending", None, None),
        ReceiptFetch::Failed => ("unknown", None, None),
        ReceiptFetch::Observed {
            status_ok: false,
            block_number,
        } => (
            "failed",
            Some(block_number),
            tip_block.map(|tip| tip.saturating_sub(block_number)),
        ),
        ReceiptFetch::Observed {
            status_ok: true,
            block_number,
        } => {
            let confirmations = tip_block.map(|tip| tip.saturating_sub(block_number));
            let finalized = confirmations.is_some_and(|count| count >= required_confirmations);
            (
                if finalized { "finalized" } else { "confirmed" },
                Some(block_number),
                confirmations,
            )
        }
    }
}

/// Detects reorg suspects among previously-finalized receipts: a suspect is a
/// feed checkpoint whose finalized receipt is now missing or mined at a
/// different block. `current` carries (tx hash, finality status, receipt block).
/// Checkpoints that left the feed are ignored (feed edits are not reorgs), and
/// a re-finalized receipt clears even at a new block (the chain moved on).
pub(crate) fn detect_reorg_suspects(
    previously_finalized: &[(String, u64)],
    current: &[(String, String, Option<u64>)],
) -> Vec<String> {
    previously_finalized
        .iter()
        .filter(|(tx, block)| {
            let Some((_, status, observed)) =
                current.iter().find(|(current_tx, _, _)| current_tx == tx)
            else {
                return false;
            };
            if status == "finalized" {
                return false;
            }
            match observed {
                Some(observed_block) => observed_block != block,
                None => true,
            }
        })
        .map(|(tx, _)| tx.clone())
        .collect()
}

pub(crate) fn finality_confirmations_required() -> u64 {
    std::env::var("CIPHERVAULT_FINALITY_CONFIRMATIONS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|confirmations| *confirmations > 0)
        .unwrap_or(DEFAULT_FINALITY_CONFIRMATIONS)
}

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

/// Normalizes a transaction hash for JSON-RPC `DATA` params. Nodes reject
/// bare hex (`cannot unmarshal hex string without 0x prefix`), while older
/// feed files predate the publisher's `0x` prefix — accept both, emit `0x`.
pub(crate) fn normalize_rpc_tx_hash(hash: &str) -> String {
    let trimmed = hash.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        trimmed.to_string()
    } else {
        format!("0x{trimmed}")
    }
}

pub(crate) async fn fetch_receipt_observation(
    client: &HttpClient,
    rpc_url: &str,
    tx_hash_hex: String,
) -> ReceiptFetch {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [normalize_rpc_tx_hash(&tx_hash_hex)],
    });
    let response = match client.post(rpc_url).json(&body).send().await {
        Ok(response) => response,
        Err(_) => return ReceiptFetch::Failed,
    };
    let payload: serde_json::Value = match response.json().await {
        Ok(payload) => payload,
        Err(_) => return ReceiptFetch::Failed,
    };
    if payload.get("error").is_some() {
        return ReceiptFetch::Failed;
    }
    match payload.get("result") {
        Some(result) => classify_receipt_result(result),
        None => ReceiptFetch::Failed,
    }
}

pub(crate) async fn fetch_chain_tip_block(client: &HttpClient, rpc_url: &str) -> Option<u64> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_blockNumber",
        "params": [],
    });
    let response = client.post(rpc_url).json(&body).send().await.ok()?;
    let payload: serde_json::Value = response.json().await.ok()?;
    if payload.get("error").is_some() {
        return None;
    }
    payload.get("result").and_then(parse_rpc_quantity)
}

pub(crate) static CHECKPOINT_FINALITY_CACHE: OnceLock<
    tokio::sync::Mutex<Option<FinalityCacheEntry>>,
> = OnceLock::new();

#[derive(Clone)]
pub(crate) struct FinalityCacheEntry {
    cached_at: Instant,
    checkpoints: Vec<serde_json::Value>,
    /// Previously-finalized receipts as (tx hash, block): reorg memory.
    finalized: Vec<(String, u64)>,
}

/// Loads the verified feed and, when `CIPHERVAULT_ARBITRUM_RPC_URL` is set,
/// enriches transaction-bearing checkpoints with independent receipt finality.
/// Results are cached briefly; without an RPC URL this is the plain feed.
pub(crate) async fn load_public_feed_with_finality(
) -> Result<Option<Vec<serde_json::Value>>, String> {
    let checkpoints = match load_public_checkpoint_feed()? {
        Some(checkpoints) => checkpoints,
        None => return Ok(None),
    };
    let rpc_url = std::env::var("CIPHERVAULT_ARBITRUM_RPC_URL")
        .ok()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty());
    let Some(rpc_url) = rpc_url else {
        return Ok(Some(checkpoints));
    };

    let cache = CHECKPOINT_FINALITY_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    let previous_finalized = match cache.lock().await.clone() {
        Some(entry) if entry.cached_at.elapsed() < CHECKPOINT_FINALITY_CACHE_TTL => {
            return Ok(Some(entry.checkpoints));
        }
        Some(entry) => entry.finalized,
        None => Vec::new(),
    };

    let client = checkpoint_rpc_http_client();
    let required = finality_confirmations_required();
    let tip = fetch_chain_tip_block(&client, &rpc_url).await;
    let tx_hashes: Vec<Option<String>> = checkpoints
        .iter()
        .map(|checkpoint| {
            checkpoint
                .get("tx_hash_hex")
                .and_then(|hash| hash.as_str())
                .filter(|hash| !hash.is_empty())
                .map(str::to_string)
        })
        .collect();
    let targets: Vec<(usize, String)> = tx_hashes
        .iter()
        .enumerate()
        .filter_map(|(index, hash)| hash.clone().map(|hash| (index, hash)))
        .collect();
    let mut enriched = checkpoints;
    for chunk in targets.chunks(8) {
        let fetches = chunk
            .iter()
            .map(|(_, hash)| fetch_receipt_observation(&client, &rpc_url, hash.clone()));
        let observations = join_all(fetches).await;
        for ((index, _), fetch) in chunk.iter().zip(observations) {
            let (status, block, confirmations) = checkpoint_finality(fetch, tip, required);
            let Some(record) = enriched.get_mut(*index) else {
                continue;
            };
            let Some(object) = record.as_object_mut() else {
                continue;
            };
            object.insert("finality_status".to_string(), serde_json::json!(status));
            object.insert("receipt_block_number".to_string(), serde_json::json!(block));
            object.insert(
                "confirmations".to_string(),
                serde_json::json!(confirmations),
            );
        }
    }

    let current: Vec<(String, String, Option<u64>)> = enriched
        .iter()
        .filter_map(|record| {
            let tx = record
                .get("tx_hash_hex")?
                .as_str()
                .filter(|hash| !hash.is_empty())?;
            let status = record
                .get("finality_status")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let block = record
                .get("receipt_block_number")
                .and_then(|value| value.as_u64());
            Some((tx.to_string(), status.to_string(), block))
        })
        .collect();
    let suspects = detect_reorg_suspects(&previous_finalized, &current);
    for record in enriched.iter_mut() {
        let tx = record
            .get("tx_hash_hex")
            .and_then(|hash| hash.as_str())
            .unwrap_or("");
        if suspects.iter().any(|suspect| suspect == tx) {
            if let Some(object) = record.as_object_mut() {
                object.insert(
                    "finality_status".to_string(),
                    serde_json::json!("reorg_suspected"),
                );
            }
        }
    }
    for tx in &suspects {
        eprintln!("checkpoint reorg suspected: finalized receipt for {tx} missing or re-mined");
    }
    let mut next_finalized: Vec<(String, u64)> = Vec::new();
    for (tx, status, block) in &current {
        if status == "finalized" {
            if let Some(number) = block {
                next_finalized.push((tx.clone(), *number));
            }
        }
    }
    // Suspects stay in memory so the alarm persists until re-finalized; feed
    // removals drop out (feed edits are not reorgs).
    for (tx, block) in &previous_finalized {
        if current.iter().any(|(current_tx, _, _)| current_tx == tx)
            && !next_finalized.iter().any(|(known, _)| known == tx)
        {
            next_finalized.push((tx.clone(), *block));
        }
    }

    let entry = FinalityCacheEntry {
        cached_at: Instant::now(),
        checkpoints: enriched.clone(),
        finalized: next_finalized,
    };
    *cache.lock().await = Some(entry);
    Ok(Some(enriched))
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
            let rpc_configured = std::env::var("CIPHERVAULT_ARBITRUM_RPC_URL")
                .ok()
                .is_some_and(|url| !url.trim().is_empty());
            axum::Json(serde_json::json!({
                "status": "ok",
                "access_mode": "public",
                "relayer_status": {
                    "public_read_only": true,
                    "target_network": network,
                    "verification_status": "publisher_signed",
                    "finality_status": if rpc_configured { "independent_rpc" } else { "unverified" },
                    "canary_status": canary,
                    "reorg_suspected": !reorg_suspect_tx_hashes.is_empty(),
                    "reorg_suspect_tx_hashes": reorg_suspect_tx_hashes,
                    "canary_max_age_secs": canary_max_age,
                    "newest_checkpoint_at_utc": newest_checkpoint,
                },
                "checkpoints": checkpoints,
                "count": checkpoint_count,
                "message": "Checkpoint records are signed by the configured publisher; per-checkpoint finality reflects independent RPC receipts when an Arbitrum RPC URL is configured.",
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
    fn rpc_tx_hash_normalizer_emits_0x_prefix() {
        assert_eq!(
            normalize_rpc_tx_hash(
                "7dc9c9852a75804a2216b31e085900a9fccf35de684a897c970e6e4b090f8e22"
            ),
            "0x7dc9c9852a75804a2216b31e085900a9fccf35de684a897c970e6e4b090f8e22"
        );
        assert_eq!(
            normalize_rpc_tx_hash(
                "0x7dc9c9852a75804a2216b31e085900a9fccf35de684a897c970e6e4b090f8e22"
            ),
            "0x7dc9c9852a75804a2216b31e085900a9fccf35de684a897c970e6e4b090f8e22"
        );
        assert_eq!(normalize_rpc_tx_hash("  0xabc123  "), "0xabc123");
    }

    #[test]
    fn published_feed_prefixes_transaction_hashes_for_rpc() {
        // Nodes reject bare-hex DATA params, so the publisher must emit
        // 0x-prefixed hashes (the verifier already accepts both forms).
        let now = Utc::now().timestamp().max(0) as u64;
        let signing_key = ciphervault_crypto::generate_signing_key();
        let evidence = ciphervault_format::CheckpointEvidence::new(
            [0x11u8; 32],
            [0x22u8; 32],
            421614,
            [0x33u8; 20],
            [0x44u8; 32],
            312825597,
            now,
        );
        let feed = build_public_checkpoint_feed(
            vec![evidence],
            "Arbitrum Sepolia".to_string(),
            &signing_key,
            now,
        )
        .unwrap();
        assert_eq!(feed.checkpoints.len(), 1);
        assert_eq!(
            feed.checkpoints[0].tx_hash_hex.as_deref().unwrap(),
            format!("0x{}", "44".repeat(32))
        );
        let queued = ciphervault_format::CheckpointEvidence::new(
            [0x11u8; 32],
            [0x22u8; 32],
            421614,
            [0x33u8; 20],
            [0u8; 32],
            0,
            now,
        );
        let feed = build_public_checkpoint_feed(
            vec![queued],
            "Arbitrum Sepolia".to_string(),
            &signing_key,
            now,
        )
        .unwrap();
        assert!(feed.checkpoints[0].tx_hash_hex.is_none());
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
    fn reorg_alarm_fires_on_finalized_receipt_regression() {
        let previous = vec![("0xaaa".to_string(), 100u64), ("0xbbb".to_string(), 120u64)];
        // Vanished receipt + re-mined receipt alarm; steady ones stay quiet.
        let current = vec![
            ("0xaaa".to_string(), "unknown".to_string(), None),
            ("0xbbb".to_string(), "confirmed".to_string(), Some(125u64)),
        ];
        assert_eq!(
            detect_reorg_suspects(&previous, &current),
            vec!["0xaaa".to_string(), "0xbbb".to_string()]
        );
        // Still finalized, or confirmed at the same block: no alarm.
        let current = vec![
            ("0xaaa".to_string(), "finalized".to_string(), Some(100u64)),
            ("0xbbb".to_string(), "confirmed".to_string(), Some(120u64)),
        ];
        assert!(detect_reorg_suspects(&previous, &current).is_empty());
        // Re-finalized at a new block clears; feed removals never alarm.
        let current = vec![("0xaaa".to_string(), "finalized".to_string(), Some(140u64))];
        assert!(detect_reorg_suspects(&previous, &current).is_empty());
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
    fn receipt_quantities_and_finality_classification() {
        assert_eq!(parse_rpc_quantity(&serde_json::json!("0x10")), Some(16));
        assert_eq!(parse_rpc_quantity(&serde_json::json!("0x0")), Some(0));
        assert_eq!(parse_rpc_quantity(&serde_json::json!(7)), Some(7));
        assert_eq!(parse_rpc_quantity(&serde_json::json!("zz")), None);
        assert_eq!(parse_rpc_quantity(&serde_json::Value::Null), None);
        assert_eq!(
            classify_receipt_result(&serde_json::Value::Null),
            ReceiptFetch::Pending
        );
        let observed = serde_json::json!({"status": "0x1", "blockNumber": "0x64"});
        assert_eq!(
            classify_receipt_result(&observed),
            ReceiptFetch::Observed {
                status_ok: true,
                block_number: 100
            }
        );
        let failed_tx = serde_json::json!({"status": "0x0", "blockNumber": "0x64"});
        assert_eq!(
            classify_receipt_result(&failed_tx),
            ReceiptFetch::Observed {
                status_ok: false,
                block_number: 100
            }
        );
        assert_eq!(
            classify_receipt_result(&serde_json::json!({"blockNumber": "0x64"})),
            ReceiptFetch::Failed
        );
        assert_eq!(
            checkpoint_finality(ReceiptFetch::Pending, Some(200), 12).0,
            "pending"
        );
        assert_eq!(
            checkpoint_finality(ReceiptFetch::Failed, Some(200), 12).0,
            "unknown"
        );
        let obs = ReceiptFetch::Observed {
            status_ok: true,
            block_number: 100,
        };
        assert_eq!(checkpoint_finality(obs, Some(200), 12).0, "finalized");
        assert_eq!(checkpoint_finality(obs, Some(105), 12).0, "confirmed");
        assert_eq!(checkpoint_finality(obs, None, 12).0, "confirmed");
        let reverted = ReceiptFetch::Observed {
            status_ok: false,
            block_number: 100,
        };
        assert_eq!(checkpoint_finality(reverted, Some(200), 12).0, "failed");
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
