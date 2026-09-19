//! Public operator collector, telemetry persistence, and public ops handlers.

use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::Client as HttpClient;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use futures_util::future::join_all;

use ciphervault_storage::OperatorClient;

use crate::get_configured_operator_regions;

pub(crate) fn public_operator_id(operator_id: &str, index: usize) -> String {
    let safe_id = operator_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>();
    if safe_id.is_empty() {
        format!("operator-{}", index + 1)
    } else {
        safe_id
    }
}

/// Returns true only when an operator identity is present in the independently
/// configured trust registry.  A self-signed `/v1/info` response proves that
/// the responder controls the returned key, but it does not prove that the key
/// is the key the deployment intended to contact.
///
/// `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES` accepts comma-separated entries in
/// either `operator-id=64-byte-hex-key` form or as a bare public key.  The
/// registry is deliberately opt-in: when it is absent, public telemetry stays
/// unverified instead of silently falling back to trust-on-first-use.
pub(crate) fn trusted_public_operator_identity_from_registry(
    registry: &str,
    operator_id: &str,
    public_key_hex: &str,
) -> bool {
    let key = public_key_hex
        .trim()
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    registry.split(',').any(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return false;
        }
        let (entry_id, entry_key) = entry
            .split_once('=')
            .map_or((None, entry), |(id, key)| (Some(id.trim()), key.trim()));
        let entry_key = entry_key.trim_start_matches("0x").to_ascii_lowercase();
        entry_key == key
            && entry_id.is_none_or(|id| !id.is_empty() && id.eq_ignore_ascii_case(operator_id))
    })
}

pub(crate) fn trusted_public_operator_identity(operator_id: &str, public_key_hex: &str) -> bool {
    std::env::var("CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES")
        .ok()
        .is_some_and(|registry| {
            trusted_public_operator_identity_from_registry(&registry, operator_id, public_key_hex)
        })
}

pub(crate) const PUBLIC_OPERATOR_IDENTITY_EXPIRING_SOON_SECS: u64 = 6 * 60 * 60;

/// Maps pinning + expiry evidence to one dashboard-facing identity status.
/// `verified` requires both a valid self-signature (via `identity_pinned`) and
/// an unexpired identity; `expiring_soon` warns within 6h of expiry so rotation
/// can happen before the explorer flips an operator to `expired`.
pub(crate) fn public_operator_identity_status(
    identity_pinned: bool,
    expires_at_utc: u64,
    now_utc: u64,
) -> &'static str {
    if expires_at_utc != 0 && now_utc > expires_at_utc {
        return "expired";
    }
    if !identity_pinned {
        return "unverified";
    }
    let seconds_to_expiry = expires_at_utc.saturating_sub(now_utc);
    if expires_at_utc != 0 && seconds_to_expiry < PUBLIC_OPERATOR_IDENTITY_EXPIRING_SOON_SECS {
        return "expiring_soon";
    }
    "verified"
}

pub(crate) const PUBLIC_OPERATOR_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const PUBLIC_OPERATOR_CACHE_TTL: Duration = Duration::from_secs(30);
pub(crate) const PUBLIC_OPERATOR_PERSISTED_MAX_AGE: Duration = Duration::from_secs(90);

#[derive(Clone)]
pub(crate) struct PublicOperatorTelemetry {
    pub(crate) observed_at: chrono::DateTime<Utc>,
    cached_at: Instant,
    pub(crate) operators: Vec<serde_json::Value>,
}

pub(crate) static PUBLIC_OPERATOR_TELEMETRY_CACHE: OnceLock<
    tokio::sync::Mutex<Option<PublicOperatorTelemetry>>,
> = OnceLock::new();
pub(crate) static PUBLIC_OPERATOR_HTTP_CLIENT: OnceLock<HttpClient> = OnceLock::new();

pub(crate) fn public_operator_http_client() -> HttpClient {
    PUBLIC_OPERATOR_HTTP_CLIENT
        .get_or_init(|| {
            HttpClient::builder()
                .connect_timeout(Duration::from_secs(2))
                .timeout(PUBLIC_OPERATOR_PROBE_TIMEOUT)
                .pool_idle_timeout(Duration::from_secs(120))
                .pool_max_idle_per_host(2)
                .tcp_keepalive(Some(Duration::from_secs(30)))
                .build()
                .unwrap_or_else(|_| HttpClient::new())
        })
        .clone()
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedPublicOperatorTelemetry {
    observed_at_utc: String,
    operators: Vec<serde_json::Value>,
}

pub(crate) fn public_operator_telemetry_path() -> Option<PathBuf> {
    std::env::var("CIPHERVAULT_PUBLIC_OPERATOR_TELEMETRY_FILE")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
}

pub(crate) const PUBLIC_OPERATOR_HISTORY_MAX: usize = 288;
pub(crate) const PUBLIC_OPERATOR_JOB_HISTORY_MAX: usize = 1_000;

pub(crate) fn public_operator_history_path() -> Option<PathBuf> {
    let path = public_operator_telemetry_path()?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("operator-telemetry.json");
    Some(path.with_file_name(format!("{}.history.jsonl", name)))
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedPublicOperatorHistoryEntry {
    observed_at_utc: String,
    operators: Vec<serde_json::Value>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedPublicOperatorJob {
    job_id: String,
    started_at_utc: String,
    completed_at_utc: String,
    status: String,
    #[serde(default)]
    regions: Vec<String>,
    operator_count: usize,
    reachable_count: usize,
    failure_count: usize,
    #[serde(default)]
    attempts: usize,
    #[serde(default)]
    retry_count: usize,
    #[serde(default)]
    error_summary: Option<String>,
}

pub(crate) fn public_operator_jobs_path() -> Option<PathBuf> {
    let path = public_operator_telemetry_path()?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("operator-telemetry.json");
    Some(path.with_file_name(format!("{}.jobs.jsonl", name)))
}

pub(crate) fn load_persisted_public_operator_telemetry() -> Option<PublicOperatorTelemetry> {
    let path = public_operator_telemetry_path()?;
    let contents = fs::read_to_string(path).ok()?;
    let persisted: PersistedPublicOperatorTelemetry = serde_json::from_str(&contents).ok()?;
    let observed_at = chrono::DateTime::parse_from_rfc3339(&persisted.observed_at_utc)
        .ok()?
        .with_timezone(&Utc);
    let now = Utc::now();
    if observed_at > now + chrono::Duration::minutes(5)
        || now.signed_duration_since(observed_at).to_std().ok()? > PUBLIC_OPERATOR_PERSISTED_MAX_AGE
    {
        return None;
    }
    Some(PublicOperatorTelemetry {
        observed_at,
        cached_at: Instant::now(),
        operators: persisted.operators,
    })
}

pub(crate) fn persist_public_operator_telemetry(snapshot: &PublicOperatorTelemetry) -> Result<()> {
    let path = public_operator_telemetry_path()
        .context("public operator telemetry persistence path is not configured")?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec_pretty(&PersistedPublicOperatorTelemetry {
        observed_at_utc: snapshot.observed_at.to_rfc3339(),
        operators: snapshot.operators.clone(),
    })?;
    let temp_path = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("operator-telemetry.json"),
        std::process::id()
    ));
    fs::write(&temp_path, payload)?;
    let result = (|| -> Result<()> {
        if path.exists() {
            fs::remove_file(&path)?;
        }
        fs::rename(&temp_path, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

pub(crate) fn persist_public_operator_history(snapshot: &PublicOperatorTelemetry) -> Result<()> {
    let path = public_operator_history_path()
        .context("public operator telemetry history path is not configured")?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut entries = fs::read_to_string(&path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| {
                    serde_json::from_str::<PersistedPublicOperatorHistoryEntry>(line).ok()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    entries.push(PersistedPublicOperatorHistoryEntry {
        observed_at_utc: snapshot.observed_at.to_rfc3339(),
        operators: snapshot.operators.clone(),
    });
    if entries.len() > PUBLIC_OPERATOR_HISTORY_MAX {
        entries.drain(..entries.len() - PUBLIC_OPERATOR_HISTORY_MAX);
    }
    let encoded = entries
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("operator-history.jsonl"),
        std::process::id()
    ));
    fs::write(&tmp, format!("{}\n", encoded))?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

pub(crate) fn persist_public_operator_job(job: &PersistedPublicOperatorJob) -> Result<()> {
    let path = public_operator_jobs_path()
        .context("public operator job persistence path is not configured")?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut jobs = fs::read_to_string(&path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| serde_json::from_str::<PersistedPublicOperatorJob>(line).ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Some(existing) = jobs
        .iter_mut()
        .find(|existing| existing.job_id == job.job_id)
    {
        *existing = job.clone();
    } else {
        jobs.push(job.clone());
    }
    if jobs.len() > PUBLIC_OPERATOR_JOB_HISTORY_MAX {
        jobs.drain(..jobs.len() - PUBLIC_OPERATOR_JOB_HISTORY_MAX);
    }
    let encoded = jobs
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("operator-jobs.jsonl"),
        std::process::id()
    ));
    fs::write(&tmp, format!("{}\n", encoded))?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

pub(crate) fn load_public_operator_jobs() -> Vec<serde_json::Value> {
    public_operator_jobs_path()
        .and_then(|path| fs::read_to_string(path).ok())
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| serde_json::from_str::<PersistedPublicOperatorJob>(line).ok())
                .map(|job| serde_json::to_value(job).unwrap_or(serde_json::Value::Null))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn reconcile_public_operator_job_records(
    jobs: &mut [PersistedPublicOperatorJob],
    completed_at_utc: &str,
) -> usize {
    let mut interrupted = 0usize;
    for job in jobs {
        if job.status == "running" {
            job.status = "interrupted".to_string();
            job.completed_at_utc = completed_at_utc.to_string();
            job.error_summary = Some("collector restarted before job completion".to_string());
            interrupted += 1;
        }
    }
    interrupted
}

/// Mark jobs that were persisted as running before a process restart. Keeping
/// an explicit interrupted outcome prevents the public job feed from claiming
/// that work is still active forever after a crash and gives operators a
/// durable recovery signal for the next collector cycle.
pub(crate) fn reconcile_public_operator_jobs() -> Result<usize> {
    let path = public_operator_jobs_path()
        .context("public operator job persistence path is not configured")?;
    let mut jobs = fs::read_to_string(&path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| serde_json::from_str::<PersistedPublicOperatorJob>(line).ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let now = Utc::now().to_rfc3339();
    let interrupted = reconcile_public_operator_job_records(&mut jobs, &now);
    if interrupted == 0 {
        return Ok(0);
    }
    let encoded = jobs
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("operator-jobs.jsonl"),
        std::process::id()
    ));
    fs::write(&tmp, format!("{}\n", encoded))?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    if let Err(error) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(error.into());
    }
    Ok(interrupted)
}

pub(crate) fn spawn_public_operator_collector() {
    if public_operator_telemetry_path().is_none() {
        return;
    }
    if let Ok(interrupted) = reconcile_public_operator_jobs() {
        if interrupted > 0 {
            eprintln!("Marked {interrupted} interrupted public operator collector job(s)");
        }
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PUBLIC_OPERATOR_CACHE_TTL);
        loop {
            interval.tick().await;
            let started_at = Utc::now();
            let job_id = hex::encode(rand::random::<[u8; 16]>());
            let started_at_utc = started_at.to_rfc3339();
            let mut regions = get_configured_operator_regions()
                .into_iter()
                .map(|(_, region)| region)
                .collect::<Vec<_>>();
            regions.sort();
            regions.dedup();
            if let Err(error) = persist_public_operator_job(&PersistedPublicOperatorJob {
                job_id: job_id.clone(),
                started_at_utc: started_at_utc.clone(),
                completed_at_utc: String::new(),
                status: "running".to_string(),
                regions: regions.clone(),
                operator_count: 0,
                reachable_count: 0,
                failure_count: 0,
                attempts: 0,
                retry_count: 0,
                error_summary: None,
            }) {
                eprintln!("Public operator collector start persistence failed: {error}");
            }
            let snapshot = PublicOperatorTelemetry {
                observed_at: started_at,
                cached_at: Instant::now(),
                operators: probe_public_operators_uncached().await,
            };
            let operator_count = snapshot.operators.len();
            let reachable_count = snapshot
                .operators
                .iter()
                .filter(|operator| operator["status"] == "reachable")
                .count();
            let failure_count = operator_count.saturating_sub(reachable_count);
            let attempts = snapshot
                .operators
                .iter()
                .filter_map(|operator| {
                    operator
                        .get("probe_attempts")
                        .and_then(serde_json::Value::as_u64)
                })
                .map(|value| value as usize)
                .sum::<usize>();
            let retry_count = attempts.saturating_sub(operator_count);
            let status = if operator_count == 0 || reachable_count == 0 {
                "failed"
            } else if failure_count > 0 {
                "degraded"
            } else {
                "succeeded"
            };
            if let Err(error) = persist_public_operator_telemetry(&snapshot) {
                eprintln!("Public operator telemetry persistence failed: {error}");
            }
            if let Err(error) = persist_public_operator_history(&snapshot) {
                eprintln!("Public operator telemetry history persistence failed: {error}");
            }
            if let Err(error) = persist_public_operator_job(&PersistedPublicOperatorJob {
                job_id,
                started_at_utc,
                completed_at_utc: Utc::now().to_rfc3339(),
                status: status.to_string(),
                regions: {
                    let mut observed_regions = snapshot
                        .operators
                        .iter()
                        .filter_map(|operator| operator.get("region"))
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    observed_regions.extend(regions);
                    observed_regions.sort();
                    observed_regions.dedup();
                    observed_regions
                },
                operator_count,
                reachable_count,
                failure_count,
                attempts,
                retry_count,
                error_summary: (failure_count > 0)
                    .then(|| format!("{failure_count} operator probe(s) failed")),
            }) {
                eprintln!("Public operator collector job persistence failed: {error}");
            }
        }
    });
}

pub(crate) async fn probe_public_operators_uncached() -> Vec<serde_json::Value> {
    const MAX_ATTEMPTS: usize = 3;
    let http = public_operator_http_client();
    let probes =
        get_configured_operator_regions()
            .into_iter()
            .enumerate()
            .map(|(index, (endpoint, region))| {
                let http = http.clone();
                async move {
                let client = OperatorClient::with_http_client(endpoint, http.clone());
                let start = std::time::Instant::now();
                let mut attempts = 0usize;
                let result = loop {
                    attempts += 1;
                    match tokio::time::timeout(PUBLIC_OPERATOR_PROBE_TIMEOUT, client.get_info()).await {
                        Ok(Ok(info)) => break Ok(info),
                        Ok(Err(error)) if attempts < MAX_ATTEMPTS => {
                            tokio::time::sleep(Duration::from_millis(75 * attempts as u64)).await;
                            let _ = error;
                        }
                        Err(_) if attempts < MAX_ATTEMPTS => {
                            tokio::time::sleep(Duration::from_millis(75 * attempts as u64)).await;
                        }
                        Ok(Err(error)) => break Err(error.to_string()),
                        Err(_) => break Err("probe timeout".to_string()),
                    }
                };
                match result {
                    Ok(info) => {
                        let self_signed = info.verify_identity_signature();
                        let identity_pinned = self_signed
                            && trusted_public_operator_identity(
                                &info.operator_id,
                                &info.operator_signing_pk_hex,
                            );
                        let now_utc = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|elapsed| elapsed.as_secs())
                            .unwrap_or(0);
                        let identity_status = public_operator_identity_status(
                            identity_pinned,
                            info.identity_expires_at_utc,
                            now_utc,
                        );
                        serde_json::json!({
                        "display_name": format!("Operator {}", index + 1),
                        "operator_id": public_operator_id(&info.operator_id, index),
                        "region": region,
                        "status": "reachable",
                        "identity_verification": if identity_pinned { "verified" } else { "unverified" },
                        "identity_self_signature": if self_signed { "valid" } else { "invalid" },
                        "identity_trust": if identity_pinned { "pinned" } else { "not_pinned" },
                        "identity_status": identity_status,
                        "identity_expires_at_utc": info.identity_expires_at_utc,
                        "identity_signature_present": !info.identity_signature_hex.is_empty(),
                        "latency_ms": start.elapsed().as_millis(),
                        "probe_attempts": attempts,
                        })
                    }
                    Err(error) => serde_json::json!({
                        "display_name": format!("Operator {}", index + 1),
                        "operator_id": format!("operator-{}", index + 1),
                        "region": region,
                        "status": "unreachable",
                        "identity_verification": "not_observed",
                        "identity_self_signature": "not_observed",
                        "identity_trust": "not_observed",
                        "identity_status": "not_observed",
                        "identity_signature_present": false,
                        "latency_ms": serde_json::Value::Null,
                        "probe_attempts": attempts,
                        "error": error,
                    }),
                }
                }
            });

    join_all(probes).await
}

pub(crate) async fn public_operator_telemetry() -> PublicOperatorTelemetry {
    if let Some(snapshot) = load_persisted_public_operator_telemetry() {
        let cache = PUBLIC_OPERATOR_TELEMETRY_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
        *cache.lock().await = Some(snapshot.clone());
        return snapshot;
    }
    let cache = PUBLIC_OPERATOR_TELEMETRY_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    let mut cached = cache.lock().await;
    if let Some(snapshot) = cached.as_ref() {
        if snapshot.cached_at.elapsed() < PUBLIC_OPERATOR_CACHE_TTL {
            return snapshot.clone();
        }
    }

    // Hold this lock while probing so a burst of browser requests has one
    // shared measurement instead of fanning out requests to every operator.
    let snapshot = PublicOperatorTelemetry {
        observed_at: Utc::now(),
        cached_at: Instant::now(),
        operators: probe_public_operators_uncached().await,
    };
    *cached = Some(snapshot.clone());
    snapshot
}

pub(crate) async fn api_public_operators_handler() -> axum::Json<serde_json::Value> {
    let telemetry = public_operator_telemetry().await;
    let observed_at = telemetry.observed_at.to_rfc3339();
    let operators = telemetry
        .operators
        .into_iter()
        .map(|mut operator| {
            if let Some(object) = operator.as_object_mut() {
                object.insert(
                    "observed_at".to_string(),
                    serde_json::Value::String(observed_at.clone()),
                );
            }
            operator
        })
        .collect::<Vec<_>>();
    axum::Json(serde_json::json!(operators))
}

pub(crate) async fn api_public_operators_history_handler() -> axum::Json<serde_json::Value> {
    let samples = public_operator_history_path()
        .and_then(|path| fs::read_to_string(path).ok())
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| {
                    serde_json::from_str::<PersistedPublicOperatorHistoryEntry>(line).ok()
                })
                .map(|entry| {
                    serde_json::json!({
                        "observed_at": entry.observed_at_utc,
                        "operators": entry.operators,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    axum::Json(serde_json::json!({
        "samples": samples,
        "sample_limit": PUBLIC_OPERATOR_HISTORY_MAX,
    }))
}

pub(crate) async fn api_public_operators_jobs_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "jobs": load_public_operator_jobs(),
        "job_limit": PUBLIC_OPERATOR_JOB_HISTORY_MAX,
        "message": "Collector job history is observational telemetry; it does not establish storage durability or quorum.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_operator_identity_requires_independent_pin() {
        let key = ciphervault_crypto::generate_signing_key();
        let key_hex = hex::encode(key.verifying_key().as_bytes());
        assert!(!trusted_public_operator_identity_from_registry(
            "",
            "operator-1",
            &key_hex
        ));
        assert!(trusted_public_operator_identity_from_registry(
            &format!("operator-1={key_hex}"),
            "operator-1",
            &key_hex,
        ));
        assert!(!trusted_public_operator_identity_from_registry(
            &format!("operator-1={key_hex}"),
            "operator-2",
            &key_hex,
        ));
        assert!(!trusted_public_operator_identity_from_registry(
            &format!("operator-1={key_hex}"),
            "operator-1",
            &"00".repeat(32),
        ));
        assert!(trusted_public_operator_identity_from_registry(
            &key_hex, "any-id", &key_hex,
        ));
    }

    #[test]
    fn public_operator_identity_status_tracks_pinning_and_expiry() {
        let now = 1_800_000_000u64;
        assert_eq!(public_operator_identity_status(true, 0, now), "verified");
        assert_eq!(
            public_operator_identity_status(true, now + 7 * 60 * 60, now),
            "verified"
        );
        assert_eq!(
            public_operator_identity_status(true, now + 5 * 60 * 60, now),
            "expiring_soon"
        );
        assert_eq!(
            public_operator_identity_status(true, now - 1, now),
            "expired"
        );
        assert_eq!(public_operator_identity_status(false, 0, now), "unverified");
        assert_eq!(
            public_operator_identity_status(false, now - 1, now),
            "expired"
        );
    }

    #[test]
    fn collector_restart_marks_inflight_jobs_interrupted() {
        let mut jobs = vec![
            PersistedPublicOperatorJob {
                job_id: "running".into(),
                started_at_utc: "2026-09-16T00:00:00Z".into(),
                completed_at_utc: String::new(),
                status: "running".into(),
                regions: vec!["default".into()],
                operator_count: 0,
                reachable_count: 0,
                failure_count: 0,
                attempts: 0,
                retry_count: 0,
                error_summary: None,
            },
            PersistedPublicOperatorJob {
                job_id: "done".into(),
                started_at_utc: "2026-09-16T00:00:00Z".into(),
                completed_at_utc: "2026-09-16T00:00:01Z".into(),
                status: "succeeded".into(),
                regions: vec!["default".into()],
                operator_count: 1,
                reachable_count: 1,
                failure_count: 0,
                attempts: 1,
                retry_count: 0,
                error_summary: None,
            },
        ];
        assert_eq!(
            reconcile_public_operator_job_records(&mut jobs, "2026-09-16T00:00:30Z"),
            1
        );
        assert_eq!(jobs[0].status, "interrupted");
        assert_eq!(jobs[0].completed_at_utc, "2026-09-16T00:00:30Z");
        assert!(jobs[0]
            .error_summary
            .as_deref()
            .is_some_and(|message| message.contains("restarted")));
        assert_eq!(jobs[1].status, "succeeded");
    }
}
