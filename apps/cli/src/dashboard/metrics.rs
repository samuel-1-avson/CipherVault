//! Prometheus metrics exposition endpoint for CipherVault Explorer.
//!
//! Generates OpenMetrics / Prometheus 0.0.4 text format telemetry
//! covering operator reachability, latencies, checkpoint finality,
//! reorg suspect counts, PoS probe cache stats, and rate limiter windows.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::dashboard::collectors::public_operator_telemetry;
use crate::dashboard::finality::{explorer_probe_cache_stats, load_public_feed_with_finality};
use crate::dashboard::router::RateLimiter;

/// Escapes a label value according to Prometheus text exposition format rules:
/// backslash (\), double-quote ("), and newline (\n) must be escaped.
pub(crate) fn escape_prometheus_label_value(val: &str) -> String {
    let mut out = String::with_capacity(val.len());
    for c in val.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Formats and renders all Prometheus metrics as a UTF-8 text string.
pub(crate) async fn render_prometheus_metrics(limiter: Option<&RateLimiter>) -> String {
    let mut buffer = String::with_capacity(4096);

    // 1. Build Info
    buffer.push_str("# HELP ciphervault_build_info Build and version metadata\n");
    buffer.push_str("# TYPE ciphervault_build_info gauge\n");
    buffer.push_str(&format!(
        "ciphervault_build_info{{version=\"{}\"}} 1\n\n",
        escape_prometheus_label_value(env!("CARGO_PKG_VERSION"))
    ));

    // 2. Operator Telemetry
    let telemetry = public_operator_telemetry().await;
    let total_operators = telemetry.operators.len();
    let reachable_operators = telemetry
        .operators
        .iter()
        .filter(|op| op.get("status").and_then(|s| s.as_str()) == Some("reachable"))
        .count();
    let unreachable_operators = total_operators.saturating_sub(reachable_operators);

    buffer.push_str(
        "# HELP ciphervault_operators_total Total number of configured storage operators\n",
    );
    buffer.push_str("# TYPE ciphervault_operators_total gauge\n");
    buffer.push_str(&format!(
        "ciphervault_operators_total {}\n\n",
        total_operators
    ));

    buffer.push_str(
        "# HELP ciphervault_operators_reachable Total storage operators currently reachable\n",
    );
    buffer.push_str("# TYPE ciphervault_operators_reachable gauge\n");
    buffer.push_str(&format!(
        "ciphervault_operators_reachable {}\n\n",
        reachable_operators
    ));

    buffer.push_str(
        "# HELP ciphervault_operators_unreachable Total storage operators currently unreachable\n",
    );
    buffer.push_str("# TYPE ciphervault_operators_unreachable gauge\n");
    buffer.push_str(&format!(
        "ciphervault_operators_unreachable {}\n\n",
        unreachable_operators
    ));

    // Per-operator status & latency
    buffer.push_str("# HELP ciphervault_operator_reachable Reachability status per operator (1 = reachable, 0 = unreachable)\n");
    buffer.push_str("# TYPE ciphervault_operator_reachable gauge\n");
    for op in &telemetry.operators {
        let op_id = op
            .get("operator_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let region = op
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let identity_status = op
            .get("identity_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unverified");
        let is_reachable = op.get("status").and_then(|s| s.as_str()) == Some("reachable");
        let val = if is_reachable { 1 } else { 0 };

        buffer.push_str(&format!(
            "ciphervault_operator_reachable{{operator_id=\"{}\",region=\"{}\",identity_status=\"{}\"}} {}\n",
            escape_prometheus_label_value(op_id),
            escape_prometheus_label_value(region),
            escape_prometheus_label_value(identity_status),
            val
        ));
    }
    buffer.push('\n');

    buffer.push_str("# HELP ciphervault_operator_latency_seconds Observed round-trip latency to operator in seconds\n");
    buffer.push_str("# TYPE ciphervault_operator_latency_seconds gauge\n");
    for op in &telemetry.operators {
        if let Some(latency_ms) = op.get("latency_ms").and_then(|v| v.as_f64()) {
            let op_id = op
                .get("operator_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let region = op
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let latency_secs = latency_ms / 1000.0;
            buffer.push_str(&format!(
                "ciphervault_operator_latency_seconds{{operator_id=\"{}\",region=\"{}\"}} {:.6}\n",
                escape_prometheus_label_value(op_id),
                escape_prometheus_label_value(region),
                latency_secs
            ));
        }
    }
    buffer.push('\n');

    buffer.push_str("# HELP ciphervault_operator_probe_attempts Probe retry attempts during last reachability check\n");
    buffer.push_str("# TYPE ciphervault_operator_probe_attempts gauge\n");
    for op in &telemetry.operators {
        let op_id = op
            .get("operator_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let attempts = op
            .get("probe_attempts")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        buffer.push_str(&format!(
            "ciphervault_operator_probe_attempts{{operator_id=\"{}\"}} {}\n",
            escape_prometheus_label_value(op_id),
            attempts
        ));
    }
    buffer.push('\n');

    // 3. Arbitrum L2 Anchors & Checkpoints
    let checkpoints = load_public_feed_with_finality()
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let checkpoints_count = checkpoints.len();

    buffer.push_str(
        "# HELP ciphervault_checkpoints_total Total verified L2 checkpoints in published feed\n",
    );
    buffer.push_str("# TYPE ciphervault_checkpoints_total gauge\n");
    buffer.push_str(&format!(
        "ciphervault_checkpoints_total {}\n\n",
        checkpoints_count
    ));

    if let Some(head) = checkpoints.first() {
        if let Some(block) = head.get("reported_block_number").and_then(|v| v.as_u64()) {
            buffer.push_str("# HELP ciphervault_anchor_block_height Latest verified Arbitrum L2 anchor block height\n");
            buffer.push_str("# TYPE ciphervault_anchor_block_height gauge\n");
            buffer.push_str(&format!("ciphervault_anchor_block_height {}\n\n", block));
        }
    }

    let reorg_suspects = checkpoints
        .iter()
        .filter(|cp| cp.get("finality_status").and_then(|v| v.as_str()) == Some("reorg_suspected"))
        .count();

    buffer.push_str(
        "# HELP ciphervault_reorg_suspects_total Total detected Arbitrum blockchain reorg events\n",
    );
    buffer.push_str("# TYPE ciphervault_reorg_suspects_total counter\n");
    buffer.push_str(&format!(
        "ciphervault_reorg_suspects_total {}\n\n",
        reorg_suspects
    ));

    // 4. Proof of Storage (PoS) Probe Cache & Semaphore
    let (cache_entries, in_flight) = explorer_probe_cache_stats().await;

    buffer.push_str("# HELP ciphervault_pos_probe_cache_entries Active cached Proof-of-Storage probe responses\n");
    buffer.push_str("# TYPE ciphervault_pos_probe_cache_entries gauge\n");
    buffer.push_str(&format!(
        "ciphervault_pos_probe_cache_entries {}\n\n",
        cache_entries
    ));

    buffer.push_str("# HELP ciphervault_pos_probes_in_flight Outbound Proof-of-Storage probes currently in-flight\n");
    buffer.push_str("# TYPE ciphervault_pos_probes_in_flight gauge\n");
    buffer.push_str(&format!(
        "ciphervault_pos_probes_in_flight {}\n\n",
        in_flight
    ));

    // 5. In-App Rate Limiter Metrics
    if let Some(limiter) = limiter {
        let tracked_clients = limiter.tracked_clients_count();
        buffer.push_str("# HELP ciphervault_rate_limit_tracked_clients Active client rate limit windows tracked in memory\n");
        buffer.push_str("# TYPE ciphervault_rate_limit_tracked_clients gauge\n");
        buffer.push_str(&format!(
            "ciphervault_rate_limit_tracked_clients {}\n\n",
            tracked_clients
        ));
    }

    buffer
}

/// Handler for `GET /metrics` and `GET /api/metrics`.
pub(crate) async fn api_public_metrics_handler(
    limiter: Option<axum::Extension<RateLimiter>>,
) -> Response {
    let limiter_ref = limiter.as_ref().map(|ext| &ext.0);
    let body = render_prometheus_metrics(limiter_ref).await;

    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-store, must-revalidate"),
            ),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_label_escaping_handles_special_characters() {
        assert_eq!(escape_prometheus_label_value("simple"), "simple");
        assert_eq!(
            escape_prometheus_label_value("quote\"test"),
            "quote\\\"test"
        );
        assert_eq!(
            escape_prometheus_label_value("slash\\test"),
            "slash\\\\test"
        );
        assert_eq!(escape_prometheus_label_value("line\ntest"), "line\\ntest");
        assert_eq!(
            escape_prometheus_label_value("mix\"\\end"),
            "mix\\\"\\\\end"
        );
    }
}
