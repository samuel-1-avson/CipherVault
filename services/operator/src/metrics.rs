//! Dependency-free operator metrics and request spans (R11).
//!
//! Atomic counters and fixed-bucket latency histograms back the Prometheus
//! `/metrics` endpoint. [`OperatorMetrics::observe_request`] additionally
//! records one structured span per request (a JSON access line on stderr when
//! `CIPHERVAULT_TRACE_LOG` is set), correlated by the client-supplied trace ID.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

/// Histogram bucket upper bounds in milliseconds.
const LATENCY_BOUNDS_MS: [u64; 6] = [1, 5, 25, 100, 500, 5000];

/// Fixed-bucket latency histogram over atomic counters (cumulative buckets).
pub struct LatencyHistogram {
    buckets: [AtomicU64; 6],
    sum_ms: AtomicU64,
    count: AtomicU64,
}

impl LatencyHistogram {
    fn new() -> Self {
        Self {
            buckets: [(); 6].map(|()| AtomicU64::new(0)),
            sum_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, elapsed: Duration) {
        let ms: u64 = elapsed.as_millis().try_into().unwrap_or(u64::MAX);
        for (bound, bucket) in LATENCY_BOUNDS_MS.iter().zip(self.buckets.iter()) {
            if ms <= *bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum_ms.fetch_add(ms, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} histogram\n"));
        for (bound, bucket) in LATENCY_BOUNDS_MS.iter().zip(self.buckets.iter()) {
            out.push_str(&format!(
                "{name}_bucket{{le=\"{bound}\"}} {}\n",
                bucket.load(Ordering::Relaxed)
            ));
        }
        let count = self.count.load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
        out.push_str(&format!(
            "{name}_sum {}\n{name}_count {count}\n",
            self.sum_ms.load(Ordering::Relaxed)
        ));
    }
}

/// Process-wide operator metrics. Everything is interior-mutable so `&self`
/// state methods and the trace middleware can record without signature changes.
pub struct OperatorMetrics {
    requests_total: AtomicU64,
    requests_4xx_total: AtomicU64,
    requests_5xx_total: AtomicU64,
    objects_put_total: AtomicU64,
    objects_put_bytes_total: AtomicU64,
    objects_put_failures_total: AtomicU64,
    objects_get_total: AtomicU64,
    objects_get_bytes_total: AtomicU64,
    pos_challenges_total: AtomicU64,
    pos_failures_total: AtomicU64,
    leases_created_total: AtomicU64,
    leases_renewed_total: AtomicU64,
    lease_failures_total: AtomicU64,
    recovery_appends_total: AtomicU64,
    recovery_append_bytes_total: AtomicU64,
    recovery_reads_total: AtomicU64,
    recovery_records_read_total: AtomicU64,
    auth_failures_total: AtomicU64,
    request_latency_ms: LatencyHistogram,
    put_latency_ms: LatencyHistogram,
    get_latency_ms: LatencyHistogram,
    pos_latency_ms: LatencyHistogram,
    started_at_unix: u64,
}

impl OperatorMetrics {
    pub fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_4xx_total: AtomicU64::new(0),
            requests_5xx_total: AtomicU64::new(0),
            objects_put_total: AtomicU64::new(0),
            objects_put_bytes_total: AtomicU64::new(0),
            objects_put_failures_total: AtomicU64::new(0),
            objects_get_total: AtomicU64::new(0),
            objects_get_bytes_total: AtomicU64::new(0),
            pos_challenges_total: AtomicU64::new(0),
            pos_failures_total: AtomicU64::new(0),
            leases_created_total: AtomicU64::new(0),
            leases_renewed_total: AtomicU64::new(0),
            lease_failures_total: AtomicU64::new(0),
            recovery_appends_total: AtomicU64::new(0),
            recovery_append_bytes_total: AtomicU64::new(0),
            recovery_reads_total: AtomicU64::new(0),
            recovery_records_read_total: AtomicU64::new(0),
            auth_failures_total: AtomicU64::new(0),
            request_latency_ms: LatencyHistogram::new(),
            put_latency_ms: LatencyHistogram::new(),
            get_latency_ms: LatencyHistogram::new(),
            pos_latency_ms: LatencyHistogram::new(),
            started_at_unix: unix_now(),
        }
    }

    /// Records one completed HTTP request (trace middleware).
    pub fn observe_request(
        &self,
        route: &str,
        status: u16,
        elapsed: Duration,
        trace_id: Option<&str>,
    ) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if (400..500).contains(&status) {
            self.requests_4xx_total.fetch_add(1, Ordering::Relaxed);
        } else if status >= 500 {
            self.requests_5xx_total.fetch_add(1, Ordering::Relaxed);
        }
        self.request_latency_ms.observe(elapsed);
        log_span(route, trace_id, status, elapsed);
    }

    /// Records one object write with its store latency (push-latency signal).
    pub fn observe_put(&self, bytes: u64, elapsed: Duration, ok: bool) {
        if ok {
            self.objects_put_total.fetch_add(1, Ordering::Relaxed);
            self.objects_put_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.objects_put_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
        self.put_latency_ms.observe(elapsed);
    }

    /// Records one object read; `hit_bytes` is `Some` on a cache/store hit.
    pub fn observe_get(&self, hit_bytes: Option<u64>, elapsed: Duration) {
        self.objects_get_total.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = hit_bytes {
            self.objects_get_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
        self.get_latency_ms.observe(elapsed);
    }

    /// Records one Proof-of-Storage challenge (PoS-rate signal).
    pub fn observe_pos(&self, elapsed: Duration, ok: bool) {
        self.pos_challenges_total.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.pos_failures_total.fetch_add(1, Ordering::Relaxed);
        }
        self.pos_latency_ms.observe(elapsed);
    }

    pub fn observe_lease_create(&self, ok: bool) {
        if ok {
            self.leases_created_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.lease_failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn observe_lease_renew(&self, ok: bool) {
        if ok {
            self.leases_renewed_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.lease_failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn observe_recovery_append(&self, bytes: u64, ok: bool) {
        if ok {
            self.recovery_appends_total.fetch_add(1, Ordering::Relaxed);
            self.recovery_append_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn observe_recovery_read(&self, records: &[Vec<u8>]) {
        self.recovery_reads_total.fetch_add(1, Ordering::Relaxed);
        self.recovery_records_read_total
            .fetch_add(records.len() as u64, Ordering::Relaxed);
    }

    pub fn observe_auth_failure(&self) {
        self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn uptime_secs(&self) -> u64 {
        unix_now().saturating_sub(self.started_at_unix)
    }

    /// Renders all counters in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        render_counter(
            &mut out,
            "ciphervault_operator_requests_total",
            "Total HTTP requests served.",
            self.requests_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_requests_4xx_total",
            "HTTP requests completed with a 4xx status.",
            self.requests_4xx_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_requests_5xx_total",
            "HTTP requests completed with a 5xx status.",
            self.requests_5xx_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_objects_put_total",
            "Objects stored successfully.",
            self.objects_put_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_objects_put_bytes_total",
            "Stored object bytes.",
            self.objects_put_bytes_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_objects_put_failures_total",
            "Object writes rejected (size, CID, or digest).",
            self.objects_put_failures_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_objects_get_total",
            "Object reads attempted.",
            self.objects_get_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_objects_get_bytes_total",
            "Object bytes served on reads.",
            self.objects_get_bytes_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_pos_challenges_total",
            "Proof-of-Storage challenges served.",
            self.pos_challenges_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_pos_failures_total",
            "Proof-of-Storage challenges that failed.",
            self.pos_failures_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_leases_created_total",
            "Leases created.",
            self.leases_created_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_leases_renewed_total",
            "Leases renewed.",
            self.leases_renewed_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_lease_failures_total",
            "Lease create/renew operations that failed.",
            self.lease_failures_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_recovery_appends_total",
            "Recovery records appended.",
            self.recovery_appends_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_recovery_append_bytes_total",
            "Recovery record bytes appended.",
            self.recovery_append_bytes_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_recovery_reads_total",
            "Recovery log reads.",
            self.recovery_reads_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_recovery_records_read_total",
            "Recovery records returned by reads.",
            self.recovery_records_read_total
                .load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_auth_failures_total",
            "Session validations that failed.",
            self.auth_failures_total.load(Ordering::Relaxed),
        );
        out.push_str("# HELP ciphervault_operator_uptime_seconds Seconds since process start.\n");
        out.push_str("# TYPE ciphervault_operator_uptime_seconds gauge\n");
        out.push_str(&format!(
            "ciphervault_operator_uptime_seconds {}\n",
            self.uptime_secs()
        ));
        self.request_latency_ms.render(
            &mut out,
            "ciphervault_operator_request_latency_ms",
            "End-to-end HTTP request latency in milliseconds.",
        );
        self.put_latency_ms.render(
            &mut out,
            "ciphervault_operator_put_latency_ms",
            "Object store latency in milliseconds.",
        );
        self.get_latency_ms.render(
            &mut out,
            "ciphervault_operator_get_latency_ms",
            "Object read latency in milliseconds.",
        );
        self.pos_latency_ms.render(
            &mut out,
            "ciphervault_operator_pos_latency_ms",
            "Proof-of-Storage challenge latency in milliseconds.",
        );
        out
    }
}

impl Default for OperatorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

fn render_counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    out.push_str(&format!("{name} {value}\n"));
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn trace_log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CIPHERVAULT_TRACE_LOG")
            .ok()
            .is_some_and(|value| {
                !matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "" | "0" | "false" | "no"
                )
            })
    })
}

fn log_span(route: &str, trace_id: Option<&str>, status: u16, elapsed: Duration) {
    if !trace_log_enabled() {
        return;
    }
    let elapsed_ms: u64 = elapsed.as_millis().try_into().unwrap_or(u64::MAX);
    eprintln!(
        "{}",
        serde_json::json!({
            "span": "operator_request",
            "route": route,
            "trace_id": trace_id,
            "status": status,
            "elapsed_ms": elapsed_ms,
        })
    );
}

/// Validates and normalizes a client trace ID: exactly 32 hex characters.
pub fn parse_trace_id(value: &str) -> Option<String> {
    let id = value.trim().to_ascii_lowercase();
    if id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(id)
    } else {
        None
    }
}
