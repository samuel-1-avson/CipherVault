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

/// Reserved Prometheus series names for the decentralized swarm (DON plan,
/// Phase 0). Name reservation only: these series are NOT rendered until the
/// swarm lands, so exposition output is byte-identical with or without them.
pub const SWARM_METRIC_NAMES: &[&str] = &[
    "ciphervault_swarm_peers_connected",
    "ciphervault_swarm_dht_lookups_total",
    "ciphervault_swarm_dht_lookup_failures_total",
    "ciphervault_swarm_chunk_pushes_total",
    "ciphervault_swarm_chunk_gets_total",
    // NOTE: `ciphervault_swarm_repair_bytes_total` graduated from this
    // list in Phase 4 slice 2 (it renders below now).
    "ciphervault_swarm_dht_lookup_latency_ms",
];

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
    heartbeats_sent_total: AtomicU64,
    heartbeats_received_total: AtomicU64,
    heartbeats_dropped_bad_envelope_total: AtomicU64,
    heartbeats_dropped_bad_version_total: AtomicU64,
    heartbeats_dropped_clock_skew_total: AtomicU64,
    heartbeats_dropped_unknown_sender_total: AtomicU64,
    heartbeats_dropped_bad_signature_total: AtomicU64,
    heartbeats_dropped_stale_seq_total: AtomicU64,
    control_unknown_kind_ignored_total: AtomicU64,
    peers_live: AtomicU64,
    peer_joins_total: AtomicU64,
    peer_graduations_total: AtomicU64,
    repair_checks_total: AtomicU64,
    repair_jobs_started_total: AtomicU64,
    repair_jobs_completed_total: AtomicU64,
    repair_jobs_failed_total: AtomicU64,
    repair_backoff_total: AtomicU64,
    repair_cooldown_suppressed_total: AtomicU64,
    repair_bucket_deferred_total: AtomicU64,
    repair_budget_exhausted_total: AtomicU64,
    repair_bytes_total: AtomicU64,
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
            heartbeats_sent_total: AtomicU64::new(0),
            heartbeats_received_total: AtomicU64::new(0),
            heartbeats_dropped_bad_envelope_total: AtomicU64::new(0),
            heartbeats_dropped_bad_version_total: AtomicU64::new(0),
            heartbeats_dropped_clock_skew_total: AtomicU64::new(0),
            heartbeats_dropped_unknown_sender_total: AtomicU64::new(0),
            heartbeats_dropped_bad_signature_total: AtomicU64::new(0),
            heartbeats_dropped_stale_seq_total: AtomicU64::new(0),
            control_unknown_kind_ignored_total: AtomicU64::new(0),
            peers_live: AtomicU64::new(0),
            peer_joins_total: AtomicU64::new(0),
            peer_graduations_total: AtomicU64::new(0),
            repair_checks_total: AtomicU64::new(0),
            repair_jobs_started_total: AtomicU64::new(0),
            repair_jobs_completed_total: AtomicU64::new(0),
            repair_jobs_failed_total: AtomicU64::new(0),
            repair_backoff_total: AtomicU64::new(0),
            repair_cooldown_suppressed_total: AtomicU64::new(0),
            repair_bucket_deferred_total: AtomicU64::new(0),
            repair_budget_exhausted_total: AtomicU64::new(0),
            repair_bytes_total: AtomicU64::new(0),
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

    /// Records one heartbeat published on the control topic.
    pub fn observe_heartbeat_sent(&self) {
        self.heartbeats_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one heartbeat that verified and advanced liveness.
    pub fn observe_heartbeat_received(&self) {
        self.heartbeats_received_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one dropped heartbeat by verification-stage reason.
    /// `reason` must be one of: `bad_envelope`, `bad_version`,
    /// `clock_skew`, `unknown_sender`, `bad_signature`, `stale_seq`.
    /// Unknown reasons are ignored (never panic on a metric path).
    pub fn observe_heartbeat_dropped(&self, reason: &str) {
        let counter = match reason {
            "bad_envelope" => &self.heartbeats_dropped_bad_envelope_total,
            "bad_version" => &self.heartbeats_dropped_bad_version_total,
            "clock_skew" => &self.heartbeats_dropped_clock_skew_total,
            "unknown_sender" => &self.heartbeats_dropped_unknown_sender_total,
            "bad_signature" => &self.heartbeats_dropped_bad_signature_total,
            "stale_seq" => &self.heartbeats_dropped_stale_seq_total,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one well-formed control message of an unknown kind that
    /// was ignored for forward compatibility.
    pub fn observe_control_unknown_kind(&self) {
        self.control_unknown_kind_ignored_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Sets the current live-peer gauge. Called by the swarm loop, which
    /// owns the liveness view; the gauge renders the last set value.
    pub fn set_peers_live(&self, live: u64) {
        self.peers_live.store(live, Ordering::Relaxed);
    }

    /// Records one verified ticket join admitted into probation.
    pub fn observe_peer_joined(&self) {
        self.peer_joins_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one probation-to-full graduation (earned or admin-granted).
    pub fn observe_peer_graduated(&self) {
        self.peer_graduations_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one repair assessment (provider query answered, plan
    /// computed — whatever the outcome).
    pub fn observe_repair_check(&self) {
        self.repair_checks_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one repair push sent (sender side).
    pub fn observe_repair_started(&self) {
        self.repair_jobs_started_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one repair push that finished OK. Fed by both roles:
    /// senders count `RepairDone`, receivers count accepts.
    pub fn observe_repair_completed(&self) {
        self.repair_jobs_completed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one repair push that failed (any role, any terminal
    /// reason except receiver budget exhaustion, which has its own
    /// series so 429s are distinguishable from rejections).
    pub fn observe_repair_failed(&self) {
        self.repair_jobs_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one sender backoff scheduled after a 429 or transport
    /// failure (paced retry, not a terminal failure).
    pub fn observe_repair_backoff(&self) {
        self.repair_backoff_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one repair assessment skipped by per-CID cooldown.
    pub fn observe_repair_cooldown_suppressed(&self) {
        self.repair_cooldown_suppressed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one planned push deferred for lack of sender bucket
    /// tokens (repair falling behind its bandwidth budget).
    pub fn observe_repair_bucket_deferred(&self) {
        self.repair_bucket_deferred_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one push 429ed by the receiver-side repair budget.
    pub fn observe_repair_budget_exhausted(&self) {
        self.repair_budget_exhausted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records repair bytes on the wire (sender counts at send,
    /// receiver at accept).
    pub fn observe_repair_bytes(&self, bytes: u64) {
        self.repair_bytes_total.fetch_add(bytes, Ordering::Relaxed);
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
            self.recovery_records_read_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_operator_auth_failures_total",
            "Session validations that failed.",
            self.auth_failures_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_heartbeats_sent_total",
            "Liveness heartbeats published on the control topic.",
            self.heartbeats_sent_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_heartbeats_received_total",
            "Heartbeats that verified and advanced liveness.",
            self.heartbeats_received_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_heartbeats_dropped_bad_envelope_total",
            "Control messages that did not parse as a control envelope.",
            self.heartbeats_dropped_bad_envelope_total
                .load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_heartbeats_dropped_bad_version_total",
            "Heartbeats with an unknown wire version.",
            self.heartbeats_dropped_bad_version_total
                .load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_heartbeats_dropped_clock_skew_total",
            "Heartbeats outside the accepted clock-skew window.",
            self.heartbeats_dropped_clock_skew_total
                .load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_heartbeats_dropped_unknown_sender_total",
            "Heartbeats from operators with no verified announced key.",
            self.heartbeats_dropped_unknown_sender_total
                .load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_heartbeats_dropped_bad_signature_total",
            "Heartbeats failing signature verification.",
            self.heartbeats_dropped_bad_signature_total
                .load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_heartbeats_dropped_stale_seq_total",
            "Heartbeats with replayed or reordered sequence numbers.",
            self.heartbeats_dropped_stale_seq_total
                .load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_control_unknown_kind_ignored_total",
            "Well-formed control messages of unknown kinds ignored for forward compatibility.",
            self.control_unknown_kind_ignored_total
                .load(Ordering::Relaxed),
        );
        render_gauge(
            &mut out,
            "ciphervault_swarm_peers_live",
            "Peers with a heartbeat inside the liveness timeout.",
            self.peers_live.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_peer_joins_total",
            "Verified ticket joins admitted into probation.",
            self.peer_joins_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_peer_graduations_total",
            "Probation-to-full graduations (earned or admin-granted).",
            self.peer_graduations_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_checks_total",
            "Repair assessments completed (plan computed).",
            self.repair_checks_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_jobs_started_total",
            "Repair pushes sent.",
            self.repair_jobs_started_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_jobs_completed_total",
            "Repair pushes finished OK (sender RepairDone + receiver accepts).",
            self.repair_jobs_completed_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_jobs_failed_total",
            "Repair pushes terminally failed (either role).",
            self.repair_jobs_failed_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_backoff_total",
            "Sender backoffs scheduled after 429 or transport failure.",
            self.repair_backoff_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_cooldown_suppressed_total",
            "Repair assessments skipped by per-CID cooldown.",
            self.repair_cooldown_suppressed_total
                .load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_bucket_deferred_total",
            "Planned pushes deferred for lack of sender bucket tokens.",
            self.repair_bucket_deferred_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_budget_exhausted_total",
            "Pushes 429ed by the receiver-side repair budget.",
            self.repair_budget_exhausted_total.load(Ordering::Relaxed),
        );
        render_counter(
            &mut out,
            "ciphervault_swarm_repair_bytes_total",
            "Repair bytes on the wire (sent + accepted).",
            self.repair_bytes_total.load(Ordering::Relaxed),
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

fn render_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} gauge\n"));
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
