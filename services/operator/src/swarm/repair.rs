//! Repair assignment and pacing (DON Phase 4, repair protocol §2–§3).
//!
//! Holders detect under-replication, agree on ONE pusher per object via
//! rendezvous hashing, and backfill through the operator-signed
//! `RepairPush` RPC. Pushes are paced by a sender token bucket, suffer
//! the receiver's own repair budget (429 → backoff), and never hot-loop
//! thanks to per-CID cooldowns. Repair bytes are self-authenticating:
//! the receiver only stores bytes whose digest equals the CID, so a
//! repair push can never plant garbage — at most it burns budget, which
//! both sides bound.

use std::time::{Duration, Instant};

use libp2p::PeerId;

/// Repair knobs, bundled so `SwarmNodeConfig` grows by one field.
/// Defaults suit a small fleet; chaos gates and large meshes tune down
/// the interval and up the budgets.
#[derive(Debug, Clone)]
pub struct RepairConfig {
    /// Target live replicas per object.
    pub target: usize,
    /// Interval between repair-scan ticks.
    pub interval: Duration,
    /// Local objects assessed per tick (cursor-rotated).
    pub sample_size: usize,
    /// Cap on concurrent in-flight repair provider queries.
    pub max_queries: usize,
    /// Sender token-bucket refill: repair bytes per second.
    pub max_bytes_per_sec: u64,
    /// Cap on concurrent in-flight repair pushes.
    pub max_concurrent_pushes: usize,
    /// Base per-CID cooldown after any repair assessment.
    pub cooldown: Duration,
    /// Ceiling for failure backoff.
    pub max_backoff: Duration,
}

impl Default for RepairConfig {
    fn default() -> Self {
        Self {
            target: 3,
            interval: Duration::from_secs(30),
            sample_size: 16,
            max_queries: 16,
            max_bytes_per_sec: 8 * 1024 * 1024,
            max_concurrent_pushes: 4,
            cooldown: Duration::from_secs(60),
            max_backoff: Duration::from_secs(600),
        }
    }
}

/// Default receiver-side repair budget: repair bytes accepted per second
/// across all senders. Over-budget pushes are 429ed without storing.
pub const DEFAULT_REPAIR_BUDGET_PER_SEC: u64 = 8 * 1024 * 1024;

/// Signature domain for repair pushes.
pub const REPAIR_PUSH_DOMAIN: &[u8] = b"ciphervault_repair_push_v1";

/// One deterministic repair job: exactly one pusher backfills `recipients`
/// (possibly fewer than needed when candidates are scarce — the next
/// round completes it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    pub pusher: PeerId,
    pub recipients: Vec<PeerId>,
}

/// Rendezvous-hash repair plan. `holders` are LIVE holders (the caller
/// intersects providers with liveness and adds itself); `live` is the
/// full live set. Returns `None` when no repair is needed (holders at
/// target), no holder can push (empty holders), or no candidate exists.
/// Pure function of its inputs: every holder with the same view computes
/// the same pusher and recipients — that is what prevents N-holder
/// fan-out and duplicate backfills.
pub fn plan_repair(
    cid: &[u8; 32],
    holders: &[PeerId],
    live: &[PeerId],
    target: usize,
) -> Option<RepairPlan> {
    if target == 0 || holders.is_empty() || holders.len() >= target {
        return None;
    }
    let mut scored_holders: Vec<([u8; 32], PeerId)> = holders
        .iter()
        .map(|peer| (score(cid, peer), *peer))
        .collect();
    scored_holders.sort();
    let pusher = scored_holders[0].1;
    let needed = target - holders.len();
    let mut scored_candidates: Vec<([u8; 32], PeerId)> = live
        .iter()
        .filter(|peer| !holders.contains(peer))
        .map(|peer| (score(cid, peer), *peer))
        .collect();
    if scored_candidates.is_empty() {
        return None;
    }
    scored_candidates.sort();
    let recipients = scored_candidates
        .into_iter()
        .take(needed)
        .map(|(_, peer)| peer)
        .collect();
    Some(RepairPlan { pusher, recipients })
}

/// Rendezvous score: SHA-256 over the candidate identity and the object.
/// Lowest wins. Ties are impossible in practice (256-bit) but the
/// `(score, peer)` tuple sort keeps the order total regardless.
fn score(cid: &[u8; 32], peer: &PeerId) -> [u8; 32] {
    let mut input = peer.to_bytes();
    input.extend_from_slice(cid);
    ciphervault_format::compute_digest(&input)
}

/// Token bucket pacing repair bytes. Refills lazily on `try_take`;
/// capacity equals one second of rate (bounded burst).
#[derive(Debug)]
pub struct TokenBucket {
    per_sec: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(bytes_per_sec: u64) -> Self {
        Self::new_at(bytes_per_sec, Instant::now())
    }

    pub fn new_at(bytes_per_sec: u64, at: Instant) -> Self {
        let capacity = bytes_per_sec as f64;
        Self {
            per_sec: bytes_per_sec as f64,
            capacity,
            tokens: capacity,
            last: at,
        }
    }

    pub fn set_rate(&mut self, bytes_per_sec: u64) {
        self.per_sec = bytes_per_sec as f64;
        self.capacity = bytes_per_sec as f64;
        self.tokens = self.tokens.min(self.capacity);
    }

    /// Takes `bytes` if available now (after refill). A zero rate never
    /// admits; an admission larger than capacity never fits (fail closed
    /// rather than debt-spend).
    pub fn try_take(&mut self, bytes: u64) -> bool {
        self.refill();
        if (bytes as f64) <= self.tokens {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_sec).min(self.capacity);
    }
}

/// Exponential backoff for consecutive per-CID failures: `base * 2^fails`
/// capped at `max`, plus uniform jitter in `[0, base)` to desynchronize
/// herds. `fails` saturates (no overflow at any count).
pub fn backoff_for(fails: u32, base: Duration, max: Duration) -> Duration {
    let shifts = fails.min(10);
    let grown = base.saturating_mul(1 << shifts).min(max);
    let jitter_ms = if base.as_millis() == 0 {
        0
    } else {
        rand::random::<u64>() % (base.as_millis() as u64 + 1)
    };
    grown
        .saturating_add(Duration::from_millis(jitter_ms))
        .min(max)
}

/// Canonical bytes covered by a repair-push signature: the recipient
/// (anti-redirection), the CID, and the full object bytes.
pub fn repair_signing_bytes(recipient_operator_id: &str, cid: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(recipient_operator_id.len() + 32 + data.len() + 2);
    bytes.extend_from_slice(recipient_operator_id.as_bytes());
    bytes.extend_from_slice(b":");
    bytes.extend_from_slice(cid);
    bytes.extend_from_slice(b":");
    bytes.extend_from_slice(data);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::random()
    }

    fn cid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn plan_is_deterministic_and_disjoint() {
        let c = cid(9);
        let holders = vec![peer(), peer()];
        let mut live = holders.clone();
        let extra: Vec<PeerId> = (0..4).map(|_| peer()).collect();
        live.extend(extra.iter().cloned());
        let plan = plan_repair(&c, &holders, &live, 4).expect("plan exists");
        // Same inputs, any order → same plan.
        let mut shuffled = live.clone();
        shuffled.reverse();
        let plan2 = plan_repair(&c, &holders, &shuffled, 4).expect("plan exists");
        assert_eq!(plan, plan2);
        // Pusher is a holder; recipients are live non-holders; count fits.
        assert!(holders.contains(&plan.pusher));
        assert_eq!(plan.recipients.len(), 2);
        for recipient in &plan.recipients {
            assert!(live.contains(recipient));
            assert!(!holders.contains(recipient));
        }
    }

    #[test]
    fn plan_edges_noop_without_work() {
        let c = cid(1);
        let holders = vec![peer(), peer(), peer()];
        let live = holders.clone();
        assert_eq!(plan_repair(&c, &holders, &live, 3), None);
        assert_eq!(plan_repair(&c, &[], &live, 3), None);
        assert_eq!(plan_repair(&c, &holders, &live, 0), None);
        // No live non-holders: nothing to push to.
        assert_eq!(plan_repair(&c, &holders[..1], &holders[..1], 3), None);
    }

    #[test]
    fn plan_is_partial_when_candidates_scarce() {
        let c = cid(2);
        let holder = peer();
        let only = peer();
        let live = vec![holder, only];
        let plan = plan_repair(&c, &[holder], &live, 5).expect("partial plan");
        assert_eq!(plan.pusher, holder);
        assert_eq!(plan.recipients, vec![only]);
    }

    #[test]
    fn plan_recipients_are_lowest_scored() {
        let c = cid(3);
        let holder = peer();
        let candidates: Vec<PeerId> = (0..8).map(|_| peer()).collect();
        let mut live = vec![holder];
        live.extend(candidates.iter().cloned());
        let plan = plan_repair(&c, &[holder], &live, 4).expect("plan");
        assert_eq!(plan.recipients.len(), 3);
        // Every recipient outranks every non-recipient candidate.
        let mut scored: Vec<([u8; 32], PeerId)> = candidates
            .iter()
            .map(|peer| (score(&c, peer), *peer))
            .collect();
        scored.sort();
        let expected: Vec<PeerId> = scored.into_iter().take(3).map(|(_, peer)| peer).collect();
        assert_eq!(plan.recipients, expected);
    }

    #[test]
    fn bucket_paces_and_refills() {
        let start = Instant::now() - Duration::from_secs(10);
        let mut bucket = TokenBucket::new_at(1000, start);
        assert!(bucket.try_take(1000));
        assert!(!bucket.try_take(1));
        // Refill over time (sleep a hair past 100ms for 100 tokens).
        std::thread::sleep(Duration::from_millis(120));
        assert!(bucket.try_take(100));
        assert!(!bucket.try_take(1000));
    }

    #[test]
    fn bucket_zero_rate_never_admits() {
        let mut bucket = TokenBucket::new(0);
        // Any nonzero take fails; the bucket starts and stays empty.
        assert!(!bucket.try_take(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!bucket.try_take(1));
    }

    #[test]
    fn bucket_oversize_never_fits() {
        let mut bucket = TokenBucket::new(100);
        assert!(!bucket.try_take(101));
        assert!(bucket.try_take(100));
    }

    #[test]
    fn backoff_grows_and_caps() {
        let base = Duration::from_secs(60);
        let max = Duration::from_secs(600);
        let first = backoff_for(0, base, max);
        assert!(first >= base && first <= base + base);
        let second = backoff_for(1, base, max);
        assert!(second >= base * 2 && second <= base * 2 + base);
        // Saturation: huge fail counts pin at max, never overflow.
        assert_eq!(backoff_for(u32::MAX, base, max), max);
        assert_eq!(backoff_for(100, base, max), max);
    }

    #[test]
    fn repair_signing_bytes_bind_recipient_cid_and_data() {
        let a = repair_signing_bytes("op-b", &cid(1), b"data");
        let b = repair_signing_bytes("op-c", &cid(1), b"data");
        let c = repair_signing_bytes("op-b", &cid(2), b"data");
        let d = repair_signing_bytes("op-b", &cid(1), b"DATA");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }
}
