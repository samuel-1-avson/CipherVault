//! Signed liveness heartbeats (DON Phase 4, repair protocol §1).
//!
//! Every swarm node gossips a signed [`Heartbeat`] on the control topic.
//! Receivers verify (envelope → version → clock skew → known sender →
//! signature → monotonic seq) and track liveness locally. There are no
//! death claims on the wire: a peer is live while its heartbeats arrive
//! within the timeout, so there is nothing to forge and views converge
//! without trust. Authorship comes ONLY from the inner ed25519
//! signature — the gossipsub forwarder is never the author.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

/// Heartbeat wire version. Bumped only for incompatible changes; unknown
/// versions are rejected (not ignored) so a bad sender is penalized.
pub const HEARTBEAT_VERSION: u32 = 1;
/// Signature domain separation (see `sign_with_domain`).
pub const HEARTBEAT_DOMAIN: &[u8] = b"ciphervault_heartbeat_v1";
/// Maximum accepted clock skew in either direction. Bounds the replay
/// window together with the monotonic seq.
pub const HEARTBEAT_CLOCK_SKEW_MS: u64 = 60_000;
/// Default gossip interval between heartbeats.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// Default liveness timeout (3x the interval).
pub const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);

/// One signed liveness claim. The `peer_id` is the sender's claimed
/// libp2p identity (base58); it is trusted only because the signature
/// binds it to the sender's announced operator key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Heartbeat {
    pub version: u32,
    pub operator_id: String,
    pub peer_id: String,
    pub seq: u64,
    pub wall_time_ms: u64,
    pub signer_pk_hex: String,
    pub signature_hex: String,
}

impl Heartbeat {
    pub fn new(
        operator_id: String,
        peer_id: PeerId,
        seq: u64,
        wall_time_ms: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let mut hb = Self {
            version: HEARTBEAT_VERSION,
            operator_id,
            peer_id: peer_id.to_string(),
            seq,
            wall_time_ms,
            signer_pk_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            signature_hex: String::new(),
        };
        hb.sign(signing_key);
        hb
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(self.operator_id.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.peer_id.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&self.seq.to_le_bytes());
        bytes.extend_from_slice(&self.wall_time_ms.to_le_bytes());
        bytes.extend_from_slice(self.signer_pk_hex.as_bytes());
        bytes
    }

    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let msg = self.signing_bytes();
        let sig =
            ciphervault_crypto::signatures::sign_with_domain(signing_key, HEARTBEAT_DOMAIN, &msg);
        self.signature_hex = hex::encode(sig);
    }
}

/// Control-topic envelope. Externally tagged so future control kinds
/// (repair claims, erasure manifests) ride the same topic; see
/// [`classify_control_bytes`] for the forward-compatible parse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlMessage {
    Heartbeat(Heartbeat),
}

/// Why a heartbeat was rejected. Variants map 1:1 onto drop-reason
/// metrics and onto gossipsub acceptance (Reject for all of these;
/// unknown senders and unknown kinds are classified before verification
/// and map to Ignore — see [`classify_control_bytes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatReject {
    BadVersion,
    ClockSkew,
    BadSignature,
    StaleSeq,
}

/// First-stage parse of a control-topic payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlInput {
    Heartbeat(Heartbeat),
    /// Well-formed JSON naming an unknown control kind. Ignored (not
    /// rejected) so old nodes stay meshed when new kinds deploy.
    UnknownKind,
    /// Not a control envelope at all.
    BadEnvelope,
}

/// Parses control-topic bytes with upgrade-compatible classification:
/// a JSON value shaped like an envelope but naming an unknown kind is
/// [`ControlInput::UnknownKind`]; anything else unparsable is
/// [`ControlInput::BadEnvelope`].
pub fn classify_control_bytes(data: &[u8]) -> ControlInput {
    match serde_json::from_slice::<ControlMessage>(data) {
        Ok(ControlMessage::Heartbeat(hb)) => ControlInput::Heartbeat(hb),
        Err(_) => {
            // Unknown-kind detection: a JSON object with exactly one key
            // that is not a known variant tag.
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_slice::<serde_json::Value>(data)
            {
                if map.len() == 1 && !map.contains_key("Heartbeat") {
                    return ControlInput::UnknownKind;
                }
            }
            ControlInput::BadEnvelope
        }
    }
}

/// Verifies a heartbeat against the sender's announced key and the last
/// accepted seq. `expected_pk_hex` is `None` when the sender is unknown
/// (no routing-table entry or key mismatch — the caller checks both);
/// unknown senders never reach signature verification.
pub fn verify_heartbeat(
    hb: &Heartbeat,
    expected_pk_hex: Option<&str>,
    last_seq: Option<u64>,
    now_ms: u64,
) -> Result<(), HeartbeatReject> {
    if hb.version != HEARTBEAT_VERSION {
        return Err(HeartbeatReject::BadVersion);
    }
    let skew = hb.wall_time_ms.abs_diff(now_ms);
    if skew > HEARTBEAT_CLOCK_SKEW_MS {
        return Err(HeartbeatReject::ClockSkew);
    }
    let expected = match expected_pk_hex {
        // Without a pinned key there is nothing to verify against. The
        // caller reports unknown-sender (Ignore); treating it as a
        // signature failure here would penalize the forwarder for a key
        // the AUTHOR never announced.
        None => return Err(HeartbeatReject::BadSignature),
        Some(pk) => pk,
    };
    if !constant_time_eq_hex(&hb.signer_pk_hex, expected) {
        return Err(HeartbeatReject::BadSignature);
    }
    let pk_bytes = hex::decode(&hb.signer_pk_hex).map_err(|_| HeartbeatReject::BadSignature)?;
    if pk_bytes.len() != 32 {
        return Err(HeartbeatReject::BadSignature);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);
    let sig_bytes = hex::decode(&hb.signature_hex).map_err(|_| HeartbeatReject::BadSignature)?;
    if sig_bytes.len() != 64 {
        return Err(HeartbeatReject::BadSignature);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    ciphervault_crypto::signatures::verify_with_domain(
        &pk,
        HEARTBEAT_DOMAIN,
        &hb.signing_bytes(),
        &sig,
    )
    .map_err(|_| HeartbeatReject::BadSignature)?;
    if let Some(last) = last_seq {
        if hb.seq <= last {
            return Err(HeartbeatReject::StaleSeq);
        }
    }
    Ok(())
}

fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Local liveness view: last accepted heartbeat per peer. Entries only
/// exist for senders that verified against the (bounded) peer routing
/// table, so the tracker cannot grow past it.
#[derive(Debug, Default)]
pub struct LivenessTracker {
    entries: HashMap<PeerId, LivenessEntry>,
}

#[derive(Debug, Clone)]
pub struct LivenessEntry {
    pub operator_id: String,
    pub last_seq: u64,
    pub last_seen: Instant,
}

impl LivenessTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn note_heartbeat(&mut self, peer: PeerId, operator_id: &str, seq: u64) {
        self.entries.insert(
            peer,
            LivenessEntry {
                operator_id: operator_id.to_string(),
                last_seq: seq,
                last_seen: Instant::now(),
            },
        );
    }

    pub fn last_seq(&self, peer: &PeerId) -> Option<u64> {
        self.entries.get(peer).map(|entry| entry.last_seq)
    }

    /// The operator id a live peer heartbeat-claims, if tracked. Repair
    /// addressing resolves recipients through this (the routing table is
    /// keyed the other way).
    pub fn operator_for(&self, peer: &PeerId) -> Option<String> {
        self.entries
            .get(peer)
            .map(|entry| entry.operator_id.clone())
    }

    pub fn is_live(&self, peer: &PeerId, timeout: Duration) -> bool {
        self.entries
            .get(peer)
            .is_some_and(|entry| entry.last_seen.elapsed() < timeout)
    }

    pub fn live_peers(&self, timeout: Duration) -> Vec<PeerId> {
        let mut peers: Vec<PeerId> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.last_seen.elapsed() < timeout)
            .map(|(peer, _)| *peer)
            .collect();
        peers.sort();
        peers
    }

    pub fn live_count(&self, timeout: Duration) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.last_seen.elapsed() < timeout)
            .count()
    }

    /// Drops entries dead for more than 4x the timeout. Liveness answers
    /// are unchanged (expired either way); this keeps scans cheap.
    pub fn prune(&mut self, timeout: Duration) {
        let horizon = timeout.saturating_mul(4);
        self.entries
            .retain(|_, entry| entry.last_seen.elapsed() < horizon);
    }
}

/// Heartbeat emission/liveness knobs, bundled so the event loop keeps a
/// stable argument list as the swarm grows.
#[derive(Debug, Clone, Copy)]
pub struct HeartbeatConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

/// Current unix time in millis for heartbeat stamping/checking.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> ed25519_dalek::SigningKey {
        ciphervault_crypto::generate_signing_key()
    }

    fn test_hb(seq: u64) -> (Heartbeat, ed25519_dalek::SigningKey) {
        let key = test_key();
        let peer = PeerId::random();
        let hb = Heartbeat::new("op-a".to_string(), peer, seq, now_ms(), &key);
        (hb, key)
    }

    fn pk_hex(key: &ed25519_dalek::SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    #[test]
    fn roundtrip_verifies_and_envelope_classifies() {
        let (hb, key) = test_hb(1);
        let pk = pk_hex(&key);
        assert_eq!(verify_heartbeat(&hb, Some(&pk), None, now_ms()), Ok(()));
        // First-seen baselines any seq; advancement requires increase.
        assert_eq!(verify_heartbeat(&hb, Some(&pk), Some(0), now_ms()), Ok(()));
        let bytes = serde_json::to_vec(&ControlMessage::Heartbeat(hb.clone())).unwrap();
        assert_eq!(classify_control_bytes(&bytes), ControlInput::Heartbeat(hb));
    }

    #[test]
    fn tampered_fields_rejected() {
        let (hb, key) = test_hb(7);
        let pk = pk_hex(&key);
        for mutate in [
            |hb: &mut Heartbeat| hb.seq += 1,
            |hb: &mut Heartbeat| hb.operator_id.push('x'),
            |hb: &mut Heartbeat| hb.peer_id.push('x'),
            |hb: &mut Heartbeat| hb.wall_time_ms += 1000,
            |hb: &mut Heartbeat| hb.signature_hex.push('0'),
        ] {
            let mut bad = hb.clone();
            mutate(&mut bad);
            assert_eq!(
                verify_heartbeat(&bad, Some(&pk), None, now_ms()),
                Err(HeartbeatReject::BadSignature),
                "tampered heartbeat must fail verification"
            );
        }
    }

    #[test]
    fn wrong_key_rejected_without_pinned_match() {
        let (hb, _) = test_hb(1);
        let other = pk_hex(&test_key());
        // Claimed signer differs from the announced key → reject even
        // though the signature itself is well-formed.
        assert_eq!(
            verify_heartbeat(&hb, Some(&other), None, now_ms()),
            Err(HeartbeatReject::BadSignature)
        );
        // Unknown sender never reaches crypto.
        assert_eq!(
            verify_heartbeat(&hb, None, None, now_ms()),
            Err(HeartbeatReject::BadSignature)
        );
    }

    #[test]
    fn replay_and_reorder_rejected() {
        let (hb, key) = test_hb(9);
        let pk = pk_hex(&key);
        assert_eq!(
            verify_heartbeat(&hb, Some(&pk), Some(9), now_ms()),
            Err(HeartbeatReject::StaleSeq)
        );
        assert_eq!(
            verify_heartbeat(&hb, Some(&pk), Some(41), now_ms()),
            Err(HeartbeatReject::StaleSeq)
        );
    }

    #[test]
    fn clock_skew_rejected_both_directions() {
        let (hb, key) = test_hb(1);
        let pk = pk_hex(&key);
        let now = now_ms();
        assert_eq!(
            verify_heartbeat(&hb, Some(&pk), None, now + HEARTBEAT_CLOCK_SKEW_MS + 1000),
            Err(HeartbeatReject::ClockSkew)
        );
        assert_eq!(
            verify_heartbeat(
                &hb,
                Some(&pk),
                None,
                now.saturating_sub(HEARTBEAT_CLOCK_SKEW_MS + 1000)
            ),
            Err(HeartbeatReject::ClockSkew)
        );
        assert_eq!(verify_heartbeat(&hb, Some(&pk), None, now), Ok(()));
    }

    #[test]
    fn bad_version_rejected() {
        let (mut hb, key) = test_hb(1);
        let pk = pk_hex(&key);
        hb.version = HEARTBEAT_VERSION + 1;
        assert_eq!(
            verify_heartbeat(&hb, Some(&pk), None, now_ms()),
            Err(HeartbeatReject::BadVersion)
        );
    }

    #[test]
    fn unknown_kind_ignored_bad_envelope_rejected() {
        assert_eq!(
            classify_control_bytes(br#"{"RepairClaimV9": {"x": 1}}"#),
            ControlInput::UnknownKind
        );
        assert_eq!(
            classify_control_bytes(b"not json at all"),
            ControlInput::BadEnvelope
        );
        assert_eq!(
            classify_control_bytes(b"[1,2,3]"),
            ControlInput::BadEnvelope
        );
        assert_eq!(
            classify_control_bytes(br#"{"Heartbeat": {"broken": true}}"#),
            ControlInput::BadEnvelope
        );
    }

    #[test]
    fn tracker_liveness_and_prune() {
        let mut tracker = LivenessTracker::new();
        let peer = PeerId::random();
        let timeout = Duration::from_secs(60);
        assert!(!tracker.is_live(&peer, timeout));
        assert_eq!(tracker.last_seq(&peer), None);
        tracker.note_heartbeat(peer, "op-a", 3);
        assert!(tracker.is_live(&peer, timeout));
        assert_eq!(tracker.last_seq(&peer), Some(3));
        assert_eq!(tracker.live_peers(timeout), vec![peer]);
        assert_eq!(tracker.live_count(timeout), 1);
        // Zero timeout: nothing is live, but the entry is retained until
        // prune (expired either way).
        assert!(!tracker.is_live(&peer, Duration::ZERO));
        tracker.prune(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        tracker.prune(Duration::from_millis(1));
        assert_eq!(tracker.last_seq(&peer), None);
    }
}
