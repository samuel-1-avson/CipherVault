//! Signed Kademlia peer records (DON Phase 2, D5).
//!
//! Provider/peer records published to the DHT are the SAME signed
//! [`PeerDescriptor`] already gossiped over HTTP (`operator_peer_gossip`
//! domain), so DHT identity evolves from the existing gossip layer instead
//! of forking it. Reads are validated client-side: a record is trusted only
//! when (1) it decodes, (2) its embedded signing key matches the queried
//! key (anti-substitution), (3) its ed25519 signature verifies, and (4) its
//! timestamp is fresh. Anything else is dropped — fail closed.
//!
//! [`PeerDescriptor`]: ciphervault_storage::types::PeerDescriptor

use std::time::{SystemTime, UNIX_EPOCH};

use ciphervault_storage::types::PeerDescriptor;
use libp2p::kad::{Record as KadRecord, RecordKey};

/// DHT key namespace for peer records (versioned; bump on format change).
pub const PEER_RECORD_KEY_PREFIX: &str = "ciphervault/peer/1/";
/// Records older than this are never trusted (replay bound).
pub const MAX_PEER_RECORD_AGE_SECS: u64 = 7 * 24 * 60 * 60;
/// Future timestamps beyond this skew are never trusted (clock bound).
pub const MAX_PEER_RECORD_SKEW_SECS: u64 = 60 * 60;
/// Largest DHT peer-record value accepted (decode AND local store).
/// Real descriptors are < 1 KiB; 64 KiB matches the recovery-record cap
/// and bounds hostile-record allocation at the reader.
pub const MAX_PEER_RECORD_BYTES: usize = 64 * 1024;

/// Raw key preimage for a peer record, so tests and tools can address the
/// same key the typed API uses.
pub fn peer_record_key_bytes(signing_pk_hex: &str) -> Vec<u8> {
    format!("{PEER_RECORD_KEY_PREFIX}{signing_pk_hex}").into_bytes()
}

/// Kademlia key for the peer record of `signing_pk_hex`.
pub fn peer_record_key(signing_pk_hex: &str) -> RecordKey {
    RecordKey::new(&peer_record_key_bytes(signing_pk_hex))
}

/// Encodes a signed descriptor for DHT storage (JSON: debuggable, and the
/// descriptor's own signature — not the envelope — carries trust).
pub fn encode_peer_record(descriptor: &PeerDescriptor) -> Vec<u8> {
    serde_json::to_vec(descriptor).unwrap_or_default()
}

/// Builds the DHT record a node publishes for its own descriptor.
pub fn peer_kad_record(descriptor: &PeerDescriptor) -> KadRecord {
    KadRecord::new(
        peer_record_key(&descriptor.signing_pk_hex),
        encode_peer_record(descriptor),
    )
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decodes and validates one DHT record value against the queried
/// `signing_pk_hex`. Returns `None` for anything untrusted: undecodable
/// bytes, key mismatch, bad signature, or stale/future timestamps.
pub fn decode_and_verify_peer_record(signing_pk_hex: &str, value: &[u8]) -> Option<PeerDescriptor> {
    if value.len() > MAX_PEER_RECORD_BYTES {
        return None;
    }
    let descriptor: PeerDescriptor = serde_json::from_slice(value).ok()?;
    if !descriptor
        .signing_pk_hex
        .eq_ignore_ascii_case(signing_pk_hex)
    {
        return None;
    }
    descriptor.verify().ok()?;
    let now = now_unix_secs();
    let ts = descriptor.timestamp_utc;
    if ts > now.saturating_add(MAX_PEER_RECORD_SKEW_SECS) {
        return None;
    }
    if ts.saturating_add(MAX_PEER_RECORD_AGE_SECS) < now {
        return None;
    }
    Some(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_descriptor(operator_id: &str) -> (PeerDescriptor, String) {
        let key = ciphervault_crypto::generate_signing_key();
        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        let descriptor = PeerDescriptor::new(
            operator_id.to_string(),
            format!("https://{operator_id}.example"),
            &key,
        );
        (descriptor, pk_hex)
    }

    #[test]
    fn roundtrip_verifies() {
        let (descriptor, pk_hex) = test_descriptor("op-a");
        let bytes = encode_peer_record(&descriptor);
        let back = decode_and_verify_peer_record(&pk_hex, &bytes).expect("valid record");
        assert_eq!(back.operator_id, "op-a");
        assert_eq!(back.signature_hex, descriptor.signature_hex);
    }

    #[test]
    fn tampered_endpoint_rejected() {
        let (mut descriptor, pk_hex) = test_descriptor("op-a");
        descriptor.endpoint = "https://evil.example".to_string();
        let bytes = encode_peer_record(&descriptor);
        assert!(decode_and_verify_peer_record(&pk_hex, &bytes).is_none());
    }

    #[test]
    fn wrong_key_rejected() {
        let (descriptor, _) = test_descriptor("op-a");
        let (_, other_pk) = test_descriptor("op-b");
        let bytes = encode_peer_record(&descriptor);
        assert!(decode_and_verify_peer_record(&other_pk, &bytes).is_none());
    }

    #[test]
    fn garbage_rejected() {
        let (_, pk_hex) = test_descriptor("op-a");
        assert!(decode_and_verify_peer_record(&pk_hex, b"not json").is_none());
        assert!(decode_and_verify_peer_record(&pk_hex, b"{}").is_none());
        assert!(decode_and_verify_peer_record(&pk_hex, b"").is_none());
    }

    #[test]
    fn oversize_rejected() {
        let (_, pk_hex) = test_descriptor("op-a");
        let big = vec![b'{'; MAX_PEER_RECORD_BYTES + 1];
        assert!(decode_and_verify_peer_record(&pk_hex, &big).is_none());
    }

    #[test]
    fn stale_and_future_rejected() {
        let (descriptor, _pk_hex) = test_descriptor("op-a");
        let key = ciphervault_crypto::generate_signing_key();
        // Re-sign with a tampered timestamp is impossible without the key,
        // so build stale/future descriptors by re-creating and backdating
        // the struct, then re-signing with a FRESH key we own: signature
        // stays valid, freshness must still reject.
        let mut stale = PeerDescriptor::new(
            descriptor.operator_id.clone(),
            descriptor.endpoint.clone(),
            &key,
        );
        stale.timestamp_utc = 1;
        stale.sign(&key);
        let stale_pk = hex::encode(key.verifying_key().to_bytes());
        let bytes = encode_peer_record(&stale);
        assert!(decode_and_verify_peer_record(&stale_pk, &bytes).is_none());

        let mut future = PeerDescriptor::new(
            descriptor.operator_id.clone(),
            descriptor.endpoint.clone(),
            &key,
        );
        future.timestamp_utc = now_unix_secs() + MAX_PEER_RECORD_SKEW_SECS + 3600;
        future.sign(&key);
        let bytes = encode_peer_record(&future);
        assert!(decode_and_verify_peer_record(&stale_pk, &bytes).is_none());
        // Control: the fresh descriptor for the same key verifies.
        let mut fresh = PeerDescriptor::new(
            descriptor.operator_id.clone(),
            descriptor.endpoint.clone(),
            &key,
        );
        fresh.sign(&key);
        let bytes = encode_peer_record(&fresh);
        assert!(decode_and_verify_peer_record(&stale_pk, &bytes).is_some());
    }
}
