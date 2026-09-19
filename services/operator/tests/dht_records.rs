// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Signed DHT peer-record tests (DON Phase 2, D5): one node publishes its
//! signed [`PeerDescriptor`] to Kademlia, the other reads it back through
//! client-side verification. Tampered bytes, key-mismatched records, and
//! garbage under the same key are all dropped — fail closed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::records;
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;
use ciphervault_storage::types::PeerDescriptor;

static DHT_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestNode {
    handle: SwarmHandle,
    _task: tokio::task::JoinHandle<()>,
    dir: PathBuf,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self._task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn boot_node(operator_id: &str) -> TestNode {
    let slot = DHT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-dht-{}-{}-{}",
        std::process::id(),
        slot,
        operator_id,
    ));
    let state = Arc::new(OperatorState::new(
        operator_id.to_string(),
        dir.clone(),
        generate_signing_key(),
    ));
    let (handle, task) = boot_swarm(
        SwarmNodeConfig {
            key_path: dir.join("swarm.key"),
            tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            bootstrap: Vec::new(),
            enable_mdns: false,
            enable_relay_server: false,
            enable_dcutr: true,
            bootstrap_list_path: None,
            bootstrap_signer_hex: None,
            enable_rendezvous_server: false,
            advertise_addrs: Vec::new(),
            max_established_connections: None,
            max_established_per_peer: None,
            blocked_peers: Vec::new(),
            max_rpc_per_sec_per_peer: None,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
            repair: RepairConfig::default(),
        },
        state,
    )
    .await
    .expect("swarm node boots");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let listeners = handle.listeners().await.unwrap();
        if listeners.len() >= 2 || tokio::time::Instant::now() > deadline {
            assert!(listeners.len() >= 2, "listen addrs: {listeners:?}");
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    TestNode {
        handle,
        _task: task,
        dir,
    }
}

async fn dial_and_wait(a: &TestNode, b: &TestNode) {
    let b_tcp = b
        .handle
        .listeners()
        .await
        .unwrap()
        .into_iter()
        .find(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        })
        .expect("B has a tcp listen addr");
    let dial_addr: libp2p::Multiaddr = format!("{b_tcp}/p2p/{}", b.handle.peer_id).parse().unwrap();
    a.handle.dial(dial_addr).await.expect("A dials B");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if a.handle.is_connected(b.handle.peer_id).await.unwrap() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "A never connected to B"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Polls one DHT lookup per iteration (fresh query each time) until the
/// predicate holds or the deadline passes.
async fn poll_verified(
    reader: &SwarmHandle,
    pk_hex: &str,
    timeout: Duration,
) -> Vec<PeerDescriptor> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let found = tokio::time::timeout(
            Duration::from_secs(10),
            reader.get_verified_peers(pk_hex.to_string()),
        )
        .await
        .expect("single DHT lookup terminates")
        .expect("lookup channel open");
        if !found.is_empty() || tokio::time::Instant::now() > deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn publishes_and_verifies_peer_record() {
    let a = boot_node("dht-a").await;
    let b = boot_node("dht-b").await;
    dial_and_wait(&a, &b).await;
    dial_and_wait(&b, &a).await;

    let key = generate_signing_key();
    let pk_hex = hex::encode(key.verifying_key().to_bytes());
    let descriptor = PeerDescriptor::new(
        "dht-a".to_string(),
        "https://dht-a.example".to_string(),
        &key,
    );
    a.handle.publish_peer(descriptor).await.unwrap();

    let found = poll_verified(&b.handle, &pk_hex, Duration::from_secs(25)).await;
    assert_eq!(found.len(), 1, "exactly the valid record");
    assert_eq!(found[0].operator_id, "dht-a");
    assert_eq!(found[0].signing_pk_hex, pk_hex);
    found[0].verify().expect("round-tripped signature verifies");
}

#[tokio::test]
async fn drops_tampered_foreign_and_garbage_records() {
    let a = boot_node("dht-c").await;
    let b = boot_node("dht-d").await;
    dial_and_wait(&a, &b).await;
    dial_and_wait(&b, &a).await;

    // Victim publishes a valid record; wait until the reader sees it.
    let victim_key = generate_signing_key();
    let victim_pk = hex::encode(victim_key.verifying_key().to_bytes());
    let victim = PeerDescriptor::new(
        "victim".to_string(),
        "https://victim.example".to_string(),
        &victim_key,
    );
    a.handle.publish_peer(victim).await.unwrap();
    let seen = poll_verified(&b.handle, &victim_pk, Duration::from_secs(25)).await;
    assert_eq!(seen.len(), 1);

    // 1. Validly signed descriptor for key X planted under a fresh key Z
    // nobody owns: dropped as a key mismatch (anti-substitution), so the
    // attacker cannot spoof Z's identity.
    let other_key = generate_signing_key();
    let other = PeerDescriptor::new(
        "other".to_string(),
        "https://other.example".to_string(),
        &other_key,
    );
    let spoof_pk = hex::encode(generate_signing_key().verifying_key().to_bytes());
    b.handle
        .put_raw_record(
            records::peer_record_key_bytes(&spoof_pk),
            records::encode_peer_record(&other),
        )
        .await
        .unwrap();
    let spoofed = tokio::time::timeout(
        Duration::from_secs(15),
        b.handle.get_verified_peers(spoof_pk),
    )
    .await
    .expect("mismatched lookup terminates")
    .expect("lookup channel open");
    assert!(spoofed.is_empty(), "key-mismatched record dropped");

    // 2. Garbage-only key: reads terminate with zero trusted records.
    let ghost_pk = hex::encode(generate_signing_key().verifying_key().to_bytes());
    b.handle
        .put_raw_record(
            records::peer_record_key_bytes(&ghost_pk),
            b"definitely not json".to_vec(),
        )
        .await
        .unwrap();
    let ghost = tokio::time::timeout(
        Duration::from_secs(15),
        b.handle.get_verified_peers(ghost_pk),
    )
    .await
    .expect("garbage-only lookup terminates")
    .expect("lookup channel open");
    assert!(ghost.is_empty(), "garbage-only key yields nothing trusted");

    // 3. Same-key puts are last-writer-wins, so an overwrite can blank the
    // victim's slot — but never spoof it — and a republish restores it.
    b.handle
        .put_raw_record(
            records::peer_record_key_bytes(&victim_pk),
            b"\x00\x01not-a-record".to_vec(),
        )
        .await
        .unwrap();
    let blank_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let current = tokio::time::timeout(
            Duration::from_secs(10),
            b.handle.get_verified_peers(victim_pk.clone()),
        )
        .await
        .expect("blank-check lookup terminates")
        .expect("lookup channel open");
        if current.is_empty() || tokio::time::Instant::now() > blank_deadline {
            assert!(current.is_empty(), "overwrite blanks the victim slot");
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let republished = PeerDescriptor::new(
        "victim".to_string(),
        "https://victim.example".to_string(),
        &victim_key,
    );
    a.handle.publish_peer(republished).await.unwrap();
    let restored = poll_verified(&b.handle, &victim_pk, Duration::from_secs(25)).await;
    assert_eq!(restored.len(), 1, "republish restores the victim record");
    assert_eq!(restored[0].operator_id, "victim");
}
