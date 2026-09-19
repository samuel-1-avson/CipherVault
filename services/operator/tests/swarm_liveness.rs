// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Liveness gossip tests (DON Phase 4 slice 1): signed heartbeats drive
//! the live set, silence past the timeout reads as dead (no death
//! claims on the wire), and every forgery class is dropped with its own
//! metric while the victim's liveness view stays correct.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::swarm::liveness::{now_ms, ControlMessage, Heartbeat};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;
use ciphervault_storage::types::PeerDescriptor;

static NODE_COUNTER: AtomicU64 = AtomicU64::new(0);

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

async fn boot_node(
    operator_id: &str,
    interval: Duration,
    timeout: Duration,
) -> (TestNode, Arc<OperatorState>) {
    let slot = NODE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-swarm-live-{}-{}-{}",
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
            heartbeat_interval: interval,
            heartbeat_timeout: timeout,
            repair: RepairConfig::default(),
        },
        state.clone(),
    )
    .await
    .expect("swarm node boots");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let listeners = handle.listeners().await.unwrap();
        let has_tcp = listeners.iter().any(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        });
        if has_tcp || tokio::time::Instant::now() > deadline {
            assert!(has_tcp, "tcp listen addr: {listeners:?}");
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (
        TestNode {
            handle,
            _task: task,
            dir,
        },
        state,
    )
}

/// Seeds `receiver` with the sender's announced key, as a prior
/// `AnnouncePeer` would (the announce RPC path itself is covered by the
/// conformance suite; this suite tests heartbeat verification).
fn announce_key_to(receiver: &OperatorState, operator_id: &str, key: &ed25519_dalek::SigningKey) {
    let descriptor = PeerDescriptor::new(
        operator_id.to_string(),
        "http://127.0.0.1:1".to_string(),
        key,
    );
    receiver
        .register_peer(descriptor)
        .expect("announce accepted");
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

fn metric_value(exposition: &str, name: &str) -> u64 {
    exposition
        .lines()
        .find(|line| line.starts_with(&format!("{name} ")))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn heartbeat_bytes(hb: &Heartbeat) -> Vec<u8> {
    serde_json::to_vec(&ControlMessage::Heartbeat(hb.clone())).unwrap()
}

/// Publishes until gossipsub accepts (mesh forms asynchronously after
/// connect); returns once the bytes are on the wire.
async fn publish_until_ok(node: &TestNode, data: Vec<u8>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match node.handle.publish_control(data.clone()).await {
            Ok(_) => break,
            Err(e) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "publish never accepted: {e}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn wait_live(node: &TestNode, peer: libp2p::PeerId) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if node.handle.is_live(peer).await.unwrap() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "peer {peer} never read as live"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_dead(node: &TestNode, peer: libp2p::PeerId) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if !node.handle.is_live(peer).await.unwrap() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "peer {peer} never timed out"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn heartbeats_drive_liveness_then_timeout() {
    let fast = Duration::from_millis(100);
    let timeout = Duration::from_millis(600);
    let (node_a, state_a) = boot_node("live-op-a", fast, timeout).await;
    let (node_b, state_b) = boot_node("live-op-b", fast, timeout).await;
    announce_key_to(&state_a, "live-op-b", &state_b.signing_key);
    announce_key_to(&state_b, "live-op-a", &state_a.signing_key);

    dial_and_wait(&node_a, &node_b).await;
    wait_live(&node_b, node_a.handle.peer_id).await;
    wait_live(&node_a, node_b.handle.peer_id).await;
    assert_eq!(
        node_b.handle.live_peers().await.unwrap(),
        vec![node_a.handle.peer_id]
    );

    // Both directions emit and receive; the gauge exports the live set.
    let exp_b = state_b.metrics.render_prometheus();
    assert!(
        metric_value(&exp_b, "ciphervault_swarm_heartbeats_received_total") >= 1,
        "B must receive A's heartbeats"
    );
    let exp_a = state_a.metrics.render_prometheus();
    assert!(
        metric_value(&exp_a, "ciphervault_swarm_heartbeats_sent_total") >= 1,
        "A must publish heartbeats once meshed"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let exp = state_b.metrics.render_prometheus();
        if metric_value(&exp, "ciphervault_swarm_peers_live") == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "live gauge never exported 1"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Silence reads as dead with no death claim on the wire: drop A and
    // B times it out locally.
    let peer_a = node_a.handle.peer_id;
    drop(node_a);
    drop(state_a);
    wait_dead(&node_b, peer_a).await;
    assert!(node_b.handle.live_peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn forged_gossip_dropped_without_effect() {
    // Long interval: no genuine heartbeats interfere (the boot tick fires
    // before any mesh exists and fails unpublished).
    let idle = Duration::from_secs(30);
    let timeout = Duration::from_secs(90);
    let (node_v, state_v) = boot_node("live-victim", idle, timeout).await;
    let (node_f, _state_f) = boot_node("live-forger", idle, timeout).await;

    // X is a known operator (announced key) but not a swarm node: its
    // heartbeats arrive only via the forger's gossip.
    let key_x = generate_signing_key();
    announce_key_to(&state_v, "live-op-x", &key_x);
    let peer_x = libp2p::PeerId::random();
    let peer_ghost = libp2p::PeerId::random();

    dial_and_wait(&node_f, &node_v).await;

    // Mesh probe doubles as the Accept-path proof: a valid X heartbeat
    // advances V's liveness for a peer that never connected.
    let valid_x = Heartbeat::new("live-op-x".to_string(), peer_x, 1, now_ms(), &key_x);
    publish_until_ok(&node_f, heartbeat_bytes(&valid_x)).await;
    wait_live(&node_v, peer_x).await;

    // Every forgery class, published onto the live mesh.
    let mut bad_sig = Heartbeat::new("live-op-x".to_string(), peer_x, 2, now_ms(), &key_x);
    bad_sig.signature_hex.push('0');
    publish_until_ok(&node_f, heartbeat_bytes(&bad_sig)).await;

    publish_until_ok(&node_f, heartbeat_bytes(&valid_x)).await; // replay: stale seq

    let key_ghost = generate_signing_key();
    let ghost = Heartbeat::new(
        "live-ghost".to_string(),
        peer_ghost,
        1,
        now_ms(),
        &key_ghost,
    );
    publish_until_ok(&node_f, heartbeat_bytes(&ghost)).await; // unknown sender

    publish_until_ok(&node_f, br#"{"FutureKind": {"v": 1}}"#.to_vec()).await;
    publish_until_ok(&node_f, b"not json".to_vec()).await;

    let skewed = Heartbeat::new(
        "live-op-x".to_string(),
        peer_x,
        3,
        now_ms() + 3_600_000,
        &key_x,
    );
    publish_until_ok(&node_f, heartbeat_bytes(&skewed)).await;

    let mut wrong_version = Heartbeat::new("live-op-x".to_string(), peer_x, 4, now_ms(), &key_x);
    wrong_version.version = 999;
    publish_until_ok(&node_f, heartbeat_bytes(&wrong_version)).await;

    // Every class lands in its own drop metric; the valid heartbeat is
    // the only one that counted as received.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let exp = state_v.metrics.render_prometheus();
        let all_dropped = [
            "bad_envelope",
            "bad_version",
            "clock_skew",
            "unknown_sender",
        ]
        .iter()
        .all(|reason| {
            metric_value(
                &exp,
                &format!("ciphervault_swarm_heartbeats_dropped_{reason}_total"),
            ) >= 1
        }) && metric_value(
            &exp,
            "ciphervault_swarm_heartbeats_dropped_bad_signature_total",
        ) >= 1
            && metric_value(&exp, "ciphervault_swarm_heartbeats_dropped_stale_seq_total") >= 1
            && metric_value(&exp, "ciphervault_swarm_control_unknown_kind_ignored_total") >= 1;
        if all_dropped {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "drop metrics never filled:\n{exp}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Victim's liveness view: X live (valid heartbeat), ghost absent
    // (unknown sender never advances), forger absent (never announced).
    assert!(node_v.handle.is_live(peer_x).await.unwrap());
    assert!(!node_v.handle.is_live(peer_ghost).await.unwrap());
    assert!(!node_v.handle.is_live(node_f.handle.peer_id).await.unwrap());
    let exp = state_v.metrics.render_prometheus();
    assert!(
        metric_value(&exp, "ciphervault_swarm_heartbeats_received_total") >= 1,
        "valid heartbeat must count as received"
    );
}
