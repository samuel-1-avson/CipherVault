// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Swarm DoS-posture tests (DON Phase 3 slice 3): connection caps deny
//! excess peers, the block-list refuses connections in both directions and
//! drops live ones, the per-peer RPC limiter answers 429 before serve, and
//! oversize gossip publishes are rejected without touching the mesh.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::swarm::behaviour::{
    OperatorRpcBody, OperatorRpcRequest, OperatorRpcResponse, P2pAuth, GOSSIP_MAX_TRANSMIT_SIZE,
};
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;

static NODE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct DosConfig {
    max_established_connections: Option<u32>,
    max_rpc_per_sec_per_peer: Option<u32>,
    blocked_peers: Vec<libp2p::PeerId>,
    bootstrap: Vec<libp2p::Multiaddr>,
}

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

async fn boot_node(operator_id: &str, dos: DosConfig) -> (TestNode, Arc<OperatorState>) {
    let slot = NODE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-swarm-dos-{}-{}-{}",
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
            bootstrap: dos.bootstrap,
            enable_mdns: false,
            enable_relay_server: false,
            enable_dcutr: true,
            bootstrap_list_path: None,
            bootstrap_signer_hex: None,
            enable_rendezvous_server: false,
            advertise_addrs: Vec::new(),
            max_established_connections: dos.max_established_connections,
            max_established_per_peer: None,
            blocked_peers: dos.blocked_peers,
            max_rpc_per_sec_per_peer: dos.max_rpc_per_sec_per_peer,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
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

fn tcp_dial_addr(node: &TestNode, listeners: &[libp2p::Multiaddr]) -> libp2p::Multiaddr {
    let tcp = listeners
        .iter()
        .find(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        })
        .expect("node has a tcp listen addr");
    format!("{tcp}/p2p/{}", node.handle.peer_id)
        .parse()
        .unwrap()
}

async fn dial(a: &TestNode, b: &TestNode) {
    let listeners = b.handle.listeners().await.unwrap();
    a.handle.dial(tcp_dial_addr(b, &listeners)).await.unwrap();
}

async fn wait_connected(a: &TestNode, b: &TestNode) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if a.handle.is_connected(b.handle.peer_id).await.unwrap() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never connected to {}",
            b.handle.peer_id
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Asserts `a` stays disconnected from `peer` for the whole `duration`.
/// Callers always pair this with a positive control (an unblocked peer
/// connecting, or the same peer connecting after unblock) so a broken
/// test harness cannot produce a false pass.
async fn assert_stays_disconnected(a: &TestNode, peer: libp2p::PeerId, duration: Duration) {
    let deadline = tokio::time::Instant::now() + duration;
    while tokio::time::Instant::now() < deadline {
        assert!(
            !a.handle.is_connected(peer).await.unwrap(),
            "peer {peer} connected despite the DoS control"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn rpc(node: &TestNode, peer: libp2p::PeerId, body: OperatorRpcBody) -> OperatorRpcResponse {
    tokio::time::timeout(
        Duration::from_secs(15),
        node.handle.rpc_request(
            peer,
            OperatorRpcRequest {
                auth: P2pAuth::default(),
                body,
            },
        ),
    )
    .await
    .expect("rpc completes")
    .expect("rpc succeeds")
}

#[tokio::test]
async fn connection_cap_denies_second_peer() {
    let (node_c, _state_c) = boot_node(
        "dos-c",
        DosConfig {
            max_established_connections: Some(1),
            ..DosConfig::default()
        },
    )
    .await;
    let (node_a, _state_a) = boot_node("dos-a", DosConfig::default()).await;
    let (node_b, _state_b) = boot_node("dos-b", DosConfig::default()).await;

    // First peer connects fine: the cap is 1, not 0.
    dial(&node_a, &node_c).await;
    wait_connected(&node_a, &node_c).await;

    // Second peer is denied at the swarm edge ...
    dial(&node_b, &node_c).await;
    assert_stays_disconnected(&node_c, node_b.handle.peer_id, Duration::from_secs(3)).await;

    // ... while the first peer's connection survives.
    assert!(node_c
        .handle
        .is_connected(node_a.handle.peer_id)
        .await
        .unwrap());
    assert!(node_a
        .handle
        .is_connected(node_c.handle.peer_id)
        .await
        .unwrap());
}

#[tokio::test]
async fn block_list_refuses_drops_and_releases() {
    let (node_a, _state_a) = boot_node("dos-a", DosConfig::default()).await;
    let (node_b, _state_b) = boot_node("dos-b", DosConfig::default()).await;

    node_a
        .handle
        .block_peer(node_b.handle.peer_id)
        .await
        .unwrap();
    assert!(node_a
        .handle
        .is_blocked(node_b.handle.peer_id)
        .await
        .unwrap());

    // Blocked peer cannot connect, even though nothing else changed.
    dial(&node_b, &node_a).await;
    assert_stays_disconnected(&node_a, node_b.handle.peer_id, Duration::from_secs(3)).await;

    // Unblock releases: the same dial now connects (positive control).
    node_a
        .handle
        .unblock_peer(node_b.handle.peer_id)
        .await
        .unwrap();
    assert!(!node_a
        .handle
        .is_blocked(node_b.handle.peer_id)
        .await
        .unwrap());
    dial(&node_b, &node_a).await;
    wait_connected(&node_a, &node_b).await;

    // Blocking a LIVE peer drops the connection promptly.
    node_a
        .handle
        .block_peer(node_b.handle.peer_id)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !node_a
            .handle
            .is_connected(node_b.handle.peer_id)
            .await
            .unwrap()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "blocked peer stayed connected"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn boot_block_list_skips_bootstrap_dial() {
    let (node_a, _state_a) = boot_node("dos-a", DosConfig::default()).await;
    let listeners = node_a.handle.listeners().await.unwrap();
    let boot_addr = tcp_dial_addr(&node_a, &listeners);

    // C lists A as a bootstrap but ALSO block-lists A: the boot dial is
    // skipped, so C never connects.
    let (node_c, _state_c) = boot_node(
        "dos-c",
        DosConfig {
            blocked_peers: vec![node_a.handle.peer_id],
            bootstrap: vec![boot_addr],
            ..DosConfig::default()
        },
    )
    .await;
    assert_stays_disconnected(&node_c, node_a.handle.peer_id, Duration::from_secs(3)).await;

    // Unblock releases: an explicit dial connects (positive control —
    // unblock itself never re-dials).
    node_c
        .handle
        .unblock_peer(node_a.handle.peer_id)
        .await
        .unwrap();
    dial(&node_c, &node_a).await;
    wait_connected(&node_c, &node_a).await;
}

#[tokio::test]
async fn rpc_rate_limit_answers_429_then_recovers() {
    let (node_b, _state_b) = boot_node(
        "dos-b",
        DosConfig {
            max_rpc_per_sec_per_peer: Some(3),
            ..DosConfig::default()
        },
    )
    .await;
    let (node_a, _state_a) = boot_node("dos-a", DosConfig::default()).await;
    dial(&node_a, &node_b).await;
    wait_connected(&node_a, &node_b).await;

    // GetInfo needs no session, so served answers prove the limiter sits
    // in front of (not instead of) serve. No positional asserts: the burst
    // may straddle a window boundary, but 10 back-to-back loopback RPCs
    // against a limit of 3 always trip at least one window.
    let mut saw_info = false;
    let mut saw_429 = false;
    for _ in 0..10 {
        match rpc(&node_a, node_b.handle.peer_id, OperatorRpcBody::GetInfo).await {
            OperatorRpcResponse::Info(_) => saw_info = true,
            OperatorRpcResponse::Err { status, .. } => {
                assert_eq!(status, 429, "over-limit status must be 429");
                saw_429 = true;
            }
            other => panic!("unexpected rate-limit response: {other:?}"),
        }
    }
    assert!(saw_info, "under-limit requests must be served");
    assert!(saw_429, "burst of 10 with limit 3 must trip the limiter");

    // The window slides: after it passes, the same caller is served again.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    match rpc(&node_a, node_b.handle.peer_id, OperatorRpcBody::GetInfo).await {
        OperatorRpcResponse::Info(_) => {}
        other => panic!("expected recovery after the window, got: {other:?}"),
    }
}

#[tokio::test]
async fn gossip_oversize_publish_rejected() {
    let (node_a, _state_a) = boot_node("dos-a", DosConfig::default()).await;
    let (node_b, _state_b) = boot_node("dos-b", DosConfig::default()).await;
    dial(&node_a, &node_b).await;
    wait_connected(&node_a, &node_b).await;

    // The control topic mesh forms on the gossipsub heartbeat: poll a
    // small publish until a subscribed peer exists (positive control).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let id = loop {
        match node_a.handle.publish_control(vec![0u8; 64]).await {
            Ok(id) => break id,
            Err(e) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "small publish never succeeded: {e}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    assert!(!id.is_empty(), "publish returns a message id");

    let boundary = node_a
        .handle
        .publish_control(vec![0u8; GOSSIP_MAX_TRANSMIT_SIZE])
        .await;
    assert!(
        boundary.is_ok(),
        "exact-cap publish must succeed: {boundary:?}"
    );

    let oversize = node_a
        .handle
        .publish_control(vec![0u8; GOSSIP_MAX_TRANSMIT_SIZE + 1])
        .await;
    match oversize {
        Err(e) => assert!(
            e.to_string().contains("MessageTooLarge"),
            "oversize publish must fail with MessageTooLarge, got: {e}"
        ),
        Ok(id) => panic!("oversize publish must be rejected, got id {id}"),
    }
}
