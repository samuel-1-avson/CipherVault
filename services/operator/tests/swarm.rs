// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Swarm connectivity tests (DON Phase 2): two nodes boot on loopback with
//! ephemeral ports, dial directly, and exchange operator RPCs served from
//! the live operator store. mDNS stays off here for determinism; explicit
//! dial plus identify is what this harness pins. Deep per-operation parity
//! lives in the three-leg conformance suite.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_crypto::generate_signing_key;
use ciphervault_format::compute_digest;
use ciphervault_operator::swarm::behaviour::{
    OperatorRpcBody, OperatorRpcRequest, OperatorRpcResponse, P2pAuth,
};
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;

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

async fn boot_node(operator_id: &str) -> (TestNode, Arc<OperatorState>) {
    let slot = NODE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-swarm-{}-{}-{}",
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
        state.clone(),
    )
    .await
    .expect("swarm node boots");
    // Wait for both transports to report listen addresses.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let listeners = handle.listeners().await.unwrap();
        let has_tcp = listeners.iter().any(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        });
        let has_quic = listeners
            .iter()
            .any(|addr| addr.to_string().contains("quic-v1"));
        if has_tcp && has_quic || tokio::time::Instant::now() > deadline {
            assert!(has_tcp, "tcp listen addr: {listeners:?}");
            assert!(has_quic, "quic listen addr: {listeners:?}");
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
    // Peer-qualified dial so request-response can route, then wait for the
    // connection — requesting mid-dial fails with no known peer address.
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

async fn rpc(node: &TestNode, peer: libp2p::PeerId, body: OperatorRpcBody) -> OperatorRpcResponse {
    rpc_authed(node, peer, P2pAuth::default(), body).await
}

fn anonymous_auth() -> P2pAuth {
    P2pAuth {
        bearer_token: Some("recovery_anonymous".to_string()),
        vault_id_hex: None,
        service_token: None,
        voucher: None,
    }
}

async fn rpc_authed(
    node: &TestNode,
    peer: libp2p::PeerId,
    auth: P2pAuth,
    body: OperatorRpcBody,
) -> OperatorRpcResponse {
    tokio::time::timeout(
        Duration::from_secs(15),
        node.handle
            .rpc_request(peer, OperatorRpcRequest { auth, body }),
    )
    .await
    .expect("rpc completes")
    .expect("rpc succeeds")
}

#[tokio::test]
async fn two_nodes_exchange_object_over_operator_rpc() {
    let (node_a, _state_a) = boot_node("swarm-op-a").await;
    let (node_b, state_b) = boot_node("swarm-op-b").await;
    assert_ne!(node_a.handle.peer_id, node_b.handle.peer_id);

    dial_and_wait(&node_a, &node_b).await;

    // Identity RPCs work before any session exists.
    match rpc(&node_a, node_b.handle.peer_id, OperatorRpcBody::GetInfo).await {
        OperatorRpcResponse::Info(info) => {
            assert_eq!(info.operator_id, "swarm-op-b");
            assert!(info.verify_identity_signature());
        }
        other => panic!("unexpected info response: {other:?}"),
    }

    // Seed B's live store, then fetch it from A over libp2p (anonymous
    // reads mirror the HTTP `recovery_anonymous` semantics).
    let bytes = b"swarm chunk fixture".to_vec();
    let cid = compute_digest(&bytes);
    state_b
        .put_object(&hex::encode(cid), &bytes)
        .expect("seed object");

    let response = rpc_authed(
        &node_a,
        node_b.handle.peer_id,
        anonymous_auth(),
        OperatorRpcBody::GetObject { cid },
    )
    .await;
    match response {
        OperatorRpcResponse::Object { bytes: got } => assert_eq!(got, bytes),
        other => panic!("unexpected get response: {other:?}"),
    }

    // Missing objects are a 404 Err, never fabricated ...
    let missing: [u8; 32] = rand::random();
    let response = rpc_authed(
        &node_a,
        node_b.handle.peer_id,
        anonymous_auth(),
        OperatorRpcBody::GetObject { cid: missing },
    )
    .await;
    match response {
        OperatorRpcResponse::Err { status, .. } => assert_eq!(status, 404),
        other => panic!("unexpected missing response: {other:?}"),
    }

    // ... while missing credentials fail closed with 401.
    let response = rpc(
        &node_a,
        node_b.handle.peer_id,
        OperatorRpcBody::GetObject { cid },
    )
    .await;
    match response {
        OperatorRpcResponse::Err { status, .. } => assert_eq!(status, 401),
        other => panic!("unexpected unauth response: {other:?}"),
    }
}
