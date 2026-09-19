// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Rendezvous first-contact test (DON Phase 2): a seed node runs the
//! rendezvous server, one operator registers, another discovers it, then
//! dials the discovered address and runs an operator RPC — the full
//! first-contact story without any hardcoded peer address on the joiner.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::swarm::behaviour::{
    OperatorRpcBody, OperatorRpcRequest, OperatorRpcResponse, P2pAuth,
};
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, RendezvousPeer, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;

static RZ_COUNTER: AtomicU64 = AtomicU64::new(0);

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

async fn boot_node(operator_id: &str, rendezvous_server: bool) -> TestNode {
    let slot = RZ_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-rendezvous-{}-{}-{}",
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
            enable_rendezvous_server: rendezvous_server,
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
    let node = TestNode {
        handle,
        _task: task,
        dir,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let listeners = node.handle.listeners().await.unwrap();
        if listeners.len() >= 2 || tokio::time::Instant::now() > deadline {
            assert!(listeners.len() >= 2, "listen addrs: {listeners:?}");
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    node
}

async fn tcp_addr(node: &TestNode) -> libp2p::Multiaddr {
    node.handle
        .listeners()
        .await
        .unwrap()
        .into_iter()
        .find(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        })
        .expect("node has a tcp listen addr")
}

async fn dial_and_wait(from: &TestNode, to: &TestNode) {
    let to_tcp = tcp_addr(to).await;
    let dial_addr: libp2p::Multiaddr = format!("{to_tcp}/p2p/{}", to.handle.peer_id)
        .parse()
        .unwrap();
    from.handle.dial(dial_addr).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if from.handle.is_connected(to.handle.peer_id).await.unwrap() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "dial never connected"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn rendezvous_register_discover_then_rpc() {
    let seed = boot_node("rz-seed", true).await;
    let a = boot_node("rz-a", false).await;
    let b = boot_node("rz-b", false).await;

    // Both operators reach the seed (out-of-band seed addr, e.g. from the
    // signed bootstrap list); neither knows about the other.
    dial_and_wait(&a, &seed).await;
    dial_and_wait(&b, &seed).await;

    // A advertises its reachable address and registers; B polls discovery
    // until A appears. Both sides retry: registration needs the connection
    // plus external addresses, discovery needs the registration to land.
    let a_tcp = tcp_addr(&a).await;
    a.handle.add_external_addr(a_tcp.clone()).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    let found: RendezvousPeer = loop {
        a.handle
            .rendezvous_register(seed.handle.peer_id)
            .await
            .unwrap();
        b.handle
            .rendezvous_discover(seed.handle.peer_id, Some(10))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let discovered = b.handle.take_rendezvous_discoveries().await.unwrap();
        if let Some(hit) = discovered.into_iter().find(|p| p.peer == a.handle.peer_id) {
            break hit;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "B never discovered A via rendezvous"
        );
    };
    assert!(
        found.addrs.contains(&a_tcp),
        "discovered addrs carry A's reachable addr: {:?}",
        found.addrs
    );

    // First contact completes: B dials the discovered address and runs an
    // operator RPC with no prior knowledge of A.
    let dial_addr: libp2p::Multiaddr = format!("{a_tcp}/p2p/{}", found.peer).parse().unwrap();
    b.handle.dial(dial_addr).await.unwrap();
    dial_and_wait(&b, &a).await;
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        b.handle.rpc_request(
            a.handle.peer_id,
            OperatorRpcRequest {
                auth: P2pAuth::default(),
                body: OperatorRpcBody::GetInfo,
            },
        ),
    )
    .await
    .expect("rpc completes")
    .expect("rpc succeeds");
    match response {
        OperatorRpcResponse::Info(info) => {
            assert_eq!(info.operator_id, "rz-a");
            assert!(info.verify_identity_signature());
        }
        other => panic!("unexpected info response: {other:?}"),
    }
}
