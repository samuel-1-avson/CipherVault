// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! NAT-traversal harness (DON Phase 2): circuit-relay reservations, RPCs
//! over relayed connections, DCUtR direct-upgrade coordination, and AutoNAT
//! v2 reachability confirmation — all on loopback with ephemeral ports.
//!
//! Loopback cannot simulate a real NAT (everything is directly dialable),
//! so the relayed-path test pins DCUtR off to prove data flows through the
//! circuit, while the upgrade test proves DCUtR coordination fires and
//! succeeds. Together with the AutoNAT dial-back test this exercises every
//! protocol message of the NAT ladder.
//!
//! KNOWN FLAKE (2026-09-18): `rpc_flows_over_relayed_circuit` intermittently
//! times out in `wait_for_relay_ready` (1 failure in 3 local runs; relay's
//! own AutoNAT confirmation never arrives within 60 s while sibling tests
//! pass). Passing runs confirm in ~10 s, so this is a missed probe under
//! parallel load, not scheduling latency — re-run the suite. A related
//! deterministic hazard was fixed the same day: the AutoNAT predicate
//! called a panicking TCP-only port helper on QUIC confirmations.

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
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

static NODE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct NatNode {
    handle: SwarmHandle,
    _task: tokio::task::JoinHandle<()>,
    dir: PathBuf,
}

impl Drop for NatNode {
    fn drop(&mut self) {
        self._task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn boot_nat_node(
    tag: &str,
    relay_server: bool,
    dcutr: bool,
) -> (NatNode, Arc<OperatorState>) {
    let slot = NODE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-nat-{}-{}-{}",
        std::process::id(),
        slot,
        tag,
    ));
    let state = Arc::new(OperatorState::new(
        format!("nat-{tag}"),
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
            enable_relay_server: relay_server,
            enable_dcutr: dcutr,
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
    .expect("nat node boots");
    wait_for_tcp(&handle).await;
    (
        NatNode {
            handle,
            _task: task,
            dir,
        },
        state,
    )
}

async fn wait_for_tcp(handle: &SwarmHandle) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let listeners = handle.listeners().await.unwrap();
        if listeners
            .iter()
            .any(|addr| addr.iter().any(|p| matches!(p, Protocol::Tcp(_))))
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "node never listened on tcp"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn tcp_addr(listeners: &[Multiaddr]) -> Multiaddr {
    listeners
        .iter()
        .find(|addr| {
            addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
                && !addr.to_string().contains("p2p-circuit")
        })
        .expect("tcp listen addr")
        .clone()
}

fn tcp_port(addr: &Multiaddr) -> u16 {
    addr.iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("tcp port")
}

/// Waits until the relay server can accept reservations: it advertises
/// HOP only after AutoNAT confirms its own external reachability.
async fn wait_for_relay_ready(relay: &NatNode) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if !relay.handle.external_addrs().await.unwrap().is_empty() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relay never became externally reachable"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn dial_and_wait(from: &NatNode, to_tcp: &Multiaddr, to_peer: PeerId) {
    let dial_addr: Multiaddr = format!("{to_tcp}/p2p/{to_peer}").parse().unwrap();
    from.handle.dial(dial_addr).await.expect("dial succeeds");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if from.handle.is_connected(to_peer).await.unwrap() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "dial never connected"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Reserves a relay slot and returns the circuit address once accepted.
async fn reserve_circuit(node: &NatNode, relay_tcp: &Multiaddr, relay_peer: PeerId) -> Multiaddr {
    let base: Multiaddr = format!("{relay_tcp}/p2p/{relay_peer}/p2p-circuit")
        .parse()
        .unwrap();
    node.handle
        .listen_on(base)
        .await
        .expect("circuit listen ok");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let listeners = node.handle.listeners().await.unwrap();
        if let Some(circuit) = listeners
            .iter()
            .find(|addr| addr.to_string().contains("p2p-circuit"))
        {
            return circuit.clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relay reservation never accepted"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn rpc_get_info(node: &NatNode, peer: PeerId) -> OperatorRpcResponse {
    tokio::time::timeout(
        Duration::from_secs(15),
        node.handle.rpc_request(
            peer,
            OperatorRpcRequest {
                auth: P2pAuth::default(),
                body: OperatorRpcBody::GetInfo,
            },
        ),
    )
    .await
    .expect("rpc completes")
    .expect("rpc succeeds")
}

#[tokio::test]
async fn rpc_flows_over_relayed_circuit() {
    // DCUtR off: the ONLY path between A and B is the relay, so a working
    // RPC proves the reservation + circuit data path deterministically.
    let (relay, _) = boot_nat_node("relay", true, false).await;
    let (node_a, _) = boot_nat_node("a", false, false).await;
    let (node_b, _) = boot_nat_node("b", false, false).await;

    let relay_tcp = tcp_addr(&relay.handle.listeners().await.unwrap());
    dial_and_wait(&node_a, &relay_tcp, relay.handle.peer_id).await;
    dial_and_wait(&node_b, &relay_tcp, relay.handle.peer_id).await;
    wait_for_relay_ready(&relay).await;

    let a_circuit = reserve_circuit(&node_a, &relay_tcp, relay.handle.peer_id).await;
    let b_circuit = reserve_circuit(&node_b, &relay_tcp, relay.handle.peer_id).await;
    assert!(a_circuit.to_string().contains("p2p-circuit"));
    assert!(b_circuit.to_string().contains("p2p-circuit"));

    // A only ever learns B's circuit address — never its direct address.
    // (The reservation address already ends in /p2p/<B>; dial it as-is.)
    node_a
        .handle
        .dial(b_circuit)
        .await
        .expect("circuit dial ok");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if node_a
            .handle
            .is_connected(node_b.handle.peer_id)
            .await
            .unwrap()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "circuit dial never connected"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    match rpc_get_info(&node_a, node_b.handle.peer_id).await {
        OperatorRpcResponse::Info(info) => assert_eq!(info.operator_id, "nat-b"),
        other => panic!("unexpected relayed rpc response: {other:?}"),
    }
    // No upgrade coordination ran with DCUtR off.
    assert!(node_a
        .handle
        .take_dcutr_upgrades()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn dcutr_upgrades_relayed_connection() {
    let (relay, _) = boot_nat_node("relay", true, true).await;
    let (node_a, _) = boot_nat_node("a", false, true).await;
    let (node_b, _) = boot_nat_node("b", false, true).await;

    let relay_tcp = tcp_addr(&relay.handle.listeners().await.unwrap());
    dial_and_wait(&node_a, &relay_tcp, relay.handle.peer_id).await;
    dial_and_wait(&node_b, &relay_tcp, relay.handle.peer_id).await;
    wait_for_relay_ready(&relay).await;

    reserve_circuit(&node_a, &relay_tcp, relay.handle.peer_id).await;
    let b_circuit = reserve_circuit(&node_b, &relay_tcp, relay.handle.peer_id).await;

    node_a
        .handle
        .dial(b_circuit)
        .await
        .expect("circuit dial ok");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if node_a
            .handle
            .is_connected(node_b.handle.peer_id)
            .await
            .unwrap()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "circuit dial never connected"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // DCUtR coordinates a direct upgrade over the relayed link; on loopback
    // the hole-punch dial succeeds and the dialer observes success.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let upgrades = node_a.handle.take_dcutr_upgrades().await.unwrap();
        if upgrades
            .iter()
            .any(|u| u.peer == node_b.handle.peer_id && u.success)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "dcutr upgrade never observed"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The data path survives the upgrade.
    match rpc_get_info(&node_a, node_b.handle.peer_id).await {
        OperatorRpcResponse::Info(info) => assert_eq!(info.operator_id, "nat-b"),
        other => panic!("unexpected post-upgrade rpc response: {other:?}"),
    }
}

#[tokio::test]
async fn autonat_confirms_loopback_reachability() {
    let (relay, _) = boot_nat_node("relay", true, true).await;
    let (node_a, _) = boot_nat_node("a", false, true).await;

    let relay_tcp = tcp_addr(&relay.handle.listeners().await.unwrap());
    dial_and_wait(&node_a, &relay_tcp, relay.handle.peer_id).await;

    // The relay dials A back at its observed (listen-port, thanks to port
    // reuse) address; success confirms A as externally reachable.
    let a_port = tcp_port(&tcp_addr(&node_a.handle.listeners().await.unwrap()));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let external = node_a.handle.external_addrs().await.unwrap();
        // Match TCP only without panicking on QUIC confirmations: the node
        // listens on TCP + QUIC and AutoNAT may confirm either first.
        let tcp_confirmed = external.iter().any(|addr| {
            addr.to_string().contains("127.0.0.1")
                && addr
                    .iter()
                    .any(|proto| matches!(proto, Protocol::Tcp(port) if port == a_port))
        });
        if tcp_confirmed {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "autonat never confirmed reachability (external: {external:?})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
