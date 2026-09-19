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
//! FLAKINESS DESIGN (2026-09-19): the relay's own AutoNAT confirmation
//! needs a two-tick cascade — a leaf must probe first so the relay's server
//! dials back (its only outbound connection, which is what teaches its
//! client a server), and only then can the relay probe at its next tick.
//! Worse, libp2p-autonat 0.16 latches a candidate `Failed` forever after one
//! `AddressNotReachable`, so a single transient dial-back stall past the
//! 10 s server timeout wedges that node until the deadline with zero
//! further probes. Three mitigations, all load-bearing:
//!
//! 1. The tests in this file run serially (`NAT_SERIAL`): nine swarms
//!    probing at once is what stalls a loopback dial-back past 10 s.
//! 2. The relay dials a leaf back explicitly, so its client learns a
//!    server immediately instead of via the dial-back cascade.
//! 3. Relay/AutoNAT readiness retries the whole setup with fresh nodes
//!    (fresh AutoNAT state) a bounded number of times instead of failing
//!    the suite on one wedged candidate.

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

/// Serializes this file's tests: concurrent nine-swarm stampedes stall
/// loopback AutoNAT dial-backs past the 10 s server timeout, and one
/// `AddressNotReachable` latches the candidate `Failed` forever.
static NAT_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

/// Waits until the relay server can accept reservations: libp2p denies
/// inbound HOP at the protocol level until AutoNAT confirms our own
/// external reachability. Returns the observed state on timeout so the
/// caller can retry with fresh nodes (a latched `Failed` candidate never
/// re-probes) instead of asserting on the first stall.
async fn wait_for_relay_ready(relay: &NatNode) -> Result<(), String> {
    // Healthy confirmation lands in ~5 s (first probe tick once a server
    // is known); 30 s is six ticks of headroom, past which the candidate
    // is assumed latched and the setup is rebuilt rather than waited out.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let external = relay.handle.external_addrs().await.unwrap();
        if !external.is_empty() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            let listeners = relay.handle.listeners().await.unwrap();
            return Err(format!(
                "external_addrs still empty; listeners={listeners:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Boots relay+A+B, meshes the dials, and waits for relay HOP readiness,
/// retrying the whole setup with fresh nodes when readiness stalls: fresh
/// keys/ports mean fresh AutoNAT candidates, which is the only recovery
/// from the permanent `Failed` latch.
async fn setup_relayed_trio(dcutr: bool) -> (NatNode, NatNode, NatNode, Multiaddr) {
    let mut last_err = String::new();
    for attempt in 1..=3 {
        let (relay, _) = boot_nat_node("relay", true, dcutr).await;
        let (node_a, _) = boot_nat_node("a", false, dcutr).await;
        let (node_b, _) = boot_nat_node("b", false, dcutr).await;
        let relay_tcp = tcp_addr(&relay.handle.listeners().await.unwrap());
        let a_tcp = tcp_addr(&node_a.handle.listeners().await.unwrap());
        dial_and_wait(&node_a, &relay_tcp, relay.handle.peer_id).await;
        dial_and_wait(&node_b, &relay_tcp, relay.handle.peer_id).await;
        // Outbound from the relay: its AutoNAT client only probes via
        // servers learned on outbound connections, so without this dial
        // the relay waits a full extra probe tick for the dial-back
        // cascade. This changes nothing about the A<->B path under test,
        // which stays circuit-only with DCUtR off.
        dial_and_wait(&relay, &a_tcp, node_a.handle.peer_id).await;
        match wait_for_relay_ready(&relay).await {
            Ok(()) => return (relay, node_a, node_b, relay_tcp),
            Err(err) => {
                last_err = format!("attempt {attempt}: {err}");
                // Nodes drop here: swarm tasks aborted, temp dirs removed.
            }
        }
    }
    panic!("relay never became externally reachable ({last_err})");
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
    let _serial = NAT_SERIAL.lock().await;
    let (relay, node_a, node_b, relay_tcp) = setup_relayed_trio(false).await;

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
    let _serial = NAT_SERIAL.lock().await;
    let (relay, node_a, node_b, relay_tcp) = setup_relayed_trio(true).await;

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

/// Waits until AutoNAT confirms the node's TCP listen address. Returns
/// the observed state on timeout so the caller can retry with fresh nodes
/// (same permanent-`Failed` latch as [`wait_for_relay_ready`]).
async fn wait_for_autonat_tcp(node: &NatNode, port: u16) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let external = node.handle.external_addrs().await.unwrap();
        // Match TCP only without panicking on QUIC confirmations: the node
        // listens on TCP + QUIC and AutoNAT may confirm either first.
        let tcp_confirmed = external.iter().any(|addr| {
            addr.to_string().contains("127.0.0.1")
                && addr
                    .iter()
                    .any(|proto| matches!(proto, Protocol::Tcp(p) if p == port))
        });
        if tcp_confirmed {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("external: {external:?}"));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn autonat_confirms_loopback_reachability() {
    let _serial = NAT_SERIAL.lock().await;
    let mut last_err = String::new();
    for attempt in 1..=3 {
        let (relay, _) = boot_nat_node("relay", true, true).await;
        let (node_a, _) = boot_nat_node("a", false, true).await;

        let relay_tcp = tcp_addr(&relay.handle.listeners().await.unwrap());
        dial_and_wait(&node_a, &relay_tcp, relay.handle.peer_id).await;

        // The relay dials A back at its observed (listen-port, thanks to port
        // reuse) address; success confirms A as externally reachable.
        let a_port = tcp_port(&tcp_addr(&node_a.handle.listeners().await.unwrap()));
        match wait_for_autonat_tcp(&node_a, a_port).await {
            Ok(()) => return,
            Err(err) => {
                last_err = format!("attempt {attempt}: {err}");
            }
        }
    }
    panic!("autonat never confirmed reachability ({last_err})");
}
