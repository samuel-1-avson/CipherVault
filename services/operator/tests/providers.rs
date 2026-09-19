// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Chunk provider-record tests (DON Phase 2): two nodes advertise the same
//! chunk CID and a third discovers both providers through Kademlia; an
//! unprovided CID resolves to zero providers. Provider records are routing
//! hints — fetched bytes self-verify by CID hash — so the assertions cover
//! discovery completeness, not trust.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;

static PROV_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    let slot = PROV_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-prov-{}-{}-{}",
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

async fn dial_and_wait(from: &TestNode, to: &TestNode) {
    let to_tcp = to
        .handle
        .listeners()
        .await
        .unwrap()
        .into_iter()
        .find(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        })
        .expect("peer has a tcp listen addr");
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
async fn providers_advertise_and_resolve() {
    let a = boot_node("prov-a").await;
    let b = boot_node("prov-b").await;
    let c = boot_node("prov-c").await;
    dial_and_wait(&a, &b).await;
    dial_and_wait(&b, &c).await;
    dial_and_wait(&c, &a).await;

    let cid: [u8; 32] = rand::random();
    a.handle.provide_chunk(cid).await.unwrap();
    b.handle.provide_chunk(cid).await.unwrap();

    // Fresh query per iteration until both providers are visible.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    let found = loop {
        let providers = tokio::time::timeout(Duration::from_secs(10), c.handle.get_providers(cid))
            .await
            .expect("single provider lookup terminates")
            .expect("lookup channel open");
        let has_a = providers.contains(&a.handle.peer_id);
        let has_b = providers.contains(&b.handle.peer_id);
        if has_a && has_b || tokio::time::Instant::now() > deadline {
            break providers;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(
        found.contains(&a.handle.peer_id),
        "provider A resolves: {found:?}"
    );
    assert!(
        found.contains(&b.handle.peer_id),
        "provider B resolves: {found:?}"
    );
    assert_eq!(found.len(), 2, "exactly the two providers: {found:?}");
}

#[tokio::test]
async fn unprovided_chunk_resolves_no_providers() {
    let a = boot_node("prov-d").await;
    let b = boot_node("prov-e").await;
    dial_and_wait(&a, &b).await;

    let ghost: [u8; 32] = rand::random();
    let providers = tokio::time::timeout(Duration::from_secs(15), b.handle.get_providers(ghost))
        .await
        .expect("empty provider lookup terminates")
        .expect("lookup channel open");
    assert!(providers.is_empty(), "nothing provides it: {providers:?}");
}
