// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Signed bootstrap-list tests (DON Phase 2): a node boots from a fleet-signed
//! first-contact list and dials the listed seed; tampered lists, signer
//! mismatches, and half-configured list options refuse to boot.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::swarm::bootstrap::BootstrapList;
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;

static BOOT_COUNTER: AtomicU64 = AtomicU64::new(0);

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

fn fresh_dir(tag: &str) -> PathBuf {
    let slot = BOOT_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "ciphervault-bootstrap-{}-{}-{}",
        std::process::id(),
        slot,
        tag,
    ))
}

async fn boot_with(
    tag: &str,
    bootstrap_list_path: Option<PathBuf>,
    bootstrap_signer_hex: Option<String>,
) -> Result<TestNode, ciphervault_operator::swarm::SwarmError> {
    let dir = fresh_dir(tag);
    let state = Arc::new(OperatorState::new(
        format!("boot-{tag}"),
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
            bootstrap_list_path,
            bootstrap_signer_hex,
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
    .await?;
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
    Ok(node)
}

async fn node_tcp_addr(node: &TestNode) -> libp2p::Multiaddr {
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

#[tokio::test]
async fn signed_list_boots_and_dials_seed() {
    let seed = boot_with("seed", None, None).await.expect("seed boots");
    let seed_tcp = node_tcp_addr(&seed).await;
    let seed_addr = format!("{seed_tcp}/p2p/{}", seed.handle.peer_id);

    let fleet_key = generate_signing_key();
    let fleet_pk = hex::encode(fleet_key.verifying_key().to_bytes());
    let mut list = BootstrapList::unsigned(vec![seed_addr]);
    list.sign(&fleet_key);
    let list_path = fresh_dir("list").join("bootstrap.json");
    std::fs::create_dir_all(list_path.parent().unwrap()).unwrap();
    std::fs::write(&list_path, serde_json::to_vec_pretty(&list).unwrap()).unwrap();

    let node = boot_with("node", Some(list_path.clone()), Some(fleet_pk))
        .await
        .expect("signed list boots");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if node.handle.is_connected(seed.handle.peer_id).await.unwrap() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "node never dialed the listed seed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = std::fs::remove_dir_all(list_path.parent().unwrap());
}

#[tokio::test]
async fn tampered_list_refuses_to_boot() {
    let fleet_key = generate_signing_key();
    let fleet_pk = hex::encode(fleet_key.verifying_key().to_bytes());
    let mut list = BootstrapList::unsigned(vec!["/ip4/192.0.2.1/tcp/9101".to_string()]);
    list.sign(&fleet_key);
    // Tamper after signing: the signature no longer covers the addrs.
    list.addrs[0] = "/ip4/198.51.100.9/tcp/9101".to_string();
    let list_path = fresh_dir("tampered").join("bootstrap.json");
    std::fs::create_dir_all(list_path.parent().unwrap()).unwrap();
    std::fs::write(&list_path, serde_json::to_vec_pretty(&list).unwrap()).unwrap();

    let err = match boot_with("refused", Some(list_path.clone()), Some(fleet_pk)).await {
        Err(err) => err,
        Ok(_) => panic!("tampered list must refuse to boot"),
    };
    assert!(
        err.to_string().contains("signature"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_dir_all(list_path.parent().unwrap());
}

#[tokio::test]
async fn signer_mismatch_refuses_to_boot() {
    let fleet_key = generate_signing_key();
    let mut list = BootstrapList::unsigned(vec!["/ip4/192.0.2.1/tcp/9101".to_string()]);
    list.sign(&fleet_key);
    let other_pk = hex::encode(generate_signing_key().verifying_key().to_bytes());
    let list_path = fresh_dir("mismatch").join("bootstrap.json");
    std::fs::create_dir_all(list_path.parent().unwrap()).unwrap();
    std::fs::write(&list_path, serde_json::to_vec_pretty(&list).unwrap()).unwrap();

    let err = match boot_with("refused", Some(list_path.clone()), Some(other_pk)).await {
        Err(err) => err,
        Ok(_) => panic!("signer mismatch must refuse to boot"),
    };
    assert!(
        err.to_string().contains("signer"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_dir_all(list_path.parent().unwrap());
}

#[tokio::test]
async fn half_configured_list_refuses_to_boot() {
    let list_path = fresh_dir("half").join("bootstrap.json");
    let err = match boot_with("refused", Some(list_path), None).await {
        Err(err) => err,
        Ok(_) => panic!("list path without signer must refuse to boot"),
    };
    assert!(
        err.to_string().contains("together"),
        "unexpected error: {err}"
    );

    let fleet_pk = hex::encode(generate_signing_key().verifying_key().to_bytes());
    let err = match boot_with("refused", None, Some(fleet_pk)).await {
        Err(err) => err,
        Ok(_) => panic!("signer without list path must refuse to boot"),
    };
    assert!(
        err.to_string().contains("together"),
        "unexpected error: {err}"
    );
}
