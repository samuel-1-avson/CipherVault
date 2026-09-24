// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Repair backfill tests (DON Phase 4 slice 2): an under-replicated
//! object is pushed to exactly the deterministically assigned recipients
//! by exactly one pusher, 429s back off and recover, and every step
//! carries telemetry.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_crypto::generate_signing_key;
use ciphervault_format::compute_digest;
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

async fn boot_node(operator_id: &str, repair: RepairConfig) -> (TestNode, Arc<OperatorState>) {
    let slot = NODE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-swarm-repair-{}-{}-{}",
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
            heartbeat_interval: Duration::from_millis(100),
            heartbeat_timeout: Duration::from_millis(600),
            repair,
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

fn mesh_keys(nodes: &[(&TestNode, Arc<OperatorState>, &str)]) {
    for (i, (_, state_i, id_i)) in nodes.iter().enumerate() {
        for (j, (_, state_j, _)) in nodes.iter().enumerate() {
            if i != j {
                announce_key_to(state_j, id_i, &state_i.signing_key);
            }
        }
    }
}

async fn dial(a: &TestNode, b: &TestNode) {
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

/// Waits until `node` reads every peer in `expected` as live (heartbeat
/// mesh converged — the precondition for deterministic repair plans).
async fn wait_live_set(node: &TestNode, expected: &[libp2p::PeerId]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let live = node.handle.live_peers().await.unwrap();
        if expected.iter().all(|peer| live.contains(peer)) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "live set never converged: {live:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_object(state: &OperatorState, cid_hex: &str) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(bytes) = state.get_object(cid_hex) {
            return bytes;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "object {cid_hex} never arrived"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
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

/// Waits until `state`'s `name` counter reaches `want`. Sender-side
/// completion fires on RPC response receipt, which always lags the
/// byte-landing `wait_object` observes — an instant read would race.
async fn wait_metric(state: &OperatorState, name: &str, want: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let exposition = state.metrics.render_prometheus();
        let got = metric_value(&exposition, name);
        if got >= want {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "metric {name} stuck at {got}, want {want}: {exposition}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn test_repair_config(target: usize) -> RepairConfig {
    RepairConfig {
        target,
        cooldown: Duration::from_secs(60),
        // The periodic scanner is out of scope here: these tests assert
        // exact single-round `trigger_repair` semantics, and a scan tick
        // landing after recipients hold the object — but before any
        // provider announcement propagates — elects a second pusher and
        // breaks the exact counts. Disarm it (first tick at boot holds
        // nothing, so it stays a no-op).
        interval: Duration::from_secs(3600),
        ..RepairConfig::default()
    }
}

#[tokio::test]
async fn repair_backfills_under_replicated_object() {
    let config = test_repair_config(3);
    let (node_a, state_a) = boot_node("repair-op-a", config.clone()).await;
    let (node_b, state_b) = boot_node("repair-op-b", config.clone()).await;
    let (node_c, state_c) = boot_node("repair-op-c", config).await;
    mesh_keys(&[
        (&node_a, state_a.clone(), "repair-op-a"),
        (&node_b, state_b.clone(), "repair-op-b"),
        (&node_c, state_c.clone(), "repair-op-c"),
    ]);
    dial(&node_a, &node_b).await;
    dial(&node_a, &node_c).await;
    dial(&node_b, &node_c).await;
    wait_live_set(&node_a, &[node_b.handle.peer_id, node_c.handle.peer_id]).await;

    // A alone holds the object: one holder against a target of 3.
    let bytes = b"repair fixture object".to_vec();
    let cid = compute_digest(&bytes);
    let cid_hex = hex::encode(cid);
    state_a.put_object(&cid_hex, &bytes).expect("seed object");
    node_a.handle.provide_chunk(cid).await.unwrap();

    node_a.handle.trigger_repair(cid).await.unwrap();
    assert_eq!(wait_object(&state_b, &cid_hex).await, bytes);
    assert_eq!(wait_object(&state_c, &cid_hex).await, bytes);

    // Sender telemetry: one assessment, two pushes, both completed.
    let exp_a = state_a.metrics.render_prometheus();
    assert!(metric_value(&exp_a, "ciphervault_swarm_repair_checks_total") >= 1);
    assert_eq!(
        metric_value(&exp_a, "ciphervault_swarm_repair_jobs_started_total"),
        2,
        "one push per recipient: {exp_a}"
    );
    wait_metric(&state_a, "ciphervault_swarm_repair_jobs_completed_total", 2).await;
    assert!(metric_value(&exp_a, "ciphervault_swarm_repair_bytes_total") >= 2 * bytes.len() as u64);
    // Receiver telemetry: B accepted one push.
    let exp_b = state_b.metrics.render_prometheus();
    assert_eq!(
        metric_value(&exp_b, "ciphervault_swarm_repair_jobs_completed_total"),
        1,
        "B accepts exactly one push: {exp_b}"
    );
}

#[tokio::test]
async fn single_pusher_no_duplicate_backfill() {
    let config = test_repair_config(3);
    let (node_a, state_a) = boot_node("repair-op-a", config.clone()).await;
    let (node_b, state_b) = boot_node("repair-op-b", config.clone()).await;
    let (node_c, state_c) = boot_node("repair-op-c", config).await;
    mesh_keys(&[
        (&node_a, state_a.clone(), "repair-op-a"),
        (&node_b, state_b.clone(), "repair-op-b"),
        (&node_c, state_c.clone(), "repair-op-c"),
    ]);
    dial(&node_a, &node_b).await;
    dial(&node_a, &node_c).await;
    dial(&node_b, &node_c).await;
    for node in [&node_a, &node_b, &node_c] {
        let others: Vec<libp2p::PeerId> = [&node_a, &node_b, &node_c]
            .iter()
            .filter(|n| n.handle.peer_id != node.handle.peer_id)
            .map(|n| n.handle.peer_id)
            .collect();
        wait_live_set(node, &others).await;
    }

    // Both A and B hold the object; C is the only repair candidate.
    let bytes = b"two-holder repair fixture".to_vec();
    let cid = compute_digest(&bytes);
    let cid_hex = hex::encode(cid);
    state_a.put_object(&cid_hex, &bytes).expect("seed A");
    state_b.put_object(&cid_hex, &bytes).expect("seed B");
    node_a.handle.provide_chunk(cid).await.unwrap();
    node_b.handle.provide_chunk(cid).await.unwrap();

    // Convergence precondition: both holders see the same provider set
    // before triggering, so both compute the identical plan.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let providers_a = node_a.handle.get_providers(cid).await.unwrap();
        let providers_b = node_b.handle.get_providers(cid).await.unwrap();
        let want = [node_a.handle.peer_id, node_b.handle.peer_id];
        if want.iter().all(|p| providers_a.contains(p))
            && want.iter().all(|p| providers_b.contains(p))
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "provider views never converged: {providers_a:?} vs {providers_b:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    node_a.handle.trigger_repair(cid).await.unwrap();
    node_b.handle.trigger_repair(cid).await.unwrap();
    assert_eq!(wait_object(&state_c, &cid_hex).await, bytes);

    // Exactly one pusher sent exactly one push: rendezvous agreement,
    // no N-holder fan-out, no duplicate backfill.
    let exp_a = state_a.metrics.render_prometheus();
    let exp_b = state_b.metrics.render_prometheus();
    let total_started = metric_value(&exp_a, "ciphervault_swarm_repair_jobs_started_total")
        + metric_value(&exp_b, "ciphervault_swarm_repair_jobs_started_total");
    assert_eq!(total_started, 1, "single pusher, single push");
    let exp_c = state_c.metrics.render_prometheus();
    assert_eq!(
        metric_value(&exp_c, "ciphervault_swarm_repair_jobs_completed_total"),
        1,
        "C accepts exactly one push"
    );
}

#[tokio::test]
async fn repair_backoff_on_budget_exhaustion_then_recovers() {
    let config = test_repair_config(2);
    let (node_a, state_a) = boot_node("repair-op-a", config.clone()).await;
    let (node_b, state_b) = boot_node("repair-op-b", config).await;
    mesh_keys(&[
        (&node_a, state_a.clone(), "repair-op-a"),
        (&node_b, state_b.clone(), "repair-op-b"),
    ]);
    dial(&node_a, &node_b).await;
    wait_live_set(&node_a, &[node_b.handle.peer_id]).await;

    let bytes = b"budget-gated repair fixture".to_vec();
    let cid = compute_digest(&bytes);
    let cid_hex = hex::encode(cid);
    state_a.put_object(&cid_hex, &bytes).expect("seed object");
    node_a.handle.provide_chunk(cid).await.unwrap();

    // Zero receiver budget: the push 429s, nothing stores, the sender
    // schedules paced backoff instead of hot-looping.
    state_b.set_repair_budget(0);
    node_a.handle.trigger_repair(cid).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let exp = state_a.metrics.render_prometheus();
        if metric_value(&exp, "ciphervault_swarm_repair_backoff_total") >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sender never backed off"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(state_b.get_object(&cid_hex).is_none());
    let exp_b = state_b.metrics.render_prometheus();
    assert_eq!(
        metric_value(&exp_b, "ciphervault_swarm_repair_budget_exhausted_total"),
        1,
        "B 429s exactly once: {exp_b}"
    );

    // Recovery: budget restored, explicit re-trigger bypasses the
    // backoff cooldown, the object lands.
    state_b.set_repair_budget(100 * 1024 * 1024);
    node_a.handle.trigger_repair(cid).await.unwrap();
    assert_eq!(wait_object(&state_b, &cid_hex).await, bytes);
    wait_metric(&state_a, "ciphervault_swarm_repair_jobs_completed_total", 1).await;
}
