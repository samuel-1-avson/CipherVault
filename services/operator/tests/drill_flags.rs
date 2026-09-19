// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Drill-flag tests (DON Phase 2): spawn the real operator daemon binary
//! against an in-process node and assert `--p2p-probe-peer` reports the
//! probed operator and `--p2p-relay-reserve` prints a live circuit address.
//! These flags are what make the NAT hole-punch drill executable.

use std::path::PathBuf;
use std::process::Stdio;
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
use tokio::io::{AsyncBufReadExt, BufReader};

static DRILL_COUNTER: AtomicU64 = AtomicU64::new(0);

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

async fn boot_target(operator_id: &str, relay_server: bool) -> TestNode {
    let slot = DRILL_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-drill-{}-{}-{}",
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
            enable_relay_server: relay_server,
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
    .expect("target node boots");
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

async fn target_tcp(node: &TestNode) -> libp2p::Multiaddr {
    node.handle
        .listeners()
        .await
        .unwrap()
        .into_iter()
        .find(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        })
        .expect("target has a tcp listen addr")
}

/// Spawns the daemon with `extra_args`, waits up to `timeout` for a stdout
/// line containing `want`, then kills the child and returns all captured
/// output plus whether the line appeared. The child is ALWAYS reaped, even
/// on timeout, so failures never orphan daemons.
async fn run_daemon_until(
    tag: &str,
    extra_args: &[String],
    want: &str,
    timeout: Duration,
) -> (bool, String) {
    let slot = DRILL_COUNTER.fetch_add(1, Ordering::SeqCst);
    let data_dir = std::env::temp_dir().join(format!(
        "ciphervault-drilld-{}-{}-{}",
        std::process::id(),
        slot,
        tag,
    ));
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ciphervault-operator"))
        .arg("--operator-id")
        .arg(format!("drill-{tag}"))
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--port")
        .arg("0")
        .arg("--enable-p2p")
        .arg("--p2p-tcp-port")
        .arg("0")
        .arg("--p2p-quic-port")
        .arg("0")
        .args(extra_args)
        .env("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", "drill-token")
        .env("CIPHERVAULT_SWARM_DEBUG", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("daemon spawns");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout piped")).lines();
    let mut err_lines = BufReader::new(child.stderr.take().expect("stderr piped")).lines();
    let mut captured = String::new();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut found = false;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Drain stderr opportunistically so the pipe never blocks the child.
        while let Ok(Ok(Some(line))) =
            tokio::time::timeout(Duration::from_millis(1), err_lines.next_line()).await
        {
            captured.push_str("[stderr] ");
            captured.push_str(&line);
            captured.push('\n');
        }
        match tokio::time::timeout(remaining, lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                captured.push_str(&line);
                captured.push('\n');
                if line.contains(want) {
                    found = true;
                    break;
                }
            }
            _ => break,
        }
    }
    // Collect stderr for failure diagnosis.
    while let Ok(Ok(Some(line))) =
        tokio::time::timeout(Duration::from_millis(50), err_lines.next_line()).await
    {
        captured.push_str("[stderr] ");
        captured.push_str(&line);
        captured.push('\n');
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
    let _ = std::fs::remove_dir_all(&data_dir);
    (found, captured)
}

#[tokio::test]
async fn probe_peer_flag_reports_operator_info() {
    let target = boot_target("drill-target", false).await;
    let tcp = target_tcp(&target).await;
    let bootstrap = format!("{tcp}/p2p/{}", target.handle.peer_id);
    let want = format!(
        "P2P probe {}: OK operator=drill-target",
        target.handle.peer_id
    );
    let (found, captured) = run_daemon_until(
        "prober",
        &[
            "--p2p-bootstrap".to_string(),
            bootstrap,
            "--p2p-probe-peer".to_string(),
            target.handle.peer_id.to_string(),
        ],
        &want,
        Duration::from_secs(45),
    )
    .await;
    assert!(
        found,
        "probe line missing.\n--- daemon output ---\n{captured}"
    );
}

#[tokio::test]
async fn relay_reserve_flag_prints_circuit_addr() {
    let relay = boot_target("drill-relay", true).await;
    let tcp = target_tcp(&relay).await;
    // The relay server advertises HOP only once the swarm knows an external
    // address (AutoNAT confirmation in production); declare it directly for
    // a deterministic test.
    relay.handle.add_external_addr(tcp.clone()).await.unwrap();
    let relay_addr = format!("{tcp}/p2p/{}", relay.handle.peer_id);
    let (found, captured) = run_daemon_until(
        "reserver",
        &[
            "--p2p-bootstrap".to_string(),
            relay_addr.clone(),
            "--p2p-relay-reserve".to_string(),
            relay_addr,
        ],
        "p2p-circuit",
        Duration::from_secs(45),
    )
    .await;
    assert!(
        found,
        "circuit addr line missing.\n--- daemon output ---\n{captured}"
    );
    assert!(
        captured.contains("P2P relay circuit:"),
        "reservation banner missing.\n--- daemon output ---\n{captured}"
    );
}
