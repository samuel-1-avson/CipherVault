// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Containerized 10-node chaos gates (DON Phase 4, slice 4). Boots ten real
//! operator containers on one bridge network, meshes their routing tables
//! over HTTP, then proves repair's storm-resistance claims:
//!
//! - Gate A (kill 3/10 mid-write): objects seeded to single holders, repair
//!   observed in flight, then 3 nodes killed; every object must return to
//!   3 replicas on the survivors.
//! - Gate B (partition): 2 survivors cut off past the heartbeat timeout,
//!   then healed; liveness must reconverge and objects stay readable.
//! - Gate C (bandwidth bounds): total repair bytes stay under a fixed cap
//!   (no storm amplification) with zero receiver-side 429s at defaults.
//!
//! Run: `bash scripts/drill/chaos-10node.sh` (builds the image, then runs
//! this test). Direct: `CIPHERVAULT_CHAOS=1 cargo test -p
//! ciphervault-operator --test chaos -- --ignored --nocapture` with the
//! `ciphervault-operator:chaos` image already built.
//!
//! `#[ignore]` + `CIPHERVAULT_CHAOS=1` keep this out of the default gate:
//! it needs a docker daemon and runs ~10 minutes. `CIPHERVAULT_CHAOS_KEEP=1`
//! leaves containers and the network behind for debugging.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use ciphervault_crypto::generate_signing_key;
use ciphervault_storage::client::OperatorClient;
use ciphervault_storage::types::PeerDescriptor;

const IMAGE: &str = "ciphervault-operator:chaos";
const NET: &str = "chaos-net";
const TOKEN: &str = "chaos-token";
const NODES: usize = 10;
const HTTP_PORT_BASE: u16 = 18301;
const P2P_TCP_PORT: u16 = 9101;
const P2P_QUIC_PORT: u16 = 9102;
const OBJECTS: usize = 4;
const OBJECT_BYTES: usize = 8192;
// Generous storm cap: 4 objects x 8 KiB x 2 pushes x 3 rounds x 2
// (sender + receiver both count bytes). Anything above this is a
// repair storm, not backfill.
const REPAIR_BYTES_CAP: u64 = 2 * 1024 * 1024;

fn node_name(i: usize) -> String {
    format!("chaos-n{i}")
}

fn http_endpoint(i: usize) -> String {
    format!("http://127.0.0.1:{}", HTTP_PORT_BASE + i as u16)
}

fn docker(args: &[&str]) -> Vec<u8> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("docker {} failed to spawn: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "docker {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn docker_ok(args: &[&str]) -> bool {
    Command::new("docker")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn docker_logs(name: &str) -> String {
    let out = Command::new("docker")
        .args(["logs", name])
        .output()
        .expect("docker logs spawn");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Best-effort teardown shared by Drop and the explicit end-of-test call.
fn teardown(alive: &[usize]) {
    let keep = std::env::var("CIPHERVAULT_CHAOS_KEEP").as_deref() == Ok("1");
    if keep {
        println!("CIPHERVAULT_CHAOS_KEEP=1: leaving containers and network behind");
        return;
    }
    for i in alive {
        docker_ok(&["rm", "-f", &node_name(*i)]);
    }
    docker_ok(&["network", "rm", NET]);
}

struct Mesh {
    alive: Vec<usize>,
}

impl Drop for Mesh {
    fn drop(&mut self) {
        teardown(&self.alive);
    }
}

async fn wait_http_ok(http: &reqwest::Client, url: &str, timeout: Duration, what: &str) {
    let start = Instant::now();
    loop {
        if let Ok(resp) = http.get(url).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        assert!(
            start.elapsed() < timeout,
            "timeout waiting for {what} at {url}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn metric_value(exposition: &str, name: &str) -> u64 {
    exposition
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (key == name).then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

async fn fetch_metrics(http: &reqwest::Client, i: usize) -> String {
    http.get(format!("{}/metrics", http_endpoint(i)))
        .send()
        .await
        .unwrap_or_else(|e| panic!("node {i} /metrics unreachable: {e}"))
        .text()
        .await
        .expect("metrics body")
}

fn parse_peer_id(logs: &str) -> String {
    logs.lines()
        .find(|l| l.contains("P2P Peer ID:"))
        .and_then(|l| l.split_whitespace().last().map(str::to_string))
        .expect("P2P Peer ID line present")
}

/// Counts live holders of `cid` across `holders`: GET-200 with
/// digest-verified bytes counts, anything else does not.
async fn count_holders(
    clients: &HashMap<usize, (OperatorClient, String)>,
    alive: &[usize],
    cid: &[u8; 32],
) -> usize {
    let mut count = 0;
    for i in alive {
        let (client, token) = &clients[i];
        if client.get_object(token, cid).await.is_ok() {
            count += 1;
        }
    }
    count
}

async fn wait_replicas(
    clients: &HashMap<usize, (OperatorClient, String)>,
    alive: &[usize],
    cids: &[[u8; 32]],
    want: usize,
    timeout: Duration,
    what: &str,
) {
    let start = Instant::now();
    loop {
        let mut ok = true;
        for cid in cids {
            if count_holders(clients, alive, cid).await < want {
                ok = false;
                break;
            }
        }
        if ok {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "timeout ({what}): replicas did not reach {want} per object"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn wait_peers_live(
    http: &reqwest::Client,
    alive: &[usize],
    want: u64,
    timeout: Duration,
    what: &str,
) {
    let start = Instant::now();
    loop {
        let mut ok = true;
        for i in alive {
            let m = fetch_metrics(http, *i).await;
            if metric_value(&m, "ciphervault_swarm_peers_live") != want {
                ok = false;
                break;
            }
        }
        if ok {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "timeout ({what}): peers_live did not converge to {want}"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[tokio::test]
#[ignore]
async fn ten_node_chaos_gates() {
    assert_eq!(
        std::env::var("CIPHERVAULT_CHAOS").as_deref(),
        Ok("1"),
        "refusing to run docker chaos gates without CIPHERVAULT_CHAOS=1"
    );
    assert!(
        docker_ok(&["image", "inspect", IMAGE]),
        "missing image {IMAGE}; run scripts/drill/chaos-10node.sh to build it"
    );
    // HttpTransport attaches this to announce/peer calls (control auth).
    std::env::set_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", TOKEN);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("http client");

    // --- boot ----------------------------------------------------------------
    for i in 0..NODES {
        docker_ok(&["rm", "-f", &node_name(i)]);
    }
    docker_ok(&["network", "rm", NET]);
    docker(&["network", "create", NET]);
    let mut mesh = Mesh {
        alive: (0..NODES).collect(),
    };

    // Dense bootstrap mesh: each node bootstraps every earlier node, so
    // gossipsub/DHT convergence never depends on mDNS multicast.
    let mut peer_addrs: Vec<String> = Vec::new();
    for i in 0..NODES {
        let name = node_name(i);
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            name.clone(),
            "--network".into(),
            NET.into(),
            "-p".into(),
            format!("127.0.0.1:{}:8201", HTTP_PORT_BASE + i as u16),
            "-e".into(),
            format!("CIPHERVAULT_OPERATOR_SERVICE_TOKEN={TOKEN}"),
            "-e".into(),
            "CIPHERVAULT_SWARM_DEBUG=1".into(),
            "-e".into(),
            format!("CIPHERVAULT_ADVERTISE_ENDPOINT=http://{name}:8201"),
            IMAGE.into(),
            "--operator-id".into(),
            name.clone(),
            "--data-dir".into(),
            // Must match the image's writable dir (non-root uid 10001);
            // /data does not exist in ciphervault-operator:chaos.
            "/var/lib/ciphervault".into(),
            "--port".into(),
            "8201".into(),
            "--enable-p2p".into(),
            "--p2p-tcp-port".into(),
            P2P_TCP_PORT.to_string(),
            "--p2p-quic-port".into(),
            P2P_QUIC_PORT.to_string(),
        ];
        if i == 0 {
            args.push("--p2p-rendezvous-server".into());
        }
        for addr in &peer_addrs {
            args.push("--p2p-bootstrap".into());
            args.push(addr.clone());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        docker(&refs);
        wait_http_ok(
            &http,
            &format!("{}/healthz", http_endpoint(i)),
            Duration::from_secs(120),
            &format!("node {i} boot"),
        )
        .await;
        let id = parse_peer_id(&docker_logs(&name));
        peer_addrs.push(format!("/dns/{name}/tcp/{P2P_TCP_PORT}/p2p/{id}"));
        println!("chaos: {name} up peer={id}");
    }

    // --- mesh routing tables ---------------------------------------------------
    // Heartbeats from unknown senders are ignored, so every node must hold
    // every other node's descriptor before liveness can converge.
    let mut selves: HashMap<usize, PeerDescriptor> = HashMap::new();
    for i in 0..NODES {
        let desc: PeerDescriptor = http
            .get(format!("{}/v1/peers/self", http_endpoint(i)))
            .send()
            .await
            .unwrap_or_else(|e| panic!("node {i} /v1/peers/self failed: {e}"))
            .json()
            .await
            .unwrap_or_else(|e| panic!("node {i} self descriptor decode failed: {e}"));
        desc.verify().expect("self descriptor verifies");
        selves.insert(i, desc);
    }
    for i in 0..NODES {
        let client = OperatorClient::new(http_endpoint(i));
        for j in 0..NODES {
            if i != j {
                client
                    .announce_peer(&selves[&j])
                    .await
                    .unwrap_or_else(|e| panic!("announce n{j} -> n{i} failed: {e}"));
            }
        }
    }
    println!("chaos: routing tables meshed (90 announces)");
    wait_peers_live(
        &http,
        &mesh.alive,
        (NODES - 1) as u64,
        Duration::from_secs(240),
        "initial liveness",
    )
    .await;
    println!("chaos: liveness converged (peers_live=9 everywhere)");

    // --- seed objects, one holder each -----------------------------------------
    let device_key = generate_signing_key();
    let vault_id = rand::random::<[u8; 32]>();
    let mut clients: HashMap<usize, (OperatorClient, String)> = HashMap::new();
    for i in 0..NODES {
        let client = OperatorClient::new(http_endpoint(i));
        let token = client
            .authenticate(&vault_id, &device_key)
            .await
            .unwrap_or_else(|e| panic!("node {i} authenticate failed: {e}"));
        clients.insert(i, (client, token));
    }
    let mut cids = Vec::new();
    for (k, holder) in [1usize, 2, 3, 4].into_iter().enumerate() {
        let mut data = vec![0u8; OBJECT_BYTES];
        let tag = format!("chaos-obj-{k}-");
        data[..tag.len()].copy_from_slice(tag.as_bytes());
        for chunk in data[tag.len()..].chunks_mut(32) {
            let word: [u8; 32] = rand::random();
            let len = chunk.len();
            chunk.copy_from_slice(&word[..len]);
        }
        let cid = ciphervault_format::compute_digest(&data);
        let (client, token) = &clients[&holder];
        client
            .put_object(token, &cid, data)
            .await
            .unwrap_or_else(|e| panic!("seed obj{k} -> n{holder} failed: {e}"));
        cids.push(cid);
        println!("chaos: obj{k} seeded on n{holder}");
    }
    let cids: [[u8; 32]; OBJECTS] = cids.try_into().expect("4 cids");

    // Wait until repair is actually in flight somewhere: the kill below
    // must land mid-write, not before the first assessment.
    let start = Instant::now();
    loop {
        let mut inflight = false;
        for i in 0..NODES {
            let m = fetch_metrics(&http, i).await;
            if metric_value(&m, "ciphervault_swarm_repair_jobs_started_total") > 0 {
                inflight = true;
                break;
            }
        }
        if inflight {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(180),
            "timeout: repair never started; kills would not be mid-write"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    println!("chaos: repair in flight; starting Gate A");

    // --- Gate A: kill 3/10 mid-write ---------------------------------------------
    // Victims: two single-holders plus one bystander. n0 (rendezvous seed)
    // survives so the gate tests repair, not re-bootstrap.
    let victims = [1usize, 2, 5];
    for v in victims {
        assert!(docker_ok(&["kill", &node_name(v)]), "kill n{v}");
        mesh.alive.retain(|n| *n != v);
    }
    println!("chaos: Gate A killed n1 n2 n5 mid-write");
    let completed_before: u64 = {
        let mut sum = 0;
        for i in &mesh.alive {
            sum += metric_value(
                &fetch_metrics(&http, *i).await,
                "ciphervault_swarm_repair_jobs_completed_total",
            );
        }
        sum
    };
    wait_replicas(
        &clients,
        &mesh.alive,
        &cids,
        3,
        Duration::from_secs(420),
        "gate A backfill",
    )
    .await;
    let completed_after: u64 = {
        let mut sum = 0;
        for i in &mesh.alive {
            sum += metric_value(
                &fetch_metrics(&http, *i).await,
                "ciphervault_swarm_repair_jobs_completed_total",
            );
        }
        sum
    };
    assert!(
        completed_after > completed_before,
        "Gate A: no repair completed after the kill (before={completed_before} after={completed_after})"
    );
    println!("chaos: Gate A PASS (3 replicas x 4 objects on 7 survivors)");

    // --- Gate B: partition 2 survivors, then heal ----------------------------------
    // Pause (SIGSTOP), not network disconnect: disconnecting tears down the
    // published-port NAT rules and `network connect` does not restore them,
    // leaving the host unable to poll the healed nodes. A freeze is also a
    // faithful partition — no heartbeats in or out past the 15 s timeout.
    let cut = [3usize, 4];
    for c in cut {
        assert!(docker_ok(&["pause", &node_name(c)]), "pause n{c}");
    }
    println!("chaos: Gate B froze n3 n4 for 45s (past the 15s heartbeat timeout)");
    tokio::time::sleep(Duration::from_secs(45)).await;
    for c in cut {
        assert!(docker_ok(&["unpause", &node_name(c)]), "unpause n{c}");
        wait_http_ok(
            &http,
            &format!("{}/healthz", http_endpoint(c)),
            Duration::from_secs(60),
            &format!("node {c} unpause"),
        )
        .await;
    }
    wait_peers_live(
        &http,
        &mesh.alive,
        (mesh.alive.len() - 1) as u64,
        Duration::from_secs(300),
        "gate B reconverge",
    )
    .await;
    wait_replicas(
        &clients,
        &mesh.alive,
        &cids,
        3,
        Duration::from_secs(300),
        "gate B readability",
    )
    .await;
    println!("chaos: Gate B PASS (partition healed, liveness + replicas converged)");

    // --- Gate C: bandwidth bounds --------------------------------------------------
    let mut repair_bytes = 0u64;
    let mut exhausted = 0u64;
    for i in &mesh.alive {
        let m = fetch_metrics(&http, *i).await;
        repair_bytes += metric_value(&m, "ciphervault_swarm_repair_bytes_total");
        exhausted += metric_value(&m, "ciphervault_swarm_repair_budget_exhausted_total");
    }
    assert!(
        repair_bytes > 0,
        "Gate C: repair_bytes_total is 0 — repair never ran, gates prove nothing"
    );
    assert!(
        repair_bytes <= REPAIR_BYTES_CAP,
        "Gate C: repair storm: {repair_bytes} bytes > {REPAIR_BYTES_CAP} cap"
    );
    assert_eq!(
        exhausted, 0,
        "Gate C: {exhausted} pushes 429ed at default 8 MiB/s budget"
    );
    println!("chaos: Gate C PASS ({repair_bytes} repair bytes <= {REPAIR_BYTES_CAP}, 0 exhausted)");

    teardown(&mesh.alive);
    mesh.alive.clear();
    println!("CHAOS PASS: kill-3/10, partition-heal, and bandwidth gates all green");
}
