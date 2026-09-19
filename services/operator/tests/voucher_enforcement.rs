// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Voucher enforcement tests (DON Phase 3, D4): with policy on, voucherless
//! writes are rejected before persistence (403, zero bytes on disk) and
//! quotas bound spend (429) — identically across the HTTP, P2P, and memory
//! legs. Policy-off nodes keep static behavior byte-for-byte. The disk-fill
//! drill (attacker without a voucher, holder with a small quota) is the
//! Phase 3 gate scenario.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};

use ciphervault_crypto::generate_signing_key;
use ciphervault_format::compute_digest;
use ciphervault_operator::swarm::behaviour::{
    OperatorRpcBody, OperatorRpcRequest, OperatorRpcResponse, P2pAuth,
};
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::transport::Libp2pTransport;
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::{create_router, OperatorState};
use ciphervault_storage::vouchers::WriteVoucher;
use ciphervault_storage::StorageError;
use ciphervault_storage::{MemoryTransport, OperatorClient, OperatorTransport};

static VOUCHER_COUNTER: AtomicU64 = AtomicU64::new(0);

fn setup_env() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::env::set_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", "voucher-test-token");
        for name in [
            "CIPHERVAULT_OPERATOR_STRICT_AUTH",
            "CIPHERVAULT_OPERATOR_REQUIRE_ENROLLMENT",
            "CIPHERVAULT_TRUSTED_PEER_KEYS",
            "CIPHERVAULT_MAX_OBJECT_SIZE",
            "CIPHERVAULT_MAX_RECOVERY_RECORD_SIZE",
            "CIPHERVAULT_MAX_RECOVERY_RESPONSE_BYTES",
        ] {
            std::env::remove_var(name);
        }
    });
}

fn server_status(err: &StorageError) -> Option<u16> {
    match err {
        StorageError::ServerError { status, .. } => Some(*status),
        _ => None,
    }
}

fn random_object(size: usize) -> ([u8; 32], Vec<u8>) {
    let bytes: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
    let cid = compute_digest(&bytes);
    (cid, bytes)
}

fn dir_bytes(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = std::fs::read_dir(&path).expect("read dir");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let meta = entry.metadata().expect("metadata");
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    total
}

fn fresh_holder_pk() -> String {
    hex::encode(generate_signing_key().verifying_key().to_bytes())
}

struct HttpNode {
    base_url: String,
    dir: PathBuf,
    state: Arc<OperatorState>,
    _task: tokio::task::JoinHandle<()>,
}

impl Drop for HttpNode {
    fn drop(&mut self) {
        self._task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn boot_http(operator_id: &str, vouchers_required: bool, max_quota: u64) -> HttpNode {
    setup_env();
    let slot = VOUCHER_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-voucher-{}-{}-{}",
        std::process::id(),
        slot,
        operator_id,
    ));
    let state = Arc::new(OperatorState::new(
        operator_id.to_string(),
        dir.clone(),
        generate_signing_key(),
    ));
    state.set_vouchers_required(vouchers_required);
    state.set_voucher_max_quota(max_quota);
    let app = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("test server runs");
    });
    HttpNode {
        base_url,
        dir,
        state,
        _task: task,
    }
}

struct P2pNode {
    handle: SwarmHandle,
    state: Arc<OperatorState>,
    _task: tokio::task::JoinHandle<()>,
    dir: PathBuf,
}

impl Drop for P2pNode {
    fn drop(&mut self) {
        self._task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn boot_p2p_node(operator_id: &str, tag: &str) -> P2pNode {
    setup_env();
    let slot = VOUCHER_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-voucher-p2p-{}-{}-{}",
        std::process::id(),
        slot,
        tag,
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
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let listeners = handle.listeners().await.unwrap();
        if listeners.iter().any(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "swarm node never listened"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    P2pNode {
        handle,
        state,
        _task: task,
        dir,
    }
}

async fn p2p_client_for(server: &P2pNode) -> (OperatorClient, P2pNode) {
    let client_node = boot_p2p_node("voucher-client", "client").await;
    let server_tcp = server
        .handle
        .listeners()
        .await
        .expect("server listeners")
        .into_iter()
        .find(|addr| {
            addr.iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
        })
        .expect("server tcp listen addr");
    let dial_addr: libp2p::Multiaddr = format!("{server_tcp}/p2p/{}", server.handle.peer_id)
        .parse()
        .unwrap();
    client_node
        .handle
        .dial(dial_addr)
        .await
        .expect("client dials server");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if client_node
            .handle
            .is_connected(server.handle.peer_id)
            .await
            .unwrap()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "p2p client never connected"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let transport = Libp2pTransport::new(
        client_node.handle.clone(),
        server.handle.peer_id,
        vec![server_tcp],
    );
    let client = OperatorClient::with_transport(
        format!("p2p://{}", server.handle.peer_id),
        Arc::new(transport.clone()) as Arc<dyn OperatorTransport>,
    );
    (client, client_node)
}

#[tokio::test]
async fn policy_off_keeps_static_behavior() {
    // Frozen static proof: policy off + no voucher behaves exactly as
    // before. A presented voucher is still honored (uniform semantics),
    // including its quota bound.
    let node = boot_http("voucher-off", false, u64::MAX).await;
    let client = OperatorClient::new(node.base_url.clone());
    let vault_id: [u8; 32] = rand::random();
    let vault_key = generate_signing_key();
    let token = client
        .authenticate(&vault_id, &vault_key)
        .await
        .expect("authenticate works");

    let (cid, bytes) = random_object(64);
    client
        .put_object(&token, &cid, bytes)
        .await
        .expect("voucherless put works when policy off");

    let voucher = node
        .state
        .issue_voucher(fresh_holder_pk(), 64, 3600)
        .expect("issue works");
    client.set_write_voucher(Some(voucher));
    let (cid2, bytes2) = random_object(64);
    client
        .put_object(&token, &cid2, bytes2)
        .await
        .expect("vouchered put works when policy off");
    let (cid3, bytes3) = random_object(64);
    let err = client
        .put_object(&token, &cid3, bytes3)
        .await
        .expect_err("quota still bounds vouchered spend when policy off");
    assert_eq!(server_status(&err), Some(429));
}

#[tokio::test]
async fn http_voucherless_write_rejected_before_persistence() {
    let node = boot_http("voucher-on", true, u64::MAX).await;
    let client = OperatorClient::new(node.base_url.clone());
    let vault_id: [u8; 32] = rand::random();
    let vault_key = generate_signing_key();
    let token = client
        .authenticate(&vault_id, &vault_key)
        .await
        .expect("authenticate works");

    let (cid, bytes) = random_object(1024);
    let err = client
        .put_object(&token, &cid, bytes)
        .await
        .expect_err("voucherless put rejected");
    assert_eq!(server_status(&err), Some(403));
    assert_eq!(
        dir_bytes(&node.dir.join("objects")),
        0,
        "rejected write persisted nothing"
    );

    // Leases need vouchers too (authorize, no bytes charged).
    let closure: [u8; 32] = rand::random();
    let err = client
        .commit_lease(&token, &closure, 4096, 30)
        .await
        .expect_err("voucherless lease rejected");
    assert_eq!(server_status(&err), Some(403));
}

#[tokio::test]
async fn http_issuance_endpoint_gates_on_service_token() {
    let node = boot_http("voucher-issue", true, u64::MAX).await;
    let http = reqwest::Client::new();
    let body = serde_json::json!({
        "holder_pk_hex": fresh_holder_pk(),
        "quota_bytes": 1024,
        "ttl_secs": 3600,
    });
    let denied = http
        .post(format!("{}/v1/vouchers", node.base_url))
        .json(&body)
        .send()
        .await
        .expect("request sends");
    assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);

    let granted = http
        .post(format!("{}/v1/vouchers", node.base_url))
        .header("X-CipherVault-Service-Token", "voucher-test-token")
        .json(&body)
        .send()
        .await
        .expect("request sends");
    assert_eq!(granted.status(), reqwest::StatusCode::OK);
    let voucher: WriteVoucher = granted.json().await.expect("voucher parses");

    // The issued voucher authorizes a real write end to end.
    let client = OperatorClient::new(node.base_url.clone());
    let vault_id: [u8; 32] = rand::random();
    let vault_key = generate_signing_key();
    let token = client.authenticate(&vault_id, &vault_key).await.unwrap();
    client.set_write_voucher(Some(voucher));
    let (cid, bytes) = random_object(512);
    client
        .put_object(&token, &cid, bytes)
        .await
        .expect("issued voucher authorizes the write");
}

#[tokio::test]
async fn client_issue_voucher_roundtrip() {
    let node = boot_http("voucher-client", true, u64::MAX).await;
    let client = OperatorClient::new(node.base_url.clone());
    let holder = fresh_holder_pk();
    let voucher = client
        .issue_voucher(&holder, 4096, 3600)
        .await
        .expect("client issuance works with the service token env");
    assert_eq!(voucher.holder_pk_hex, holder);
    assert_eq!(voucher.quota_bytes, 4096);

    // The client-issued voucher authorizes a real write end to end.
    let vault_id: [u8; 32] = rand::random();
    let vault_key = generate_signing_key();
    let token = client.authenticate(&vault_id, &vault_key).await.unwrap();
    client.set_write_voucher(Some(voucher));
    let (cid, bytes) = random_object(512);
    client
        .put_object(&token, &cid, bytes)
        .await
        .expect("client-issued voucher authorizes the write");
}

#[tokio::test]
async fn disk_fill_drill_attacker_blocked_holder_bounded() {
    // Phase 3 gate scenario: an authenticated attacker with no voucher
    // cannot store a single byte; a holder with a 4 KiB quota fills it and
    // is then cut off. Disk usage stays bounded throughout.
    let node = boot_http("voucher-drill", true, 1024 * 1024).await;

    let attacker = OperatorClient::new(node.base_url.clone());
    let attacker_vault: [u8; 32] = rand::random();
    let attacker_key = generate_signing_key();
    let attacker_token = attacker
        .authenticate(&attacker_vault, &attacker_key)
        .await
        .expect("attacker authenticates");
    let mut rejected = 0u32;
    for _ in 0..50 {
        let (cid, bytes) = random_object(4096);
        let err = attacker
            .put_object(&attacker_token, &cid, bytes)
            .await
            .expect_err("attacker put rejected");
        assert_eq!(server_status(&err), Some(403));
        rejected += 1;
    }
    assert_eq!(rejected, 50);
    assert_eq!(
        dir_bytes(&node.dir.join("objects")),
        0,
        "50 rejected writes persisted nothing"
    );

    let holder = OperatorClient::new(node.base_url.clone());
    let holder_vault: [u8; 32] = rand::random();
    let holder_key = generate_signing_key();
    let holder_token = holder
        .authenticate(&holder_vault, &holder_key)
        .await
        .expect("holder authenticates");
    let voucher = node
        .state
        .issue_voucher(fresh_holder_pk(), 4096, 3600)
        .expect("issue works");
    holder.set_write_voucher(Some(voucher));
    let (cid, bytes) = random_object(4096);
    holder
        .put_object(&holder_token, &cid, bytes.clone())
        .await
        .expect("quota-fitting write succeeds");
    // Idempotent re-PUT of identical bytes stores nothing new, so it
    // succeeds even with the quota fully spent.
    holder
        .put_object(&holder_token, &cid, bytes)
        .await
        .expect("idempotent re-PUT consumes no quota");
    let err = {
        let (cid2, bytes2) = random_object(4096);
        holder
            .put_object(&holder_token, &cid2, bytes2)
            .await
            .expect_err("over-quota write rejected")
    };
    assert_eq!(server_status(&err), Some(429));
    assert!(
        dir_bytes(&node.dir.join("objects")) <= 4096,
        "disk bounded by quota"
    );
}

#[tokio::test]
async fn leases_authorize_without_charging_quota() {
    let node = boot_http("voucher-lease", true, u64::MAX).await;
    let client = OperatorClient::new(node.base_url.clone());
    let vault_id: [u8; 32] = rand::random();
    let vault_key = generate_signing_key();
    let token = client.authenticate(&vault_id, &vault_key).await.unwrap();
    let voucher = node
        .state
        .issue_voucher(fresh_holder_pk(), 100, 3600)
        .expect("issue works");
    client.set_write_voucher(Some(voucher));

    let closure: [u8; 32] = rand::random();
    client
        .commit_lease(&token, &closure, 4096, 30)
        .await
        .expect("lease commits with voucher");
    // The full 100-byte quota is still available: leases charge nothing.
    let (cid, bytes) = random_object(100);
    client
        .put_object(&token, &cid, bytes)
        .await
        .expect("quota untouched by lease");
    let (cid2, bytes2) = random_object(1);
    let err = client
        .put_object(&token, &cid2, bytes2)
        .await
        .expect_err("quota exhausted");
    assert_eq!(server_status(&err), Some(429));
}

#[tokio::test]
async fn p2p_voucher_enforcement_matches_http() {
    let server = boot_p2p_node("voucher-p2p", "server").await;
    server.state.set_vouchers_required(true);
    let (client, _client_node) = p2p_client_for(&server).await;
    let vault_id: [u8; 32] = rand::random();
    let vault_key = generate_signing_key();
    let token = client
        .authenticate(&vault_id, &vault_key)
        .await
        .expect("p2p authenticate works");

    // Raw RPC without a voucher but with a valid session: 403 (voucher
    // gate, not the 401 session gate).
    let (cid, bytes) = random_object(128);
    let raw = client
        .put_object(&token, &cid, bytes.clone())
        .await
        .expect_err("p2p voucherless put rejected");
    assert_eq!(server_status(&raw), Some(403));

    let voucher = server
        .state
        .issue_voucher(fresh_holder_pk(), 128, 3600)
        .expect("issue works");
    client.set_write_voucher(Some(voucher));
    client
        .put_object(&token, &cid, bytes)
        .await
        .expect("p2p vouchered put works");
    let (cid2, bytes2) = random_object(128);
    let err = client
        .put_object(&token, &cid2, bytes2)
        .await
        .expect_err("p2p over-quota rejected");
    assert_eq!(server_status(&err), Some(429));
}

#[tokio::test]
async fn p2p_raw_rpc_without_voucher_returns_403() {
    // Below the client: a hand-built envelope with a valid session but no
    // voucher must fail at the voucher gate (403), proving the server —
    // not the client — enforces.
    let server = boot_p2p_node("voucher-raw", "server").await;
    server.state.set_vouchers_required(true);
    let (client, client_node) = p2p_client_for(&server).await;
    let vault_id: [u8; 32] = rand::random();
    let vault_key = generate_signing_key();
    let token = client
        .authenticate(&vault_id, &vault_key)
        .await
        .expect("p2p authenticate works");

    let (cid, bytes) = random_object(64);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        client_node.handle.rpc_request(
            server.handle.peer_id,
            OperatorRpcRequest {
                auth: P2pAuth {
                    bearer_token: Some(token),
                    vault_id_hex: Some(hex::encode(vault_id)),
                    service_token: None,
                    voucher: None,
                },
                body: OperatorRpcBody::PutObject { cid, data: bytes },
            },
        ),
    )
    .await
    .expect("rpc completes")
    .expect("rpc succeeds");
    match response {
        OperatorRpcResponse::Err { status, .. } => assert_eq!(status, 403),
        other => panic!("expected 403, got {other:?}"),
    }
}

#[tokio::test]
async fn memory_leg_matches_enforcement() {
    let transport = MemoryTransport::new("voucher-memory");
    transport.set_vouchers_required(true);
    let client = OperatorClient::with_transport(
        "memory://voucher-memory".to_string(),
        Arc::new(transport.clone()) as Arc<dyn OperatorTransport>,
    );
    let vault_id: [u8; 32] = rand::random();
    let vault_key = generate_signing_key();
    let token = client
        .authenticate(&vault_id, &vault_key)
        .await
        .expect("memory authenticate works");

    let (cid, bytes) = random_object(64);
    let err = client
        .put_object(&token, &cid, bytes.clone())
        .await
        .expect_err("memory voucherless put rejected");
    assert_eq!(server_status(&err), Some(403));

    let voucher = transport
        .issue_voucher(fresh_holder_pk(), 64, 3600)
        .expect("memory issue works");
    client.set_write_voucher(Some(voucher));
    client
        .put_object(&token, &cid, bytes)
        .await
        .expect("memory vouchered put works");
    let (cid2, bytes2) = random_object(64);
    let err = client
        .put_object(&token, &cid2, bytes2)
        .await
        .expect_err("memory over-quota rejected");
    assert_eq!(server_status(&err), Some(429));

    // Recovery appends enforce identically on the memory leg.
    client.set_write_voucher(None);
    let locator: [u8; 32] = rand::random();
    let err = client
        .append_recovery_record(&token, &locator, vec![1u8; 32])
        .await
        .expect_err("memory voucherless append rejected");
    assert_eq!(server_status(&err), Some(403));
}
