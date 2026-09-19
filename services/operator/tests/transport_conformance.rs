// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! # Dual-transport conformance suite
//!
//! Identical behavioral assertions run against BOTH the [`HttpTransport`]
//! (live Axum operator backends on localhost, built from the real
//! [`create_router`] with fresh signing keys and temp data dirs) and the
//! [`MemoryTransport`] (in-process, no sockets). Any divergence is a bug —
//! the memory backend must model the exact HTTP semantics from
//! `services/operator/src/handlers.rs` so DON Phase 2 (libp2p) can build on
//! a trustworthy contract.
//!
//! Each case is an `async fn(Harness)` instantiated once per backend via
//! [`all_transports`]. Cases assert on [`OperatorClient`] behavior only;
//! transport-specific faults (memory offline flags, TCP failures) are
//! covered by unit tests in each transport instead.
//!
//! Deliberate divergences (documented on [`MemoryTransport`]) are NOT
//! asserted here: recovery CBOR authorization, challenge/session TTLs,
//! recovery append sequence values, and non-HTTP peer endpoint schemes.
//! The P2P leg has no divergences: it reuses the HTTP auth checks and state
//! methods by construction.
//!
//! [`HttpTransport`]: ciphervault_storage::HttpTransport
//! [`MemoryTransport`]: ciphervault_storage::MemoryTransport
//! [`OperatorClient`]: ciphervault_storage::OperatorClient
//! [`create_router`]: ciphervault_operator::create_router

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};

use ciphervault_crypto::generate_signing_key;
use ciphervault_format::{compute_digest, to_canonical_cbor, GenesisRecord, PROTOCOL_VERSION};
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::transport::Libp2pTransport;
use ciphervault_operator::swarm::{boot_swarm, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::{create_router, OperatorState};
use ciphervault_storage::types::{ChallengeRequest, ChallengeResponse, SessionRequest};
use ciphervault_storage::{
    compute_pos_proof, MemoryTransport, MultiOperatorPool, OperatorClient, OperatorTransport,
    PeerDescriptor, StorageError,
};
use ed25519_dalek::SigningKey;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

static SERVER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Hermetic control-plane environment: the service token is fixed for the
/// whole test process (both [`HttpTransport`] and the handlers read the same
/// var), and every env switch that could change handler semantics is
/// removed so developer shells cannot skew results.
fn setup_env() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::env::set_var(
            "CIPHERVAULT_OPERATOR_SERVICE_TOKEN",
            "conformance-test-token",
        );
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

struct HttpGuard {
    task: tokio::task::JoinHandle<()>,
    dir: PathBuf,
}

impl Drop for HttpGuard {
    fn drop(&mut self) {
        self.task.abort();
        // Best effort: a failed assertion must not leave temp dirs behind,
        // but cleanup failure must never mask the real failure.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// One backend under test. HTTP legs hold the server guard so the router
/// stays alive for the whole case; memory legs hold the transport handle;
/// P2P legs hold a server swarm node plus a client node bound to it.
enum Harness {
    Http {
        client: OperatorClient,
        base_url: String,
        _guard: HttpGuard,
    },
    Memory {
        client: OperatorClient,
        transport: MemoryTransport,
    },
    P2p {
        client: OperatorClient,
        transport: Libp2pTransport,
        _server: Box<P2pNode>,
        _client_node: Box<P2pNode>,
    },
}

struct P2pNode {
    handle: SwarmHandle,
    _task: tokio::task::JoinHandle<()>,
    dir: PathBuf,
}

impl Drop for P2pNode {
    fn drop(&mut self) {
        self._task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Harness {
    async fn http(operator_id: &str) -> Self {
        setup_env();
        let slot = SERVER_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "ciphervault-conformance-{}-{}-{}",
            std::process::id(),
            slot,
            operator_id,
        ));
        let state = Arc::new(OperatorState::new(
            operator_id.to_string(),
            dir.clone(),
            generate_signing_key(),
        ));
        let app = create_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener binds");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });
        let client = OperatorClient::new(base_url.clone());
        for _ in 0..100 {
            if client.get_info().await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // Fail loudly if the server never came up instead of timing out later.
        client.get_info().await.expect("test server ready");
        Harness::Http {
            client,
            base_url,
            _guard: HttpGuard { task, dir },
        }
    }

    fn memory(operator_id: &str) -> Self {
        setup_env();
        let transport = MemoryTransport::new(operator_id);
        let client = OperatorClient::with_transport(
            format!("memory://{operator_id}"),
            Arc::new(transport.clone()) as Arc<dyn OperatorTransport>,
        );
        Harness::Memory { client, transport }
    }

    async fn p2p(operator_id: &str) -> Self {
        setup_env();
        let server = Self::boot_p2p_node(operator_id, "server").await;
        let client_node = Self::boot_p2p_node("conformance-client", "client").await;

        // Peer-qualified dial, then wait for the connection before any RPC.
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
        Harness::P2p {
            client,
            transport,
            _server: Box::new(server),
            _client_node: Box::new(client_node),
        }
    }

    async fn boot_p2p_node(operator_id: &str, tag: &str) -> P2pNode {
        let slot = SERVER_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "ciphervault-conformance-p2p-{}-{}-{}",
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
            state,
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
            _task: task,
            dir,
        }
    }

    fn client(&self) -> &OperatorClient {
        match self {
            Harness::Http { client, .. } => client,
            Harness::Memory { client, .. } => client,
            Harness::P2p { client, .. } => client,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Harness::Http { .. } => "http",
            Harness::Memory { .. } => "memory",
            Harness::P2p { .. } => "p2p",
        }
    }
}

/// Instantiates one `async fn(Harness)` case against all three backends.
macro_rules! all_transports {
    ($http_test:ident, $mem_test:ident, $p2p_test:ident, $case:ident) => {
        #[tokio::test]
        async fn $http_test() {
            $case(Harness::http("conformance-op").await).await;
        }

        #[tokio::test]
        async fn $mem_test() {
            $case(Harness::memory("conformance-op")).await;
        }

        #[tokio::test]
        async fn $p2p_test() {
            $case(Harness::p2p("conformance-op").await).await;
        }
    };
}

fn sample_object() -> ([u8; 32], Vec<u8>) {
    let bytes = b"dual-transport conformance fixture".to_vec();
    let cid = compute_digest(&bytes);
    (cid, bytes)
}

/// Self-certifying genesis record signed by the session key, so the real
/// operator's CBOR authorization accepts it (first append registers the
/// recovery key; repeats match it and the caller equals it).
fn genesis_bytes(vault_id: &[u8; 32], recovery_key: &SigningKey) -> Vec<u8> {
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: recovery_key.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: vec![7u8; 32],
        policy_digest: vec![0u8; 32],
        created_at_utc: chrono::Utc::now().timestamp().max(0) as u64,
        creation_nonce: vec![9u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(recovery_key).expect("genesis signs");
    to_canonical_cbor(&genesis).expect("genesis encodes")
}

fn server_status(err: &StorageError) -> Option<u16> {
    match err {
        StorageError::ServerError { status, .. } => Some(*status),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Cases: identity and sessions
// ---------------------------------------------------------------------------

async fn case_info_identity_verifies(h: Harness) {
    let info = h.client().get_info().await.expect("get_info works");
    assert_eq!(info.operator_id, "conformance-op", "leg {}", h.label());
    assert!(info.verify_identity_signature(), "leg {}", h.label());
    assert_eq!(info.supported_version, 1, "leg {}", h.label());

    // Pinned path: the advertised key pins, is fresh, and still verifies.
    let pk_bytes = hex::decode(&info.operator_signing_pk_hex).unwrap();
    let pk: [u8; 32] = pk_bytes.as_slice().try_into().unwrap();
    let pinned = h
        .client()
        .get_info_pinned(&pk)
        .await
        .expect("pinned identity verifies");
    assert_eq!(pinned.operator_id, "conformance-op", "leg {}", h.label());

    // A wrong pin is rejected on both backends.
    let wrong_pin = [0xA5u8; 32];
    assert!(
        h.client().get_info_pinned(&wrong_pin).await.is_err(),
        "leg {}",
        h.label()
    );
}

async fn case_auth_put_revoke_cycle(h: Harness) {
    let client = h.client();
    let key = generate_signing_key();
    let vault_id: [u8; 32] = rand::random();
    let token = client
        .authenticate(&vault_id, &key)
        .await
        .expect("authenticate works");

    // The session authorizes writes.
    let (cid, bytes) = sample_object();
    client
        .put_object(&token, &cid, bytes.clone())
        .await
        .expect("session put works");

    // Revocation kills the session on both backends ...
    client.revoke_session(&token).await.expect("revoke works");
    let err = client
        .put_object(&token, &cid, bytes)
        .await
        .expect_err("revoked session cannot write");
    assert_eq!(server_status(&err), Some(401), "leg {}", h.label());

    // ... and revoking twice (or revoking garbage) fails identically.
    let err = client
        .revoke_session(&token)
        .await
        .expect_err("double revoke fails");
    assert_eq!(server_status(&err), Some(401), "leg {}", h.label());
    let err = client
        .revoke_session("bogus-token")
        .await
        .expect_err("bogus revoke fails");
    assert_eq!(server_status(&err), Some(401), "leg {}", h.label());
}

async fn case_challenge_replay_rejected(h: Harness) {
    let key = generate_signing_key();
    let vault_id: [u8; 32] = rand::random();
    let vault_hex = hex::encode(vault_id);
    let pk_hex = hex::encode(key.verifying_key().as_bytes());

    // Transport-level legs share one helper: single-use challenges and
    // unknown IDs fail instead of minting sessions.
    async fn assert_replay_rejected(
        transport: &impl OperatorTransport,
        key: &SigningKey,
        vault_hex: String,
        pk_hex: String,
    ) {
        let challenge = transport
            .request_challenge(ChallengeRequest {
                vault_id_hex: vault_hex,
                public_key_hex: pk_hex.clone(),
                account_id: None,
                device_id_hex: None,
            })
            .await
            .unwrap();
        let nonce = hex::decode(&challenge.nonce_hex).unwrap();
        let sig =
            ciphervault_crypto::signatures::sign_with_domain(key, b"operator_challenge", &nonce);
        let redeem = SessionRequest {
            challenge_id: challenge.challenge_id.clone(),
            public_key_hex: pk_hex.clone(),
            signature_hex: hex::encode(sig),
        };
        transport.redeem_session(redeem.clone()).await.unwrap();
        assert!(transport.redeem_session(redeem).await.is_err());
        assert!(transport
            .redeem_session(SessionRequest {
                challenge_id: "no-such-challenge".into(),
                public_key_hex: pk_hex,
                signature_hex: hex::encode([0u8; 64]),
            })
            .await
            .is_err());
    }

    match h {
        Harness::Memory { transport, .. } => {
            assert_replay_rejected(&transport, &key, vault_hex, pk_hex).await;
        }
        Harness::P2p { transport, .. } => {
            assert_replay_rejected(&transport, &key, vault_hex, pk_hex).await;
        }
        Harness::Http { base_url, .. } => {
            let http = reqwest::Client::new();
            let challenge: ChallengeResponse = http
                .post(format!("{base_url}/v1/challenges"))
                .json(&ChallengeRequest {
                    vault_id_hex: vault_hex,
                    public_key_hex: pk_hex.clone(),
                    account_id: None,
                    device_id_hex: None,
                })
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            let nonce = hex::decode(&challenge.nonce_hex).unwrap();
            let sig = ciphervault_crypto::signatures::sign_with_domain(
                &key,
                b"operator_challenge",
                &nonce,
            );
            let redeem = SessionRequest {
                challenge_id: challenge.challenge_id.clone(),
                public_key_hex: pk_hex.clone(),
                signature_hex: hex::encode(sig),
            };
            let first = http
                .post(format!("{base_url}/v1/sessions"))
                .json(&redeem)
                .send()
                .await
                .unwrap();
            assert_eq!(first.status(), reqwest::StatusCode::OK);
            // The challenge is single-use: the identical redeem is rejected.
            let replay = http
                .post(format!("{base_url}/v1/sessions"))
                .json(&redeem)
                .send()
                .await
                .unwrap();
            assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
            let unknown = http
                .post(format!("{base_url}/v1/sessions"))
                .json(&SessionRequest {
                    challenge_id: "no-such-challenge".into(),
                    public_key_hex: pk_hex,
                    signature_hex: hex::encode([0u8; 64]),
                })
                .send()
                .await
                .unwrap();
            assert_eq!(unknown.status(), reqwest::StatusCode::UNAUTHORIZED);
        }
    }
}

// ---------------------------------------------------------------------------
// Cases: objects and PoS
// ---------------------------------------------------------------------------

async fn case_object_put_get_roundtrip(h: Harness) {
    let client = h.client();
    let key = generate_signing_key();
    let vault_id: [u8; 32] = rand::random();
    let token = client.authenticate(&vault_id, &key).await.unwrap();

    let (cid, bytes) = sample_object();
    client
        .put_object(&token, &cid, bytes.clone())
        .await
        .unwrap();
    // Idempotent re-upload of identical bytes succeeds.
    client
        .put_object(&token, &cid, bytes.clone())
        .await
        .unwrap();
    assert_eq!(client.get_object(&token, &cid).await.unwrap(), bytes);

    // Missing objects are 404 on both backends.
    let missing: [u8; 32] = rand::random();
    let err = client
        .get_object(&token, &missing)
        .await
        .expect_err("missing object fails");
    assert_eq!(server_status(&err), Some(404), "leg {}", h.label());

    // CID/body digest mismatches are rejected before storage.
    let wrong_cid: [u8; 32] = rand::random();
    assert!(
        client.put_object(&token, &wrong_cid, bytes).await.is_err(),
        "leg {}",
        h.label()
    );

    // Oversize payloads are rejected (4 MiB cap on both backends).
    let big = vec![0x55u8; 4 * 1024 * 1024 + 1];
    let big_cid = compute_digest(&big);
    assert!(
        client.put_object(&token, &big_cid, big).await.is_err(),
        "leg {}",
        h.label()
    );
}

async fn case_anonymous_reads_and_pos(h: Harness) {
    let client = h.client();
    let key = generate_signing_key();
    let vault_id: [u8; 32] = rand::random();
    let token = client.authenticate(&vault_id, &key).await.unwrap();

    let (cid, bytes) = sample_object();
    client
        .put_object(&token, &cid, bytes.clone())
        .await
        .unwrap();

    // The public recovery token reads objects and PoS on both backends ...
    assert_eq!(
        client.get_object("recovery_anonymous", &cid).await.unwrap(),
        bytes,
        "leg {}",
        h.label()
    );
    let nonce: [u8; 32] = rand::random();
    let receipt = client
        .challenge_object_pos("recovery_anonymous", &cid, &nonce)
        .await
        .expect("anonymous PoS works");
    assert_eq!(
        receipt.proof_hex,
        hex::encode(compute_pos_proof(&cid, &nonce, &bytes))
    );

    // ... while garbage tokens fail closed on reads and writes alike.
    let err = client
        .get_object("bogus-token", &cid)
        .await
        .expect_err("bogus read fails");
    assert_eq!(server_status(&err), Some(401), "leg {}", h.label());
    let err = client
        .put_object("recovery_anonymous", &cid, bytes)
        .await
        .expect_err("anonymous write fails");
    assert_eq!(server_status(&err), Some(401), "leg {}", h.label());
}

async fn case_pos_proof_verifies(h: Harness) {
    let client = h.client();
    let key = generate_signing_key();
    let vault_id: [u8; 32] = rand::random();
    let token = client.authenticate(&vault_id, &key).await.unwrap();

    let info = client.get_info().await.unwrap();
    let pk_bytes = hex::decode(&info.operator_signing_pk_hex).unwrap();
    let pk: [u8; 32] = pk_bytes.as_slice().try_into().unwrap();

    let (cid, bytes) = sample_object();
    client
        .put_object(&token, &cid, bytes.clone())
        .await
        .unwrap();
    let nonce: [u8; 32] = rand::random();
    let receipt = client
        .challenge_object_pos(&token, &cid, &nonce)
        .await
        .unwrap();
    let expected = compute_pos_proof(&cid, &nonce, &bytes);
    assert_eq!(
        receipt.proof_hex,
        hex::encode(expected),
        "leg {}",
        h.label()
    );
    assert_eq!(receipt.size_bytes, bytes.len() as u64, "leg {}", h.label());
    receipt
        .verify(&pk, &expected)
        .expect("PoS receipt verifies");

    // PoS over a missing object is 404, not a fabricated proof.
    let missing: [u8; 32] = rand::random();
    let err = client
        .challenge_object_pos(&token, &missing, &nonce)
        .await
        .expect_err("PoS over missing object fails");
    assert_eq!(server_status(&err), Some(404), "leg {}", h.label());
}

// ---------------------------------------------------------------------------
// Cases: leases
// ---------------------------------------------------------------------------

async fn case_lease_commit_renew(h: Harness) {
    let client = h.client();
    let key = generate_signing_key();
    let vault_id: [u8; 32] = rand::random();
    let token = client.authenticate(&vault_id, &key).await.unwrap();

    let info = client.get_info().await.unwrap();
    let pk_bytes = hex::decode(&info.operator_signing_pk_hex).unwrap();
    let pk: [u8; 32] = pk_bytes.as_slice().try_into().unwrap();

    let closure: [u8; 32] = rand::random();
    let receipt = client
        .commit_lease(&token, &closure, 4096, 30)
        .await
        .expect("lease commits");
    assert_eq!(receipt.operator_id, "conformance-op", "leg {}", h.label());
    assert_eq!(
        receipt.closure_digest_hex,
        hex::encode(closure),
        "leg {}",
        h.label()
    );
    assert_eq!(receipt.bytes, 4096, "leg {}", h.label());
    assert_eq!(receipt.term_days, 30, "leg {}", h.label());
    receipt.verify(&pk).expect("lease receipt verifies");

    // Renewal extends term and expiry and re-signs.
    let renewed = client
        .renew_lease(&token, &receipt.lease_id, 15, 4096)
        .await
        .expect("lease renews");
    assert_eq!(renewed.lease_id, receipt.lease_id, "leg {}", h.label());
    assert_eq!(renewed.term_days, 45, "leg {}", h.label());
    assert!(
        renewed.expires_at_utc > receipt.expires_at_utc,
        "leg {}",
        h.label()
    );
    renewed.verify(&pk).expect("renewed receipt verifies");

    // Unknown leases, empty renewals, byte mismatches, and empty terms fail.
    let err = client
        .renew_lease(&token, &"0".repeat(32), 15, 4096)
        .await
        .expect_err("unknown lease renew fails");
    assert!(server_status(&err).is_some(), "leg {}", h.label());
    assert!(
        client
            .renew_lease(&token, &receipt.lease_id, 0, 4096)
            .await
            .is_err(),
        "leg {}",
        h.label()
    );
    assert!(
        client
            .renew_lease(&token, &receipt.lease_id, 15, 1)
            .await
            .is_err(),
        "leg {}",
        h.label()
    );
    assert!(
        client
            .commit_lease(&token, &closure, 4096, 0)
            .await
            .is_err(),
        "leg {}",
        h.label()
    );
}

all_transports!(
    info_identity_verifies_http,
    info_identity_verifies_memory,
    info_identity_verifies_p2p,
    case_info_identity_verifies
);
all_transports!(
    auth_put_revoke_cycle_http,
    auth_put_revoke_cycle_memory,
    auth_put_revoke_cycle_p2p,
    case_auth_put_revoke_cycle
);
all_transports!(
    challenge_replay_rejected_http,
    challenge_replay_rejected_memory,
    challenge_replay_rejected_p2p,
    case_challenge_replay_rejected
);
all_transports!(
    object_put_get_roundtrip_http,
    object_put_get_roundtrip_memory,
    object_put_get_roundtrip_p2p,
    case_object_put_get_roundtrip
);
all_transports!(
    anonymous_reads_and_pos_http,
    anonymous_reads_and_pos_memory,
    anonymous_reads_and_pos_p2p,
    case_anonymous_reads_and_pos
);
all_transports!(
    pos_proof_verifies_http,
    pos_proof_verifies_memory,
    pos_proof_verifies_p2p,
    case_pos_proof_verifies
);
all_transports!(
    lease_commit_renew_http,
    lease_commit_renew_memory,
    lease_commit_renew_p2p,
    case_lease_commit_renew
);

// ---------------------------------------------------------------------------
// Cases: recovery log
// ---------------------------------------------------------------------------

async fn case_recovery_log_roundtrip(h: Harness) {
    let client = h.client();
    // The session key doubles as the recovery authority so the real
    // operator's caller check accepts follow-up appends.
    let recovery_key = generate_signing_key();
    let vault_id: [u8; 32] = rand::random();
    let token = client.authenticate(&vault_id, &recovery_key).await.unwrap();

    let locator: [u8; 32] = rand::random();
    let genesis = genesis_bytes(&vault_id, &recovery_key);
    client
        .append_recovery_record(&token, &locator, genesis.clone())
        .await
        .expect("first append works");
    client
        .append_recovery_record(&token, &locator, genesis.clone())
        .await
        .expect("repeat append works");

    // Appends are anonymously discoverable, in order, on both backends.
    // (Sequence values differ by design: memory reports 0-based positions
    // while the server always returns 1. The pool ignores the value.)
    let records = client.get_recovery_records(&locator).await.unwrap();
    assert_eq!(records, vec![genesis.clone(), genesis], "leg {}", h.label());

    // Unknown locators read back empty rather than failing.
    let unknown: [u8; 32] = rand::random();
    assert!(
        client
            .get_recovery_records(&unknown)
            .await
            .unwrap()
            .is_empty(),
        "leg {}",
        h.label()
    );

    // Oversize records are rejected (64 KiB cap on both backends).
    let big = vec![0x33u8; 64 * 1024 + 1];
    assert!(
        client
            .append_recovery_record(&token, &locator, big)
            .await
            .is_err(),
        "leg {}",
        h.label()
    );
}

// ---------------------------------------------------------------------------
// Cases: gossip and approvals
// ---------------------------------------------------------------------------

async fn case_peer_gossip_roundtrip(h: Harness) {
    let client = h.client();
    assert!(
        client.get_peers().await.expect("peers list").is_empty(),
        "leg {}",
        h.label()
    );

    let peer_key = generate_signing_key();
    let descriptor = PeerDescriptor::new(
        "gossip-peer-1".to_string(),
        "http://127.0.0.1:9".to_string(),
        &peer_key,
    );
    client.announce_peer(&descriptor).await.unwrap();
    let peers = client.get_peers().await.unwrap();
    assert_eq!(peers, vec![descriptor.clone()], "leg {}", h.label());

    // Re-announcing the same operator ID replaces the entry on both.
    let updated = PeerDescriptor::new(
        "gossip-peer-1".to_string(),
        "http://127.0.0.1:10".to_string(),
        &peer_key,
    );
    client.announce_peer(&updated).await.unwrap();
    let peers = client.get_peers().await.unwrap();
    assert_eq!(peers, vec![updated], "leg {}", h.label());

    // Tampered announcements are rejected before storage.
    let mut tampered = PeerDescriptor::new(
        "gossip-peer-evil".to_string(),
        "http://127.0.0.1:11".to_string(),
        &peer_key,
    );
    tampered.endpoint = "http://127.0.0.1:12".to_string();
    assert!(
        client.announce_peer(&tampered).await.is_err(),
        "leg {}",
        h.label()
    );
    assert_eq!(
        client.get_peers().await.unwrap().len(),
        1,
        "leg {}",
        h.label()
    );
}

async fn case_pending_approvals_empty(h: Harness) {
    let pending = h.client().get_pending_approvals().await.unwrap();
    assert!(pending.is_empty(), "leg {}", h.label());
}

async fn case_peer_discovery_expands_pool(h: Harness) {
    // Seeding one peer through gossip lets the pool discover one endpoint.
    let endpoint = match &h {
        Harness::Http { base_url, .. } => base_url.clone(),
        Harness::Memory { .. } => "memory://conformance-op".to_string(),
        Harness::P2p { transport, .. } => format!("p2p://{}", transport.peer_id()),
    };
    let peer_key = generate_signing_key();
    h.client()
        .announce_peer(&PeerDescriptor::new(
            "discovered-seed".to_string(),
            "http://127.0.0.1:9".to_string(),
            &peer_key,
        ))
        .await
        .unwrap();

    let client = match h {
        Harness::Http { client, .. } => client,
        Harness::Memory { client, .. } => client,
        Harness::P2p { client, .. } => client,
    };
    let mut pool = MultiOperatorPool::from_clients(vec![client]);
    assert_eq!(pool.endpoints(), vec![endpoint]);
    let added = pool.discover_and_expand_peers().await.unwrap();
    assert_eq!(added, 1);
    assert_eq!(pool.clients().len(), 2);
}

// ---------------------------------------------------------------------------
// Cases: full replication pipeline
// ---------------------------------------------------------------------------

async fn case_pool_replicate_end_to_end(h: Harness) {
    let client = match h {
        Harness::Http { client, .. } => client,
        Harness::Memory { client, .. } => client,
        Harness::P2p { client, .. } => client,
    };
    let pool = MultiOperatorPool::from_clients(vec![client]);

    let vault_id: [u8; 32] = rand::random();
    let recovery_key = generate_signing_key();
    let (cid, bytes) = sample_object();
    let closure: [u8; 32] = rand::random();
    let locator: [u8; 32] = rand::random();
    let genesis = genesis_bytes(&vault_id, &recovery_key);

    // The whole static pipeline — PoS dedup, upload, lease + signature
    // verification, readback, recovery publication + discovery — runs
    // unchanged against all three transports.
    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &recovery_key,
            &[(cid, bytes.clone())],
            &closure,
            bytes.len() as u64,
            30,
            &locator,
            &genesis,
            std::slice::from_ref(&genesis),
            1,
        )
        .await
        .expect("pipeline replicates");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].operator_id, "conformance-op");
    assert_eq!(receipts[0].closure_digest_hex, hex::encode(closure));
    assert_eq!(receipts[0].bytes, bytes.len() as u64);
    assert_eq!(receipts[0].term_days, 30);
}

all_transports!(
    recovery_log_roundtrip_http,
    recovery_log_roundtrip_memory,
    recovery_log_roundtrip_p2p,
    case_recovery_log_roundtrip
);
all_transports!(
    peer_gossip_roundtrip_http,
    peer_gossip_roundtrip_memory,
    peer_gossip_roundtrip_p2p,
    case_peer_gossip_roundtrip
);
all_transports!(
    pending_approvals_empty_http,
    pending_approvals_empty_memory,
    pending_approvals_empty_p2p,
    case_pending_approvals_empty
);
all_transports!(
    peer_discovery_expands_pool_http,
    peer_discovery_expands_pool_memory,
    peer_discovery_expands_pool_p2p,
    case_peer_discovery_expands_pool
);
all_transports!(
    pool_replicate_end_to_end_http,
    pool_replicate_end_to_end_memory,
    pool_replicate_end_to_end_p2p,
    case_pool_replicate_end_to_end
);
