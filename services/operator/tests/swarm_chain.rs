//! Chain-sync gossip transport tests (Phase 2, item 3).
//!
//! Two live operator swarms prove envelopes cross the mesh and the
//! transport admission gate classifies them: well-formed fleet messages
//! are accepted and relayed, forgeries and non-members are rejected
//! (Byzantine penalty), wrong-chain payloads and the unset-validator case
//! are ignored without penalty. Consensus decisions stay in
//! `ciphervault-chain::sync` unit tests; this suite covers the bytes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciphervault_chain::sync::{ChainSyncEnvelope, ChainSyncMsg, ProposalMsg, VoteMsg};
use ciphervault_chain::{
    BlockHeader, CipherChainBlock, CommitmentTx, ConsensusSigner, SovereignLedger, ValidatorSet,
    SOVEREIGN_CHAIN_ID_STR,
};
use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, ChainStats, SwarmHandle, SwarmNodeConfig};
use ciphervault_operator::OperatorState;

static NODE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestNode {
    handle: SwarmHandle,
    _task: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn legacy_state(
    id: String,
    dir: std::path::PathBuf,
    key: ed25519_dalek::SigningKey,
) -> OperatorState {
    OperatorState::new_with_security(
        id,
        dir,
        key,
        ciphervault_operator::state::OperatorSecurityConfig::legacy(),
    )
}

async fn boot_node(operator_id: &str) -> (TestNode, Arc<OperatorState>) {
    let slot = NODE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-swarm-chain-{}-{}-{}",
        std::process::id(),
        slot,
        operator_id,
    ));
    let state = Arc::new(legacy_state(
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
            repair: RepairConfig::default(),
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

async fn dial_and_wait(a: &TestNode, b: &TestNode) {
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

async fn wait_chain_stats(node: &TestNode, want: ChainStats) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let stats = node.handle.chain_stats().await.unwrap();
        if stats.accepted >= want.accepted
            && stats.rejected >= want.rejected
            && stats.ignored >= want.ignored
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "chain stats stuck at {stats:?}, want at least {want:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn publish_chain_until_ok(node: &TestNode, data: Vec<u8>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        match node.handle.publish_chain(data.clone()).await {
            Ok(_) => break,
            Err(e) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "chain publish never accepted: {e}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn fleet(signers: &[ConsensusSigner]) -> ValidatorSet {
    ValidatorSet::new(signers.iter().map(|s| s.public_key()).collect()).unwrap()
}

fn dummy_header(proposer: &[u8; 32]) -> BlockHeader {
    BlockHeader {
        version: 1,
        chain_id: SOVEREIGN_CHAIN_ID_STR.to_string(),
        height: 1,
        prev_block_hash: [0u8; 32],
        state_root: [0u8; 32],
        tx_root: [0u8; 32],
        timestamp_ms: 2_000,
        proposer: *proposer,
        signatures: Vec::new(),
    }
}

fn sealed_vote_bytes(signer: &ConsensusSigner) -> Vec<u8> {
    let header = dummy_header(&signer.public_key());
    let endorsement = signer.sign_header(&header);
    let envelope = ChainSyncEnvelope::seal(
        signer,
        ChainSyncMsg::Vote(VoteMsg {
            chain_id: SOVEREIGN_CHAIN_ID_STR.to_string(),
            observed_ms: header.timestamp_ms,
            header,
            endorsement,
        }),
    );
    serde_json::to_vec(&envelope).unwrap()
}

fn sealed_proposal_bytes(signer: &ConsensusSigner) -> Vec<u8> {
    let mut header = dummy_header(&signer.public_key());
    header.signatures.push(signer.sign_header(&header));
    let envelope = ChainSyncEnvelope::seal(
        signer,
        ChainSyncMsg::Proposal(ProposalMsg {
            block: CipherChainBlock {
                header,
                transactions: Vec::new(),
            },
        }),
    );
    serde_json::to_vec(&envelope).unwrap()
}

#[tokio::test]
async fn chain_envelope_propagates_and_admits() {
    let (node_a, _state_a) = boot_node("chain-op-a").await;
    let (node_b, _state_b) = boot_node("chain-op-b").await;

    let validators: Vec<ConsensusSigner> = (0..3).map(|_| ConsensusSigner::generate()).collect();
    let set = fleet(&validators);
    node_a
        .handle
        .set_chain_validators(set.clone())
        .await
        .unwrap();
    node_b.handle.set_chain_validators(set).await.unwrap();

    dial_and_wait(&node_a, &node_b).await;

    publish_chain_until_ok(&node_a, sealed_vote_bytes(&validators[0])).await;
    wait_chain_stats(
        &node_b,
        ChainStats {
            accepted: 1,
            rejected: 0,
            ignored: 0,
        },
    )
    .await;

    publish_chain_until_ok(&node_a, sealed_proposal_bytes(&validators[1])).await;
    wait_chain_stats(
        &node_b,
        ChainStats {
            accepted: 2,
            rejected: 0,
            ignored: 0,
        },
    )
    .await;
}

#[tokio::test]
async fn chain_forgeries_rejected_and_disabled_ignored() {
    let (node_a, _state_a) = boot_node("chain-op-a2").await;
    let (node_b, _state_b) = boot_node("chain-op-b2").await;
    let (node_c, _state_c) = boot_node("chain-op-c2").await;

    let validators: Vec<ConsensusSigner> = (0..3).map(|_| ConsensusSigner::generate()).collect();
    let outsider = ConsensusSigner::generate();
    let set = fleet(&validators);
    node_a
        .handle
        .set_chain_validators(set.clone())
        .await
        .unwrap();
    node_b.handle.set_chain_validators(set).await.unwrap();
    // Node C never sets validators: chain sync disabled there.

    dial_and_wait(&node_a, &node_b).await;
    dial_and_wait(&node_a, &node_c).await;

    // Tampered bytes fail admission.
    let mut tampered = sealed_vote_bytes(&validators[0]);
    tampered[20] ^= 0xff;
    publish_chain_until_ok(&node_a, tampered).await;

    // Non-member seal is a Byzantine forgery.
    publish_chain_until_ok(&node_a, sealed_vote_bytes(&outsider)).await;

    // Wrong-chain payloads are ignored, not penalized.
    let header = dummy_header(&validators[1].public_key());
    let wrong_chain = ChainSyncEnvelope::seal(
        &validators[1],
        ChainSyncMsg::Vote(VoteMsg {
            chain_id: "other-chain".to_string(),
            header: header.clone(),
            observed_ms: header.timestamp_ms,
            endorsement: validators[1].sign_header(&header),
        }),
    );
    publish_chain_until_ok(&node_a, serde_json::to_vec(&wrong_chain).unwrap()).await;

    wait_chain_stats(
        &node_b,
        ChainStats {
            accepted: 0,
            rejected: 2,
            ignored: 1,
        },
    )
    .await;

    // A well-formed fleet envelope is ignored (not rejected) while disabled.
    publish_chain_until_ok(&node_a, sealed_vote_bytes(&validators[2])).await;
    wait_chain_stats(
        &node_c,
        ChainStats {
            accepted: 0,
            rejected: 0,
            ignored: 1,
        },
    )
    .await;
}

#[tokio::test]
async fn chain_oversize_publish_rejected() {
    let (node_a, _state_a) = boot_node("chain-op-solo").await;
    let big = vec![0u8; 70_000];
    assert!(node_a.handle.publish_chain(big).await.is_err());
}

fn client_tx(client: &ConsensusSigner, salt_byte: u8, cid_byte: u8, nonce: u64) -> CommitmentTx {
    let salt = [salt_byte; 32];
    let head_cid = [cid_byte; 32];
    let commitment = CommitmentTx::calculate_commitment(&salt, &head_cid);
    let mut tx = CommitmentTx {
        vault_id: [0x33; 32],
        salt,
        head_cid,
        commitment,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce,
        timestamp_ms: 1_100,
    };
    client.sign_tx(&mut tx, SOVEREIGN_CHAIN_ID_STR);
    tx
}

async fn wait_hub_complete(state: &Arc<OperatorState>, height: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if state.chain_hub_complete() && state.chain_hub_height() == Some(height) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "hub did not complete at height {height}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn chain_backfill_brings_lagging_node_to_tip() {
    let validators: Vec<ConsensusSigner> = (0..3).map(|_| ConsensusSigner::generate()).collect();
    let set = fleet(&validators);
    let client = ConsensusSigner::generate();

    // Node A starts with a full 3-block history on disk.
    let (node_a, state_a) = boot_node("chain-op-full").await;
    {
        let refs: Vec<&ConsensusSigner> = validators.iter().collect();
        let chain_dir = node_a.dir.join("chain");
        let mut ledger = SovereignLedger::create_genesis(
            SOVEREIGN_CHAIN_ID_STR,
            set.clone(),
            &refs,
            1_000,
            Some(chain_dir),
        )
        .unwrap();
        for n in 1..=2u64 {
            let tx = client_tx(&client, n as u8, n as u8, n);
            let mut block = ledger
                .propose_block(&validators[0], vec![tx], 1_000 + n * 1_000)
                .unwrap();
            for signer in [&validators[1], &validators[2]] {
                block
                    .header
                    .signatures
                    .push(signer.sign_header(&block.header));
            }
            ledger.commit_block(block).unwrap();
        }
        assert_eq!(ledger.height(), 2);
    }
    node_a
        .handle
        .set_chain_validators(set.clone())
        .await
        .unwrap();
    wait_hub_complete(&state_a, 2).await;

    // Node B starts empty.
    let (node_b, state_b) = boot_node("chain-op-empty").await;
    node_b
        .handle
        .set_chain_validators(set.clone())
        .await
        .unwrap();
    assert!(!state_b.chain_hub_complete());
    assert_eq!(state_b.chain_hub_height(), None);

    dial_and_wait(&node_a, &node_b).await;

    // A gossips the certified tip; B adopts it, then backfills to genesis.
    let tip = state_a
        .chain_block_range(2, 1)
        .0
        .into_iter()
        .next()
        .unwrap();
    let tip_raw = serde_json::to_vec(&ChainSyncEnvelope::seal(
        &validators[0],
        ChainSyncMsg::CertifiedBlock(tip),
    ))
    .unwrap();
    publish_chain_until_ok(&node_a, tip_raw).await;

    wait_hub_complete(&state_b, 2).await;
    // Backfill cleared the tip snapshot: restarts would open genesis-anchored.
    assert!(!node_b.dir.join("chain").join("tip.json").exists());
}
