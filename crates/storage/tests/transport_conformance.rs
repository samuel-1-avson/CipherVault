// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! # Memory-transport pool conformance (no sockets)
//!
//! Pool-level behavior driven end to end through [`MemoryTransport`]: full
//! replication pipelines, offline/flaky failover, quorum accounting, and
//! discovery readback. The dual HTTP/memory suite that pins memory semantics
//! to the real Axum operator lives in
//! `services/operator/tests/transport_conformance.rs`, next to the only crate
//! that can host the real router without a dependency cycle.

use std::sync::Arc;

use ciphervault_crypto::generate_signing_key;
use ciphervault_format::{compute_digest, to_canonical_cbor, GenesisRecord, PROTOCOL_VERSION};
use ciphervault_storage::{
    MemoryTransport, MultiOperatorPool, OperatorClient, OperatorTransport, StorageError,
};
use ed25519_dalek::SigningKey;

fn memory_client(operator_id: &str) -> (OperatorClient, MemoryTransport) {
    let transport = MemoryTransport::new(operator_id);
    let client = OperatorClient::with_transport(
        format!("memory://{operator_id}"),
        Arc::new(transport.clone()) as Arc<dyn OperatorTransport>,
    );
    (client, transport)
}

/// Builds a self-certifying genesis record: the memory backend accepts any
/// bytes, but realistic records keep these tests honest about what the pool
/// carries on the wire.
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

fn sample_object() -> ([u8; 32], Vec<u8>) {
    let bytes = b"conformance fixture object".to_vec();
    let cid = compute_digest(&bytes);
    (cid, bytes)
}

#[tokio::test]
async fn pool_replicates_closure_across_memory_operators() {
    let (client_a, _) = memory_client("pool-op-a");
    let (client_b, _) = memory_client("pool-op-b");
    let pool = MultiOperatorPool::from_clients(vec![client_a, client_b]);

    let vault_id: [u8; 32] = rand::random();
    let recovery_key = generate_signing_key();
    let (cid, bytes) = sample_object();
    let closure_digest: [u8; 32] = rand::random();
    let locator: [u8; 32] = rand::random();
    let genesis = genesis_bytes(&vault_id, &recovery_key);

    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &recovery_key,
            &[(cid, bytes.clone())],
            &closure_digest,
            bytes.len() as u64,
            30,
            &locator,
            &genesis,
            std::slice::from_ref(&genesis),
            2,
        )
        .await
        .expect("quorum of 2 over healthy memory operators");
    assert_eq!(receipts.len(), 2);
    assert_ne!(receipts[0].operator_id, receipts[1].operator_id);

    // Discovery readback sees the published log.
    let discovered = pool.query_recovery_records(&locator).await;
    assert!(discovered.contains(&genesis));
    assert_eq!(pool.fetch_object_from_any(&cid).await.unwrap(), bytes);
}

#[tokio::test]
async fn pool_skips_offline_operator_and_reports_quorum_deficit() {
    let (client_a, offline) = memory_client("pool-op-offline");
    let (client_b, _) = memory_client("pool-op-healthy");
    offline.set_offline(true);
    let pool = MultiOperatorPool::from_clients(vec![client_a, client_b]);

    let vault_id: [u8; 32] = rand::random();
    let recovery_key = generate_signing_key();
    let (cid, bytes) = sample_object();
    let closure_digest: [u8; 32] = rand::random();
    let locator: [u8; 32] = rand::random();
    let genesis = genesis_bytes(&vault_id, &recovery_key);
    let objects = vec![(cid, bytes.clone())];
    let total_bytes = bytes.len() as u64;
    let bootstrap = vec![genesis.clone()];

    // Quorum of 1 succeeds on the survivor.
    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &recovery_key,
            &objects,
            &closure_digest,
            total_bytes,
            30,
            &locator,
            &genesis,
            &bootstrap,
            1,
        )
        .await
        .expect("quorum of 1 survives a dead operator");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].operator_id, "pool-op-healthy");

    // Quorum of 2 is honestly reported as a deficit, not a silent shortfall.
    let err = pool
        .replicate_and_verify(
            &vault_id,
            &recovery_key,
            &objects,
            &closure_digest,
            total_bytes,
            30,
            &locator,
            &genesis,
            &bootstrap,
            2,
        )
        .await
        .expect_err("quorum of 2 over one live operator must fail");
    assert!(matches!(
        err,
        StorageError::QuorumDeficit {
            required: 2,
            successful: 1
        }
    ));

    offline.set_offline(false);
    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &recovery_key,
            &objects,
            &closure_digest,
            total_bytes,
            30,
            &locator,
            &genesis,
            &bootstrap,
            2,
        )
        .await
        .expect("recovered operator rejoins quorum");
    assert_eq!(receipts.len(), 2);
}

#[tokio::test]
async fn pool_skips_operator_with_failing_puts() {
    let (client_a, flaky) = memory_client("pool-op-flaky");
    let (client_b, _) = memory_client("pool-op-steady");
    flaky.set_failing_put(true);
    let pool = MultiOperatorPool::from_clients(vec![client_a, client_b]);

    let vault_id: [u8; 32] = rand::random();
    let recovery_key = generate_signing_key();
    let (cid, bytes) = sample_object();
    let closure_digest: [u8; 32] = rand::random();
    let locator: [u8; 32] = rand::random();
    let genesis = genesis_bytes(&vault_id, &recovery_key);

    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &recovery_key,
            &[(cid, bytes.clone())],
            &closure_digest,
            bytes.len() as u64,
            30,
            &locator,
            &genesis,
            std::slice::from_ref(&genesis),
            1,
        )
        .await
        .expect("healthy replica carries quorum");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].operator_id, "pool-op-steady");
}

#[tokio::test]
async fn memory_stats_count_puts_and_challenges() {
    let (client, transport) = memory_client("pool-op-stats");
    let key = generate_signing_key();
    let vault_id: [u8; 32] = rand::random();
    let token = client.authenticate(&vault_id, &key).await.unwrap();
    let (cid, bytes) = sample_object();
    client.put_object(&token, &cid, bytes).await.unwrap();
    let nonce: [u8; 32] = rand::random();
    client
        .challenge_object_pos(&token, &cid, &nonce)
        .await
        .unwrap();
    let stats = transport.stats();
    assert_eq!(stats.puts, 1);
    assert_eq!(stats.challenges, 1);
}

#[tokio::test]
async fn idempotent_get_retries_transport_failures() {
    // Connection-refused fails in ~ms per attempt; three attempts with
    // 100ms + 200ms backoff must take at least 200ms total.
    let transport = ciphervault_storage::transport::HttpTransport::new("http://127.0.0.1:9".into());
    let start = std::time::Instant::now();
    let err = transport
        .get_peers()
        .await
        .expect_err("unreachable host fails");
    assert!(
        matches!(err, StorageError::HttpError(_)),
        "transport failure surfaces as HttpError: {err}"
    );
    assert!(
        start.elapsed() >= std::time::Duration::from_millis(200),
        "retries happened: {:?}",
        start.elapsed()
    );
}
