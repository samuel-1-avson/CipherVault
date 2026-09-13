use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};
use ciphervault_storage::{MultiOperatorPool, OperatorClient, PeerDescriptor};
use std::sync::Arc;

async fn spawn_operator(
    operator_id: &str,
) -> (String, Arc<OperatorState>, tokio::task::JoinHandle<()>) {
    let dir =
        std::env::temp_dir().join(format!("cv-p2p-{}-{}", operator_id, rand::random::<u64>()));
    let signing_key = generate_signing_key();
    let state = Arc::new(OperatorState::new(
        operator_id.to_string(),
        dir,
        signing_key,
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);

    let router = create_router(state.clone());
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (endpoint, state, handle)
}

#[tokio::test]
async fn test_p2p_gossip_and_pool_peer_expansion() {
    // 1. Spawn three operator nodes
    let (ep1, state1, _h1) = spawn_operator("operator-alpha").await;
    let (ep2, state2, _h2) = spawn_operator("operator-beta").await;
    let (ep3, state3, _h3) = spawn_operator("operator-gamma").await;

    // 2. Form signed PeerDescriptors for operator 2 and operator 3
    let peer2 = PeerDescriptor::new(
        "operator-beta".to_string(),
        ep2.clone(),
        &state2.signing_key,
    );
    let peer3 = PeerDescriptor::new(
        "operator-gamma".to_string(),
        ep3.clone(),
        &state3.signing_key,
    );

    // 3. Announce peer2 and peer3 to operator 1
    let client1 = OperatorClient::new(ep1.clone());
    let ann2 = client1.announce_peer(&peer2).await;
    assert!(ann2.is_ok(), "Announce peer 2 to node 1 failed: {:?}", ann2);

    let ann3 = client1.announce_peer(&peer3).await;
    assert!(ann3.is_ok(), "Announce peer 3 to node 1 failed: {:?}", ann3);

    // 4. Query peers directly from operator 1
    let discovered = client1
        .get_peers()
        .await
        .expect("Failed to get peers from operator 1");
    assert_eq!(discovered.len(), 2, "Expected 2 announced peers");
    assert!(discovered.iter().any(|p| p.operator_id == "operator-beta"));
    assert!(discovered.iter().any(|p| p.operator_id == "operator-gamma"));

    // 5. Initialize client pool with ONLY operator 1 (static seed bootstrap)
    let mut pool = MultiOperatorPool::new(vec![ep1.clone()]);
    assert_eq!(pool.endpoints().len(), 1);

    // 6. Dynamic peer expansion: pool discovers peer2 and peer3 via gossip from node 1
    let expanded_count = pool
        .discover_and_expand_peers()
        .await
        .expect("Discovery failed");
    assert_eq!(expanded_count, 2, "Should have expanded by 2 peers");
    assert_eq!(
        pool.endpoints().len(),
        3,
        "Pool should now contain 3 endpoints"
    );
    assert!(pool.endpoints().contains(&ep1));
    assert!(pool.endpoints().contains(&ep2));
    assert!(pool.endpoints().contains(&ep3));

    // 7. Test invalid signature rejection: tampered endpoint
    let mut tampered = peer2.clone();
    tampered.endpoint = "http://127.0.0.1:9999".into(); // Tamper without re-signing
    let bad_ann = client1.announce_peer(&tampered).await;
    assert!(
        bad_ann.is_err(),
        "Operator 1 should reject tampered peer descriptor signature"
    );

    // Clean up temporary operator dirs
    let _ = std::fs::remove_dir_all(&state1.data_dir);
    let _ = std::fs::remove_dir_all(&state2.data_dir);
    let _ = std::fs::remove_dir_all(&state3.data_dir);
}
