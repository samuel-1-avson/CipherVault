use ciphervault_format::CheckpointEvidence;
use ciphervault_local_store::LocalVaultStore;
use ciphervault_storage::chain::{ArbitrumAnchorClient, COMMITMENT_PUBLISHED_TOPIC};
use std::fs;

#[tokio::test]
async fn test_arbitrum_anchoring_commitment_and_evidence() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_anchor_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();
    let db_path = test_dir.join("vault.db");
    let store = LocalVaultStore::open(&db_path).unwrap();

    let salt = [0xAAu8; 32];
    let head_cid = [0xBBu8; 32];
    let contract_address = [0x11u8; 20];
    let tx_hash = [0x77u8; 32];
    let chain_id = 42161; // Arbitrum One
    let block_number = 250_000_000;
    let timestamp = 1710000000;

    // 1. Compute commitment
    let commitment = CheckpointEvidence::compute_commitment(&salt, &head_cid);
    assert_ne!(commitment, [0u8; 32]);

    // 2. Build CheckpointEvidence
    let evidence = CheckpointEvidence::new(
        salt,
        head_cid,
        chain_id,
        contract_address,
        tx_hash,
        block_number,
        timestamp,
    );

    assert_eq!(evidence.commitment, commitment.to_vec());
    assert!(evidence.verify_commitment());

    // 3. Reject tampered salt or head_cid
    let mut bad_evidence = evidence.clone();
    bad_evidence.salt[0] ^= 0xFF;
    assert!(!bad_evidence.verify_commitment());

    let mut bad_head = evidence.clone();
    bad_head.head_record_cid[0] ^= 0x01;
    assert!(!bad_head.verify_commitment());

    // 4. Save to LocalVaultStore
    store.save_checkpoint_evidence(&evidence).unwrap();

    // 5. Query from store
    let fetched = store.get_checkpoint_evidence(&head_cid).unwrap().unwrap();
    assert_eq!(fetched.commitment, evidence.commitment);
    assert_eq!(fetched.block_number, block_number);
    assert_eq!(fetched.chain_id, chain_id);
    assert_eq!(fetched.contract_address, contract_address.to_vec());
    assert!(fetched.verify_commitment());

    // 6. Test ArbitrumAnchorClient calldata and verification
    let client = ArbitrumAnchorClient::new("http://127.0.0.1:1".into(), chain_id, contract_address);

    let pub_calldata = ArbitrumAnchorClient::encode_publish_calldata(&commitment);
    assert_eq!(pub_calldata.len(), 36);
    assert_eq!(&pub_calldata[4..36], &commitment);

    let get_calldata = ArbitrumAnchorClient::encode_get_first_seen_calldata(&commitment);
    assert_eq!(get_calldata.len(), 36);
    assert_eq!(&get_calldata[4..36], &commitment);

    let report = client.verify_evidence(&evidence).await.unwrap();
    assert!(report.preimage_valid);
    assert_eq!(report.chain_id, chain_id);
    assert_eq!(report.recorded_block_number, block_number);

    let _ = fs::remove_dir_all(test_dir);
}

#[tokio::test]
async fn test_automated_l2_relayer_flow() {
    use ciphervault_operator::{create_router, OperatorState};
    use ciphervault_storage::AnchorRelayerClient;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    // This in-process relayer intentionally exercises the legacy migration
    // mode. Production operators fail closed when strict auth is unset.
    std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");

    let test_dir = std::env::temp_dir().join(format!(
        "cv_relayer_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    let signing_key = ciphervault_crypto::generate_signing_key();
    let state = Arc::new(OperatorState::new(
        "test-relayer-op".into(),
        test_dir.clone(),
        signing_key,
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = create_router(state.clone());

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let relayer_url = format!("http://{}", addr);
    let client = AnchorRelayerClient::new(relayer_url);

    let salt = [0x42u8; 32];
    let head_cid = [0x99u8; 32];
    let contract = [0x55u8; 20];
    let dummy_tx = [0u8; 32];

    let draft_evidence =
        CheckpointEvidence::new(salt, head_cid, 42161, contract, dummy_tx, 0, 1710000000);

    // 1. Submit unmined draft to relayer -> Truthful QueuedForRelay status (F03 resolved)
    let receipt = client.submit_checkpoint(&draft_evidence).await.unwrap();
    assert_eq!(receipt.status, "QueuedForRelay");
    assert_eq!(
        receipt.commitment_hex,
        hex::encode(&draft_evidence.commitment)
    );
    assert_eq!(receipt.block_number, 0);

    // 2. Query status from relayer -> remains QueuedForRelay until on-chain mined
    let mut commitment_arr = [0u8; 32];
    commitment_arr.copy_from_slice(&draft_evidence.commitment);
    let queried = client.get_checkpoint(&commitment_arr).await.unwrap();
    assert!(queried.is_some());
    let q = queried.unwrap();
    assert_eq!(q.status, "QueuedForRelay");
    assert_eq!(q.block_number, 0);

    // 3. Update relayer state upon sequencer confirmation receipt
    let confirmed_tx = "0x7777777777777777777777777777777777777777777777777777777777777777";
    state.update_relayed_checkpoint(
        &receipt.commitment_hex,
        confirmed_tx,
        250_000_100,
        "SequencerConfirmed",
    );
    let updated = client
        .get_checkpoint(&commitment_arr)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.status, "SequencerConfirmed");
    assert_eq!(updated.tx_hash_hex, confirmed_tx);
    assert_eq!(updated.block_number, 250_000_100);

    // 4. Reject tampered evidence
    let mut bad_evidence = draft_evidence.clone();
    bad_evidence.salt[0] ^= 0xFF;
    assert!(client.submit_checkpoint(&bad_evidence).await.is_err());

    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    let _ = fs::remove_dir_all(test_dir);
}

#[tokio::test]
async fn test_live_arbitrum_rpc_send_raw_transaction_and_receipt() {
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use std::time::Duration;
    use tokio::net::TcpListener;

    let dummy_tx_hash = "0x9876543210987654321098765432109876543210987654321098765432109876";
    // Mock receipt binds to the same registry ([0x55; 20]) and commitment
    // inputs ([0x11; 32] / [0x22; 32]) the evidence below uses; the
    // `receipt_verified` assertion fails on any drift between them.
    let registry_hex = format!("0x{}", hex::encode([0x55u8; 20]));
    let topic0_hex = format!("0x{}", hex::encode(COMMITMENT_PUBLISHED_TOPIC));
    let mock_commitment = CheckpointEvidence::compute_commitment(&[0x11u8; 32], &[0x22u8; 32]);
    let commitment_topic = format!("0x{}", hex::encode(mock_commitment));
    let publisher_topic =
        "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

    // Mock Ethereum / Arbitrum JSON-RPC Server
    let rpc_app = Router::new().route(
        "/",
        post(move |Json(payload): Json<Value>| {
            let to_hex = registry_hex.clone();
            let topic0 = topic0_hex.clone();
            let commitment_topic = commitment_topic.clone();
            let publisher_topic = publisher_topic.clone();
            async move {
            let method = payload["method"].as_str().unwrap_or("");
            let id = payload["id"].clone();

            match method {
                "eth_sendRawTransaction" => Json(json!({
                    "jsonrpc": "2.0",
                    "result": dummy_tx_hash,
                    "id": id
                })),
                "eth_getTransactionReceipt" => Json(json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "transactionHash": dummy_tx_hash,
                        "blockNumber": "0x12345",
                        "status": "0x1",
                        "to": to_hex.clone(),
                        "logs": [{
                            "address": to_hex,
                            "topics": [topic0, commitment_topic, publisher_topic]
                        }]
                    },
                    "id": id
                })),
                "eth_call" => Json(json!({
                    "jsonrpc": "2.0",
                    "result": "0x0000000000000000000000000000000000000000000000000000000000012345",
                    "id": id
                })),
                "eth_blockNumber" => Json(json!({
                    "jsonrpc": "2.0",
                    "result": "0x12350",
                    "id": id
                })),
                _ => Json(json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32601, "message": "Method not found" },
                    "id": id
                })),
            }
            }
        })
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, rpc_app).await.unwrap();
    });

    let rpc_url = format!("http://{}", addr);
    let contract = [0x55u8; 20];
    let client = ArbitrumAnchorClient::new(rpc_url, 42161, contract);

    // 1. Test eth_sendRawTransaction
    let raw_tx = "0x02f87082a4b180843b9aca008502540be4008252089455555555555555555555555555555555555555558080c0";
    let tx_hash = client.send_raw_transaction(raw_tx).await.unwrap();
    assert_eq!(format!("0x{}", hex::encode(tx_hash)), dummy_tx_hash);

    // 2. Test wait_for_receipt polling
    let receipt = client
        .wait_for_receipt(&tx_hash, Duration::from_secs(5), Duration::from_millis(50))
        .await
        .unwrap();
    assert!(receipt.status);
    assert_eq!(receipt.block_number, 0x12345);

    // 3. Test on-chain query for first-seen block
    let dummy_commitment = [0x77u8; 32];
    let first_seen = client
        .query_first_seen_block(&dummy_commitment)
        .await
        .unwrap();
    assert_eq!(first_seen, Some(0x12345));

    // 4. Test verify_evidence with on-chain confirmation
    let salt = [0x11u8; 32];
    let head_cid = [0x22u8; 32];
    let evidence = CheckpointEvidence::new(
        salt, head_cid, 42161, contract, tx_hash, 0x12345, 1700000000,
    );
    let report = client.verify_evidence(&evidence).await.unwrap();
    assert!(report.preimage_valid);
    assert!(report.on_chain_confirmed);
    assert!(report.receipt_verified);
    assert_eq!(report.receipt_block_number, Some(0x12345));
    assert_eq!(report.recorded_block_number, 0x12345);
}
