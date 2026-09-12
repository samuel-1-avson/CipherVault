use ciphervault_format::CheckpointEvidence;
use ciphervault_local_store::LocalVaultStore;
use ciphervault_storage::chain::ArbitrumAnchorClient;
use std::fs;

#[tokio::test]
async fn test_arbitrum_anchoring_commitment_and_evidence() {
    let test_dir = std::env::temp_dir().join(format!("cv_anchor_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
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
    let client = ArbitrumAnchorClient::new("https://mock-rpc.arbitrum.io".into(), chain_id, contract_address);

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
