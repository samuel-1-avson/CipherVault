use ciphervault_chain::{
    AnchorProofResponse, CommitmentTx, ConsensusSigner, SovereignLedger, SovereignLightClient,
    ValidatorSet, SOVEREIGN_CHAIN_ID_NUM, SOVEREIGN_CHAIN_ID_STR,
};
use ciphervault_format::CheckpointEvidence;
use ciphervault_local_store::LocalVaultStore;
use std::fs;

#[tokio::test]
async fn test_sovereign_chain_end_to_end_anchoring_and_light_verification() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_sovereign_chain_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();
    let db_path = test_dir.join("vault.db");
    let chain_dir = test_dir.join("chain");
    fs::create_dir_all(&chain_dir).unwrap();

    let store = LocalVaultStore::open(&db_path).unwrap();

    // 1. Setup 3 Operator Validators for Sovereign CipherChain
    let op1 = ConsensusSigner::generate();
    let op2 = ConsensusSigner::generate();
    let op3 = ConsensusSigner::generate();

    let validator_set =
        ValidatorSet::new(vec![op1.public_key(), op2.public_key(), op3.public_key()])
            .expect("Validator set initialization succeeds");

    assert_eq!(validator_set.quorum_threshold(), 3);

    // 2. Initialize Sovereign Genesis Block
    let signers = [&op1, &op2, &op3];
    let mut ledger = SovereignLedger::create_genesis(
        SOVEREIGN_CHAIN_ID_STR,
        validator_set.clone(),
        &signers,
        1_700_000_000_000,
        Some(chain_dir.clone()),
    )
    .expect("Genesis creation succeeds");

    assert_eq!(ledger.height(), 0);

    // 3. Vault Snapshot Head and Client Commitment
    let head_cid = [0x42u8; 32];
    let salt = [0x99u8; 32];
    let commitment = CheckpointEvidence::compute_commitment(&salt, &head_cid);
    assert_ne!(commitment, [0u8; 32]);

    let vault_id = [0x01u8; 32];
    let client_signer = ConsensusSigner::generate();

    let mut tx = CommitmentTx {
        version: 0,
        vault_id,
        salt,
        head_cid,
        commitment,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce: 101,
        timestamp_ms: 1_700_000_001_000,
    };
    client_signer.sign_tx(&mut tx, SOVEREIGN_CHAIN_ID_STR);
    assert!(tx.verify_signature(SOVEREIGN_CHAIN_ID_STR).is_ok());

    // 4. Operator 1 proposes Block #1 packaging the commitment
    let mut proposed = ledger
        .propose_block(&op1, vec![tx.clone()], 1_700_000_005_000, None)
        .expect("Propose block succeeds");

    // Collect quorum signatures from Operators 2 and 3
    proposed
        .header
        .signatures
        .push(op2.sign_header(&proposed.header));
    proposed
        .header
        .signatures
        .push(op3.sign_header(&proposed.header));
    assert_eq!(proposed.header.signatures.len(), 3);

    // Commit to Sovereign Ledger
    ledger
        .commit_block(proposed.clone())
        .expect("Commit block succeeds");
    assert_eq!(ledger.height(), 1);

    let block_hash = proposed.header.block_hash();

    // 5. Save Checkpoint Evidence to Vault Store
    let evidence = CheckpointEvidence::new(
        salt,
        head_cid,
        SOVEREIGN_CHAIN_ID_NUM,
        [0u8; 20],
        block_hash,
        1,
        1_700_000_005,
    );
    assert!(evidence.verify_commitment());
    store
        .save_checkpoint_evidence(&evidence)
        .expect("Save evidence succeeds");

    // 6. Verify Evidence Persisted in Local Store
    let saved_evidence = store
        .get_checkpoint_evidence(&head_cid)
        .unwrap()
        .expect("Saved evidence exists");

    assert_eq!(saved_evidence.chain_id, SOVEREIGN_CHAIN_ID_NUM);
    assert_eq!(saved_evidence.contract_address, vec![0u8; 20]);
    assert_eq!(saved_evidence.block_number, 1);
    assert_eq!(saved_evidence.tx_hash, block_hash.to_vec());
    assert!(saved_evidence.verify_commitment());

    // 7. Light Client Verification
    let proof: AnchorProofResponse = ledger
        .get_proof_for_commitment(&commitment)
        .expect("Proof exists");

    let light_client = SovereignLightClient::new(
        SOVEREIGN_CHAIN_ID_STR,
        vec![op1.public_key(), op2.public_key(), op3.public_key()],
    );

    let report = light_client
        .verify_anchor(&head_cid, &salt, &proof)
        .expect("Light client verification must succeed");

    assert!(report.verified);
    assert_eq!(report.chain_id, SOVEREIGN_CHAIN_ID_STR);
    assert_eq!(report.height, 1);
    assert_eq!(report.signatures_verified, 3);
    assert_eq!(report.quorum_required, 3);
    assert_eq!(report.commitment_hex, hex::encode(commitment));
    assert_eq!(report.head_cid_hex, hex::encode(head_cid));

    // 8. Re-opening Ledger from Disk
    let reopened_ledger =
        SovereignLedger::open(SOVEREIGN_CHAIN_ID_STR, validator_set.clone(), &chain_dir)
            .expect("Re-opening ledger from disk succeeds");

    assert_eq!(reopened_ledger.height(), 1);
    let reopened_proof = reopened_ledger
        .get_proof_for_commitment(&commitment)
        .expect("Proof exists in re-opened ledger");
    assert_eq!(reopened_proof.block_hash, block_hash);

    let _ = fs::remove_dir_all(&test_dir);
}
