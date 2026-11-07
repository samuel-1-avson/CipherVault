use ciphervault_chain::{
    AnchorProofResponse, CommitmentTx, ConsensusSigner, SovereignLedger, SovereignLightClient,
    ValidatorSet,
};

#[test]
fn test_sovereign_blockchain_full_lifecycle() {
    let chain_id = "ciphervault-sovereign-test-1";

    // 1. Initialize 3 independent Operator node signing keys
    let operator_1 = ConsensusSigner::generate();
    let operator_2 = ConsensusSigner::generate();
    let operator_3 = ConsensusSigner::generate();

    let validator_set = ValidatorSet::new(vec![
        operator_1.public_key(),
        operator_2.public_key(),
        operator_3.public_key(),
    ])
    .expect("Valid validator set");

    assert_eq!(validator_set.len(), 3);
    assert_eq!(validator_set.quorum_threshold(), 3); // 2*3/3 + 1 = 3

    // 2. Create Sovereign Genesis Block
    let signers = [&operator_1, &operator_2, &operator_3];
    let mut ledger = SovereignLedger::create_genesis(
        chain_id,
        validator_set.clone(),
        &signers,
        1_700_000_000_000,
        None,
    )
    .expect("Genesis block creation succeeds");

    assert_eq!(ledger.height(), 0);
    assert_eq!(ledger.latest_block().header.height, 0);

    // 3. Client creates vault snapshot and generates commitment transaction
    let client_signer = ConsensusSigner::generate();
    let vault_id = [0x11; 32];
    let salt = [0xaa; 32];
    let head_cid = [0x55; 32];
    let commitment = CommitmentTx::calculate_commitment(&salt, &head_cid);

    let mut tx1 = CommitmentTx {
        vault_id,
        salt,
        head_cid,
        commitment,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce: 1,
        timestamp_ms: 1_700_000_001_000,
    };
    client_signer.sign_tx(&mut tx1, chain_id);
    assert!(tx1.verify_signature(chain_id).is_ok());

    // Second vault transaction
    let salt2 = [0xbb; 32];
    let head_cid2 = [0x66; 32];
    let commitment2 = CommitmentTx::calculate_commitment(&salt2, &head_cid2);
    let mut tx2 = CommitmentTx {
        vault_id,
        salt: salt2,
        head_cid: head_cid2,
        commitment: commitment2,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce: 2,
        timestamp_ms: 1_700_000_001_100,
    };
    client_signer.sign_tx(&mut tx2, chain_id);

    // 4. Operator 1 proposes Block #1
    let mut proposed_block = ledger
        .propose_block(
            &operator_1,
            vec![tx1.clone(), tx2.clone()],
            1_700_000_005_000,
        )
        .expect("Block proposal succeeds");

    assert_eq!(proposed_block.header.height, 1);
    assert_eq!(proposed_block.header.signatures.len(), 1); // Proposer signature

    // 5. Operators 2 and 3 validate and endorse the block proposal
    proposed_block
        .header
        .signatures
        .push(operator_2.sign_header(&proposed_block.header));
    proposed_block
        .header
        .signatures
        .push(operator_3.sign_header(&proposed_block.header));

    assert_eq!(proposed_block.header.signatures.len(), 3);

    // 6. Commit Block #1 to Sovereign Ledger
    ledger
        .commit_block(proposed_block.clone())
        .expect("Block commit succeeds");

    assert_eq!(ledger.height(), 1);
    assert_ne!(ledger.state_root(), ciphervault_chain::EMPTY_TREE_ROOT);

    // 7. Query Anchor Proof from Ledger
    let proof: AnchorProofResponse = ledger
        .get_proof_for_commitment(&commitment)
        .expect("Proof for commitment 1 exists");

    assert_eq!(proof.height, 1);
    assert_eq!(proof.commitment, commitment);
    assert_eq!(proof.head_cid, head_cid);
    assert_eq!(proof.validator_signatures_count, 3);

    // Also query by Head CID
    let proof_by_cid = ledger
        .get_proof_for_head_cid(&head_cid2)
        .expect("Proof for head_cid 2 exists");
    assert_eq!(proof_by_cid.commitment, commitment2);

    // 8. Standalone Light Client Verification
    let light_client = SovereignLightClient::new(
        chain_id,
        vec![
            operator_1.public_key(),
            operator_2.public_key(),
            operator_3.public_key(),
        ],
    );

    let verify_result = light_client
        .verify_anchor(&head_cid, &salt, &proof)
        .expect("Light client verification must succeed");

    assert!(verify_result.verified);
    assert_eq!(verify_result.height, 1);
    assert_eq!(verify_result.signatures_verified, 3);
    assert_eq!(verify_result.quorum_required, 3);
    println!("Light client verification: {}", verify_result.message);

    // 9. Tamper Proof Testing: Altering salt or CID fails light client
    let wrong_salt = [0x00; 32];
    assert!(light_client
        .verify_anchor(&head_cid, &wrong_salt, &proof)
        .is_err());

    let wrong_cid = [0x00; 32];
    assert!(light_client
        .verify_anchor(&wrong_cid, &salt, &proof)
        .is_err());

    // Altering Merkle root fails light client
    let mut tampered_proof = proof.clone();
    tampered_proof.header.tx_root[0] ^= 0xff;
    assert!(light_client
        .verify_anchor(&head_cid, &salt, &tampered_proof)
        .is_err());
}

#[test]
fn test_byzantine_fault_tolerance_rejection() {
    let chain_id = "ciphervault-bft-test";
    let op1 = ConsensusSigner::generate();
    let op2 = ConsensusSigner::generate();
    let op3 = ConsensusSigner::generate();
    let rogue = ConsensusSigner::generate();

    let validator_set =
        ValidatorSet::new(vec![op1.public_key(), op2.public_key(), op3.public_key()]).unwrap();

    let signers = [&op1, &op2, &op3];
    let mut ledger =
        SovereignLedger::create_genesis(chain_id, validator_set, &signers, 1_000, None).unwrap();

    let client = ConsensusSigner::generate();
    let salt = [1u8; 32];
    let head_cid = [2u8; 32];
    let commitment = CommitmentTx::calculate_commitment(&salt, &head_cid);
    let mut tx = CommitmentTx {
        vault_id: [3u8; 32],
        salt,
        head_cid,
        commitment,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce: 1,
        timestamp_ms: 1_100,
    };
    client.sign_tx(&mut tx, chain_id);

    // Block proposed with only 2 signatures (less than required 3 for 3-node BFT)
    let mut block = ledger.propose_block(&op1, vec![tx.clone()], 2_000).unwrap();
    block.header.signatures.push(op2.sign_header(&block.header));
    assert_eq!(block.header.signatures.len(), 2);

    // Commit must fail due to InsufficientQuorum
    let err = ledger.commit_block(block.clone()).unwrap_err();
    assert!(format!("{}", err).contains("Insufficient quorum"));

    // Rogue validator signature must be rejected
    block
        .header
        .signatures
        .push(rogue.sign_header(&block.header));
    let err_rogue = ledger.commit_block(block).unwrap_err();
    assert!(format!("{}", err_rogue).contains("Unauthorized validator"));
}
