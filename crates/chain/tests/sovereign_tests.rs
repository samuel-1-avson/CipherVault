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
            None,
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
    let mut block = ledger
        .propose_block(&op1, vec![tx.clone()], 2_000, None)
        .unwrap();
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

fn test_support_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "ciphervault-chain-test-{}-{}-{}",
        name,
        std::process::id(),
        nanos
    ));
    dir
}

fn signed_tx(
    client: &ConsensusSigner,
    chain_id: &str,
    salt_byte: u8,
    cid_byte: u8,
    nonce: u64,
    ts: u64,
) -> CommitmentTx {
    let salt = [salt_byte; 32];
    let head_cid = [cid_byte; 32];
    let commitment = CommitmentTx::calculate_commitment(&salt, &head_cid);
    let mut tx = CommitmentTx {
        vault_id: [9u8; 32],
        salt,
        head_cid,
        commitment,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce,
        timestamp_ms: ts,
    };
    client.sign_tx(&mut tx, chain_id);
    tx
}

#[test]
fn test_consensus_key_persistence_roundtrip() {
    let dir = test_support_dir("keys");
    let key_path = dir.join("device.key");

    let first = ConsensusSigner::load_or_create(&key_path).expect("create key");
    let second = ConsensusSigner::load_or_create(&key_path).expect("reload key");
    assert_eq!(first.public_key(), second.public_key());
    assert_eq!(std::fs::metadata(&key_path).expect("key file").len(), 32);

    let other = ConsensusSigner::load_or_create(&dir.join("other.key")).expect("second key");
    assert_ne!(other.public_key(), first.public_key());

    std::fs::write(&key_path, [0u8; 16]).expect("corrupt key");
    assert!(ConsensusSigner::load_or_create(&key_path).is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_nonce_replay_protection() {
    let chain_id = "ciphervault-nonce-test";
    let op = ConsensusSigner::generate();
    let validator_set = ValidatorSet::new(vec![op.public_key()]).unwrap();
    let mut ledger =
        SovereignLedger::create_genesis(chain_id, validator_set, &[&op], 1_000, None).unwrap();
    let client = ConsensusSigner::generate();

    // First transaction with nonce 5 commits fine.
    let tx1 = signed_tx(&client, chain_id, 0xaa, 0xbb, 5, 1_100);
    let block1 = ledger.propose_block(&op, vec![tx1], 2_000, None).unwrap();
    ledger.commit_block(block1).unwrap();
    assert_eq!(ledger.last_nonce(&client.public_key()), 5);
    assert_eq!(ledger.next_nonce(&client.public_key()), 6);

    // Exact replay is rejected.
    let replay = signed_tx(&client, chain_id, 0xaa, 0xbb, 5, 1_200);
    let err = ledger
        .propose_block(&op, vec![replay], 2_100, None)
        .unwrap_err();
    assert!(format!("{err}").contains("Stale"));

    // Lower nonce is rejected too.
    let lower = signed_tx(&client, chain_id, 0xcc, 0xdd, 3, 1_300);
    let err_lower = ledger
        .propose_block(&op, vec![lower], 2_200, None)
        .unwrap_err();
    assert!(format!("{err_lower}").contains("Stale"));

    // Higher nonce commits and advances the table.
    let tx2 = signed_tx(&client, chain_id, 0xee, 0xff, 6, 1_400);
    let block2 = ledger.propose_block(&op, vec![tx2], 3_000, None).unwrap();
    ledger.commit_block(block2).unwrap();
    assert_eq!(ledger.height(), 2);
    assert_eq!(ledger.last_nonce(&client.public_key()), 6);
}

#[test]
fn test_nonce_table_survives_reopen() {
    let chain_id = "ciphervault-nonce-reopen-test";
    let dir = test_support_dir("reopen");
    let op = ConsensusSigner::generate();
    let validator_set = ValidatorSet::new(vec![op.public_key()]).unwrap();
    let mut ledger = SovereignLedger::create_genesis(
        chain_id,
        validator_set.clone(),
        &[&op],
        1_000,
        Some(dir.clone()),
    )
    .unwrap();
    let client = ConsensusSigner::generate();

    let tx = signed_tx(&client, chain_id, 0x11, 0x22, 5, 1_100);
    let block = ledger.propose_block(&op, vec![tx], 2_000, None).unwrap();
    ledger.commit_block(block).unwrap();
    drop(ledger);

    let reopened = SovereignLedger::open(chain_id, validator_set, &dir).unwrap();
    assert_eq!(reopened.height(), 1);
    assert_eq!(reopened.last_nonce(&client.public_key()), 5);
    assert_eq!(reopened.next_nonce(&client.public_key()), 6);

    std::fs::remove_dir_all(&dir).ok();
}
