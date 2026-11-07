// Sovereign CipherChain anchoring fixtures.
//
// The Ethereum/Arbitrum anchor path was removed in Phase 1 of the
// sovereign-chain migration (legacy EVM code preserved in git tag
// `last-evm-anchor`).
use ciphervault_chain::{
    CommitmentTx, ConsensusSigner, SovereignLedger, SovereignLightClient, ValidatorSet,
    SOVEREIGN_CHAIN_ID_NUM, SOVEREIGN_CHAIN_ID_STR,
};
use ciphervault_format::CheckpointEvidence;
use ciphervault_local_store::LocalVaultStore;
use std::fs;

fn test_operators() -> (ValidatorSet, Vec<ConsensusSigner>) {
    let signers = vec![
        ConsensusSigner::generate(),
        ConsensusSigner::generate(),
        ConsensusSigner::generate(),
    ];
    let keys: Vec<[u8; 32]> = signers.iter().map(|s| s.public_key()).collect();
    let set = ValidatorSet::new(keys).expect("validator set");
    (set, signers)
}

#[test]
fn test_sovereign_commitment_evidence_roundtrip() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_sovereign_anchor_{}",
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
    let contract_address = [0u8; 20];
    let tx_hash = [0x77u8; 32];
    let block_number = 7u64;

    let commitment = CheckpointEvidence::compute_commitment(&salt, &head_cid);
    assert_ne!(commitment, [0u8; 32]);

    let evidence = CheckpointEvidence::new(
        salt,
        head_cid,
        SOVEREIGN_CHAIN_ID_NUM,
        contract_address,
        tx_hash,
        block_number,
        1710000000,
    );
    assert_eq!(evidence.commitment, commitment.to_vec());
    assert!(evidence.verify_commitment());

    let mut tampered = evidence.clone();
    tampered.salt[0] ^= 0xFF;
    assert!(!tampered.verify_commitment());

    store.save_checkpoint_evidence(&evidence).unwrap();
    let fetched = store.get_checkpoint_evidence(&head_cid).unwrap().unwrap();
    assert_eq!(fetched.commitment, evidence.commitment);
    assert_eq!(fetched.block_number, block_number);
    assert_eq!(fetched.chain_id, SOVEREIGN_CHAIN_ID_NUM);
    assert!(fetched.verify_commitment());

    let _ = fs::remove_dir_all(test_dir);
}

#[test]
fn test_sovereign_ledger_anchor_proof_and_light_verify() {
    let (validator_set, signers) = test_operators();
    assert_eq!(validator_set.quorum_threshold(), 3);

    let mut ledger = SovereignLedger::create_genesis(
        SOVEREIGN_CHAIN_ID_STR,
        validator_set.clone(),
        &[&signers[0], &signers[1], &signers[2]],
        1_700_000_000_000,
        None,
    )
    .expect("genesis");

    let client = ConsensusSigner::generate();
    let salt = [0x42u8; 32];
    let head_cid = [0x99u8; 32];
    let commitment = CommitmentTx::calculate_commitment(&salt, &head_cid);
    let mut tx = CommitmentTx {
        vault_id: [0x11u8; 32],
        salt,
        head_cid,
        commitment,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce: 1,
        timestamp_ms: 1_700_000_001_000,
    };
    client.sign_tx(&mut tx, SOVEREIGN_CHAIN_ID_STR);

    let mut block = ledger
        .propose_block(&signers[0], vec![tx], 1_700_000_005_000)
        .expect("propose");
    block
        .header
        .signatures
        .push(signers[1].sign_header(&block.header));
    block
        .header
        .signatures
        .push(signers[2].sign_header(&block.header));
    ledger.commit_block(block).expect("commit");
    assert_eq!(ledger.height(), 1);

    let proof = ledger.get_proof_for_commitment(&commitment).expect("proof");
    let light =
        SovereignLightClient::new(SOVEREIGN_CHAIN_ID_STR, validator_set.validators().to_vec());
    let result = light
        .verify_anchor(&head_cid, &salt, &proof)
        .expect("verify");
    assert!(result.verified);
    assert_eq!(result.height, 1);
}
