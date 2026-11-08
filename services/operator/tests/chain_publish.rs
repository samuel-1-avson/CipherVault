// HTTP proposal publication: `POST /v1/chain/publish` feeds the hub
// replica with the same admission rule as gossip, then relays to the swarm.
use axum::{extract::State, Json};
use ciphervault_chain::{
    ChainSyncEnvelope, ChainSyncMsg, CommitmentTx, ConsensusSigner, SovereignLedger, ValidatorSet,
    SOVEREIGN_CHAIN_ID_STR,
};
use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::handlers::post_chain_publish;
use ciphervault_operator::OperatorState;
use std::sync::Arc;

fn client_tx(
    client: &ConsensusSigner,
    salt_byte: u8,
    cid_byte: u8,
    nonce: u64,
    chain_id: &str,
) -> CommitmentTx {
    let salt = [salt_byte; 32];
    let head_cid = [cid_byte; 32];
    let commitment = CommitmentTx::calculate_commitment(&salt, &head_cid);
    let mut tx = CommitmentTx {
        vault_id: [0x44; 32],
        salt,
        head_cid,
        commitment,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce,
        timestamp_ms: 2_100,
    };
    client.sign_tx(&mut tx, chain_id);
    tx
}

/// Builds a 2-block chain (genesis + 1) and returns the sealed tip.
fn sealed_tip(signers: &[ConsensusSigner], set: &ValidatorSet) -> ChainSyncEnvelope {
    let refs: Vec<&ConsensusSigner> = signers.iter().collect();
    let client = ConsensusSigner::generate();
    let mut ledger =
        SovereignLedger::create_genesis(SOVEREIGN_CHAIN_ID_STR, set.clone(), &refs, 2_000, None)
            .unwrap();
    let tx = client_tx(&client, 1, 1, 1, SOVEREIGN_CHAIN_ID_STR);
    let mut block = ledger
        .propose_block(&signers[0], vec![tx], 3_000, None)
        .unwrap();
    for signer in &signers[1..] {
        block
            .header
            .signatures
            .push(signer.sign_header(&block.header));
    }
    ledger.commit_block(block.clone()).unwrap();
    ChainSyncEnvelope::seal(&signers[0], ChainSyncMsg::CertifiedBlock(block))
}

fn test_state(name: &str) -> (Arc<OperatorState>, ValidatorSet, Vec<ConsensusSigner>) {
    let dir = std::env::temp_dir().join(format!("cv-chain-publish-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signers: Vec<ConsensusSigner> = (0..3).map(|_| ConsensusSigner::generate()).collect();
    let keys: Vec<[u8; 32]> = signers.iter().map(|s| s.public_key()).collect();
    let set = ValidatorSet::new(keys).unwrap();
    let state = Arc::new(OperatorState::new_with_security(
        name.to_string(),
        dir,
        generate_signing_key(),
        ciphervault_operator::state::OperatorSecurityConfig::legacy(),
    ));
    state.set_chain_validators(set.clone());
    (state, set, signers)
}

#[tokio::test]
async fn publish_certified_tip_commits_then_duplicates() {
    let (state, set, signers) = test_state("tip");
    let envelope = sealed_tip(&signers, &set);

    let resp = post_chain_publish(State(state.clone()), Json(envelope.clone()))
        .await
        .unwrap();
    assert_eq!(resp.0["status"], "accepted");
    assert_eq!(resp.0["outcome"], "committed");
    assert_eq!(resp.0["gossip_published"], false);
    assert_eq!(state.chain_hub_height(), Some(1));

    // Same tip again: accepted, but a duplicate with no state change.
    let resp = post_chain_publish(State(state.clone()), Json(envelope))
        .await
        .unwrap();
    assert_eq!(resp.0["outcome"], "duplicate");
    assert_eq!(state.chain_hub_height(), Some(1));

    let _ = std::fs::remove_dir_all(&state.data_dir);
}

#[tokio::test]
async fn publish_rejects_tampered_and_foreign_envelopes() {
    let (state, set, signers) = test_state("reject");
    let mut envelope = sealed_tip(&signers, &set);

    // Tampered seal: 400.
    envelope.signature[0] ^= 0xFF;
    let err = post_chain_publish(State(state.clone()), Json(envelope))
        .await
        .unwrap_err();
    assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);

    // Foreign chain id (same fleet keys, different chain): 400.
    let refs: Vec<&ConsensusSigner> = signers.iter().collect();
    let foreign =
        SovereignLedger::create_genesis("foreign-chain-9", set.clone(), &refs, 2_000, None)
            .unwrap();
    let client = ConsensusSigner::generate();
    let tx = client_tx(&client, 7, 7, 1, "foreign-chain-9");
    let mut block = foreign
        .propose_block(&signers[0], vec![tx], 3_000, None)
        .unwrap();
    for signer in &signers[1..] {
        block
            .header
            .signatures
            .push(signer.sign_header(&block.header));
    }
    let foreign_env = ChainSyncEnvelope::seal(
        &signers[0],
        ChainSyncMsg::Proposal(ciphervault_chain::ProposalMsg { block }),
    );
    let err = post_chain_publish(State(state.clone()), Json(foreign_env))
        .await
        .unwrap_err();
    assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);

    let _ = std::fs::remove_dir_all(&state.data_dir);
}
