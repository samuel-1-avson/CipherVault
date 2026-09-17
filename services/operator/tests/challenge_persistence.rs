//! Auth challenges survive an operator restart (B4 remainder: sessions, peers,
//! approvals, and checkpoints were already durable; 5-minute handshake nonces
//! were the only in-memory map left).

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::OperatorState;

#[test]
fn issued_challenge_survives_restart() {
    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    let root =
        std::env::temp_dir().join(format!("cv-challenge-restart-{}", rand::random::<u128>()));
    let device_key = generate_signing_key();
    let device_pk_hex = hex::encode(device_key.verifying_key().as_bytes());
    let vault_id_hex = hex::encode([7u8; 32]);

    let (challenge_id, nonce_hex, _) = {
        let state = OperatorState::new(
            "challenge-restart".into(),
            root.clone(),
            generate_signing_key(),
        );
        state
            .issue_challenge(&vault_id_hex, &device_pk_hex)
            .expect("issue")
    };
    assert!(root.join("challenges.json").exists());

    let signature = ciphervault_crypto::signatures::sign_with_domain(
        &device_key,
        b"operator_challenge",
        &hex::decode(&nonce_hex).unwrap(),
    );
    let reopened = OperatorState::new(
        "challenge-restart".into(),
        root.clone(),
        generate_signing_key(),
    );
    let token = reopened
        .verify_and_create_session(&challenge_id, &device_pk_hex, &hex::encode(signature))
        .expect("challenge must survive restart");
    assert!(!token.is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn consumed_challenge_does_not_come_back_after_restart() {
    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
    let root =
        std::env::temp_dir().join(format!("cv-challenge-consume-{}", rand::random::<u128>()));
    let device_key = generate_signing_key();
    let device_pk_hex = hex::encode(device_key.verifying_key().as_bytes());
    let vault_id_hex = hex::encode([9u8; 32]);

    let state = OperatorState::new(
        "challenge-consume".into(),
        root.clone(),
        generate_signing_key(),
    );
    let (challenge_id, nonce_hex, _) = state
        .issue_challenge(&vault_id_hex, &device_pk_hex)
        .expect("issue");
    let signature = ciphervault_crypto::signatures::sign_with_domain(
        &device_key,
        b"operator_challenge",
        &hex::decode(&nonce_hex).unwrap(),
    );
    state
        .verify_and_create_session(&challenge_id, &device_pk_hex, &hex::encode(signature))
        .expect("first verification succeeds");
    drop(state);

    let reopened = OperatorState::new(
        "challenge-consume".into(),
        root.clone(),
        generate_signing_key(),
    );
    assert!(
        reopened
            .verify_and_create_session(&challenge_id, &device_pk_hex, &hex::encode(signature))
            .is_none(),
        "single-use challenge must not verify twice across a restart"
    );
    let _ = std::fs::remove_dir_all(root);
}
