use super::*;
fn legacy_state(id: String, dir: PathBuf, key: SigningKey) -> OperatorState {
    OperatorState::new_with_security(id, dir, key, OperatorSecurityConfig::legacy())
}

#[test]
fn lease_persistence_renewal_and_signed_fields() {
    let root = std::env::temp_dir().join(format!("cv-lease-{}", rand::random::<u128>()));
    let key = ciphervault_crypto::generate_signing_key();
    let state = legacy_state("test".into(), root.clone(), key.clone());
    let receipt = state.create_lease(&"a".repeat(64), 100, 90).unwrap();
    let pk = key.verifying_key().to_bytes();
    receipt.verify(&pk).unwrap();
    let mut tampered = receipt.clone();
    tampered.bytes += 1;
    assert!(tampered.verify(&pk).is_err());
    drop(state);
    let restarted = legacy_state("test".into(), root.clone(), key);
    let renewed = restarted.renew_lease(&receipt.lease_id, 30, 100).unwrap();
    assert_eq!(renewed.closure_digest_hex, receipt.closure_digest_hex);
    assert_eq!(renewed.expires_at_utc, receipt.expires_at_utc + 30 * 86400);
    assert!(restarted.renew_lease("../escape", 30, 100).is_err());
    assert!(restarted.renew_lease(&"0".repeat(32), 30, 100).is_err());
    assert!(restarted.renew_lease(&receipt.lease_id, 30, 999).is_err());
    drop(restarted);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lease_listing_is_vault_scoped_and_skips_legacy() {
    let root = std::env::temp_dir().join(format!("cv-leaselist-{}", rand::random::<u128>()));
    let key = ciphervault_crypto::generate_signing_key();
    let state = legacy_state("test".into(), root.clone(), key);
    let vault_a = "a".repeat(64);
    let vault_b = "b".repeat(64);
    let first = state.create_lease(&"c".repeat(64), 100, 90).unwrap();
    let second = state.create_lease(&"d".repeat(64), 200, 30).unwrap();
    let legacy = state.create_lease(&"e".repeat(64), 300, 30).unwrap();
    state.record_lease_owner(&first.lease_id, &vault_a).unwrap();
    state
        .record_lease_owner(&second.lease_id, &vault_b)
        .unwrap();
    // No sidecar for `legacy`: it stays invisible to every vault.
    let listed_a = state.list_leases_for_vault(&vault_a);
    assert_eq!(listed_a.len(), 1);
    assert_eq!(listed_a[0].lease_id, first.lease_id);
    let listed_b = state.list_leases_for_vault(&vault_b);
    assert_eq!(listed_b.len(), 1);
    assert_eq!(listed_b[0].lease_id, second.lease_id);
    assert!(listed_a.iter().all(|r| r.lease_id != legacy.lease_id));
    assert!(state.list_leases_for_vault(&"f".repeat(64)).is_empty());
    // Bad inputs never write.
    assert!(state.record_lease_owner("../escape", &vault_a).is_err());
    assert!(state.record_lease_owner(&first.lease_id, "short").is_err());
    // Corrupt records are skipped, not fatal.
    fs::write(
        root.join("leases")
            .join(format!("{}.json", second.lease_id)),
        b"{not json",
    )
    .unwrap();
    assert_eq!(state.list_leases_for_vault(&vault_b).len(), 0);
    assert_eq!(state.list_leases_for_vault(&vault_a).len(), 1);
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_failed_persistence_and_anonymous_writes() {
    let root = std::env::temp_dir().join(format!("cv-write-{}", rand::random::<u128>()));
    let state = legacy_state(
        "test".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    assert!(state.validate_read_session("recovery_anonymous"));
    assert!(!state.validate_write_session("recovery_anonymous"));
    fs::remove_dir(root.join("leases")).unwrap();
    fs::write(root.join("leases"), b"block writes").unwrap();
    assert!(state.create_lease(&"a".repeat(64), 100, 90).is_err());
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn challenge_binds_device_key_and_vault_and_persists_session() {
    std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");
    let root = std::env::temp_dir().join(format!("cv-session-{}", rand::random::<u128>()));
    let operator_key = ciphervault_crypto::generate_signing_key();
    let state = legacy_state("test-auth".into(), root.clone(), operator_key);
    let device_key = ciphervault_crypto::generate_signing_key();
    let other_key = ciphervault_crypto::generate_signing_key();
    let vault_id = "11".repeat(32);
    let other_vault = "22".repeat(32);
    let device_pk = hex::encode(device_key.verifying_key().as_bytes());

    let (challenge_id, nonce_hex, _) = state
        .issue_challenge(&vault_id, &device_pk)
        .expect("valid challenge inputs");
    let nonce = hex::decode(nonce_hex).unwrap();
    let signature = ciphervault_crypto::signatures::sign_with_domain(
        &device_key,
        b"operator_challenge",
        &nonce,
    );
    assert!(state
        .verify_and_create_session(
            &challenge_id,
            &hex::encode(other_key.verifying_key().as_bytes()),
            &hex::encode(signature)
        )
        .expect("persist ok")
        .is_none());

    let (challenge_id, nonce_hex, _) = state
        .issue_challenge(&vault_id, &device_pk)
        .expect("valid challenge inputs");
    let nonce = hex::decode(nonce_hex).unwrap();
    let signature = ciphervault_crypto::signatures::sign_with_domain(
        &device_key,
        b"operator_challenge",
        &nonce,
    );
    let token = state
        .verify_and_create_session(&challenge_id, &device_pk, &hex::encode(signature))
        .expect("persist ok")
        .expect("bound session");
    assert!(state.validate_session_for_vault(&token, &vault_id));
    assert!(!state.validate_session_for_vault(&token, &other_vault));

    drop(state);
    let restarted = legacy_state(
        "test-auth".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    assert!(restarted.validate_session_for_vault(&token, &vault_id));
    assert!(restarted.revoke_session(&token).expect("persist ok"));
    assert!(!restarted.validate_write_session(&token));
    drop(restarted);
    fs::remove_dir_all(root).unwrap();
    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
}

#[test]
fn test_operator_recovery_record_cryptographic_authorization() {
    use ciphervault_crypto::RecoverySecret;
    use ciphervault_format::to_canonical_cbor;

    let root = std::env::temp_dir().join(format!("cv-auth-{}", rand::random::<u128>()));
    let op_key = ciphervault_crypto::generate_signing_key();
    let state = legacy_state("test".into(), root.clone(), op_key);

    let vault_id = vec![0x42u8; 32];
    let locator_hex = "a".repeat(64);

    let r_secret = RecoverySecret::generate();
    let r_sk = r_secret.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r_secret.derive_recovery_encryption_keys().unwrap();

    // 1. Poisoning attempt with arbitrary bytes must be rejected
    let poisoned = b"malicious random garbage payload";
    assert!(state
        .append_recovery_record(&locator_hex, poisoned)
        .is_err());

    // 2. GenesisRecord signed by recovery authority must be accepted
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.clone(),
        recovery_signing_pk: r_sk.verifying_key().to_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![1u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();
    let genesis_cbor = to_canonical_cbor(&genesis).unwrap();
    assert!(state
        .append_recovery_record(&locator_hex, &genesis_cbor)
        .is_ok());

    // 3. Forged GenesisRecord for the same locator must be rejected
    let rogue_sk = ciphervault_crypto::generate_signing_key();
    let mut forged_genesis = genesis.clone();
    forged_genesis.recovery_signing_pk = rogue_sk.verifying_key().to_bytes().to_vec();
    forged_genesis.sign(&rogue_sk).unwrap();
    let forged_genesis_cbor = to_canonical_cbor(&forged_genesis).unwrap();
    assert!(state
        .append_recovery_record(&locator_hex, &forged_genesis_cbor)
        .is_err());

    // 4. Valid DeviceCertificate signed by recovery authority must be accepted
    let dev_sk = ciphervault_crypto::generate_signing_key();
    let mut cert = DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.clone(),
        certificate_id: vec![2u8; 32],
        device_signing_pk: dev_sk.verifying_key().to_bytes().to_vec(),
        permissions: 1,
        authority_generation: 1,
        issued_at_utc: 1001,
        signature: Vec::new(),
    };
    cert.sign(&r_sk).unwrap();
    let cert_cbor = to_canonical_cbor(&cert).unwrap();
    assert!(state
        .append_recovery_record(&locator_hex, &cert_cbor)
        .is_ok());

    // 5. Forged DeviceCertificate signed by attacker must be rejected
    let mut forged_cert = cert.clone();
    forged_cert.certificate_id = vec![3u8; 32];
    forged_cert.sign(&rogue_sk).unwrap();
    let forged_cert_cbor = to_canonical_cbor(&forged_cert).unwrap();
    assert!(state
        .append_recovery_record(&locator_hex, &forged_cert_cbor)
        .is_err());

    // 6. Valid HeadRecord signed by authorized device must be accepted
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.clone(),
        snapshot_id: vec![0xAAu8; 32],
        parent_snapshot_ids: Vec::new(),
        closure_digest: vec![0xBBu8; 32],
        device_id: vec![0xCCu8; 32],
        device_counter: 1,
        signature: Vec::new(),
    };
    head.sign(&dev_sk).unwrap();
    let head_cbor = to_canonical_cbor(&head).unwrap();
    assert!(state
        .append_recovery_record(&locator_hex, &head_cbor)
        .is_ok());

    // 7. Forged HeadRecord signed by unauthorized key must be rejected
    let mut forged_head = head.clone();
    forged_head.device_counter = 2;
    forged_head.sign(&rogue_sk).unwrap();
    let forged_head_cbor = to_canonical_cbor(&forged_head).unwrap();
    assert!(state
        .append_recovery_record(&locator_hex, &forged_head_cbor)
        .is_err());

    // Verify that only the 3 valid records were committed to disk
    let stored = state.get_recovery_records(&locator_hex);
    assert_eq!(stored.len(), 3);

    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_operator_pos_challenge_and_proof() {
    let root = std::env::temp_dir().join(format!("cv-pos-{}", rand::random::<u128>()));
    let key = ciphervault_crypto::generate_signing_key();
    let operator_pk = key.verifying_key().to_bytes();
    let state = legacy_state("test-pos-operator".into(), root.clone(), key);

    let data = b"encrypted-blob-for-proof-of-storage-challenge";
    let cid = ciphervault_format::compute_digest(data);
    let cid_hex = hex::encode(cid);

    // Put object
    state.put_object(&cid_hex, data).unwrap();

    // 1. Valid challenge generates matching verifiable receipt
    let nonce = [0x55u8; 32];
    let receipt = state.generate_pos_proof(&cid_hex, &nonce).unwrap();
    assert_eq!(receipt.operator_id, "test-pos-operator");
    assert_eq!(receipt.cid_hex, cid_hex);
    assert_eq!(receipt.nonce_hex, hex::encode(nonce));
    assert_eq!(receipt.size_bytes, data.len() as u64);

    let expected_proof = ciphervault_storage::compute_pos_proof(&cid, &nonce, data);
    assert!(receipt.verify(&operator_pk, &expected_proof).is_ok());

    // 2. Nonexistent CID fails with Object not found
    let missing_cid = hex::encode([0x99u8; 32]);
    let err = state.generate_pos_proof(&missing_cid, &nonce).unwrap_err();
    assert_eq!(err, "Object not found");

    // 3. Invalid CID hex length fails
    assert!(state.generate_pos_proof("short_cid", &nonce).is_err());

    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_peer_gossip_registry() {
    let root = std::env::temp_dir().join(format!("cv-peer-{}", rand::random::<u128>()));
    let key = ciphervault_crypto::generate_signing_key();
    let state = legacy_state("test-op".into(), root.clone(), key);

    let peer_key = ciphervault_crypto::generate_signing_key();
    let peer_pk = peer_key.verifying_key().to_bytes();
    let mut peer = ciphervault_storage::PeerDescriptor {
        operator_id: "peer-1".into(),
        endpoint: "http://127.0.0.1:8102".into(),
        signing_pk_hex: hex::encode(peer_pk),
        timestamp_utc: Utc::now().timestamp() as u64,
        signature_hex: String::new(),
    };
    peer.sign(&peer_key);

    assert_eq!(state.register_peer(peer.clone()).unwrap(), 1);
    let peers = state.get_active_peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].operator_id, "peer-1");

    // Invalid signature rejected
    let mut bad_peer = peer.clone();
    bad_peer.signature_hex = hex::encode([0x00u8; 64]);
    assert!(state.register_peer(bad_peer).is_err());

    // Stale and future-dated announces are rejected even with a VALID
    // signature (re-signed after backdating so only freshness fails).
    // Margins are an hour past each bound: register_peer reads its own
    // clock, so a 1s margin flakes when a loaded runner stalls the
    // thread across a second boundary between the two reads.
    let now = Utc::now().timestamp() as u64;
    let mut stale = peer.clone();
    stale.timestamp_utc = now - MAX_PEER_ANNOUNCE_AGE_SECS - 3600;
    stale.sign(&peer_key);
    assert!(state.register_peer(stale).is_err());

    let mut future = peer.clone();
    future.timestamp_utc = now + MAX_PEER_ANNOUNCE_SKEW_SECS + 3600;
    future.sign(&peer_key);
    assert!(state.register_peer(future).is_err());

    // Control: the fresh descriptor still registers.
    assert!(state.register_peer(peer.clone()).is_ok());

    // Routing state survives an operator restart.
    drop(state);
    let reopened = legacy_state(
        "test-op".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    let peers = reopened.get_active_peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].operator_id, "peer-1");
    assert_eq!(peers[0].endpoint, "http://127.0.0.1:8102");

    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn byte_size_limits_parse_and_clamp() {
    assert_eq!(parse_byte_size("8388608"), Some(8_388_608));
    assert_eq!(parse_byte_size("8MB"), Some(8 * 1024 * 1024));
    assert_eq!(parse_byte_size("64kb"), Some(64 * 1024));
    assert_eq!(parse_byte_size("512"), Some(512));
    assert_eq!(parse_byte_size(""), None);
    assert_eq!(parse_byte_size("nope"), None);
    std::env::set_var("CIPHERVAULT_TEST_LIMIT_BYTES", "2MB");
    assert_eq!(
        operator_limit_from_env("CIPHERVAULT_TEST_LIMIT_BYTES", 1024, 512),
        2 * 1024 * 1024
    );
    std::env::set_var("CIPHERVAULT_TEST_LIMIT_BYTES", "1");
    assert_eq!(
        operator_limit_from_env("CIPHERVAULT_TEST_LIMIT_BYTES", 1024, 512),
        1024
    );
    std::env::remove_var("CIPHERVAULT_TEST_LIMIT_BYTES");
    assert_eq!(
        operator_limit_from_env("CIPHERVAULT_TEST_LIMIT_BYTES", 1024, 512),
        1024
    );
}

#[test]
fn test_approval_challenge_registry() {
    let root = std::env::temp_dir().join(format!("cv-appr-{}", rand::random::<u128>()));
    let key = ciphervault_crypto::generate_signing_key();
    let state = legacy_state("test-op".into(), root.clone(), key);

    let vault_id = [0xAAu8; 32];
    let device_id = [0xBBu8; 32];
    let challenge = ciphervault_recovery::ApprovalChallenge::new(
        &vault_id,
        ciphervault_recovery::ApprovalAction::EmergencyRecovery,
        &device_id,
        "Recovery test".into(),
        300,
    );

    state
        .register_approval_challenge(challenge.clone())
        .unwrap();
    let pending = state.get_pending_challenges();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].challenge_id, challenge.challenge_id);

    let approver_key = ciphervault_crypto::generate_signing_key();
    let receipt = ciphervault_recovery::SignedApprovalReceipt::sign(
        &challenge,
        "Alice Lead".into(),
        &approver_key,
    );

    assert_eq!(state.submit_approval_receipt(receipt.clone()).unwrap(), 1);

    let status = state.get_challenge_status(&challenge.challenge_id).unwrap();
    assert_eq!(status.1.len(), 1);
    assert_eq!(status.1[0].approver_name, "Alice Lead");

    // Challenge + receipts survive an operator restart.
    drop(state);
    let reopened = legacy_state(
        "test-op".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    let status = reopened
        .get_challenge_status(&challenge.challenge_id)
        .unwrap();
    assert_eq!(status.1.len(), 1);
    assert_eq!(status.1[0].approver_name, "Alice Lead");

    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn io_stripes_shard_by_key() {
    let root = std::env::temp_dir().join(format!("cv-stripes-{}", rand::random::<u128>()));
    let state = legacy_state(
        "test".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    // Distinct keys must spread across stripes so concurrent uploads for
    // different CIDs do not serialize on one lock.
    let mut shards = std::collections::HashSet::new();
    for index in 0..256u32 {
        shards.insert(state.io_stripe(&format!("{index:064x}")) as *const _ as usize);
    }
    assert!(
        shards.len() > 16,
        "expected striped locks to spread 256 keys, got {}",
        shards.len()
    );
    // The same key must always resolve to the same stripe.
    let first = state.io_stripe(&"ab".repeat(32)) as *const _ as usize;
    let second = state.io_stripe(&"ab".repeat(32)) as *const _ as usize;
    assert_eq!(first, second);
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn metrics_count_operations_and_render_prometheus() {
    let root = std::env::temp_dir().join(format!("cv-metrics-{}", rand::random::<u128>()));
    let state = legacy_state(
        "test".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    let payload = b"metrics-observed-object";
    let cid_hex = hex::encode(ciphervault_format::compute_digest(payload));
    state.put_object(&cid_hex, payload).unwrap();
    assert!(state.put_object(&cid_hex, b"wrong bytes!!").is_err());
    assert_eq!(state.get_object(&cid_hex).as_deref(), Some(&payload[..]));
    assert!(state.get_object(&"00".repeat(32)).is_none());
    let nonce = [0x77u8; 32];
    assert!(state.generate_pos_proof(&cid_hex, &nonce).is_ok());
    assert!(state.generate_pos_proof(&"00".repeat(32), &nonce).is_err());
    assert!(!state.validate_session_for_vault("bogus", &"11".repeat(32)));

    let exposition = state.metrics.render_prometheus();
    for line in [
        "ciphervault_operator_objects_put_total 1",
        "ciphervault_operator_objects_put_failures_total 1",
        "ciphervault_operator_objects_get_total 2",
        "ciphervault_operator_pos_challenges_total 2",
        "ciphervault_operator_pos_failures_total 1",
        "ciphervault_operator_auth_failures_total 1",
        "ciphervault_operator_uptime_seconds ",
    ] {
        assert!(
            exposition.contains(line),
            "missing metric line {line:?} in:\n{exposition}"
        );
    }
    assert!(exposition.contains("# TYPE ciphervault_operator_put_latency_ms histogram"));
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn poisoned_locks_recover_with_prior_state() {
    let root = std::env::temp_dir().join(format!("cv-poison-{}", rand::random::<u128>()));
    let state = legacy_state(
        "test".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    lock_or_recover(&state.sessions, "sessions").insert("tok".into(), u64::MAX);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = state.sessions.lock().unwrap();
        panic!("intentional poison");
    }));
    assert!(state.sessions.is_poisoned());
    // Recovery, not panic: prior state is intact and the lock works again.
    assert!(state.validate_write_session("tok"));
    assert!(!state.sessions.is_poisoned());
    assert!(state.revoke_session("tok").expect("revoke recovers"));
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

/// Blocks an atomic-persist target the way a full disk would: the temp
/// file writes fine but the rename onto a non-empty directory fails on
/// every platform.
fn block_persist_target(path: &std::path::Path) {
    let _ = fs::remove_file(path);
    fs::create_dir(path).unwrap();
    fs::write(path.join("block"), b"no renames here").unwrap();
}

#[test]
fn session_persist_failure_rolls_back_and_errors() {
    let root = std::env::temp_dir().join(format!("cv-sessfail-{}", rand::random::<u128>()));
    let state = legacy_state(
        "test".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    lock_or_recover(&state.sessions, "sessions").insert("tok".into(), u64::MAX);
    lock_or_recover(&state.session_keys, "session_keys").insert("tok".into(), [9u8; 32]);
    lock_or_recover(&state.session_vaults, "session_vaults").insert("tok".into(), "ab".repeat(32));
    block_persist_target(&root.join("sessions.json"));
    assert!(state.persist_sessions().is_err());
    // Revocation fails loudly and restores the in-memory session so
    // memory still matches the (unwritten) disk state.
    let error = state.revoke_session("tok").expect_err("persist must fail");
    assert!(
        error.contains("Unable to persist session revocation"),
        "{error}"
    );
    assert!(state.validate_write_session("tok"));
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn challenge_persist_failure_rolls_back_and_errors() {
    std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");
    let root = std::env::temp_dir().join(format!("cv-chalfail-{}", rand::random::<u128>()));
    let state = legacy_state(
        "test".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    block_persist_target(&root.join("challenges.json"));
    let error = state
        .issue_challenge(&"11".repeat(32), &"22".repeat(32))
        .expect_err("persist must fail");
    assert!(error.contains("Unable to persist challenges"), "{error}");
    assert!(lock_or_recover(&state.challenges, "challenges").is_empty());
    // The removal persist runs before validation, so a seeded challenge
    // also surfaces the store error rather than an auth verdict.
    lock_or_recover(&state.challenges, "challenges").insert(
        "cid".into(),
        ChallengeRecord {
            nonce_hex: "00".repeat(32),
            expires_at_utc: u64::MAX,
            vault_id_hex: "11".repeat(32),
            public_key_hex: "22".repeat(32),
            account_id: None,
            device_id_hex: None,
        },
    );
    let error = state
        .verify_and_create_session("cid", &"22".repeat(32), &"00".repeat(64))
        .expect_err("persist must fail");
    assert!(
        error.contains("Unable to persist challenge removal"),
        "{error}"
    );
    drop(state);
    fs::remove_dir_all(root).unwrap();
    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
}

#[test]
fn session_issue_persist_failure_rolls_back_login() {
    std::env::set_var("CIPHERVAULT_OPERATOR_STRICT_AUTH", "false");
    let root = std::env::temp_dir().join(format!("cv-loginfail-{}", rand::random::<u128>()));
    let state = legacy_state(
        "test".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    let device_key = ciphervault_crypto::generate_signing_key();
    let device_pk = hex::encode(device_key.verifying_key().as_bytes());
    let vault_id = "11".repeat(32);
    let (challenge_id, nonce_hex, _) = state.issue_challenge(&vault_id, &device_pk).expect("issue");
    let nonce = hex::decode(nonce_hex).unwrap();
    let signature = ciphervault_crypto::signatures::sign_with_domain(
        &device_key,
        b"operator_challenge",
        &nonce,
    );
    block_persist_target(&root.join("sessions.json"));
    let error = state
        .verify_and_create_session(&challenge_id, &device_pk, &hex::encode(signature))
        .expect_err("persist must fail");
    assert!(error.contains("Unable to persist session"), "{error}");
    // No half-minted session lingers in memory.
    assert!(lock_or_recover(&state.sessions, "sessions").is_empty());
    drop(state);
    fs::remove_dir_all(root).unwrap();
    std::env::remove_var("CIPHERVAULT_OPERATOR_STRICT_AUTH");
}

fn assert_quota_exhausted(result: Result<(), StorageError>, what: &str) {
    match result {
        Err(StorageError::ServerError { status, .. }) => {
            assert_eq!(status, 429, "{what}");
        }
        other => panic!("expected 429 quota exhaustion for {what}, got {other:?}"),
    }
}

#[test]
fn voucher_spend_survives_restart() {
    let root = std::env::temp_dir().join(format!("cv-voucherrestart-{}", rand::random::<u128>()));
    let key = ciphervault_crypto::generate_signing_key();
    let holder = hex::encode(
        ciphervault_crypto::generate_signing_key()
            .verifying_key()
            .to_bytes(),
    );
    let payload = vec![0xABu8; 64];
    let cid_hex = hex::encode(compute_digest(&payload));
    let voucher = {
        let state = legacy_state("test".into(), root.clone(), key.clone());
        let voucher = state.issue_voucher(holder, 64, 3600).expect("issue");
        state
            .put_object_with_voucher(&cid_hex, &payload, Some(&voucher))
            .expect("first write spends the quota");
        // Control: exhaustion is enforced before any restart.
        let extra = vec![0xCDu8; 1];
        let extra_cid = hex::encode(compute_digest(&extra));
        assert_quota_exhausted(
            state.put_object_with_voucher(&extra_cid, &extra, Some(&voucher)),
            "pre-restart over-quota write",
        );
        assert!(root.join("voucher-ledger.json").is_file());
        voucher
    };
    let restarted = legacy_state("test".into(), root.clone(), key);
    let extra = vec![0xCDu8; 1];
    let extra_cid = hex::encode(compute_digest(&extra));
    assert_quota_exhausted(
        restarted.put_object_with_voucher(&extra_cid, &extra, Some(&voucher)),
        "post-restart over-quota write",
    );
    drop(restarted);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_voucher_ledger_preserves_evidence_and_disables_writes() {
    let root = std::env::temp_dir().join(format!("cv-vouchercorrupt-{}", rand::random::<u128>()));
    let key = ciphervault_crypto::generate_signing_key();
    drop(legacy_state("test".into(), root.clone(), key.clone()));
    fs::write(root.join("voucher-ledger.json"), b"{oops").unwrap();
    let reopened = legacy_state("test".into(), root.clone(), key);
    let backups: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("voucher-ledger.corrupt-")
        })
        .collect();
    assert!(backups.is_empty());
    assert_eq!(
        fs::read(root.join("voucher-ledger.json")).unwrap(),
        b"{oops"
    );
    let holder = hex::encode(
        ciphervault_crypto::generate_signing_key()
            .verifying_key()
            .to_bytes(),
    );
    let voucher = reopened.issue_voucher(holder, 10, 3600).expect("issue");
    let payload = b"0123456789".to_vec();
    let cid_hex = hex::encode(compute_digest(&payload));
    assert!(matches!(
        reopened.put_object_with_voucher(&cid_hex, &payload, Some(&voucher)),
        Err(StorageError::ServerError { status: 503, .. })
    ));
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

/// Serializes tests that mutate join-related env (`CIPHERVAULT_FLEET_KEY`,
/// `CIPHERVAULT_PROBATION_SECS`, ...): process env is global, so parallel
/// tests would otherwise read each other's pins.
static JOIN_TEST_SERIALIZER: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn join_test_guard() -> std::sync::MutexGuard<'static, ()> {
    JOIN_TEST_SERIALIZER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn join_test_state(tag: &str) -> (OperatorState, PathBuf) {
    let root = std::env::temp_dir().join(format!("cv-{tag}-{}", rand::random::<u128>()));
    let key = ciphervault_crypto::generate_signing_key();
    let state = legacy_state("test-op".into(), root.clone(), key);
    (state, root)
}

fn join_test_peer(operator_id: &str) -> (ciphervault_storage::PeerDescriptor, SigningKey) {
    let peer_key = ciphervault_crypto::generate_signing_key();
    let mut peer = ciphervault_storage::PeerDescriptor {
        operator_id: operator_id.into(),
        endpoint: "http://127.0.0.1:8301".into(),
        signing_pk_hex: hex::encode(peer_key.verifying_key().to_bytes()),
        timestamp_utc: Utc::now().timestamp() as u64,
        signature_hex: String::new(),
    };
    peer.sign(&peer_key);
    (peer, peer_key)
}

fn backdate_membership(root: &std::path::Path, operator_id: &str, joined_ago: u64, seen_ago: u64) {
    let path = root.join("peer-membership.json");
    let raw = fs::read_to_string(&path).unwrap();
    let mut records: HashMap<String, PeerMembership> = serde_json::from_str(&raw).unwrap();
    let now = Utc::now().timestamp() as u64;
    let record = records.get_mut(operator_id).unwrap();
    record.joined_utc = now - joined_ago;
    record.last_seen_utc = now - seen_ago;
    fs::write(&path, serde_json::to_vec_pretty(&records).unwrap()).unwrap();
}

fn quorum_test_keys(n: usize) -> (Vec<SigningKey>, Vec<String>) {
    let keys: Vec<SigningKey> = (0..n)
        .map(|_| ciphervault_crypto::generate_signing_key())
        .collect();
    let pks = keys
        .iter()
        .map(|key| hex::encode(key.verifying_key().to_bytes()))
        .collect();
    (keys, pks)
}

fn pin_quorum_keys(pks: &[String], k: Option<usize>) {
    std::env::set_var("CIPHERVAULT_FLEET_KEYS", pks.join(","));
    match k {
        Some(threshold) => std::env::set_var("CIPHERVAULT_QUORUM_K", threshold.to_string()),
        None => std::env::remove_var("CIPHERVAULT_QUORUM_K"),
    }
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
}

fn unpin_quorum_keys() {
    std::env::remove_var("CIPHERVAULT_FLEET_KEYS");
    std::env::remove_var("CIPHERVAULT_QUORUM_K");
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
}

fn quorum_ticket(keys: &[SigningKey], approvers: &[usize], node_pk_hex: String) -> JoinInvite {
    use ciphervault_storage::invites::{InviteApproval, InviteRequest};
    let request = InviteRequest::new(node_pk_hex, 3600).unwrap();
    let approvals: Vec<InviteApproval> = approvers
        .iter()
        .map(|index| InviteApproval::approve(&keys[*index], &request).unwrap())
        .collect();
    JoinInvite::issue_quorum(&request, &approvals).unwrap()
}

#[test]
fn quorum_join_admits_and_logs_evidence() {
    let _guard = join_test_guard();
    let (keys, pks) = quorum_test_keys(3);
    pin_quorum_keys(&pks, None);
    let (state, root) = join_test_state("quorum-join");
    let (peer, _) = join_test_peer("quorum-joiner");
    let invite = quorum_ticket(&keys, &[0, 2], peer.signing_pk_hex.clone());
    assert_eq!(state.join_with_invite(peer.clone(), &invite).unwrap(), 1);
    assert!(state.is_probationary("quorum-joiner"));
    let admissions = state.admissions_snapshot();
    assert_eq!(admissions.len(), 1);
    let record = &admissions[0];
    assert_eq!(record.ticket_version, 2);
    assert_eq!(record.operator_id, "quorum-joiner");
    assert_eq!(record.node_pk_hex, peer.signing_pk_hex);
    assert_eq!(record.nonce_hex, invite.nonce_hex);
    assert_eq!(record.signer_pks, vec![pks[0].clone(), pks[2].clone()]);
    assert_eq!(record.ticket_sha256.len(), 64);
    assert!(root.join("join-admissions.json").is_file());
    // Evidence survives restarts.
    drop(state);
    let reopened = legacy_state(
        "test-op".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    assert_eq!(reopened.admissions_snapshot().len(), 1);
    drop(reopened);
    unpin_quorum_keys();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn quorum_join_rejects_below_threshold_without_side_effects() {
    let _guard = join_test_guard();
    let (keys, pks) = quorum_test_keys(3);
    pin_quorum_keys(&pks, None);
    let (state, root) = join_test_state("quorum-short");
    let (peer, _) = join_test_peer("short-joiner");
    let invite = quorum_ticket(&keys, &[1], peer.signing_pk_hex.clone());
    let err = state
        .join_with_invite(peer.clone(), &invite)
        .expect_err("below threshold");
    assert!(err.contains("have 1 of 2"), "{err}");
    assert!(state.admissions_snapshot().is_empty());
    assert!(state.membership_snapshot().is_empty());
    // A quorate ticket for the same node still works: nothing poisoned.
    let full = quorum_ticket(&keys, &[0, 1], peer.signing_pk_hex.clone());
    assert_eq!(state.join_with_invite(peer, &full).unwrap(), 1);
    assert_eq!(state.admissions_snapshot().len(), 1);
    drop(state);
    unpin_quorum_keys();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn quorum_v1_ticket_counts_as_single_approval_at_k1() {
    let _guard = join_test_guard();
    let (keys, pks) = quorum_test_keys(2);
    pin_quorum_keys(&pks, Some(1));
    let (state, root) = join_test_state("quorum-v1");
    let (peer, _) = join_test_peer("v1-joiner");
    let invite = JoinInvite::issue(&keys[1], peer.signing_pk_hex.clone(), 3600).unwrap();
    assert_eq!(state.join_with_invite(peer, &invite).unwrap(), 1);
    let admissions = state.admissions_snapshot();
    assert_eq!(admissions.len(), 1);
    assert_eq!(admissions[0].ticket_version, 1);
    assert_eq!(admissions[0].signer_pks, vec![pks[1].clone()]);
    drop(state);
    unpin_quorum_keys();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn quorum_config_fails_closed() {
    let _guard = join_test_guard();
    let (keys, pks) = quorum_test_keys(2);
    let (state, root) = join_test_state("quorum-closed");
    let (peer, _) = join_test_peer("closed-joiner");
    let invite = quorum_ticket(&keys, &[0, 1], peer.signing_pk_hex.clone());
    for bad_k in ["0", "3", "99", "nope"] {
        pin_quorum_keys(&pks, None);
        std::env::set_var("CIPHERVAULT_QUORUM_K", bad_k);
        let err = state
            .join_with_invite(peer.clone(), &invite)
            .expect_err("bad K fails closed");
        assert_eq!(err, "Verified join is not configured on this node");
    }
    // Default K with 2 keys is strict majority (2): the 2-approval
    // ticket passes once K is valid again.
    pin_quorum_keys(&pks, None);
    assert_eq!(state.join_with_invite(peer, &invite).unwrap(), 1);
    drop(state);
    unpin_quorum_keys();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn quorum_rotation_rejects_old_tickets() {
    let _guard = join_test_guard();
    let (keys_a, pks_a) = quorum_test_keys(2);
    let (_, pks_b) = quorum_test_keys(2);
    pin_quorum_keys(&pks_a, Some(1));
    let (state, root) = join_test_state("quorum-rotate");
    let (peer, _) = join_test_peer("rotate-joiner");
    let invite = quorum_ticket(&keys_a, &[0], peer.signing_pk_hex.clone());
    assert_eq!(state.join_with_invite(peer.clone(), &invite).unwrap(), 1);
    // Same ticket under the rotated set: signer no longer pinned.
    pin_quorum_keys(&pks_b, Some(1));
    let (peer2, _) = join_test_peer("rotate-joiner-2");
    let stale = quorum_ticket(&keys_a, &[1], peer2.signing_pk_hex.clone());
    let err = state
        .join_with_invite(peer2, &stale)
        .expect_err("rotated signer rejected");
    assert!(err.contains("not in fleet key set"), "{err}");
    assert_eq!(state.admissions_snapshot().len(), 1);
    drop(state);
    unpin_quorum_keys();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_mode_join_logs_evidence() {
    let _guard = join_test_guard();
    unpin_quorum_keys();
    let fleet = ciphervault_crypto::generate_signing_key();
    let fleet_pk = hex::encode(fleet.verifying_key().to_bytes());
    std::env::set_var("CIPHERVAULT_FLEET_KEY", &fleet_pk);
    let (state, root) = join_test_state("legacy-evidence");
    let (peer, _) = join_test_peer("legacy-joiner");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    assert_eq!(state.join_with_invite(peer, &invite).unwrap(), 1);
    let admissions = state.admissions_snapshot();
    assert_eq!(admissions.len(), 1);
    assert_eq!(admissions[0].ticket_version, 1);
    assert_eq!(admissions[0].signer_pks, vec![fleet_pk]);
    drop(state);
    unpin_quorum_keys();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_join_admits_into_probation() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    let (state, root) = join_test_state("join");
    let (peer, _) = join_test_peer("joiner-1");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    assert_eq!(state.join_with_invite(peer.clone(), &invite).unwrap(), 1);
    assert!(state.is_probationary("joiner-1"));
    let views = state.membership_snapshot();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].operator_id, "joiner-1");
    assert_eq!(views[0].status, MembershipStatus::Probation);
    assert!(views[0].graduated_utc.is_none());
    assert!(root.join("join-invites.json").is_file());
    assert!(root.join("peer-membership.json").is_file());
    drop(state);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_join_fails_closed_without_fleet_pin() {
    let _guard = join_test_guard();
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    let (state, root) = join_test_state("joinclosed");
    let (peer, _) = join_test_peer("joiner-1");
    let fleet = ciphervault_crypto::generate_signing_key();
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    let err = state.join_with_invite(peer, &invite).unwrap_err();
    assert_eq!(err, "Verified join is not configured on this node");
    assert!(state.get_active_peers().is_empty());
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_join_rejects_forged_expired_and_mismatched() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    let (state, root) = join_test_state("joinreject");
    let (peer, _) = join_test_peer("joiner-1");
    // Wrong issuer: signed by a non-fleet key.
    let rogue = ciphervault_crypto::generate_signing_key();
    let forged = JoinInvite::issue(&rogue, peer.signing_pk_hex.clone(), 3600).unwrap();
    let err = state.join_with_invite(peer.clone(), &forged).unwrap_err();
    assert!(err.contains("issuer mismatch"), "unexpected: {err}");
    // Tampered node binding breaks the fleet signature.
    let mut tampered = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    tampered.node_pk_hex = hex::encode([9u8; 32]);
    let err = state.join_with_invite(peer.clone(), &tampered).unwrap_err();
    assert!(
        err.contains("signature verification failed"),
        "unexpected: {err}"
    );
    // Expired invite (re-signed over a past expiry so only TTL fails).
    let mut expired = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    expired.expires_utc = Utc::now().timestamp() as u64 - 1;
    let sig = sign_with_domain(&fleet, b"operator_join_invite", &expired.signing_bytes());
    expired.signature_hex = hex::encode(sig);
    let err = state.join_with_invite(peer.clone(), &expired).unwrap_err();
    assert!(err.contains("expired"), "unexpected: {err}");
    // Valid ticket, wrong presenter: descriptor key must equal the grant.
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    let (other, _) = join_test_peer("joiner-1");
    let err = state.join_with_invite(other, &invite).unwrap_err();
    assert_eq!(
        err,
        "Invite node key does not match the announced descriptor"
    );
    assert!(state.get_active_peers().is_empty());
    drop(state);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_join_ticket_is_single_use_per_admission() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    let (state, root) = join_test_state("joinonce");
    let (peer, peer_key) = join_test_peer("joiner-1");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    assert!(state.join_with_invite(peer.clone(), &invite).is_ok());
    // Same admission re-presents the spent ticket: grace rejoin, still
    // probationary, no duplicate routing entry.
    assert_eq!(state.join_with_invite(peer.clone(), &invite).unwrap(), 1);
    assert!(state.is_probationary("joiner-1"));
    // Same key under a NEW operator id is a new admission: 409 stands.
    // (Signed with the original key so only the id differs.)
    let (mut renamed, _) = join_test_peer("joiner-2");
    renamed.signing_pk_hex = peer.signing_pk_hex.clone();
    renamed.timestamp_utc = Utc::now().timestamp() as u64;
    renamed.sign(&peer_key);
    let err = state.join_with_invite(renamed, &invite).unwrap_err();
    assert_eq!(err, "Join invite was already spent");
    // Grace survives restarts: membership + spend both persist.
    drop(state);
    let reopened = legacy_state(
        "test-op".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    assert!(reopened.join_with_invite(peer, &invite).is_ok());
    assert!(reopened.is_probationary("joiner-1"));
    drop(reopened);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn grace_rejoin_after_lapse_keeps_probation_clock() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    let (state, root) = join_test_state("joinlapse");
    let (peer, peer_key) = join_test_peer("joiner-1");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 7200).unwrap();
    assert!(state.join_with_invite(peer.clone(), &invite).is_ok());
    drop(state);
    // 25 h pass with no refresh: served time, but lapsed.
    backdate_membership(&root, "joiner-1", 90_000, 90_000);
    let reopened = legacy_state(
        "test-op".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    // Simulate the 24 h routing eviction (membership survives it).
    lock_or_recover(&reopened.peer_routing_table, "peer_routing_table").remove("joiner-1");
    let mut fresh = peer.clone();
    fresh.timestamp_utc = Utc::now().timestamp() as u64;
    fresh.sign(&peer_key);
    let err = reopened.refresh_peer_join(fresh.clone()).unwrap_err();
    assert!(err.starts_with("Unknown joiner"), "unexpected: {err}");
    // Same ticket re-admits without an admin round-trip.
    assert_eq!(reopened.join_with_invite(peer.clone(), &invite).unwrap(), 1);
    // Probation clock survived the lapse: time served + fresh
    // liveness graduates immediately.
    assert_eq!(
        reopened.refresh_peer_join(fresh).unwrap(),
        MembershipStatus::Full
    );
    assert!(!reopened.is_probationary("joiner-1"));
    drop(reopened);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn join_refresh_extends_own_entry_only() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    let (state, root) = join_test_state("joinrefresh");
    let (peer, peer_key) = join_test_peer("joiner-1");
    // Unknown joiners cannot refresh their way in.
    let err = state.refresh_peer_join(peer.clone()).unwrap_err();
    assert!(err.starts_with("Unknown joiner"), "unexpected: {err}");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    assert!(state.join_with_invite(peer.clone(), &invite).is_ok());
    // Same operator id, different node key: not our entry.
    let (mut impostor, impostor_key) = join_test_peer("joiner-1");
    impostor.sign(&impostor_key);
    let err = state.refresh_peer_join(impostor).unwrap_err();
    assert!(err.starts_with("Unknown joiner"), "unexpected: {err}");
    // Control: the key holder refreshes and stays probationary (time
    // not yet served under the default 24 h probation).
    let mut fresh = peer.clone();
    fresh.timestamp_utc = Utc::now().timestamp() as u64;
    fresh.sign(&peer_key);
    assert_eq!(
        state.refresh_peer_join(fresh).unwrap(),
        MembershipStatus::Probation
    );
    assert!(state.is_probationary("joiner-1"));
    drop(state);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn probation_graduation_needs_time_and_liveness() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    std::env::set_var("CIPHERVAULT_PROBATION_SECS", "60");
    std::env::set_var("CIPHERVAULT_JOIN_LIVENESS_GRACE_SECS", "60");
    let (state, root) = join_test_state("joingraduate");
    let (peer, peer_key) = join_test_peer("joiner-1");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    assert!(state.join_with_invite(peer.clone(), &invite).is_ok());
    drop(state);
    // Time served but silent beyond the grace window: no graduation.
    backdate_membership(&root, "joiner-1", 61, 61);
    let reopened = legacy_state(
        "test-op".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    let views = reopened.membership_snapshot();
    assert_eq!(views[0].status, MembershipStatus::Probation);
    // A fresh proof of life graduates: time served, liveness now.
    let mut fresh = peer.clone();
    fresh.timestamp_utc = Utc::now().timestamp() as u64;
    fresh.sign(&peer_key);
    assert_eq!(
        reopened.refresh_peer_join(fresh).unwrap(),
        MembershipStatus::Full
    );
    assert!(!reopened.is_probationary("joiner-1"));
    let views = reopened.membership_snapshot();
    assert_eq!(views[0].status, MembershipStatus::Full);
    assert!(views[0].graduated_utc.is_some());
    drop(reopened);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    std::env::remove_var("CIPHERVAULT_PROBATION_SECS");
    std::env::remove_var("CIPHERVAULT_JOIN_LIVENESS_GRACE_SECS");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn heartbeat_liveness_graduates_served_probation() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    std::env::set_var("CIPHERVAULT_PROBATION_SECS", "60");
    let (state, root) = join_test_state("joinheartbeat");
    let (peer, _) = join_test_peer("joiner-1");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    assert!(state.join_with_invite(peer, &invite).is_ok());
    // Early heartbeat: liveness noted, still probationary.
    state.note_peer_heartbeat("joiner-1");
    assert!(state.is_probationary("joiner-1"));
    drop(state);
    backdate_membership(&root, "joiner-1", 61, 61);
    let reopened = legacy_state(
        "test-op".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    );
    reopened.note_peer_heartbeat("joiner-1");
    assert!(!reopened.is_probationary("joiner-1"));
    drop(reopened);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    std::env::remove_var("CIPHERVAULT_PROBATION_SECS");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn control_announce_promotes_probation_to_full() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    let (state, root) = join_test_state("joinpromote");
    let (peer, _) = join_test_peer("joiner-1");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    assert!(state.join_with_invite(peer.clone(), &invite).is_ok());
    assert!(state.is_probationary("joiner-1"));
    // An admin announce is an explicit trust grant: probation ends now.
    assert!(state.register_peer(peer).is_ok());
    assert!(!state.is_probationary("joiner-1"));
    let views = state.membership_snapshot();
    assert_eq!(views[0].status, MembershipStatus::Full);
    drop(state);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn graduate_peer_admin_override() {
    let _guard = join_test_guard();
    let fleet = ciphervault_crypto::generate_signing_key();
    std::env::set_var(
        "CIPHERVAULT_FLEET_KEY",
        hex::encode(fleet.verifying_key().to_bytes()),
    );
    let (state, root) = join_test_state("joingrad");
    let (peer, _) = join_test_peer("joiner-1");
    let invite = JoinInvite::issue(&fleet, peer.signing_pk_hex.clone(), 3600).unwrap();
    assert!(state.join_with_invite(peer, &invite).is_ok());
    assert!(state.graduate_peer("joiner-1").unwrap());
    assert!(!state.is_probationary("joiner-1"));
    assert!(!state.graduate_peer("unknown-node").unwrap());
    drop(state);
    std::env::remove_var("CIPHERVAULT_FLEET_KEY");
    fs::remove_dir_all(root).unwrap();
}
