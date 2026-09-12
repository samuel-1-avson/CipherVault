use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;

use ciphervault_crypto::{
    decrypt_chunk, encrypt_chunk, generate_signing_key, keys::VaultEpochKey, RecoverySecret,
};
use ciphervault_format::{
    to_canonical_cbor, GenesisRecord, HeadRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_operator::{
    create_router, state::MAX_OBJECT_SIZE, state::MAX_RECOVERY_RECORD_SIZE, OperatorState,
};
use ciphervault_snapshot::{
    create_snapshot, validate_safe_relative_path, SnapshotError,
};
use ciphervault_storage::MultiOperatorPool;

async fn spawn_test_operator(port: u16, data_dir: PathBuf, operator_id: &str) -> (String, tokio::task::JoinHandle<()>) {
    let state = Arc::new(OperatorState::new(
        operator_id.to_string(),
        data_dir,
        generate_signing_key(),
    ));
    let app = create_router(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await.unwrap();
    let url = format!("http://127.0.0.1:{}", port);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (url, handle)
}

fn search_bytes_for_needle(path: &Path, needle: &[u8]) -> usize {
    let mut count = 0;
    if path.is_file() {
        if let Ok(bytes) = fs::read(path) {
            if bytes.windows(needle.len()).any(|w| w == needle) {
                count += 1;
            }
        }
        return count;
    }

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                count += search_bytes_for_needle(&p, needle);
            } else if let Ok(bytes) = fs::read(&p) {
                if bytes.windows(needle.len()).any(|w| w == needle) {
                    count += 1;
                }
            }
        }
    }
    count
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_canary_leak_defense_across_operators_and_db() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_canary_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    let vault_root = test_dir.join("vault");
    fs::create_dir_all(&vault_root).unwrap();

    // 1. Seed sensitive canary credentials into vault files
    let canary_aws_secret = b"CANARY_AWS_SECRET_8492049182301923";
    let canary_db_password = b"CANARY_DB_PASS_4920194810293847";

    let env_content = format!(
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET={}\nDATABASE_URL=postgres://admin:{}@db:5432/prod\n",
        std::str::from_utf8(canary_aws_secret).unwrap(),
        std::str::from_utf8(canary_db_password).unwrap()
    );
    let env_path = vault_root.join(".env");
    fs::write(&env_path, env_content).unwrap();

    // 2. Spin up 3 storage operators
    let op1_dir = test_dir.join("op1");
    let op2_dir = test_dir.join("op2");
    let op3_dir = test_dir.join("op3");
    let (url1, _h1) = spawn_test_operator(8501, op1_dir.clone(), "op_8501").await;
    let (url2, _h2) = spawn_test_operator(8502, op2_dir.clone(), "op_8502").await;
    let (url3, _h3) = spawn_test_operator(8503, op3_dir.clone(), "op_8503").await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let op_endpoints = vec![url1, url2, url3];

    // 3. Init local store with Genesis and Keys
    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();
    let r_locator = r.derive_recovery_locator().unwrap();

    let vault_id = [0x55u8; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![0u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();

    let device_sk = generate_signing_key();
    let device_id = [0x11u8; 32];
    let epoch_key = VaultEpochKey::generate();

    let db_path = vault_root.join("vault.db");
    let store = LocalVaultStore::open(&db_path).unwrap();
    store
        .init_vault(&vault_id, &genesis, &device_sk, &device_id, &epoch_key)
        .unwrap();

    store.track_file(".env").unwrap();
    let tracked = store.list_tracked_files().unwrap();

    let snap = create_snapshot(
        &vault_root,
        &tracked,
        &vault_id,
        1,
        &epoch_key,
        vec![],
        &device_id,
        1,
        1,
        &device_sk,
    )
    .unwrap();

    store
        .save_snapshot(&snap.record, &snap.encrypted_manifest, &snap.chunks)
        .unwrap();

    let record_cid = snap.record.compute_record_cid().unwrap();
    let closure_digest = snap.closure.compute_base_closure_digest().unwrap();
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        snapshot_id: record_cid.to_vec(),
        parent_snapshot_ids: Vec::new(),
        closure_digest: closure_digest.to_vec(),
        device_id: device_id.to_vec(),
        device_counter: 1,
        signature: Vec::new(),
    };
    head.sign(&device_sk).unwrap();
    store.set_head(&head).unwrap();

    // 4. Replicate encrypted chunks and manifest to all 3 operators with readback
    let pool = MultiOperatorPool::new(op_endpoints.clone());
    let mut wire_objects = Vec::new();
    for chunk in &snap.chunks {
        let cid = chunk.compute_cid().unwrap();
        let cbor = to_canonical_cbor(chunk).unwrap();
        wire_objects.push((cid, cbor));
    }
    wire_objects.push((snap.manifest_cid, snap.encrypted_manifest.clone()));
    wire_objects.push((record_cid, to_canonical_cbor(&snap.record).unwrap()));

    let head_cbor = to_canonical_cbor(&head).unwrap();
    let receipts = pool
        .replicate_and_verify(
            &vault_id,
            &device_sk,
            &wire_objects,
            &closure_digest,
            snap.closure.total_bytes,
            90,
            &r_locator,
            &head_cbor,
            3,
        )
        .await
        .unwrap();

    assert_eq!(receipts.len(), 3);

    // 5. ADVERSARIAL INSPECTION:
    // Ensure raw canary secrets NEVER appear anywhere on operator disk storage or in SQLite!
    let op1_leaks = search_bytes_for_needle(&op1_dir, canary_aws_secret)
        + search_bytes_for_needle(&op1_dir, canary_db_password);
    let op2_leaks = search_bytes_for_needle(&op2_dir, canary_aws_secret)
        + search_bytes_for_needle(&op2_dir, canary_db_password);
    let op3_leaks = search_bytes_for_needle(&op3_dir, canary_aws_secret)
        + search_bytes_for_needle(&op3_dir, canary_db_password);
    let db_leaks = search_bytes_for_needle(&db_path, canary_aws_secret)
        + search_bytes_for_needle(&db_path, canary_db_password);

    assert_eq!(op1_leaks, 0, "Operator 1 leaked canary plaintext on disk!");
    assert_eq!(op2_leaks, 0, "Operator 2 leaked canary plaintext on disk!");
    assert_eq!(op3_leaks, 0, "Operator 3 leaked canary plaintext on disk!");
    assert_eq!(db_leaks, 0, "Local SQLite store leaked canary plaintext in database!");
}

#[test]
fn test_path_sanitization_adversarial_rejections() {
    let attacks = [
        "../../etc/passwd",
        "../secret.key",
        "..\\..\\Windows\\System32\\cmd.exe",
        "/root/evil.sh",
        "\\Windows\\evil.exe",
        "C:\\Program Files\\evil.dll",
        "CON",
        "con.txt",
        "PRN",
        "prn.dat",
        "AUX",
        "aux.cfg",
        "NUL",
        "nul.json",
        "COM1",
        "com2.txt",
        "com9",
        "LPT1",
        "lpt5.log",
        "nested/subfolder/CON",
        "nested/subfolder/aux.key",
        "secret.env:stream_name",
        "target.txt::$DATA",
        "bad_char\0null_byte",
        "ends_with_dot.",
        "ends_with_space ",
        "has<bracket",
        "has>bracket",
        "has|pipe",
        "has?question",
        "has*asterisk",
        "has\"quote",
    ];

    for attack in &attacks {
        let result = validate_safe_relative_path(attack);
        assert!(
            result.is_err(),
            "Path validation should have REJECTED malicious path: '{}'",
            attack
        );
        match result.unwrap_err() {
            SnapshotError::UnsafePath(_) => {}
            other => panic!("Expected UnsafePath error for '{}', got: {:?}", attack, other),
        }
    }

    let legitimate_paths = [
        ".env",
        ".env.production",
        "secrets/app.key",
        "certs/ca.pem",
        "config/settings.json",
        "deeply/nested/path/to/data_2026-09.csv",
    ];

    for path in &legitimate_paths {
        assert!(
            validate_safe_relative_path(path).is_ok(),
            "Path validation should have ACCEPTED legitimate path: '{}'",
            path
        );
    }
}

#[test]
fn test_cryptographic_tamper_matrix() {
    let key = [0x42u8; 32];
    let aad = b"test_aad_context";
    let plaintext = b"cryptographic_integrity_verification_payload";

    let mut ciphertext = encrypt_chunk(&key, plaintext, aad).unwrap();
    assert_eq!(decrypt_chunk(&key, &ciphertext, aad).unwrap(), plaintext);

    // 1. Wrong key rejection
    let wrong_key = [0x43u8; 32];
    assert!(decrypt_chunk(&wrong_key, &ciphertext, aad).is_err());

    // 2. Altered AAD rejection
    let altered_aad = b"wrong_aad_context";
    assert!(decrypt_chunk(&key, &ciphertext, altered_aad).is_err());

    // 3. Truncated Poly1305 MAC tag (15 bytes instead of 16)
    let truncated = &ciphertext[0..ciphertext.len() - 1];
    assert!(decrypt_chunk(&key, truncated, aad).is_err());

    // 4. Bit flip in payload
    let last_idx = ciphertext.len() - 5;
    ciphertext[last_idx] ^= 0x01;
    assert!(decrypt_chunk(&key, &ciphertext, aad).is_err());
}

#[test]
fn test_operator_boundary_and_dos_limits() {
    let test_dir = std::env::temp_dir().join(format!(
        "cv_op_limit_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    let state = OperatorState::new("op_test".to_string(), test_dir, generate_signing_key());

    let valid_cid = "a".repeat(64);

    // 1. Enforce MAX_OBJECT_SIZE (4 MiB)
    let oversized_payload = vec![0x99u8; MAX_OBJECT_SIZE + 1];
    let err = state.put_object(&valid_cid, &oversized_payload).unwrap_err();
    assert!(err.contains("exceeds maximum size limit"), "Got error: {}", err);

    // 2. Enforce CID length (must be 64 hex characters)
    let short_cid = "abcd";
    let payload = b"small_chunk";
    let err2 = state.put_object(short_cid, payload).unwrap_err();
    assert!(err2.contains("Invalid CID length"), "Got error: {}", err2);

    // 3. Enforce MAX_RECOVERY_RECORD_SIZE (64 KiB)
    let oversized_rec = vec![0x88u8; MAX_RECOVERY_RECORD_SIZE + 1];
    let err3 = state.append_recovery_record(&valid_cid, &oversized_rec).unwrap_err();
    assert!(err3.contains("exceeds maximum size limit"), "Got error: {}", err3);

    // 4. Enforce recovery locator format
    let bad_locator = "not_valid_hex_string";
    let err4 = state.append_recovery_record(bad_locator, b"normal_rec").unwrap_err();
    assert!(err4.contains("Invalid recovery locator"), "Got error: {}", err4);
}
