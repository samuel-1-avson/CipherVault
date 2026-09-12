use ciphervault_crypto::{decrypt_chunk, VaultEpochKey};
use ciphervault_format::compute_digest;
use ciphervault_snapshot::{chunk_and_encrypt_file, CHUNK_SIZE};
use std::time::Instant;

#[test]
fn test_multi_chunk_encryption_and_decryption_throughput() {
    let vault_id = [0x77u8; 32];
    let epoch = 1;
    let epoch_key = VaultEpochKey::generate();

    // 10 MiB payload = 10 full 1 MiB chunks
    let size_10mb = 10 * 1024 * 1024;
    let mut payload_10mb = vec![0u8; size_10mb];
    // Fill with deterministic pseudo-random bytes
    for (i, b) in payload_10mb.iter_mut().enumerate() {
        *b = ((i * 37 + 19) % 256) as u8;
    }
    let expected_sha256 = compute_digest(&payload_10mb);

    println!("\n=== CIPHERVAULT MULTI-CHUNK ENCRYPTION BENCHMARK ===");
    println!(
        "Payload Size: {:.2} MiB",
        size_10mb as f64 / (1024.0 * 1024.0)
    );
    println!(
        "Chunk Size:   {:.2} MiB",
        CHUNK_SIZE as f64 / (1024.0 * 1024.0)
    );

    // Measure Encryption Throughput
    let start_enc = Instant::now();
    let chunked = chunk_and_encrypt_file(&vault_id, epoch, &epoch_key, &payload_10mb).unwrap();
    let elapsed_enc = start_enc.elapsed();

    let enc_secs = elapsed_enc.as_secs_f64();
    let enc_mibs = (size_10mb as f64 / (1024.0 * 1024.0)) / enc_secs;

    println!("Chunks Produced:    {}", chunked.chunks.len());
    println!(
        "Encryption Time:    {:.3} ms",
        elapsed_enc.as_secs_f64() * 1000.0
    );
    println!("Encryption Speed:   {:.2} MiB/s", enc_mibs);

    assert!(
        chunked.chunks.len() > 10,
        "Expected multiple FastCDC dynamic chunks, got {}",
        chunked.chunks.len()
    );
    assert_eq!(
        chunked.plaintext_sha256.as_slice(),
        expected_sha256.as_slice()
    );

    // Measure Decryption & Reassembly Throughput
    let start_dec = Instant::now();
    let mut restored = Vec::with_capacity(chunked.padded_length as usize);
    for chunk in &chunked.chunks {
        let aad = chunk.compute_aad();
        let decrypted_padded =
            decrypt_chunk(chunked.file_version_key.as_bytes(), &chunk.payload, &aad).unwrap();
        restored.extend_from_slice(&decrypted_padded);
    }
    let restored_plaintext = &restored[0..chunked.raw_length as usize];
    let restored_sha256 = compute_digest(restored_plaintext);
    let elapsed_dec = start_dec.elapsed();

    let dec_secs = elapsed_dec.as_secs_f64();
    let dec_mibs = (size_10mb as f64 / (1024.0 * 1024.0)) / dec_secs;

    println!(
        "Decryption Time:    {:.3} ms",
        elapsed_dec.as_secs_f64() * 1000.0
    );
    println!("Decryption Speed:   {:.2} MiB/s", dec_mibs);
    println!("Plaintext Match:    100% byte-for-byte fidelity\n");

    assert_eq!(restored_sha256.as_slice(), expected_sha256.as_slice());
    assert_eq!(restored_plaintext, payload_10mb.as_slice());

    // Sanity check: verify throughput is recorded and non-zero
    assert!(
        enc_mibs > 1.0,
        "Encryption speed too low: {:.2} MiB/s",
        enc_mibs
    );
    assert!(
        dec_mibs > 1.0,
        "Decryption speed too low: {:.2} MiB/s",
        dec_mibs
    );
}

#[test]
fn test_fastcdc_content_defined_deduplication() {
    let vault_id = [0x88u8; 32];
    let epoch = 1;
    let epoch_key = VaultEpochKey::generate();

    // Create a ~1 MiB simulated .env / config file
    let mut env_v1 = Vec::new();
    for i in 0..20_000 {
        env_v1.extend_from_slice(
            format!(
                "ENV_VAR_SETTING_{:05}=SECRET_VALUE_CONFIG_TOKEN_{:05}\n",
                i, i
            )
            .as_bytes(),
        );
    }

    let chunked_v1 = chunk_and_encrypt_file(&vault_id, epoch, &epoch_key, &env_v1).unwrap();
    assert!(chunked_v1.chunks.len() >= 10);

    // Insert a new variable into the middle of the config
    let mut env_v2 = env_v1.clone();
    let insertion_offset = env_v1.len() / 2;
    let insertion = b"INSERTED_MIDDLE_FEATURE_TOKEN=NEW_PRODUCTION_SECRET_KEY_999\n";
    env_v2.splice(
        insertion_offset..insertion_offset,
        insertion.iter().copied(),
    );

    let chunked_v2 = chunk_and_encrypt_file(&vault_id, epoch, &epoch_key, &env_v2).unwrap();

    // Verify plaintext content-defined boundaries:
    // When using FastCDC, the byte slices of unmodified regions align identically
    let v1_slices: Vec<Vec<u8>> = chunked_v1
        .chunks
        .iter()
        .map(|c| {
            let aad = c.compute_aad();
            decrypt_chunk(chunked_v1.file_version_key.as_bytes(), &c.payload, &aad).unwrap()
        })
        .collect();

    let v2_slices: Vec<Vec<u8>> = chunked_v2
        .chunks
        .iter()
        .map(|c| {
            let aad = c.compute_aad();
            decrypt_chunk(chunked_v2.file_version_key.as_bytes(), &c.payload, &aad).unwrap()
        })
        .collect();

    let mut identical_slices = 0;
    for slice2 in &v2_slices {
        if v1_slices.iter().any(|slice1| slice1 == slice2) {
            identical_slices += 1;
        }
    }

    let dedup_ratio = identical_slices as f64 / v1_slices.len() as f64;
    println!("\n=== FASTCDC CONTENT-DEFINED CHUNKING DEDUPLICATION ===");
    println!("Base File Chunks:        {}", v1_slices.len());
    println!("Modified File Chunks:    {}", v2_slices.len());
    println!("Identical Slices Reused: {}", identical_slices);
    println!("Deduplication Ratio:     {:.2}%\n", dedup_ratio * 100.0);

    assert!(
        dedup_ratio >= 0.80,
        "FastCDC expected >= 80% chunk preservation across middle insertion, got {:.2}%",
        dedup_ratio * 100.0
    );
}

#[tokio::test]
async fn test_proof_of_storage_readback_bandwidth_reduction() {
    use ciphervault_crypto::generate_signing_key;
    use ciphervault_operator::{create_router, OperatorState};
    use ciphervault_storage::OperatorClient;
    use std::sync::Arc;

    let op_sk = generate_signing_key();
    let op_pk: [u8; 32] = op_sk.verifying_key().to_bytes();
    let temp_dir = std::env::temp_dir().join(format!("cv-pos-bench-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "bench_op".into(),
        temp_dir.clone(),
        op_sk,
    ));
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = OperatorClient::new(endpoint);
    let dev_sk = generate_signing_key();
    let vault_id = [0x42u8; 32];
    let token = client.authenticate(&vault_id, &dev_sk).await.unwrap();

    // 1 MiB chunk of simulated ciphertext
    let chunk_size = 1024 * 1024;
    let mut chunk_bytes = vec![0u8; chunk_size];
    for (i, b) in chunk_bytes.iter_mut().enumerate() {
        *b = ((i * 31 + 7) % 256) as u8;
    }
    let cid = ciphervault_format::compute_digest(&chunk_bytes);

    // Put object
    client
        .put_object(&token, &cid, chunk_bytes.clone())
        .await
        .unwrap();

    // 1. Full Object Download (Naive Readback)
    let start_download = Instant::now();
    let downloaded = client.get_object(&token, &cid).await.unwrap();
    let download_elapsed = start_download.elapsed();
    assert_eq!(downloaded.len(), chunk_size);
    let naive_bytes_transferred = downloaded.len();

    // 2. Proof-of-Storage Challenge (Bandwidth-Optimized Readback)
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let expected_proof = ciphervault_storage::compute_pos_proof(&cid, &nonce, &chunk_bytes);

    let start_pos = Instant::now();
    let receipt = client
        .challenge_object_pos(&token, &cid, &nonce)
        .await
        .unwrap();
    let pos_elapsed = start_pos.elapsed();

    // Receipt cryptographic verification
    receipt
        .verify(&op_pk, &expected_proof)
        .expect("Valid PoS receipt should verify");

    // Serialize receipt to measure wire size
    let receipt_json = serde_json::to_string(&receipt).unwrap();
    let pos_bytes_transferred = 32 + receipt_json.len(); // nonce sent + receipt json received

    let bandwidth_savings =
        (1.0 - (pos_bytes_transferred as f64 / naive_bytes_transferred as f64)) * 100.0;

    println!("\n=== PROOF-OF-STORAGE (PoS) READBACK BENCHMARK ===");
    println!(
        "Chunk Size:                  {:.2} MiB ({} bytes)",
        chunk_size as f64 / (1024.0 * 1024.0),
        chunk_size
    );
    println!(
        "Naive Readback Bytes:        {} bytes",
        naive_bytes_transferred
    );
    println!(
        "PoS Readback Wire Bytes:     {} bytes (Nonce: 32B, Receipt: {}B)",
        pos_bytes_transferred,
        receipt_json.len()
    );
    println!("Bandwidth Reduction:         {:.4}%", bandwidth_savings);
    println!(
        "Naive Download Time:         {:.3} ms",
        download_elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "PoS Verification Time:       {:.3} ms",
        pos_elapsed.as_secs_f64() * 1000.0
    );

    // Assertions
    assert!(
        bandwidth_savings > 99.95,
        "Bandwidth savings must be > 99.95%, got {:.4}%",
        bandwidth_savings
    );
    assert!(
        pos_bytes_transferred < 500,
        "PoS wire overhead must be under 500 bytes, got {}",
        pos_bytes_transferred
    );

    // Negative tests: Tampered data or nonce must fail verification
    let bad_proof = [0x55u8; 32];
    assert!(
        receipt.verify(&op_pk, &bad_proof).is_err(),
        "Tampered proof must fail"
    );

    let bad_pk = [0x99u8; 32];
    assert!(
        receipt.verify(&bad_pk, &expected_proof).is_err(),
        "Invalid operator key must fail"
    );

    server_task.abort();
    let _ = std::fs::remove_dir_all(temp_dir);
}
