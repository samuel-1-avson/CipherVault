use ciphervault_crypto::decrypt_chunk;
use ciphervault_format::compute_digest;
use ciphervault_snapshot::{chunk_and_encrypt_file, CHUNK_SIZE};
use std::time::Instant;

#[test]
fn test_multi_chunk_encryption_and_decryption_throughput() {
    let vault_id = [0x77u8; 32];
    let epoch = 1;

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
        "Payload Size: {:.2} MiB ({} bytes)",
        size_10mb as f64 / (1024.0 * 1024.0),
        size_10mb
    );
    println!(
        "Chunk Size:   {:.2} MiB",
        CHUNK_SIZE as f64 / (1024.0 * 1024.0)
    );

    // Measure Encryption Throughput
    let start_enc = Instant::now();
    let chunked = chunk_and_encrypt_file(&vault_id, epoch, &payload_10mb).unwrap();
    let elapsed_enc = start_enc.elapsed();

    let enc_secs = elapsed_enc.as_secs_f64();
    let enc_mibs = (size_10mb as f64 / (1024.0 * 1024.0)) / enc_secs;

    println!("Chunks Produced:    {}", chunked.chunks.len());
    println!(
        "Encryption Time:    {:.3} ms",
        elapsed_enc.as_secs_f64() * 1000.0
    );
    println!("Encryption Speed:   {:.2} MiB/s", enc_mibs);

    assert_eq!(chunked.chunks.len(), 10);
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
