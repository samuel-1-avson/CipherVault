// D7 erasure-coding spike harness: measures Reed-Solomon (reed-solomon-simd)
// encode/decode throughput, byte overhead, and reconstruction correctness
// for candidate (k, m) params at CipherVault blob sizes. Deliberately
// dependency-light (no clap); args are parsed by hand like the D6 harness.
use std::time::Instant;

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  d7-erasure encode --data K --parity M --blob-bytes N --iters I");
    eprintln!("  d7-erasure recover --data K --parity M --blob-bytes N --drop D [--seed S]");
    eprintln!("  d7-erasure sweep");
    std::process::exit(2);
}

fn flag(args: &[String], name: &str) -> usize {
    args.windows(2)
        .find(|w| w[0] == name)
        .and_then(|w| w[1].parse().ok())
        .unwrap_or_else(|| {
            eprintln!("missing/invalid {name}");
            usage()
        })
}

fn flag_or(args: &[String], name: &str, default: usize) -> usize {
    args.windows(2)
        .find(|w| w[0] == name)
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(default)
}

fn fill_deterministic(buf: &mut [u8], seed: u64) {
    // Splitmix64 stream: verifiable without storing expectations.
    let mut s = seed;
    for chunk in buf.chunks_mut(8) {
        s = s.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        let n = chunk.len().min(8);
        chunk[..n].copy_from_slice(&bytes[..n]);
    }
}

/// Splits `blob_bytes` of deterministic data into `k` equal shards
/// (last-padded), returning the shards plus the unpadded original.
fn make_shards(k: usize, blob_bytes: usize, seed: u64) -> (Vec<Vec<u8>>, Vec<u8>, usize) {
    let shard = blob_bytes.div_ceil(k);
    let mut original = vec![0u8; shard * k];
    fill_deterministic(&mut original, seed);
    original.truncate(blob_bytes);
    let mut shards = Vec::with_capacity(k);
    for i in 0..k {
        let mut s = vec![0u8; shard];
        let end = ((i + 1) * shard).min(blob_bytes);
        s[..end - i * shard].copy_from_slice(&original[i * shard..end]);
        shards.push(s);
    }
    (shards, original, shard)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "encode" => {
            let k = flag(&args, "--data");
            let m = flag(&args, "--parity");
            let blob = flag(&args, "--blob-bytes");
            let iters = flag(&args, "--iters");
            run_encode(k, m, blob, iters);
        }
        "recover" => {
            let k = flag(&args, "--data");
            let m = flag(&args, "--parity");
            let blob = flag(&args, "--blob-bytes");
            let drop = flag(&args, "--drop");
            let seed = flag_or(&args, "--seed", 42) as u64;
            run_recover(k, m, blob, drop, seed);
        }
        "sweep" => {
            for (k, m) in [(2, 1), (3, 1), (4, 2), (8, 4), (10, 4)] {
                for blob in [4096usize, 65536, 1_048_576] {
                    let iters = if blob >= 1_048_576 { 20 } else { 200 };
                    run_encode(k, m, blob, iters);
                }
            }
            for (k, m) in [(2, 1), (4, 2), (10, 4)] {
                run_recover(k, m, 65536, m, 7);
            }
        }
        _ => usage(),
    }
}

fn run_encode(k: usize, m: usize, blob_bytes: usize, iters: usize) {
    let (shards, _, shard) = make_shards(k, blob_bytes, 0xD7);
    // Warmup, then timed loop (end-to-end incl. parity allocation).
    let _ = reed_solomon_simd::encode(k, m, &shards).expect("encode");
    let start = Instant::now();
    for _ in 0..iters {
        let _ = reed_solomon_simd::encode(k, m, &shards).expect("encode");
    }
    let elapsed = start.elapsed().as_secs_f64();
    let wire_bytes = shard * (k + m);
    let mb_s = (blob_bytes as f64 * iters as f64) / elapsed / 1e6;
    println!(
        "RESULT encode k={k} m={m} blob={blob_bytes} shard={shard} wire={wire_bytes} overhead_x={:.3} iters={iters} secs={elapsed:.3} encode_MB_s={mb_s:.1}",
        wire_bytes as f64 / blob_bytes as f64,
    );
}

fn run_recover(k: usize, m: usize, blob_bytes: usize, drop: usize, seed: u64) {
    assert!(drop <= m, "cannot drop more than m shards");
    assert!(drop >= 1, "drop at least one shard");
    let (shards, original, shard) = make_shards(k, blob_bytes, seed);
    let parity = reed_solomon_simd::encode(k, m, &shards).expect("encode");
    // Drop the FIRST `drop` shards (adversarial: data shards first).
    let mut present_original: Vec<(usize, &[u8])> = Vec::new();
    for (i, s) in shards.iter().enumerate().skip(drop) {
        present_original.push((i, s.as_slice()));
    }
    let present_parity: Vec<(usize, &[u8])> = parity
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.as_slice()))
        .collect();
    let start = Instant::now();
    let restored =
        reed_solomon_simd::decode(k, m, present_original, present_parity).expect("decode");
    let elapsed = start.elapsed().as_secs_f64();
    // Reassemble data shards in index order and compare.
    let mut rebuilt = Vec::with_capacity(shard * k);
    for i in 0..k {
        if let Some(s) = restored.get(&i) {
            rebuilt.extend_from_slice(s);
        } else {
            rebuilt.extend_from_slice(&shards[i]);
        }
    }
    rebuilt.truncate(blob_bytes);
    assert_eq!(rebuilt, original, "reconstruction mismatch");
    // Single-fragment repair cost: rebuilding 1 lost fragment reads k.
    let repair_read_bytes = shard * k;
    println!(
        "RESULT recover k={k} m={m} blob={blob_bytes} dropped={drop} ok=true secs={elapsed:.4} repair_read_bytes={repair_read_bytes} repair_amplification_x={:.2}",
        repair_read_bytes as f64 / shard as f64,
    );
}
