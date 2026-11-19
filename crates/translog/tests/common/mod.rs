//! Helpers shared by the integration tests.
//!
//! Randomized tests use a seeded RNG so that every failure is
//! reproducible. Set `TRANSLOG_TEST_SEED` to explore other seeds and
//! `TRANSLOG_TEST_SCALE` (default 1) to multiply iteration counts for a
//! longer fuzzing run.
#![allow(dead_code)]

use ciphervault_translog::{empty_root, leaf_hash, node_hash, Hash};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const DEFAULT_SEED: u64 = 0x5eed_c1f3_2026_1119;

/// The base seed, from `TRANSLOG_TEST_SEED` (decimal) or the default.
pub fn base_seed() -> u64 {
    std::env::var("TRANSLOG_TEST_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED)
}

/// A reproducible RNG for one test, and the seed to report on failure.
pub fn rng(test_salt: u64) -> (StdRng, u64) {
    let seed = base_seed() ^ test_salt;
    (StdRng::seed_from_u64(seed), seed)
}

/// `default` iterations, times `TRANSLOG_TEST_SCALE`.
pub fn iterations(default: usize) -> usize {
    let scale = std::env::var("TRANSLOG_TEST_SCALE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    default * scale
}

/// `n` leaf hashes of random entries.
pub fn random_leaves(rng: &mut StdRng, n: usize) -> Vec<Hash> {
    (0..n).map(|_| leaf_hash(&rng.gen::<[u8; 24]>())).collect()
}

/// `MTH(D_n)` straight from the recursive definition of RFC 9162 §2.1.1,
/// as an oracle independent of the crate's stack algorithm.
pub fn reference_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_below(n);
            node_hash(&reference_root(&leaves[..k]), &reference_root(&leaves[k..]))
        }
    }
}

/// The largest power of two strictly below `n`, for `n >= 2`.
pub fn largest_power_of_two_below(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// `hash` with bit `bit` (0 to 255) flipped.
pub fn flip_bit(hash: &Hash, bit: usize) -> Hash {
    let mut out = *hash;
    out[bit / 8] ^= 1 << (bit % 8);
    out
}

/// Decodes hex test data.
pub fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test vector is valid hex")
}

/// Decodes a 32-byte hex hash.
pub fn unhex32(s: &str) -> Hash {
    unhex(s).try_into().expect("test vector is 32 bytes")
}
