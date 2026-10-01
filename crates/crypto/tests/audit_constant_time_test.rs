use ciphervault_crypto::shamir::{gf_div, gf_inv, gf_mul};

/// Reference independent GF(2^8) multiplication for Known Answer Test (KAT) verification.
fn reference_gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u16;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= (a as u16) & 0xFF;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    (p & 0xFF) as u8
}

#[test]
fn test_constant_time_gf_mul_matches_reference_kat_exhaustive() {
    // Exhaustive test across all 256 * 256 = 65,536 pairs
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            let actual = gf_mul(a, b);
            let expected = reference_gf_mul(a, b);
            assert_eq!(
                actual, expected,
                "KAT mismatch for gf_mul({}, {}): actual={}, expected={}",
                a, b, actual, expected
            );
        }
    }
}

#[test]
fn test_gf_algebraic_field_axioms_exhaustive() {
    // 1. Multiplicative identity: a * 1 = a, a * 0 = 0
    for a in 0..=255u8 {
        assert_eq!(gf_mul(a, 1), a, "Identity failed for a={}", a);
        assert_eq!(gf_mul(a, 0), 0, "Zero multiplication failed for a={}", a);
        assert_eq!(gf_mul(1, a), a, "Left identity failed for a={}", a);
        assert_eq!(
            gf_mul(0, a),
            0,
            "Left zero multiplication failed for a={}",
            a
        );
    }

    // 2. Multiplicative inverse & division consistency for all non-zero elements
    for a in 1..=255u8 {
        let inv = gf_inv(a).expect("gf_inv should succeed for non-zero element");
        let prod = gf_mul(a, inv);
        assert_eq!(
            prod, 1,
            "Inverse axiom failed: {} * {}^-1 ({}) = {} != 1",
            a, a, inv, prod
        );

        for b in 1..=255u8 {
            let quot = gf_div(a, b).expect("gf_div should succeed for non-zero denominator");
            let reconstructed = gf_mul(quot, b);
            assert_eq!(
                reconstructed, a,
                "Division consistency failed: ({} / {}) * {} = {} != {}",
                a, b, b, reconstructed, a
            );
        }
    }
}

#[test]
fn test_gf_distributivity_and_commutativity() {
    // Test commutativity for all pairs
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            assert_eq!(
                gf_mul(a, b),
                gf_mul(b, a),
                "Commutativity failed for ({}, {})",
                a,
                b
            );
        }
    }

    // Test distributivity over addition (XOR): a * (b ^ c) == (a * b) ^ (a * c)
    // Sample a deterministic grid of 100,000 triplets
    let mut count = 0;
    for a in (0..=255u8).step_by(5) {
        for b in (0..=255u8).step_by(3) {
            for c in (0..=255u8).step_by(2) {
                let left = gf_mul(a, b ^ c);
                let right = gf_mul(a, b) ^ gf_mul(a, c);
                assert_eq!(
                    left, right,
                    "Distributivity failed for a={}, b={}, c={}",
                    a, b, c
                );
                count += 1;
            }
        }
    }
    assert!(count >= 20_000, "Tested {} distributivity cases", count);
}

#[test]
fn test_constant_time_execution_profile() {
    // Coarse timing regression, not proof of constant-time execution: hosted OS
    // scheduling and CPU frequency affect wall time. Keep the original ratio
    // gate while comparing balanced samples of all three pathological inputs.
    const ITERATIONS: usize = 200_000;
    const SAMPLES: usize = 9;
    const PATTERNS: [u8; 3] = [0x00, 0xFF, 0xAA];

    fn timed_batch(multiplier: u8) -> std::time::Duration {
        let start = std::time::Instant::now();
        let mut accumulator = 0u8;
        for i in 0..ITERATIONS {
            // Opaque operands prevent constant folding of zero multiplication;
            // consuming each accumulator keeps every multiplication observable.
            accumulator = std::hint::black_box(
                accumulator
                    ^ gf_mul(
                        std::hint::black_box((i & 0xFF) as u8),
                        std::hint::black_box(multiplier),
                    ),
            );
        }
        std::hint::black_box(accumulator);
        start.elapsed()
    }

    for pattern in PATTERNS {
        timed_batch(pattern);
    }

    let mut samples = [[0u128; PATTERNS.len()]; SAMPLES];
    for (round, timings) in samples.iter_mut().enumerate() {
        // Each pattern occupies first, middle and last position equally often.
        for offset in 0..PATTERNS.len() {
            let index = (round + offset) % PATTERNS.len();
            timings[index] = timed_batch(PATTERNS[index]).as_nanos();
        }
    }
    let medians: [u128; PATTERNS.len()] = std::array::from_fn(|index| {
        let mut timings = samples.map(|round| round[index]);
        timings.sort_unstable();
        timings[SAMPLES / 2]
    });
    for left in 0..PATTERNS.len() {
        for right in left + 1..PATTERNS.len() {
            let ratio = medians[left] as f64 / (medians[right] as f64).max(1.0);
            assert!(
                ratio > 0.4 && ratio < 2.5,
                "Coarse timing ratio abnormal for {:#04x}/{:#04x}: {ratio}; median ns: {medians:?}",
                PATTERNS[left],
                PATTERNS[right],
            );
        }
    }
}
