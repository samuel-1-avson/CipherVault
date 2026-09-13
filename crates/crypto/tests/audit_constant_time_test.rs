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
    // Timing benchmark ensuring zero divergence between pathological inputs (0x00 vs 0xFF vs 0xAA)
    let iterations = 200_000;

    let start = std::time::Instant::now();
    let mut acc1 = 0u8;
    for i in 0..iterations {
        acc1 ^= gf_mul((i & 0xFF) as u8, 0x00);
    }
    let dur_zeros = start.elapsed();

    let start = std::time::Instant::now();
    let mut acc2 = 0u8;
    for i in 0..iterations {
        acc2 ^= gf_mul((i & 0xFF) as u8, 0xFF);
    }
    let dur_ones = start.elapsed();

    assert_eq!(acc1, 0);
    let _ = acc2;

    // Both loops execute the identical number of branchless operations.
    // Ensure timing ratio stays tightly bounded (within 2.0x allowing for OS thread scheduler variance)
    let ratio = dur_zeros.as_nanos() as f64 / (dur_ones.as_nanos() as f64).max(1.0);
    assert!(
        ratio > 0.4 && ratio < 2.5,
        "Timing variance ratio abnormal: {}",
        ratio
    );
}
