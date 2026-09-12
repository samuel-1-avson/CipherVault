//! # Shamir's Secret Sharing over GF(2^8)
//!
//! Provides an M-of-N threshold scheme for splitting 32-byte cryptographic secrets
//! (such as the Master Recovery Secret R) across designated team guardians.
//!
//! Any subset of M shares can reconstruct the original secret, while any subset of
//! M - 1 or fewer shares reveals zero information about the secret.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Multiplication in GF(2^8) with Rijndael polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
#[inline(always)]
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi_bit = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(2^8) using Fermat's Little Theorem: a^-1 = a^254.
#[inline(always)]
pub fn gf_inv(a: u8) -> Result<u8, CryptoError> {
    if a == 0 {
        return Err(CryptoError::ThresholdError(
            "Division by zero in GF(2^8)".into(),
        ));
    }
    // a^254 = a^(128 + 64 + 32 + 16 + 8 + 4 + 2)
    let a2 = gf_mul(a, a);
    let a3 = gf_mul(a2, a);
    let a6 = gf_mul(a3, a3);
    let a7 = gf_mul(a6, a);
    let a14 = gf_mul(a7, a7);
    let a15 = gf_mul(a14, a);
    let a30 = gf_mul(a15, a15);
    let a31 = gf_mul(a30, a);
    let a62 = gf_mul(a31, a31);
    let a63 = gf_mul(a62, a);
    let a126 = gf_mul(a63, a63);
    let a127 = gf_mul(a126, a);
    let a254 = gf_mul(a127, a127);
    Ok(a254)
}

/// Division in GF(2^8): a / b = a * b^-1.
#[inline(always)]
pub fn gf_div(a: u8, b: u8) -> Result<u8, CryptoError> {
    if b == 0 {
        return Err(CryptoError::ThresholdError(
            "Division by zero in GF(2^8)".into(),
        ));
    }
    if a == 0 {
        Ok(0)
    } else {
        Ok(gf_mul(a, gf_inv(b)?))
    }
}

/// Evaluates polynomial f(x) = c_0 + c_1*x + ... + c_{d}*x^d in GF(2^8) using Horner's method.
pub fn gf_poly_eval(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &coeff in coefficients.iter().rev() {
        result = gf_mul(result, x) ^ coeff;
    }
    result
}

/// A single share in an M-of-N threshold secret sharing scheme.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ShamirShare {
    pub index: u8,
    pub data: [u8; 32],
}

impl std::fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShamirShare")
            .field("index", &self.index)
            .field("data", &"[REDACTED_SHARE]")
            .finish()
    }
}

impl ShamirShare {
    pub fn new(index: u8, data: [u8; 32]) -> Self {
        Self { index, data }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.data)
    }

    pub fn from_hex(index: u8, hex_str: &str) -> Result<Self, CryptoError> {
        let clean = hex_str.trim().trim_start_matches("0x");
        let bytes = hex::decode(clean)
            .map_err(|e| CryptoError::ThresholdError(format!("Invalid share hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut data = [0u8; 32];
        data.copy_from_slice(&bytes);
        Ok(Self { index, data })
    }
}

/// Splits a 32-byte secret into N shares using an M-of-N threshold scheme.
///
/// Parameters:
/// - `secret`: The 32-byte secret to protect.
/// - `threshold` (M): Minimum number of shares required to reconstruct the secret (must be >= 2).
/// - `total_shares` (N): Total number of shares to generate (must satisfy threshold <= total_shares <= 255).
pub fn split_secret(
    secret: &[u8; 32],
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<ShamirShare>, CryptoError> {
    if threshold < 2 {
        return Err(CryptoError::ThresholdError(
            "Threshold (M) must be at least 2".into(),
        ));
    }
    if total_shares < threshold {
        return Err(CryptoError::ThresholdError(format!(
            "Total shares (N={}) cannot be less than threshold (M={})",
            total_shares, threshold
        )));
    }

    let mut shares_data: Vec<[u8; 32]> = vec![[0u8; 32]; total_shares as usize];
    let mut rng = rand::thread_rng();

    // For each byte position in the 32-byte secret:
    for byte_idx in 0..32 {
        let mut poly = vec![0u8; threshold as usize];
        poly[0] = secret[byte_idx];
        for coeff in poly.iter_mut().skip(1) {
            *coeff = (rng.next_u32() & 0xFF) as u8;
        }

        // Evaluate at x = 1, 2, ..., total_shares
        for (share_idx, share_buf) in shares_data.iter_mut().enumerate() {
            let x = (share_idx + 1) as u8;
            share_buf[byte_idx] = gf_poly_eval(&poly, x);
        }

        // Zeroize ephemeral polynomial coefficients
        poly.zeroize();
    }

    let result = shares_data
        .into_iter()
        .enumerate()
        .map(|(i, data)| ShamirShare {
            index: (i + 1) as u8,
            data,
        })
        .collect();

    Ok(result)
}

/// Reconstructs the 32-byte secret from M or more distinct Shamir shares.
pub fn combine_shares(shares: &[ShamirShare]) -> Result<[u8; 32], CryptoError> {
    if shares.is_empty() {
        return Err(CryptoError::ThresholdError(
            "At least one share is required".into(),
        ));
    }

    // Check for duplicate share indices or index 0
    let mut seen = std::collections::HashSet::new();
    for share in shares {
        if share.index == 0 {
            return Err(CryptoError::ThresholdError(
                "Invalid share index: 0 is reserved for the secret".into(),
            ));
        }
        if !seen.insert(share.index) {
            return Err(CryptoError::ThresholdError(format!(
                "Duplicate share index {} provided",
                share.index
            )));
        }
    }

    let m = shares.len();
    if m < 2 {
        return Err(CryptoError::ThresholdError(
            "At least 2 shares are required to reconstruct threshold secret".into(),
        ));
    }

    // Compute Lagrange basis weights w_j = l_j(0) = \prod_{k != j} (x_k / (x_j ^ x_k))
    let mut weights = Vec::with_capacity(m);
    for (j, share) in shares.iter().enumerate() {
        let xj = share.index;
        let mut w = 1u8;
        for (k, other_share) in shares.iter().enumerate() {
            if k == j {
                continue;
            }
            let xk = other_share.index;
            let denom = xj ^ xk;
            let factor = gf_div(xk, denom)?;
            w = gf_mul(w, factor);
        }
        weights.push(w);
    }

    // Reconstruct secret: secret[byte] = \bigoplus_j (share_j[byte] * w_j)
    let mut secret = [0u8; 32];
    for (byte_idx, out_byte) in secret.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (j, share) in shares.iter().enumerate() {
            let term = gf_mul(share.data[byte_idx], weights[j]);
            acc ^= term;
        }
        *out_byte = acc;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul_and_inv() {
        assert_eq!(gf_mul(0, 5), 0);
        assert_eq!(gf_mul(5, 0), 0);
        assert_eq!(gf_mul(1, 42), 42);
        assert_eq!(gf_mul(42, 1), 42);

        // For all non-zero elements, x * x^-1 == 1
        for x in 1..=255u8 {
            let inv = gf_inv(x).unwrap();
            assert_eq!(gf_mul(x, inv), 1, "Failed inversion for {}", x);
        }

        assert!(gf_inv(0).is_err());
    }

    #[test]
    fn test_shamir_2_of_3_reconstruction() {
        let original_secret = [0x5Au8; 32];
        let shares = split_secret(&original_secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares should recover secret
        let recovered_12 = combine_shares(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered_12, original_secret);

        let recovered_13 = combine_shares(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered_13, original_secret);

        let recovered_23 = combine_shares(&[shares[1].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered_23, original_secret);
    }

    #[test]
    fn test_shamir_3_of_5_reconstruction() {
        let mut original_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut original_secret);

        let shares = split_secret(&original_secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Subsets of 3
        let subset_012 =
            combine_shares(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]).unwrap();
        assert_eq!(subset_012, original_secret);

        let subset_134 =
            combine_shares(&[shares[1].clone(), shares[3].clone(), shares[4].clone()]).unwrap();
        assert_eq!(subset_134, original_secret);

        let subset_024 =
            combine_shares(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]).unwrap();
        assert_eq!(subset_024, original_secret);

        // Duplicate shares rejected
        assert!(
            combine_shares(&[shares[0].clone(), shares[0].clone(), shares[1].clone()]).is_err()
        );

        // Under-threshold reconstruction with only 2 shares fails or produces incorrect secret
        let partial = combine_shares(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_ne!(partial, original_secret);
    }

    #[test]
    fn test_shamir_validation_bounds() {
        let secret = [0x11u8; 32];
        assert!(split_secret(&secret, 1, 3).is_err());
        assert!(split_secret(&secret, 4, 3).is_err());
    }
}
