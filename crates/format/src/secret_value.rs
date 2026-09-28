//! Redacted in-memory secret value.
//!
//! Phase 1 (T-102) of the scoped-secret implementation plan
//! (`report/SCOPED_SECRETS_IMPLEMENTATION_TASKS.md`). Holds plaintext only in
//! RAM: zeroized on drop, `Debug` redacted, and — by design — no `Display`,
//! `Serialize`, or `to_string` surface, so values cannot leak via logs, error
//! envelopes, or wire formats. Audit and search use [`SecretValue::sha256`].

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Variable-length secret plaintext resident in RAM only.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Wraps owned bytes (no copy).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Wraps an owned string without copying (moves the buffer).
    pub fn from_string(value: String) -> Self {
        Self(value.into_bytes())
    }

    /// Controlled read access to the plaintext bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Controlled read access as UTF-8 (fails for binary secrets).
    pub fn expose_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    /// Plaintext length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// SHA-256 digest of the plaintext for audit payloads, dedup checks, and
    /// migration readback verification. The digest is safe to log and store.
    pub fn sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.0);
        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        digest
    }

    /// Constant-time equality (safe to compare candidate secrets).
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl From<Vec<u8>> for SecretValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self::from_string(value)
    }
}

impl From<&[u8]> for SecretValue {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<&str> for SecretValue {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.constant_time_eq(other)
    }
}

impl Eq for SecretValue {}

/// Redacted: prints a fixed marker that reveals nothing about the value —
/// not even its length.
impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_is_redacted() {
        let value = SecretValue::from("super-secret-canary-12345");
        let rendered = format!("{value:?}");
        assert_eq!(rendered, "SecretValue([REDACTED])");
        assert!(!rendered.contains("canary"));
    }

    #[test]
    fn test_expose_and_len() {
        let value = SecretValue::from_bytes(vec![1, 2, 3]);
        assert_eq!(value.expose(), &[1, 2, 3]);
        assert_eq!(value.len(), 3);
        assert!(!value.is_empty());
        assert!(SecretValue::from_bytes(Vec::new()).is_empty());
        assert_eq!(SecretValue::from("abc").expose_str().unwrap(), "abc");
        assert!(SecretValue::from_bytes(vec![0xff, 0xfe])
            .expose_str()
            .is_err());
    }

    #[test]
    fn test_sha256_vector() {
        // SHA-256("abc") — FIPS 180-4 vector.
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(SecretValue::from("abc").sha256(), expected);
    }

    #[test]
    fn test_constant_time_eq() {
        let first = SecretValue::from("same-value");
        let second = SecretValue::from("same-value");
        let other = SecretValue::from("other-value!");
        assert!(first.constant_time_eq(&second));
        assert_eq!(first, second);
        assert!(!first.constant_time_eq(&other));
        assert_ne!(first, other);
        assert!(!first.constant_time_eq(&SecretValue::from("short")));
    }

    #[test]
    fn test_explicit_zeroize_scrubs() {
        let mut value = SecretValue::from("scrub-me");
        value.zeroize();
        assert!(value.expose().iter().all(|byte| *byte == 0));
    }
}
