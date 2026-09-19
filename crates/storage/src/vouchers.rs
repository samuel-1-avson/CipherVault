//! Capability vouchers (DON Phase 3, D4): signed quota grants for writes.
//!
//! Under barter economics (D3, Option A) each operator self-issues vouchers
//! against its own disk quota: no voucher, no bytes persisted. A voucher
//! binds a holder key to a byte quota and an expiry; the [`VoucherLedger`]
//! tracks spend per voucher nonce so a quota cannot be overspent or have
//! its terms swapped mid-life. Verification is fail-closed and transport
//! agnostic — HTTP and P2P enforcement share this code, so both reject
//! identically.
//!
//! HTTP mapping: invalid/expired/forged vouchers are 403; quota exhaustion
//! is 429.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

/// Only this voucher version is accepted; bump on format change.
pub const VOUCHER_VERSION: u32 = 1;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn forbidden(message: impl Into<String>) -> StorageError {
    StorageError::ServerError {
        status: 403,
        message: message.into(),
    }
}

/// Decodes a hex field, requiring lowercase-canonical form. Case variants
/// decode to identical bytes, so without this rule one voucher would verify
/// under 2^64 nonce spellings and the spend ledger (keyed by nonce string)
/// would honor each as a fresh quota — an unlimited quota bypass.
fn decode_canonical_hex(field: &str, what: &str, len: usize) -> Result<Vec<u8>, StorageError> {
    let bytes = hex::decode(field).map_err(|_| forbidden(format!("voucher {what} must be hex")))?;
    if bytes.len() != len {
        return Err(forbidden(format!("voucher {what} must be {len} bytes")));
    }
    if hex::encode(&bytes) != field {
        return Err(forbidden(format!("voucher {what} must be lowercase hex")));
    }
    Ok(bytes)
}

/// A signed write authorization: holder `holder_pk_hex` may store up to
/// `quota_bytes` bytes with the issuing operator until `expires_utc`.
/// `nonce_hex` uniquely identifies this grant for spend accounting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteVoucher {
    pub version: u32,
    pub issuer_pk_hex: String,
    pub holder_pk_hex: String,
    pub quota_bytes: u64,
    pub expires_utc: u64,
    pub nonce_hex: String,
    pub signature_hex: String,
}

impl WriteVoucher {
    /// Issues a voucher for `holder_pk_hex` good for `quota_bytes` bytes
    /// over the next `ttl_secs` seconds. Fails fast on malformed holders
    /// and empty grants — verification would reject them anyway.
    pub fn issue(
        issuer: &SigningKey,
        holder_pk_hex: String,
        quota_bytes: u64,
        ttl_secs: u64,
    ) -> Result<Self, StorageError> {
        let holder =
            hex::decode(&holder_pk_hex).map_err(|_| forbidden("voucher holder key must be hex"))?;
        if holder.len() != 32 {
            return Err(forbidden("voucher holder key must be 32 bytes"));
        }
        if quota_bytes == 0 {
            return Err(forbidden("voucher quota must be positive"));
        }
        if ttl_secs == 0 {
            return Err(forbidden("voucher TTL must be positive"));
        }
        let nonce: [u8; 32] = rand::random();
        let mut voucher = Self {
            version: VOUCHER_VERSION,
            issuer_pk_hex: hex::encode(issuer.verifying_key().to_bytes()),
            holder_pk_hex,
            quota_bytes,
            expires_utc: now_unix_secs().saturating_add(ttl_secs),
            nonce_hex: hex::encode(nonce),
            signature_hex: String::new(),
        };
        let msg = voucher.signing_bytes();
        let sig = ciphervault_crypto::signatures::sign_with_domain(
            issuer,
            b"operator_write_voucher",
            &msg,
        );
        voucher.signature_hex = hex::encode(sig);
        Ok(voucher)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ciphervault-write-voucher-v1:");
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.issuer_pk_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.holder_pk_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&self.quota_bytes.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&self.expires_utc.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.nonce_hex.as_bytes());
        bytes
    }

    /// Verifies everything except spend: version, issuer match, key shapes,
    /// signature, expiry, and a positive quota. Pure — no ledger access.
    pub fn verify(&self, expected_issuer_pk_hex: &str, now_utc: u64) -> Result<(), StorageError> {
        if self.version != VOUCHER_VERSION {
            return Err(forbidden(format!(
                "unsupported voucher version {}",
                self.version
            )));
        }
        if !self
            .issuer_pk_hex
            .eq_ignore_ascii_case(expected_issuer_pk_hex)
        {
            return Err(forbidden("voucher issuer mismatch"));
        }
        let issuer = decode_canonical_hex(&self.issuer_pk_hex, "issuer key", 32)?;
        let mut issuer_arr = [0u8; 32];
        issuer_arr.copy_from_slice(&issuer);
        decode_canonical_hex(&self.holder_pk_hex, "holder key", 32)?;
        decode_canonical_hex(&self.nonce_hex, "nonce", 32)?;
        let sig = decode_canonical_hex(&self.signature_hex, "signature", 64)?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        ciphervault_crypto::signatures::verify_with_domain(
            &issuer_arr,
            b"operator_write_voucher",
            &self.signing_bytes(),
            &sig_arr,
        )
        .map_err(|_| forbidden("voucher signature verification failed"))?;
        if self.quota_bytes == 0 {
            return Err(forbidden("voucher quota must be positive"));
        }
        if now_utc > self.expires_utc {
            return Err(forbidden("voucher expired"));
        }
        Ok(())
    }
}

/// Spend terms pinned on first use: quota confusion via nonce reuse (same
/// nonce, bigger quota) is rejected even though both vouchers verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VoucherCharge {
    quota_bytes: u64,
    expires_utc: u64,
    spent_bytes: u64,
}

/// Per-operator spend ledger, keyed by voucher nonce. Callers hold the
/// lock across verify→charge, so concurrent writes on one voucher cannot
/// overspend; call [`VoucherLedger::release`] when persistence fails or
/// the write turns out to be a no-op (idempotent re-PUT).
#[derive(Debug, Default)]
pub struct VoucherLedger {
    max_quota_bytes: u64,
    spent: HashMap<String, VoucherCharge>,
}

impl VoucherLedger {
    /// `max_quota_bytes` caps the largest single grant this operator
    /// honors (operator policy; vouchers above it are refused outright).
    pub fn new(max_quota_bytes: u64) -> Self {
        Self {
            max_quota_bytes,
            spent: HashMap::new(),
        }
    }

    /// Retunes the operator maximum (existing pinned terms are unaffected;
    /// new grants above the new maximum are refused).
    pub fn set_max_quota(&mut self, max_quota_bytes: u64) {
        self.max_quota_bytes = max_quota_bytes;
    }

    /// Verifies the voucher, checks quota for `bytes`, and charges them,
    /// atomically. Expired entries are pruned first so the ledger cannot
    /// grow without bound.
    pub fn try_consume(
        &mut self,
        voucher: &WriteVoucher,
        expected_issuer_pk_hex: &str,
        now_utc: u64,
        bytes: u64,
    ) -> Result<(), StorageError> {
        self.prune_expired(now_utc);
        voucher.verify(expected_issuer_pk_hex, now_utc)?;
        if voucher.quota_bytes > self.max_quota_bytes {
            return Err(forbidden("voucher quota exceeds operator maximum"));
        }
        let entry = self
            .spent
            .entry(voucher.nonce_hex.clone())
            .or_insert(VoucherCharge {
                quota_bytes: voucher.quota_bytes,
                expires_utc: voucher.expires_utc,
                spent_bytes: 0,
            });
        if entry.quota_bytes != voucher.quota_bytes || entry.expires_utc != voucher.expires_utc {
            return Err(forbidden("voucher terms changed for nonce"));
        }
        if entry.spent_bytes.saturating_add(bytes) > entry.quota_bytes {
            return Err(StorageError::ServerError {
                status: 429,
                message: "voucher quota exhausted".to_string(),
            });
        }
        entry.spent_bytes = entry.spent_bytes.saturating_add(bytes);
        Ok(())
    }

    /// Returns `bytes` to the voucher's quota (persistence failed or the
    /// write stored no new bytes). Unknown nonces are a no-op.
    pub fn release(&mut self, nonce_hex: &str, bytes: u64) {
        if let Some(entry) = self.spent.get_mut(nonce_hex) {
            entry.spent_bytes = entry.spent_bytes.saturating_sub(bytes);
        }
    }

    /// Drops entries whose vouchers have expired. Called on every
    /// [`VoucherLedger::try_consume`]; also callable directly.
    pub fn prune_expired(&mut self, now_utc: u64) {
        self.spent.retain(|_, charge| charge.expires_utc >= now_utc);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.spent.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64: reproducible mutation battery without deps.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn issuer() -> SigningKey {
        ciphervault_crypto::generate_signing_key()
    }

    fn issuer_pk(key: &SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    fn holder_pk() -> String {
        hex::encode(
            ciphervault_crypto::generate_signing_key()
                .verifying_key()
                .to_bytes(),
        )
    }

    fn valid_voucher() -> (WriteVoucher, SigningKey) {
        let key = issuer();
        let voucher = WriteVoucher::issue(&key, holder_pk(), 1_000_000, 3600).unwrap();
        (voucher, key)
    }

    #[test]
    fn issue_verify_roundtrip() {
        let (voucher, key) = valid_voucher();
        assert!(voucher.verify(&issuer_pk(&key), now_unix_secs()).is_ok());
    }

    #[test]
    fn issue_rejects_garbage() {
        let key = issuer();
        assert!(WriteVoucher::issue(&key, "not-hex".into(), 100, 60).is_err());
        assert!(WriteVoucher::issue(&key, hex::encode([0u8; 16]), 100, 60).is_err());
        assert!(WriteVoucher::issue(&key, holder_pk(), 0, 60).is_err());
        assert!(WriteVoucher::issue(&key, holder_pk(), 100, 0).is_err());
    }

    #[test]
    fn every_field_is_integrity_protected() {
        let (voucher, key) = valid_voucher();
        let pk = issuer_pk(&key);
        let now = now_unix_secs();
        let mut tampered = voucher.clone();
        tampered.version += 1;
        assert!(tampered.verify(&pk, now).is_err());
        let mut tampered = voucher.clone();
        tampered.holder_pk_hex = holder_pk();
        assert!(tampered.verify(&pk, now).is_err());
        let mut tampered = voucher.clone();
        tampered.quota_bytes += 1;
        assert!(tampered.verify(&pk, now).is_err());
        let mut tampered = voucher.clone();
        tampered.expires_utc += 1;
        assert!(tampered.verify(&pk, now).is_err());
        let mut tampered = voucher.clone();
        tampered.nonce_hex = hex::encode(rand::random::<[u8; 32]>());
        assert!(tampered.verify(&pk, now).is_err());
        let mut tampered = voucher.clone();
        let mut bad_sig = [0u8; 64];
        bad_sig[..32].copy_from_slice(&rand::random::<[u8; 32]>());
        bad_sig[32..].copy_from_slice(&rand::random::<[u8; 32]>());
        tampered.signature_hex = hex::encode(bad_sig);
        assert!(tampered.verify(&pk, now).is_err());
        // Wrong issuer key: well-formed but not ours.
        let other_pk = issuer_pk(&issuer());
        assert!(voucher.verify(&other_pk, now).is_err());
        // Expired.
        assert!(voucher.verify(&pk, voucher.expires_utc + 1).is_err());
        // Malformed shapes.
        let mut tampered = voucher.clone();
        tampered.holder_pk_hex = "zz".to_string();
        assert!(tampered.verify(&pk, now).is_err());
        let mut tampered = voucher.clone();
        tampered.signature_hex = "00".to_string();
        assert!(tampered.verify(&pk, now).is_err());
    }

    #[test]
    fn uppercase_hex_is_rejected_as_non_canonical() {
        // Same decoded bytes, different strings: without the canonical
        // form rule, each case variant would open a fresh ledger entry
        // and multiply the quota without bound.
        let (voucher, key) = valid_voucher();
        let pk = issuer_pk(&key);
        let now = now_unix_secs();
        let mut upper = voucher.clone();
        upper.nonce_hex = voucher.nonce_hex.to_uppercase();
        assert!(upper.verify(&pk, now).is_err());
        let mut upper = voucher.clone();
        upper.signature_hex = voucher.signature_hex.to_uppercase();
        assert!(upper.verify(&pk, now).is_err());
        let mut upper = voucher.clone();
        upper.holder_pk_hex = voucher.holder_pk_hex.to_uppercase();
        assert!(upper.verify(&pk, now).is_err());
    }

    #[test]
    fn ledger_accounts_spend_and_exhaustion() {
        let (voucher, key) = valid_voucher();
        let pk = issuer_pk(&key);
        let now = now_unix_secs();
        let mut ledger = VoucherLedger::new(u64::MAX);
        assert!(ledger.try_consume(&voucher, &pk, now, 400_000).is_ok());
        assert!(ledger.try_consume(&voucher, &pk, now, 600_000).is_ok());
        let err = ledger.try_consume(&voucher, &pk, now, 1).unwrap_err();
        match err {
            StorageError::ServerError { status, .. } => assert_eq!(status, 429),
            other => panic!("expected 429, got {other:?}"),
        }
        // Release and re-spend works.
        ledger.release(&voucher.nonce_hex, 600_000);
        assert!(ledger.try_consume(&voucher, &pk, now, 600_000).is_ok());
        // Unknown nonce release is a no-op.
        ledger.release(&hex::encode([9u8; 32]), 10);
    }

    #[test]
    fn ledger_rejects_terms_change_and_over_max() {
        let key = issuer();
        let pk = issuer_pk(&key);
        let holder = holder_pk();
        let now = now_unix_secs();
        let small = WriteVoucher::issue(&key, holder.clone(), 100, 3600).expect("issue");
        // Same nonce, bigger quota, freshly and validly re-signed (what an
        // issuer-side bug or confused deputy would produce): verifies
        // alone, but the ledger pinned the original terms.
        let mut big = WriteVoucher::issue(&key, holder, 10_000, 3600).expect("issue");
        big.nonce_hex.clone_from(&small.nonce_hex);
        let mut unsigned = big.clone();
        unsigned.signature_hex = String::new();
        big.signature_hex = hex::encode(ciphervault_crypto::signatures::sign_with_domain(
            &key,
            b"operator_write_voucher",
            &unsigned.signing_bytes(),
        ));
        assert!(big.verify(&pk, now).is_ok());
        let mut ledger = VoucherLedger::new(u64::MAX);
        assert!(ledger.try_consume(&small, &pk, now, 50).is_ok());
        assert!(ledger.try_consume(&big, &pk, now, 50).is_err());
        // Over operator maximum: a valid voucher the operator won't honor.
        let mut capped = VoucherLedger::new(50);
        assert!(capped.try_consume(&small, &pk, now, 10).is_err());
    }

    #[test]
    fn ledger_prunes_expired() {
        let key = issuer();
        let pk = issuer_pk(&key);
        let now = now_unix_secs();
        let voucher = WriteVoucher::issue(&key, holder_pk(), 100, 3600).expect("issue");
        let mut ledger = VoucherLedger::new(u64::MAX);
        assert!(ledger.try_consume(&voucher, &pk, now, 10).is_ok());
        assert_eq!(ledger.len(), 1);
        ledger.prune_expired(voucher.expires_utc + 1);
        assert_eq!(ledger.len(), 0);
    }

    /// Dumb-fuzz battery: 512 seeded byte-level mutations of a valid
    /// voucher envelope must ALL fail decode or verify, while the
    /// unmutated control verifies. Deterministic seed — reproducible.
    #[test]
    fn mutation_battery_rejects_everything() {
        let (voucher, key) = valid_voucher();
        let pk = issuer_pk(&key);
        let now = now_unix_secs();
        let valid = serde_json::to_vec(&voucher).unwrap();
        let control: WriteVoucher = serde_json::from_slice(&valid).unwrap();
        assert!(control.verify(&pk, now).is_ok());
        let mut rng = XorShift(0x243F_6A88_85A3_08D3);
        for _ in 0..512 {
            let mut bytes = valid.clone();
            match rng.below(4) {
                0 => {
                    // Flip a random byte.
                    let i = rng.below(bytes.len());
                    bytes[i] ^= 1u8 << rng.below(8) as u8;
                }
                1 => {
                    // Truncate to a random length (possibly empty).
                    bytes.truncate(rng.below(bytes.len() + 1));
                }
                2 => {
                    // Swap two random bytes.
                    let a = rng.below(bytes.len());
                    let b = rng.below(bytes.len());
                    bytes.swap(a, b);
                }
                _ => {
                    // Splice random bytes at a random position.
                    let i = rng.below(bytes.len() + 1);
                    let junk = (rng.next() % 16) as usize + 1;
                    let filler: Vec<u8> = (0..junk).map(|_| rng.next() as u8).collect();
                    bytes.splice(i..i, filler);
                }
            }
            let Ok(candidate) = serde_json::from_slice::<WriteVoucher>(&bytes) else {
                continue;
            };
            // A mutation that happens to preserve validity is only
            // possible if it left every signed byte intact; byte flips
            // inside string escapes could theoretically do that, so
            // assert the parsed form still equals the original when it
            // verifies (i.e. the mutation was a semantic no-op).
            if candidate.verify(&pk, now).is_ok() {
                assert_eq!(
                    candidate, voucher,
                    "mutation produced a DIFFERENT valid voucher: {candidate:?}"
                );
            }
        }
    }
}
