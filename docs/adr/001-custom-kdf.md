# ADR-001: Custom Blake2b KDF with domain separation

Date: 2026-09-12 (recorded 2026-09-18) · Status: Accepted

## Context

CipherVault derives subkeys, file keys, 24-byte chunk nonces, and
recovery locators from root secrets. HKDF was the default candidate.

## Decision

Use a custom Blake2b KDF prefixed `CipherVault-KDF-v1` with 8-byte
context strings per derivation (`crates/crypto/src/kdf.rs`).
It is NOT libsodium-compatible by design.

## Consequences

- Every derivation is domain-separated; cross-context key reuse is a
  type-level non-event.
- Custom crypto carries review burden: the KDF is covered by
  `CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md` §2 and unit tests.
