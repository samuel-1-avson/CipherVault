# ADR-001: Custom Blake2b KDF with domain separation

Date: 2026-09-12 (recorded 2026-09-18) · Status: Accepted

30 September 2026 update: this decision remains the compatibility contract for recovery descriptors, manifest keys and v1 chunks. Opt-in chunk v2 uses HKDF-SHA256 with fixed-width versioned vault/epoch bindings; its writer is gated by `CIPHERVAULT_CHUNK_V2_WRITE=1` pending independent review. Default captures remain v1. See [CHUNK_PROTOCOL_V2.md](../../crates/snapshot/CHUNK_PROTOCOL_V2.md). This ADR is not independent cryptographic certification.

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
