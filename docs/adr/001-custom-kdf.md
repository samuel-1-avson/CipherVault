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

## Amendment (2026-11-08, v1.0.31 audit)

- **Default captures are chunk protocol v2** (HKDF-SHA256, domain-separated);
  the `CIPHERVAULT_CHUNK_V2_WRITE=0` opt-out writes legacy v1 and now warns.
  The 30 Sep note above ("default captures remain v1", gate `=1`) is superseded.
- The Blake2b `CipherVault-KDF-v1` hierarchy remains the **compatibility
  contract** for recovery descriptors, manifest keys, epoch keys and v1
  chunks. Its outputs are pinned by known-answer tests
  (`kdf::tests::legacy_kdf_known_answer`) and must never change in place.
- Residual risk, stated plainly: this is a custom unkeyed-hash PRF
  construction, not HKDF/keyed-BLAKE2. It has no independent cryptographic
  certification. Domain separation (fixed prefix + 8-byte contexts +
  subkey ids) prevents cross-context reuse, but the construction's PRF
  security rests on Blake2b-512 behaving as a random oracle.
- Migration plan (future, versioned): introduce `CipherVault-KDF-v2`
  (HKDF-SHA256) behind a new key-version field with dual-read — derive
  with v2 for new epochs, keep v1 derivation for existing epochs/kits —
  only after an external review of both constructions and the migration.
  Never re-derive existing material under a new function.
