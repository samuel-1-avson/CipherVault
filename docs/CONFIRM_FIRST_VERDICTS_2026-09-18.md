# Confirm-first verdicts (2026-09-18)

Narrow items held for evidence per the system audit; verdicts with proof.

## Transport-conformance gaps — KILLED (no instance)

- `services/operator/tests/transport_conformance.rs`: 36/36 green.
- `crates/storage/tests/transport_conformance.rs`: 5/5 green (incl. the
  new idempotent-retry test).
- No failing case, no divergent leg, no gap instance was ever cited.
  Verdict: no action; the two suites are the standing evidence.

## Further naming drift — CONFIRMED, fixed

Code ground truth: XChaCha20-Poly1305 AEAD (`aead.rs`), custom
Blake2b KDF (`kdf.rs`, ADR-001), SHA-256 CIDs (`compute_digest`).
`hkdf` appears in `Cargo.lock` only as a transitive dependency.

- `docs/SYSTEM_WORKFLOW.md`: 6× bare `ChaCha20-Poly1305` → XChaCha20;
  BLAKE2b CID claim → SHA-256.
- `README.md`: 2× BLAKE2b addressing/CID → SHA-256; 3× HKDF key
  derivation → custom Blake2b KDF.
- `docs/DECENTRALIZED_ARCHITECTURE_SPEC.md`: BLAKE2b hash claim → SHA-256.
