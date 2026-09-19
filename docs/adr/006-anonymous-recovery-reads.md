# ADR-006: Anonymous capability reads for disaster recovery

Date: 2026-09-18 · Status: Accepted

## Context

`GET /v1/recovery/:locator/records` (and the P2P mirror) requires no
session. Gating it would break clean-machine bootstrap, which has no
session by definition.

## Decision

Keep reads anonymous. The locator is a 256-bit KDF-derived capability
(`derive_recovery_locator`), unenumerable without the recovery secret.
Writes stay Ed25519-gated on the vault recovery key. Locked by
`services/operator/tests/recovery_auth.rs` + handler doc comments.

## Consequences

- Recovery works from a bare machine with only the paper kit.
- Locator secrecy is load-bearing; rotation story is future work.
