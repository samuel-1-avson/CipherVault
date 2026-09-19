# ADR-003: Repair is a dedicated lane, not voucher traffic

Date: 2026-09-18 · Status: Accepted

## Context

Mesh repair moves bytes operator→operator. Routing it through the
voucher/quota path would couple durability to payment state and let a
spent voucher halt healing.

## Decision

`RepairPush` is a P2P-only RPC: operator-signed, verified against the
known-sender routing table (ed25519 + digest), paced by a dedicated
receiver-side token bucket (8 MiB/s shared, 429 past budget) via
`put_repair_object`. No session, no voucher, no quota involved.

## Consequences

- Repair works with vouchers exhausted or policy on/off.
- Storm bound is the bucket + sender backoff/jitter + per-CID cooldowns,
  proven by the slice-4 chaos gates (kill/partition/bandwidth).
