# ADR-002: Write vouchers, barter model (D4)

Date: 2026-09-18 · Status: Accepted

## Context

Open operators need disk-fill protection: without authorization, anyone
can store unlimited bytes (Phase 3 gate scenario).

## Decision

Bearer write vouchers, self-issued per operator (`POST /v1/vouchers`,
service-token admin). A voucher binds holder key + byte quota + expiry;
the spend ledger charges verify→charge under one lock with expiry
pruning. Enforcement sits before persistence on all four write funnels;
idempotent re-PUTs bill zero. No staking, no chain settlement.

## Consequences

- Disk-fill drill holds: voucherless writes 403 with zero bytes stored.
- Vouchers are Bearer [REDACTED] by design (possession = authority);
  sender-constrained binding is future work.
- Ledger is memory-only: restart resets spend (≤1 quota per boot).
  See `docs/OPERATOR_PLAYBOOKS.md` (restart playbook).
