# ADR-007: Durable voucher spend ledger

Date: 2026-09-19 · Status: Accepted

## Context

The D4 voucher spend ledger (`VoucherLedger`, ADR-002) was memory-only: an
operator restart reset every voucher's spend to zero, so a quota could be
re-spent in full after each restart. Bounded (≤1 quota per boot, restart
access required, vouchers opt-in) but wrong as a mesh policy — restarts
are routine (deploys, crashes), and quota confusion across restarts
undermines the barter accounting the mesh settles on.

## Decision

Persist the spend map to `voucher-ledger.json` in the operator data dir:

- Spend only (`nonce → {quota, expiry, spent}`), atomic write + fsync like
  the peer/approval stores. Operator policy (`max_quota_bytes`) is NOT
  persisted — it comes from current startup configuration, never from
  last boot's file.
- The ledger lock is held across charge + file persist (same convention
  as the relay/peer/approval stores) so concurrent charges cannot
  interleave file writes and lose spend.
- Persist on every consume; re-persist on release (idempotent retries,
  failed writes). A consume-persist failure rolls back the in-memory
  charge and fails the write (500) rather than minting unrecorded spend.
- A corrupt/unparseable file is renamed aside (`voucher-ledger.corrupt-*`)
  with an error log and the ledger starts empty; entries with
  non-canonical keys or impossible terms are skipped individually.
  Vouchers re-pin terms on next use, still bounded by their own quotas
  and re-verified. This is accident recovery, not a trust boundary — an
  attacker with disk write could delete the file anyway.
- The receiver repair budget stays memory-only by design: a token bucket
  is a rate over wall-clock time with no meaningful spend to persist.

Locked by `vouchers::tests::ledger_encode_decode_roundtrip_preserves_spend`,
`state::tests::voucher_spend_survives_restart`, and
`state::tests::corrupt_voucher_ledger_starts_empty_with_backup`.

## Consequences

- Voucher quotas survive operator restarts; restart no longer mints
  spendable quota.
- One fsync per charged (and per released) write — same order as the
  object/lease/recovery writes it gates.
- Operators triage post-restart quota reuse as a corrupt-ledger signal
  (backup file + stderr line), not as expected behavior (playbook §1).
- Rejected: memory-only + document (keeps the gap); persisting policy
  with spend (stale config overrides operator intent); SQLite (a second
  store for one small map).
