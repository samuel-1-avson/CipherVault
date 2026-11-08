# ADR-013: CipherChain liveness under split votes

Date: 2026-11-08 · Status: Accepted (mitigations landed; view-change designed, not yet implemented)

## Context

CipherChain block production allows any validator to propose at the next
height, votes are keyed by proposal hash, and a block commits only when a
quorum certificate is assembled (`crates/chain/src/sync.rs`). If two
proposers broadcast competing proposals at the same height, honest votes
can split below quorum and the height stalls: there is no leader
schedule, timeout, or view change. Separately, proposal/vote/equivocation
state in the sync hub was unbounded, and proposal vetting recomputed the
full cumulative Merkle root per proposal.

## Decision (landed in v1.0.31)

- Proposal ingestion is capped (16 distinct proposals per height, 256
  total) and decided heights are pruned; equivocation evidence is capped
  at 256 entries; certified heights drop their vote buckets.
- Proposal vetting (`check_block`) computes the prospective state root
  with `MerkleTree::root_with_appended` (suffix-only recomputation,
  equality with a full rebuild pinned by test) instead of cloning and
  rehashing the entire commitment history per proposal.

## Liveness design (future, requires a chain version bump)

1. Deterministic proposer rotation: the eligible proposer for
   `(height, view)` is `validators[(height + view) % n]`. Proposals from
   non-eligible proposers in that view are rejected at ingest.
2. View change: if no certificate forms within a timeout (wall-clock,
   e.g. 10s, gossiped `observed_ms` already provides the median-time
   substrate), validators move to `view + 1` and may vote for the new
   view's proposer; votes record their view and only same-or-later-view
   votes count toward a certificate.
3. Compatibility: this changes vote/proposal validity, so it ships as
   block version 4 with activation at a flag height agreed by the
   validator set (the rotation mechanism in `next_validators` is the
   natural carrier). Pre-activation heights keep today's rules.

## Consequences

- Until the view-change ships, a split vote at a height requires
  operator coordination to resolve (re-proposal by agreement). This is
  a known, documented limitation of the current sovereign chain, not a
  silent failure: the hub logs rejected/stalled proposals and the CLI
  anchor path reports `PROPOSED — awaiting fleet quorum` instead of
  claiming a commit.
- The caps mean a flooding validator gets its excess proposals rejected
  (visible) rather than silently consuming memory.
