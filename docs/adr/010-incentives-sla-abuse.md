# ADR-010: Incentives, settlement path, honest SLA, and abuse tiers

Date: 2026-09-24 · Status: Accepted

## Context

D3 decided barter/permissioned-fleet-first (2026-09-18): operators join by
allow-list or off-chain attestation, storage is mutual (run a node, use
the mesh), abuse control is technical (vouchers, quotas, rate limits,
blocklists). On-chain settlement is a separable Phase 5, gated on a named
gas payer, a griefing analysis, and an external audit. This record sets
the settlement path from that baseline, the metering hooks settlement
would need, the availability language the project can honestly use today,
and the abuse-response vocabulary. It authorizes no code: metering and
settlement implementation stay gated on this ADR plus the DON Phase 5
gates.

## Settlement options against the barter baseline

### A. Continued barter (current state) — decision for now

Mutual storage with technical abuse controls. Zero gas, zero token
decisions, zero joiner-crypto burden. Limitation, unchanged from D3: no
open enrollment economics and no paid durability tiers. This remains the
operating model until either path below meets its gate.

### B. Off-chain bilateral accounting (next step, needs metering)

Operators settle bilaterally (invoices, credits, mutual offset) against
metered per-peer bytes served/stored. No chain, no audit gate, no griefing
analysis — disputes are human, as vetting already is under ADR-008/009.
Gate: per-peer metering labels (see below) plus one settlement cycle run
manually between two fleets to prove the numbers are trusted. This path
composes with federation (ADR-009 option 2): federated fleets are the
natural first bilateral counterparties.

### C. On-chain lease escrow (D3 Option B, still gated)

Staking registry, Merkle batcher, challenge/adjudication/slash loop on
Arbitrum One per `docs/DON_ECONOMICS_DECISION.md`. Gates unchanged: DON
Q2 answered (staking asset + chain confirmation), named gas payer,
completed griefing analysis, external audit. No new input from this
record; path B does not pre-empt it — bilateral accounting transfers to
escrowed settlement as the metering both need is identical.

## Metering: current coverage and needed hooks

Today the operator exposes aggregate counters only: object put/get byte
totals, recovery-append bytes, repair bytes, peer join/graduation counts,
live-peer gauge (`services/operator/src/metrics.rs`). There are no
per-peer byte labels: no series answers "bytes served to peer X" or
"bytes stored on behalf of peer Y".

Needed hooks (design, not yet code):

- `served_bytes_total{peer}` — bytes read by or pushed to each peer.
- `stored_bytes{peer}` — bytes currently held attributable to each peer
  (or holder set, for erasure/replicated objects).
- `voucher_spend_bytes_total{holder}` — quota consumption per voucher
  holder (the ledger tracks spend; it is not yet a labeled series).

Re-entry: when path B has two willing fleets, implement the three hooks
behind the existing metrics surface, run one manual settlement cycle,
then decide whether the labels are trustworthy enough to automate
against. Cardinality discipline applies: peer labels are bounded by mesh
size, holder labels by voucher issuance — both small today, both need a
cap design before open enrollment.

## SLA vocabulary the project can honestly offer today

No contractual SLA exists and this record creates none. The honest,
usable vocabulary:

- Durability posture: 3-node quorum survives any single-node loss;
  repair restores replica count without client action (drill-proven,
  not contractually timed).
- Availability posture: best-effort community testnet; the public
  status page is the source of truth for current state.
- Response posture: manual, best-effort; no response-time target is
  offered. Incidents follow the operator playbooks (§9) and are
  recorded in the chaos log.
- Anything stricter (uptime percentage, RTO/RPO numbers, paid tiers)
  requires path B metering plus a second fleet as counterparty, at
  minimum — and is explicitly out of scope until then.

## Abuse tiers

Ordered by severity of response; each tier names the mechanism and
whether it exists today.

- T0 Observe: aggregate byte/repair/429 metrics (§9 triage). Exists.
- T1 Throttle: rate-degrade one peer/holder before refusing them.
  Missing — the HTTP limiter is global (600/min default), vouchers are
  accept-until-quota. Needs per-key limiting design.
- T2 Probation re-entry: demote a full member back to probation so
  repair replicas are withheld while liveness continues. Missing —
  graduation is one-way plus admin override; no demote path exists.
- T3 Quarantine: `block_peer`/`unblock_peer` (own layer over
  libp2p-swarm 0.48; verify drops in metrics). Exists (§4).
- T4 Eject: remove from `CIPHERVAULT_TRUSTED_PEER_KEYS` where the
  allowlist is used, rotate the ejected node's operator key (§7),
  re-mesh (§2), treat old-key leases/vouchers as untrusted. Exists
  (§9 compromised-node path).
- T5 Fleet-key rotation: new offline seed, re-pin every node, old
  tickets die with the old pin. Procedure missing — no rotation drill
  has been run; the pin is read at boot and join fails closed when
  unset, which bounds the design space.

Escalation order is T0 → T1 → T2 → T3 → T4; T5 is incident-only (fleet
key compromise), never routine abuse response. T1/T2/T5 are re-entry
conditions, not backlog: design them when abuse volume justifies it,
not before.

## Re-entry conditions

- Path B metering: two fleets willing to settle one manual cycle.
- Path C escrow: DON Q2 + named gas payer + griefing analysis + audit
  (unchanged from D3).
- T1 throttle: sustained 429 floods that global limits cannot shape.
- T2 re-entry: a graduated peer misbehaves but stays live (quarantine
  too blunt, ejection too final).
- T5 rotation drill: before the second fleet federates — federation
  without a practiced rotation is a shared single point of failure.

## Consequences

- No metering code, no settlement code, no limiter changes in this unit.
- Operators get honest language: posture statements, not promises.
- The abuse ladder is documented in the playbooks (§12) with exists/
  missing marked per tier, so the next incident does not rediscover it.
- DON Q2 stays the binding constraint on every economic path; nothing
  here answers it.
