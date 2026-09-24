# ADR-009: Membership openness beyond permissioned tickets

Date: 2026-09-24 · Status: Accepted

## Context

ADR-008 gave the fleet permissioned community join: fleet-signed invite
tickets (`operator_join_invite` domain, bound to one node key + expiry +
nonce), public `POST /v1/peers/join` into probation, graduation on time
served plus liveness, admin overrides on the control plane. The mesh going
live (P2P dual-mode rollout) does not change admission: P2P heartbeats feed
liveness, but the ticket remains the authorization and there is no P2P join
mirror (libp2p/memory transports report 501 for join).

The question this record answers: what comes after permissioned tickets?
Four models were evaluated against Sybil cost, joiner UX, key-management
burden, and compatibility with the current ticket flow. Two DON open
questions bound the answer: Q2 (staking asset + settlement chain) and Q4
(legal review of community operators storing third-party ciphertext) are
still open, and engineering cannot resolve either alone.

## Options

### 1. Status-quo permissioned (ADR-008) — baseline

Humans vet joiners out of band; the fleet key is a gatekeeper. Sybil cost
is social (one vetting conversation per ticket), joiner UX is one ticket
handoff plus periodic refresh, key management is one offline seed file,
ticket-flow compatibility is total by definition. Limitation: no open
enrollment; every joiner needs a human relationship with a fleet operator.

### 2. Federated fleet keys (multi-fleet trust bundles)

Each fleet keeps its own offline seed and ticket flow; fleets cross-pin
each other's `CIPHERVAULT_FLEET_KEY` copies into a trust bundle, so a
ticket signed by any bundled fleet admits into probation on any other.
Sybil cost stays social but distributes across fleets; joiner UX is
unchanged (one ticket from any member fleet); key-management burden is one
bundle file to rotate on membership change; ticket-flow compatibility is
high — verification iterates over pinned keys, issuance/nonce-spend/
probation/graduation are untouched. Requires a bundle-distribution story
(signed bundle object, rotation cadence) but no new cryptography and no
product/legal decision.

### 3. Stake-gated invites (conditional on DON Q2)

Tickets mint automatically against verifiable stake (on-chain bond or
off-chain attestation) instead of human vetting. Sybil cost becomes
economic rather than social; joiner UX gains self-service at the price of
joiner-side crypto burden (wallet, bond transaction, gas); key management
adds stake-verification keys/oracles; ticket-flow compatibility is
medium — the ticket format survives, but issuance moves from an offline
CLI to a stake-verifying minter. Blocked on Q2 (no staking asset chosen,
no settlement chain confirmed) and on the Phase 5 gates (named gas payer,
griefing analysis, audit) for any on-chain variant.

### 4. Web-of-trust introducers

Full members vouch for joiners (N introductions mint a ticket). Sybil cost
is weak at small scale — a single compromised full member mints an
arbitrary Sybil army up to the introduction quota — and only becomes real
with N >= 2 plus introduction rate limits plus introducer
accountability (strikes on introducers whose invitees misbehave).
Key-management burden is low, ticket-flow compatibility is medium (minter
moves to a quorum-signed introduction). Rejected for now: at fleet sizes
below ~20 full members the accountability graph is too thin to price
Sybils, and the mechanism adds social complexity without surviving the
threat it targets.

## Decision

Remain permissioned under ADR-008. Federated fleet keys (option 2) are the
approved next step and may proceed to design as soon as a second fleet
exists to federate with. Stake-gating (option 3) stays conditional on DON
Q2 plus the Phase 5 gates. Web-of-trust (option 4) is rejected at current
scale with a sized re-entry condition below.

## Re-entry conditions

- Federation: a second fleet operator requests mutual admission. Design
  deliverables then are the trust-bundle format, rotation/revocation
  procedure, and cross-fleet probation semantics (probation served in one
  fleet does not transfer unless the bundle says so).
- Stake-gating: DON Q2 answered (asset + chain) AND Phase 5 gates met
  (named gas payer, griefing analysis, external audit). Then: stake-minter
  design against the current ticket format.
- Web-of-trust: fleet sustains 20+ full members AND an abuse case that
  federation cannot express. Then: quorum/introduction-quota design with
  introducer accountability.

## Consequences

- No code, no config, no ticket-format change in this unit.
- Community growth stays human-gated; the known bottleneck is operator
  vetting time, not software.
- The mesh rollout (Units 1–3) proceeds without an admission dependency:
  probation, liveness, graduation, and recipient exclusion are unchanged
  by whatever mints the ticket, per ADR-008.
- DON Q2 and Q4 stay open and are now carried with owners
  (see Open Questions in `docs/DON_IMPLEMENTATION_PLAN.md`).
