# ADR-011: Quorum admission (K-of-N tickets + evidence log)

Date: 2026-09-24 · Status: Accepted

## Context

ADR-008 gave the fleet permissioned community join: one offline seed
signs v1 invite tickets, the join endpoint verifies against one pinned
`CIPHERVAULT_FLEET_KEY`, probation and graduation do the rest. ADR-009
kept the human gatekeeper and named federated fleet keys as the
approved next step — but federation answers fleet-to-fleet trust, not
the single keyholder inside one fleet.

The question this record answers: how does one fleet stop depending on
one human holding one seed, without changing what probation,
graduation, and repair-recipient exclusion already guarantee? Two facts
bound the answer. First, ADR-008 designed the minter as swappable:
probation, liveness, graduation, and recipient exclusion are unchanged
by whatever mints the ticket. Second, v1 binds the issuer key into the
signed body, so one v1 body can never carry two signers — quorum needs
a new ticket version, not a flag.

## Decision

Admission by K-of-N keyholder signatures on a v2 ticket, with a
mandatory admission evidence log:

- v2 ticket (`crates/storage/src/invites.rs`): the signed body covers
  version, node key, expiry, and nonce only — no issuer — so every
  keyholder signs the identical body. Signatures live in a
  `signatures` list; v1 single-sig fields stay empty on v2 tickets,
  and the `v2` body prefix makes cross-version replay impossible.
- Uniform approval counting: a v1 ticket counts as one approval from
  its issuer, a v2 ticket one per signature. The rule — at least K
  distinct valid approvals from the pinned set — applies to both.
  Duplicates count once; any signature from outside the set rejects
  the whole ticket, so key rotation naturally revokes old tickets.
- Ceremony keeps seeds apart: `invite request` (unsigned body, anyone
  may create it) → each keyholder `invite approve`s the same file on
  their own machine → coordinator `invite combine`s (every approval
  re-verified: mismatched, duplicate-signer, and bad-signature
  approvals rejected) → `invite verify` checks the ticket fully
  offline before it is handed out. `invite issue` (v1) stays for
  legacy mode and K=1 bootstrap.
- Server modes: quorum when `CIPHERVAULT_FLEET_KEYS` is pinned (K from
  `CIPHERVAULT_QUORUM_K`, default strict majority —
  `quorum_default(n) = n/2 + 1`), legacy single-key when only
  `CIPHERVAULT_FLEET_KEY` is set (byte-for-byte v1 behavior),
  fail-closed otherwise and on any config mistake.
- Evidence is mandatory, not best-effort: every successful admission
  appends `join-admissions.json` (admitted time, node key, operator
  id, nonce, expiry, ticket version, signer keys, ticket SHA-256),
  and a log-write failure rolls back routing, membership, and spend
  so the ticket stays redeemable. Read path is the control-plane
  `GET /v1/peers/admissions` plus the quorum-joins counter.
- Probation, liveness, graduation, refresh, P2P heartbeat standing,
  repair-recipient exclusion, and admin overrides are untouched. No
  P2P join mirror (unchanged 501).

Locked by `invites::tests::quorum_*` (ceremony roundtrip, threshold,
unknown/duplicate signers, v1-as-one-approval, cross-version replay,
mixed-format rejection, canonical hex, expiry, JSON back-compat),
`recover::quorum_ceremony_cli_tests::*` (file-level ceremony, cross
request rejection, shortfall message),
`state::tests::quorum_*` + `legacy_mode_join_logs_evidence` (admit,
reject-without-side-effects, K=1 legacy counting, fail-closed config,
rotation revocation, evidence durability across restart), and a real
CLI dry-run transcript (2-of-3 valid at default K, correctly rejected
at K=3).

## Consequences

- No single keyholder can mint alone at K >= 2, and no single seed
  theft admits anything — the gatekeeper becomes a quorum with a
  permanent, per-admission record of who signed.
- At fleet sizes where all keys share one holder, the quorum is
  procedural rather than trust-decentralizing: it buys key hygiene,
  coercion resistance (two machines, not one file), and evidence —
  not independent trust. Handing a key to the first independent
  operator is what makes the quorum real; the protocol needs no
  further change that day.
- Rotation is a clean break: new ceremony, new pin set, old tickets
  die. Rollout is two re-promotes (pin set at K=1, verify a join,
  then raise K=2) to keep the pin set verifiable live before the
  threshold rises.
- Stake-gating (ADR-009 option 3) composes unchanged on top: it swaps
  the minter again (stake-verifying instead of human-signing) while
  probation, graduation, and now the evidence log stay put.
- Rejected: N independent v1 tickets per join (evidence scatters,
  spend logic tangles); lenient unknown signers (junk signatures
  indicate tampering or coordinator bugs — fail closed); best-effort
  evidence (an admission without a record defeats the purpose).
