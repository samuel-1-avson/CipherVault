# Account control-plane decentralization (Step 4, direction — not design)

ADR-012 step 4, recorded as analysis. Nothing here is a committed
protocol; the trigger and phase criteria at the end say when to promote
this into an ADR.

## Current state

The account service is centralized SQLite: one writer holding sessions,
MFA state, vault links (now including key-backup locators), scope
tokens, and audit events. Availability and integrity both rest on one
host and one operator. Steps 1–3 deliberately kept it that way while
removing it from the *confidentiality* path: it stores a public locator
and ciphertext metadata, never vault keys or passphrase-derived
material. A breach leaks who-links-what and can deny service; it cannot
decrypt vaults or forge key-backup envelopes.

## Why decentralize, and what is hard

- Reads are easy: vault links, locators, public keys, and audit history
  are all replicable as signed, versioned, content-addressed objects —
  the operator fleet already stores that shape.
- Writes are hard, specifically *revocation-sensitive* writes: session
  issuance/revocation, MFA changes, and role changes need a globally
  consistent "no" (a revoked session must stop working everywhere,
  promptly). That is the consensus problem, not a storage problem.
- The threat model must survive *operator* compromise, not just host
  failure: a quorum of independent operators must be unable to mint
  sessions or rewrite links alone. Anything weaker is ops
  (replicas/failover), not decentralization.

## Options considered

1. **Read replicas + managed failover.** Cheapest availability fix;
   zero trust improvement. Single writer remains the crown jewels.
2. **Anchored attestations.** The service publishes signed checkpoints
   (link set, revocation list heads) to operators/L2 on a schedule.
   Anyone can verify history; no one can fork it undetectably. Improves
   auditability, not write availability.
3. **Replicated control log on operators.** Sessions/revocations/links
   as an ordered log of signed entries across N operators with quorum
   reads. Revocation becomes "first quorum to carry the entry wins";
   clients enforce freshness windows. Real decentralization for the
   read path and revocation visibility; session *issuance* still needs
   a minter rule (see 4).
4. **Quorum issuance (M-of-N minters).** Login/MFA verification split
   across operators via threshold signatures or quorum countersign.
   Maximum decentralization, maximum complexity: ceremony design,
   liveness under churn, and client verification all get harder. Only
   justified once the fleet has genuinely independent operators.

## Recommended direction

Phase A (portability first): exportable, signed, versioned account
snapshots restorable onto any host — kills the single-host dependency
and makes every later phase a replication problem instead of a
rewrite. Phase B: anchored attestations (option 2) for fork detection.
Phase C: replicated revocation/link reads (option 3, read path).
Phase D: quorum issuance (option 4) — only after independent operators
exist and Phase C has run in production.

## Promotion triggers

Promote to a build ADR when: (a) at least two mutually untrusting
parties operate production account state, or (b) account-plane downtime
has caused a user-facing incident twice in one quarter. Until then,
centralized-with-portability is the honest architecture, and this file
stays a direction note.
