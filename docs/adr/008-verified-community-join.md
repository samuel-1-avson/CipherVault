# ADR-008: Verified community join (fleet-signed invites + probation)

Date: 2026-09-19 · Status: Accepted

## Context

The fleet is a static 3-node cluster: membership changes require the
service token (`POST /v1/peers/announce` + `ciphervault peers --mesh`), so
a willing community operator cannot join on their own. The DON spec (§4.2,
§7) designs open membership around on-chain staking, which is not built.
The goal for this milestone: let anyone run `ciphervault-operator` and
join the fleet, while keeping malicious nodes out — without a blockchain,
without breaking static mode, and without weakening what already works.

Two design facts bound the threat: stored chunks are opaque client-side
ciphertext (a rogue node reads nothing) and content-addressed (a rogue
node serving bad bytes fails the digest check and is ignored). Open join
therefore threatens availability and routing — Sybil floods, data drops,
eclipse — not confidentiality or integrity. Verification targets those.

## Decision

Admission by fleet-signed invite ticket, then probation:

- `JoinInvite` (`crates/storage/src/invites.rs`) mirrors the `WriteVoucher`
  pattern: versioned, fleet-key-signed (`operator_join_invite` domain),
  bound to one node public key + expiry + random nonce, lowercase-canonical
  hex throughout so one ticket cannot verify under many nonce spellings.
- Issuance is fully offline: `ciphervault invite issue` signs with a
  32-byte fleet seed file (same convention as `sign-bootstrap-list`). The
  fleet key never lives on a server; nodes verify against the pinned
  `CIPHERVAULT_FLEET_KEY` copy. When the pin is unset, the join endpoint
  fails closed and static fleets behave byte-for-byte as before.
- `POST /v1/peers/join` is public (the ticket is the authorization) and
  admits into probation. The nonce is spent before the routing insert
  (`join-invites.json`, atomic + fsync, restart-durable), so one ticket
  admits exactly one node key; reuse is 409, forgery/expiry/mismatch 403.
- Probationary standing (`peer-membership.json`) gates exactly one thing:
  repair recipients. Probationers still count as holders and may push —
  pushes are digest-verified, so they cannot plant garbage. Peers with no
  record (meshed before verified join) read as full: upgrades never
  demote the existing fleet.
- Graduation needs time served (`CIPHERVAULT_PROBATION_SECS`, default 24 h,
  floored at 60 s) plus recent liveness. Liveness arrives over both
  transports: verified P2P heartbeats (persisted only on the
  probation→full edge, never per heartbeat) and `POST /v1/peers/join/refresh`
  (public; signature + stored-key match, so a refresh extends only its own
  entry). The membership listing lazily graduates only when liveness is
  inside the grace window — a node that served its time but went silent
  does not graduate until it proves life again.
- Admin overrides stay control-plane: a service-token announce promotes to
  full (explicit trust grant), `POST /v1/peers/:id/graduate` graduates
  immediately, `GET /v1/peers/membership` lists standing.
- After graduation the admin adds the node key to
  `CIPHERVAULT_TRUSTED_PEER_KEYS` (when the allowlist is used) and includes
  the endpoint in `peers --mesh`: full members are kept alive by the same
  mesh the static fleet already uses.

Locked by `invites::tests::*` (issue/verify/forgery/expiry/canonical),
`state::tests::verified_join_*` (probation admission, closed-by-default,
forgery matrix, single-use across restart), `state::tests::join_refresh_*`
and `*_graduation_*`/`heartbeat_liveness_*` (own-entry-only refresh,
time+liveness graduation), `state::tests::control_announce_promotes_*` and
`graduate_peer_admin_override`, `swarm::join_tests::repair_candidates_*`
(recipient exclusion), and `handlers::tests::join_errors_map_to_status`.

## Consequences

- Community operators can join with one ticket handoff and stay joined
  with periodic refresh; no service token ever changes hands.
- Ticket theft admits at most the bound node key, once, within the TTL —
  and probation still withholds repair replicas until the node proves
  itself over time.
- Repair determinism weakens slightly: probation views can differ across
  holders mid-propagation, so two holders may rarely elect different
  recipients for one round. Pushes are idempotent and budgeted, so the
  worst case is one duplicate backfill.
- The fleet key is a gatekeeper, not a decentralizer: humans vet joiners
  out of band. Fully trustless admission (staking/Sybil cost) stays future
  work per the DON spec and composes with this ladder (probation,
  liveness, graduation, and recipient exclusion are unchanged by whatever
  mints the ticket).
- Rejected: open announce without tickets (Sybil-trivial); on-chain
  staking now (contract + audit + joiner-crypto burden for this milestone);
  P2P join mirror (HTTP-only keeps one verified path; the libp2p and
  memory transports report 501).
