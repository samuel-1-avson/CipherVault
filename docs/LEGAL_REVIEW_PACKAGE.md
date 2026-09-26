# Legal Review Package (Blocker 6)

**Status:** `BLOCKED — LEGAL REVIEW PENDING`. Owner: `legal` (DON plan Q4).
This package states technical facts for counsel; it assumes no legal
conclusions and does not substitute for sign-off.

## 1. What operators store

Opaque content-addressed chunks (XChaCha20-Poly1305 ciphertext), lease
receipts, signed peer descriptors/heartbeats, recovery log records
(encrypted blobs indexed by KDF-derived locators), and (fleet nodes)
spent-invite nonces + membership/probation records. No filenames, no
directory trees, no plaintext, no user keys.

## 2. Ciphertext vs plaintext

Strictly ciphertext plus protocol metadata (CIDs, sizes, lease terms,
block numbers, signatures). Operators cannot decrypt user data: keys
derive from the user's master secret R, which never leaves the user's
custody (paper kit + Shamir guardian shares).

## 3. Key control

Users (and their guardians) control all decryption capability. Operators
hold only transport/identity keys (node key, TLS) and authorization keys
(service tokens, fleet verification pins) — none of which decrypt vault
content.

## 4. Data residency / cross-border

Chunks replicate across operators wherever they run (seed fleet: Iowa +
South Carolina, US; community nodes: anywhere). The protocol has no
geofencing; placement is by membership/quorum, not jurisdiction. Counsel
should assume any operator's ciphertext may rest in any other operator's
jurisdiction.

## 5. Operator vs user responsibilities

Operators: run the daemon, keep it patched and backed up, protect their
node key/service token, enforce the access posture (post-re-close:
enrolled devices only), respond to abuse within their power (revocation,
blocking). Users: guard R and device keys, enroll/revoke devices, choose
operators (`init --operators`), retain recovery kits.

## 6. Retention / deletion

Leases expire (terms + renewal); object deletion follows lease/retention
policy. Ciphertext addressed by CID is immutable while stored; there is
no remote-wipe of copies an operator retained outside the protocol.
Deletion guarantees are lease-expiry + overwrite-policy, not
cryptographic erasure (a known limitation to put to counsel).

## 7. Incident response implications

A compromised operator node exposes: its node key (identity), service
token (control plane), and the ciphertext it holds (still encrypted).
It does not expose user plaintext or R. Response: rotate operator key
(revocation ceremony), rotate service token, re-pin trust registries,
audit membership. Fleet-seed compromise = re-bootstrap membership.

## 8. Permissioned vs permissionless

Today: permissioned growth (ADR-008 tickets, ADR-009: permissioned
retained; federation approved as next step only). The open-write test
posture is an access-control setting, not open membership — joining the
routing table still requires a ticket. No staking/token, no payouts.

## 9. Technical controls (context, not approval)

Authenticated encryption, content addressing, quorum replication,
ticket-gated membership with probation/graduation, device enrollment +
revocation, session scoping, vouchers/quotas, rate limits, signed feeds,
signed releases, immutable audit trails (anchor registry, evidence logs).

## 10. Questions for counsel

1. Does storing third-party ciphertext (undecryptable by the operator)
   create custodian/hosting obligations in target jurisdictions?
2. Does cross-border replication of such ciphertext trigger transfer
   rules despite non-decryptability?
3. Is lease-expiry deletion sufficient, or is a stronger erasure story
   required before mainnet?
4. Any operator-agreement / ToS / privacy-notice requirements for the
   permissioned fleet and community join flow?

## 11. Sign-off record

| Date | Reviewer | Scope | Conclusion |
|---|---|---|---|
| — | — | Intended production operating model (closed fleet, permissioned growth, Sepolia→mainnet anchor) | PENDING |

Blocker 6 closes only when this table carries an explicit documented
legal sign-off.
