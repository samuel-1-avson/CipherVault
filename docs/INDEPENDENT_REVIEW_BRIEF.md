# Independent security review: commissioning brief

The 1 October review was internal by owner choice. It is useful evidence but
cannot validate its own scope. Before describing CipherVault as independently
audited or expanding sensitive multi-tenant use, commission both tracks below
from a party with no implementation stake. Do not merge their findings into
the internal report; keep independent evidence separately attributed.

## Track A: penetration test (application + deployment)

Scope: account service API (authn, sessions, TOTP/WebAuthn, MFA policy,
recovery codes and reset, memberships, scoped credentials, secret routes),
operator HTTP admission and quorum behavior, dashboard routes, and the GCP
deployment (least-privilege identity, cloud scope, container configuration).

Rules: test an isolated canary built from a tagged release with synthetic
data only. No testing against production tenants, no live backup buckets,
no social engineering of custodians. Time-boxed credentials, agreed window,
safe-harbor contact.

## Track B: cryptographic review

Scope: sealed-box X25519/AEAD construction including non-contributory input
rejection (IA-01 fix), v1/v2 chunk derivations and HKDF domain separation,
authenticated manifest/header/nonce/digest checks, recovery envelope
signatures and head-selection across generations (IA-04), TOTP handling and
proof binding, age whole-archive encryption wiring for custody copies.

Explicit open questions for the reviewer: default v1 candidate-file
confirmation and encrypted-chunk identity replacement across complete-file
changes (IA-03, open for default/history), and head-record authority
generation across same-key recertification (IA-04, fails closed, migration
unreviewed).

## Inputs provided to reviewers

- Tagged source and release workflow provenance for the reviewed version.
- `report/SECURITY_REVIEW_READINESS_2026-10-01.md` (internal scope, IA-01..
  IA-09 dispositions, MFA cross-checks) so effort goes to gaps, not repeats.
- `docs/INDEPENDENT_RECOVERY_CUSTODY.md`, `docs/MFA_ROLLOUT.md`, and this goal's
  soak plan for operational context.
- A seeded canary with the capacity-harness fixture generator.

## Expected deliverables

1. Findings with severity, affected component/version, reproduction steps,
   and retest procedure. No finding is closed by internal assertion alone.
2. Explicit opinion on IA-03 and IA-04 as shippable, shippable-with-limits,
   or must-fix, with rationale.
3. A one-page executive statement suitable for quoting: what was tested,
   what was excluded, and the residual risks the owner accepts.

Schedule retest after fixes; a point-in-time letter does not cover later
releases.
