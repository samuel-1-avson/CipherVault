# External review outreach drafts (fill blanks, send)

Context: `docs/INDEPENDENT_REVIEW_BRIEF.md` defines both tracks. Our 1 Oct
review was internal; these commission the independent tracks. Attach to both:
tagged source link + release provenance for the reviewed version,
`report/SECURITY_REVIEW_READINESS_2026-10-01.md`,
`docs/INDEPENDENT_RECOVERY_CUSTODY.md`, `docs/MFA_ROLLOUT.md`, and the soak
plan/evidence (`docs/CAPACITY_SOAK_PLAN.md`,
`report/SOAK_EVIDENCE_2026-10-03.md`).

---

## Track A — penetration test (to: [FIRM])

Subject: Pen-test engagement inquiry: CipherVault account service + GCP deployment

> Hello [NAME],
>
> I'm looking to commission a time-boxed penetration test of CipherVault, a
> self-hosted secrets platform (Rust: account service API, storage operators,
> web dashboard; GCP deployment with Caddy edge + containers).
>
> Scope: account service API (authn, sessions, TOTP/WebAuthn, MFA policy,
> recovery codes and reset, memberships, scoped credentials, secret routes),
> operator HTTP admission and quorum behavior, dashboard routes, and the GCP
> deployment (least-privilege identity, cloud scope, container config).
> Full scope and rules of engagement are in the attached brief.
>
> Constraints (non-negotiable): isolated canary built from a tagged release
> with synthetic data only — no testing against production tenants, live
> backup buckets, or social engineering of custodians. Time-boxed
> credentials, agreed window, safe-harbor contact provided.
>
> Deliverables: findings with severity, affected component/version,
> reproduction and retest steps; plus a one-page executive statement (what
> was tested, what was excluded, residual risks). Retest after fixes is
> expected and will be scheduled separately.
>
> Could you share availability, a fixed-fee or capped estimate, and two
> comparable references? Happy to walk through the architecture on a call.
>
> [YOUR NAME]

---

## Track B — cryptographic review (to: [REVIEWER/FIRM])

Subject: Crypto review inquiry: CipherVault sealed-box, audit chain, recovery envelopes

> Hello [NAME],
>
> I'm looking to commission a focused cryptographic review of CipherVault
> (Rust codebase, tagged release provided with build provenance).
>
> Scope: sealed-box X25519/AEAD construction including non-contributory
> input rejection, v1/v2 chunk derivations and HKDF domain separation,
> authenticated manifest/header/nonce/digest checks, recovery envelope
> signatures and head-selection across generations, TOTP handling and proof
> binding, and age whole-archive encryption wiring for custody copies.
>
> Two explicit open questions I need your opinion on (shippable /
> shippable-with-limits / must-fix, with rationale): default v1
> candidate-file confirmation and encrypted-chunk identity replacement
> (IA-03), and head-record authority across same-key recertification
> (IA-04, currently fails closed, migration unreviewed). Prior internal
> dispositions (IA-01..IA-09) are attached so effort goes to gaps, not
> repeats — but please treat them as claims to check, not findings to
> close; no finding closes on internal assertion alone.
>
> Deliverables: findings with severity, affected component/version,
> reproduction and retest steps; the IA-03/IA-04 opinions above; and a
> one-page executive statement (tested / excluded / residual risks).
>
> Could you share availability, an estimate, and any additional inputs you
> need beyond the attached brief and source? Happy to walk through the
> constructions on a call.
>
> [YOUR NAME]

---

## After sending

Record: vendor, date sent, version under review, agreed window. Keep all
independent findings separately attributed — never merged into the internal
report.
