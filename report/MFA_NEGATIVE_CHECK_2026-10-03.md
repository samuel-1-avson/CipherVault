# MFA negative check — PASS (owner-reported, 2026-10-03)

Account: Alice (`cvacct_c6da30342f8b9d0601c15c8fcb3edc43`), MFA policy
`required: true` (enforced 2026-10-02, verified `enforced_ready` offline).

Method (per `docs/MFA_ROLLOUT.md` step 5): fresh primary-only session,
secret read attempted without step-up → denied (`MFA_STEP_UP_REQUIRED`
surface); TOTP step-up completed; same read retried → allowed.

Result: `denied-then-allowed: PASS`, reported by the owner. No codes, seeds,
or keys were shared with the agent; nothing to redact.
