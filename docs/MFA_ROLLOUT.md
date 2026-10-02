# Enforced-MFA rollout runbook

Per-account MFA enforcement is available and its enable path is lockout-safe
in code: `PATCH /v1/accounts/:id/mfa` requires a fresh primary session, a
fresh second-factor proof, and at least one unused recovery code before it
accepts `{"required": true}`. There is no global default switch; rollout is a
per-owner enrollment ceremony followed by per-account enablement. Do not invent
one: flipping a default while owners lack enrolled factors would lock them out.

## Per-owner ceremony (repeat for every production owner)

1. Owner opens a fresh primary session (device key or passkey).
2. Owner enrolls a TOTP authenticator (`/totp/enrollment`, then
   `/totp/enrollment/verify`) and, where available, a WebAuthn credential.
3. Owner generates recovery codes (`/recovery/codes`) and stores them offline,
   separate from the authenticator device.
4. Owner proves the authenticator once (`/sessions/mfa/totp` step-up), then
   enables enforcement: `PATCH /v1/accounts/:id/mfa {"required": true}`.
   Other sessions are revoked and the change is audited (`mfa_policy_changed`).
5. Owner confirms `GET /v1/accounts/:id/mfa` returns `required: true` and that
   secret reads without step-up are denied.

## Operator verification (offline copies only)

After each batch, take a fresh stopped-database snapshot through the normal
backup flow and report readiness from the offline copy:

```sh
python scripts/recovery/mfa_readiness.py /path/to/offline-copy.sqlite3
python scripts/recovery/mfa_readiness.py /path/to/offline-copy.sqlite3 --check
```

`--check` exits 0 only when every account is `enforced_ready` (policy required
plus at least one active factor). Act on each other verdict:

| Verdict | Meaning | Action |
|---|---|---|
| `ready_to_enable` | Factor + unused codes present | Owner runs step 4 |
| `blocked_no_factor` | Nothing enrolled | Run the enrollment ceremony |
| `blocked_no_recovery_codes` | Factor but no unused codes | Generate and escrow codes first |
| `enforced_no_factor` | Required but no active factor | Treat as lockout: use recovery reset, re-enroll, re-enable |

The report never prints secret material. It opens the copy read-only and
refuses files that lack the account schema.

## Recovery from lockout

`POST /v1/accounts/:id/mfa/recovery-reset` consumes one offline recovery code,
sets policy back to not-required, and revokes every session. It is a recovery
ceremony, not an MFA attestation: after it, re-run enrollment before
re-enabling.

## New accounts

New accounts are created without a policy row, which the service treats as
not-required. Until a default-on creation flow with enrollment grace exists,
onboard every new owner through this same ceremony before they store
production secrets.
