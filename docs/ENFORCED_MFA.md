# Enforced account MFA

Updated 1 October 2026. This implementation adds a durable **per-account
required-MFA policy**. Existing accounts migrate with the policy optional, so an
upgrade does not strand accounts without an authenticator or retained recovery
codes. Enabling it is an explicit owner action; deployment alone does not enable it.

## Normal authentication and protected operations

A signing-key or passkey login supplies primary proof. Verify the TOTP second
factor for that exact session at `POST /v1/sessions/mfa/totp`:

```json
{"code":"123456"}
```

Primary authentication must be no more than five minutes old. TOTP-only and
recovery sessions cannot establish second-factor proof. Code verification,
replay consumption, and proof publication share an immediate SQLite transaction.
The failure budget is rechecked under that transaction across independent
service connections.

Factor proof lasts less than five minutes. The database stores its verification
time, random proof ID, and encrypted-credential fingerprint, not the supplied
code. Replacement or revocation invalidates proof. Session expiry/logout and
device/passkey revocation continue to invalidate the source and derived tokens.

`GET /v1/sessions` reports `mfa_required` and `mfa_verified_at_utc`; the internal
proof ID is omitted. Required-MFA sensitive guards demand fresh primary and
second-factor proof. Membership guards honor the target account's required policy.
Account-signed device enrollment receives the same check: a root signature alone
cannot bypass an enabled policy.

Scoped policy revalidates the source and factor against the connection used for
authorization/storage. Tokens bind the proof present at issuance. A token without
that proof cannot gain it when its source session later completes step-up. Tokens
for required accounts expire within the primary/factor freshness window. Legacy
originless account tokens fail when their account requires MFA. Catalog metadata
and session/policy status remain available for navigation and recovery; they do
not release values or grant sensitive authority.

Handoffs preserve original primary age/expiry and do **not** transfer factor
proof. The new session needs a fresh unused code. Ordinary TOTP login remains an
alternate login method. Passkey user-verification settings do not imply that an
independent second factor was checked.

## Enrollment and activation

1. Authenticate using an enrolled key or passkey. Preserve usable primary keys
   and protected recovery material before changing authentication.
2. Enroll and confirm the authenticator through the existing setup flow.
3. Generate and retain unused recovery codes. Code generation requires a
   device-bound primary session; CLI account connection can provide the binding.
4. Verify a fresh code at the step-up endpoint. Enrollment/login codes already
   used in the current 30-second step cannot be reused; wait for the next code.
5. Set `PATCH /v1/accounts/{account_id}/mfa` to `{"required":true}`.

Both enabling and disabling require fresh primary and factor proof. Enabling
also requires unused recovery codes. Changes revoke other sessions and outstanding
handoffs, preserving the current verified session. An authenticator cannot be
revoked while required MFA is enabled: disable the policy using valid proof first,
or use emergency recovery.

This is an account policy, not a tenant-wide workforce mandate. Enable it for
every human account allowed to access sensitive projects. Tenant minimum-factor
policy and verified workload-identity adapters remain separate capabilities.

## Emergency recovery and its trust boundary

`POST /v1/accounts/{account_id}/mfa/recovery-reset` accepts
`{"code":"cvrc_..."}` with a fresh signing-key/passkey session. It atomically
consumes the unused offline code, disables required MFA, revokes the authenticator,
revokes **all** sessions, and invalidates handoffs. It returns no replacement
session or MFA proof. Log in again, replace the authenticator, replenish protected
codes, and explicitly re-enable the policy.

This is **full-account emergency recovery**, not an ordinary factor assertion.
Existing recovery codes can authorize lost-key device enrollment. A code-sheet
holder can redeem one code, enroll a replacement device, log in with it, and use
a second unused code for reset. Those codes belong to one recovery set; they are
not independent factors or proof of a pre-existing device. A recovery session
alone cannot mint credentials, read scoped values, or reset MFA.

Protect the code sheet as recovery authority, separately from everyday devices
and cloud credentials. Independently governed recovery approval is a further
deployment policy, not a guarantee inferred from this API. See
[independent custody](INDEPENDENT_RECOVERY_CUSTODY.md). Database backup preserves
policy and encrypted factors. Restore rehearsal revokes copied sessions, so their
factor proofs cannot authorize traffic. Retain wrapping keys and historical KEKs
separately; backup bundles exclude them.

## Validation and rollout

Regressions exercise activation prerequisites, policy persistence, proof-ID
omission, handoff/replay denial, scope binding/expiry/replacement, TOTP-only and
stale-primary denial, recovery-code consumption/revocation, and concurrent failed
guesses across separate SQLite connections. Run account/workspace checks, strict
Clippy, and actual browser/proxy regressions before promotion. Rehearse enrollment,
handoff, factor loss, and recovery using a synthetic account before enabling live
policies. Keep protected database/key backups and a verified signed rollback path.
