# CipherVault v1.0.28 production and assurance follow-up

**Date:** 2 October 2026 (UTC)

**Release source:** `38de126d46518e2c19e0af10c5b5434d4c2f20ae`

**Production project:** `gen-lang-client-0022105784`

## Executive assessment

CipherVault v1.0.28 is deployed and its running images, service health, dashboard
routes, operator readiness and advertised account-security capabilities were
verified. The signed release workflow and the optimized Linux synthetic capacity
workflow both passed on the release source. A clean post-deployment account
backup and isolated restore rehearsal also passed.

Those results improve release and recovery evidence; they do **not** close the
remaining organizational assurance gaps. MFA is available as an enforced
per-account policy but is not required by default. The recovery bucket remains
inside the production project, no separate custodians or retention lock are
active, and production-equivalent sustained capacity has not been measured. The
security review was internal as requested, not independent.

**Project rating remains 7.6/10; broad production readiness remains 6.5/10.**
These are subjective engineering judgments from the 1 October reassessment, not
certifications. I am not increasing them for a successful release alone: the
highest-impact gaps below still need owner action or separate acceptance
evidence. See the [previous whole-project reassessment](PROJECT_REASSESSMENT_2026-10-01.md).

## Release and rollout

PR [#20](https://github.com/samuel-1-avson/CipherVault/pull/20) merged as
`f12c5673ec7115d089e8fd973cdd96dbcd62198e` after all required checks passed.
The user authorized a one-time administrator merge. GitHub still reports
`REVIEW_REQUIRED`; that administrative exception is not a human approving review
or an independent assurance review. PR #20 fixes release package-manifest
version, URL and checksum synchronization, including creating a missing Winget
version directory. Its checks and the final release workflow passed.

The [v1.0.28 release workflow](https://github.com/samuel-1-avson/CipherVault/actions/runs/36935872841)
completed successfully for tag `v1.0.28` and the source commit above. Cosign
verified all three images against the expected GitHub Actions OIDC identity and
release source:

| Service | Immutable production image digest |
|---|---|
| Dashboard | `ghcr.io/samuel-1-avson/ciphervault-dashboard@sha256:a2cee5149746462d20b16f26c792964f66211c491d2833cd8301caac7598c123` |
| Account | `ghcr.io/samuel-1-avson/ciphervault-account@sha256:92a7d03ea7772c08192ebf5d423dc531ca6aa7a97b8f0abf4d7e296bac33836d` |
| Operator | `ghcr.io/samuel-1-avson/ciphervault-operator@sha256:7d9525fe3d0adcbc6948817f32d985f93bd673505ec1ba131632c4a3acccc9a0` |

The rollout updated the account/dashboard containers on `cv-web-ui` and all
three operator nodes. The web VM was restarted to apply the least-privilege
runtime identity and cloud scope. The [post-deployment verifier](../.agents/assurance-2026-10-01/postdeploy-v1.0.28-verification.json)
recorded build `1.0.28`, the expected image identities, non-root runtime users,
healthy dashboard/account containers, three running v1.0.28 operators with
ready storage, and successful dashboard/API routes. An anonymous account-session
request returned HTTP 401. Live account capabilities confirmed session-bound
TOTP step-up and recovery reset support, with a 300-second proof age.

## Findings against the four assurance gaps

| Area | Current result | Remaining acceptance work |
|---|---|---|
| Security review | Internal source review, fixes and regression evidence are recorded in the [review readiness report](SECURITY_REVIEW_READINESS_2026-10-01.md). | No independent penetration or cryptographic review has occurred. Internal review is useful evidence but cannot independently validate its own scope or conclusions. |
| Enforced MFA | v1.0.28 exposes enforced per-account TOTP policy and session-bound step-up. Synthetic required-MFA tests passed. | Production reports `mfa_required_by_default=false`; the policy scope is `per_account_explicit_enable`. The production database had zero required-MFA policies, one TOTP credential and zero WebAuthn credentials. Enrollments and recovery-code custody must precede a policy rollout to avoid locking users out. |
| Independent recovery custody | Pre- and post-deployment archives, isolated rehearsals, workstation copies and generation-pinned GCS downloads were checksum-verified. | GCS is still in the production project. The workstation copy is not a second administrative domain. No separate administrators, named key custodians, locked retention policy, active schedule/alert path or witnessed clean-machine ceremony are in evidence. `custody_activated` remains false. |
| Capacity | The optimized [Linux capacity workflow](https://github.com/samuel-1-avson/CipherVault/actions/runs/36935230687) passed all seven gates on the exact v1.0.28 source. | This is a short closed-loop synthetic run on a 4-vCPU CI runner, not production-equivalent sizing, sustained open-loop load, disk-pressure, multi-region or soak qualification. |

### Capacity details

The CI fixture used isolated local TCP services and synthetic data; it made no
production or cloud calls. The account workload completed 240/240 requests at
concurrency 1/8/32/64, with p99 latency of 5.69/47.85/140.00/275.73 ms. At
concurrency 64 it delivered 397 successful requests/second. A separate synthetic
required-MFA account completed 120/120 reads at concurrency 8, p99 73.79 ms;
a new primary-authenticated session without factor proof received HTTP 404 and
no secret value. The 128-write, 1 MiB operator overload phase accepted 95 and
rejected 33 with capacity responses; all 429 stored objects passed CID integrity
checks, with zero unexpected failures. SQLite integrity was `ok`, and four
concurrent backups each checked one audit chain. All seven configured workflow
gates passed.

This validates the release build under the test's limits, not a production
ceiling. The longer local measurements in the [capacity report](CAPACITY_VALIDATION_2026-10-01.md)
and the CI numbers both show the account SQLite connection/global mutex as a
scaling concern. Keep SQLite `FULL` durability. Profile lock wait and realistic
audit-history growth before considering bounded database workers or a different
storage architecture.

## Recovery evidence

Both workstation directories are outside OneDrive. Every item, including
directories, artifacts, download copies and transfer receipts, had a protected
Windows DACL granting only the current user full control. Local archives were
validated without extraction or opening SQLite as a database; each downloaded
GCS object matched its local SHA-256 and its current generation.

| Backup | Run ID | Local archive SHA-256 | GCS archive generation | Result |
|---|---|---|---:|---|
| Pre-deploy account archive | `pre-v1.0.28-20261002T001415Z` | `a440a90945b6301295d925dd7561b96abfb78daf4404323a10deaaf5f62786c2` | `1790900147875282` | Verified archive, receipt, rehearsal and stopped SQLite snapshot; 15 protected local paths. |
| Post-deploy account archive | `post-v1.0.28-20261002T003908Z` | `679d4a9a1132568039713207385c64a1810bf57bd250c5e78674933a52ba123d` | `1790901624414334` | Verified archive, receipt and rehearsal; 12 protected local paths. |

The pre-deploy archive and raw stopped-database snapshot remain in
`%LOCALAPPDATA%\CipherVault-Recovery-pre-v1.0.28-20261002T001415Z-e74ddb0ee2e7`.
The post-deploy copy remains in
`%LOCALAPPDATA%\CipherVault-Recovery-post-v1.0.28-20261002T003908Z-c0a844a817d7`.
The pre-deploy GCS prefix is
`gs://ciphervault-account-backups-108687509435/releases/v1.0.28/pre-v1.0.28-20261002T001415Z/`;
the post-deploy prefix is
`gs://ciphervault-account-backups-108687509435/releases/v1.0.28/post-v1.0.28-20261002T003908Z/`.
Receipts list all object generations and hashes. Keys were excluded from the
archives and supplied separately to the isolated restore rehearsal.

The post-deployment production database contained four accounts, three devices,
eight recovery codes, two sessions, one TOTP credential and no WebAuthn
credentials. It contained zero secrets, secret versions or audit events, so the
rehearsal does not prove recovery of retained secret values or an audit chain.
The copied TOTP seed decrypted, both copied sessions were revoked, and the
production source was not modified. The rehearsal used the active host key files;
those keys have not been placed under separate custodian control.

The post-deploy transfer helper returned a nonzero exit **after writing** its
receipt. I independently rechecked all three local artifacts, all three
downloaded copies, all protected ACLs and the current GCS generations; those
checks passed. The helper's final status/exit behavior is a tooling defect to
fix and test before relying on it as an unattended success signal. No cloud
objects or recovery files were overwritten to resolve it.

## Strengths, disadvantages and recommendations

**Strengths:** the release is signature-verified and digest-pinned; account
authorization/MFA capabilities have negative and concurrency tests; the operator
rejects excess storage work rather than growing an unbounded queue; the deployed
fleet and recovery archives have concrete post-change evidence; and release
package hashes now have automated synchronization checks.

**Disadvantages and bottlenecks:** production MFA is not mandatory for existing
accounts; backup and key control share production-project administration; a
single SQLite connection/global mutex serializes account work; production SLO and
soak limits have not been established; account restore evidence contains no
retained secret values; and administrative merge exceptions do not supply peer
review.

**Recommended next work, in order:**

1. Arrange MFA enrollment and recovery-code handling for every production owner,
   then enable required policy in a controlled, monitored rollout. Do not flip a
   global default while most users lack an enrolled factor.
2. Establish recovery in a separately administered cloud project/account with
   named backup and offline key custodians. Review IAM independently, set an
   approved retention period, prove restore from a clean machine and only then
   activate the schedule and failure/staleness alerts.
3. Define production request mix, SLO, RPO and RTO. Run an isolated canary sized
   like production with open-loop traffic, realistic growing audit history,
   rotation/materialization/backup overlap, disk pressure and a multi-hour soak.
4. Commission an independent security/cryptography review before describing the
   product as independently audited or expanding sensitive multi-tenant use.
5. Fix and regression-test the recovery transfer helper's post-receipt exit
   handling; measure SQLite mutex wait time before changing the database design.
6. Defer unrelated chain/economic features until custody, MFA enrollment and
   operational capacity have owners and acceptance evidence.

## Links and retained evidence

- [v1.0.28 release run](https://github.com/samuel-1-avson/CipherVault/actions/runs/36935872841)
- [v1.0.28 isolated capacity run](https://github.com/samuel-1-avson/CipherVault/actions/runs/36935230687)
- [PR #20 package-manifest fix](https://github.com/samuel-1-avson/CipherVault/pull/20)
- [Recovery custody design and remaining gates](RECOVERY_CUSTODY_2026-10-01.md)
- [Internal security review package](SECURITY_REVIEW_READINESS_2026-10-01.md)
- [Capacity validation report](CAPACITY_VALIDATION_2026-10-01.md)
