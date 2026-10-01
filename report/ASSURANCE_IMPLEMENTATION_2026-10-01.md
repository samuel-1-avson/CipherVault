# CipherVault assurance improvements — 1 October 2026

## Outcome

This development cycle implements account MFA enforcement, corrects defects found
by the requested internal security audit, adds a tested recovery-custody runner
and provisioning plan, and measures account/operator behavior over real isolated
TCP connections. The production baseline remains v1.0.26. Source changes and
local validation do not establish a new production rollout.

The user selected an **internal audit** and delegated the recovery architecture
choice. The recommended destination is a separately administered GCP project,
with production restricted to uploading encrypted archives and custodians
responsible for verification and historical recovery keys.

| Requested area | Delivered | Current acceptance limit |
|---|---|---|
| Security review | Internal source review, corrective changes, regression tests, and an allowlisted source evidence builder | Internal review is complete for the recorded scope; independent assurance remains absent by the chosen review approach. |
| Enforced MFA | Durable per-account policy, fresh session-bound TOTP verification after key/passkey authentication, guarded mutations and scoped credentials, dashboard controls, and emergency recovery | Existing accounts remain optional until their owners complete enrollment, preserve recovery codes, and explicitly enable the policy. No live account policy was changed. |
| Independent recovery custody | Backup/archive/restore checks, private outputs, destination checks, stale/failure monitoring, inactive scheduler templates, and a separate-administration provisioning plan | Real independent administrators, backup/key custodians and custody evidence are still required. No cloud IAM, retention lock, key transfer or scheduler was activated. |
| Capacity validation | Repeatable local TCP workload, concurrent backups, byte-verified operator storage, required-MFA reads, overload accounting, and a manual optimized Linux CI workflow | Local Windows debug measurements identify bottlenecks; production-equivalent capacity and sustained arrival-rate/soak qualification remain open. |

## Changes and why they matter

Required-MFA accounts now demand a fresh primary authentication and a fresh TOTP
proof for protected operations. Proof belongs to one session and one active
authenticator; handoffs and new logins do not inherit it. Derived scope tokens bind
the exact proof present at issuance. Verification consumes codes and rechecks
rate-limit state within an immediate transaction. Sensitive mutations revalidate
the current session, policy and role under the connection used for storage.

Activation requires retained unused recovery codes. Disabling normally requires
valid primary/factor proof; emergency reset consumes an unused recovery code,
revokes the factor and all sessions, and returns no authenticated replacement.
The existing lost-key recovery path remains deliberate: a protected recovery-code
sheet can authorize replacement-device enrollment and, with a second unused code,
MFA reset. Codes from that sheet are one recovery authority, not independent
factors. See [the MFA runbook](../docs/ENFORCED_MFA.md).

Sealed-box encryption/decryption now rejects non-contributory X25519 inputs before
deriving encryption keys. Saturated operator HTTP disk workers return capacity
503 responses instead of admitting an unbounded queue of waiting operations.
Invitation acceptance also uses the correct source timestamp column, fixing a
previously unexercised server error. The dashboard account proxy rejects
credential-body redirects. See [the internal audit](SECURITY_REVIEW_READINESS_2026-10-01.md).
Content-addressed object uploads retry temporary capacity 503 responses up to
three attempts with bounded backoff. Integration tests verified that replication
and partial-log healing still reach quorum after operator admission changed.

Recovery archives and keys have separate custody paths. The tooling rejects weak
destination/privacy/retention declarations, expired custody records, unsafe
paths, unexpected archive entries, changed downloads and stale or interrupted
evidence. Hashes establish integrity; unsigned custody records and direct bucket
IAM inspection cannot prove independent administration or authenticity.
See [the custody implementation ledger](RECOVERY_CUSTODY_2026-10-01.md) and
[the operational runbook](../docs/INDEPENDENT_RECOVERY_CUSTODY.md).

## Capacity findings

The final mixed account workload fell from 165.72 successful requests/second at
concurrency 8 to 119.57 at concurrency 64; p99 rose from 110.05 to 1,137.56 ms.
The single SQLite connection and global mutex remain a scaling limit. Preserve
the current durability guarantees while measuring lock wait, bounded admission,
blocking execution, transaction lengths and audit-history growth.

The updated operator rejects excess admitted disk work with HTTP 503 and recovers
after pressure subsides. Measured stored objects retain valid SHA-256 CIDs.
This corrects the waiting-queue defect; connection/body memory limits and
sustainable accepted throughput need further measurement. A p99 that includes
fast rejections is not a successful-work capacity claim.

The MFA workload uses actual device enrollment/login, recovery-code generation,
authenticator confirmation, second-factor verification and policy activation.
Authorized value reads succeed; a fresh device login without factor proof is
denied. All 1,080 account requests succeeded; the MFA phase's p99 was 39.38 ms.
The final overload burst accepted 26 of 128 writes and rejected 102 with capacity
503; all 349 stored objects verified. Exact binaries and qualifications are recorded in
[the capacity report](CAPACITY_VALIDATION_2026-10-01.md) and its JSON evidence.

## Integrated verification

| Check | Result |
|---|---|
| Workspace unit, integration and documentation tests | 843 passed, 0 failed, 3 existing tests ignored across 81 result groups. |
| Final account/storage library verification | 155 account and 67 storage tests passed; 1 existing account load test ignored. Rechecked after the final request-build and lint corrections. These are repeats, not additional tests added to the workspace total. |
| Final concurrent replication verification | Both quorum/order and partial-recovery-log healing tests passed. |
| Strict Clippy | `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` passed. |
| Rust 1.89 compatibility | `cargo +1.89.0 check --workspace --all-targets --locked --offline` passed. |
| Custody/provisioning/receiver regressions | 30 passed, 0 failed, 0 skipped, including a real account CLI backup/isolated restore and Windows private-output permissions. |
| Source evidence builder | 7 passed, 0 failed, 1 skipped because this workstation cannot create a symlink; its actual Windows junction rejection test passed. |
| Capacity harness tests | 3 passed; final isolated service workload passed all recorded gates. |
| Dashboard and proxy | JavaScript syntax, DOM/audit regressions, actual Chrome CSP run, container contract, MFA forwarding and credential-redirect regressions passed. Rust proxy tests are included in the workspace total. |
| Installer trust regression | 14 signature/bootstrap cases passed. |
| Artifact checks | Changed-file credential-pattern check found no high-confidence token/private-key patterns; 9 JSON files parsed, and local Markdown links resolved. This is a scoped pattern check, not proof that arbitrary secrets cannot exist. |

The three existing ignored tests are the scoped load gate, push throughput bench
and ten-node chaos gate. The new capacity harness supplies separate measured load
evidence; it does not silently count those ignored tests as passing.

Detailed scoped results and commands are retained in the linked implementation
ledgers. Synthetic backup/capacity fixtures use isolated temporary databases and
storage; they do not access the live account database or send production traffic.

## Remaining work in order

1. Review the integrated change and run the existing cross-platform CI and minimum
   supported Rust checks on its final commit before release promotion.
2. Enroll and explicitly enable required MFA for every relevant human production
   account. The capability's existence is not evidence that live accounts enforce it.
3. Assign real independent backup and key custodians, complete the provisioning
   configuration, verify inherited/group IAM separation, and perform a protected
   key-custody ceremony and independently witnessed clean-machine restore.
4. Run the optimized workload on an isolated production-equivalent host with an
   agreed successful-operation SLO, expected database/audit size and sustained
   arrival rate. Complete restart, disk-pressure and several-hour backup/rotation
   overlap tests before publishing production capacity limits.
5. Continue the existing v1 privacy and recovery-generation protocol work. Default
   v1 candidate confirmation/history exposure and same-key recertification limits
   remain open; these improvements do not resolve those protocol findings.

The prior [7.6/10 reassessment](PROJECT_REASSESSMENT_2026-10-01.md) remains the
dated baseline. This report does not raise the rating based on unactivated
controls or unverified operational custody/capacity claims.
