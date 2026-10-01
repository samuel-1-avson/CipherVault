# CipherVault assurance release and deployment ledger

Date: 1 October 2026 (UTC / Africa/Accra)

## Current status

Deployment is held. Production remains on v1.0.26. PR #16 passed all checks and
merged as `d91656a7b17e9c57b740e44a2a7441d7e0e5ef8f`; its v1.0.27 tag passed the
mandatory pre-release gate. Publication was stopped after the optimized capacity
run exposed an incomplete first account backup. No v1.0.27 production promotion
occurred. Corrective work and verification are in progress.

The user authorized deployment and a one-time administrator merge of PR
[#16](https://github.com/samuel-1-avson/CipherVault/pull/16) after all checks pass.
The repository ruleset requires one approving review; neither review bot supplied
one, and the PR author is the only listed repository collaborator. This exception
does not establish peer review or independent security assurance.

## Release scope

The candidate adds explicit per-account MFA, fresh session/factor-bound proofs,
guarded account mutations and scoped credentials, emergency recovery reset,
non-contributory X25519 rejection, invitation timestamp correction and protection
against credential-body proxy redirects. Operator disk work has bounded admission,
and immutable object uploads retry temporary capacity 503 responses.

Custody tooling, a separate-administration provisioning plan and inactive
schedulers are included. The manual optimized Linux capacity workflow runs only
against isolated synthetic databases and storage.

No live MFA policy, independent recovery IAM, retention lock, custodian key
transfer or scheduler is activated by this deployment.

## Release preparation corrections

CI exposed concurrent initialization of the MFA limiter outside its transaction.
Both MFA ceremonies now initialize/check the limiter inside their immediate
transaction. The regression sends sixteen requests per ceremony through two
independent SQLite connections and requires exactly five 401s and eleven 429s.
Local account tests passed 155 tests with one existing ignored load test; strict
account Clippy passed.

The web rollback now stops account writers and verifies the real database before
downgrading to a legacy account image. Required policy or failed verification
blocks downgrade and preserves the candidate configuration. Actual SQLite cases
cover legacy, optional, required, unknown, malformed and corrupt policy/database
states; POSIX cases reject file and ancestor symlinks. The macOS fixture uses a
canonical temporary directory, while production retains strict path checks.

The browser harness drains final stdout, reports wall-clock timeout explicitly
and allows sixty seconds in CI. All CSP and MFA assertions remain enabled.
An existing crypto timing regression now uses opaque operands, warmup, balanced
interleaved samples and nine-sample medians. All three input pairs retain the
original ratio gate. Debug and optimized runs passed all four arithmetic/timing
tests, and strict targeted Clippy passed. This remains a coarse regression check,
not proof of constant-time execution.

## Optimized Linux validation and publication hold

The first optimized [capacity run](https://github.com/samuel-1-avson/CipherVault/actions/runs/36907279445)
measured the exact merged source on a four-CPU, approximately 16 GB GitHub Linux
host. All 1,080 account operations succeeded, including 120 required-MFA reads;
fresh primary authentication without factor proof returned 404 without a value.
Account p99 at concurrency 1/8/32/64 was 6.22/36.85/149.02/258.64 ms. The overload
burst accepted 22 writes and rejected 106 with capacity 503; 356 stored CIDs
verified. The default limiter accepted 599 and rejected 41 with HTTP 429.

The overall run **failed** its backup audit gate. Its first backup contained zero
secrets, versions, encryption keys or audit events despite fifty completed secret
creations and successful value reads before backup. Later three backups included
the expected records. Passing load and integrity gates do not excuse that omission.
The release [publication workflow](https://github.com/samuel-1-avson/CipherVault/actions/runs/36907115781)
was cancelled before publication; the v1.0.27 tag is retained and was never promoted.

An isolated Linux reproduction confirmed that native descriptor closes in account
permission hardening release SQLite's POSIX locks. An external connection then
unlinks active WAL/shared-memory files; subsequent writes remain visible to the
original connection while an independent reader/backup sees older main-file data.
SQLite documents this [raw descriptor close hazard](https://www.sqlite.org/howtocorrupt.html)
and its [WAL locking and cleanup rules](https://www.sqlite.org/walformat.html).
The corrective v1.0.28 candidate uses metadata-only path validation and SQLite's
no-follow open flag, preserves private permissions, and adds independent-process
visibility/backup checks. The original Linux regression failed before the fix and
passed afterward, including startup, a second account connection and a same-process
backup. Nine unsafe database/sidecar path cases also passed. Full account tests
passed on Linux (159) and Windows (155), plus the backup/restore CLI integration;
strict account Clippy passed on both platforms. Corrected optimized validation and
cross-platform release CI are pending.

Read-only production inode inspection found that the account process's database,
WAL and shared-memory descriptors all matched linked pathnames: no deleted or
missing live SQLite file was observed. That observation does not prove the
freshness of an earlier backup. Deployment must preserve a fresh consistent
snapshot before stopping the old process.

Failed-run JSON SHA-256:
`55393ee0ea4e6b8c60ca0124e42b3ea9a93631d15057c49e8662482c6e1993dd`.
Account binary SHA-256:
`59696f7435859061eb2b9a173e56e327233c601c95f496e06bf3d4272d42edda`.
Operator binary SHA-256:
`c7fb1395e2b87b320e8162be3c9e5c8e8d763035e8bf412ae61fd6eadb4e0532`.
These are failed-run evidence, not final release digests or production capacity
certification. Sustained SLO and production-equivalent qualification remain open.

The first corrected [optimized run](https://github.com/samuel-1-avson/CipherVault/actions/runs/36919878541)
on source `468eeab9300a0d23c15824d98d770ef0f843929d` passed all seven gates.
Its first backup included all fifty initial secrets and versions, the encryption
key and sixty-five audit events; all four backups verified one audit chain and
overlapped requests. Account p99 at concurrency 1/8/32/64 was
6.20/38.55/145.18/308.04 ms. JSON SHA-256:
`e9571558580ed4173c7350a5910d413d5d94e058bd149bf34a86d5b236039177`.
This confirms the lock correction for the measured workload. Final source still
requires another run after the backup sidecar guards identified during review.
Review required the read-only backup path to share database/WAL/shared-memory/
rollback-journal validation with startup. Regression cases reject unsafe paths
without changing source bytes or external targets. The first macOS CI also found
that an older `VACUUM INTO` test inherited NOFOLLOW while using the system's
`/var` alias; its existing temporary parent is now canonicalized before forming
the new output path. Production link rejection remains enabled.

The next [optimized run](https://github.com/samuel-1-avson/CipherVault/actions/runs/36921149212),
on source `5672b4b12fe44fffd4e5960c5b4846b8ec69d558`, passed all backup and
integrity gates but failed one audit-export response at concurrency sixty-four.
The service verified its chain under one database guard, released it and generated
the JSONL body under another guard. A concurrent append could therefore make the
count/head headers describe an earlier chain than the body. The correction must
hold both one mutex guard and one SQLite read transaction across verification
and export, protecting against both same-process and independent writers.
Failed-run JSON SHA-256:
`63147bdb1590cc5bbd9f9aa2f5db8c7cae160ef71411cc4b5c6212fc96b89c78`.
The gate is retained unchanged; another final-source run is required.

## Pre-deployment account recovery

The exact signed v1.0.26 account image created an online backup with
the production volume mounted read-only. A network-disabled isolated rehearsal
used the existing protected KEK and TOTP key files. It decrypted the retained
authenticator seed and revoked both copied sessions; `production_modified` was
false and `keys_included` was false. The newly discovered lock defect means this
earlier archive alone cannot establish that it contains every live commit; a fresh
snapshot with the corrected image is required before promotion.

Inventory: four accounts, three devices, eight recovery codes, two sessions,
one TOTP credential and zero secret versions. The absence of retained secret
versions limits this production rehearsal; synthetic regressions exercise value
decryption separately.

- VM directory: `/var/lib/ciphervault-recovery-pre-v1.0.27-20261001T171529Z`.
- Protected workstation directory outside OneDrive:
  `C:\Users\samue\AppData\Local\CipherVault\Recovery-20261001-v1.0.27-pre-171529Z`.
- GCS object:
  `gs://ciphervault-account-backups-108687509435/releases/v1.0.27/pre-v1.0.27-20261001T171529Z/account-backup.tar.gz`.
- GCS generation: `1790875614608318`.
- Archive: 14,408 bytes; SHA-256
  `74c8bf6a116e19956d4f9e3764072526ec8b192751334e8402a46816646fc761`.
- Database: 425,984 bytes; SHA-256
  `fcd5db795a7461de26a5dc62f16ee62a6265a5cb8959dfa0c2d75932fed1389b`.

The archive contains only `accounts.sqlite3` and `backup-receipt.json`. Its
create-only upload was downloaded and its checksum matched. Workstation archives
and receipt have verified private ACLs. The actual rehearsal report remains in
the protected VM directory; separate report SCP attempts encountered connection
resets, while archive transfer and verification succeeded.

The bucket has uniform access, public-access prevention, versioning and a
seven-day soft-delete window. It remains in the production GCP project, so this
does not establish independent custody. Receipts/hashes verify corruption and
integrity; they are not publisher authentication or custody certification.

## Remaining operational acceptance

Account owners must enroll, preserve recovery codes and explicitly enable required
MFA. Real independent backup/key custodians, inherited/group IAM separation and a
witnessed clean-machine recovery remain necessary. The selected review is internal.
Production-equivalent SLO, sustained arrival-rate, soak, disk-pressure and rotation
overlap qualification remain open. The account SQLite connection mutex remains a
scaling bottleneck. Shared authentication limiter persistence-error handling also
needs fault-injection review; this release does not claim that coverage.

Default v1 capture/history privacy findings and same-key recovery-generation
limits remain open. v2 writes remain opt-in. The prior dated 7.6/10 project rating
is not raised merely because operational controls exist in source.

See [the assurance implementation report](ASSURANCE_IMPLEMENTATION_2026-10-01.md),
[the MFA runbook](../docs/ENFORCED_MFA.md),
[the custody runbook](../docs/INDEPENDENT_RECOVERY_CUSTODY.md) and
[the capacity report](CAPACITY_VALIDATION_2026-10-01.md).
