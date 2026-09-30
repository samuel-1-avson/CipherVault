# CipherVault 1.0.26 release and deployment ledger

Date: 30 September 2026 (UTC/Africa/Accra). User authorized finishing remaining
remediation, committing, pushing and deploying. This ledger records actual evidence;
pending steps are not successful deployment claims.

## Starting state

- Repository baseline: `a9df97dfee9ae64f9c82ce48d9c4ddc67176dc78` on protected `main`.
- Dashboard/account: 1.0.25; dashboard digest
  `sha256:72e4c78a3e74f41670c2d0d838600b302f05a04a73514d605a3c4059e4f1d548`;
  account digest `sha256:9b218c124de3b872ac72405a2797d94af7828b170a4e48b434414eae99742f03`.
- All three storage operators: 1.0.21, digest
  `sha256:524ae05ef2bab9abce8f00f625c39bd71c5ba37bf5869fd2a665f7fd09ab1155`.
- All operator health endpoints ready; strict authentication and enrollment enabled.
  Operator identities independently checked through authenticated administration;
  signing keys and P2P settings are retained during promotion.
- Hosted DB contains four accounts, three devices, one TOTP credential and two
  sessions, with no scoped-secret versions. Counts were obtained without reading
  or printing credential values. Synthetic regressions cover retained secrets.

## Final local verification

The final Windows workspace run passed **826 tests, 0 failed, 3 existing ignored**
across 81 result blocks. Formatting, strict all-target Clippy, Rust 1.89 workspace/
all-target check, real Chromium strict CSP, DOM/landing/container checks, 14
installer signature cases, 30 cloud key-bootstrap cases and release packaging
regressions pass. Dependency audit reports zero known vulnerabilities with the
explicit time-limited `paste` maintenance exception. Logs are retained under the
ignored `.agents/audit-2026-09-30/` directory.

## Publication and rollout gates

Protected-branch CI, signed V2 release manifests, independent
image-signature verification, protected account restore rehearsal, health-gated
rolling operator promotion and verified dashboard build version are pending.

All four recovery disk snapshots reached `READY` before rollout:
`cv-audit-20260930-web`, `cv-audit-20260930-op1`, `cv-audit-20260930-op2`,
`cv-audit-20260930-op3`. These are retained for rollback.
Disk snapshots alone are not an application-consistent backup certificate.

A dedicated off-VM bucket, `gs://ciphervault-account-backups-108687509435`,
was created with US multiregion placement, uniform bucket-level access,
public-access prevention enforced and object versioning enabled. It remains
in the same GCP project; this is not independent organizational key custody.

## Remaining assurance boundaries

Default production writes remain v1. Independent external review is required
before enabling v2 writing; F13/F21 remain open for default v1 captures and old
history. No external cryptographic audit or physical-token ceremony is claimed.
Enforced MFA and verified CI workload identity, provider/KMS adapters, retention/
compaction and production capacity characterization remain tracked work.

The account rehearsal uses independently supplied KEK/TOTP files; keys are never
included in the DB backup or this report. The remote plaintext drill uses existing
local protected epoch keys and therefore does not certify clean-machine offline
recovery. Synthetic tests do not establish future operator availability.

See [remediation](AUDIT_REMEDIATION_2026-09-30.md),
[original audit](PROJECT_AUDIT_2026-09-30.md), and
[release notes](../dist/RELEASE_NOTES.md).

One synthetic failed-test fixture remains in the local temporary folder because automatic approval review rejected cleanup with "blocked by policy". An operator identity inspection initially created an unused nested identity; only that newly created file/empty directory were removed after exact path, timestamp and contents checks. The active production identity remained unchanged.
