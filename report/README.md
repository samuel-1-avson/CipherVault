# 📊 CipherVault Evidence & Design Specs

This directory publishes the curated evidence that current CipherVault documents, code comments and tooling cite: audit and remediation ledgers, deployment and capacity evidence, release test evidence, and the scoped-secrets design specs.

Dated working notes (ratings, status reports, plans, outreach drafts, rollout logs) are kept locally by the maintainers and are not published here. `.gitignore` allow-lists exactly the files below; to publish another report, add an explicit `!/report/<name>` line and list it in this index.

For current behavior and guarantees, start with [`docs/CURRENT_SECURITY_GUARANTEES.md`](../docs/CURRENT_SECURITY_GUARANTEES.md). Reports describe the version and date they record and do not override it.

---

## 🔎 Audit, Remediation & Deployment Evidence

| Report | Date | Scope |
|---|---|---|
| [**`PROJECT_AUDIT_2026-09-30.md`**](./PROJECT_AUDIT_2026-09-30.md) | 2026-09-30 | Whole-project audit: authorization and recovery findings, bottlenecks, recommendations and local verification. |
| [**`AUDIT_REMEDIATION_2026-09-30.md`**](./AUDIT_REMEDIATION_2026-09-30.md) | 2026-09-30 | Implementation and verification ledger for audit fixes, added features, rollout requirements and outstanding assurance. |
| [**`DEPLOYMENT_2026-09-30.md`**](./DEPLOYMENT_2026-09-30.md) | 2026-09-30 | 1.0.26 release, deployment evidence, backups, rollout gates and remaining limitations. |
| [**`PROJECT_REASSESSMENT_2026-10-01.md`**](./PROJECT_REASSESSMENT_2026-10-01.md) | 2026-10-01 | Post-remediation project report (assessed release v1.0.26). |
| [**`SECURITY_REVIEW_READINESS_2026-10-01.md`**](./SECURITY_REVIEW_READINESS_2026-10-01.md) | 2026-10-01 | Internal security audit: scope, outcome and handoff readiness. |
| [**`ASSURANCE_IMPLEMENTATION_2026-10-01.md`**](./ASSURANCE_IMPLEMENTATION_2026-10-01.md) | 2026-10-01 | Assurance improvements: account MFA enforcement and corrected defects. |
| [**`RECOVERY_CUSTODY_2026-10-01.md`**](./RECOVERY_CUSTODY_2026-10-01.md) | 2026-10-01 | Recovery custody implementation and remaining evidence. |
| [**`CAPACITY_VALIDATION_2026-10-01.md`**](./CAPACITY_VALIDATION_2026-10-01.md) | 2026-10-01 | Capacity validation assessment and gate results. Raw runs: [`capacity-final`](./capacity-final-2026-10-01.json), [`capacity-fresh-mfa`](./capacity-fresh-mfa-2026-10-01.json), [`capacity-http-admission`](./capacity-http-admission-2026-10-01.json), [`capacity-legacy-baseline`](./capacity-legacy-baseline-2026-10-01.json). |
| [**`EXTERNAL_REHEARSAL_PROOF_2026-09-20.md`**](./EXTERNAL_REHEARSAL_PROOF_2026-09-20.md) | 2026-09-20 | Testnet proof: fleet seed rotation and 3/3 probation join ceremony from a clean external host. |
| [**`CIPHERCHAIN_ROTATION_DRILL_EVIDENCE_2026-11-08.md`**](./CIPHERCHAIN_ROTATION_DRILL_EVIDENCE_2026-11-08.md) | 2026-11-08 | CipherChain genesis ceremony and validator rotation drill evidence. |
| [**`CIPHERVAULT_SOVEREIGN_CHAIN_ARCHITECTURE.html`**](./CIPHERVAULT_SOVEREIGN_CHAIN_ARCHITECTURE.html) | 2026-11-07 | Architecture page for the sovereign CipherChain ledger (v1.0.29; open in a browser). |
| [**`TEST_EVIDENCE_v1.0.31.md`**](./TEST_EVIDENCE_v1.0.31.md) | 2026-11-08/09 | Test evidence for the v1.0.31 release. |
| [**`OPERATOR_AUDIT_2026-11-08.md`**](./OPERATOR_AUDIT_2026-11-08.md) | 2026-11-08 | Operator service audit (`services/operator` source plus `dist/` drift). See also the [operator architecture page](../operator-architecture.html). |
| [**`OPERATOR_REMEDIATION_PLAN_2026-11-08.md`**](./OPERATOR_REMEDIATION_PLAN_2026-11-08.md) | 2026-11-08 | Remediation plan and status for the operator audit. |

`scripts/security/build_review_pack.py` bundles the 2026-09-30 and 2026-10-01 reports and the four capacity JSON files above into the external review pack; do not rename them without updating that script.

---

## 🔐 Scoped-Secrets Design Specs (v2.5.0, dated 2026-09-27)

These are the design specifications written for the scoped-secrets feature. Their content is marked `[Proposed design]`; the shipped behavior is described in [`docs/CURRENT_SECURITY_GUARANTEES.md`](../docs/CURRENT_SECURITY_GUARANTEES.md) and [`services/account/README.md`](../services/account/README.md).

| Specification | Scope |
|---|---|
| [**`SCOPED_SECRETS_TARGET_ARCHITECTURE.md`**](./SCOPED_SECRETS_TARGET_ARCHITECTURE.md) | Target architecture for hierarchical, resource-scoped secrets. |
| [**`SCOPED_SECRETS_DATABASE_SPEC.md`**](./SCOPED_SECRETS_DATABASE_SPEC.md) | Database schema, constraints, indexes and transactions. |
| [**`SCOPED_SECRETS_API_SPEC.md`**](./SCOPED_SECRETS_API_SPEC.md) | REST endpoints, auth matrix and rate limits. |
| [**`SCOPED_SECRETS_SECURITY_THREAT_MODEL.md`**](./SCOPED_SECRETS_SECURITY_THREAT_MODEL.md) | Trust boundaries, threat catalogue, invariants and test gates. |
| [**`SCOPED_SECRETS_IMPLEMENTATION_TASKS.md`**](./SCOPED_SECRETS_IMPLEMENTATION_TASKS.md) | Implementation task breakdown mapped to repository paths (referenced from `crates/format` and `services/account`). |

---

## 🎬 Submission & Distribution

| File | Purpose |
|---|---|
| [**`HACKATHON_VIDEO_SCRIPT.md`**](./HACKATHON_VIDEO_SCRIPT.md) | Script for the hackathon film "Sealed" (two cuts, one source) and the claims it makes and deliberately does not make. Film source: [`ciphervault-film/`](../ciphervault-film/). |
| [**`plugin-catalog-ciphervault.yaml`**](./plugin-catalog-ciphervault.yaml) | Plugin catalog entry for CipherVault (repository and pinned commit). |
