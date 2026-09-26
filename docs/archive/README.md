# 🏛️ CipherVault Documentation Archive

This directory permanently preserves historical Requests for Comments (RFCs), early engineering milestones, completed exploratory spikes, point-in-time security audits, and prior rollout notes for full architectural and cryptographic provenance.

> [!NOTE]
> The documents in this directory are preserved strictly for historical context. For current, authoritative system documentation, refer to the [**Master Documentation Hub**](../README.md).

---

## 📑 Archive Catalog

### 1. Foundational RFC Specifications (Phase 01 – Phase 10)
Early design RFCs drafted during initial project inception:

| Document | Historical Subject |
|---|---|
| [`01-product-and-requirements.md`](./01-product-and-requirements.md) | Initial product scope, threat assumptions, and acceptance criteria. |
| [`02-technology-decisions.md`](./02-technology-decisions.md) | Preliminary trade-off analysis between storage backends, L2 rollups, and local keystores. |
| [`03-security-and-recovery.md`](./03-security-and-recovery.md) | Foundational threat model, adversary assumptions, and recovery primitives. |
| [`04-architecture-and-storage.md`](./04-architecture-and-storage.md) | Early storage operator topology and chunk retention model. |
| [`05-protocol-and-interfaces.md`](./05-protocol-and-interfaces.md) | Preliminary CBOR wire schemas and CLI command definitions. |
| [`06-operations-performance-costs.md`](./06-operations-performance-costs.md) | Early cloud capacity projections and hosting cost estimations. |
| [`07-delivery-and-review-gates.md`](./07-delivery-and-review-gates.md) | Pre-production delivery milestones and verification checklists. |
| [`08-sources-and-evidence.md`](./08-sources-and-evidence.md) | Primary technical literature, standards citations, and cryptographic references. |
| [`09-yubikey-hsm-guide.md`](./09-yubikey-hsm-guide.md) | Initial hardware token specification (superseded by [`docs/SYSTEM_WORKFLOW.md`](../SYSTEM_WORKFLOW.md)). |
| [`10-recovery-milestone.md`](./10-recovery-milestone.md) | Verification record of the Phase 10 clean-machine recovery drill. |

---

### 2. Completed Research Spikes & Decision Records
Exploratory engineering investigations whose outcomes are codified in current Architecture Decision Records (ADRs):

| Document | Outcome & Codification |
|---|---|
| [`D6_OBJECT_STORE_SPIKE.md`](./D6_OBJECT_STORE_SPIKE.md) | Object store spike measuring `redb` vs file baseline at 1M objects. **Verdict: Adopt `redb`** (codified in [ADR-004](../adr/004-redb-store.md)). |
| [`D7_ERASURE_SPIKE.md`](./D7_ERASURE_SPIKE.md) | Reed-Solomon erasure coding spike measuring `reed-solomon-simd`. **Verdict: Decline erasure coding for 3-node fleet; retain 3x full replication** (codified in [ADR-005](../adr/005-decline-erasure.md)). |
| [`DON_ECONOMICS_DECISION.md`](./DON_ECONOMICS_DECISION.md) | Barter-economics vs token staking evaluation. **Verdict: Self-issued barter write vouchers** (codified in [ADR-002](../adr/002-voucher-barter.md)). |
| [`DON_SPEC_CORRECTIONS.md`](./DON_SPEC_CORRECTIONS.md) | Dated corrections to parent DON architecture (folded into [DON v2.0 Spec](../DECENTRALIZED_ARCHITECTURE_SPEC.md)). |
| [`SPLIT_PLAN.md`](./SPLIT_PLAN.md) | Crate and service separation roadmap (completed across 11 workspace crates). |

---

### 3. Historical Drills & Failure Injection Logs
Live-fire drills and failure injection runs:

| Document | Historical Subject |
|---|---|
| [`NAT_HOLEPUNCH_DRILL.md`](./NAT_HOLEPUNCH_DRILL.md) | Containerized NAT traversal and DCUtR relay hole-punch drill evidence. |
| [`CHAOS_LOG.md`](./CHAOS_LOG.md) | Failure injection execution log across multi-node test harnesses. |
| [`CONFIRM_FIRST_VERDICTS_2026-09-18.md`](./CONFIRM_FIRST_VERDICTS_2026-09-18.md) | Transport-conformance and naming drift audit resolution memo. |

---

### 4. Historical Security Audits & Rollout Snapshots
Point-in-time security evaluations and release transition logs:

| Document | Date | Scope & Subject |
|---|---|---|
| [`CIPHERVAULT_AUDIT_2026-09-12.md`](./CIPHERVAULT_AUDIT_2026-09-12.md) | 2026-09-12 | Pre-production security audit (all findings remediated in v1.0.0). |
| [`RELEASE_READINESS_2026-09-13.md`](./RELEASE_READINESS_2026-09-13.md) | 2026-09-13 | Release readiness evaluation snapshot. |
| [`WEB_DASHBOARD_EXPLORER_AUDIT_2026-09-13.md`](./WEB_DASHBOARD_EXPLORER_AUDIT_2026-09-13.md) | 2026-09-13 | Web dashboard and secrets explorer security audit. |
| [`OPERATORS_AUDIT_2026-09-14.md`](./OPERATORS_AUDIT_2026-09-14.md) | 2026-09-14 | Storage operator service security audit. |
| [`WEB_DASHBOARD_EXPLORER_IMPLEMENTATION_PROGRESS_2026-09-14.md`](./WEB_DASHBOARD_EXPLORER_IMPLEMENTATION_PROGRESS_2026-09-14.md) | 2026-09-14 | Web UI implementation progress snapshot. |
| [`PRODUCTION_ROLLOUT_2026-09-15.md`](./PRODUCTION_ROLLOUT_2026-09-15.md) | 2026-09-15 | Production rollout and package staging notes. |
| [`PROJECT_AUDIT_2026-09-16.md`](./PROJECT_AUDIT_2026-09-16.md) | 2026-09-16 | Whole-project audit review snapshot. |
| [`PROJECT_REPORT.md`](./PROJECT_REPORT.md) | 2026-09-12 | Initial consolidation report (unified into `SYSTEM_WORKFLOW.md`). |
| [`LANDING_PAGE_PLAN_AND_REPORT.md`](./LANDING_PAGE_PLAN_AND_REPORT.md) | 2026-09-24 | Landing page strategic architecture and benchmark report. |
