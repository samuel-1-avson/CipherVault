# 🏛️ CipherVault Documentation Archive

This directory preserves the historical Requests for Comments (RFCs), completed exploratory spikes and decision packets behind CipherVault's architecture, for design and cryptographic provenance.

> [!NOTE]
> The documents in this directory are preserved strictly for historical context. For current, authoritative system documentation, refer to the [**Master Documentation Hub**](../README.md). Dated audits, rollout logs, status reports and finished plans are working notes: they are kept by the maintainers locally and are not published in this repository.

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

---

### 3. Historical Drills
Live-fire drill procedure and evidence:

| Document | Historical Subject |
|---|---|
| [`NAT_HOLEPUNCH_DRILL.md`](./NAT_HOLEPUNCH_DRILL.md) | Containerized NAT traversal and DCUtR relay hole-punch drill evidence. |
