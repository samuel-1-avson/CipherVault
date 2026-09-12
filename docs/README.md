# CipherVault — design review pack

**CipherVault — Decentralized, encrypted version control for confidential files.** Version 0.1 · 12 September 2026 · Documentation and research only. No product has been implemented, audited, deployed, or benchmarked by this task.

The product backs up explicitly selected confidential development files before the original machine disappears. A developer can push versioned, locally encrypted snapshots and restore them on a replacement machine using an independently stored recovery kit. Git remains responsible for source code; this product covers files Git intentionally leaves out.

The motivating incident was a lost external disk: GitHub restored source code, but ignored environment files and private keys had no recoverable copy. Recovery cannot recreate keys that were never backed up. A newly generated blockchain key does not recover the old key's authority.

## Recommendation to review

Build a standalone Rust CLI and background agent, with libsodium authenticated encryption performed before any network upload. Store immutable ciphertext and all recovery metadata on **three independently administered Kubo/IPFS operators**, using direct authenticated HTTPS interfaces. Use **Arbitrum One**, an existing Ethereum rollup, solely for asynchronous checkpoint commitments. Start chain integration on Arbitrum Sepolia; do not create a blockchain or token. Use an optional replaceable coordinator for billing, scheduling, and discovery assistance. A recovery kit and direct operator access must suffice when that coordinator has disappeared.

These are provisional engineering decisions, not claims that the assembled system is production ready. Three processes run by one company do not meet the independence requirement. The MVP needs operators who can actually offer the proposed retention and recovery protocol; procuring and testing them is a release dependency.

The highest priority demonstration is deliberately small: back up a synthetic `.env`, a synthetic key file, and a few binary files; destroy the original machine state; take the coordinator and one operator offline; restore exact bytes on a clean machine using only the recovery kit and independently reachable services. Pass this before adding a GUI, marketplace, or social recovery.

## Reading order

| Document | Review purpose |
|---|---|
| [01 — Product and requirements](01-product-and-requirements.md) | User experience, scope, assumptions, acceptance criteria |
| [02 — Technology decisions](02-technology-decisions.md) | Chain/storage comparison, chosen stack, residual trust |
| [03 — Security and recovery](03-security-and-recovery.md) | Threat model, key hierarchy, device-loss procedure, limitations |
| [04 — Architecture and storage](04-architecture-and-storage.md) | Data flow, independence, retention, discovery, repair |
| [05 — Protocol and interfaces](05-protocol-and-interfaces.md) | Objects, API, CLI, consistency, contract scope, module structure |
| [06 — Operations, performance and costs](06-operations-performance-costs.md) | Provisional SLOs, runbooks, capacity and cost model |
| [07 — Delivery and review gates](07-delivery-and-review-gates.md) | Phases, research spikes, tests, decisions required |
| [08 — Sources and evidence](08-sources-and-evidence.md) | Primary sources checked, local context, evidence boundaries |

## Non-negotiable design invariants

1. Plaintext and decryption keys never reach storage operators, coordinator, public chain, logs, telemetry, or Git.
2. Wallet authentication, payment authority, device write authority, and decryption are separate capabilities.
3. A successful local snapshot is not a remote backup. The UI always shows durability, retention, integrity-check time, and anchoring separately.
4. Every retained snapshot must include recoverable manifests, envelopes, authorization history, and locator metadata as well as file chunks.
5. Loss of all decryption/recovery material is unrecoverable. Loss of all ciphertext copies is also unrecoverable. No chain can change either fact.
6. Recovery works without the original device, its OS account, its wallet session, or the product company's database.
7. Old ciphertext may survive deletion; rotating a key cannot retroactively revoke plaintext already disclosed or old keys already copied.

## Decisions versus unresolved work

The stack, three-copy storage layout, offline recovery kit, immutable snapshots, and asynchronous chain anchoring are selected for the proposed MVP. Exact library versions, operator selection, privacy settings, economics, contract deployment addresses, and production SLO commitments remain unapproved. Optional threshold guardians, permissionless operator admission, and team sharing are later projects with separate security reviews.

The most consequential user decisions are retention duration and budget, whether storing recoverable private keys is appropriate for the intended audience, acceptable metadata exposure, and willingness to maintain two geographically separate recovery-kit copies. See [the decision register](07-delivery-and-review-gates.md#decisions-for-the-product-owner).

This product is separate from Chain Registry. A later integration may show backup status or link a repository locally, but must not send secrets into CREG's package analysis or validator pipeline.
