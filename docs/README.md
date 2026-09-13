# CipherVault: Master Documentation Hub

**Version:** `v1.0.0` (Production Release)  
**Classification:** Enterprise System Documentation & Reference Manual  
**Repository:** [github.com/samuel-1-avson/CipherVault](https://github.com/samuel-1-avson/CipherVault)

---

## Overview

Welcome to the **CipherVault** technical documentation suite. CipherVault is a zero-knowledge, developer-first secret backup and clean-machine disaster recovery platform engineered in pure Rust and Solidity.

This documentation suite has been organized into **four focused, authoritative manuals** for core engineers, security auditors, and site reliability operators, supported by interactive vector diagrams and preserved historical RFC specifications.

---

## 📚 Core Active Documentation Suite

| Document | Primary Audience | Scope & Topics Covered |
|---|---|---|
| [**`SYSTEM_WORKFLOW.md`**](./SYSTEM_WORKFLOW.md) | **Engineers, Architects, Security Teams** | **Master System Architecture & Operational Workflows**: Complete component architecture, cryptographic key hierarchy, 7 end-to-end workflows (Init, Watch, Push, L2 Rollup, Self-Repair, Disaster Recovery, YubiKey PIV), live GCP multi-region quorum status, crate directory map, and the 10.0/10.0 production readiness scorecard. |
| [**`DEPLOYMENT_RUNBOOK.md`**](./DEPLOYMENT_RUNBOOK.md) | **DevOps, SREs, Infrastructure Engineers** | **Master Production Deployment & Operations Runbook**: Multi-region GCP Compute Engine VPS setup (`e2-micro`, ~$0.97/day), automated one-click provisioning (`deploy-operators.ps1` / `.sh`), teardown scripts, private VPC / on-premise Docker Compose, Caddy reverse proxy hardening, HSTS security headers, rate limiting, and autonomous fleet maintenance. |
| [**`CICD_INTEGRATION.md`**](./CICD_INTEGRATION.md) | **DevOps, Security Engineers, Developers** | **Zero-Disk CI/CD Pipeline Guide**: In-memory secret injection (`ciphervault run`) for GitHub Actions, GitLab CI, and CircleCI. Log masking defense, ephemeral runner hygiene, and zero-disk environment variable security without persistent plaintext `.env` files. |
| [**`CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`**](./CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md) | **Cryptographers, Whitebox Auditors** | **Formal Cryptographic Audit Specification**: Mathematical specification for security evaluation. Constant-time $\text{GF}(2^8)$ arithmetic, domain separation across HKDF and AEAD nonces, memory zeroization compiler fences (`Zeroize`), YubiKey PIV ISO 7816-4 smartcard driver, and threat boundary definitions. |

---

## 🎨 System Architecture Diagrams (`docs/diagrams/`)

Interactive, publication-grade vector graphics illustrating key system workflows and boundary models:

* [**`01_system_architecture.svg`**](./diagrams/01_system_architecture.svg): End-to-end topology across Developer Workstation, Storage Operators, Maintenance Fleet, and Arbitrum L2.
* [**`02_key_hierarchy.svg`**](./diagrams/02_key_hierarchy.svg): Derivation tree from Master Secret $R$ to Device Keys, Vault Keys, Epoch Keys, and Operator Auth Tokens.
* [**`03_vault_init_flow.svg`**](./diagrams/03_vault_init_flow.svg): Vault initialization, paper kit generation, and zeroization sequence.
* [**`04_push_dedup_flow.svg`**](./diagrams/04_push_dedup_flow.svg): FastCDC dual-mask chunking, client-side encryption, and Proof-of-Storage quorum replication.
* [**`05_l2_settlement_flow.svg`**](./diagrams/05_l2_settlement_flow.svg): EIP-712 state commitment and Arbitrum L2 relayer receipt anchoring.
* [**`06_maintenance_self_repair.svg`**](./diagrams/06_maintenance_self_repair.svg): Autonomous fleet pinging, degraded replica detection, and self-repair pipeline.
* [**`07_disaster_recovery_flow.svg`**](./diagrams/07_disaster_recovery_flow.svg): Virgin replacement workstation reconstruction from Paper Recovery Kit or $M$-of-$N$ Shamir Guardian Shares.

---

## 🏛️ Historical Specifications & Audit Archive (`docs/archive/`)

Early design RFCs (Phase 01 through Phase 10) and historical audit reports are permanently preserved in the [`archive/`](./archive/) directory for full historical provenance:

| Archive File | Historical Purpose |
|---|---|
| [`01-product-and-requirements.md`](./archive/01-product-and-requirements.md) | Initial product scope, assumptions, and acceptance criteria. |
| [`02-technology-decisions.md`](./archive/02-technology-decisions.md) | Initial trade-off analysis between storage layers, L2 rollups, and local keystores. |
| [`03-security-and-recovery.md`](./archive/03-security-and-recovery.md) | Foundational threat model, adversary assumptions, and recovery primitives. |
| [`04-architecture-and-storage.md`](./archive/04-architecture-and-storage.md) | Early storage operator topology and chunk retention model. |
| [`05-protocol-and-interfaces.md`](./archive/05-protocol-and-interfaces.md) | Preliminary CBOR wire schemas and CLI command definitions. |
| [`06-operations-performance-costs.md`](./archive/06-operations-performance-costs.md) | Early cloud capacity projections and cost estimations. |
| [`07-delivery-and-review-gates.md`](./archive/07-delivery-and-review-gates.md) | Pre-production delivery milestones and verification checklists. |
| [`08-sources-and-evidence.md`](./archive/08-sources-and-evidence.md) | Primary technical literature, standards citations, and research references. |
| [`09-yubikey-hsm-guide.md`](./archive/09-yubikey-hsm-guide.md) | Initial hardware token specification (superseded by [`SYSTEM_WORKFLOW.md`](./SYSTEM_WORKFLOW.md)). |
| [`10-recovery-milestone.md`](./archive/10-recovery-milestone.md) | Verification record of the Phase 10 recovery drill. |
| [`CIPHERVAULT_AUDIT_2026-09-12.md`](./archive/CIPHERVAULT_AUDIT_2026-09-12.md) | Pre-production security audit report (all findings resolved in v1.0.0). |
| [`PROJECT_REPORT.md`](./archive/PROJECT_REPORT.md) | Initial consolidation report (now unified into [`SYSTEM_WORKFLOW.md`](./SYSTEM_WORKFLOW.md)). |

---

## 🛡️ Non-Negotiable Architectural Invariants

1. **Zero Plaintext at Rest**: Decryption keys and device credentials are stored exclusively in OS credential vaults (Windows DPAPI or machine-entropy AEAD keyrings).
2. **Zero Plaintext to Operators**: Storage operators only receive opaque ciphertext chunks addressed by content digest (CID). Operators cannot infer file names, directory hierarchies, or secret contents.
3. **Zero-Disk Recovery Kit**: The master secret $R$ is never persisted unencrypted to physical disk. Memory buffers holding $R$ are explicitly zeroized on drop.
4. **Autonomous Durability**: Replication requires real-time Proof-of-Storage verification (461-byte cryptographic challenge readback), and autonomous daemons maintain quorum across independent multi-region VPS nodes.
5. **Clean-Machine Sovereign Recovery**: Any lost machine can be reconstructed without centralized SaaS access, blockchain wallets, or database accounts—requiring only the offline paper kit or $M$-of-$N$ guardian shares.
