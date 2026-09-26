# 🛡️ CipherVault: Master Documentation Hub

**Current Version:** `v1.0.17`  
**Classification:** Enterprise System Architecture, Protocol Specification & Reference Manual  
**Repository:** [github.com/samuel-1-avson/CipherVault](https://github.com/samuel-1-avson/CipherVault)  

---

## Overview

Welcome to the **CipherVault** master documentation hub. CipherVault is a sovereign, zero-knowledge secret backup, version control, and clean-machine disaster recovery platform engineered in pure Rust and Solidity.

This documentation suite is organized into focused, authoritative tracks designed for core protocol engineers, security auditors, site reliability operators, and application developers.

```mermaid
flowchart TB
    subgraph Hub ["CipherVault Master Documentation Architecture"]
        direction TB
        
        subgraph TrackA ["1. Getting Started & Guides"]
            direction TB
            Setup["SETUP_GUIDE.md\n(Developer & Node Paths)"]
            Workflow["WORKFLOW_GUIDE.md\n(Day-to-Day Operations)"]
            Onboard["OPERATOR_ONBOARDING.md\n(Run a Node)"]
            Playbooks["OPERATOR_PLAYBOOKS.md\n(Mesh, Vouchers, Quotas)"]
            CICD["CICD_INTEGRATION.md\n(Zero-Disk CI/CD Injection)"]
        end

        subgraph TrackB ["2. Core Architecture & Cryptography"]
            direction TB
            Arch["SYSTEM_WORKFLOW.md\n(Master Architecture & Key Hierarchy)"]
            DON["DECENTRALIZED_ARCHITECTURE_SPEC.md\n(DON v2.0 & P2P Swarm)"]
            Crypto["CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md\n(Formal Verification & GF(2^8))"]
            Acct["ACCOUNT_IDENTITY_DESIGN.md\n(WebAuthn Passkeys & Device Auth)"]
            Keys["KEY_CEREMONIES_AND_BACKUPS.md\n(Custody, Paper Kits, Rotation)"]
        end

        subgraph TrackC ["3. Protocol, Network & Deployment"]
            direction TB
            Repair["REPAIR_PROTOCOL.md\n(Liveness & Paced Backfill)"]
            Plan["DON_IMPLEMENTATION_PLAN.md\n(7-Phase Engineering Roadmap)"]
            Testnet["TESTNET.md\n(Public Testnet Fleet)"]
            Deploy["DEPLOYMENT_RUNBOOK.md\n(Production GCP/Docker Cluster)"]
            Mainnet["MAINNET_ANCHOR_PROMOTION.md\n(Arbitrum One L2 Settlement)"]
        end

        subgraph TrackD ["4. API Reference & Decision Records"]
            direction TB
            ApiRef["API_REFERENCE.md\n(Operator HTTP & P2P RPC)"]
            DashRef["DASHBOARD_API_REFERENCE.md\n(Web Dashboard & Explorer)"]
            Platforms["PLATFORM_SUPPORT.md\n(OS Keyrings & Token Drivers)"]
            ADR["adr/ (001 - 011)\n(Architecture Decision Records)"]
            Diagrams["diagrams/ (01 - 07)\n(Publication-Grade SVGs)"]
        end

        subgraph TrackE ["5. Audits, Evidence & Archive"]
            direction TB
            Reports["report/\n(Live Ratings & Audit Reports)"]
            Archive["archive/\n(Historical RFCs & Spikes)"]
        end
    end

    classDef g1 fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef g2 fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#f8fafc;
    classDef g3 fill:#312e81,stroke:#818cf8,stroke-width:2px,color:#f8fafc;
    classDef g4 fill:#7c2d12,stroke:#fb923c,stroke-width:2px,color:#f8fafc;
    classDef g5 fill:#4c1d95,stroke:#a78bfa,stroke-width:2px,color:#f8fafc;

    class Setup,Workflow,Onboard,Playbooks,CICD g1;
    class Arch,DON,Crypto,Acct,Keys g2;
    class Repair,Plan,Testnet,Deploy,Mainnet g3;
    class ApiRef,DashRef,Platforms,ADR,Diagrams g4;
    class Reports,Archive g5;
```

---

## 📚 1. Getting Started & Operational Guides

| Manual | Target Audience | Scope & Key Topics Covered |
|---|---|---|
| [**`SETUP_GUIDE.md`**](./SETUP_GUIDE.md) | **Developers & Node Operators** | **Two-Track Setup Guide**: One-liner installer scripts, role selection (`developer`, `node`, `full`), 5-command developer quickstart, guided `node setup` wizard, and health verification (`ciphervault doctor`). |
| [**`WORKFLOW_GUIDE.md`**](./WORKFLOW_GUIDE.md) | **All Users & Team Leads** | **Day-to-Day Operations Guide**: Practical workflow walkthrough covering secret tracking, FastCDC chunking, in-memory execution (`ciphervault run`), shoulder-surfing safe diffing, snapshot commit DAG, and clean-machine restore. |
| [**`OPERATOR_ONBOARDING.md`**](./OPERATOR_ONBOARDING.md) | **Community Node Operators** | **Node Runner Onboarding**: Server prerequisites, hardware requirements, invite ticket join ceremonies, probation period, and automatic graduation to full replica status. |
| [**`OPERATOR_PLAYBOOKS.md`**](./OPERATOR_PLAYBOOKS.md) | **Fleet Operators & SREs** | **Operator Operational Runbook**: Node lifecycle, mesh announce, self-issued write vouchers (ADR-002), per-user quota caps, peer quarantining, zero-downtime key rotation, and disaster backup/recovery. |
| [**`CICD_INTEGRATION.md`**](./CICD_INTEGRATION.md) | **DevOps & Security Engineers** | **Zero-Disk CI/CD Pipeline Guide**: In-memory secret injection (`ciphervault run`) for GitHub Actions, GitLab CI, CircleCI, and Jenkins. Eliminates persistent `.env` files from CI runners and protects logs from accidental credential dumping. |

---

## 🏛 2. Core Architecture & Cryptographic Specifications

| Specification | Primary Audience | Scope & Key Topics Covered |
|---|---|---|
| [**`SYSTEM_WORKFLOW.md`**](./SYSTEM_WORKFLOW.md) | **Architects, Engineers, Auditors** | **Master System Architecture & Workflows**: End-to-end component topology, Blake2b KDF key hierarchy, 7 operational workflows (Init, Watch, Push, L2 Rollup, Self-Repair, Disaster Recovery, YubiKey PIV), and verification invariants. |
| [**`DECENTRALIZED_ARCHITECTURE_SPEC.md`**](./DECENTRALIZED_ARCHITECTURE_SPEC.md) | **Protocol Engineers & Core Devs** | **Decentralized Operator Network (DON v2.0)**: Multi-plane architecture, Kademlia DHT routing, libp2p Gossipsub swarm, DCUtR NAT holepunching, Arbitrum L2 batch settlement, and backward-compatible storage abstractions. |
| [**`CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`**](./CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md) | **Cryptographers & Security Auditors** | **Formal Cryptographic Specification**: Mathematical proofs, branchless constant-time $\text{GF}(2^8)$ arithmetic, domain-separated Blake2b KDF tree, memory zeroization compiler fences (`ZeroizeOnDrop`), and native ISO 7816-4 smartcard driver. |
| [**`ACCOUNT_IDENTITY_DESIGN.md`**](./ACCOUNT_IDENTITY_DESIGN.md) | **Security Architects & Fullstack Devs** | **Account & Device Identity Control Plane**: Optional control plane for multi-device sync, WebAuthn passkey registration/authentication (Ed25519/ES256), TOTP MFA, and instant cryptographic device revocation. |
| [**`KEY_CEREMONIES_AND_BACKUPS.md`**](./KEY_CEREMONIES_AND_BACKUPS.md) | **Security Leads & Node Admins** | **Key Ceremonies, Custody & Backups**: Inventory of all signing and encryption keys, custody rules, emergency offline paper recovery kit generation, $M$-of-$N$ Shamir threshold guardians, and operator key rotation. |

---

## 🌐 3. Protocol, Network & Deployment

| Document | Primary Audience | Scope & Key Topics Covered |
|---|---|---|
| [**`REPAIR_PROTOCOL.md`**](./REPAIR_PROTOCOL.md) | **P2P Engineers & SREs** | **Autonomous Mesh Self-Repair Protocol**: Signed heartbeat liveness gossip, local-only failure detection, rendezvous hashing repair assignment (single-pusher guarantee), and token-bucket paced backfill. |
| [**`DON_IMPLEMENTATION_PLAN.md`**](./DON_IMPLEMENTATION_PLAN.md) | **Core Engineering Team** | **7-Phase DON Implementation Plan**: Gated milestones from transport abstraction (Phase 1) and libp2p connectivity (Phase 2) to capability vouchers (Phase 3), authenticated repair (Phase 4), and production cutover. |
| [**`TESTNET.md`**](./TESTNET.md) | **Beta Testers & Operators** | **Public Testnet Guide**: Official testnet seed endpoints, join ceremonies, peer discovery, reset pathways, and known operational caveats. |
| [**`DEPLOYMENT_RUNBOOK.md`**](./DEPLOYMENT_RUNBOOK.md) | **DevOps & Infrastructure Leads** | **Master Cloud VPS & Docker Runbook**: Multi-region GCP Compute Engine cluster provisioning (`e2-micro`), Caddy TLS reverse-proxy hardening, HSTS security headers, rate limiting, and systemd maintenance services. |
| [**`MAINNET_ANCHOR_PROMOTION.md`**](./MAINNET_ANCHOR_PROMOTION.md) | **Protocol Leads & Smart Contract Devs** | **Mainnet Anchor Promotion Plan**: Promotion gates, deployer key ceremonies, Arbitrum Sepolia to Arbitrum One migration, and rollback procedures. |
| [**`LOAD_SOAK_VALIDATION.md`**](./LOAD_SOAK_VALIDATION.md) | **Performance Engineers & SREs** | **Load & Soak Validation**: `push_bench` harness, sustained iteration benchmarks, rate limiter tuning, and live cluster soak evidence. |
| [**`RELEASE_PROCESS.md`**](./RELEASE_PROCESS.md) | **Release Engineers** | **Release Engineering & Cadence**: Semver policy, multi-architecture cross-compilation matrix, SBOM/SLSA generation, cosign keyless signatures, and automated package manager distribution. |
| [**`CRYPTO_DONATION_PLAN.md`**](./CRYPTO_DONATION_PLAN.md) | **Community & Contributors** | **Cryptocurrency Donation Integration**: Multi-chain EVM address configuration (Arbitrum One ETH/ARB/USDT and Ethereum Mainnet), smart contract verification links, and non-intrusive UI integration. |

---

## 🔌 4. API & Interface References

| Reference | Scope & Interface Details |
|---|---|
| [**`API_REFERENCE.md`**](./API_REFERENCE.md) | **Operator HTTP & P2P RPC Reference**: Endpoints, request/response payloads, authentication headers (`Authorization: Bearer`, `X-CipherVault-Id`), size limits, rate limiting (50 req/s), and error envelopes. |
| [**`DASHBOARD_API_REFERENCE.md`**](./DASHBOARD_API_REFERENCE.md) | **Web Dashboard & Explorer Reference**: Embedded Axum HTTP routes (`/api/overview`, `/api/vaults`, `/api/chunks`, `/api/leases`, `/api/peers`), WebSocket/SSE streams, and client contracts. |
| [**`PLATFORM_SUPPORT.md`**](./PLATFORM_SUPPORT.md) | **Platform & Keyring Matrix**: Supported OS platforms (Windows 10/11, Ubuntu/Debian/Fedora, macOS Apple Silicon/Intel), credential vaults (Windows DPAPI, Linux SecretService, macOS Keychain), and PC/SC smartcard drivers. |

---

## ⚖️ 5. Architecture Decision Records (`docs/adr/`)

Historical architectural decisions are permanently recorded as ADRs:

| ADR | Title | Decision Summary |
|---|---|---|
| [`001-custom-kdf.md`](./adr/001-custom-kdf.md) | Custom Blake2b Key Derivation Function | Adopted domain-separated Blake2b-512 KDF with `CipherVault-KDF-v1` context strings. |
| [`002-voucher-barter.md`](./adr/002-voucher-barter.md) | Write Vouchers & Barter Model | Implemented self-issued bearer write vouchers to prevent disk-fill attacks without initial token staking. |
| [`003-repair-lane.md`](./adr/003-repair-lane.md) | Dedicated Mesh Repair Lane | Established out-of-band P2P `RepairPush` RPC exempt from client write vouchers. |
| [`004-redb-store.md`](./adr/004-redb-store.md) | Embedded Object Store (redb) | Selected pure-Rust `redb` over RocksDB for crash-safety, zero C FFI dependencies, and throughput. |
| [`005-decline-erasure.md`](./adr/005-decline-erasure.md) | Decline Erasure Coding for 3-Node Fleet | Retained 3x full replication; declined Reed-Solomon erasure coding until fleet exceeds 5+ placement nodes. |
| [`006-anonymous-recovery-reads.md`](./adr/006-anonymous-recovery-reads.md) | Anonymous Recovery Reads | Permitted unauthenticated reads on recovery record routes to enable clean-machine sovereign restoration. |
| [`007-voucher-ledger-persistence.md`](./adr/007-voucher-ledger-persistence.md) | Voucher Ledger Persistence | Persisted voucher spend and per-holder quotas to disk to survive node restarts. |
| [`008-verified-community-join.md`](./adr/008-verified-community-join.md) | Verified Community Join Ceremony | Introduced fleet-signed invite tickets with probation period prior to full replica graduation. |
| [`009-membership-openness.md`](./adr/009-membership-openness.md) | Progressive Network Openness | Defined roadmap from permissioned founding fleet to open federated community nodes. |
| [`010-incentives-sla-abuse.md`](./adr/010-incentives-sla-abuse.md) | Node SLA & Abuse Vocabulary | Codified peer quarantine rules, DoS defense limits, and rate-limiting enforcement. |
| [`011-quorum-admission.md`](./adr/011-quorum-admission.md) | Multi-Party Quorum Admission | Required $K$-of-$N$ fleet keyholder approval for admitting new storage nodes to eliminate central gatekeepers. |

---

## 🎨 6. System Architecture Diagrams (`docs/diagrams/`)

Interactive, publication-grade vector graphics illustrating key system workflows and boundary models:

* [**`01_system_architecture.svg`**](./diagrams/01_system_architecture.svg) — End-to-end topology across Workstation, Storage Operators, Maintenance Fleet, and Arbitrum L2.
* [**`02_key_hierarchy.svg`**](./diagrams/02_key_hierarchy.svg) — Cryptographic key derivation hierarchy branching from Master Recovery Secret $R$.
* [**`03_vault_init_flow.svg`**](./diagrams/03_vault_init_flow.svg) — Vault initialization sequence, paper recovery kit emission, and RAM zeroization.
* [**`04_push_dedup_flow.svg`**](./diagrams/04_push_dedup_flow.svg) — FastCDC dual-mask chunking, client-side encryption, and Proof-of-Storage quorum replication.
* [**`05_l2_settlement_flow.svg`**](./diagrams/05_l2_settlement_flow.svg) — Salted EIP-712 state commitment and Arbitrum L2 relayer receipt anchoring.
* [**`06_maintenance_self_repair.svg`**](./diagrams/06_maintenance_self_repair.svg) — Autonomous fleet probing, degraded replica detection, and self-repair pipeline.
* [**`07_disaster_recovery_flow.svg`**](./diagrams/07_disaster_recovery_flow.svg) — Clean replacement machine reconstruction from Paper Recovery Kit or $M$-of-$N$ Shamir Guardian Shares.

---

## 📊 7. Verified System Evaluation Reports (`report/`)

Empirical system evaluation reports, live-fire audit ratings, and soak validation proofs are maintained in [`report/`](../report/):

* [`CIPHERVAULT_DEEP_DIVE_REPORT.md`](../report/CIPHERVAULT_DEEP_DIVE_REPORT.md) — Architectural deep-dive audit and system verification report.
* [`EXPLORER_DEEP_ANALYSIS_2026-09-21.md`](../report/EXPLORER_DEEP_ANALYSIS_2026-09-21.md) — Comprehensive Web Explorer & Dashboard security and architectural analysis.
* [`EXTERNAL_REHEARSAL_PROOF_2026-09-20.md`](../report/EXTERNAL_REHEARSAL_PROOF_2026-09-20.md) — Live-fire drill evidence: fleet seed rotation and 3/3 probation join rehearsal.
* [`TESTNET_READINESS_2026-09-20.md`](../report/TESTNET_READINESS_2026-09-20.md) — Public testnet operational readiness checklist and drill scorecard.
* [`SYSTEM_AUDIT_RATING_2026-09-18.md`](../report/SYSTEM_AUDIT_RATING_2026-09-18.md) & [`SYSTEM_AUDIT_RATING_2026-09-19.md`](../report/SYSTEM_AUDIT_RATING_2026-09-19.md) — Comprehensive security audit ratings.
* [`PROJECT_RATING_2026-09-23.md`](../report/PROJECT_RATING_2026-09-23.md) & [`PROGRESS_RATING_2026-09-24.md`](../report/PROGRESS_RATING_2026-09-24.md) — Progress ratings and milestone dispositions.
* [`PRODUCTION_READINESS_2026-09-24.md`](../report/PRODUCTION_READINESS_2026-09-24.md) & [`OPERATOR_NETWORK_2026-09-24.md`](../report/OPERATOR_NETWORK_2026-09-24.md) — Production readiness and live operator network reports.

---

## 🏛️ 8. Historical Specifications & Spikes Archive (`docs/archive/`)

Early design RFCs (Phase 01 through Phase 10), completed research spikes, and historical audit notes are permanently preserved in [`docs/archive/`](./archive/) for full architectural provenance:

* **Foundational RFCs**: [`01-product-and-requirements.md`](./archive/01-product-and-requirements.md) through [`10-recovery-milestone.md`](./archive/10-recovery-milestone.md)
* **Completed Spikes**: [`D6_OBJECT_STORE_SPIKE.md`](./archive/D6_OBJECT_STORE_SPIKE.md) (redb selection) and [`D7_ERASURE_SPIKE.md`](./archive/D7_ERASURE_SPIKE.md) (erasure coding decline)
* **Historical Drills & Audits**: [`NAT_HOLEPUNCH_DRILL.md`](./archive/NAT_HOLEPUNCH_DRILL.md), [`CHAOS_LOG.md`](./archive/CHAOS_LOG.md), [`CIPHERVAULT_AUDIT_2026-09-12.md`](./archive/CIPHERVAULT_AUDIT_2026-09-12.md), [`PROJECT_AUDIT_2026-09-16.md`](./archive/PROJECT_AUDIT_2026-09-16.md)
* **Transition Records**: [`SPLIT_PLAN.md`](./archive/SPLIT_PLAN.md), [`DON_SPEC_CORRECTIONS.md`](./archive/DON_SPEC_CORRECTIONS.md), [`DON_ECONOMICS_DECISION.md`](./archive/DON_ECONOMICS_DECISION.md), [`LANDING_PAGE_PLAN_AND_REPORT.md`](./archive/LANDING_PAGE_PLAN_AND_REPORT.md)

---

## 🛡️ Non-Negotiable Architectural Invariants

1. **Zero Plaintext at Rest**: Decryption keys and device credentials are stored exclusively in OS credential vaults (Windows DPAPI or machine-entropy AEAD keyrings).
2. **Zero Plaintext to Operators**: Storage operators only receive opaque ciphertext chunks addressed by SHA-256 content identifiers (CIDs). Operators cannot infer file names, directory hierarchies, or secret contents.
3. **Zero-Disk Master Secret ($R$)**: The master recovery secret $R$ is never persisted unencrypted to physical disk. Memory buffers holding $R$ are explicitly zeroized on drop.
4. **Autonomous Durability**: Replication requires real-time Proof-of-Storage verification (461-byte cryptographic challenge readback), and autonomous daemons maintain quorum across independent multi-region VPS nodes.
5. **Clean-Machine Sovereign Recovery**: Any lost machine can be reconstructed without centralized SaaS access, blockchain wallets, or database accounts—requiring only the offline paper kit or $M$-of-$N$ guardian shares.
