# 🛡️ CipherVault: Master Documentation Hub

**Release track:** `v1.0.37` (Hermes plugin `v0.7.2`); the [release notes](../dist/RELEASE_NOTES.md) list what each release changed. The [deployment ledger](../report/DEPLOYMENT_2026-09-30.md) records the earlier 1.0.26 production deployment.
**Classification:** Enterprise System Architecture, Protocol Specification & Reference Manual  
**Repository:** [github.com/samuel-1-avson/CipherVault](https://github.com/samuel-1-avson/CipherVault)  

---

## Overview

CipherVault provides client-encrypted file backup and hosted scoped-secret management. Hosted secret values are decrypted by the account server; the two confidentiality models are described in [current security guarantees](CURRENT_SECURITY_GUARANTEES.md).

Start with the [remediation ledger](../report/AUDIT_REMEDIATION_2026-09-30.md), [account service behavior](../services/account/README.md), [chunk v2 design](../crates/snapshot/CHUNK_PROTOCOL_V2.md), [installer signature requirements](../dist/INSTALLER_SIGNATURES.md), and [dependency audit policy](DEPENDENCY_AUDIT.md). Older design documents and deployment reports describe their recorded versions; these current behavior notes take precedence where they differ.

CipherVault also ships guardrails for AI coding agents: a native Hermes plugin, a Model Context Protocol server and cross-agent hooks. Those documents have their own track, [AI Agents & the Hermes Plugin](#-ai-agents--the-hermes-plugin), below.

This documentation suite is organized into tracks for core protocol engineers, security auditors, operators, application developers and agent users. Start with [current security and operational guarantees](./CURRENT_SECURITY_GUARANTEES.md): legacy v1 capture limitations, chunk v2 as the default writer, journaled restore, watcher retries, operator enrollment/pins, scoped batch execution and the agent-safety surfaces. Older reports and diagrams preserve historical design context and are not current release certification.

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
            Genesis["GENESIS_CEREMONY_RUNBOOK.md\n(CipherChain Genesis & Rotation)"]
        end

        subgraph TrackD ["4. API Reference & Decision Records"]
            direction TB
            ApiRef["API_REFERENCE.md\n(Operator HTTP & P2P RPC)"]
            DashRef["DASHBOARD_API_REFERENCE.md\n(Web Dashboard & Explorer)"]
            Platforms["PLATFORM_SUPPORT.md\n(OS Keyrings & Token Drivers)"]
            ADR["adr/ (001 - 014)\n(Architecture Decision Records)"]
            Diagrams["diagrams/ (01 - 07)\n(Publication-Grade SVGs)"]
        end

        subgraph TrackE ["5. Audits, Evidence & Archive"]
            direction TB
            Reports["report/\n(Curated Evidence & Scoped-Secret Specs)"]
            AuditPack["audit/\n(External Review Pack & Threat Model)"]
            Archive["archive/\n(Historical RFCs & Spikes)"]
        end

        subgraph TrackF ["6. AI Agents & Hermes Plugin"]
            direction TB
            PluginDoc["plugins/ciphervault/README.md\n(Hermes Plugin v0.7.2)"]
            Skill["SKILL.md\n(Agent Rules)"]
            Mcp["services/mcp/README.md\n(MCP Server)"]
            AgentRoadmap["SECURITY_AND_HERMES_PLUGIN_ROADMAP.md\n(Agent Security Review)"]
        end
    end

    classDef g1 fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef g2 fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#f8fafc;
    classDef g3 fill:#312e81,stroke:#818cf8,stroke-width:2px,color:#f8fafc;
    classDef g4 fill:#7c2d12,stroke:#fb923c,stroke-width:2px,color:#f8fafc;
    classDef g5 fill:#4c1d95,stroke:#a78bfa,stroke-width:2px,color:#f8fafc;

    class Setup,Workflow,Onboard,Playbooks,CICD g1;
    class Arch,DON,Crypto,Acct,Keys g2;
    class Repair,Plan,Testnet,Deploy,Genesis g3;
    class ApiRef,DashRef,Platforms,ADR,Diagrams g4;
    class Reports,AuditPack,Archive g5;
    classDef g6 fill:#831843,stroke:#f472b6,stroke-width:2px,color:#f8fafc;
    class PluginDoc,Skill,Mcp,AgentRoadmap g6;
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

## 🤖 AI Agents & the Hermes Plugin

Guardrails that let AI coding agents scan, run, diff and back up secrets without secret values entering the model context, plus a verifiable record of what the agent touched. Start with the plugin README.

| Document | Audience | Scope & Key Topics Covered |
|---|---|---|
| [**`plugins/ciphervault/README.md`**](../plugins/ciphervault/README.md) | **Hermes users & reviewers** | **Hermes plugin v0.7.2**: all 12 tools, hooks and middleware, desktop pane, secret source, binary resolution, MFA notes, validation commands, and the full process/network/audit disclosure. |
| [**`SKILL.md`**](../plugins/ciphervault/skills/ciphervault/SKILL.md) | **Agents & plugin authors** | The hard rules an agent follows around secrets: paths not contents, never wrap `init`, the guard hooks are load-bearing, and the preferred tool order. |
| [**`DEMO.md`**](../plugins/ciphervault/DEMO.md) | **Presenters** | Rehearsed 90-second demo script against a throwaway vault. |
| [**`services/mcp/README.md`**](../services/mcp/README.md) | **Claude Code, Codex & Cursor users** | The native `ciphervault mcp` server (7 tools) and the older Python server. |
| [**`SECURITY_AND_HERMES_PLUGIN_ROADMAP.md`**](./SECURITY_AND_HERMES_PLUGIN_ROADMAP.md) | **Security reviewers** | Agent-security review of the CLI and plugin: seven findings with remediation status, and what shipped from the roadmap. |
| [**`audit/AGENT_AUDIT_PATTERN.md`**](./audit/AGENT_AUDIT_PATTERN.md) | **Agent-host & tooling authors** | The pattern behind the verifiable agent audit log: deny at the tool boundary, gate execution narrowly, scrub results, and chain-and-anchor the receipts. |
| [**`CURRENT_SECURITY_GUARANTEES.md`**](./CURRENT_SECURITY_GUARANTEES.md#agent-safety-surfaces-v1032-to-v1035) | **Everyone** | Exactly what the agent surfaces guarantee, and what they do not. |

---

## 🔐 Security, Assurance & Release Integrity

| Document | Audience | Scope & Key Topics Covered |
|---|---|---|
| [**`CURRENT_SECURITY_GUARANTEES.md`**](./CURRENT_SECURITY_GUARANTEES.md) | **Everyone (start here)** | The working implementation's guarantees and stated limits. Takes precedence over older reports where they differ. |
| [**`audit/README.md`**](./audit/README.md) | **External auditors** | Engagement pack: scope (C1 to C8), claimed invariants, reproduction commands and known limitations, with the [threat model](./audit/THREAT_MODEL.md) the [2026-11-10 independent reviewer pass](./audit/INDEPENDENT_REVIEW_2026-11-10.md), and the [2026-11-19 CipherChain review](./audit/CIPHERCHAIN_REVIEW_2026-11-19.md). |
| [**`SECURITY_AUDIT_READINESS.md`**](./SECURITY_AUDIT_READINESS.md) | **Security leads** | Audit readiness package and baseline evidence. |
| [**`ENFORCED_MFA.md`**](./ENFORCED_MFA.md) and [**`MFA_ROLLOUT.md`**](./MFA_ROLLOUT.md) | **Account owners & operators** | Enforced second-factor policy for the account plane, and its rollout. |
| [**`UPDATER_SIGNATURE_VERIFICATION.md`**](./UPDATER_SIGNATURE_VERIFICATION.md) | **Release engineers** | Signed-update verification, pinned trust roots and the key-rotation record. |
| [**`DEPENDENCY_AUDIT.md`**](./DEPENDENCY_AUDIT.md) | **Maintainers** | Dependency audit policy and documented exceptions. |
| [**`PASSPHRASE_KEY_BACKUP.md`**](./PASSPHRASE_KEY_BACKUP.md) | **Users & custodians** | Passphrase-sealed recovery key backups (`recovery key-backup` / `key-restore`). |
| [**`ACCOUNT_BACKUP_AND_RECOVERY.md`**](./ACCOUNT_BACKUP_AND_RECOVERY.md) and [**`INDEPENDENT_RECOVERY_CUSTODY.md`**](./INDEPENDENT_RECOVERY_CUSTODY.md) | **Operators & custodians** | Account backup and isolated restore rehearsal, and independent recovery custody. |

---

## 🏛 2. Core Architecture & Cryptographic Specifications

| Specification | Primary Audience | Scope & Key Topics Covered |
|---|---|---|
| [**`SYSTEM_WORKFLOW.md`**](./SYSTEM_WORKFLOW.md) | **Architects, Engineers, Auditors** | **Master System Architecture & Workflows**: End-to-end component topology, Blake2b KDF key hierarchy, 7 operational workflows (Init, Watch, Push, Sovereign Anchoring, Self-Repair, Disaster Recovery, YubiKey PIV), and verification invariants. The old L2 settlement workflow is marked superseded in the document. |
| [**`DECENTRALIZED_ARCHITECTURE_SPEC.md`**](./DECENTRALIZED_ARCHITECTURE_SPEC.md) | **Protocol Engineers & Core Devs** | **Decentralized Operator Network (DON v2.0)**: Multi-plane architecture, Kademlia DHT routing, libp2p Gossipsub swarm, DCUtR NAT holepunching, and backward-compatible storage abstractions. Its Arbitrum settlement plane is superseded by the sovereign CipherChain (see the migration note at the top of the document). |
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
| [**`GENESIS_CEREMONY_RUNBOOK.md`**](./GENESIS_CEREMONY_RUNBOOK.md) | **Protocol Leads & Validator Operators** | **CipherChain Genesis Ceremony & Validator Rotation**: Network bootstrapping and validator lifecycle for the sovereign CipherChain ledger. |
| [**`LOAD_SOAK_VALIDATION.md`**](./LOAD_SOAK_VALIDATION.md) | **Performance Engineers & SREs** | **Load & Soak Validation**: `push_bench` harness, sustained iteration benchmarks, rate limiter tuning, and live cluster soak evidence. |
| [**`RELEASE_PROCESS.md`**](./RELEASE_PROCESS.md) | **Release Engineers** | **Release Engineering & Cadence**: Semver policy, multi-architecture cross-compilation matrix, SBOM/SLSA generation, cosign keyless signatures, and automated package manager distribution. |
| [**`CRYPTO_DONATION_PLAN.md`**](./CRYPTO_DONATION_PLAN.md) | **Community & Contributors** | **Cryptocurrency Donation Integration**: Multi-chain EVM address configuration (Arbitrum One ETH/ARB/USDT and Ethereum Mainnet), smart contract verification links, and non-intrusive UI integration. |

---

## 🔌 4. API & Interface References

| Reference | Scope & Interface Details |
|---|---|
| [**`API_REFERENCE.md`**](./API_REFERENCE.md) | **Operator HTTP & P2P RPC Reference**: Endpoints, request/response payloads, authentication headers (`Authorization: Bearer`, `X-CipherVault-Id`), size limits, rate limiting (50 req/s), and error envelopes. |
| [**`DASHBOARD_API_REFERENCE.md`**](./DASHBOARD_API_REFERENCE.md) | **Web Dashboard & Explorer Reference**: Embedded Axum HTTP routes (`/api/overview`, `/api/vaults`, `/api/chunks`, `/api/leases`, `/api/peers`), WebSocket/SSE streams, and client contracts. |
| [**`PLATFORM_SUPPORT.md`**](./PLATFORM_SUPPORT.md) | **Platform & Keyring Matrix**: What is implemented versus verified on Windows 10/11, Linux and macOS: key custody (Windows DPAPI, Linux Secret Service, macOS Keychain, portable file keystore), PC/SC smartcard drivers, and `--no-net` sandboxing. |

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
| [`012-unified-login-split-custody.md`](./adr/012-unified-login-split-custody.md) | Unified Login, Split Custody | One login experience over a preserved account/vault cryptographic split. |
| [`013-chain-liveness.md`](./adr/013-chain-liveness.md) | CipherChain Liveness Under Split Votes | Mitigations for block production under split validator votes; view-change designed, not yet implemented. Superseded in direction by ADR-014. |
| [`014-witnessed-transparency-log.md`](./adr/014-witnessed-transparency-log.md) | CipherChain Becomes a Witnessed Transparency Log | Replaces CipherChain consensus with per-operator RFC 9162 logs, C2SP checkpoints and witness cosignatures; six-phase plan, existing anchors stay verifiable. |

---

## 🎨 6. System Architecture Diagrams (`docs/diagrams/`)

Publication-grade vector graphics illustrating key system workflows and boundary models.

> **Historical settlement lane:** diagrams `01`, `08`, `09` and `10` were drawn before Phase 1 and still show an Arbitrum One L2 settlement lane. That path was removed; anchoring is now the sovereign CipherChain (see the current mermaid diagram in the [root README](../README.md#-system-architecture--trust-boundaries) and Workflow 3 in [`SYSTEM_WORKFLOW.md`](./SYSTEM_WORKFLOW.md)). The rest of each diagram is still accurate.

* [**`01_system_architecture.svg`**](./diagrams/01_system_architecture.svg) — End-to-end topology across Workstation, Storage Operators, Maintenance Fleet, and the (removed) L2 settlement lane.
* [**`02_key_hierarchy.svg`**](./diagrams/02_key_hierarchy.svg) — Cryptographic key derivation hierarchy branching from Master Recovery Secret $R$.
* [**`03_vault_init_flow.svg`**](./diagrams/03_vault_init_flow.svg) — Vault initialization sequence, paper recovery kit emission, and RAM zeroization.
* [**`04_push_dedup_flow.svg`**](./diagrams/04_push_dedup_flow.svg) — FastCDC dual-mask chunking, client-side encryption, and Proof-of-Storage quorum replication.
* *05_* settlement flow diagram — removed Phase 1 with the EVM path; the sovereign flow is Workflow 3 in SYSTEM_WORKFLOW.md (propose → quorum → commit → publish → verify).*
* [**`06_maintenance_self_repair.svg`**](./diagrams/06_maintenance_self_repair.svg) — Autonomous fleet probing, degraded replica detection, and self-repair pipeline.
* [**`07_disaster_recovery_flow.svg`**](./diagrams/07_disaster_recovery_flow.svg) — Clean replacement machine reconstruction from Paper Recovery Kit or $M$-of-$N$ Shamir Guardian Shares.
* [**`08_network_topology.svg`**](./diagrams/08_network_topology.svg) — Network topology (the L2 settlement lane is historical, see above).
* [**`09_architectural_blueprint.svg`**](./diagrams/09_architectural_blueprint.svg) — Architectural blueprint (the L2 settlement lane is historical).
* [**`10_data_lifecycle_flow.svg`**](./diagrams/10_data_lifecycle_flow.svg) — Data lifecycle flow (its L2 anchoring step is historical).

---

## 📊 7. Published Evidence & Scoped-Secret Specs (`report/`)

[`report/`](../report/) publishes only the curated evidence that current documents, code comments and tooling cite: the 2026-09-30 audit/remediation/deployment ledgers, the October assurance and capacity evidence, release test evidence, and the scoped-secrets design specs. See the [`report/README.md`](../report/README.md) index. Dated working notes (ratings, status reports, plans, drafts) are kept locally and are not published.

---

## 🏛️ 8. Historical Specifications & Spikes Archive (`docs/archive/`)

Early design RFCs (Phase 01 through Phase 10), completed research spikes and decision packets are preserved in [`docs/archive/`](./archive/) for architectural provenance:

* **Foundational RFCs**: [`01-product-and-requirements.md`](./archive/01-product-and-requirements.md) through [`10-recovery-milestone.md`](./archive/10-recovery-milestone.md)
* **Completed Spikes**: [`D6_OBJECT_STORE_SPIKE.md`](./archive/D6_OBJECT_STORE_SPIKE.md) (redb selection) and [`D7_ERASURE_SPIKE.md`](./archive/D7_ERASURE_SPIKE.md) (erasure coding decline)
* **Decision Records & Drills**: [`DON_ECONOMICS_DECISION.md`](./archive/DON_ECONOMICS_DECISION.md), [`DON_SPEC_CORRECTIONS.md`](./archive/DON_SPEC_CORRECTIONS.md), [`NAT_HOLEPUNCH_DRILL.md`](./archive/NAT_HOLEPUNCH_DRILL.md)

---

## 🤝 9. Community Governance, Security & Licensing

CipherVault adheres to rigorous open-source governance and intellectual property standards:

* [**`CONTRIBUTING.md`**](../CONTRIBUTING.md) — Contributor onboarding, quality gates, and commit conventions.
* [**`DCO (Developer Certificate of Origin)`**](../CONTRIBUTING.md#developer-certificate-of-origin-dco) — Mandatory `git commit -s` sign-off to certify original authorship.
* [**`SECURITY.md`**](../SECURITY.md) — Responsible vulnerability reporting, Safe Harbor terms, and SLA targets.
* [**`CODE_OF_CONDUCT.md`**](../CODE_OF_CONDUCT.md) — Contributor Covenant v2.1 code of conduct.
* [**`TRADEMARK.md`**](../TRADEMARK.md) — Brand guidelines and rebranding requirements for downstream forks.
* [**`LICENSE`**](../LICENSE) — Dual-licensing terms ([Apache 2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT)).

---

## 🛡️ Non-Negotiable Architectural Invariants

1. **Protected Local Keys**: Windows uses DPAPI; other platforms use an AEAD envelope backed by a configured master key or private key file. Files and metadata still require separate disk protection.
2. **Encrypted Operator Payloads**: File paths reside in encrypted manifests. Legacy v1 captures (and history written before v2 became the default) still permit public candidate-file confirmation; the default v2 hides public candidate hashes, while equality, lengths and traffic remain visible.
3. **Zero-Disk Master Secret ($R$)**: The master recovery secret $R$ is never persisted unencrypted to physical disk. Memory buffers holding $R$ are explicitly zeroized on drop.
4. **Autonomous Durability**: Replication requires real-time Proof-of-Storage verification (461-byte cryptographic challenge readback), and autonomous daemons maintain quorum across independent multi-region VPS nodes.
5. **Clean-Machine Recovery**: Offline recovery material can reconstruct a complete remotely replicated recovery set while enough operators remain reachable. Certified incomparable branches require fork resolution; withholding newer history needs independent freshness evidence.

## Operational verification additions

- [Account backup and isolated restore rehearsal](ACCOUNT_BACKUP_AND_RECOVERY.md)
- [Remote plaintext recovery drill](CURRENT_SECURITY_GUARANTEES.md#operator-authentication-and-pins)
