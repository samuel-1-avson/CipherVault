# 🌐 CipherVault Network Topology & Trust Boundaries

> **Architectural Specification & Security Isolation Model**  
> *Git tracks your source code. CipherVault protects everything Git leaves behind.*

## 🗺️ Architectural Blueprint & Trust Boundary Map

[![CipherVault Architectural Blueprint & Trust Boundaries](diagrams/09_architectural_blueprint.svg)](diagrams/09_architectural_blueprint.svg)

<details>
<summary><b>▶ Click to inspect raw text ASCII blueprint</b></summary>

```text
====================================================================================================
                        CIPHERVAULT ZERO-KNOWLEDGE NETWORK TOPOLOGY
====================================================================================================

 [ TIER 1: DEVELOPER WORKSTATION ] ── (Sovereign Local Client — Never Exports Plaintext Secrets)
 ┌────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  Confidential Files (.env, certs, keys)                                                       │
 │       │                                                                                        │
 │       ▼                                                                                        │
 │  FastCDC Slicing Engine (4 KiB - 64 KiB Content-Defined Chunks, 96.15% Dedup)                  │
 │       │                                                                                        │
 │       ▼                                                                                        │
 │  Crypto Core Engine (XChaCha20-Poly1305 AEAD + Blake2b KDF) ◄──► YubiKey PIV (Slot 9C Touch)   │
 │       │                                                                                        │
 │       ├──► Local OS Keyring (Windows DPAPI / account.key / vault.db WAL)                       │
 │       └──► Zero-Disk In-Memory Execution (ciphervault run -- npm start)                        │
 └───────┬────────────────────────────────────────────────────────┬───────────────────────────────┘
         │                                                        │
         │ Identity & Quorum TLS                                  │ Opaque Ciphertext Blobs
         │ (Passkey / Ed25519 Signatures)                         │ (Addressed ONLY by SHA-256 CID)
         ▼                                                        ▼
 ══════════════════════════════════════ TRUST BOUNDARY ═══════════════════════════════════════════════
         │                                                        │
         ▼                                                        ▼
 [ TIER 2: IDENTITY CONTROL PLANE ]                      [ TIER 3: DATA STORAGE PLANE ]
 ciphervault-account (:8300)                             Federated Storage Operators (:8201 - :8203)
 ┌──────────────────────────────────────────────┐        ┌────────────────────────────────────────┐
 │ • User Accounts (cvacct_...) & Display Names │        │  Storage Node 1 (cv-operator-1 :8201)  │
 │ • Public Device Keys & WebAuthn Passkeys     │        │  Storage Node 2 (cv-operator-2 :8202)  │
 │ • Team Memberships & Role Grants (RBAC)      │        │  Storage Node 3 (cv-operator-3 :8203)  │
 │ • Dual-Admin Four-Eyes Gate (24h Quorum TTL) │        ├────────────────────────────────────────┤
 │ • Immutable Merkle Audit Ledger Chaining     │        │  P2P Mesh Swarm (libp2p / DHT / DCUtR) │
 ├──────────────────────────────────────────────┤        ├────────────────────────────────────────┤
 │ ❌ ZERO Plaintext Secrets or Master Keys     │        │ ❌ ZERO User Accounts or Usernames     │
 │ ❌ CANNOT Decrypt Any Vault Chunks           │        │ ❌ ZERO Plaintext or Filenames         │
 └──────────────────────────────────────────────┘        └───────────────────▲────────────────────┘
                                                                             │
                                                         Durability Audits   │ Proof-of-Storage (PoS)
                                                         (461-byte challenge)│ Nonce Responses
                                                                             │
                                                         ┌───────────────────┴────────────────────┐
                                                         │ [ TIER 4: MAINTENANCE FLEET ]          │
                                                         │ ciphervault-maintenance daemon         │
                                                         │ Automated Health Audits & Self-Repair  │
                                                         └────────────────────────────────────────┘

 ═════════════════════════════════════════════════════════════════════════════════════════════════════
 [ TIER 5: IMMUTABLE ANCHORING ]                         [ TIER 6: AIR-GAPPED RECOVERY ]
 Arbitrum One L2 Rollup (Chain ID: 42161)                Zero-Vendor Sovereign Clean-Machine Restore
 ┌──────────────────────────────────────────────┐        ┌────────────────────────────────────────┐
 │  CipherVaultRegistry.sol                     │        │  Method A: Offline Paper Kit (Root R)  │
 │  EIP-712 Checkpoint Commitment Receipts      │        │  Method B: M-of-N Shamir Guardians     │
 └──────────────────────────────────────────────┘        └────────────────────────────────────────┘
====================================================================================================
```

</details>

---

## 🏛 Visual Network Architecture & Topology

[![CipherVault Network Topology & Security Boundaries](diagrams/08_network_topology.svg)](diagrams/08_network_topology.svg)

<details>
<summary><b>▶ Click to view raw Mermaid diagram definition (for live editors)</b></summary>

```mermaid
flowchart TB
    subgraph Workstation ["💻 DEVELOPER WORKSTATION (Sovereign Local Client)"]
        direction TB
        Files["📄 Secret Files\n(.env, server.key, certs)"]
        FastCDC["🧩 FastCDC Chunker\n(4 KiB min / 16 KiB avg / 64 KiB max)"]
        Crypto["🔐 Crypto Core Engine\n(XChaCha20-Poly1305 + Blake2b KDF)"]
        Keyring[("🛡️ OS Keystore\nWindows DPAPI / account.key / vault.db")]
        YubiKey["🔑 YubiKey PIV (PC/SC)\nSlot 9C Touch Signing"]
        ZeroDisk["⚡ Zero-Disk In-Memory Execution\n(ciphervault run -- npm start)"]
        Dashboard["🖥️ Local CLI & Dashboard\n(http://127.0.0.1:8080)"]

        Files --> FastCDC --> Crypto
        Crypto <--> Keyring
        Crypto -.->|"Touch APDU"| YubiKey
        Crypto -->|"Decrypted RAM ENV"| ZeroDisk
        Dashboard <--> Keyring
    end

    subgraph ControlPlane ["🏢 IDENTITY CONTROL PLANE (:8300)"]
        direction TB
        AcctSvc["👤 ciphervault-account Service\n(https://vault.cipherv.online/api/account)"]
        Passkeys["🔑 WebAuthn / Passkeys\n(Windows Hello, Touch ID, FIDO2)"]
        DualAdmin["👥 Dual-Admin Quorum Gate\n(Four-Eyes Approval & 24h TTL)"]
        AuditLog[("📜 Merkle Audit Ledger\n(Immutable Event Hash Chain)")]

        AcctSvc <--> Passkeys
        AcctSvc <--> DualAdmin
        DualAdmin --> AuditLog
    end

    subgraph DataPlane ["🗄️ STORAGE OPERATOR FEDERATION (:8201 - :8203)"]
        direction TB
        Op1["Node 1 (:8201)\nSHA-256 Chunks"]
        Op2["Node 2 (:8202)\nSHA-256 Chunks"]
        Op3["Node 3 (:8203)\nSHA-256 Chunks"]
        Mesh["🌐 P2P Mesh Swarm\n(libp2p / Kademlia DHT / DCUtR)"]
        Op1 <--> Mesh
        Op2 <--> Mesh
        Op3 <--> Mesh
    end

    subgraph Foundation ["⚓ SETTLEMENT, AUDITING & DISASTER RECOVERY"]
        direction LR
        Arbitrum["⛓️ Arbitrum One L2 (Chain ID: 42161)\nCipherVaultRegistry.sol (EIP-712 Checkpoint Anchors)"]
        Maint["🩺 Maintenance Fleet\nciphervault-maintenance (PoS Durability Challenger)"]
        Recovery["📜 Sovereign Clean-Machine Recovery\nMethod A: Paper Kit (R) | Method B: Shamir M-of-N"]
    end

    Dashboard ==>|"1. Identity & Quorum TLS (Ed25519 Signatures / Passkeys)"| AcctSvc
    Crypto ==>|"2. Replicate Opaque Ciphertext (Addressed ONLY by SHA-256 CID)"| DataPlane
    Crypto -.->|"3. State Commitments (Salted EIP-712 Hashes)"| Arbitrum
    Maint -.->|"4. Proof-of-Storage Audits (461-byte challenge/response)"| DataPlane
    Recovery ==>|"5. Bit-for-Bit Machine Recovery"| Workstation
```

</details>

---

### 2. Zero-Knowledge Confidential Data Lifecycle (How Secrets Move)

[![Zero-Knowledge Confidential Data Lifecycle](diagrams/10_data_lifecycle_flow.svg)](diagrams/10_data_lifecycle_flow.svg)

<details>
<summary><b>▶ Click to view raw Mermaid sequence definition (for live editors)</b></summary>

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI Runner
    participant WS as Local Workstation (FastCDC + AEAD)
    participant CP as Identity Control Plane (:8300)
    participant Ops as Storage Operators (:8201-:8203)
    participant L2 as Arbitrum One L2 Registry

    Note over Dev,WS: STEP 1: Local Encryption & Chunking
    Dev->>WS: ciphervault push (e.g., .env file changed)
    WS->>WS: FastCDC slices file into 4-64KB chunks
    WS->>WS: Encrypts chunks with XChaCha20-Poly1305 (Epoch Key)
    WS->>WS: Derives SHA-256 Content IDs (CIDs)

    Note over WS,CP: STEP 2: Quorum Gate (If Production Scope)
    opt Production Scope (Dual-Admin Gate)
        WS->>CP: POST /v1/projects/:id/commits (Commitment Request)
        CP-->>Dev: 202 Accepted (Pending second admin signature)
        Dev->>CP: Admin B signs approval (ciphervault approve)
        CP-->>WS: Quorum Token issued
    end

    Note over WS,Ops: STEP 3: Zero-Knowledge Replication
    WS->>Ops: Replicate opaque encrypted chunks [CID: fed13a...]
    Ops-->>WS: Replication ACK (Operator signatures)

    Note over WS,L2: STEP 4: Immutable L2 State Anchoring
    WS->>L2: Anchor state checkpoint (EIP-712 commitment)
    L2-->>WS: Sequencer receipt confirmed

    Note over Dev,WS: STEP 5: Zero-Disk Execution
    Dev->>WS: ciphervault run -- npm start
    WS->>Ops: Fetch encrypted chunks by CID
    WS->>WS: Decrypt directly into volatile RAM process environment
    WS->>Dev: App launches with injected secrets (ZERO plaintext on disk!)
    WS->>WS: Memory zeroized immediately on exit (ZeroizeOnDrop)
```

</details>

---

## 🛡️ Trust Boundaries & Separation of Planes

CipherVault is engineered around mathematical isolation: no single compromised component or network compromise leaks your secrets.

| Plane | Network Components & Ports | What It Stores | Isolation & Zero-Knowledge Guarantee |
|---|---|---|---|
| **Client Workstation** | CLI (`ciphervault`), TUI, Embedded Web UI (`127.0.0.1:8080`) | Plaintext `.env`, Master Secret $R$, Device signing keys, OS Keyring (`DPAPI`) | **Complete sovereignty.** Master keys and decryption routines never leave local RAM. Zeroize buffers immediately scrub sensitive memory on exit. |
| **Identity Control Plane** | [`services/account`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/account) (`:8300`) | Account IDs (`cvacct_...`), Public Keys, WebAuthn Passkeys, RBAC Roles | **No Secret Access.** Holds identities, device links, and quorum gates, but has **0% access** to vault encryption keys or file plaintexts. |
| **Data Storage Plane** | [`services/operator`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/operator) (`:8201-8203`), P2P Swarm | Opaque encrypted ciphertext chunks indexed by SHA-256 Content IDs (CIDs) | **No User Accounts.** Operators know nothing about usernames, passwords, or folder trees. They only store anonymous ciphertext blobs. |
| **Maintenance & Fleet** | [`services/maintenance`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/maintenance) daemon | Heartbeat logs, latency telemetry, Proof-of-Storage challenge receipts | Audits replica availability without ever downloading or decrypting full files. |
| **Settlement Layer** | Arbitrum One L2 (`Chain ID: 42161`), [`contracts/`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/contracts) | Salted EIP-712 checkpoint hashes | Mathematically anchors snapshot head state on an immutable public ledger. |
| **Offline Recovery** | Paper Kit / Shamir Guardians | $M$-of-$N$ $\text{GF}(2^8)$ Polynomial Shares | **Air-gapped.** Restores machines cleanly even if all cloud accounts, services, and local disks are completely destroyed. |

---

## 🔑 Key Lifecycle & Data Flows

### 1. Write / Push Flow (`ciphervault push`)
```text
Plaintext Secret File (.env)
  │
  ▼ [FastCDC Engine]
Content-Defined Chunks (4 KiB - 64 KiB)
  │
  ▼ [Crypto Core Engine]
Encrypted with XChaCha20-Poly1305 (Derived from Epoch Key via Blake2b KDF)
  │
  ▼ [Hardware Presence]
Optional Touch on YubiKey Slot 9C (Ed25519)
  │
  ▼ [HTTP / TLS Pool]
Replicated concurrently to Storage Operators as opaque blobs:
  ├── Storage Node 1 (:8201) ── [CID: fed13a...]
  ├── Storage Node 2 (:8202) ── [CID: fed13a...]
  └── Storage Node 3 (:8203) ── [CID: fed13a...]
```

### 2. Runtime Decryption Flow (`ciphervault run -- npm start`)
```text
Storage Operators (Encrypted Chunks)
  │
  ▼ [HTTP Fetch by CID]
Workstation RAM (Volatile Memory)
  │
  ▼ [Decrypt with Local Keyring]
Decrypted Environment Variables
  │
  ▼ [Fork Child Process]
Injected directly into child process environment (Zero Plaintext on Disk!)
  │
  ▼ [Process Exit]
Memory wiped immediately via ZeroizeOnDrop compiler fences.
```

### 3. Dual-Admin Quorum Flow (`services/account/src/grants.rs`)
```text
Admin A (Alice)
  │
  ├── Requests: Escalate Bob to Admin (role=admin)
  ▼
Account Service (:8300)
  ├── Creates: grant_requests row (Status: Pending, TTL: 24 Hours)
  └── Returns: 202 Accepted (Not yet granted)
  │
Admin A attempts self-approval?
  └── ❌ Rejected with 403 Forbidden (GrantError::SelfApproval)
  │
Admin B (Charlie) reviews request:
  ├── Approves: POST /v1/projects/:pid/members/requests/:rid/decision
  ▼
Account Service (:8300)
  ├── Role applied to Bob
  └── Event appended to cryptographic Merkle Audit Ledger
```

---

## 📡 Network Port & Protocol Reference

| Service / Binary | Default Port | Protocol | Scope | Description |
|---|---|---|---|---|
| **Local Dashboard / Explorer** | `8080` | HTTP / SSE | Loopback (`127.0.0.1`) | Local visual secrets explorer and inspection server. |
| **Storage Operator 1** | `8201` | HTTP / REST | Public / Clustered | Federated zero-knowledge storage node. |
| **Storage Operator 2** | `8202` | HTTP / REST | Public / Clustered | Federated zero-knowledge storage node. |
| **Storage Operator 3** | `8203` | HTTP / REST | Public / Clustered | Federated zero-knowledge storage node. |
| **P2P Swarm Gossip** | `8211-8213` | libp2p / TCP / UDP | Cluster Mesh | Peer discovery, Kademlia DHT, and DCUtR hole-punching. |
| **Account Service** | `8300` | HTTP / TLS | Control Plane | Device enrollment, WebAuthn passkeys, and RBAC policies. |
| **Arbitrum L2 Relayer** | `8787` | HTTP / REST | Private / Local | Automated batch relayer for on-chain state commitments. |

---

## 🔗 Related Documentation & References

* [`docs/ACCOUNT_IDENTITY_DESIGN.md`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/docs/ACCOUNT_IDENTITY_DESIGN.md) — Account vs. Vault Identity Architecture
* [`docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md) — AEAD and KDF Mathematical Specifications
* [`docs/SETUP_GUIDE.md`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/docs/SETUP_GUIDE.md) — Node Operator and Self-Hosting Guide
* [`services/account/src/grants.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/account/src/grants.rs) — Dual-Admin and Four-Eyes Implementation
* [`README.md`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/README.md) — Main Project Readme and Benchmark Specifications
