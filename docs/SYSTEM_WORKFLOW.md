# CipherVault: Comprehensive System Architecture & Operational Workflows

**Version:** `v1.0.0`  
**Classification:** Technical Architecture & Workflow Specification  
**Status:** Hardened Production Ready  

---

## 1. Executive System Overview

**CipherVault** is a zero-knowledge, developer-first secret backup and disaster recovery platform engineered in Rust and Solidity. It guarantees that confidential application configurations (e.g. `.env`, TLS private keys, database credentials, API tokens) can be reliably recovered on a clean replacement machine using only an offline paper recovery kit or distributed threshold guardian shares, without trusting or relying upon centralized coordinators, SaaS databases, or blockchain wallets.

### Fundamental Security Axioms
1. **Zero Plaintext at Rest**: Local database secrets (device signing keys, active epoch encryption keys) are protected using OS-native credential storage (Windows DPAPI or machine-entropy AEAD).
2. **Zero Plaintext Leakage to Operators**: Storage operators store opaque ciphertexts addressed by content digests (CIDs). Chunks, manifests, and head records are encrypted client-side using ChaCha20-Poly1305 with domain-separated derivation contexts.
3. **RAM Zeroization & Zero-Disk Recovery Kit**: The master recovery secret $R$ is never persisted unencrypted to disk. During vault initialization, $R$ is printed exclusively to the terminal and immediately scrubbed from volatile memory using compiler-fence memory zeroization (`Zeroize` / `ZeroizeOnDrop`).
4. **Autonomous Durability**: Replication requires proof-of-storage readback, while an autonomous maintenance fleet monitors replica durability and triggers self-repair across independent nodes.
5. **Trustless L2 Settlement**: Vault head state commitments can be anchored on Arbitrum L2, providing immutable sequencing and tamper-evident audit trails.

### Developer Operating Model: CipherVault vs. Traditional SaaS (e.g., GitHub)

Unlike traditional cloud SaaS tools where developers must register centralized accounts with email/passwords and entrust plaintext to third-party servers, CipherVault operates on **self-sovereign cryptography and zero-knowledge federated storage**:

| Dimension | GitHub / Cloud SaaS | CipherVault Architecture |
|---|---|---|
| **Identity & Access** | Centralized username, password, OAuth, and API tokens. | **Self-sovereign cryptographic keypairs** derived locally from Master Secret $R$. No email, account, or registration. |
| **Where Files Reside** | Centralized multi-tenant servers (e.g., Microsoft Azure / AWS). | **Untrusted Storage Operator Federation** holding opaque, client-side encrypted chunks. |
| **Server Knowledge** | Host servers can inspect plaintexts, files, and metadata. | **Zero Knowledge**: Operators only observe BLAKE2b content hashes (CIDs). |
| **New Computer Recovery** | Log in with password + 2FA $\to$ clone repo. | Download binary $\to$ run `ciphervault recover --kit kit.txt` (or Shamir shares) to restore bit-for-bit onto virgin machine. |
| **Blockchain / Wallet** | None. | **No cryptocurrency wallet required** (No MetaMask, seed phrases, or gas tokens for standard developer workflows). |
| **Developer Synchronization** | Explicit `git push` / `git pull`. | **Dual Operating Modes**: Explicit manual CLI (`push`) or fully automated background file watcher (`watch --sync`). |

### The Two Developer Operating Modes

```text
┌─────────────────────────────────────────────────────────────┐
│                    DEVELOPER WORKSTATION                    │
├──────────────────────────────┬──────────────────────────────┤
│  MODE 1: DELIBERATE MANUAL   │  MODE 2: AUTONOMOUS SYNC     │
│  (Like Git / Version Control)│  (Like Dropbox / Continuous) │
├──────────────────────────────┼──────────────────────────────┤
│ • ciphervault diff           │ • ciphervault watch --sync   │
│   (Inspect masked revisions) │   (Background kernel daemon) │
│ • ciphervault push -m "msg"  │ • Auto-detects editor saves  │
│   (Deliberate snapshot sync) │ • 2-second sliding debounce  │
│ • Custom commit messages     │ • FastCDC chunk dedup & push │
│ • Explicit team coordination │ • Hands-off silent backup    │
└──────────────────────────────┴──────────────────────────────┘
```

### System Architecture Map

![CipherVault System Architecture](./diagrams/01_system_architecture.svg)

<details>
<summary><b>View Mermaid Source Code</b></summary>

```mermaid
flowchart TB
    subgraph Client ["Client Workstation (CLI / TUI / Agent / Dashboard)"]
        FS[("Target Files\n.env, certs, keys")]
        CDC["FastCDC Dual-Mask\nChunk Chunker"]
        KDF["Cryptographic Engine\nArgon2id + HKDF + BLAKE2b"]
        DB[("Local SQLite WAL\n(DPAPI Encrypted)")]
        HSM["Hardware Token / YubiKey\n(PIV Slot 9C/9D)"]
        UI["TUI & Web Dashboard\n(ratatui / 127.0.0.1:8080)"]
    end

    subgraph Operators ["Storage Operator Cluster (Quorum)"]
        OP1["Operator 1\n(:8201)"]
        OP2["Operator 2\n(:8202)"]
        OP3["Operator 3\n(:8203)"]
    end

    subgraph Maintenance ["Durability & Fleet Daemon"]
        FLT["Maintenance Scheduler\n(:8200 / SQLite WAL)"]
    end

    subgraph Settlement ["Arbitrum L2 Rollup"]
        ARB["CipherVaultRegistry.sol\nSequencer Anchoring"]
    end

    FS --> CDC
    CDC --> KDF
    KDF --> DB
    KDF -.->|Touch Sign| HSM
    KDF ==>|Encrypted Chunks & PoS| Operators
    FLT -.->|Heartbeats & Self-Repair| Operators
    Client -.->|Anchor Commitment| ARB
    DB <--> UI
```
</details>

---

## 2. Distributed System Components

| Component | Technology | Primary Responsibilities | Network / Process Boundary |
|---|---|---|---|
| **CipherVault CLI** (`apps/cli`) | Rust, Tokio, Clap, Axum | Command-line interface for init, tracking, snapshots, anchoring, guardian ceremonies, and web dashboard hosting. | Local Client Workstation |
| **CipherVault Agent** (`apps/agent`) | Rust, Notify, Crossbeam | Background file-watcher service detecting secret file modifications and triggering debounced automated snapshots. | Local Daemon Service |
| **Local Store** (`crates/local-store`) | SQLite WAL, DPAPI, Rusqlite | Transactional persistence of tracked file manifests, snapshot history DAG, device certificates, and durable upload queues. | `.ciphervault/vault.db` |
| **Crypto Core** (`crates/crypto`) | ChaCha20-Poly1305, Ed25519, X25519, BLAKE2b, Shamir $\text{GF}(2^8)$ | Key hierarchy derivation, authenticated encryption, threshold secret sharing, and PIV APDU smartcard driver. | In-memory zeroized structures |
| **Snapshot Engine** (`crates/snapshot`) | Pure-Rust FastCDC, Gear Hash | Content-defined chunking, deduplication detection, snapshot serialization (canonical CBOR), and atomic restore. | In-memory stream processing |
| **Storage Operator** (`services/operator`) | Rust, Axum, RocksDB/Disk | Untrusted federated storage nodes holding encrypted chunks, serving PoS challenges, and storing recovery envelopes. | HTTP REST (`:8201-8203`) |
| **Maintenance Daemon** (`services/maintenance`) | Rust, Reqwest, Rusqlite | Continuous heartbeat probing, replica quorum auditing, PoS integrity verification, and autonomous self-repair. | HTTP REST (`:8200`) |
| **Arbitrum Registry** (`contracts/CipherVaultRegistry.sol`) | Solidity (0.8.28), Foundry | On-chain registration of state commitments (`setCommitment`), salt binding, and sequencer receipt validation. | Arbitrum One / Sepolia L2 |

---

## 3. Cryptographic Key Hierarchy

The CipherVault security model branches from a single 256-bit high-entropy Master Recovery Secret ($R$). All operational keys are derived deterministically via domain-separated HKDF-BLAKE2b trees:

![Cryptographic Key Derivation Hierarchy](./diagrams/02_key_hierarchy.svg)

<details>
<summary><b>View Mermaid Source Code</b></summary>

```mermaid
graph TD
    R["Master Recovery Secret (R)\n[32 Bytes High Entropy]"]
    
    subgraph RecoveryIdentities ["Recovery Identities (Public & Unwrapped)"]
        R_SK["Recovery Signing Private Key\nEd25519"]
        R_PK["Recovery Signing Public Key\n(Registered in Certificates)"]
        E_SK["Recovery Encryption Private Key\nX25519"]
        E_PK["Recovery Encryption Public Key\n(Target for Envelopes)"]
        LOC["Public Recovery Locator (L)\nBLAKE2b(R, 'locator')"]
    end

    subgraph EpochKeys ["Epoch Key Hierarchy"]
        EPOCH["Vault Epoch Key (EpochKey_v1)\nChaCha20-Poly1305 [32 Bytes]"]
        ENV["Epoch Key Recovery Envelope\nX25519 Box Sealed with E_PK"]
        FVK["File Version Key\nHKDF(EpochKey, VaultID, ContentDigest)"]
        NONCE["Deterministic Chunk Nonce\nHKDF(FVK, ChunkIdx, Plaintext)"]
    end

    subgraph DeviceIdentity ["Local Workstation Device Identity"]
        DEV_SK["Device Signing Private Key\n(Ed25519 / DPAPI Protected / YubiKey Slot 9C)"]
        DEV_PK["Device Public Key\n(Certified by R_SK in DeviceCertificate)"]
    end

    R -->|HKDF b'sign'| R_SK --> R_PK
    R -->|HKDF b'encrypt'| E_SK --> E_PK
    R -->|BLAKE2b b'locator'| LOC
    R -->|HKDF b'epoch_1'| EPOCH
    EPOCH --> ENV
    EPOCH --> FVK --> NONCE
    R_SK ==>|Signs Certificate| DEV_PK
    DEV_SK -.-> DEV_PK
```
</details>

---

## 4. End-to-End Operational Workflows

### Workflow 1: Vault Initialization (`ciphervault init`)

Initialization bootstraps a zero-knowledge confidential environment on the developer's machine without transmitting keys across any network:

![Workflow 1: Vault Initialization](./diagrams/03_vault_init_flow.svg)

<details>
<summary><b>View Mermaid Source Code</b></summary>

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / Admin
    participant CLI as CipherVault CLI
    participant KDF as Crypto KDF Engine
    participant DPAPI as OS Keyring (DPAPI)
    participant Store as Local SQLite (vault.db)
    participant Term as Terminal Stdout

    Dev->>CLI: ciphervault init [--operators ...]
    CLI->>KDF: Generate 32-byte Master Secret R (OsRng)
    KDF->>KDF: Derive Recovery Signing Keypair (Ed25519)
    KDF->>KDF: Derive Recovery Encryption Keypair (X25519)
    KDF->>KDF: Derive Public Locator L = BLAKE2b(R, "locator")
    KDF->>KDF: Derive Epoch 1 Key = HKDF(R, "epoch_1")
    KDF->>KDF: Generate Device Keypair (or probe YubiKey Slot 9C)
    KDF->>KDF: Sign DeviceCertificate with Recovery Signing Key
    
    CLI->>DPAPI: Encrypt Device Signing Key & Epoch Key
    DPAPI-->>CLI: DPAPI Ciphertext Blobs
    CLI->>Store: Persist encrypted keys, certificates & operator list (WAL Mode)
    
    CLI->>Term: Print Emergency Paper Recovery Kit (R, L, Checksums)
    CLI->>Dev: Prompt interactive confirmation: "Have you secured this kit?"
    Dev-->>CLI: Confirmed ("yes")
    CLI->>KDF: Zeroize master secret R from volatile process memory
    CLI->>Dev: Scan .gitignore for secret patterns (.env, *.key, etc.)
    alt Discovered Secrets Found
        CLI->>Dev: Prompt: "Track discovered secrets in CipherVault? [y/N]"
        Dev-->>CLI: Confirmed ("y") or passed --import-gitignore
        CLI->>Store: Register discovered secrets for encrypted tracking
    end
    CLI->>Dev: Vault ready (.ciphervault/ initialized)
```
</details>

**Security Invariants Enforced:**
* The paper kit contains the ONLY instance of $R$ in the universe.
* If the workstation is decommissioned, zero readable keys exist in `.ciphervault/vault.db` without Windows user logon credentials.
* `git status` automatically ignores `.ciphervault/` to prevent repository leaks.
* **Smart `.gitignore` Leak Defense & Discovery**: `ciphervault init` inspects `.gitignore` to onboard existing project secrets into encrypted tracking. Whenever secrets are tracked via `ciphervault track <path>`, CipherVault automatically verifies and appends them to `.gitignore` (unless `--no-gitignore` is specified), preventing plaintext secrets from ever being staged or committed to Git.

---

### Workflow 2: File Tracking & Snapshot Creation (`ciphervault push`)

When a developer changes secret files, `ciphervault push` executes content-defined chunking, deduplication checks, and encrypted replication:

![Workflow 2: FastCDC Deduplication & Hardware Push](./diagrams/04_push_dedup_flow.svg)

<details>
<summary><b>View Mermaid Source Code</b></summary>

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / Watcher Agent
    participant CLI as CLI Snapshot Engine
    participant CDC as FastCDC Engine
    participant AEAD as ChaCha20-Poly1305 Engine
    participant HSM as YubiKey PIV (Slot 9C)
    participant Pool as Multi-Operator Pool
    participant Ops as Storage Operators (1..N)
    participant Store as Local SQLite Store

    Dev->>CLI: ciphervault push -m "Rotate DB credentials" [--pos] [--touch]
    CLI->>Store: Read tracked files (.env, credentials.json)
    
    loop For each tracked confidential file
        CLI->>CDC: Slicing into chunks (min=4KB, avg=16KB, max=64KB)
        CDC-->>CLI: Yield chunk byte slices
        loop For each chunk
            CLI->>AEAD: Derive deterministic FileVersionKey & ChunkNonce
            AEAD->>AEAD: Encrypt chunk with ChaCha20-Poly1305 (AAD = CID)
            AEAD-->>CLI: Ciphertext chunk & Content Identifier (CID)
            
            alt Smart Deduplication / Proof-of-Storage Readback
                CLI->>Pool: POST /v1/objects/:cid/challenge (32-byte nonce)
                Pool->>Ops: Forward PoS Challenge
                alt Operator holds valid chunk
                    Ops-->>Pool: Signed PoS Receipt (429 bytes)
                    Pool-->>CLI: PoS Valid (Upload skipped! 99.96% bandwidth saved)
                else Chunk missing on operator
                    Pool-->>CLI: HTTP 404 Not Found
                    CLI->>Ops: PUT /v1/objects/:cid (Upload encrypted chunk)
                    Ops-->>CLI: HTTP 201 Created
                end
            end
        end
    end

    CLI->>CLI: Construct SnapshotRecord & Manifest (Canonical CBOR)
    
    alt Hardware Touch Signing Required (--touch)
        CLI->>HSM: Send APDU dynamic auth hash to Slot 9C
        HSM-->>Dev: Flashing LED / Wait for physical capacitive touch
        Dev->>HSM: Physical Touch on Hardware Token
        HSM-->>CLI: Hardware-backed Ed25519 Signature
    else Software Key Signing
        CLI->>AEAD: Sign SnapshotRecord with Device Signing Key
    end

    CLI->>Ops: Replicate SnapshotRecord to Quorum
    CLI->>Store: Update Local Head, commit SQLite WAL transaction
    CLI-->>Dev: ✓ Snapshot confirmed across 3/3 operators
```
</details>

**Key Performance & Efficiency Gains:**
* **FastCDC Boundary Realignment**: Modifying a line in a file only changes 1 chunk; all other chunks retain identical CIDs.
* **Deterministic Version Keying**: Chunks are deduplicated across snapshots for the same vault, while remaining cryptographically isolated across different vaults.
* **PoS Readback Challenge**: Replaced 1–4 MB full chunk readbacks with a 461-byte cryptographic handshake.

---

### Workflow 3: On-Chain Settlement on Arbitrum L2 (`ciphervault anchor`)

For tamper-evident sequencing and regulatory compliance, state commitments can be anchored on Arbitrum L2:

![Workflow 3: Arbitrum L2 Settlement](./diagrams/05_l2_settlement_flow.svg)

<details>
<summary><b>View Mermaid Source Code</b></summary>

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Administrator
    participant CLI as CLI Anchoring Engine
    participant Store as Local Vault Store
    participant Relayer as Automated L2 Relayer / RPC
    participant Seq as Arbitrum L2 Sequencer
    participant SC as CipherVaultRegistry.sol

    Dev->>CLI: ciphervault anchor --auto-relay
    CLI->>Store: Read active snapshot Head CID & Vault ID
    CLI->>CLI: Compute Commitment = BLAKE2b(VaultID || HeadCID || Salt)
    CLI->>CLI: Construct EIP-712 Checkpoint Evidence Payload
    
    CLI->>Relayer: POST /v1/relayer/checkpoint (Evidence)
    Relayer->>Relayer: Validate evidence signature against DeviceCertificate
    Relayer-->>CLI: HTTP 202 Accepted ("QueuedForRelay", block_number = 0)
    
    Relayer->>Seq: eth_sendRawTransaction(setCommitment(vaultId, commitment, salt))
    Seq->>SC: Execute state update on Arbitrum L2
    SC-->>Seq: StateCommitmentAnchored Event emitted
    
    loop Sequencer Receipt Polling
        CLI->>Relayer: GET /v1/relayer/checkpoint/:commitment/status
        alt Transaction Mined by Sequencer
            Relayer-->>CLI: "SequencerConfirmed", Block #308,231,027, TxHash: 0x...
        else Transaction Still in Sequencer Mempool
            Relayer-->>CLI: "QueuedForRelay"
        end
    end
    
    CLI->>Store: Record verified on-chain block receipt & explorer URL
    CLI-->>Dev: ✓ Checkpoint SequencerConfirmed on Arbitrum L2
```
</details>

---

### Workflow 4: Autonomous Fleet Durability & Self-Repair (`ciphervault-maintenance`)

The maintenance daemon runs as a continuous system service to ensure 3-of-3 replica durability across untrusted operator nodes:

![Workflow 4: Autonomous Fleet Durability & Self-Repair](./diagrams/06_maintenance_self_repair.svg)

<details>
<summary><b>View Mermaid Source Code</b></summary>

```mermaid
sequenceDiagram
    autonumber
    participant Daemon as Maintenance Daemon (:8200)
    participant M_DB as Fleet SQLite DB (fleet.db)
    participant Ops as Storage Operators (1..3)
    participant UI as Web Dashboard SSE Stream

    loop Every 15 Seconds (Configurable Interval)
        Daemon->>Ops: GET /v1/info (Heartbeat probe & latency test)
        Ops-->>Daemon: HTTP 200 OK (Latency: 12ms, 18ms, 999ms [Offline])
        
        Daemon->>Ops: Audit object closure via PoS challenge matrix
        alt Quorum intact (3/3 operators responsive)
            Daemon->>M_DB: Record Healthy Audit (0 lost, 0 degraded)
        else Degraded replica detected (Operator 1 dropped)
            Daemon->>M_DB: Record Degraded Audit (Operator 1 uncontactable)
            Daemon->>Daemon: Trigger Autonomous Self-Repair Protocol
            Daemon->>Ops: Read surviving chunks from Operator 2 & 3
            Ops-->>Daemon: Encrypted chunk streams
            Daemon->>Ops: Re-replicate missing chunks to replacement Operator 4
            Ops-->>Daemon: Replication ACK
            Daemon->>M_DB: Record Repaired State (3/3 replicas restored)
        end
        
        Daemon->>UI: Emit Live SSE Telemetry Event {"operators": [...], "durability": "100%"}
    end
```
</details>

---

### Workflow 5: Catastrophic Workstation Loss & Clean-Machine Disaster Recovery (`ciphervault recover`)

When the original development machine is destroyed, stolen, or lost, recovery proceeds onto a blank machine using **zero cached disk credentials**:

![Workflow 5: Clean-Machine Disaster Recovery](./diagrams/07_disaster_recovery_flow.svg)

<details>
<summary><b>View Mermaid Source Code</b></summary>

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer on Virgin Laptop
    participant CLI as ciphervault recover
    participant Term as Terminal / Paper Shares
    participant Ops as Storage Operator Federation
    participant Restore as Atomic Staging Directory (.ciphervault_staging_*)
    participant Target as Working Workspace

    Dev->>CLI: ciphervault recover --shares share1.txt share2.txt share3.txt
    CLI->>Term: Read M printable guardian shares (or single master secret R)
    CLI->>CLI: Verify CRC32 checksums on individual shares
    CLI->>CLI: Perform Shamir Lagrange Interpolation over GF(2^8) in RAM
    CLI->>CLI: Reconstruct Master Recovery Secret R
    CLI->>CLI: Derive Public Locator L = BLAKE2b(R, "locator")
    CLI->>CLI: Derive Recovery Encryption Keypair (E_SK, E_PK)
    
    CLI->>Ops: GET /v1/recovery/:locator/records
    Ops-->>CLI: Return signed RecoveryRecord with Epoch Key Envelope
    CLI->>CLI: Authenticate record signature against R_PK
    CLI->>CLI: Open sealed box using E_SK -> Yield VaultEpochKey
    
    CLI->>Ops: GET /v1/objects/:head_cid -> Fetch Head Record
    CLI->>CLI: Authenticate Head signature and decrypt Manifest
    
    CLI->>Restore: Create isolated staging directory (.ciphervault_staging_*)
    loop For each file declared in manifest
        loop For each chunk CID
            CLI->>Ops: GET /v1/objects/:cid
            Ops-->>CLI: Encrypted chunk ciphertext
            CLI->>CLI: Decrypt chunk with FileVersionKey & ChunkNonce
            CLI->>Restore: Append decrypted slice to staging file
        end
        CLI->>CLI: Verify reconstructed file SHA-256 matches manifest digest
    end
    
    CLI->>Target: Atomic Move / Rename (Replace destination files atomically)
    CLI->>Restore: Clean up temporary staging directory
    CLI->>CLI: Zeroize all recovery keys, R, and Epoch keys from RAM
    CLI-->>Dev: ✓ Disaster Recovery Complete: All secrets restored bit-for-bit
```
</details>

**Clean-Machine Guarantees:**
* **Zero Host Plaintext Dependency**: No passwords or cached keys required from the destroyed machine.
* **Atomic All-or-Nothing Integrity**: If a single chunk is corrupted or truncated, staging files are deleted; target files are NEVER left in a partial state.
* **100% Bit-for-Bit Fidelity**: Restored `.env` and cryptographic keys have zero byte discrepancy against original files.

---

### Workflow 6: Zero-Disk Secret Injection & Subprocess Execution (`ciphervault run`)

To eliminate plaintext `.env` files from developer laptops and production instances, `ciphervault run` streams secrets directly into child process environments:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI Pipeline
    participant CLI as CipherVault CLI Engine
    participant Store as Local SQLite Store (or Operators)
    participant Decrypt as In-Memory Decryption Engine
    participant Parser as Zero-Copy Dotenv Parser
    participant Child as Spawned Child Process (e.g. Node / Cargo / Python)

    Dev->>CLI: ciphervault run [--env-file ...] -- npm start
    CLI->>Store: Read active snapshot manifest & encrypted chunks
    CLI->>Decrypt: Decrypt chunks in RAM using VaultEpochKey (zero disk writes)
    Decrypt-->>CLI: DecryptedFile plaintexts in volatile heap
    CLI->>Parser: Parse KEY=VALUE pairs & strip comments/quotes
    Parser-->>CLI: In-memory environment variable key-value map
    CLI->>Decrypt: Zeroize in-memory file buffers (Zeroize::zeroize)
    CLI->>Child: Spawn child process with injected environment variables
    Child-->>CLI: Inherit stdio and run application
    Child-->>Dev: Execution completed (Exit status code propagated)
```

**Zero-Disk Security Invariants:**
* Plaintext credentials never touch disk, SSD swap blocks, or temporary files.
* Decrypted buffers are wiped with memory zeroization before child execution begins.
* `--dry-run` enables developers and security teams to inspect configured variable names without printing secret values or executing commands.

---

### Workflow 7: Autonomous Background File Watcher & Automated Sync (`ciphervault watch`)

CipherVault supports two distinct developer operating modes:
1. **Manual Mode (`ciphervault push`)**: Traditional Git-style explicit commits with user-supplied commit messages.
2. **Automated Continuous Mode (`ciphervault watch --sync`)**: Hands-off, real-time background synchronization whenever secrets are updated in developer editors (VS Code, Cursor, IntelliJ, etc.).

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer (Editor: VS Code / Cursor)
    participant FS as Host Filesystem (.env)
    participant Watcher as Autonomous Agent (ciphervault watch)
    participant Debounce as 2s Sliding Debounce Buffer
    participant CDC as FastCDC Engine
    participant AEAD as ChaCha20-Poly1305 Engine
    participant Ops as Storage Operator Federation

    Dev->>FS: Saves tracked secret (Ctrl+S in Editor)
    FS->>Watcher: Kernel event notification (ReadDirectoryChangesW / inotify / FSEvents)
    Watcher->>Watcher: Check path matches tracked secrets & ignore filters
    Watcher->>Debounce: Register modification event
    Note over Watcher,Debounce: Sliding 2-second debounce window collapses rapid multi-saves
    Debounce->>Watcher: Window elapsed; trigger coherent read
    Watcher->>FS: Read confidential file bytes & verify write completion
    Watcher->>CDC: Slices file using FastCDC Gear rolling hash
    CDC-->>Watcher: Dynamic chunk slices
    Watcher->>AEAD: Encrypt chunks under FileVersionKey & deterministic nonce
    AEAD-->>Watcher: Encrypted chunks & CIDs
    Watcher->>Ops: Replicate new chunks & update snapshot Head
    Ops-->>Watcher: Replication confirmation (3/3 operators durable)
    Watcher-->>Dev: Console notification: Snapshot auto-captured and pushed
```

**Watcher Invariants & Guarantees:**
* **Native Kernel Event Drivers**: Utilizes `ReadDirectoryChangesW` (Windows), `inotify` (Linux), and `FSEvents` (macOS) for sub-millisecond save detection with zero CPU polling overhead.
* **Sliding Debounce Window**: Defaults to 2 seconds (`--debounce <SECS>`) to collapse multiple rapid editor saves or autosaves into a single coherent snapshot.
* **Coherent Read Validation**: Verifies that the file write lock is released and complete before reading bytes into memory.
* **Content-Defined Deduplication**: FastCDC guarantees that localized edits only re-encrypt changed chunks, minimizing network payload to the cluster.
* **One-Click Launch**: Can be started in the background via `start-watcher.bat` or added to workstation startup scripts.

---

### Workflow 8: Encrypted Secret Diffing & Shoulder-Surfing Defense (`ciphervault diff`)

Developers and security engineers can inspect changes between secret revisions without exposing plaintext values to screen recorders or shoulder surfers:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / Security Auditor
    participant CLI as ciphervault diff
    participant Store as Local Store (vault.db)
    participant FS as Working Filesystem (.env)

    Dev->>CLI: ciphervault diff [--reveal] [--file <path>] [--json]
    CLI->>Store: Fetch active head manifest & decrypt in RAM
    CLI->>FS: Read tracked secret files from disk
    CLI->>CLI: Parse dotenv/plain key-values & compute diff set
    alt Default Mode (No --reveal)
        CLI->>CLI: Apply mask_value(k, v) -> "sk_live_***...a8f"
        CLI-->>Dev: Display colorized diff with masked secret values
    else Explicit --reveal
        CLI-->>Dev: Display colorized diff with unmasked plaintext values
    end
    CLI->>CLI: Zeroize in-memory secret buffers
```

* **Default Shoulder-Surfing Mask**: All secret values display as `***...` with leading and trailing hint characters unless `--reveal` is explicitly passed.
* **Revision Modes**: Compares working tree vs head (`ciphervault diff`), working tree vs specific snapshot (`ciphervault diff <snap_id>`), or between two snapshots (`ciphervault diff <snap_a> <snap_b>`).
* **Format-Aware**: Performs semantic key-level diffing for `.env` files (added, removed, modified, unchanged) and line-level diffing for general confidential files.

---

### Workflow 9: Multi-Workstation Synchronization (`ciphervault pull`)

When collaborating across team laptops or updating build servers, `ciphervault pull` updates secrets securely:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer on Workstation B
    participant CLI as ciphervault pull
    participant Store as Local Store (vault.db)
    participant Ops as Storage Operator Federation
    participant FS as Working Filesystem

    Dev->>CLI: ciphervault pull [--dry-run] [--force]
    CLI->>Store: Load vault locator & recovery signing public key
    CLI->>Ops: POST /v1/recovery/:locator/query
    Ops-->>CLI: Quorum of signed head records
    CLI->>CLI: Cryptographically select authentic latest head
    alt Local Head == Remote Head
        CLI-->>Dev: ✓ Already up to date with operator cluster
    else Newer Remote Head Found
        CLI->>FS: Check for uncommitted local modifications
        alt Uncommitted dirty files exist and !force
            CLI-->>Dev: ✗ Abort: Local tracked files modified (use --force)
        else Clean or --force
            CLI->>Ops: Fetch missing chunk objects by CID
            Ops-->>CLI: Encrypted chunk wire objects
            CLI->>CLI: Decrypt manifest & verify closure integrity
            CLI->>FS: Atomically restore updated secrets into workspace
            CLI->>Store: Save snapshot, chunks, and advance local active head
            CLI-->>Dev: ✓ Successfully synchronized with operator cluster
        end
    end
```

---

### Workflow 10: Zero-Disk Secret Execution in CI/CD Runners

Automated build and release pipelines inject secrets dynamically without persistent disk writes:

```mermaid
sequenceDiagram
    autonumber
    participant CI as GitHub / GitLab CI Runner
    participant Action as Composite Action (ciphervault-run)
    participant CLI as ciphervault run
    participant Child as Build Subprocess (e.g. docker build)

    CI->>Action: uses: ./.github/actions/ciphervault-run
    Action->>CLI: ciphervault run --quiet -- <command>
    CLI->>CLI: Decrypt snapshot secrets into volatile RAM
    CLI->>Child: Spawn child process with injected environment block
    Note over CLI,Child: Zero secrets ever written to runner disk!
    Child-->>CLI: Subprocess completes execution
    CLI->>CLI: Overwrite secret memory buffers with zeroes (Zeroize)
    CLI-->>Action: Forward child process exit code
    Action-->>CI: Build pipeline step succeeds cleanly
```

---

### Workflow 11: Dynamic P2P Operator Discovery & Gossip Protocol

Decentralized operator clusters discover active peers dynamically without requiring static IP configuration:

```mermaid
sequenceDiagram
    autonumber
    participant OpNew as New Operator Node (Beta)
    participant OpSeed as Seed Operator (Alpha)
    participant Client as Client MultiOperatorPool

    OpNew->>OpNew: Generate PeerDescriptor(ID, Endpoint, Timestamp)
    OpNew->>OpNew: Sign descriptor with Ed25519 node key (operator_peer_gossip)
    OpNew->>OpSeed: POST /v1/peers/announce (PeerDescriptor)
    OpSeed->>OpSeed: Verify Ed25519 signature & update peer_routing_table
    OpSeed-->>OpNew: 200 OK (Registration accepted)
    
    Client->>OpSeed: GET /v1/peers
    OpSeed-->>Client: 200 OK (List of active, verified PeerDescriptors)
    Client->>Client: Verify each PeerDescriptor signature
    Client->>Client: Dynamically expand MultiOperatorPool endpoints
    Client->>OpNew: Perform read/write/recovery operations directly
```

---

### Workflow 12: Out-of-Band Push Approvals for Emergency Disaster Recovery

Clean-machine emergency recovery can be gated upon out-of-band cryptographic approval receipts signed by authorized team leads or guardians:

```mermaid
sequenceDiagram
    autonumber
    participant Target as Recovering Machine (ciphervault recover --require-approval)
    participant Cluster as Operator Federation
    participant Lead as Security Lead / Approver (ciphervault approve)

    Target->>Target: Generate ApprovalChallenge(VaultID, Action, TTL=600s)
    Target->>Cluster: POST /v1/auth/challenges (Broadcast challenge)
    Cluster-->>Target: Challenge registered; awaiting approval receipt
    
    Lead->>Cluster: GET /v1/auth/challenges/pending (ciphervault approve list)
    Cluster-->>Lead: List of active challenges with details and TTL
    Lead->>Lead: Review target directory, vault ID, and action
    Lead->>Lead: Sign challenge with device/guardian key (out_of_band_approval)
    Lead->>Cluster: POST /v1/auth/challenges/:id/approve (SignedApprovalReceipt)
    Cluster->>Cluster: Verify receipt signature & mark challenge approved
    
    loop Polling (Every 500ms, up to TTL)
        Target->>Cluster: GET /v1/auth/challenges/:id
        Cluster-->>Target: 200 OK (approved: true, receipts: [SignedApprovalReceipt])
    end
    Target->>Target: Verify approver signature & proceed with snapshot restoration
```

---

## 6. Security Invariants Matrix

| Attack / Failure Vector | Mitigating Subsystem | Cryptographic / Architectural Guarantee |
|---|---|---|
| **Workstation Theft / Disk Forensic Dump** | OS Keyring Encrypted Store | Local SQLite database keys are DPAPI-encrypted; master secret $R$ is zeroized from disk and RAM. |
| **Storage Operator Compromise / Rogue Host** | AEAD Client-Side Encryption | Operators only store encrypted chunks ($CID = \text{BLAKE2b}(C)$); zero plaintext or file paths are ever sent. |
| **Malicious Operator Record Injection** | Cryptographic Authorization Boundary | `POST /v1/recovery/:locator/records` verifies Ed25519 signatures against $R_{PK}$ or valid `DeviceCertificate`. |
| **Man-in-the-Middle Checkpoint Spoofing** | Live Arbitrum L2 Settlement | Checkpoints include EIP-712 structured evidence and sequencer receipt verification against `CipherVaultRegistry.sol`. |
| **Single Operator Outage / Data Center Fire** | Multi-Operator Quorum & Maintenance | 3-node replication with autonomous fleet repair reconstitutes degraded chunks onto healthy operators. |
| **Key Extraction via Debugger / Memory Dump** | `ZeroizeOnDrop` Hygiene | `RecoverySecret`, `VaultEpochKey`, and `FileVersionKey` wipe stack and heap buffers immediately upon falling out of scope. |
| **Corrupted Download During Restore** | Atomic Staging Directory | Chunks are assembled in `.ciphervault_staging_*` and validated against declared SHA-256 digests before touching working directories. |
| **Unauthorized Snapshot Commit** | Hardware Token (YubiKey PIV) | Enforces physical capacitive touch confirmation (`Slot 9C`) before signing snapshot head records. |
| **Shoulder Surfing / Visual Secret Leakage** | Encrypted Diff Engine | Secret values in `ciphervault diff` masked with `***` unless `--reveal` is explicitly supplied. |
| **Accidental Overwrite on Remote Pull** | Working Tree Dirty Guard | `ciphervault pull` aborts if local tracked files have uncommitted edits unless `--force` is given. |
| **CI/CD Plaintext Disk Persistence** | Zero-Disk Secret Injection | `ciphervault run` passes decrypted secrets strictly via in-memory process environment blocks. |
| **Cache-Timing / Branch Microarchitectural Attacks** | Branchless $\text{GF}(2^8)$ Galois Field Arithmetic | Elimination of secret-dependent branches in Shamir Secret Sharing multiplication via bitwise masking. |
| **Rogue Operator Impersonation & Sybil Attacks** | P2P Signed Gossip Descriptors | Peer discovery requires Ed25519 domain-separated signatures (`operator_peer_gossip`) with timestamp freshness. |
| **Unapproved Clean-Machine Secret Extraction** | Out-of-Band Push Authorization | Emergency recovery enforced through cryptographic challenge receipts signed by team leads or threshold guardians. |

---

## 7. Verification Commands & Diagnostics

To verify the operational workflow on any environment:

```powershell
# 1. Run Complete Rust Workspace Test Suite
cargo test --workspace --locked --offline

# 2. Run Hardware Smartcard APDU Ceremony Tests
cargo test --test hardware_token --locked --offline

# 3. Run End-to-End Multi-Operator Chaos & Disaster Drill
powershell -ExecutionPolicy Bypass -File deploy/chaos_drill.ps1

# 4. Verify Live Arbitrum Settlement Deployer
node scripts/deploy-registry.cjs --network arbitrum_sepolia

# 5. Launch Hardened Production Ingress & Multi-Container Cluster
docker compose -f deploy/docker-compose.prod.yml up -d
docker compose -f deploy/docker-compose.prod.yml ps

# 6. Run Automated Staging & Disaster Verification Drill
powershell -ExecutionPolicy Bypass -File scripts/verify-cluster.ps1

# 7. Launch Interactive Terminal Operations Console (TUI)
ciphervault tui
# or run the one-click Windows launcher:
.\launch-tui.bat

# 8. Launch Autonomous File Watcher Daemon
ciphervault watch --debounce 2 --sync
# or run the one-click Windows launcher:
.\start-watcher.bat
```
