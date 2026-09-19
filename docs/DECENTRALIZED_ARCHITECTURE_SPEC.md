# CipherVault Decentralized Operator Network (DON)
## Technical Architecture, Structural Design & Zero-Downtime Implementation Plan

**Classification:** System Architecture Specification & Engineering Roadmap  
**Target Version:** v2.0.0 (Progressive Non-Breaking Upgrade from v1.0.6)  
**Status:** Under Review / Open for Technical Questioning  
**Author:** Antigravity Architecture Group & Samuel Avson  

---

## 📋 Table of Contents
1. [Executive Summary & Core Philosophy](#1-executive-summary--core-philosophy)
2. [Macro System Architecture](#2-macro-system-architecture)
3. [Micro Component Design & Crate Structure](#3-micro-component-design--crate-structure)
4. [Detailed Network Protocols & Data Flows](#4-detailed-network-protocols--data-flows)
5. [Backward Compatibility & Zero-Breakage Guarantees](#5-backward-compatibility--zero-breakage-guarantees)
6. [Step-by-Step Phased Implementation Plan](#6-step-by-step-phased-implementation-plan)
7. [Threat Model, Sybil Defense & Economic Incentives](#7-threat-model-sybil-defense--economic-incentives)
8. [Architectural Review & Questioning Guide](#8-architectural-review--questioning-guide)

---

## 1. Executive Summary & Core Philosophy

### 1.1 The Objective
Transform CipherVault from a **static 3-node federated cluster** into a **100% decentralized, self-organizing, sovereign Peer-to-Peer (P2P) storage network** capable of serving **500,000 to 10,000,000+ users** with zero central cloud infrastructure costs, zero single points of failure, and zero corporate dependency.

### 1.2 The Golden Invariant: "Never Break Working Systems"
The existing static federated mode (`ciphervault init --operators http://...`, local Docker Compose, and self-hosted private VPS clusters) is heavily tested, stable, and essential for private corporate intranets. 

**Non-Negotiable Rule**: All decentralization features must be **strictly additive and interface-compatible**.
* A developer running `ciphervault init --operators http://127.0.0.1:8201` must experience **zero breaking changes**.
* An operator configured in static mode must continue operating with zero code regressions.
* The decentralized network is activated via progressive flags (e.g., `--p2p` / `--network mainnet`).

---

## 2. Macro System Architecture

```text
===================================================================================================
                                GLOBAL DECENTRALIZED TOPOLOGY
===================================================================================================

  [ Developer Workstation / CI Runner ]
      │
      ├── Local Keyring: Master Secret R, Epoch Envelopes, Device Keys (OS Keyring / DPAPI)
      ├── Snapshot Engine: FastCDC Slicing (Gear Hash) -> Content IDs (BLAKE2b-512)
      │
      ▼ (P2P Stream over libp2p)
  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐
  │                         KADEMLIA DISTRIBUTED HASH TABLE (DHT)                               │
  │                                                                                             │
  │     [Node 01 (US-East)] ─────────── [Node 02 (Frankfurt)] ─────────── [Node 03 (Tokyo)]     │
  │            │                                │                                │              │
  │       (P2P Gossip)                     (P2P Gossip)                     (P2P Gossip)        │
  │            │                                │                                │              │
  │     [Node 04 (São Paulo)] ───────── [Node 05 (London)] ────────────── [Node 06 (Sydney)]    │
  │                                                                                             │
  │  • Nodes discover peers via Kademlia XOR routing & local mDNS.                              │
  │  • Chunks map to the k=3 closest physical nodes on the 256-bit keyspace.                    │
  │  • Neighbor nodes continuously ping each other and autonomously heal missing replicas.     │
  └──────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                         │
                                         ▼ (Periodic Trustless Settlement)
  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐
  │                         ARBITRUM ONE (ETHEREUM L2 ROLLUP)                                   │
  │                                                                                             │
  │   1. CipherVaultRegistry.sol:                                                               │
  │      • Operator Registry & Collateral Staking (Sybil prevention & reputation score).        │
  │      • Batched Merkle Roots (Aggregates 100k snapshot commitments in 1 hourly tx).          │
  │      • Micro-Lease Escrow (Streams micropayments to operators providing valid PoS).         │
  └─────────────────────────────────────────────────────────────────────────────────────────────┘
===================================================================================================
```

### 2.1 The Three Core Planes

1. **Client Execution Plane (Local Workstation)**:
   * Client-side zero-knowledge encryption (`XChaCha20-Poly1305`).
   * FastCDC dynamic boundary chunking (4/16/64 KiB).
   * Local SQLite database (`vault.db`) holding local heads, device certs, and staging queues.
   * Emergency recovery kit generation ($R$ zeroized from RAM).

2. **Storage Swarm Plane (Independent Operator Mesh)**:
   * Content-addressed chunk storage (addressed strictly by BLAKE2b hash; zero metadata).
   * Kademlia DHT routing table (`libp2p-kad`) organizing nodes by Node ID distance.
   * Proof-of-Storage (PoS) nonce challenge responder (461-byte mathematical proofs).
   * Peer Gossip & Neighbor Repair Worker (auto-replicates when peers go dark).

3. **Settlement & Identity Plane (Arbitrum One Blockchain)**:
   * Open smart contract registry for node discovery and staking.
   * Merkle batch verification: eliminates high gas fees by settling tens of thousands of commits per transaction.
   * Micro-lease streaming: automated micropayments for durable storage.

---

## 3. Micro Component Design & Crate Structure

To avoid disrupting existing code, we introduce modular traits and a new P2P networking module without rewriting core packages.

```text
CipherVault/
├── crates/
│   ├── crypto/                 # UNTOUCHED: Core AEAD, KDF, Shamir, YubiKey APDU
│   ├── format/                 # EXTENDED: Add P2P CBOR wire messages (Voucher, SwarmAnnouncement)
│   ├── snapshot/               # UNTOUCHED: FastCDC chunker & atomic restore engine
│   ├── local-store/            # EXTENDED: Local operator cache & peer routing table schema
│   ├── recovery/               # UNTOUCHED: Paper kit & M-of-N threshold math
│   └── storage/                # REFACTORED: Introduce StoragePool trait
│       ├── pool.rs             # Existing MultiOperatorPool (implements StoragePool)
│       ├── p2p_pool.rs         # [NEW] P2pOperatorPool (implements StoragePool via libp2p)
│       └── traits.rs           # [NEW] StoragePool & OperatorTransport traits
│
├── services/
│   ├── operator/               # EXTENDED: Add P2P Swarm Capability
│   │   ├── src/
│   │   │   ├── main.rs         # Accepts --p2p, --bootstrap-nodes, --stake-key
│   │   │   ├── state.rs        # Existing state logic
│   │   │   ├── handlers.rs     # Existing HTTP handlers
│   │   │   ├── store/          # [NEW] Pluggable ObjectStore trait (LocalDisk vs RocksDB vs S3)
│   │   │   └── swarm/          # [NEW] libp2p swarm engine, DHT behavior, PoS protocol
│   │   └── Cargo.toml          # Add libp2p (features = ["tokio", "kad", "gossipsub", "noise", "tcp"])
│   │
│   ├── maintenance/            # EXTENDED: Standalone fleet auditor OR decentralized peer mode
│   └── account/                # UNTOUCHED: Remains optional hosted control plane
│
├── contracts/
│   ├── CipherVaultRegistry.sol # EXTENDED: Add operator staking, heartbeats, and Merkle roots
│   └── test/                   # Expanded Foundry tests
```

---

## 4. Detailed Network Protocols & Data Flows

### 4.1 Trait Abstraction (The Key to Zero-Breakage)

Currently, the CLI talks directly to HTTP operator endpoints through `MultiOperatorPool`. 
We define a unified `StoragePool` trait in `crates/storage/src/traits.rs`:

```rust
#[async_trait]
pub trait StoragePool: Send + Sync {
    /// Upload a chunk to the required quorum of operators
    async fn put_chunk(&self, cid: &ChunkId, data: &[u8]) -> Result<Vec<LeaseReceipt>>;
    
    /// Download a chunk from any available healthy operator
    async fn get_chunk(&self, cid: &ChunkId) -> Result<Vec<u8>>;
    
    /// Execute a bandwidth-optimized Proof-of-Storage challenge
    async fn verify_pos(&self, cid: &ChunkId, nonce: &[u8; 32]) -> Result<bool>;
    
    /// Query active operators/peers
    async fn list_peers(&self) -> Result<Vec<PeerInfo>>;
}
```

* **Static HTTP Mode**: `MultiOperatorPool` implements `StoragePool` (Legacy behavior, 100% preserved).
* **Decentralized P2P Mode**: `P2pOperatorPool` implements `StoragePool` (New swarm behavior).
* **CLI & Snapshot Engine**: The CLI interacts strictly with the `StoragePool` trait. It doesn't know (or care) whether data travels over HTTP or libp2p DHT!

---

### 4.2 Sequence Diagram: Node Join & Staking

```text
[ New Operator Node ]           [ Arbitrum Smart Contract ]           [ P2P DHT Swarm ]
         │                                   │                               │
         ├── 1. Generate Ed25519 Node Key    │                               │
         ├── 2. Submit stake deposit ───────▶│                               │
         │      (e.g., 50 ARB collateral)    │                               │
         │                                   ├── 3. Record in Registry       │
         │                                   │      (Emits OperatorJoined)   │
         │                                   │                               │
         ├── 4. Connect to Bootstrap Node ──────────────────────────────────▶│
         ├── 5. Broadcast Kad Swarm Ping (Multiaddr + Stake Tx Hash) ───────▶│
         │                                                                   │
         ◀── 6. Routing table populated with neighbor peer nodes ────────────┘
```

---

### 4.3 Sequence Diagram: Client Upload & Kademlia Replication ($k=3$)

```text
[ Client (ciphervault push) ]             [ Kademlia DHT ]             [ 3 Closest Operators ]
             │                                   │                               │
             ├── 1. FastCDC: Chunk CID = 7a3f    │                               │
             ├── 2. Query: "Who holds 7a3f?" ───▶│                               │
             │                                   ├── 3. Compute XOR distance     │
             │                                   │      Find Node A, B, C        │
             │                                   │                               │
             ◀── 4. Return Node A, B, C addresses ┘                               │
             │                                                                   │
             ├── 5. Stream encrypted chunk concurrently ────────────────────────▶│
             │      (Payload = XChaCha20 ciphertext + Ed25519 Client Sig)       │
             │                                                                   │
             │                                   ┌───────────────────────────────┤
             │                                   │ Verify Client Signature       │
             │                                   │ Check Lease Lock              │
             │                                   │ Persist to objects/7a3f       │
             │                                   └───────────────────────────────┤
             │                                                                   │
             ◀── 6. Return 3x Signed LeaseReceipts ──────────────────────────────┘
```

---

### 4.4 Sequence Diagram: Autonomous Peer Self-Healing

What happens when an operator node disappears from the network?

```text
[ Operator A (US) ]         [ Operator B (EU) ]         [ Operator C (Asia) ]      [ Operator D (Neighbor) ]
         │                           │                            │                            │
         │ (Holds Chunk 7a3f)        │ (Goes Offline / Crashes)   │ (Holds Chunk 7a3f)         │ (Empty)
         │                           X                            │                            │
         │                                                        │                            │
         │                                                        ├── 1. Pings B (Timeout) ───▶│
         │                                                        ├── 2. Gossip: "Node B dead"─▶│
         │                                                        │                            │
         │                                                        │                            ├── 3. D computes distance:
         │                                                        │                            │      "I am the next closest
         │                                                        │                            │       node for Chunk 7a3f"
         │                                                        │                            │
         ◀────────────────────────────────────────────────────────┼────────────────────────────┼── 4. D fetches chunk from A
         │                                                        │                            │
         ├── 5. Sends verified Chunk 7a3f (Matches BLAKE2b hash) ─────────────────────────────▶│
         │                                                        │                            │
         │                                                        │                            ├── 6. D stores chunk,
         │                                                        │                            │      claims lease escrow
         │                                                        │                            │
         ▼                                                        ▼                            ▼
                      Quorum fully restored to 3/3 without client involvement!
```

---

## 5. Backward Compatibility & Zero-Breakage Guarantees

To ensure that upgrading the system never breaks existing workflows:

### 1. Database Schema Forward-Compatibility
The local SQLite database (`vault.db`) in `crates/local-store` receives non-destructive migrations:
* Existing tables (`tracked_files`, `snapshots`, `device_certs`) remain **100% untouched**.
* A new optional table `p2p_peers` is added:
  ```sql
  CREATE TABLE IF NOT EXISTS p2p_peers (
      peer_id TEXT PRIMARY KEY,
      multiaddr TEXT NOT NULL,
      last_seen_utc INTEGER NOT NULL,
      latency_ms INTEGER,
      staked_collateral TEXT
  );
  ```

### 2. Dual-Mode Storage Operator
The `ciphervault-operator` binary will support running both HTTP and P2P interfaces on the same machine:
```bash
# Legacy / Private Mode (Runs standard Axum HTTP server)
ciphervault-operator --port 8201 --data-dir ./data

# Dual Mode (Runs Axum HTTP on :8201 AND libp2p swarm on :9201)
ciphervault-operator --port 8201 --p2p-port 9201 --data-dir ./data --enable-p2p

# Pure P2P Swarm Mode (Headless, no open HTTP port required)
ciphervault-operator --p2p-port 9201 --data-dir ./data --headless
```

### 3. CLI Invocation Compatibility
The developer CLI keeps all default behaviors:
```bash
# Existing static workflow (Unchanged, continues working)
ciphervault init --operators http://127.0.0.1:8201 http://127.0.0.1:8202

# New decentralized swarm workflow (Opt-in)
ciphervault init --p2p --network arbitrum-one
```

---

## 6. Step-by-Step Phased Implementation Plan

We execute the transition across **5 controlled phases**. Each phase ends with a strict verification gate and unit test suite before the next phase begins.

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│                          PHASED ROADMAP OVERVIEW                                  │
├───────────────────────────────────────────────────────────────────────────────────┤
│ Phase 1: Storage Trait Abstraction (Internal Refactor - Zero Behavior Change)     │
│ Phase 2: Libp2p Transport & Kademlia DHT Engine (Core P2P Mesh)                   │
│ Phase 3: Smart Contract Expansion & Merkle Rollup Batcher (On-Chain Layer)        │
│ Phase 4: Autonomous Peer Self-Healing & Proof-of-Storage Escrow (Durability Engine│
│ Phase 5: CLI Dual-Mode Integration & Full Chaos Engineering Drill (Launch)        │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

### 🔹 Phase 1 — Storage Trait Abstraction
* **Goal**: Decouple client code from HTTP networking.
* **Tasks**:
  1. Define `StoragePool` and `OperatorTransport` traits in `crates/storage/src/traits.rs`.
  2. Implement `StoragePool` on the existing `MultiOperatorPool`.
  3. Update `apps/cli` to consume `Arc<dyn StoragePool>`.
  4. Create an `ObjectStore` trait in `services/operator` so the storage engine can write to local disk, RocksDB, or memory.
* **Gate / Verification**: Run `cargo test --workspace --locked`. 100% of existing tests must pass with zero regression.

---

### 🔹 Phase 2 — Libp2p Transport & Kademlia DHT
* **Goal**: Enable operator nodes to discover each other and exchange chunks over P2P streams.
* **Tasks**:
  1. Add `libp2p` dependency to `crates/storage` and `services/operator` (Tokio runtime).
  2. Implement `CipherVaultSwarm`:
     * Transport: TCP + Noise protocol (encryption) + Yamux (multiplexing).
     * Behavior: Kademlia (`libp2p-kad`) + Gossipsub (`libp2p-gossipsub`) + Ping.
  3. Implement chunk transmission protocol over P2P stream:
     * Request: `PushChunkRequest { cid, data, signature }`
     * Response: `PushChunkResponse { receipt }`
  4. Implement `P2pOperatorPool` in `crates/storage/src/p2p_pool.rs`.
* **Gate / Verification**: Unit tests spinning up 5 virtual in-memory P2P nodes, pushing a chunk to Node 1, and verifying retrieval from Node 5 via DHT routing.

---

### 🔹 Phase 3 — Smart Contract Expansion & Merkle Batching
* **Goal**: Provide trustless operator discovery and cost-effective on-chain anchoring on Arbitrum One.
* **Tasks**:
  1. Update `contracts/CipherVaultRegistry.sol`:
     * Add `registerOperator(bytes32 operatorKey, string multiaddr)` with collateral bond.
     * Add `submitBatchRoot(bytes32 merkleRoot, uint256 count)` for 100k-to-1 rollup commitments.
     * Add `deregisterOperator()` with unbonding challenge period.
  2. Write Solidity unit & fuzz tests in `contracts/test/`.
  3. Build the Merkle Batcher worker inside `services/operator` to aggregate snapshot hashes.
* **Gate / Verification**: `forge test` passes with 100% branch coverage and gas optimization checks.

---

### 🔹 Phase 4 — Autonomous Peer Self-Healing & PoS Escrow
* **Goal**: Ensure the network automatically heals corrupted or missing chunks without human intervention.
* **Tasks**:
  1. Implement the **Neighbor Gossip Monitor**:
     * Each operator actively heartbeats its $k=3$ predecessor and successor nodes on the hash ring.
     * If a neighbor fails 3 consecutive heartbeats, mark it degraded.
  2. Implement the **Self-Healing Replication Loop**:
     * The surviving neighbor queries the DHT for alternative chunk replicas.
     * Streams the missing chunks and stores them locally to maintain $k=3$ replication.
  3. Integrate Proof-of-Storage challenge readbacks into the P2P swarm loop.
* **Gate / Verification**: Chaos test: Spin up 10 virtual operators, upload 50 chunks, forcibly kill 3 operators, and assert that surviving nodes recover all chunks back to 3/3 replication within 15 seconds.

---

### 🔹 Phase 5 — CLI Dual-Mode Integration & Release Gate
* **Goal**: Expose decentralized capabilities cleanly to developers while maintaining full backward compatibility.
* **Tasks**:
  1. Add `--p2p` flag to `ciphervault init`, `push`, `pull`, and `recover`.
  2. Add P2P swarm telemetry tab to the Ratatui TUI (`ciphervault tui` View `[4] Swarm`).
  3. Update `ciphervault doctor` to perform DHT peer connectivity and NAT traversal checks.
  4. Run full workspace regression suites and documentation checks.
* **Gate / Verification**: Clean-machine disaster recovery drill performed exclusively over the decentralized P2P testnet.

---

## 7. Threat Model, Sybil Defense & Economic Incentives

```text
┌──────────────────────────────┬───────────────────────────────────────────────────────────┐
│ Adversarial Threat           │ Countermeasure & Protocol Invariant                       │
├──────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 1. Sybil Node Inundation     │ Operators must stake collateral (e.g., 50 ARB) on-chain  │
│    (Spinning up 10,000 fake  │ to be indexed in the official DHT bootstrap registry.     │
│    nodes to disrupt routing) │ XOR distance routing prevents clustering around targets.   │
├──────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 2. Dishonest Data Drop       │ Proof-of-Storage (PoS) challenges: Clients challenge      │
│    (Nodes claiming to store  │ operators with random nonces. Failing nodes lose lease    │
│    chunks but deleting them) │ rewards and have their on-chain collateral slashed.       │
├──────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 3. Eavesdropping / Sniffing  │ Pointless for attackers: all chunks are encrypted with    │
│    (Rogue community nodes    │ client-side XChaCha20-Poly1305 before leaving the laptop. │
│    inspecting stored chunks) │ Operators only see opaque SHA-256 content hashes (CIDs).         │
├──────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 4. Network Eclipse Attacks   │ Nodes maintain diverse routing tables with buckets        │
│    (Surrounding a victim's   │ populated across distinct autonomous systems (ASNs) and   │
│    routing table)            │ geographic IP prefixes.                                   │
└──────────────────────────────┴───────────────────────────────────────────────────────────┘
```

---

## 8. Architectural Review & Questioning Guide

To ensure complete alignment before writing any code, here are the key architectural decisions and open questions for review:

### Question 1: Transport Engine Selection
* **Option A (Recommended)**: `libp2p-rs` (Standard battle-tested P2P stack used by Ethereum, Filecoin, and IPFS; includes NAT traversal, Noise security, and Kademlia DHT).
* **Option B**: Custom lightweight UDP/QUIC protocol built directly in Tokio (smaller binary footprint, but requires writing custom NAT traversal and DHT logic).

### Question 2: Economic Model Strategy
* **Option A: Pure Altruistic / Barter Swarm ("Seed to Store")**:
  * Developers who run an operator node get free distributed storage across the network. Zero tokens, zero crypto payments required.
* **Option B: Hybrid Micro-Lease Model**:
  * Free for open-source/personal use (mutual barter); optional Arbitrum L2 micro-lease contracts for high-availability enterprise guarantees.

### Question 3: Replication Factor ($k$)
* **Default**: $k=3$ (Provides Byzantine fault tolerance against 1 node failure with minimal bandwidth).
* **High-Security Profile**: $k=5$ (Tolerates up to 2 concurrent node failures, ideal for critical enterprise production environments).

---

### Review Sign-Off
* **Architecture Status**: Fully Specified & Backward-Compatible.
* **Code Modification Risk**: **Low** (Decoupled via `StoragePool` traits; zero breaking changes to existing CLI commands or local databases).
* **Next Action**: Review and resolve open questions above before proceeding to Phase 1 implementation.
