# CipherVault High-Availability Database Clustering Architecture

This document defines the high-availability (HA), multi-region clustering, and database migration architecture for the CipherVault control-plane account service (`services/account`).

---

## 1. Problem Statement & Motivation

In single-node deployments, `services/account` utilizes embedded SQLite via `rusqlite`. While SQLite provides zero-configuration simplicity and ACID transactions for single-host topologies, enterprise requirements necessitate:

1. **High Concurrency & Multi-Reader Throughput:** Horizontally scaling scoped secret retrieval across distributed application clusters.
2. **Zero-Downtime High Availability (HA):** Sub-second failover in the event of node, zone, or cloud provider failure.
3. **Audit Chain Linearizability:** Strict ordering of tamper-evident SHA-256 audit log events (`prev_hash` chaining) across distributed replicas.
4. **Disaster Recovery Isolation:** Continuous asynchronous or synchronous replication without exposing plaintext secrets to database replicas.

---

## 2. Evaluated Topologies

```mermaid
flowchart TD
    subgraph ClientLayer["Edge / API Gateway"]
        GW["API Gateway / Envoy\n(Header: X-Write-Intent)"]
    end

    subgraph LiteFSArch["Option A: LiteFS Distributed Raft"]
        LF_Primary["Primary Node (Write Leader)\nLiteFS FUSE + SQLite\nLocal NVMe"]
        LF_Replica1["Read Replica 1\nLiteFS FUSE + SQLite"]
        LF_Replica2["Read Replica 2\nLiteFS FUSE + SQLite"]
        Consensus["LiteFS Cloud / Consul Raft\nLease Coordinator"]
    end

    subgraph PostgresArch["Option B: Enterprise Clustered PostgreSQL"]
        PG_Pool["PgBouncer Connection Pooler"]
        PG_Primary["PostgreSQL Primary (Leader)\nSynchronous Replication"]
        PG_Standby["PostgreSQL Standby (Hot Standby)\nStreaming Replication"]
        Patroni["Patroni / Raft DCS\nAutomated Failover"]
    end

    GW -->|Writes| LF_Primary
    GW -->|Reads| LF_Replica1
    GW -->|Reads| LF_Replica2
    LF_Primary -->|Replication Stream| LF_Replica1
    LF_Primary -->|Replication Stream| LF_Replica2
    LF_Primary -.->|Heartbeat| Consensus

    GW -->|Enterprise Mode| PG_Pool
    PG_Pool -->|Writes| PG_Primary
    PG_Pool -->|Reads| PG_Standby
    PG_Primary -->|WAL Stream| PG_Standby
    PG_Primary -.->|Lease| Patroni
```

### Option A: LiteFS (Distributed Raft-Replicated SQLite)
- **Mechanism:** FUSE filesystem that intercepts SQLite transactions and replicates transactional LTX files via Raft consensus.
- **Pros:**
  - Zero code rewrite: applications continue to speak SQLite dialect via `rusqlite`.
  - Microsecond read latencies (reads served directly from node RAM / NVMe).
  - Built-in transaction forwarding (replicas automatically proxy write transactions to the elected leader).
- **Cons:**
  - Requires Linux FUSE kernel support in container environments.
  - Write throughput capped at ~1,000 tx/sec (bound to single leader).

### Option B: Clustered PostgreSQL (Patroni + PgBouncer)
- **Mechanism:** Dedicated multi-node PostgreSQL cluster with Patroni DCS, streaming WAL replication, and PgBouncer connection pooling.
- **Pros:**
  - Arbitrary write throughput and table partitioning.
  - Native enterprise backup ecosystem (pgBackRest, WAL-G, AWS RDS Multi-AZ, GCP Cloud SQL).
  - Mature connection multiplexing.
- **Cons:**
  - Network hop required for read queries.
  - Requires database dialect abstraction layer.

---

## 3. Abstract Database Interface Specification

To support both single-node local development, LiteFS edge clusters, and enterprise PostgreSQL without code duplication, `services/account` implements the `HaDatabaseStore` abstraction:

```rust
#[async_trait]
pub trait HaDatabaseBackend: Send + Sync {
    /// Return the active backend topology descriptor
    fn topology(&self) -> ClusterTopology;

    /// Return whether this node is currently the elected write leader
    fn is_leader(&self) -> bool;

    /// Health check and replication lag inspection
    async fn check_health(&self) -> Result<ClusterHealth, HaDatabaseError>;

    /// Execute a read-only query (routed to local replica or standby)
    async fn execute_read<F, R>(&self, f: F) -> Result<R, HaDatabaseError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<R, rusqlite::Error> + Send + 'static,
        R: Send + 'static;

    /// Execute a write transaction (strictly routed to leader)
    async fn execute_write<F, R>(&self, f: F) -> Result<R, HaDatabaseError>
    where
        F: FnOnce(&mut rusqlite::Connection) -> Result<R, rusqlite::Error> + Send + 'static,
        R: Send + 'static;
}
```

---

## 4. Audit Sequence Linearizability Invariant

Audit rows form an append-only hash chain where `row[n].prev_hash == SHA256(row[n-1])`.

In clustered read-replica configurations:
1. **Write Consensus:** Every audit insertion must acquire an `IMMEDIATE` transaction on the cluster write leader.
2. **Replication Guard:** Read replicas maintain an in-memory high-water mark of the latest replicated `audit_event_id`.
3. **Linearizability Verification:** If a client requests audit verification immediately following a write, the API gateway verifies that `replica.last_tx_id >= client.tx_id`; otherwise, the query is forwarded to the leader.

---

## 5. Decision record (2026-11-07): single-writer SQLite stays, LiteFS is the scale path

**Decision:** the account service keeps exactly one writer (embedded SQLite +
WAL, `AccountState`). LiteFS is the approved scale-out: it preserves the
single-writer invariant, so the audit-chain linearizability rule in §4 holds
unchanged (every `prev_hash` links on the leader; replicas never take writes —
`HaDatabaseStore::execute_write` fails closed with `NotLeader`, and a LiteFS
node that forgot its role defaults to read-only via `CIPHERVAULT_DB_LEADER`).
PostgreSQL stays rejected until a sequencer design lands: multi-writer PG
breaks the hash-chain append invariant and needs an advisory lock or a single
sequencer, which is a new distributed component, not a migration.

**Measured evidence (this repo, debug build, 8 workers):**
- Write gate `scoped_write_gate` (new, `#[ignore]` soak lane): 64 secret
  creates, 281 writes/s, p50 24 ms / p99 78 ms, 0 failures,
  0 SQLite busy retries. Budget: p99 ≤ 250 ms.
- Read gate `scoped_load_gate`: 0 failures, 0 busy retries under paced load.
- Both gates assert `sqlite_busy_retries() == 0`: contention surfaces as
  global-mutex wait (logged past 10 ms for canary visibility), never as
  `SQLITE_BUSY`. If either gate ever reports busy retries, the single-writer
  assumption is violated — treat as P0, not a tuning knob.

**Deployment knobs** (`HaDatabaseStore::open_selected`, unit-tested):
- `CIPHERVAULT_DB_TOPOLOGY=sqlite` (default) — standalone, always leader.
- `CIPHERVAULT_DB_TOPOLOGY=litefs` + `CIPHERVAULT_DB_LEADER=1|true|yes|on` —
  LiteFS node; unset/anything else forces read-only replica behavior.
- `CIPHERVAULT_DB_TOPOLOGY=postgres` — hard `Config` error naming this doc.
  Unknown values are rejected the same way.

**Benchmarks not yet run (require fleet hardware):** LiteFS primary + 2
replicas and PG + PgBouncer under `tests/capacity_harness.cjs` (240 requests,
concurrency 1/8/32/64, p99 2 s). The decision above holds for current scale;
re-open it with measured fleet numbers, not before.
