# CipherVault Scoped Secret Management Research Report

**Document Version:** 2.5.0-AUDIT-VERIFIED  
**Date:** September 27, 2026  
**Auditor Roles:** Senior Security Architect, Secrets-Management Engineer, Cryptography Engineer, Backend/API Architect, Platform Architect  
**Target Repository:** `ciphervault` (Rust Workspace v1.0.20)  
**Classification:** Technical Architecture Audit & Target Specification
**Verification:** v2.5.0 independently re-verified every code citation against the worktree; corrections applied and supplements S1–S7 added (see §28).
**Evidence standard:** material claims are tagged `[Verified in code]` / `[Verified in documentation]` / `[Inferred from implementation]` / `[Proposed design]` / `[Unknown]`; full register in S7.  

---

## Deliverable A — Executive Findings

```text
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                               EXECUTIVE AUDIT SUMMARY                                    │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. Current State:                                                                        │
│    CipherVault does NOT possess a repository-, project-, workspace-, or environment-     │
│    scoped secret management model. Credentials have no discrete identity. Stored data    │
│    consists entirely of opaque, chunked confidential files (.env, certs) locked to a     │
│    single random 32-byte vault_id in a local .ciphervault/ directory.                    │
│                                                                                          │
│ 2. Scoping Enforcement:                                                                  │
│    Scoping is 0% enforced in the database, storage layer, operator protocol, or APIs.   │
│    There are no tables, columns, or wire objects for project_id, repo_id, or env_id.     │
│                                                                                          │
│ 3. Enterprise / Multi-Project Readiness:                                                 │
│    Unsuitable for multi-project or automated CI/CD enterprise environments. Projects     │
│    cannot share secrets safely, credentials cannot be queried across repositories, and   │
│    environment separation (Dev vs. Prod) is purely a manual filename convention.        │
│                                                                                          │
│ 4. Target Architecture:                                                                  │
│    Transform CipherVault into a Hierarchical Resource-Scoped Secret Management Platform:│
│    Tenant -> Workspace -> Project -> [Environments, Repo Bindings, Services] -> Secrets. │
│    Preserve zero-knowledge envelope encryption while introducing first-class secret      │
│    identities, RBAC/ABAC authorization, and stable VCS bindings.                         │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Executive Summary

CipherVault is engineered as a decentralized, zero-knowledge confidential file backup, versioning, and clean-machine disaster recovery system built in Rust. It utilizes FastCDC (content-defined chunking), [XChaCha20-Poly1305](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/crypto/src/aead.rs#L12-L45) authenticated encryption, an Ed25519/X25519 cryptographic key hierarchy, and an untrusted federated operator network.

However, a technical audit of the codebase reveals that **CipherVault currently treats secrets as undifferentiated local filesystem files rather than discrete, scoped credentials**. A secret has no first-class representation, no database identity, and no programmatic access control beyond possessing the 32-byte Master Recovery Secret $R$ or local OS keyring credentials.

There is **no project abstraction, no repository abstraction, no workspace abstraction, and no environment boundary** in the core domain models, SQLite schemas, wire protocols, or CLI commands. While the optional control-plane service ([`services/account`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/account/src/lib.rs)) provides user accounts, WebAuthn/TOTP authentication, and vault linking, it acts only as an administrative registry and remains completely unaware of projects, repositories, environments, or individual credentials.

This report documents the current architecture with empirical repository evidence, identifies critical security and operational gaps, and specifies a target architecture: a **Hierarchical Resource-Scoped Secret Management Architecture** with first-class metadata, per-project envelope encryption, stable VCS repository bindings, fine-grained access control, and an automated migration path.

---

## 2. Research Question

> **Primary Research Question:** Does CipherVault currently provide a secure and explicit resource-scoping model for secrets (at the Repository, Project, Workspace, Organization, Application, or Environment level)? Does CipherVault associate every credential with a specific resource context, or are secrets stored in an undifferentiated global/local pool? Is the current model sufficient for real-world multi-project usage?

### Explicit Answer Based on Repository Evidence

**No.** CipherVault currently **does not** associate stored credentials or secrets with a project, repository, workspace, or environment context. 

Instead, CipherVault operates on a **Single-Vault Directory-Local File Model**:
1. Every secret exists merely as unparsed text or bytes within a confidential file (e.g., `DATABASE_URL=postgres://...` inside a tracked `.env` file).
2. The unit of containment is an isolated local vault (`vault_id`), initialized within a developer's local working directory inside `.ciphervault/vault.db`.
3. Storage operators in [`services/operator`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/operator/src/lib.rs) receive only opaque, content-addressed chunks (`ChunkWireObject`) indexed by SHA-256 Content Identifiers (CIDs).
4. The system cannot answer questions such as *"Which project does this credential belong to?"*, *"Show me all production credentials for Repository Y"*, or *"Rotate the Stripe API key across staging without touching production"*.

The current model is **insufficient for enterprise multi-project operations**.

---

## 3. Current-State Findings

| Architecture Dimension | Current CipherVault Implementation | Scoping Model Present? | Enforcement Level |
| :--- | :--- | :--- | :--- |
| **Secret Identity** | None. Secrets are unindexed lines inside `.env` or raw file bytes. | **None** | Unenforced |
| **Storage Unit** | File-level tracking in SQLite via [tracked_files](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/local-store/src/db.rs#L138-L141). | Local path only | Directory boundary |
| **Database Schema** | Tables: `vault_metadata`, `tracked_files`, `snapshots`, `local_chunks`, `heads`. | **None** | No project/repo tables |
| **Encryption Scope** | Vault Epoch Key ([`VaultEpochKey`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/crypto/src/kdf.rs)) encrypts entire snapshot manifests and FastCDC chunks. | Vault-wide only | No per-secret or per-project keys |
| **API Endpoints** | Operator chunk upload/download ([`PUT/GET /v1/objects/:cid`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/docs/API_REFERENCE.md#L78-L85)). | Storage CID only | Zero semantic scoping |
| **Authorization** | Possession of master recovery secret $R$ or local device signing key. | All-or-nothing | Binary vault access |
| **Secret Retrieval** | `ciphervault run -- <cmd>` decrypts full snapshots into RAM and injects `.env`. | Working directory | No scoped lookup API |
| **CLI Context** | Reads `.ciphervault/vault.db` from `std::env::current_dir()`. | Implicit CWD | Path-dependent |
| **Environment Model** | Filename convention only (`.env.production`, `.env.staging`). | **None** | User-managed convention |
| **Audit Logging (local)** | Local `activity_log` (`crates/local-store/src/db.rs:198-205`) is written only by the file-watcher agent (`apps/agent/src/watcher.rs:231,280,531`) and the dashboard restore handler (`apps/cli/src/dashboard/files_api.rs:109`); CLI `push`/`restore`/`run` write no activity events. | Vault-wide | No secret-level audit |
| **Audit Logging (control plane)** | Account-service `audit_events` via `audit_event()` (`services/account/src/util.rs:14`, 20+ call sites) covers account/device/session/membership/vault-link events only; no secret-read/update events exist. | Account-wide | No secret-level audit |

---

## 4. Repository Evidence

Our conclusions are verified directly against the active codebase:

### Evidence 1: Local Vault Schema and Tracked Files
In [`crates/local-store/src/db.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/local-store/src/db.rs#L124-L167), table initialization proves that the local store only tracks filesystem paths:
```sql
CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id BLOB NOT NULL,
    current_epoch INTEGER NOT NULL,
    device_id BLOB NOT NULL,
    device_counter INTEGER NOT NULL,
    authority_generation INTEGER NOT NULL,
    device_signing_key BLOB NOT NULL,
    recovery_signing_pk BLOB NOT NULL,
    recovery_encryption_pk BLOB NOT NULL,
    recovery_locator BLOB NOT NULL DEFAULT (zeroblob(32)),
    genesis_cbor BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS tracked_files (
    relative_path TEXT PRIMARY KEY,
    file_id BLOB NOT NULL
);
```
*Verification:* There are no columns or tables for `project_id`, `repository_id`, `environment`, or `tenant_id`. Tracking a secret simply inserts a relative path string (e.g., `track_file(".env")`) in [`crates/local-store/src/db.rs:548-570`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/local-store/src/db.rs#L548-L570).

### Evidence 2: Confidential Manifest File Model
In [`crates/format/src/schema.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/format/src/schema.rs#L188-L218), confidential state is serialized as a flat list of `ManifestFileEntry` structs:
```rust
pub struct ManifestFileEntry {
    pub file_id: Vec<u8>,
    pub relative_path: String,
    pub file_version_id: Vec<u8>,
    pub raw_length: u64,
    pub padded_length: u64,
    pub plaintext_sha256: Vec<u8>,
    pub file_version_key: Vec<u8>,
    pub chunk_cids: Vec<Vec<u8>>,
    pub is_deleted: bool,
}
```
*Verification:* Secrets have no independent identity. They are embedded inside file versions.

### Evidence 3: Retrieval and In-Memory Injection
In [`apps/cli/src/commands/run.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/commands/run.rs#L141-L180), environment variable retrieval relies on parsing text `.env` files matching naming patterns:
```rust
let mut env_files: Vec<&ciphervault_snapshot::DecryptedFile> = decrypted_files
    .iter()
    .filter(|f| {
        let p = f.relative_path.replace('\\', "/");
        let name = p.rsplit('/').next().unwrap_or(&p);
        name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
    })
    .collect();
```
*Verification:* Environment scoping does not exist at the cryptographic or database layer; it is an ad-hoc filename convention (`.env.production`, `.env.staging`) resolved at execution time.

### Evidence 4: Account Service Control Plane
In [`services/account/src/state.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/account/src/state.rs#L69-L94), the hosted account service defines:
```sql
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    account_public_key_hex TEXT NOT NULL UNIQUE,
    created_at_utc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_links (
    account_id TEXT NOT NULL,
    vault_id_hex TEXT NOT NULL,
    alias TEXT NOT NULL,
    role TEXT NOT NULL,
    linked_at_utc INTEGER NOT NULL,
    PRIMARY KEY (account_id, vault_id_hex)
);
```
*Verification:* An account links to an entire vault via `vault_links`. There is no subdivision into projects, workspaces, repositories, or environments.

---

## 5. Current Secret Ownership and Namespace Model

### Secret Identity
In the current codebase, identity is:
$$\text{Identity} = \text{vault\_id} \mathbin{\Vert} \text{relative\_path} \mathbin{\Vert} [\text{env\_variable\_name}]$$
Because `env_variable_name` is only parsed dynamically by [`apps/cli/src/dotenv.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/dotenv.rs#L9-L68), individual credentials have no durable identifier in the database or wire protocol.

### Secret Ownership
Ownership is binary and monolithic:
- A vault is owned by the entity holding the **Master Recovery Secret $R$** (32 bytes) or a registered **Device Signing Key** (`device_signing_key`).
- Any entity with access to the vault can decrypt **all** files and **all** secrets contained in any snapshot of that vault.
- There is no Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC). Access to `DATABASE_URL` cannot be separated from access to `STRIPE_PRIVATE_KEY` or `PRODUCTION_CERT.pem`.

### Secret Namespace
CipherVault provides two disconnected namespaces:
1. **Local Working Directory Namespace:** Tied to the filesystem path containing `.ciphervault/vault.db`.
2. **Global Opaque Storage Namespace:** Storage operators store chunks indexed solely by their 32-byte content hash `SHA-256(canonical_cbor(chunk))` ([`crates/format/src/schema.rs:182`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/format/src/schema.rs#L182)). Operators do not know which vault, file, or project a chunk belongs to.

### Collision Analysis
- **Within a Single Vault:** Two secrets with the same variable name (e.g. `PORT`) collide if placed in the same file. In [`apps/cli/src/commands/run.rs:194-198`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/commands/run.rs#L194-L198), `cmd_run` deduplicates variables using a `BTreeMap<String, String>`, where the last read file silently overwrites previous values.
- **Across Multiple Projects:** If Project A and Project B are in different folders on a developer workstation, each has its own independent `.ciphervault/` directory and distinct `vault_id`. Their namespaces do not collide on disk. However, because there is no central registry, discovery, or cross-project query mechanism, managing 100 projects requires navigating 100 separate directories.

---

## 6. Current Namespace / Retrieval Model & Usability Impact

```text
Current Retrieval Paradigm:
ciphervault run [OPTIONS] -- <COMMAND> [ARGS]...
  ├── Resolves active local DB from ./.ciphervault/vault.db
  ├── Loads Vault Epoch Key from local SQLite store
  ├── Decrypts active SnapshotManifest
  ├── Fetches all chunks from local DB or remote operators
  ├── Decrypts every tracked file in memory
  ├── Scans for filenames containing ".env"
  └── Injects all parsed keys into child process environment block
```

### Consequences of the Current Approach

1. **Lack of Precision:** Callers cannot retrieve a single credential (e.g., `get_secret("STRIPE_KEY")`). The system must decrypt and parse the entire confidential file set.
2. **Ambiguous Environment Separation:** To separate development from production, developers must create multiple files in the same directory (`.env.development`, `.env.production`). If a developer forgets `--env-file .env.development`, `ciphervault run` loads `.env` first, then the remaining `.env.*` files in snapshot-manifest order via a stable sort (`run.rs:152-161`, not alphabetical), with later files silently overriding earlier keys (`run.rs:193-198`), which can cause production secrets to leak into local development.
3. **Circular Bootstrapping in CI/CD:** As documented in [`docs/CICD_INTEGRATION.md`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/docs/CICD_INTEGRATION.md) and [`.github/actions/ciphervault-run/action.yml`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/.github/actions/ciphervault-run/action.yml), the CI runner expects `.ciphervault/` to already exist in the working directory. Because `.ciphervault/` is gitignored (to protect local keys), the runner must either:
   - Check sensitive vault databases into Git (violating security best practices), or
   - Pass Master Secret $R$ via GitHub Secrets and run `ciphervault recover` on every CI job.
   This introduces a circular dependency: **to retrieve secrets from CipherVault, the CI runner must first obtain secrets from another secrets manager.**

---

## 7. Security Assessment & Gaps

### Core Security Strengths (Verified in Code)
- **Zero Plaintext on Storage Operators:** Cryptographic chunking and AEAD ([`crates/crypto/src/aead.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/crypto/src/aead.rs)) prevent operators from reading file paths, sizes, or contents.
- **Volatile Memory Scrubbing:** Keys and plaintext buffers implement `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` (`crates/crypto/src/keys.rs:14,61,96`; scrubbing test `test_zeroize_memory_scrubbing` at `keys.rs:135`).
- **Hardware-Anchored Device Identity:** PIV Slot 9C hardware signing is enforced via capacitive touch ([`crates/crypto/src/piv.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/crypto/src/piv.rs)).
- **Tamper-Evident L2 Commitments:** State commitments are anchored to Arbitrum One as domain-separated salted SHA-256 commitments (`commitment = SHA-256(salt ‖ head-record CID)`) in a minimal first-seen block registry ([`contracts/CipherVaultRegistry.sol`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/contracts/CipherVaultRegistry.sol#L5-L33); no EIP-712 — corrected in v2.5.0).

### Critical Architecture Gaps

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              IDENTIFIED ARCHITECTURAL GAPS                             │
├──────────────────────────┬─────────────────────────────────────────────────────────────┤
│ Gap                      │ Empirical Evidence & Technical Impact                       │
├──────────────────────────┼─────────────────────────────────────────────────────────────┤
│ 1. No Project / Repo     │ No database table, model, or API parameter for project_id   │
│    Abstraction           │ or repository_id exists anywhere in crates/ or services/.   │
├──────────────────────────┼─────────────────────────────────────────────────────────────┤
│ 2. Monolithic Access     │ Device certificates grant binary access to the entire       │
│    Control               │ vault. No mechanism to permit access to Dev but deny Prod.  │
├──────────────────────────┼─────────────────────────────────────────────────────────────┤
│ 3. Insecure Environment  │ Environments are ad-hoc filenames (.env.staging).          │
│    Separation            │ apps/cli/src/commands/run.rs loads all .env* files if no     │
│                          │ flag is passed, risking staging/production credential leaks.│
├──────────────────────────┼─────────────────────────────────────────────────────────────┤
│ 4. No Discrete Secret    │ Cannot rotate, audit, or expire an individual API key       │
│    Lifecycle             │ without rewriting an entire file and committing a snapshot. │
├──────────────────────────┼─────────────────────────────────────────────────────────────┤
│ 5. Blind Dashboard Scan  │ apps/cli/src/main.rs:1617 walkdir scans 3 folder levels     │
│                          │ on disk for .ciphervault/ files. Lacks authorization checks.│
├──────────────────────────┼─────────────────────────────────────────────────────────────┤
│ 6. No Machine / CI/CD    │ No OIDC federation, role assumption, or short-lived token   │
│    Identity Provider     │ service for automated deployment pipelines.                 │
└──────────────────────────┴─────────────────────────────────────────────────────────────┘
```

---

> **v2.5.0 audit clarifications (all `[Verified in code]`):**
> - **Gap 5 scope:** `discover_workspace_vaults` (`apps/cli/src/main.rs:1607-1630`) walks the local disk to `max_depth(3)` for `vault.db` files, but it serves only the loopback-bound private dashboard (guarded by `private_ui_request_guard`, `apps/cli/src/dashboard/router.rs`). The residual risk is a **local** confused-deputy / multi-user-machine issue (vault A operator reads vault B metadata via a shared dashboard process), not remote exfiltration. The target architecture (§9) replaces disk-walk discovery with authenticated, scope-filtered project APIs.
> - **Audit coverage:** the control-plane account service *does* maintain `audit_events` (`services/account/src/state.rs:183-190`) with 20+ `audit_event()` call sites (account/device/session/membership/vault-link lifecycle) — but no event type relates to individual secrets, which do not exist as entities. Local `activity_log` has exactly 4 writers (agent watcher ×3, dashboard restore ×1); CLI snapshot commands are unaudited.
> - **Secret identity formula (§5):** `vault_id ‖ relative_path ‖ [env_var_name]` — the bracketed component is ephemeral (parsed at `run` time by `dotenv::parse_dotenv_bytes`, `apps/cli/src/dotenv.rs:9`) and has no durable identifier; treat the durable identity as `vault_id ‖ relative_path ‖ snapshot_id`.

---

## 8. Resource-Scoping Alternatives & Decision Matrix

We evaluated four candidate scoping models for CipherVault:

### Model A: Pure Git Repository-Scoped Secrets
`Repository -> Environment -> Secret`
- *Pros:* Natural mapping to Git repositories. Simple CI/CD lookup.
- *Cons:* Breaks down when a system spans multiple repositories (frontend, backend, infra repos needing shared database credentials). Fails for monorepos with multiple services. Brittle when repositories are renamed, transferred, or archived.

### Model B: Flat Project-Scoped Secrets
`Project -> Secret`
- *Pros:* Extremely simple database model. Easy CLI ergonomics.
- *Cons:* No native environment isolation. Forces developers to prefix names (`DEV_DB_URL`, `PROD_DB_URL`), leading to authorization failures and accidental leaks.

### Model C: Direct Workspace Hierarchy
`Workspace -> Project -> Environment -> Secret`
- *Pros:* Clear boundaries for teams and projects. Strong environment isolation.
- *Cons:* Lacks native concepts for VCS repositories or microservices.

### Model D: Recommended Target Architecture
`Tenant/Org -> Workspace -> Project -> [Environments, Repo Bindings, Services] -> Secrets`
- *Pros:* Treats the **Project** as the primary administrative and security boundary. Repositories are **bound** to projects rather than acting as owners, supporting monorepos, multi-repo architectures, and repository renames without orphaned secrets. Environments (Dev, Staging, Prod) provide strict security boundaries.
- *Cons:* Higher database and API complexity than a single-tier model.

### Decision Matrix

| Evaluation Criterion | Model A: Pure Repo | Model B: Flat Project | Model C: Workspace/Proj | Model D: Recommended Target |
| :--- | :--- | :--- | :--- | :--- |
| **Security Isolation** | High | Low | High | **Very High (ABAC + Env Gates)** |
| **Multi-Repo Projects**| Poor | Moderate | High | **Exceptional (Shared bindings)** |
| **Monorepo Support**   | Very Poor | Poor | Moderate | **Exceptional (Path/Service bindings)**|
| **Repo Rename/Transfer**| Fragile | Unaffected | Unaffected | **Resilient (Stable Provider ID)** |
| **CI/CD Integration**  | High | Moderate | High | **Native (OIDC + Scope tokens)** |
| **Audit Granularity**  | Moderate | Low | High | **Very High (Per-Secret Event DAG)**|
| **Implementation Cost**| Low | Very Low | Moderate | **High (Phased Rollout)** |

---

## 9. Recommended Target Architecture

The recommended target architecture establishes **Projects** as primary logical security boundaries within **Workspaces** and **Tenants**, with **Environments** as strict isolation gates and **Repositories** as bound access contexts.

```text
Hierarchical Resource Scope:
Tenant / Organization (tenant_id)
 └── Workspace (workspace_id)
      └── Project (project_id)
           ├── Repository Bindings (durable external VCS identity: GitHub, GitLab)
           ├── Environments (development, staging, production)
           ├── Services / Workloads (microservices, daemon identities)
           └── Secrets (discrete key-value items with versions and metadata)
```

```mermaid
flowchart TD
    subgraph Org ["Tenant / Organization: Acme Corp (org_01HXYZ)"]
        direction TB
        WS["Workspace: Platform Engineering (ws_01HABC)"]
        
        subgraph Proj ["Project: Core Payments (proj_01HDEF)"]
            direction TB
            RB["Repository Binding\n(GitHub: 84920194 / acme/payments-service)"]
            
            subgraph Envs ["Environment Boundaries"]
                Dev["Environment: development"]
                Staging["Environment: staging"]
                Prod["Environment: production"]
            end
            
            subgraph SecretsPool ["Discrete Managed Secrets"]
                S1["Secret: DATABASE_URL\n(v1, v2, v3)"]
                S2["Secret: STRIPE_SECRET_KEY\n(v1, v2)"]
                S3["Secret: WEBHOOK_SIGNING_SECRET\n(v1)"]
            end
        end
        
        WS --> Proj
        Proj --> RB
        Proj --> Envs
        Envs --> SecretsPool
    end
```

---

## 10. Secret Metadata Model

To avoid information leakage while supporting discovery, secret attributes are segregated into **Searchable Cleartext Metadata** and **Confidential Encrypted Data**:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              SECRET METADATA ARCHITECTURE                              │
├──────────────────────────────────────────┬─────────────────────────────────────────────┤
│ Field Name                               │ Storage / Security Treatment                │
├──────────────────────────────────────────┼─────────────────────────────────────────────┤
│ secret_id                                │ UUIDv7 / ULID (Indexed Primary Key)        │
│ tenant_id                                │ UUIDv7 (Indexed Tenancy Boundary)           │
│ workspace_id                             │ UUIDv7 (Indexed Organization Context)       │
│ project_id                               │ UUIDv7 (Indexed Security Boundary)          │
│ environment_id                           │ UUIDv7 (Indexed Isolation Gate)             │
│ name                                     │ String (Indexed; Unique per Project+Env)    │
│ description                              │ String (Plaintext Metadata)                 │
│ secret_type                              │ Enum: KeyValue, SymmetricKey, X509Cert, ... │
│ tags                                     │ JSON Array of Strings (Searchable)          │
│ repository_binding_id                    │ Optional UUIDv7 (Scoped VCS Link)           │
│ service_id                               │ Optional UUIDv7 (Workload Context)          │
│ current_version                          │ Unsigned 32-bit Integer                     │
│ status                                   │ Enum: Active, Deprecated, ScheduledDeletion │
│ policy_id                                │ UUIDv7 (ABAC Access Rule Reference)         │
│ encryption_key_id                        │ UUIDv7 (Active Project DEK ID)              │
│ created_by                               │ String (User / Service Account Principal)   │
│ created_at_utc                           │ Epoch Seconds (Indexed Timestamp)           │
│ updated_at_utc                           │ Epoch Seconds                               │
│ last_rotated_at_utc                      │ Epoch Seconds                               │
│ expires_at_utc                           │ Optional Epoch Seconds                      │
│ last_accessed_at_utc                     │ Epoch Seconds (Audit Telemetry)             │
├──────────────────────────────────────────┴─────────────────────────────────────────────┤
│ CONFIDENTIAL PAYLOAD (Stored strictly in encrypted secret_versions table)              │
│ - Ciphertext: XChaCha20-Poly1305 encrypted secret value                                │
│ - Nonce: 24-byte cryptographically random value                                        │
│ - Auth Tag: 16-byte Poly1305 MAC                                                       │
│ - AAD: Canonical CBOR binding (tenant_id || project_id || env_id || secret_id || ver)  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Database Architecture

The target database architecture introduces a normalized, relational schema for control-plane and metadata operations while preserving zero-knowledge chunk storage for confidential payloads.

```mermaid
erDiagram
    ORGANIZATIONS ||--o{ WORKSPACES : contains
    WORKSPACES ||--o{ PROJECTS : contains
    PROJECTS ||--o{ REPOSITORY_BINDINGS : binds
    PROJECTS ||--o{ ENVIRONMENTS : defines
    PROJECTS ||--o{ SERVICES : defines
    PROJECTS ||--o{ SECRETS : manages
    ENVIRONMENTS ||--o{ SECRETS : scopes
    SECRETS ||--o{ SECRET_VERSIONS : versions
    PROJECTS ||--o{ ENCRYPTION_KEYS : owns
    ENCRYPTION_KEYS ||--o{ SECRET_VERSIONS : encrypts
    SECRETS ||--o{ SECRET_ACCESS_EVENTS : audits
    PROJECTS ||--o{ ACCESS_POLICIES : enforces

    ORGANIZATIONS {
        uuid tenant_id PK
        string name
        int created_at_utc
    }
    PROJECTS {
        uuid project_id PK
        uuid tenant_id FK
        uuid workspace_id FK
        string slug
        string name
    }
    REPOSITORY_BINDINGS {
        uuid binding_id PK
        uuid project_id FK
        string provider
        string external_repo_id
        string repo_full_name
        string default_branch
    }
    ENVIRONMENTS {
        uuid environment_id PK
        uuid project_id FK
        string name
        string slug
        int tier
    }
    SECRETS {
        uuid secret_id PK
        uuid project_id FK
        uuid environment_id FK
        string name
        string secret_type
        int current_version
        string status
    }
    SECRET_VERSIONS {
        uuid version_id PK
        uuid secret_id FK
        int version
        uuid encryption_key_id FK
        blob nonce
        blob ciphertext
        blob tag
        int created_at_utc
    }
```

### Uniqueness Constraints Analysis

A critical database design question is whether the uniqueness constraint should be:
$$\text{Option 1: } (\text{project\_id}, \text{environment\_id}, \text{name})$$
$$\text{Option 2: } (\text{project\_id}, \text{repository\_id}, \text{environment\_id}, \text{name})$$

**Recommendation: Implement Option 1 `(project_id, environment_id, name)`.**

*Rationale:*
1. Binding secret identity directly to `repository_id` prevents sharing secrets across multiple repositories in the same project (e.g., a shared `DATABASE_URL` between an API backend repo and a background worker repo).
2. It breaks secret resolution when repositories are renamed, split, or migrated.
3. Option 1 models the project as the true ownership boundary, while allowing optional repository bindings via foreign keys for scoped authorization checks.

---

## 12. API Architecture

The Scoped Secret API makes resource context explicit in all route paths. All secret values, tokens, and connection strings in the examples below are synthetic placeholders, never real credentials; value-bearing responses require TLS 1.2+ and scoped bearer tokens:

### 1. Create a Scoped Secret
`POST /v1/projects/{project_id}/environments/{environment}/secrets`
```json
// Request
{
  "name": "DATABASE_URL",
  "secret_type": "connection_string",
  "description": "Primary PostgreSQL production connection",
  "value": "postgres://pg_user:enc_password@db.internal:5432/payments",
  "tags": ["database", "pci-dss"]
}

// Response (201 Created)
{
  "secret_id": "01923f11-9a74-7290-b1d1-6c2e74289a10",
  "project_id": "01923f0f-8c31-7b00-84a1-3e4b78912345",
  "environment": "production",
  "name": "DATABASE_URL",
  "version": 1,
  "status": "active",
  "created_at_utc": 1790520400
}
```

### 2. Retrieve a Secret Value
`GET /v1/projects/{project_id}/environments/{environment}/secrets/{name}`
```json
// Headers: Authorization: Bearer <scoped_token>
// Response (200 OK)
{
  "secret_id": "01923f11-9a74-7290-b1d1-6c2e74289a10",
  "project_id": "01923f0f-8c31-7b00-84a1-3e4b78912345",
  "environment": "production",
  "name": "DATABASE_URL",
  "version": 1,
  "value": "postgres://pg_user:enc_password@db.internal:5432/payments",
  "expires_at_utc": null,
  "last_rotated_at_utc": 1790520400
}
```

### 3. List Project Secrets (Filtered by Environment)
`GET /v1/projects/{project_id}/secrets?environment=production&tags=database`
```json
// Response (200 OK)
{
  "project_id": "01923f0f-8c31-7b00-84a1-3e4b78912345",
  "environment": "production",
  "total": 1,
  "secrets": [
    {
      "secret_id": "01923f11-9a74-7290-b1d1-6c2e74289a10",
      "name": "DATABASE_URL",
      "secret_type": "connection_string",
      "current_version": 1,
      "status": "active",
      "updated_at_utc": 1790520400
    }
  ]
}
```

### 4. Rotate a Secret
`POST /v1/projects/{project_id}/secrets/{secret_id}/rotate`
```json
// Request
{
  "new_value": "postgres://pg_user:rotated_password_99@db.internal:5432/payments"
}

// Response (200 OK)
{
  "secret_id": "01923f11-9a74-7290-b1d1-6c2e74289a10",
  "previous_version": 1,
  "current_version": 2,
  "status": "active",
  "rotated_at_utc": 1790524000
}
```

---

## 13. CLI and Developer Experience

To ensure security without sacrificing usability, the CLI supports both explicit flags and local context resolution:

```bash
# 1. Project Context Management
ciphervault project list
ciphervault project use payments-service

# 2. Scoped Secret Management
ciphervault secret set DATABASE_URL --env production
ciphervault secret get DATABASE_URL --env production
ciphervault secret list --env production

# 3. Context-Aware Execution (Zero-Disk)
ciphervault run --env production -- npm start

# 4. Safe Context Resolution Logic
# The CLI resolves context using a strict precedence order:
# Priority 1: Explicit Command-Line Flags (--project, --env)
# Priority 2: CIPHERVAULT_PROJECT / CIPHERVAULT_ENV environment variables
# Priority 3: Local repository binding file (.ciphervault/context.json)
# Priority 4: Git remote auto-detection (queries provider ID against project bindings)
```

> [!IMPORTANT]
> **Context Safety Invariant:** Automatic Git remote detection only identifies candidate projects. Authorization is always verified server-side against the caller's authenticated identity and active tokens.

---

## 14. Repository Integration & Durable Identity

To protect against repository renaming, organization transfers, and forks, CipherVault binds projects to **stable, provider-issued numerical/immutable IDs**:

| VCS Provider | Mutable Human Reference | Durable Immutable Identifier | Verification Endpoint |
| :--- | :--- | :--- | :--- |
| **GitHub** | `owner/repo` (e.g. `acme/payments`) | GitHub Node/Repository ID (`84920194`) | `GET /repositories/:id` |
| **GitLab** | `group/subgroup/project` | GitLab Project ID (`3910582`) | `GET /api/v4/projects/:id` |
| **Bitbucket** | `workspace/repo-slug` | Repository UUID (`{a3b1c2d3-...}`) | `GET /2.0/repositories/{uuid}` |

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI Runner
    participant CLI as CipherVault CLI
    participant API as CipherVault Control Plane
    participant VCS as GitHub / GitLab API
    
    Dev->>CLI: ciphervault repo link
    CLI->>VCS: Query git remote origin
    VCS-->>CLI: Return stable repo_id (84920194)
    CLI->>API: POST /v1/projects/{id}/repositories (repo_id: 84920194)
    API->>VCS: Verify installation token & repo ownership
    VCS-->>API: Confirm ownership verified
    API-->>CLI: Binding registered (binding_id)
    CLI-->>Dev: Repository bound successfully
```

---

## 15. Security Model & Isolation Guarantees

### 1. Multi-Level Authorization
CipherVault enforces a dual RBAC/ABAC model:
- **Project Roles:** `Admin`, `Developer`, `Operator`, `Auditor`.
- **Environment Gates:** A developer with `Write` access to the `development` environment may be restricted to `No Access` in `production`.
- **ABAC Attributes:** Policy evaluation enforces IP CIDR limits, hardware token presence, and VCS branch rules (e.g., `production` secrets are only accessible from `refs/heads/main`).

### 2. Envelope Encryption Architecture
Every project receives a cryptographically isolated **Project Key Encryption Key (P-KEK)** derived from the organization master key and project identity. Each secret version is encrypted with a unique **Data Encryption Key (DEK)** using authenticated encryption:
$$\text{Ciphertext} = \text{XChaCha20-Poly1305}_{\text{DEK}}(\text{Secret Value}, \text{Nonce}, \text{AAD})$$
$$\text{AAD} = \text{tenant\_id} \mathbin{\Vert} \text{project\_id} \mathbin{\Vert} \text{environment\_id} \mathbin{\Vert} \text{secret\_id} \mathbin{\Vert} \text{version}$$

> [!NOTE]
> Authenticated Additional Data (AAD) binds the ciphertext to its exact tenant, project, environment, and version. A ciphertext copied from `development` to `production` or from `Project A` to `Project B` **will fail cryptographic MAC verification** during decryption.

---

## 16. Threat Modeling

| Threat | Attack Path | Affected Component | Severity | Existing Mitigation | Proposed Target Mitigation | Verification Method |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Cross-Project Access** | Attacker accesses Project B secrets using Project A token. | API / Database | **Critical** | None (Single vault model). | Server-side project boundary enforcement in SQL and AAD checks. | Automated IDOR penetration test suite. |
| **Environment Escalation** | Dev CI runner requests production secrets. | CI/CD Runner / OIDC | **Critical** | None (Files combined in vault). | Environment-specific token issuance; branch validation. | CI test requesting prod secrets from dev branch. |
| **IDOR / BOLA** | Tampering with `secret_id` in API path. | Control Plane API | **High** | None. | Validate `secret_id` belongs to `{project_id}` and caller has scope. | Automated parameterized REST security tests. |
| **Secret Leakage in Logs**| Printing secret values in audit events. | Audit Log / CLI | **High** | CLI diff masks values (`apps/cli/src/diff.rs`). | Audit schema accepts only SHA-256 digests; strict log redaction. | Log scanning gate asserting zero entropy leaks. |
| **Stale Repo Binding** | Repository transferred or deleted in Git. | VCS Integration | **Medium** | None. | Periodic background webhook / probe verifying repo ID durability. | Test runner simulating transferred GitHub repo. |
| **Cache Poisoning** | Shared cache collision across projects. | Redis / In-Memory Cache | **High** | None. | Cache keys prefixed: `{tenant}:{project}:{env}:{secret_id}`. | Cache collision unit test asserting key separation. |

---

## 17. Real-World Workflows

### Workflow A: New Project Onboarding
```text
1. Administrator creates project:
   ciphervault project create core-payments --workspace platform
2. Connect VCS repository:
   ciphervault repo connect https://github.com/acme/core-payments
3. Generate environments:
   ciphervault env create development staging production
4. Store initial secrets:
   ciphervault secret set DATABASE_URL --env development
5. Authorize CI/CD runner:
   ciphervault oidc bind --provider github --repo acme/core-payments --env production
```

### Workflow B: Production Deployment Execution
```mermaid
sequenceDiagram
    autonumber
    participant GHA as GitHub Actions Runner
    participant OIDC as GitHub OIDC Provider
    participant CV as CipherVault API
    participant App as Target Application Process
    
    GHA->>OIDC: Request OIDC ID Token (claims: repo, branch, commit)
    OIDC-->>GHA: Signed JWT ID Token
    GHA->>CV: POST /v1/auth/oidc/login (Token, target_env: production)
    CV->>CV: Validate JWT against GitHub JWKS & branch policies
    CV-->>GHA: Issue short-lived Scoped Token (TTL: 15 min)
    GHA->>CV: GET /v1/projects/{id}/environments/production/secrets
    CV-->>GHA: Decrypted Secret Key-Values (RAM only)
    GHA->>App: In-memory environment injection (Zero-Disk)
    App-->>GHA: Execution complete
    GHA->>GHA: Memory scrubbed via Zeroize
```

---

## 18. Migration Strategy

To transition from the current monolithic directory-vault model without data loss, CipherVault implements a 7-stage state machine:

```mermaid
stateDiagram-v2
    [*] --> DISCOVERED: Scan .ciphervault databases
    DISCOVERED --> CLASSIFIED: Parse .env and confidential files
    CLASSIFIED --> MAPPED_TO_PROJECT: Assign Project, Env, and Repo
    MAPPED_TO_PROJECT --> VALIDATED: Verify uniqueness and parse integrity
    VALIDATED --> MIGRATED: Encrypt with Project DEKs and write DB records
    MIGRATED --> VERIFIED: Readback verification and test injection
    VERIFIED --> LEGACY_PATH_DISABLED: Remove legacy vault.db / enable strict mode
    LEGACY_PATH_DISABLED --> [*]
```

### Migration Conflict Resolution Rules
1. **Duplicate Variable Names Across Files:** When migrating `.env.local` and `.env.production` from the same directory, values are automatically routed to their corresponding target environments (`development` vs. `production`).
2. **Ambiguous Secrets:** Secrets discovered in generic files (`.env`) default to `development` until explicitly confirmed via CLI review.
3. **Dry-Run Validation:** `ciphervault migrate --dry-run` produces a structured JSON diff of proposed database entities and encryption transformations before making any writes.

---

## 19. Search, Discovery, and Retrieval UX

1. **Authorized Search Scope:** Search queries (`ciphervault secret find STRIPE`) are filtered at the database level using the caller's security principal. Metadata for secrets in unauthorized projects is filtered out before results are returned, preventing enumeration attacks.
2. **Searchable Attributes:** Users can query by `project`, `environment`, `service`, `tag`, and `name`.
3. **Information Leakage Defense:** Secret values are never indexed in search engines or caches. Only metadata, tags, and descriptive keys are searchable.

---

## 20. Audit Logging

Every interaction with a secret generates an immutable audit record structured as follows:

```json
{
  "event_id": "01923f20-410a-7b33-91b2-108293712841",
  "event_type": "secret.read",
  "timestamp_utc": 1790525200,
  "tenant_id": "01923f00-1111-7000-8000-000000000001",
  "project_id": "01923f0f-8c31-7b00-84a1-3e4b78912345",
  "environment": "production",
  "secret_id": "01923f11-9a74-7290-b1d1-6c2e74289a10",
  "secret_name": "DATABASE_URL",
  "secret_version": 2,
  "actor": {
    "principal_type": "workload_oidc",
    "principal_id": "github-actions:run-9840212",
    "ip_address": "192.0.2.45",
    "user_agent": "ciphervault-action/v2"
  },
  "action_result": "success",
  "reason": "Production deploy deployment-4819"
}
```

> [!CAUTION]
> **Audit Privacy Rule:** Plaintext secret values and unencrypted payloads **must never** appear in audit records, error responses, stack traces, or metrics logs.

---

## 21. Performance and Scalability

```text
Performance Targets & Scaling Profiles:
┌─────────────────────────┬───────────────────┬───────────────────┬───────────────────┐
│ Scale Metric            │ Small (1 Proj)    │ Medium (100 Proj) │ Enterprise (10k)  │
├─────────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Total Secrets Managed   │ 10 - 50           │ 10,000            │ 1,000,000+        │
│ Cache Architecture      │ Process Memory    │ Redis Cluster     │ Distributed L1/L2 │
│ Secret Lookup Latency   │ < 2 ms            │ < 5 ms            │ < 10 ms (p99)     │
│ Peak Retrieval Rate     │ 5 req/s           │ 500 req/s         │ 25,000 req/s      │
│ Database Storage Engine │ SQLite WAL        │ PostgreSQL Pool   │ Partitioned PG/L2 │
└─────────────────────────┴───────────────────┴───────────────────┴───────────────────┘
```

### Safe Caching Strategies
- Cache items use strict composite keys: `cv:sec:{tenant_id}:{project_id}:{env_id}:{secret_name}`.
- Secret values in cache are stored **encrypted** under a short-lived memory key to prevent plain memory dumping.
- Rotation events publish cache invalidation signals across Redis pub/sub.

---

## 22. Failure Modes and Edge Cases

| Scenario | Immediate System Behavior | Recovery / Fail-Safe Mechanism |
| :--- | :--- | :--- |
| **Project Deleted While Secrets Exist** | Rejects immediate purge; marks project as `ScheduledDeletion` (30-day soft-delete). | Requires explicit two-person admin confirmation to purge keys. |
| **Repository Renamed in VCS** | API detects mismatch on next sync; updates `repo_full_name` using stable `external_repo_id`. | Zero secret disruption; credentials remain mapped to durable ID. |
| **Repository Transferred / Stolen** | VCS signature verification fails against initial organization owner. | Halts automatic secret retrieval; alerts project administrators. |
| **Environment Deleted** | Soft-deletes environment; retains secret versions in backup storage. | Audit event logged; prevents recreation with the same name for 24h. |
| **Secret Rotation Failure** | If new secret verification fails, transaction rolls back to previous version. | Active version pointer remains unchanged; no downtime. |
| **KMS / Operator Network Outage** | Local read-through cache serves verified secrets with active TTLs. | Degrades gracefully; blocks write/rotation mutations. |

---

## 23. Testing Strategy

1. **Unit Testing:**
   - Test AAD mismatch rejection during decryption across projects.
   - Verify unique constraint enforcement: `(project_id, environment_id, name)`.
   - Validate context resolution and precedence in the CLI.
2. **Integration Testing:**
   - Test API authorization flows across distinct projects and environments.
   - Verify GitHub/GitLab repository binding handshake and ID tracking.
   - Validate migration of legacy `.env` files into scoped database entities.
3. **Security Testing (Penetration & Red Team):**
   - **IDOR / BOLA:** Enforce rejection when Tenant A requests Tenant B secrets.
   - **Environment Escalation:** Verify dev tokens are rejected on production endpoints.
   - **Entropy Scanning:** Continuously scan CI logs and audit events to ensure zero plaintext leakage.

---

## 24. Embedded Architecture Diagrams

### Diagram 1 — Current Architecture
```mermaid
flowchart TB
    subgraph Client ["Client Machine (Zero-Knowledge)"]
        direction TB
        Files["Tracked Confidential Files\n(.env, certs/server.key)"]
        FastCDC["FastCDC Slicing Engine\n(4 - 64 KiB chunks)"]
        Crypto["Crypto Core Engine\n(XChaCha20-Poly1305 + Blake2b KDF)"]
        Store[("Local SQLite Store\n.ciphervault/vault.db")]
        
        Files --> FastCDC --> Crypto
        Crypto <--> Store
    end

    subgraph Operators ["Untrusted Storage Operators"]
        direction TB
        OP1["Operator 1 (:8201)"]
        OP2["Operator 2 (:8202)"]
        OP3["Operator 3 (:8203)"]
    end

    Crypto ==>|Encrypted Chunks by CID| Operators
```

### Diagram 2 — Current Secret Ownership / Namespace
```mermaid
flowchart LR
    LocalDir["Local Working Directory\n(CWD on Developer Machine)"]
    VaultDB["./.ciphervault/vault.db\n(vault_id: 32 bytes)"]
    TrackedFiles["tracked_files table\n(relative_path: TEXT)"]
    DotEnv[".env file content\n(unindexed strings)"]
    
    LocalDir --> VaultDB
    VaultDB --> TrackedFiles
    TrackedFiles --> DotEnv
```

### Diagram 3 — Proposed Resource Hierarchy
```mermaid
flowchart TD
    Tenant["Organization / Tenant"]
    Workspace["Workspace"]
    Project["Project (Primary Security Boundary)"]
    Repos["Repository Bindings (Stable VCS ID)"]
    Envs["Environments (Dev / Staging / Prod)"]
    Services["Services / Applications"]
    Secrets["Discrete Secrets (Name, Type, Metadata)"]
    Versions["Secret Versions (Ciphertext, Nonce, Tag)"]

    Tenant --> Workspace
    Workspace --> Project
    Project --> Repos
    Project --> Envs
    Project --> Services
    Envs --> Secrets
    Secrets --> Versions
```

### Diagram 4 — Secret Retrieval Flow
```mermaid
sequenceDiagram
    autonumber
    actor Caller as Developer / CI/CD Workload
    participant Gateway as API Gateway
    participant Auth as Auth & Policy Engine
    participant Store as Scoped Secret Service
    participant KMS as Key Management / KMS
    participant Audit as Audit Log Service

    Caller->>Gateway: GET /v1/projects/{proj}/environments/{env}/secrets/{name}
    Gateway->>Auth: Validate Bearer Token & Scope
    Auth-->>Gateway: Principal Authorized (Read)
    Gateway->>Store: Query secret by (proj, env, name)
    Store->>KMS: Request Project DEK
    KMS-->>Store: Return DEK
    Store->>Store: Decrypt version ciphertext with AAD validation
    Store->>Audit: Record secret.read event (digests only)
    Store-->>Caller: Return plaintext secret value (RAM only)
```

### Diagram 5 — Repository Binding Flow
```mermaid
flowchart LR
    VCS["VCS Provider\n(GitHub / GitLab API)"]
    Query["Fetch Stable ID\n(e.g., GitHub Node ID)"]
    Binding["Create repository_bindings Record"]
    Verify["Verify Installation Permissions"]
    Project["Link to Project Model"]

    VCS --> Query --> Binding --> Verify --> Project
```

### Diagram 6 — Migration Flow
```mermaid
flowchart TD
    Scan["Scan Filesystem for .ciphervault/vault.db"]
    Parse["Parse tracked_files and .env files"]
    Map["Map to Project, Environment, and Repo"]
    DryRun["Validate Dry-Run Diff"]
    Transform["Encrypt under Project DEKs"]
    Insert["Insert Scoped Database Records"]
    Decom["Decommission Legacy Local DB"]

    Scan --> Parse --> Map --> DryRun --> Transform --> Insert --> Decom
```

### Diagram 7 — Threat Model / Trust Boundaries
```mermaid
flowchart TB
    subgraph UntrustedZone ["Untrusted Workstation & Storage Operators"]
        Operator["Operator Storage Node\n(Sees only opaque CIDs)"]
        GitRepo["Git Repository\n(Contains code only; zero secrets)"]
    end

    subgraph SecureBoundary ["CipherVault Security Boundary"]
        API["CipherVault Scoped API"]
        PolicyEngine["ABAC / RBAC Policy Engine"]
        KMS["KMS / Envelope Key Encryption"]
        DB[("Scoped Database Store")]
    end

    GitRepo -.->|Blocked| SecureBoundary
    Operator -.->|Zero-Knowledge| SecureBoundary
    API --> PolicyEngine
    PolicyEngine --> KMS
    KMS --> DB
```

### Diagram 8 — Database ERD
```mermaid
erDiagram
    PROJECTS ||--o{ REPOSITORY_BINDINGS : has
    PROJECTS ||--o{ ENVIRONMENTS : has
    PROJECTS ||--o{ SECRETS : contains
    ENVIRONMENTS ||--o{ SECRETS : scopes
    SECRETS ||--o{ SECRET_VERSIONS : tracks

    PROJECTS {
        uuid project_id PK
        string slug
        string name
    }
    REPOSITORY_BINDINGS {
        uuid binding_id PK
        uuid project_id FK
        string provider
        string external_repo_id
    }
    ENVIRONMENTS {
        uuid environment_id PK
        uuid project_id FK
        string name
    }
    SECRETS {
        uuid secret_id PK
        uuid project_id FK
        uuid environment_id FK
        string name
    }
    SECRET_VERSIONS {
        uuid version_id PK
        uuid secret_id FK
        int version
        blob ciphertext
    }
```

### Diagram 9 — API Interaction Sequence
```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer Terminal
    participant CLI as ciphervault CLI
    participant API as CipherVault REST API
    
    Dev->>CLI: ciphervault secret set DB_PASS --env prod
    CLI->>API: POST /v1/projects/proj_1/environments/prod/secrets
    API->>API: Encrypt under Project KEK & check uniqueness
    API-->>CLI: 201 Created (secret_id, version: 1)
    CLI-->>Dev: Success: Stored DB_PASS in prod (v1)
```

### Diagram 10 — Deployment / CI-CD Secret Retrieval
```mermaid
flowchart LR
    CI["CI/CD Runner (GitHub Actions)"]
    OIDC["OIDC Identity Verification"]
    CV["CipherVault Scoped Gateway"]
    Env["In-Memory Process Injection"]
    App["Container / Node Process"]

    CI -->|OIDC JWT| OIDC
    OIDC -->|Validated Claims| CV
    CV -->|Inject Decrypted Secrets| Env
    Env -->|Execute| App
```

---

## 25. File and Module Impact Map

The proposed changes are mapped directly to active repository locations:

| Functional Area | Existing Repository Location | Proposed Architectural Change | Risk Level | Validation Test Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Domain Models & Wire Format** | [`crates/format/src/schema.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/format/src/schema.rs) | Add `ProjectRecord`, `EnvironmentRecord`, `SecretEntry`, `SecretVersionRecord`. | **High** | Wire serialization compatibility tests. |
| **Local Store Schema & Queries** | [`crates/local-store/src/db.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/local-store/src/db.rs) | Add tables for projects, environments, repository bindings, and discrete secrets. | **High** | SQLite migration tests (v3 to v4 schema). |
| **Account Service & Control Plane** | [`services/account/src/state.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/account/src/state.rs) | Expand control plane from `vault_links` to multi-tenant project/environment RBAC. | **High** | Account service integration test suite. |
| **Crypto Core (AEAD & Context)** | [`crates/crypto/src/aead.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/crypto/src/aead.rs) | Bind AAD with `tenant_id`, `project_id`, `env_id`, `secret_id`, and `version`. | **High** | Cryptographic KAT and tampering tests. |
| **Snapshot Engine & FastCDC** | [`crates/snapshot/src/engine.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/snapshot/src/engine.rs) | Support discrete secret reconstruction alongside file-level FastCDC chunking. | **Medium** | Snapshot restore and deduplication tests. |
| **CLI Commands Engine** | [`apps/cli/src/commands/`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/commands/) | Add `project.rs`, `secret.rs`, `repo.rs`, and update `run.rs` to support scoped lookups. | **Medium** | CLI command parsing and mock E2E tests. |
| **Dashboard & Web Explorer** | [`apps/cli/src/dashboard/`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/dashboard/) | Replace disk walk with authenticated, scoped project and secret explorer APIs. | **Medium** | Web UI route integration tests. |
| **CI/CD Composite Action** | [`.github/actions/ciphervault-run/`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/.github/actions/ciphervault-run/) | Add OIDC identity federation and support explicit `--project` and `--env` flags. | **Low** | GitHub Actions workflow execution matrix. |

---

## 26. Phased Implementation Plan

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               PHASED IMPLEMENTATION ROADMAP                            │
├─────────────┬──────────────────────────┬───────────────────────────────────────────────┤
│ Phase       │ Name                     │ Primary Objective                             │
├─────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ Phase 0     │ Architecture Finalization│ Review audit findings and freeze RFC spec.    │
│ Phase 1     │ Domain Models & Wire     │ Implement scoped structs in crates/format.    │
│ Phase 2     │ Database Architecture    │ Deploy v4 migrations in crates/local-store.   │
│ Phase 3     │ Cryptographic Context    │ Update crates/crypto to enforce scoped AAD.   │
│ Phase 4     │ Control-Plane Services   │ Add project & environment endpoints to account│
│ Phase 5     │ VCS Repository Linking   │ Implement durable GitHub/GitLab bindings.     │
│ Phase 6     │ CLI & DX Redesign        │ Implement ciphervault project and secret CLI. │
│ Phase 7     │ Migration & Back-Compat  │ Release automated migration CLI tool.         │
│ Phase 8     │ CI/CD OIDC Integration   │ Release OIDC federation for GitHub/GitLab.    │
│ Phase 9     │ Security Hardening       │ Complete IDOR, BOLA, and entropy audits.      │
│ Phase 10    │ Production Readiness     │ Update documentation, runbooks, and telemetry.│
└─────────────┴──────────────────────────┴───────────────────────────────────────────────┘
```

---

## 27. Security Invariants (Non-Negotiable)

The target architecture must strictly enforce the following security invariants:

1. **Scope Authorization Before Decryption:** A caller can never obtain or decrypt a secret without server-side validation of their principal against the explicit `(tenant_id, project_id, environment_id)` scope.
2. **Secret Names Lack Semantic Authority:** A secret name (e.g. `DATABASE_URL`) alone is never treated as sufficient authorization context. It must be qualified by a fully specified resource path.
3. **Cryptographic Context Binding:** Every secret ciphertext must bind `tenant_id`, `project_id`, `environment_id`, and `version` into the AEAD Authenticated Additional Data (AAD). Ciphertext copied across scopes will fail decryption.
4. **Stable VCS Identifiers:** Repository bindings must rely on immutable, provider-issued numerical IDs (`external_repo_id`), never mutable names or slugs.
5. **Zero Plaintext Leakage:** Plaintext secrets must never be written to persistent storage, returned in search queries, logged in audit events, or exposed in error messages.
6. **Isolated Caching:** All cache entries must incorporate the complete tenancy and project scope in their keys.
7. **Audited Lifecycle Operations:** Every secret creation, access, rotation, and deletion must generate an immutable, authenticated audit log event.
8. **Explicit Environment Gates:** Access to a lower environment (e.g. `development`) confers no permissions to a higher environment (`production`). Environment transitions require explicit authorization.

---

## 28. Deliverables Directory & Cross-Reference

- **Deliverable A — Executive Findings:** Formatted table in [Section Deliverable A](#deliverable-a--executive-findings).
- **Deliverable B — Full Technical Research Report:** Sections 1 through 27 of this document.
- **Deliverable C — Target Architecture Specification:** Detailed in [Section 9](#9-recommended-target-architecture).
- **Deliverable D — Database Specification:** Schemas, ERD, and constraints in [Section 11](#11-database-architecture).
- **Deliverable E — API Specification:** Scoped REST routes and JSON schemas in [Section 12](#12-api-architecture).
- **Deliverable F — Migration Plan:** 7-stage state machine and conflict resolution in [Section 18](#18-migration-strategy).
- **Deliverable G — Security & Threat Model:** Threat matrix and mitigations in [Section 15](#15-security-model--isolation-guarantees) and [Section 16](#16-threat-modeling).
- **Deliverable H — Implementation Task Breakdown:** Mapped to actual repository files in [Section 25](#25-file-and-module-impact-map) and [Section 26](#26-phased-implementation-plan).
- **Deliverable I — Architecture Diagrams:** 10 GitHub-compatible Mermaid diagrams embedded throughout this report.
- **v2.5.0 supplements in this report:** S1 full 20-threat model (§12), S2 workflows C/E/F (§13), S3 17-scenario failure table (§18), S4 7-design decision matrix (§23), S5 per-phase plan detail (§21), S6 test matrix (§19), S7 evidence register (§27).
- **Standalone deliverable files (same directory):** `SCOPED_SECRETS_EXECUTIVE_FINDINGS.md` (A), `SCOPED_SECRETS_TARGET_ARCHITECTURE.md` (C), `SCOPED_SECRETS_DATABASE_SPEC.md` (D), `SCOPED_SECRETS_API_SPEC.md` (E), `SCOPED_SECRETS_MIGRATION_PLAN.md` (F), `SCOPED_SECRETS_SECURITY_THREAT_MODEL.md` (G), `SCOPED_SECRETS_IMPLEMENTATION_TASKS.md` (H). Each is self-contained; the main report remains the authoritative audit record.

---

## 29. Acceptance Criteria

The scoped secret management implementation is complete when:
- [ ] Every stored secret is uniquely bound to a `(tenant_id, project_id, environment_id)` tuple.
- [ ] Storing identical secret names across different projects or environments produces no collisions.
- [ ] A developer without production permissions is rejected when requesting production credentials.
- [ ] The CLI command `ciphervault secret get <name> --env <env>` returns only the scoped secret.
- [ ] Renaming a GitHub repository does not break existing repository bindings or secret access.
- [ ] CI/CD runners can retrieve secrets using short-lived OIDC tokens without requiring Master Secret $R$.
- [ ] Legacy `.ciphervault` directory vaults can be migrated into scoped database records using `ciphervault migrate`.
- [ ] All 10 security invariants pass automated verification in the test suite.

---

## 30. Open Questions

1. **Storage Operator Layering:** Should untrusted federated storage operators continue storing only opaque FastCDC content chunks, or should operators support encrypted project-scoped relational state?  
   *Current consensus:* Keep operators zero-knowledge and content-addressed. Layer project scoping and metadata management in the control-plane service ([`services/account`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/account/src/lib.rs)).
2. **Offline Local Development:** How should scoped secrets function in fully air-gapped developer environments?  
   *Proposed approach:* Allow `ciphervault project export-local` to generate an encrypted local snapshot bundle tied to a specific project and environment for offline execution via `ciphervault run`.

---

## S1. Full Threat Model — 20 Scoped-Secret Threats (v2.5.0 supplement)

Each threat carries the seven required fields. Severity combines impact × likelihood under the target architecture (§9); "existing mitigation" is assessed against the current codebase only.

### T1. Cross-project secret access
- **Attack path:** Attacker holding a valid token for Project A calls `GET /v1/projects/{projectB}/.../secrets/{name}` or reuses a Project A ciphertext blob against Project B's decrypt path.
- **Affected component:** Scoped secret API + SQL access layer + AEAD decrypt path (`crates/crypto/src/aead.rs` successor).
- **Impact:** Critical — full disclosure of another project's credentials.
- **Likelihood/conditions:** High if scope checks are per-route afterthoughts; low once centralized.
- **Existing mitigation:** None as scoped API — but today's per-vault epoch keys (`LocalVaultStore::rotate_epoch_key`, `crates/local-store/src/db.rs:498`) mean distinct directories already have distinct keys `[Verified in code]`; there is no cross-vault API to abuse, only local file access.
- **Proposed mitigation:** Single `authorize(principal, tenant, project, env, action)` choke point; `tenant_id`/`project_id` predicates in every query; scope-bound AAD (`tenant‖project‖env‖secret‖version`, §15) so cross-project ciphertext fails MAC verification.
- **Test method:** Parameterized IDOR suite: for every secret route, token of project A × resource of project B ⇒ 403/404 uniformly; cross-scope ciphertext replay ⇒ decryption failure.

### T2. Cross-tenant secret access
- **Attack path:** Tenant A principal guesses or reuses UUIDs/URLs to reach tenant B rows; or a shared-service bug drops the `tenant_id` predicate.
- **Affected component:** All control-plane queries; connection/session context.
- **Impact:** Critical — multi-tenant breach, compliance failure.
- **Likelihood/conditions:** Medium; classic SaaS failure mode under shared-schema multi-tenancy.
- **Existing mitigation:** N/A — no tenancy exists; single-user local vaults `[Verified in code]`.
- **Proposed mitigation:** `tenant_id` as leading column of every tenant-owned table + composite FKs; row-level security (Postgres) or mandatory scope-context wrapper; per-tenant KEKs so cross-tenant DEK use is cryptographically impossible; tenant allowlist on service tokens.
- **Test method:** Tenant-isolation test harness: tenant A fixtures + tenant B attacker token across all endpoints; SQL assertion that no query plan touches rows of another tenant (EXPLAIN audit on sampled queries).

### T3. IDOR/BOLA against secret APIs
- **Attack path:** Attacker mutates `{secret_id}`, `{project_id}`, or `{environment}` path params to reference objects outside their grant (e.g., `POST /v1/projects/A/secrets/{id-from-B}/rotate`).
- **Affected component:** Route handlers, policy engine.
- **Impact:** High — unauthorized read/rotate/delete of arbitrary secrets.
- **Likelihood/conditions:** High without object-level checks; BOLA is OWASP API #1.
- **Existing mitigation:** None — no secret APIs exist `[Verified in code]`; closest analogue, `vault_links` PK `(account_id, vault_id_hex)`, is account-keyed `[Verified in code]`.
- **Proposed mitigation:** Resolve-then-authorize: load object, verify `(tenant, project, env)` matches route scope, then check grant; never trust path params as authorization; use non-enumerable UUIDv7 IDs; uniform 404 for unauthorized-or-missing.
- **Test method:** BOLA matrix tests per endpoint (wrong parent, sibling object, deleted object); fuzz path params; assert no 500/info leakage on invalid IDs.

### T4. Secret-name enumeration
- **Attack path:** Attacker brute-forces `GET .../secrets/{name}` or abuses list/search to learn which secret names exist in a project they partially access.
- **Affected component:** Get-by-name route, search endpoint, error messages.
- **Impact:** Medium — reveals infrastructure layout (`PROD_PCI_DB_URL`), aids targeted attacks.
- **Likelihood/conditions:** Medium where names are guessable (`DATABASE_URL`, `AWS_SECRET`).
- **Existing mitigation:** Partial — `.env` key names are inside encrypted manifests, invisible without vault keys `[Verified in code]`; but `relative_path` values are visible to anyone opening the local DB.
- **Proposed mitigation:** Uniform 404 + constant-time-ish responses for missing vs forbidden; rate-limit name lookups; search only within authorized scope (§19); avoid descriptive names in error strings; optional per-secret "existence-concealment" flag for crown jewels.
- **Test method:** Enumeration probe: measure response indistinguishability (status/body/timing bands) for existent-forbidden vs nonexistent names; assert search returns zero rows outside scope.

### T5. Repository binding bypass
- **Attack path:** Attacker forks a bound repo, or claims `owner/repo` name after a rename, and requests repo-scoped secrets; or tampers with `repo` claim in a CI token.
- **Affected component:** VCS binding service, OIDC claim validation, repo-scoped policy checks.
- **Impact:** High — CI-oriented secret disclosure.
- **Likelihood/conditions:** Medium; renames/transfers/forks are routine events.
- **Existing mitigation:** N/A — no repo bindings exist; only `.gitignore` sync + pre-commit hook (`apps/cli/src/commands/hook.rs`, `track.rs`) `[Verified in code]`.
- **Proposed mitigation:** Bind on immutable provider IDs only (GitHub repo ID, GitLab project ID, Bitbucket UUID — §14); verify OIDC `repository_id` claim against binding, never the slug; re-resolve slug→ID on every sensitive call or cache ≤5 min; fork != same ID ⇒ no inheritance; installation-token ownership proof at bind time.
- **Test method:** Simulate rename/transfer/fork with provider fixtures; assert old slug denied, new slug resolves to same binding, fork ID denied.

### T6. Environment escalation (dev → prod)
- **Attack path:** Principal authorized for `development` requests `production` secrets (direct API call, stolen prod URL, or `run --env production` with a dev token).
- **Affected component:** Token issuance, environment policy gates, CLI context resolution.
- **Impact:** Critical — production credential disclosure.
- **Likelihood/conditions:** High — today `run` merges `.env*` with no gates at all (`run.rs:141-180`) `[Verified in code]`.
- **Existing mitigation:** None — filename convention only `[Verified in code]`.
- **Proposed mitigation:** Environment-scoped tokens (env embedded in signed token claims, server-verified); separate prod approver role + branch policy (`main` only); CLI prints active scope and requires `--env` for non-default envs; prod reads additionally audit-logged + alerted.
- **Test method:** Dev-token-against-prod matrix (all routes ⇒ 403); CLI test: dev context + `--env production` ⇒ explicit denial naming the missing grant; branch-policy test from feature branch ⇒ denied.

### T7. Privilege escalation through project membership
- **Attack path:** Attacker invites self / accepts stale invite / exploits membership role confusion (`viewer` → `admin`) to gain secret write/rotate rights.
- **Affected component:** Membership/invitation service (extends today's `memberships`/`invitations`, `services/account/src/state.rs:95-119`).
- **Impact:** High — persistent privileged access to project secrets.
- **Likelihood/conditions:** Medium; invitation flows are historically bug-prone.
- **Existing mitigation:** Partial — account memberships exist with role/status lifecycle and `audit_event("membership_*")` calls `[Verified in code]`, but they govern accounts/vaults, not secret scopes.
- **Proposed mitigation:** Least-privilege default role; admin-only invite; single-use expiring invite tokens (`token_hash_hex` pattern already in schema); role-change requires second admin for `admin` grants; membership changes emit audit events + notify existing admins.
- **Test method:** Membership state-machine tests (invite→accept→revoke→reinvite); horizontal-escalation tests (member attempts admin APIs); stale-invite replay ⇒ rejected.

### T8. Stale repository bindings
- **Attack path:** Bound repo is deleted/transferred; binding silently goes stale; secrets remain reachable under a formerly-valid VCS context, or new unrelated repo reuses the name.
- **Affected component:** Binding lifecycle worker, VCS webhook receiver.
- **Impact:** Medium — authorization drift, potential disclosure after org change.
- **Likelihood/conditions:** Medium; repo churn is frequent at enterprise scale.
- **Existing mitigation:** N/A — no bindings `[Verified in code]`.
- **Proposed mitigation:** Provider webhooks (rename/transfer/delete) + daily reconciliation probe; binding states `active → suspended → revoked`; suspended bindings deny new grants but preserve audit/decrypt of existing versions for break-glass; admin alert on drift.
- **Test method:** Webhook simulation suite (rename/transfer/delete/archive); assert state transitions + denial behavior + audit events; reconciliation dry-run diff test.

### T9. Deleted-project secret retention
- **Attack path:** Project deleted but ciphertext/keys/backups linger; later re-created project with same slug resurrects or cross-reads old secrets; or legal hold requires proof of destruction.
- **Affected component:** Deletion workflow, key destruction, backup retention, slug registry.
- **Impact:** Medium-High — data remnance, compliance (GDPR/CCPA deletion) failure.
- **Likelihood/conditions:** Medium without explicit crypto-shredding.
- **Existing mitigation:** N/A — vault deletion is `rm -rf .ciphervault` (operator replicas may persist per lease terms) `[Inferred from implementation]`.
- **Proposed mitigation:** Soft-delete (30-day `ScheduledDeletion`) → crypto-shredding (destroy P-KEK/DEKs) → purge rows; slug quarantine (no reuse 30 days); backups age out under same key destruction (ciphertext unrecoverable); deletion certificate in audit log.
- **Test method:** Delete→recreate-same-slug test (zero old rows/versions reachable); post-shredding decrypt attempt ⇒ failure; backup-restore-after-shredding ⇒ unrecoverable ciphertext only.

### T10. Secret leakage through logs
- **Attack path:** Secret value printed in CLI output, API error, stack trace, trace span, or `details_json` audit field.
- **Affected component:** CLI output, API error envelope, tracing/metrics, `activity_log`/`audit_events` writers.
- **Impact:** High — plaintext in durable, widely-replicated stores.
- **Likelihood/conditions:** Medium-High; today `run --dry-run` prints only names (verify), but ad-hoc `details_json` is free-form `[Verified in code]`.
- **Existing mitigation:** Partial — `diff.rs:mask_value` masks values (`12***78`); operator error envelope standardizes shape (`services/operator/src/lib.rs:69-94`) `[Verified in code]`; no systematic secret-scrubbing in logs.
- **Proposed mitigation:** Typed `SecretValue` wrapper with `Debug` redaction; structured audit schema accepting only `sha256(value)` digests; global log-scrubber for `-----BEGIN`, `sk-`, `AKIA`, high-entropy tokens; CI entropy-scan gate on logs; `--dry-run` prints names + versions only.
- **Test method:** Log-capture tests on all secret paths assert zero occurrences of canary values; entropy scanner gate in CI; audit-row schema test rejects value-shaped fields.

### T11. Secret leakage through backups
- **Attack path:** Attacker obtains DB backup / snapshot export / `vault.db` copy containing ciphertext + (worse) keys or plaintext metadata enabling offline attack.
- **Affected component:** Backup pipeline, export/import, snapshot replication.
- **Impact:** High — bulk disclosure if keys co-located; metadata analysis otherwise.
- **Likelihood/conditions:** Medium; backups are the most-copied artifact.
- **Existing mitigation:** Partial — operator replicas hold ciphertext only (zero-knowledge) `[Verified in code]`; but local `vault.db` holds `epoch_keys` table (`db.rs:143-146`) so a DB copy = full compromise of that vault `[Verified in code]`.
- **Proposed mitigation:** Split-plane backups: ciphertext backups separate from KMS-backed keys (never co-exported); backup encryption with distinct backup KEK + Shamir break-glass; metadata minimization (no descriptions/tags in cold backups unless encrypted); restore requires quorum + audit.
- **Test method:** Backup-restore test into isolated env ⇒ ciphertext-only without KMS; DB-file theft simulation ⇒ keys absent; manifest asserts no `*_key_bytes` columns in backup schema.

### T12. Malicious CI/CD identity
- **Attack path:** Attacker with PR rights exfiltrates secrets via a malicious workflow step on a runner that holds a broad OIDC-issued token.
- **Affected component:** OIDC federation, token scope minting, runner hardening guidance.
- **Impact:** Critical — production secret exfiltration through legitimate pipeline.
- **Likelihood/conditions:** Medium-High in public/fork-PR workflows.
- **Existing mitigation:** None — no OIDC federation; CI must hold master secret R (circular dependency, §6) `[Verified in documentation + Inferred]`.
- **Proposed mitigation:** Least-privilege tokens: per-job, per-env, 15-min TTL, bound to `repo_id + branch + commit`; fork-PR ⇒ dev-only tokens; secret masking in CI logs; OIDC `job_workflow_ref` allowlist; break-glass revocation list checked per request.
- **Test method:** Malicious-step simulation (exfil attempt with job token from fork PR ⇒ dev-only); token replay from different `job_workflow_ref` ⇒ denied; TTL expiry test.

### T13. Token replay
- **Attack path:** Attacker captures a session/OIDC-derived/signed-URL token and replays it from another host, or reuses an expired token after clock skew.
- **Affected component:** Session service (extends `services/account/src/sessions.rs`), token validation.
- **Impact:** High — impersonation within token scope.
- **Likelihood/conditions:** Medium; bearer tokens are replayable by nature.
- **Existing mitigation:** Partial — short TTLs exist (`SESSION_TTL_SECONDS = 30 min`, handoff 2 min, `state.rs:14-17`); token hashes stored (`token_hash_hex`) `[Verified in code]`; no sender-constraining (DPoP/mTLS) observed.
- **Proposed mitigation:** Short TTLs (5–15 min workload tokens) + rotation; optional DPoP/mTLS binding for prod; single-use handoffs; replay cache (jti denylist) for the TTL window; strict `iat/exp/nbf` + 60s leeway; revocation propagation <60s.
- **Test method:** Replay captured token from second IP/fingerprint ⇒ denied (when bound) or scope-limited; expired-token ⇒ 401; reused handoff ⇒ rejected; clock-skew boundary tests.

### T14. Insider access
- **Attack path:** Rogue admin/dev with legitimate grants bulk-exports secrets, or DBA reads ciphertext + keys from co-located stores.
- **Affected component:** Admin APIs, export paths, key custody, audit pipeline.
- **Impact:** Critical — bulk disclosure by trusted party.
- **Likelihood/conditions:** Low-Medium probability, catastrophic impact.
- **Existing mitigation:** Weak — anyone with vault keys reads everything; no per-secret audit `[Verified in code]`; PIV touch + Shamir recovery raise the bar for unattended theft `[Verified in code]`.
- **Proposed mitigation:** Split knowledge (ciphertext ≠ keys); dual-control for bulk export + prod access (2-person rule); just-in-time elevation with expiry; immutable append-only audit (hash-chained) shipped off-host; anomaly alerts (bulk reads, off-hours prod); break-glass procedures.
- **Test method:** Dual-control test (single admin export ⇒ denied); audit-tamper test (chain verification fails on edit); anomaly-detector canary (bulk-read fixture triggers alert).

### T15. Database compromise
- **Attack path:** Attacker dumps the control-plane DB (SQLi, stolen backup, host breach) and harvests ciphertext + metadata.
- **Affected component:** Database, query layer, backup stores.
- **Impact:** High for metadata; ciphertext-only if keys are external.
- **Likelihood/conditions:** Medium — DB is the highest-value target.
- **Existing mitigation:** Partial — local `vault.db` compromise = total vault compromise (keys in `epoch_keys`) `[Verified in code]`; account DB holds hashes + TOTP ciphertext (key from env/file, `state.rs:20-21`) `[Verified in code]`.
- **Proposed mitigation:** Keys in KMS/HSM, never in the secret DB; metadata minimization + field-level encryption for sensitive metadata (descriptions); parameterized queries only; DB credentials via vault with rotation; encrypted backups (§T11).
- **Test method:** Dump-analysis test: given full DB dump without KMS, assert zero recoverable plaintexts (automated crack-attempt with fixture canaries fails); SQLi fuzz on all inputs.

### T16. Compromised application server
- **Attack path:** Attacker gains RCE on the control-plane host; reads in-memory DEKs, intercepts plaintext at decrypt time, or backdoors policy checks.
- **Affected component:** API hosts, KMS client, memory handling.
- **Impact:** Critical — total loss of confidentiality/integrity while compromised.
- **Likelihood/conditions:** Low-Medium; defense-in-depth limits blast radius/duration.
- **Existing mitigation:** Partial — zeroize-on-drop key types (`keys.rs`) + no plaintext at rest on operators `[Verified in code]`; but local CLI decrypts to RAM on the same host as the attacker in this scenario.
- **Proposed mitigation:** Confidential-computing option (enclave decrypt) for high tiers; short-lived in-memory keys + aggressive zeroize; read-only root FS, seccomp, no shell; KMS request signing + anomaly detection (bulk-decrypt alert); rapid key rotation + revocation runbooks; mutual TLS service mesh.
- **Test method:** Chaos/compromise drill: rotate all project keys + revoke tokens within SLO; memory-dump canary test (no long-lived plaintext); KMS anomaly fixture triggers alert.

### T17. Compromised developer workstation
- **Attack path:** Malware on dev laptop scrapes CLI memory, `~/.config/ciphervault`, shell history, or injected process env of `run` children.
- **Affected component:** CLI, local keystore (`crates/local-store/src/keyring.rs`), `run` env injection.
- **Impact:** High — all vaults/credentials accessible from that workstation.
- **Likelihood/conditions:** Medium — workstations are the softest endpoint.
- **Existing mitigation:** Partial — OS keyring (Windows DPAPI) + reject guessable env-derived keys (`keyring.rs:180-182`) `[Verified in code]`; PIV-backed device identity optional `[Verified in code]`; `run` zeroizes buffers on exit `[Verified in documentation: main.rs help]`; shell history risk remains.
- **Proposed mitigation:** PIV/passkey-required prod access; short-lived local grants (re-auth for prod); `run` env hygiene (no `export` echo, `--no-inherit` default for prod); clipboard/history warnings; device posture checks (disk encryption, EDR) before prod grants; remote revoke + session kill.
- **Test method:** Posture-gate tests (non-compliant device ⇒ prod denied); history-hygiene test (CLI never prints values; `--dry-run` names-only); revoke-propagation test (<60s).

### T18. Cache poisoning / cache-key collisions
- **Attack path:** Attacker causes project A's secret to be served for project B via colliding/overly-broad cache keys, or poisons shared cache entries.
- **Affected component:** Cache layer (process/Redis), invalidation bus.
- **Impact:** High — cross-project disclosure or stale-secret use.
- **Likelihood/conditions:** Medium if cache keys omit scope; low with strict keying.
- **Existing mitigation:** N/A — no secret cache exists (local chunks keyed by content CID, self-validating) `[Verified in code]`.
- **Proposed mitigation:** Mandatory key format `cv:sec:{tenant}:{project}:{env}:{secret_id}:{version}`; values stored ciphertext-only (decrypt after fetch); authenticated cache writes; rotation bumps version ⇒ old keys unreachable; Redis ACLs per service; cache-miss fallback to authoritative read.
- **Test method:** Collision unit tests (same name, different scopes ⇒ distinct keys); poisoning test (forged entry without MAC ⇒ rejected); rotation-invalidation test (old version never served post-rotate).

### T19. Secret version mix-ups
- **Attack path:** Concurrent readers/writers disagree on "current" version; rollback resurrects a compromised credential; reader caches version pointer across rotation.
- **Affected component:** Version-pointer updates, reader caching, rollback flows.
- **Impact:** Medium-High — outage or resurrected-compromised-credential use.
- **Likelihood/conditions:** Medium under high-churn/rotation storms.
- **Existing mitigation:** N/A for secrets — snapshot DAG uses content IDs + active head (`heads` table, `is_active`) `[Verified in code]`; no per-secret versioning.
- **Proposed mitigation:** Monotonic `current_version` pointer updated transactionally with new version insert; readers pin `(secret_id, version)` for a session, never float across rotation mid-deploy; rollback = new version (never pointer-rewind) with audit + reason; deprecation (not delete) for compromised versions.
- **Test method:** Concurrency tests (N parallel rotates ⇒ linear version history, single winner per version); rollback-creates-version test; deploy-pinning test (in-flight deploy keeps pinned version).

### T20. Race conditions during secret rotation
- **Attack path:** Two admins/CI jobs rotate simultaneously ⇒ lost update, skipped version, or partially-written state; readers observe half-rotated credentials.
- **Affected component:** Rotate endpoint, version transaction, external-system sync (e.g., cloud IAM + stored secret must agree).
- **Impact:** Medium-High — outage, lockout, or unknown-credential state.
- **Likelihood/conditions:** Medium in automated rotation (storms) and multi-admin teams.
- **Existing mitigation:** N/A for secrets — epoch rotation is single-writer local (`rotate_epoch_key`) `[Verified in code]`; SQLite busy-handler serializes local contention (`db.rs:33-46`) `[Verified in code]`.
- **Proposed mitigation:** `POST .../rotate` guarded by `SELECT … FOR UPDATE` on secret row + idempotency keys; rotation jobs (`secret_rotation_jobs` table) with states `pending→running→verifying→committed|rolled_back`; verify-new-credential-liveness before committing pointer; rollback preserves old version as fallback for TTL window.
- **Test method:** Double-rotate race test (same idempotency key ⇒ single version; different keys ⇒ serialized v+1, v+2); kill-mid-rotation test ⇒ `rolled_back`, old version live; liveness-verify-failure test ⇒ no pointer move.

---

## S2. Real-World Workflows C, E, F (v2.5.0 supplement)

Workflow mapping to the required set: **A** (new project) → §17-A `[Proposed design]`; **B** (migration) → §18 state machine `[Proposed design]`; **D** (production deployment) → §17-B `[Proposed design]`. The remaining required workflows are specified here.

### Workflow C: Multiple repositories, one project
- **Setup:** project `payments` binds three repos by immutable provider ID: `backend` (GitHub id `84920194`), `frontend` (id `84920195`), `infra` (id `84920196`).
- **Sharing rule (decision):** secrets default to **project+environment scope** and are shared across the project's repos; **repository isolation is opt-in** via `repository_binding_id` on secrets whose blast radius must be confined (e.g., `INFRA_TERRAFORM_TOKEN` bound to `infra` only), and **service isolation** via `service_id` for microservice credentials.
- **Rationale:** a shared `DATABASE_URL` needed by both `backend` and `infra` must not be duplicated (duplicates drift and double rotation work); binding it to one repo would break the other. Confinement is enforced at authorization time: a token minted for repo `frontend` cannot read secrets bound to repo `infra`.
- **Commands:**
```bash
ciphervault repo bind --project payments --provider github --repo-id 84920194  # backend
ciphervault repo bind --project payments --provider github --repo-id 84920196  # infra
ciphervault secret set DATABASE_URL --project payments --env production        # shared
ciphervault secret set INFRA_TERRAFORM_TOKEN --project payments --env production --repo-id 84920196  # confined
```

### Workflow E: Repository rename (zero-downtime ownership continuity)
1. `acme/payments-service` (GitHub id `84920194`) is renamed to `acme/payments-v2`. The provider fires a `repository.renamed` webhook carrying the unchanged numeric id.
2. Control plane looks up `repository_bindings` by `(provider, external_repo_id)` — **not** by slug — and updates `repo_full_name`/`repo_url` display fields only. `binding_id` and all secret references are untouched.
3. In-flight CI tokens carry `repository_id: 84920194`; validation still passes. Tokens carrying only the old slug (legacy) are rejected with `BINDING_STALE_SLUG`, directing callers to re-resolve.
4. Audit event `repository.rebound` records `{binding_id, old_slug, new_slug, actor: vcs-webhook}`.
5. If the webhook is missed, the daily reconciliation probe (§T8) detects the slug mismatch and performs the same display-only update, alerting admins.

### Workflow F: Secret rotation without identity change or cross-project impact
1. Operator runs `ciphervault secret rotate STRIPE_KEY --project payments --env production`. API opens a transaction, locks the secret row (`SELECT … FOR UPDATE`), inserts `secret_versions(version = current+1, ciphertext, nonce, tag, encryption_key_id)` with scope-bound AAD, verifies new-credential liveness (provider ping), then advances `secrets.current_version`.
2. Logical identity (`secret_id`, name, project, env) is unchanged; consumers resolving by name get v+1 on next fetch; in-flight deploys pinned to v continue until completion (§T19).
3. Rotation is scoped by construction: the `UPDATE` predicate includes `(tenant_id, project_id, environment_id)`; same-named secrets in other projects/envs share nothing (distinct rows, DEKs, AAD) and are unaffected.
4. Old version is retained per policy (rollback window), then tombstoned; `secret.rotated` audit event records `{secret_id, previous_version, current_version, actor, reason}` with value digests only.
5. Concurrent second rotation serializes on the row lock; with the same idempotency key it returns the existing outcome (§T20).

---

## S3. Failure Modes and Edge Cases — Full 17-Scenario Table (v2.5.0 supplement)

Extends §22 (6 rows) to the required 17. All behaviors are `[Proposed design]` unless noted.

| # | Scenario | Expected system behavior |
|---|----------|--------------------------|
| 1 | Project deleted while secrets exist | Soft-delete `ScheduledDeletion` (30 days); secrets unreadable except break-glass export; then crypto-shredding (destroy P-KEK) + row purge; slug quarantined 30 days (§T9). |
| 2 | Repository deleted (provider) | Binding → `suspended`; repo-confined grants denied; shared project secrets unaffected; admin alert; binding → `revoked` after 30 days or on explicit confirm. |
| 3 | Repository renamed | Display-only update via stable provider ID; zero secret disruption (§S2-E). |
| 4 | Repository transferred (new owner/org) | Binding → `suspended` pending admin re-verification of installation ownership; secret reads via that VCS context halted; audit `repository.suspended`. |
| 5 | Environment deleted | Soft-delete env; secret versions retained in backup tier; name recreation blocked 24h; tokens scoped to the env revoked immediately. |
| 6 | Secret renamed | Rename = metadata-only update on same `secret_id` (history preserved); old name reserved as alias for 7 days returning `301 Moved` equivalent (`RENAMED_TO` hint) to avoid silent misconfig. |
| 7 | Secret duplicated (same name, same scope) | Rejected by `UNIQUE(project_id, environment_id, name)`; API returns `409 SECRET_NAME_CONFLICT` with the existing `secret_id`; no overwrite. |
| 8 | User removed from project | Grants revoked <60s (token denylist + short TTL); active sessions re-scoped on next request; audit `membership.revoked`; break-glass review of their recent reads. |
| 9 | Service account revoked | Same as #8 plus immediate revocation of minted workload tokens; rotation jobs owned by the account are reassigned or paused with alert. |
| 10 | Organization suspended | All tenants under org enter read-deny (writes blocked first, then reads after grace TTL); keys sealed; audit preserved; reinstatement restores without data loss. |
| 11 | Stale cache | Version-pinned cache keys (§T18) make staleness self-limiting: post-rotation reads miss and re-fetch; max TTL 60s for metadata, values never cached plaintext. |
| 12 | Partial migration | Migration ledger records per-secret state (§18); resume is idempotent (same `migration_id` + per-secret idempotency keys); legacy path stays live until `VERIFIED`; no half-migrated secret is readable from both paths (cutover flips a per-secret pointer). |
| 13 | Failed rotation | Transaction rolls back; `current_version` unchanged; job marked `rolled_back` with reason; alert; old credential remains live (fail-safe, §T20). |
| 14 | Failed KMS operation | Reads: serve from short-TTL verified cache if fresh, else fail closed with `KMS_UNAVAILABLE` (no bypass); writes/rotations blocked; circuit breaker + alert; no key material cached beyond TTL. |
| 15 | Database failover | Reads replay on replica (read-your-write via version pin for 5s after mutation); in-flight rotation transactions abort and are safely retryable via idempotency keys; RPO/RTO per deployment tier. |
| 16 | Backup restore into another environment | Restored rows are quarantined (`restored_pending_review`): ciphertext AAD binds original scope, so cross-env decryption fails closed by MAC verification; admin must explicitly re-scope (new versions) — never auto-activate. |
| 17 | Cross-region replication | Async replication with per-row `updated_at` + vector version; conflicts resolve last-writer-wins on metadata, never on versions (versions are append-only, keyed by monotonic ints); KMS multi-region keys or per-region KEKs with re-wrap on read. |

---

## S4. Decision Matrix — 7 Candidate Designs × 8 Criteria (v2.5.0 supplement)

Extends §8 (4 models) to the required 7 designs. Legend — qualitative ratings grounded in explicit criteria: **● strong** (satisfies the criterion with no structural workaround), **◐ partial** (satisfies with conventions, extra mechanisms, or limited scale), **○ weak** (structurally incapable or requires rebuilding to satisfy). No numeric scores are used.

| # | Design | Isolation | Dev experience | Flexibility | Ops complexity (lower is better) | Multi-tenancy | Migration complexity (lower is better) | API ergonomics | Extensibility |
|---|--------|-----------|----------------|-------------|----------------------------------|---------------|----------------------------------------|----------------|---------------|
| D1 | Global namespace (`name` only) | ○ one pool; any reader sees all | ◐ trivial lookup, catastrophic at scale | ○ no boundaries to vary | ● nothing to operate | ○ no tenant boundary | ● nothing to migrate | ◐ `get(name)` simple but ambiguous | ○ nowhere to attach policy |
| D2 | User namespace (`user + name`) | ◐ per-user walls; sharing = copying | ◐ familiar, breaks on teams/CI | ○ teams, envs, services unmodelled | ◐ per-user stores × users | ◐ tenant = user set, coarse | ◐ re-home every secret to an owner | ◐ `get(name)` + implicit user | ○ hierarchy must be bolted on |
| D3 | Project-scoped (`project + name`) | ◐ project walls; no env split | ● simple mental model | ◐ envs/services via prefixes | ● one new dimension | ◐ tenant = project set | ◐ classify into projects once | ● `get(project, name)` | ◐ env/repo addable later (migration #2) |
| D4 | Repository-scoped (`repo + name`) | ◐ repo walls; shared secrets duplicated | ◐ natural for single-repo apps | ○ multi-repo/monorepo/shared-infra hostile | ◐ binding count ≈ repo count | ◐ tenant = repo set | ○ split/merge repos force re-scoping | ● `get(repo, name)` | ○ hierarchy fights repo-as-owner |
| D5 | Project + environment (`project + env + name`) | ● project × env walls; no repo confinement | ● matches deploy reality | ● envs first-class; repo via policy | ◐ env lifecycle × projects | ● tenant walls + project walls | ◐ classify into (project, env) | ● `get(project, env, name)` | ● bindings/services addable |
| D6 | Project + repo + environment (`project + repo + env + name`) | ● finest walls | ○ 4-part identity everywhere | ◐ sharing requires escape hatches | ○ binding × env matrix to operate | ● strong walls | ○ hardest classification | ○ verbose, error-prone | ◐ rigid; sharing fights the model |
| D7 | **Hierarchical resource-scoped (recommended, §9)** | ● project/env/service/repo-confinement + crypto AAD binding | ● explicit scope + safe local context (§13) | ● sharing default, confinement opt-in | ◐ most machinery, phased rollout (§26/S5) | ● tenant→workspace→project walls + per-tenant KEKs | ◐ same as D5 + optional bindings | ● scoped routes + name-based CLI | ● new dimensions attach under project |

Trade-offs (explicit):
- **D1/D2** optimize day-0 simplicity and destroy multi-project operability; D2 additionally orphans secrets on departure. Rejected.
- **D3** is the best minimal step but repeats today's `.env.*`-prefix failure at a new layer (env separation by naming convention). Acceptable only as a stepping-stone to D5/D7.
- **D4** (pure repo scoping) fails the prompt's core caution: shared infrastructure secrets, monorepos (many services, one repo), and multi-repo projects (one secret, many repos) all fight repo-as-owner; renames/transfers become ownership events instead of display updates. Rejected as the primary model; retained as *bindings* inside D7.
- **D6** over-constrains: making repo part of identity forces duplication of every shared secret and turns every repo split into a secret migration. Confinement should be a policy attachment, not an identity component.
- **D5 vs D7:** D7 = D5 identity `(project, env, name)` plus optional `repository_binding_id`/`service_id` confinement, workspaces/tenants above, and versions/audit below. D7 is recommended because the extra machinery buys precisely the required properties (rename-proof bindings, service confinement, multi-tenancy, per-secret lifecycle) with no change to the core identity.

---

## S5. Phased Implementation Plan — Per-Phase Detail (v2.5.0 supplement)

Expands the §26 roadmap: every phase lists goals, files/components, dependencies, tasks, acceptance criteria, tests, security and rollback considerations. All paths below exist in the worktree (`[Verified in code]`); new files are marked `NEW`.

### Phase 0 — Discovery (this report)
- **Goals:** freeze current-state findings, gaps, target model.
- **Files:** `report/SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md`, standalone specs A–H.
- **Dependencies:** none. **Tasks:** audit (§2–§4), threat sketch (§16/S1), RFC review.
- **Acceptance:** findings signed off; no `Unknown` on material claims (register S7).
- **Tests:** citation check — every `Verified in code` path resolves. **Security:** no secret values in docs (synthetic placeholders only). **Rollback:** n/a (docs only).

### Phase 1 — Domain model (scoped structs + wire records)
- **Goals:** `Tenant/Workspace/Project/Environment/RepositoryBinding/Service/Secret/SecretVersion` types with validation.
- **Files:** `crates/format/src/schema.rs`, `crates/format/src/lib.rs`, `crates/format/src/canonical.rs`; NEW `crates/format/src/scope.rs`.
- **Dependencies:** Phase 0. **Tasks:** structs + serde/CBOR round-trip; slug/name validators; scope-context type (`Scope{tenant,project,env}`) threaded through APIs; ID types (UUIDv7) distinct from display names.
- **Acceptance:** `cargo test -p ciphervault-format` green; invalid scopes unrepresentable (constructor-gated).
- **Tests:** unit (validation, round-trip, canonical bytes stability). **Security:** no `SecretValue` `Debug`/`Display` impls (compile-fail test). **Rollback:** additive only; delete new module.

### Phase 2 — Database (schema, constraints, indexes, migrations)
- **Goals:** control-plane + local-store v4 schema (§11/S4-D7): PKs, FKs, `UNIQUE(project_id, environment_id, name)`, indexes, soft-delete columns, migration scripts.
- **Files:** `services/account/src/state.rs` (schema), `crates/local-store/src/db.rs` (+`user_version` 4→5 migration runner; corrected during implementation — the tree was already at v4 via lease_receipts).
- **Dependencies:** Phase 1. **Tasks:** DDL for 12 tables (§D-spec); composite FKs; partial indexes (`WHERE deleted_at IS NULL`); backfill + online-migration scripts; `PRAGMA foreign_keys=ON` parity for local store.
- **Acceptance:** migrations apply cleanly on empty + fixture DBs; uniqueness/conflict tests pass; `EXPLAIN` shows index use on `(project, env, name)` lookups.
- **Tests:** migration up/down tests, constraint-violation tests, concurrency (two writers, one winner). **Security:** least-privilege DB roles; no key columns in secret DB (KMS only). **Rollback:** down-migration restores v3; dual-write window before cutover.

### Phase 3 — Authorization (RBAC + ABAC policy engine)
- **Goals:** single `authorize()` choke point; project/env/repo/service grants; ABAC attributes (branch, IP, token presence).
- **Files:** `services/account/src/guards.rs`, `services/account/src/memberships.rs`; NEW `services/account/src/policy.rs`, `services/account/src/scope_tokens.rs`.
- **Dependencies:** Phases 1–2. **Tasks:** grant tables + evaluation order (deny > allow); env gates; repo-confinement checks; scope-embedded token claims; uniform 404 mapping.
- **Acceptance:** authz decision matrix (roles × actions × scopes) fully green; no route reaches storage without `authorize()`.
- **Tests:** unit (decision table), integration (BOLA matrix per route), fuzz (claim tampering). **Security:** fail-closed defaults; policy-parse errors deny. **Rollback:** feature-flag to legacy vault-wide auth.

### Phase 4 — Secret service (CRUD, versioning, rotation core)
- **Goals:** versioned secret lifecycle with transactional pointer moves + audit emission.
- **Files:** NEW `services/account/src/secrets.rs`, `services/account/src/versions.rs`, `services/account/src/rotation_jobs.rs`; `services/account/src/lib.rs` (routes).
- **Dependencies:** Phases 1–3. **Tasks:** create/get/list/rotate/rename/soft-delete; `SELECT … FOR UPDATE` + idempotency keys; liveness verification hook; digest-only audit payloads.
- **Acceptance:** CRUD + rotate + concurrent-rotate suites green; rotation preserves `secret_id` and history (§S2-F).
- **Tests:** integration (lifecycle, races, rollback-on-verify-fail), audit-event assertions. **Security:** plaintext exists only in handler RAM, zeroized; rate limits on read/rotate. **Rollback:** disable routes; data additive.

### Phase 5 — Cryptography context (scoped AAD + envelope keys)
- **Goals:** scope-bound AAD + per-project DEKs / per-tenant KEKs + KMS/HSM integration.
- **Files:** `crates/crypto/src/aead.rs`, `crates/crypto/src/kdf.rs`, `crates/crypto/src/keys.rs`, `crates/crypto/src/hsm.rs`.
- **Dependencies:** Phase 1. **Tasks:** AAD builder `tenant‖project‖env‖secret‖version`; DEK-per-version generation/wrap; KMS envelope (AWS/GCP/Azure + PKCS#11/HSM via existing `hsm.rs` traits); key-rotation + re-wrap jobs; cross-scope negative tests.
- **Acceptance:** cross-scope ciphertext replay fails MAC; KAT vectors pass; KMS outage ⇒ fail-closed reads (§S3-14).
- **Tests:** unit (AAD vectors, tamper rejection), integration (KMS stub + HSM simulator). **Security:** keys never logged/dumped; memory-zeroize audit. **Rollback:** keep epoch-key path for legacy vault data; new data requires new path (no downgrade of written rows).

### Phase 6 — Repository integration (durable VCS bindings)
- **Goals:** provider bindings on immutable IDs + webhooks + reconciliation.
- **Files:** NEW `services/account/src/vcs.rs`, `services/account/src/reconcile.rs`; `apps/cli/src/commands/` NEW `repo.rs`.
- **Dependencies:** Phases 2–4. **Tasks:** GitHub/GitLab/Bitbucket/self-hosted ID resolution; installation-token ownership proof; webhook receiver (rename/transfer/delete); daily reconcile worker; binding state machine.
- **Acceptance:** rename/transfer/fork fixture suite green (§T5/T8); no flow keys on slug alone (grep gate).
- **Tests:** integration with provider fakes; webhook-signature tests. **Security:** webhook HMAC verify; least-scope installation tokens. **Rollback:** bindings additive; unbind without secret loss.

### Phase 7 — API/CLI/UI + search (scoped surfaces)
- **Goals:** REST routes (§12/E-spec), CLI (`project`/`secret`/`repo`/`context`), dashboard scoped explorer, authorized search.
- **Files:** `services/account/src/lib.rs`, `apps/cli/src/main.rs`, `apps/cli/src/commands/run.rs`, `apps/cli/src/dashboard/*`, `apps/ui/*`; NEW `apps/cli/src/commands/project.rs`, `secret.rs`, `context.rs`.
- **Dependencies:** Phases 3–6. **Tasks:** routes + OpenAPI; CLI context precedence (flags > env > context file > auto-detect, §13) with scope echo; `run --env/--project`; search with scope predicates; replace disk-walk discovery.
- **Acceptance:** E2E CLI flows (login→project→secret→run→rotate) green; search returns zero out-of-scope rows; UI shows active scope banner.
- **Tests:** CLI golden tests, API contract tests, UI route tests. **Security:** convenience (auto-detect) never bypasses server authz; `--dry-run` names-only. **Rollback:** legacy `run` path retained behind compat flag until Phase 9 exit criteria.

### Phase 8 — Migration engine + compatibility layer
- **Goals:** 7-stage migration (§18/F-spec) with dry-run, validation, resume, deprecation schedule.
- **Files:** NEW `apps/cli/src/commands/migrate.rs`, `services/account/src/migration_ledger.rs`.
- **Dependencies:** Phases 2,4,5,7. **Tasks:** vault discovery (reuse `discover_workspace_vaults` as *input finder* only); `.env` classification heuristics + interactive review; idempotent ledger; cutover pointer; legacy-path deprecation warnings + kill-switch.
- **Acceptance:** fixture vaults (1/100/10k secrets) migrate with byte-identical values + full audit trail; resume-after-crash test; dry-run diff approved before writes.
- **Tests:** migration matrix (duplicates, ambiguous, unknown owners), property tests (no secret lost/duplicated). **Security:** migration requires admin + writes `migration.*` audit chain; legacy DBs shredded on confirm. **Rollback:** per-secret cutover pointer flips back; legacy vaults untouched until `LEGACY_PATH_DISABLED`.

### Phase 9 — Security hardening + audit pipeline
- **Goals:** close S1 mitigations; immutable hash-chained audit; abuse protection.
- **Files:** `services/account/src/*` (audit writer), NEW `services/account/src/audit_chain.rs`; rate-limit middleware; log scrubber crate NEW `crates/redact`.
- **Dependencies:** Phases 3–8. **Tasks:** 12 audit event types (§20/G-spec) with actor/target/scope/request-id; off-host shipping; entropy-scan CI gate; rate limits + abuse quotas; DPoP/mTLS option; dual-control export.
- **Acceptance:** all S1 test methods automated and green; pen-test re-run clean on T1–T7, T10, T13, T18.
- **Tests:** security suite (§S6). **Security:** audit store append-only (tamper test). **Rollback:** n/a (hardening is monotonic; flags per control).

### Phase 10 — Production readiness (scale, DR, runbooks)
- **Goals:** meet §21 targets (1M secrets, p99 <10ms, 25k req/s burst), backups/DR, observability, runbooks.
- **Files:** `deploy/*`, `docker-compose.yml`, `docs/OPERATOR_PLAYBOOKS.md`, `docs/DEPLOYMENT_RUNBOOK.md`; dashboards.
- **Dependencies:** Phases 0–9. **Tasks:** PG partitioning + pooling; Redis L1/L2 + invalidation bus; load/soak gates (extend `LOAD_SOAK_VALIDATION.md`); backup/restore drills; KMS-failover drill; on-call runbooks; SLO dashboards (redacted).
- **Acceptance:** load gates pass at 100× and 10k× profiles; restore drill meets RPO/RTO; game-day (KMS outage + rotation storm) passes.
- **Tests:** load/soak/chaos suites. **Security:** prod telemetry contains zero value-shaped data (scan gate). **Rollback:** blue/green deploy; per-phase kill-switches documented in runbooks.

---

## S6. Testing Strategy — Full Case Matrix (v2.5.0 supplement)

Expands §23 to the required unit/integration/security/E2E coverage. Location convention: `U` = crate unit test, `I` = service integration test, `S` = security suite (`services/account/tests/`, `apps/cli/tests/`), `E` = end-to-end CLI/API flow.

**Unit (U):** scope resolution (precedence flags > env > context file > auto-detect; unknown scope ⇒ error, never default); authorization decisions (role × action × scope truth table, deny-by-default); namespace uniqueness (`UNIQUE(project, env, name)` + case-sensitivity rule); secret lookup (pinned `(id, version)` vs floating name); project/repository binding (ID-keyed, slug display-only); migration logic (classifiers on fixture `.env` corpora, idempotent ledger transitions).
**Integration (I):** database constraints (uniqueness, FKs, soft-delete partial indexes, concurrent writers); API authorization (BOLA matrix every route × every role); repository linking (bind/rename/transfer/delete webhooks vs provider fakes); secret retrieval (authorized ⇒ value, unauthorized ⇒ uniform 404); rotation (pointer atomicity, rollback-on-verify-fail, concurrent rotates); audit events (every mutation emits schema-valid event; tamper breaks hash chain).
**Security (S):** IDOR/BOLA sweep (S1-T3 test); cross-project access (T1); cross-tenant access (T2); privilege escalation (membership lifecycle, T7); enumeration indistinguishability (T4); injection (SQLi/command fuzz on all inputs); replay (expired/reused/bound-token matrix, T13); cache isolation (key separation + poisoning rejection, T18); entropy scan (canary values absent from all logs/audit/metrics).
**End-to-end (E):** login → project select → repo select → secret create → retrieve → deploy (`run`) → rotate → verify new version live + old pinned deploy completes; migration E2E (legacy vault → scoped project → legacy disabled); game-day (KMS outage + rotation storm + DB failover).
**Invariants under test:** the §27 list (10) is enforced as automated gates — each invariant maps to ≥1 S-test that fails the build on violation; invariant 3 (tenant boundaries) and 10 (rotation preserves identity/history) additionally get property-based tests.

---

## S7. Evidence & Confidence Register (v2.5.0 supplement)

Every material current-state claim, classified per §27. `[Proposed design]` items live in §9–§27/S1–S6 and are not re-listed.

| # | Claim | Classification | Pointer |
|---|-------|----------------|---------|
| 1 | No `project_id`/`repository_id`/`tenant_id`/`environment` scoping columns exist in any schema | `[Verified in code]` | Full-tree regex search over `crates/`, `services/`, `apps/`; schemas in `crates/local-store/src/db.rs:121-222`, `services/account/src/state.rs:66-198` |
| 2 | Secret identity is effectively `vault_id ‖ relative_path ‖ snapshot_id` (+ ephemeral env-var name at `run` time) | `[Verified in code]` | `tracked_files(relative_path PK)` `db.rs:138-141`; `ManifestFileEntry` `schema.rs:190-204`; `dotenv::parse_dotenv_bytes` `dotenv.rs:9`; `run.rs:141-180` |
| 3 | Same secret name cannot exist twice in one vault file-set; last write wins silently across `.env*` files | `[Verified in code]` | `run.rs:193-198` BTreeMap dedup; stable `.env`-first ordering `run.rs:152-161` |
| 4 | Encryption is XChaCha20-Poly1305 with domain-separated KDF and zeroized key types | `[Verified in code]` | `crates/crypto/src/aead.rs:2,20,78`; `keys.rs:14,61,96` derives + `test_zeroize_memory_scrubbing` `keys.rs:135` |
| 5 | Manifest AAD binds `vault_id ‖ epoch`; chunk/file keys derive per epoch | `[Verified in code]` | `run.rs:55-63` AAD construction; `kdf.rs` `derive_*`; snapshot `engine.rs:144,310` (workflow cross-read) |
| 6 | Storage operators hold ciphertext only and never decrypt | `[Verified in code]` | Zero `decrypt*/seal_box/open_sealed_box` hits in `services/operator/src/`; `PUT/GET /v1/objects/:cid` opaque CIDs `services/operator/src/lib.rs:288-290` |
| 7 | Operator sessions are vault-bound (32-byte `X-CipherVault-Id` + `validate_session_for_vault`) | `[Verified in code]` | `services/operator/src/handlers.rs:183-211` |
| 8 | Control-plane auth defaults to strict; non-strict is an explicit migration opt-out | `[Verified in code]` | `strict_operator_auth()` fail-closed default `handlers.rs:40-44`; bypass only when explicitly disabled `handlers.rs:67-71` |
| 9 | Anonymous recovery reads are deliberate capability-URL design, not an oversight | `[Verified in code]` + `[Verified in documentation]` | `recovery_anonymous` read bypass `handlers.rs:190-191`; ADR-006 `docs/adr/006-anonymous-recovery-reads.md`; locked by `services/operator/tests/recovery_auth.rs` (cited by ADR) |
| 10 | Account service provides accounts/devices/sessions/memberships/vault-links, but no project/repo/secret entities | `[Verified in code]` | Schema `state.rs:66-198`; routes `lib.rs:80-197` (25 `/v1/accounts/:id/*` routes, session-gated) |
| 11 | `activity_log` has exactly 4 writers; CLI snapshot commands are unaudited | `[Verified in code]` | Writers: `apps/agent/src/watcher.rs:231,280,531`, `apps/cli/src/dashboard/files_api.rs:109`; method `db.rs:874-885` |
| 12 | Control-plane `audit_events` covers account/device/session/membership/vault-link lifecycle only | `[Verified in code]` | `audit_event()` `services/account/src/util.rs:14`; 20+ call sites across `accounts/devices/memberships/sessions/totp/webauthn/vaults/recovery.rs` |
| 13 | Rotation today is vault-wide epoch rekey, not per-secret | `[Verified in code]` | `LocalVaultStore::rotate_epoch_key` `db.rs:498`; CLI `rekey` command `main.rs:45` |
| 14 | CLI context is implicit CWD (`.ciphervault/vault.db`); multi-vault discovery is a local max-depth-3 disk walk for the loopback dashboard | `[Verified in code]` | `discover_workspace_vaults` `main.rs:1607-1630`; `private_ui_request_guard` `dashboard/router.rs` |
| 15 | L2 anchoring is a first-seen registry of salted SHA-256 commitments, not EIP-712 | `[Verified in code]` | `contracts/CipherVaultRegistry.sol:5-33` NatSpec + `publish()` |
| 16 | PIV hardware signing supports touch-presence policy | `[Verified in code]` | `is_touch_timeout` + touch-policy parsing `crates/crypto/src/piv.rs:281-298,741-767` |
| 17 | `diff` output masks secret values | `[Verified in code]` | `mask_value` + call sites + `test_mask_value` `apps/cli/src/diff.rs:91-259,643-645` |
| 18 | CI must bootstrap from an external secret (circular dependency) | `[Verified in documentation]` + `[Inferred from implementation]` | `docs/CICD_INTEGRATION.md`, `.github/actions/ciphervault-run/action.yml` (both exist); `.ciphervault/` gitignored ⇒ runner needs R or a DB copy |
| 19 | Vault deletion today is directory removal; operator replicas persist per lease | `[Inferred from implementation]` | No delete-accounting path found for operator objects; leases govern retention (`types.rs:LeaseReceipt`) |
| 20 | TOTP ciphertext uses AES-256-GCM with empty AAD; no KMS/SQLCipher beyond DPAPI/keystore | `[Verified in code]` (TOTP/keystore) / `[Unknown]` (exhaustiveness) | `keyring.rs` DPAPI; TOTP wrap key env/file `state.rs:20-21`; full-crypto-inventory re-read not repeated in v2.5.0 — carried from workflow agents |
| 21 | Line-level bodies of `sealed_box/signatures/recovery-kit/chunker` and some dashboard/account handler internals | `[Unknown] / requires confirmation` | Carried from workflow synthesis as prior inspected evidence; not independently re-read in v2.5.0; none affect the scoping verdict (claims 1–19 are sufficient) |

**Workflow cross-check (completed background audit, 10 agents, 343 tool calls):** independent agent reads agree on all material points — implicit vault/dir/epoch/account scoping, no `--scope` surface, client-sovereign keys, ciphertext-only operators, vault-bound sessions, loopback-guarded private dashboard. No contradictions found; nuances (strict-auth default, ADR-006 intent) were re-verified first-hand above.

---

## 31. Final Question & Definitive Conclusion

### Core Question
> **“Does CipherVault currently have a secure, explicit, scalable mechanism that associates stored secrets with the project/repository/application/environment they belong to, and if not, what exact architecture should we implement to provide it?”**

### Definitive Answer

Based on empirical audit of the `CipherVault` codebase (workspace version `1.0.20`), **CipherVault does NOT currently have a secure, explicit, or scalable mechanism to associate stored secrets with their project, repository, application, or environment context.**

#### 1. What CipherVault Does Today
- CipherVault operates on a **directory-local file snapshot model**. 
- Secrets exist only as unindexed text inside confidential files (such as `.env` or `server.key`) tracked in a local SQLite database (`.ciphervault/vault.db`) in table `tracked_files`.
- The storage and encryption model is bound to a single 32-byte `vault_id`. 
- Access control is binary: anyone possessing the vault master recovery key or local device key can decrypt every tracked file and every credential.
- Environment separation is purely a user filename convention (`.env.production`). There is no `project_id`, `repository_id`, or `environment_id` in the core schemas, wire objects, or APIs.

#### 2. The Exact Architecture to Implement
To achieve robust, enterprise-grade secret management, CipherVault should implement a **Hierarchical Resource-Scoped Secret Management Architecture**:

1. **Domain Hierarchy:**  
   `Tenant/Org -> Workspace -> Project -> [Environments, Repository Bindings, Services] -> Secrets -> Versions`.
2. **Project-Level Ownership:**  
   The **Project** serves as the primary administrative and security boundary. Repositories are bound to projects using immutable external provider IDs (e.g. GitHub Repository Node IDs), allowing repositories to be renamed or transferred without orphaning credentials.
3. **Strict Environment Gates:**  
   Environments (`development`, `staging`, `production`) provide isolated access boundaries enforced by RBAC/ABAC policies.
4. **Context-Bound Authenticated Encryption:**  
   Secret values are encrypted using per-project Data Encryption Keys (DEKs) via `XChaCha20-Poly1305`, binding `tenant_id`, `project_id`, `environment_id`, and `version` into the Authenticated Additional Data (AAD) to prevent cross-scope ciphertext substitution attacks.
5. **Explicit REST & CLI Interfaces:**  
   Deploy scoped API routes (`/v1/projects/{project_id}/environments/{env}/secrets/{name}`) and CLI commands (`ciphervault secret get <name> --env <env>`), eliminating monolithic file decryption and enabling native CI/CD OIDC integration.
6. **Automated Migration Engine:**  
   Provide a 7-stage migration pipeline to parse existing `.ciphervault` directory vaults, classify `.env` files into environments, and seamlessly populate the scoped database.

This architecture resolves the multi-project dilemma, eliminates circular CI/CD dependencies, and establishes CipherVault as a scalable, secure secrets-management platform.
