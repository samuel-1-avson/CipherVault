# Deliverable D — Database Specification: Scoped Secrets

**Version:** 2.5.0 · **Date:** 2026-09-27 · **Parent report:** [SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md](./SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md) (§11, S5-Phase 2)

All content below is `[Proposed design]`. Extends — never breaks — the existing schemas (`services/account/src/state.rs`, `crates/local-store/src/db.rs`).

## 1. Minimum viable vs long-term model

- **MVP (6 tables):** `projects`, `environments`, `secrets`, `secret_versions`, `encryption_keys`, `secret_access_events`. Sufficient for single-workspace scoped CRUD + rotation + audit.
- **Long-term (+6 tables):** add `organizations`, `workspaces`, `repository_bindings`, `services`, `secret_access_policies`, `secret_principals`, `secret_rotation_jobs` (13 total with existing account tables reused for humans/devices/sessions). Tenancy, VCS, services, policy, and automation attach without re-keying secrets.

## 2. Core DDL (Postgres dialect; SQLite-compatible subset noted)

```sql
CREATE TABLE organizations (
    tenant_id        UUID PRIMARY KEY,
    name             TEXT NOT NULL,
    created_at_utc   BIGINT NOT NULL
);
CREATE TABLE workspaces (
    workspace_id     UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES organizations(tenant_id) ON DELETE RESTRICT,
    name             TEXT NOT NULL,
    created_at_utc   BIGINT NOT NULL,
    UNIQUE (tenant_id, name)
);
CREATE TABLE projects (
    project_id       UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES organizations(tenant_id) ON DELETE RESTRICT,
    workspace_id     UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE RESTRICT,
    slug             TEXT NOT NULL,               -- human handle, quarantined on delete
    name             TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',  -- active | scheduled_deletion | purged
    created_at_utc   BIGINT NOT NULL,
    deleted_at_utc   BIGINT,
    UNIQUE (tenant_id, slug)
);
CREATE TABLE environments (
    environment_id   UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    project_id       UUID NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    slug             TEXT NOT NULL,               -- development | staging | production | custom
    tier             INT  NOT NULL DEFAULT 0,     -- 0 dev … 2 prod (ordering, not authority)
    created_at_utc   BIGINT NOT NULL,
    deleted_at_utc   BIGINT,
    UNIQUE (project_id, slug),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, project_id)
);
CREATE TABLE repository_bindings (
    binding_id       UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    project_id       UUID NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    provider         TEXT NOT NULL,               -- github | gitlab | bitbucket | self_hosted
    external_repo_id TEXT NOT NULL,               -- immutable provider ID (durable identity)
    repo_full_name   TEXT NOT NULL,               -- display only
    repo_url         TEXT NOT NULL,               -- display only
    installation_id  TEXT,
    status           TEXT NOT NULL DEFAULT 'active',  -- active | suspended | revoked
    created_at_utc   BIGINT NOT NULL,
    UNIQUE (project_id, provider, external_repo_id)
);
CREATE TABLE services (
    service_id       UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    project_id       UUID NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    slug             TEXT NOT NULL,
    created_at_utc   BIGINT NOT NULL,
    UNIQUE (project_id, slug)
);
CREATE TABLE secrets (
    secret_id        UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    project_id       UUID NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    environment_id   UUID NOT NULL REFERENCES environments(environment_id) ON DELETE RESTRICT,
    repository_binding_id UUID REFERENCES repository_bindings(binding_id) ON DELETE SET NULL,
    service_id       UUID REFERENCES services(service_id) ON DELETE SET NULL,
    name             TEXT NOT NULL,
    secret_type      TEXT NOT NULL DEFAULT 'key_value',
    description      TEXT NOT NULL DEFAULT '',
    tags             JSONB NOT NULL DEFAULT '[]',
    status           TEXT NOT NULL DEFAULT 'active',
    policy_id        UUID,                          -- → secret_access_policies (nullable = inherit)
    current_version  INT  NOT NULL DEFAULT 1,
    created_by       TEXT NOT NULL,
    created_at_utc   BIGINT NOT NULL,
    updated_at_utc   BIGINT NOT NULL,
    last_rotated_at_utc BIGINT,
    expires_at_utc   BIGINT,
    last_accessed_at_utc BIGINT,
    deleted_at_utc   BIGINT,
    UNIQUE (project_id, environment_id, name)      -- THE uniqueness rule (see §4)
);
CREATE TABLE secret_versions (
    version_id       UUID PRIMARY KEY,
    secret_id        UUID NOT NULL REFERENCES secrets(secret_id) ON DELETE RESTRICT,
    version          INT  NOT NULL,                -- append-only monotonic per secret
    encryption_key_id UUID NOT NULL REFERENCES encryption_keys(key_id) ON DELETE RESTRICT,
    nonce            BYTEA NOT NULL,              -- 24-byte XChaCha nonce
    ciphertext       BYTEA NOT NULL,              -- includes 16-byte Poly1305 tag
    value_sha256     BYTEA NOT NULL,              -- digest for audit/dedup, never the value
    created_by       TEXT NOT NULL,
    created_at_utc   BIGINT NOT NULL,
    UNIQUE (secret_id, version)
);
CREATE TABLE encryption_keys (
    key_id           UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    project_id       UUID REFERENCES projects(project_id) ON DELETE RESTRICT, -- NULL = tenant KEK
    purpose          TEXT NOT NULL,               -- tenant_kek | project_kek | dek_wrapping
    wrapped_key      BYTEA NOT NULL,              -- KMS-wrapped; raw keys NEVER stored here
    status           TEXT NOT NULL DEFAULT 'active',
    created_at_utc   BIGINT NOT NULL,
    destroyed_at_utc BIGINT                        -- crypto-shredding marker
);
CREATE TABLE secret_access_policies (
    policy_id        UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    project_id       UUID REFERENCES projects(project_id) ON DELETE CASCADE, -- NULL = tenant-wide
    name             TEXT NOT NULL,
    rules            JSONB NOT NULL,              -- RBAC grants + ABAC predicates (schema-validated)
    created_at_utc   BIGINT NOT NULL
);
CREATE TABLE secret_principals (                  -- humans (→ accounts), workloads, CI identities
    principal_id     TEXT PRIMARY KEY,            -- e.g. account:<id> | oidc:<iss>:<sub> | service:<uuid>
    tenant_id        UUID NOT NULL,
    kind             TEXT NOT NULL,
    display_name     TEXT NOT NULL,
    revoked_at_utc   BIGINT
);
CREATE TABLE secret_rotation_jobs (
    job_id           UUID PRIMARY KEY,
    secret_id        UUID NOT NULL REFERENCES secrets(secret_id) ON DELETE CASCADE,
    state            TEXT NOT NULL,               -- pending|running|verifying|committed|rolled_back
    idempotency_key  TEXT NOT NULL,
    reason           TEXT NOT NULL,
    created_at_utc   BIGINT NOT NULL,
    updated_at_utc   BIGINT NOT NULL,
    UNIQUE (secret_id, idempotency_key)
);
CREATE TABLE secret_access_events (               -- append-only; no UPDATE/DELETE grants
    event_id         UUID PRIMARY KEY,
    event_type       TEXT NOT NULL,               -- secret.created|read|updated|rotated|deleted|restored|moved|rebound|…
    tenant_id        UUID NOT NULL,
    project_id       UUID,
    environment_id   UUID,
    secret_id        UUID,
    secret_version   INT,
    actor            JSONB NOT NULL,              -- {principal_type, principal_id, ip, user_agent}
    request_id       TEXT NOT NULL,
    source           TEXT NOT NULL,               -- api | cli | ci | migration | system
    result           TEXT NOT NULL,               -- success | denied | error
    reason           TEXT NOT NULL DEFAULT '',
    prev_hash        BYTEA NOT NULL,              -- hash chain link
    event_hash       BYTEA NOT NULL,
    created_at_utc   BIGINT NOT NULL
);
```

## 3. Indexes, tenancy, soft-delete, cascades

- **Indexes:** `secrets(project_id, environment_id, name)` (unique, §4); `secrets(tenant_id, updated_at)`; `secret_versions(secret_id, version DESC)`; `secret_access_events(tenant_id, created_at DESC)`, `(secret_id, created_at DESC)`; `repository_bindings(provider, external_repo_id)`; partial `WHERE deleted_at_utc IS NULL` on lookup indexes.
- **Tenancy:** `tenant_id` leads every tenant-owned table; composite FKs `(tenant_id, project_id)` prevent cross-tenant parenting; Postgres RLS policies `tenant_id = current_setting('app.tenant')` defense-in-depth.
- **Soft-delete:** `deleted_at_utc` on projects/envs/secrets; purge only after retention + crypto-shredding; unique indexes exclude deleted rows (partial) except slug quarantine table (not shown).
- **Cascades:** metadata cascades (`bindings`, `services`, `policies`); secret payloads `RESTRICT` (explicit shred workflow, never silent loss); events never cascade (retain post-purge with tombstoned scope refs).

## 4. Uniqueness: `(project, env, name)` vs `(project, repo, env, name)`

**Chosen: `UNIQUE(project_id, environment_id, name)`.** Repo-in-identity (the alternative) forces duplication of every secret shared across a project's repos, turns repo splits into secret migrations, and breaks secret references on rename. Confinement is a *policy attachment* (`repository_binding_id`, nullable) evaluated at authorization time — strictly more expressive with a simpler identity. Same-name reuse across projects/envs is therefore safe by construction.

## 5. Concurrency and transactions

- Rotate: `SELECT … FOR UPDATE` on `secrets` row → insert `secret_versions` → verify liveness → bump `current_version` → emit event, all in one transaction; concurrent rotates serialize; idempotency keys dedup retries.
- Reads are lock-free (MVCC snapshot + pinned version); name→id resolution and version fetch in a single `REPEATABLE READ` transaction to avoid pointer-tearing mid-rotation.
- SQLite (local/dev): same DDL minus RLS/`JSONB` (use `JSON`); `PRAGMA foreign_keys=ON`; busy-handler retry already exists (`db.rs:33-46`).
