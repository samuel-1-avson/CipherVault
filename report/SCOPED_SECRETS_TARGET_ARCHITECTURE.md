# Deliverable C — Target Architecture Specification: Hierarchical Resource-Scoped Secrets

**Version:** 2.5.0 · **Date:** 2026-09-27 · **Parent report:** [SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md](./SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md) (§9, §10, §13–§15, §24; supplements S1–S5)

All content below is `[Proposed design]`. All example values are synthetic placeholders.

## 1. Resource hierarchy

```text
Tenant / Organization (tenant_id)
└── Workspace (workspace_id)
    └── Project (project_id)                      ← primary security + admin boundary
        ├── Repository bindings (provider, external_repo_id)   ← confinement, not ownership
        ├── Environments (development, staging, production)     ← strict isolation gates
        ├── Services / workloads (service_id)                  ← microservice confinement
        └── Secrets → Versions (ciphertext + metadata)
```

Design decision: the **project** owns secrets; repositories are **bound** to projects. Rationale: shared secrets (one database, three repos), monorepos (one repo, many services), and repo renames/transfers all break repo-as-owner, while project-as-owner handles them with zero secret migration (see S4: D4 rejected, D7 recommended).

## 2. Secret identity and naming

- **Durable identity:** `(tenant_id, project_id, environment_id, secret_id UUIDv7)`; human lookup key `(project_slug, environment_slug, name)` resolving to `secret_id`.
- **Uniqueness:** `UNIQUE(project_id, environment_id, name)` — same name safely reused across projects and environments; duplication inside one scope rejected with `409 SECRET_NAME_CONFLICT`.
- **Naming rules:** `^[A-Z][A-Z0-9_]{0,127}$` for env-style names (back-compat with `.env` parsers); display names free-form ≤256 chars; names are lookup keys with zero authorization authority (invariant 2).
- **Versions:** append-only monotonic integers; `current_version` pointer moved transactionally; rollback creates a new version, never rewinds.

## 3. Ownership and authorization boundaries

| Boundary | Enforced by | Rule |
|----------|-------------|------|
| Tenant | `tenant_id` predicate + RLS + per-tenant KEK | No query, token, or key crosses tenants |
| Project | `authorize(principal, tenant, project, …)` choke point | Roles: Admin, Developer, Operator, Auditor |
| Environment | Env-scoped token claims + gates | Dev grants confer zero prod rights; prod requires branch (`main`) + optional second approver |
| Repository | `repository_binding_id` confinement check | Repo-scoped token reads only unbound project secrets + secrets bound to its binding |
| Service | `service_id` confinement check | Workload identity reads only its service's secrets (+ explicitly shared) |

RBAC for coarse roles, ABAC for attributes (branch, IP/CIDR, hardware-token presence, time window). Authorization is server-side only; CLI context (flags > env vars > context file > git auto-detect) is a UX convenience that never bypasses it.

## 4. Environment model

Environments are first-class rows (`environment_id`, `project_id`, `slug`, `tier`), not filename suffixes. Default set per project: `development`, `staging`, `production`; custom envs allowed. Tokens embed `env` in signed claims, verified server-side. Deletion is soft (24h name quarantine); env-scoped tokens revoked immediately on delete.

## 5. Repository and service binding behavior

- **Bindings** store `(provider, external_repo_id, repo_full_name, repo_url, installation_id)`; identity = `(provider, external_repo_id)`; slug/URL are display-only and auto-updated on rename (§S2-E).
- Providers: GitHub (numeric repo ID), GitLab (project ID), Bitbucket (repo UUID), self-hosted (instance URL + project ID). Forks get distinct IDs ⇒ no inherited access. Transfers suspend the binding pending admin re-verification.
- **Services** represent workloads (API, worker, cron) with OIDC/mTLS identities; secrets may carry `service_id` for least-privilege confinement; unbound secrets are readable per project/env grants.

## 6. Storage, encryption, and retrieval

- **Metadata** (names, tags, versions, policies) in the control-plane DB, scope-predicated on every query.
- **Values** encrypted per version with unique DEKs under XChaCha20-Poly1305; AAD = `tenant_id ‖ project_id ‖ environment_id ‖ secret_id ‖ version` — cross-scope ciphertext replay fails MAC verification. Per-project KEKs wrap DEKs; per-tenant master keys at the root; KMS/HSM-backed, never stored beside ciphertext.
- **Retrieval:** `GET /v1/projects/{p}/environments/{e}/secrets/{name}` → authenticate → authorize → resolve → KMS-unwrap → decrypt + AAD verify → audit (`secret.read`, digest only) → return value over TLS. Operators keep storing opaque chunks only; the zero-knowledge storage plane is unchanged.
- **Caching:** ciphertext-only entries keyed `cv:sec:{tenant}:{project}:{env}:{secret_id}:{version}`; rotation advances the version so stale entries are unreachable.

## 7. Audit, search, and lifecycle

- **Audit:** 12 event types (secret created/read/updated/rotated/deleted/restored/moved/rebound, membership/permission/env changes, key rotation), each with actor/target/scope/timestamp/request-ID/source/result/reason; hash-chained, append-only, shipped off-host; never contains plaintext.
- **Search:** metadata-only (project/env/repo/service/name/tag/owner/status/last-rotation), always scope-predicated; global search across unauthorized scopes returns zero rows (no existence oracle).
- **Lifecycle:** create → version → rotate (identity-preserving) → deprecate → soft-delete → crypto-shred; every transition audited; migration from legacy vaults via the 7-stage ledger (§F-spec).

## 8. Non-goals

Replacing the zero-knowledge chunk store; turning operators into policy-aware servers; repo-name-keyed identity; plaintext caching; client-side authorization.
