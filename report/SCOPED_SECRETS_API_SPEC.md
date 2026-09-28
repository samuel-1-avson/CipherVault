# Deliverable E — API Specification: Scoped Secrets (REST)

**Version:** 2.5.0 · **Date:** 2026-09-27 · **Parent report:** [SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md](./SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md) (§12, §24)

All content below is `[Proposed design]`. All tokens, values, and connection strings are synthetic placeholders. Value-bearing responses require TLS 1.2+.

## 1. Transport decision

**REST + JSON** for all human/CI surfaces (matches existing Axum services: `services/operator`, `services/account`), OpenAPI 3.1 published from code. **gRPC optional later** for high-throughput internal decrypt fan-out only — not required for correctness; REST keeps the audit/policy choke point single and reviewable.

## 2. Conventions

- Base: `/v1/projects/{project_id}`. Auth: `Authorization: Bearer <scoped-token>`; tokens embed `(tenant, project, env?, repo_binding?, service?, expires)` in signed claims, verified server-side on every request.
- Scope rule: path scope must equal token scope (or be narrower); mismatch ⇒ `403`. Missing-or-forbidden resources ⇒ uniform `404 {code:"NOT_FOUND"}` (no existence oracle).
- Errors: `{code, error, request_id}`; never include values. `409 SECRET_NAME_CONFLICT`, `423 SCOPE_SUSPENDED`, `429 RATE_LIMITED`.
- Pagination: `?limit=` (default 50, max 500) + opaque `page_token`. List/search responses are metadata-only (never values).

## 3. Endpoints

### Secrets

```http
POST /v1/projects/{project_id}/environments/{env}/secrets
{ "name":"DATABASE_URL", "secret_type":"connection_string",
  "description":"Primary Postgres (synthetic example)",
  "value":"postgres://user:REDACTED@example.invalid:5432/db",
  "tags":["database"], "repository_binding_id":null, "service_id":null }
→ 201 { "secret_id":"…", "version":1, "status":"active", "created_at_utc":… }

GET /v1/projects/{project_id}/environments/{env}/secrets/{name}
→ 200 { "secret_id":"…", "name":"…", "version":3, "value":"<plaintext over TLS>",
        "expires_at_utc":null, "last_rotated_at_utc":… }

GET /v1/projects/{project_id}/secrets?environment=production&tag=database&status=active
→ 200 { "total":1, "secrets":[{ "secret_id":"…", "name":"…", "current_version":3,
        "status":"active", "updated_at_utc":… }], "next_page_token":"…" }

GET /v1/projects/{project_id}/secrets?environment=staging&q=stripe
→ 200 { metadata-only matches } — authorized search (§19, T-703): `q` is a
  case-insensitive name substring (max 128 chars, `400 INVALID_SECRET_REQUEST`
  beyond) applied as DB-level `LIKE` *after* scope authorization, so search
  never widens scope and returns zero out-of-scope rows. `LIKE` wildcards in
  `q` match literally. Surfaced by `ciphervault secret find <query>` and the
  dashboard `GET /api/scoped/secrets?project=&environment=&q=` explorer proxy
  (private loopback router; refs normalized, upstream is the operator account
  service via `CIPHERVAULT_ACCOUNT_ENDPOINT` + `CIPHERVAULT_SCOPE_TOKEN`).

PATCH /v1/projects/{project_id}/secrets/{secret_id}        # metadata only (never value)
{ "description":"…", "tags":[…], "expires_at_utc":… } → 200 (metadata echo)

POST /v1/projects/{project_id}/secrets/{secret_id}/rotate
{ "new_value":"<REDACTED>", "idempotency_key":"…", "reason":"scheduled" }
→ 200 { "secret_id":"…", "previous_version":3, "current_version":4, "rotated_at_utc":… }

POST /v1/projects/{project_id}/secrets/{secret_id}/move     # rename or re-scope (privileged)
{ "new_name":"…", "new_environment_id":"…", "reason":"…" } → 200 + audit secret.moved

POST /v1/projects/{project_id}/secrets/{secret_id}/rebind   # repo/service (un)binding
{ "repository_binding_id":"…|null", "service_id":"…|null", "reason":"…" }
→ 200 + audit secret.rebound

DELETE /v1/projects/{project_id}/secrets/{secret_id}?reason=…
→ 202 { "status":"scheduled_deletion", "purge_after_utc":… }  # soft-delete, then shred
```

### Repository bindings

```http
POST /v1/projects/{project_id}/repositories
{ "provider":"github", "external_repo_id":"84920194",
  "installation_token":"<REDACTED>" }
→ 201 { "binding_id":"…", "repo_full_name":"acme/payments (display only)", "status":"active" }

GET /v1/projects/{project_id}/repositories → 200 { "bindings":[…] }
DELETE /v1/projects/{project_id}/repositories/{binding_id} → 202 (suspend; secrets kept)
```

### Search

```http
GET /v1/search?project_id=…&environment=…&repository_binding_id=…&service_id=…
    &q=name-fragment&tag=…&owner=…&status=…&rotated_before=…
→ 200 metadata-only hits, scope-predicated; zero rows outside the caller's grants.
```

### OIDC login (CI)

```http
POST /v1/auth/oidc/login
{ "id_token":"<REDACTED>", "target_env":"production" }
→ 200 { "token":"<REDACTED>", "expires_in":900,
        "scope":{ "project_id":"…", "environment":"production",
                  "repository_binding_id":"…", "job_workflow_ref":"…" } }
```

## 4. Authorization matrix (abridged)

| Action | Admin | Developer | Operator | Auditor | Workload/OIDC |
|---|---|---|---|---|---|
| read secret value (granted env) | ● | ● | ● | ○ (metadata only) | ● (own scope) |
| create/update metadata | ● | ● | ○ | ○ | ○ |
| rotate | ● | ● (non-prod) / dual (prod) | ● (break-glass) | ○ | ○ |
| move/rebind/purge | ● (dual-control) | ○ | ○ | ○ | ○ |
| manage bindings/members | ● | ○ | ○ | ○ | ○ |

Deny-by-default; policy-parse failure ⇒ deny; every decision logged with request ID.

## 5. Rate limits and idempotency

- Reads: 1k/min/principal/project (burst 2k); rotates: 60/min/project; login: 30/min/IP + 5-failure lockout (extends existing `AUTH_RATE_*`, `state.rs:24-27`).
- Mutations accept `idempotency_key` (24h window); replay returns the original outcome byte-identically.
