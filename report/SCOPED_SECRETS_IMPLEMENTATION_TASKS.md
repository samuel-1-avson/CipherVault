# Deliverable H — Implementation Task Breakdown (mapped to repository paths)

**Version:** 2.5.0 · **Date:** 2026-09-27 · **Parent report:** [SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md](./SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md) (§25, §26, S5)

All `EXISTS` paths verified in the worktree; `NEW` files are to be created. Phase mapping: S5.

## Domain model (Phase 1)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-101 Scope types + validators ✅ DONE | `crates/format/src/schema.rs` (EXISTS), NEW `crates/format/src/scope.rs` | Add Tenant/Workspace/Project/Environment/Binding/Service/Secret/Version structs, UUIDv7 IDs, slug/name validation | High | Unit round-trip + validation |
| T-102 `SecretValue` redacted type ✅ DONE | NEW `crates/format/src/secret_value.rs` | Byte wrapper, redacted `Debug`, no `Display`/`Serialize`, `ZeroizeOnDrop` | Medium | Compile-fail print test |

## Database (Phase 2)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-201 Control-plane DDL + migrations ✅ DONE | `services/account/src/state.rs` (EXISTS) | 13 tables per D-spec (SQLite port: single-col FKs, no RLS; deviations documented) | High | Migration up/down + constraint tests |
| T-202 Local-store v5 migration ✅ DONE | `crates/local-store/src/db.rs` (EXISTS) | `user_version` 4→5 (was already v4); `scoped_context`/`scoped_secret_cache`/`scoped_binding_cache`; `foreign_keys=ON` | High | Migration + concurrency tests (20/20 green) |

## Authorization (Phase 3)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-301 Policy engine ✅ DONE | NEW `services/account/src/policy.rs`; `services/account/src/guards.rs` (EXISTS) | RBAC+ABAC `authorize()` choke point; env gates; uniform 404 | High | Decision-table unit + BOLA matrix |
| T-302 Scope tokens ✅ DONE | NEW `services/account/src/scope_tokens.rs`; `services/account/src/sessions.rs` (EXISTS) | Signed claims `(tenant,project,env,repo,service,exp)`; jti denylist | High | Claim-tamper fuzz + replay matrix |
| T-303 Membership scoping ✅ DONE | `services/account/src/policy.rs` grant/revoke/lookup + NEW `grants.rs`/`grants_routes.rs` | Dual-admin grants (admin role via request + distinct-admin approve; self-approval 403) + invite lifecycle (single-use hashed codes, TTL, session-bound accept; no admin invites) | Medium | 9 grants units + HTTP lifecycle; 115/115 account; fmt/clippy clean |

## Secret service (Phase 4)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-401 CRUD + versions ✅ DONE | NEW `services/account/src/secrets.rs`, `versions.rs` | Create/get/list/metadata-patch/soft-delete; pinned reads | High | Lifecycle integration |
| T-402 Rotation jobs ✅ DONE | NEW `services/account/src/rotation_jobs.rs` | Row-locked rotate; idempotency; liveness verify; rollback | High | Race + kill-mid-rotate tests |
| T-403 Routes ✅ DONE | NEW `services/account/src/secret_routes.rs` (13 routes); `lib.rs` mounts; OIDC mint session-only | CRUD/move/rebind/rotate/members/tokens; BOLA matrix; token-exchange denied; prod-gate enforced | Medium | HTTP lifecycle + BOLA 8-route + auth-failure + roles + mint/revoke tests (48/48 lib green) |

## Cryptography (Phase 5)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-501 Scoped AAD ✅ DONE | `crates/crypto/src/aead.rs`, `kdf.rs` (EXISTS) | AAD builder `tenant‖project‖env‖secret‖version`; cross-scope negative tests | High | KAT + tamper vectors |
| T-502 Envelope keys 🟡 PARTIAL | `crates/crypto/src/keys.rs`, `hsm.rs` (EXISTS) | DEK type + seal/open + wrap/unwrap + `KeyWrappingService` trait + local KEK ✅; KMS providers + HSM + re-wrap jobs pending (need new deps) | High | KMS-stub + HSM-sim integration |

## Repository integration (Phase 6)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-601 VCS bindings ✅ DONE | NEW `vcs.rs` (provider IDs, state machine, bind/prove, webhooks) + `reconcile.rs` (probe, fakes) + 6 binding routes; `scoped.rs` ownership/reconcile columns; secrets active-gate | Suspended denies grants, break-glass reads kept; HMAC webhooks (no oracle); revoked terminal | Medium | 11 vcs + 6 reconcile + 2 HTTP tests (67/67 lib green); fmt/clippy clean |
| T-602 CLI `repo` ✅ DONE | NEW `commands/repo.rs` + `RepoSubcommand`; `mod.rs`/`main.rs` wired; `tests/repo_commands.rs` stub-server goldens | `bind/list/unbind` (--binding or --provider/--repo-id resolve; --revoke; endpoint/token flag→env→store) | Low | 6/6 goldens green (request shape + byte-stable output); 156/156 CLI units; fmt/clippy clean |

## API/CLI/UI (Phase 7)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-701 CLI `project`/`secret`/`context` ✅ DONE | NEW `apps/cli/src/commands/project.rs`, `secret.rs`, `context.rs`, `scope.rs`; `services/account/src/projects.rs` (NEW); `main.rs` + `repo.rs` (EXISTS) | Scoped CRUD; context precedence + scope echo; `GET /v1/projects[/:ref]` | Medium | CLI E2E: 6/6 repo + 6/6 scope goldens, 160/160 CLI units, 71/71 account |
| T-702 `run` scoping ✅ DONE | `apps/cli/src/commands/run.rs` (EXISTS); `main.rs` Run flags; NEW `apps/cli/tests/run_scoped.rs` | `--project/--env/--endpoint/--token`; scoped fetch (list+values, 500 fail-closed); names+versions dry-run; snapshot/scoped conflict error | Medium | 6/6 run goldens (inject/override/denial/conflict/env-mode/dry-run); legacy dispatch smoked |
| T-703 Dashboard + UI ✅ DONE | NEW `apps/cli/src/dashboard/scoped_api.rs`; `router.rs` + `secret find` + `apps/ui/*` (EXISTS); `q` filter in `services/account` | Scoped explorer proxy (`/api/scoped/context|projects|secrets`, loopback+session guarded, ref-normalized); scope banner (ok/unconfigured/unavailable); DB-level authorized search (`secret find`, metadata-only) | Medium | 73/73 account; 164/164 CLI bin (4 new); 7/7 scope goldens; node audit green; zero out-of-scope rows proven |

## Migration (Phase 8)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-801 Migration engine ✅ DONE | NEW `apps/cli/src/commands/migrate.rs`, `services/account/src/migration_ledger.rs` + `migration_routes.rs`; `scope.rs` MigrationId; `policy.rs` ManageMigrations | 7-stage ledgered migration (DISCOVERED→…→VERIFIED→LEGACY_PATH_DISABLED + QUARANTINED); 9 admin routes; digest-gated verify; abort rollback; CLI plan/apply/verify/resolve/shred-legacy; dotenv layering; prod ack gate; 409-adopt; `--legacy` deprecation | High | 8 ledger + 1 route-lifecycle + 82/82 account; 170/170 CLI bin; 6/6 migrate + 6/6 repo + 7/7 scope + 6/6 run goldens; fmt/clippy clean |

## Hardening + readiness (Phases 9–10)

| Task | Path | Change | Risk | Tests |
|------|------|--------|------|-------|
| T-901 Audit chain + scrubber ✅ DONE | NEW `services/account/src/audit_chain.rs`, `crates/redact`; `policy.rs` ViewAudit; `GET /v1/projects/:pid/audit/export` | 12 canonical types (typed, live at all sites) + extended passthrough; v2 full-row chain digest; verify-first fail-closed JSONL export (admin+auditor); append-only triggers; scrub-at-append; membership.revoked + token.minted + migration.* emissions | High | 8 audit_chain (taxonomy/verify/2 tamper/append-only/scrub/off-host/canary) + export HTTP lifecycle + redact 8 + 91/91 account; fmt/clippy clean |
| T-902 Abuse protection ✅ DONE | NEW `services/account/src/abuse.rs` + `dpop.rs`; `secret_routes.rs` (authenticate quotas, dual-control, mint binding); `scope_tokens.rs` cnf | Per-principal quotas (api 1000/60s + read-value/mint/export buckets, 429 + Retry-After, fail-closed 503); dual-control export (distinct ViewAudit step-up, bound tokens rejected); DPoP-lite opt-in (ed25519 cnf, single-use proofs, ±60s, replay cache); mTLS deferred (needs TLS dep) | Medium | 4 abuse + 6 dpop units + quota/dual-control/dpop/mint-bound HTTP tests; 104/104 account; fmt/clippy clean; + CLI DPoP follow-up ✅ DONE: NEW `apps/cli/src/commands/dpop.rs` (`CIPHERVAULT_DPOP_KEY` hex/`@path`, `maybe_dpop` wired into all 20 bearer sites + `api_get` choke point, dashboard proxy 500 `DPOP_KEY_INVALID` fail-closed) — 4 dpop units, 174/174 CLI bin, 25/25 scoped goldens, workspace fmt/clippy/test green |
| T-903 Scale + DR + runbooks ✅ DONE | NEW `deploy/systemd/ciphervault-account.service`; `docker-compose.yml` + `.env.example` key-file env; `OPERATOR_PLAYBOOKS.md` §13; `DEPLOYMENT_RUNBOOK.md` §20; `LOAD_SOAK_VALIDATION.md` load gate | SLOs + backup/restore drill (VACUUM INTO, RPO/RTO) + game-days + kill-switches; load gate (ignored): 574 reads/s release, p99 36ms, 0 busy; PG/Redis/KMS scale-out DESIGNED but deferred (needs new deps) | Medium | Backup roundtrip test + ignored load gate green (debug + release); 105/105 account; fmt/clippy clean |

## Dependency order

T-101/102 → T-201/202 + T-501/502 → T-301/302/303 → T-401/402/403 → T-601/602 → T-701/702/703 → T-801 → T-901/902/903. Critical path: T-101 → T-201 → T-301 → T-401 → T-402 → T-801.
