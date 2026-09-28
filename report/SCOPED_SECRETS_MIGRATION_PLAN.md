# Deliverable F — Migration Plan: Legacy Vaults → Scoped Secrets

**Version:** 2.5.0 · **Date:** 2026-09-27 · **Parent report:** [SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md](./SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md) (§18, S2-B/F, S3-12)

All content below is `[Proposed design]`. Governing rule: **no secret is ever readable from both paths at once, and legacy vaults are untouched until `VERIFIED`.**

## 1. State machine (per secret; ledgered in `migration_ledger`)

```text
DISCOVERED → CLASSIFIED → MAPPED_TO_PROJECT → VALIDATED → MIGRATED → VERIFIED → LEGACY_PATH_DISABLED
     │             │               │               │            │           │               │
     └──── any failure ⇒ QUARANTINED (manual review) ──────────┴── resume is idempotent ──┘
```

## 2. Stage procedures

1. **Inventory/discovery:** reuse `discover_workspace_vaults` (`apps/cli/src/main.rs:1607`) as an *input finder only*; record `(vault_id, db_path, tracked_files[], snapshot_heads[])` per vault. Multiple vaults may map to one project (multi-dir) or many (monorepo split) — decided in stage 3.
2. **Classification:** parse tracked files (`.env*` via `dotenv` parser; PEM/cert/key files as opaque blobs). Heuristics: `.env.production`→production, `.env.staging`→staging, `.env.local`/`.env`→development (default, flagged `ambiguous` for review). Non-`.env` files become `file`-type secrets preserving `relative_path` as the name.
3. **Ownership assignment:** interactive `ciphervault migrate plan` maps each vault → `(tenant, workspace, project)`; each classified secret → `(environment, optional repo_binding, optional service)`. Unknown owners ⇒ `QUARANTINED` with reason; nothing auto-assigns production scope.
4. **Conflict handling:** duplicate names in one target scope ⇒ kept as separate `QUARANTINED` entries with source file/line provenance; operator picks winner or renames; losers migrate as `<name>__from_<file>` drafts for review, never silently dropped.
5. **Dry-run:** `ciphervault migrate --dry-run` emits a JSON diff (projects/envs/secrets/versions to create, AAD bindings, key wraps) with zero writes; requires explicit `--apply` + admin auth to proceed.
6. **Validation:** pre-write checks (uniqueness, name rules, scope existence, KMS reachability); post-write readback of every version (decrypt + compare digest to source bytes).
7. **Cutover:** per-secret pointer flip (legacy file line → scoped secret); dual-read window per secret ≤5 min with version pinning; then `VERIFIED`.
8. **Legacy disable:** per-secret `LEGACY_PATH_DISABLED` only after verification + retention window; vault DB shredded on explicit confirm (`--shred-legacy`, requires typed project slug + second admin for prod).

## 3. Loss-prevention guarantees

- Ledger records every secret's bytes-digest before/after; final gate asserts digest equality for 100% of non-quarantined secrets.
- Legacy DBs are opened read-only during migration; no in-place mutation until the shred step.
- Crash/resume: same `migration_id` + per-secret idempotency keys ⇒ re-running continues, never duplicates.
- Rollback: flip cutover pointers back; scoped rows soft-deleted (retained for forensics); legacy vaults intact.

## 4. Backward compatibility and deprecation

- Legacy `ciphervault run` (CWD vault) keeps working behind a compat flag emitting `LEGACY_PATH_DEPRECATED` warnings with a sunset date (≥2 minor versions).
- Dashboard disk-walk discovery is replaced by scoped project APIs; the walk remains as the migration *input finder* only.
- Sunset criteria: ≥99% of non-quarantined secrets `VERIFIED` for 30 days + zero legacy reads in telemetry for 14 days ⇒ remove flag.

## 5. Worked example (synthetic)

```bash
ciphervault migrate plan --vault ./shop/.ciphervault --project shop --dry-run
# → 3 envs, 41 secrets, 2 quarantined (duplicate STRIPE_KEY in .env + .env.local)
ciphervault migrate resolve --quarantine q1 --keep .env.local --rename-loser STRIPE_KEY__legacy
ciphervault migrate --apply --migration-id mig_01H…
# → 41/41 digests match, pointers flipped, legacy retained
ciphervault migrate verify --migration-id mig_01H…   # readback + deploy smoke test
ciphervault migrate shred-legacy --project shop --confirm shop   # after 30-day window
```
