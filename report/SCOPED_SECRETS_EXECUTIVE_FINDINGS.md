# Deliverable A — CipherVault Scoped Secrets: Executive Findings

**Version:** 2.5.0 · **Date:** 2026-09-27 · **Parent report:** [SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md](./SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md) (Deliverable B, authoritative audit record)

## 1. What CipherVault does today

CipherVault (workspace v1.0.20) is a decentralized, zero-knowledge **confidential-file versioning and disaster-recovery system**, not a credential manager. Developers track whole files (`.env`, keys, certificates) into a directory-local encrypted vault (`.ciphervault/vault.db`), snapshot them with FastCDC content-defined chunking, replicate opaque ciphertext chunks across untrusted storage operators, and recover on clean machines via offline kits or Shamir shares. Secrets exist only as unparsed bytes inside tracked files.

## 2. Do scoped credentials already exist?

**No.** There is no project, repository, workspace, organization, environment, service, or application entity anywhere in the schemas, wire formats, APIs, or CLI — verified by full-tree search (`crates/`, `services/`, `apps/`). The effective secret identity is `vault_id ‖ relative_path ‖ snapshot_id`, with `.env` variable names parsed ephemerally at `run` time. Scoping is 0% enforced: no tables, columns, API parameters, or authorization checks reference project/repo/environment context.

## 3. Major gaps

1. **No discrete secret identity or lifecycle** — cannot create, read, rotate, expire, or audit one credential without rewriting a whole file and snapshotting.
2. **No environment boundary** — dev/staging/prod separation is a filename convention (`.env.*`); `ciphervault run` merges all `.env*` files with last-wins override and no gates.
3. **Binary authorization** — vault keys decrypt everything; no RBAC/ABAC, no per-secret or per-environment grants.
4. **No repository binding** — only `.gitignore` sync and a pre-commit hook; renames, forks, and multi-repo projects are invisible to the system.
5. **No machine identity** — no OIDC federation; CI must bootstrap from an external secret (circular dependency).
6. **No per-secret audit** — local `activity_log` has 4 writers (watcher + dashboard only); control-plane `audit_events` covers account/device/session lifecycle only.

## 4. Security implications

Cryptographic foundations are strong (XChaCha20-Poly1305, domain-separated KDF, zeroized keys, ciphertext-only operators, vault-bound sessions, fail-closed defaults). The risk is **architectural, not cryptographic**: all-or-nothing access, silent cross-environment key override, unaudited CLI reads, and vault-key-bearing local databases (`epoch_keys` table) make multi-project operation unsafe at scale. Any multi-tenant or team deployment on the current model risks cross-project disclosure through misconfiguration rather than cryptanalysis.

## 5. Architectural conclusion

Adopt the **hierarchical resource-scoped model**: `Tenant → Workspace → Project → [Environments, Repository bindings, Services] → Secrets → Versions`, with identity `(project_id, environment_id, name)`, optional repo/service confinement, scope-bound AEAD (AAD = `tenant‖project‖env‖secret‖version`), server-side RBAC/ABAC, and an idempotent 7-stage migration from legacy vaults. Do **not** make the Git repository the owner of secrets — bind repos to projects by immutable provider IDs so renames, transfers, forks, monorepos, and multi-repo projects work without secret migration. Full specification: Deliverables C–H.
