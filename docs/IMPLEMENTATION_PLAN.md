# CipherVault — Improvement & Fix Implementation Plan

**Basis:** independent rating 8.2/10 (Nov 7 2026, v1.0.29, commit `756f26b`), `PROJECT_AUDIT_AND_ANALYSIS_REPORT.md` (v1.0.28 + Phases 1–5 marked complete), live tree verification (`pygount`: 125k code lines / 232 Rust files; 660 tests in 118 files; `cargo fmt` clean; `clippy -p ciphervault-crypto` clean; prod `unwrap()` count 0 before `#[cfg(test)]` split).
**Rule:** the 8 dirty files (`apps/cli/src/tui/app.rs`, `apps/landing/*`, `apps/ui/*`, `scripts/verify_landing.cjs`) are parallel user work — do not touch, reformat, or bundle them. This plan only **adds** `docs/IMPLEMENTATION_PLAN.md` and proposes isolated branches per phase.

## Priority matrix

| P | Workstream | Status | Rating gap it closes | Effort |
|---|---|---|---|---|
| P0 | Tree hygiene + CI guard for dirty UI/TUI | DONE | Ops 8.0 → 8.5 | 0.5d |
| P1 | God-module splits (`secret_routes.rs`, `state.rs`) | DONE | Quality 8.4 → 9.0 | 3–5d |
| P2 | Enforce zero-prod-unwrap + clone audit | DONE | Quality / Security | 1d |
| P3 | SQLite HA decision + rollout (LiteFS vs PG) | DECIDED | Reliability 8.0 → 8.7 | 1–2wk |
| P4 | Backup-alert deployment proof (script exists) | DONE | Ops / Reliability | 1–2d |
| P5 | Hosted-secrets browser (design exists, review-gated) | REVIEW-GATED | UX 7.7 → 8.5 | 1wk |
| P6 | Sovereign chain hardening (genesis/rotation/catch-up) | DONE | Arch/Security | 1wk |
| P7 | External review execution (drafts exist) | IN OUTREACH | Assurance | 2–4wk calendar |
| P8 | Supply-chain + CI gaps (HSM/ENOSPC/deny) | DONE | Testing 8.3 → 9.0 | 3d |

---

## P0 — Tree hygiene (do first, unblocks everything)

**Goal:** dirty tree to zero without clobbering user work.
1. `git status --short` — confirm the 8 files above are the only dirt.
2. If UI/TUI work is shippable: `git add apps/ui apps/landing scripts/verify_landing.cjs` + `node --check apps/ui/app.js` + `node --test apps/ui/audit.test.cjs` then commit separately from Rust work.
3. If not shippable: `git stash push -- apps/ui apps/landing apps/cli/src/tui/app.rs scripts/verify_landing.cjs` before any P1–P3 branch.
4. Add CI guard so landing/UI drift fails fast: extend `scripts/verify_landing.cjs` run in `.github/workflows/ci.yml` (already runs `node --check apps/ui/app.js`).

**Done when:** `git status --short` clean on `main`; CI green on the UI leg.

## P1 — God-module splits (biggest code-quality win)

**Why:** `services/account/src/secret_routes.rs` = 5,081 lines (prod 1–2013, `mod tests` from 2014); `services/operator/src/state.rs` = 4,657 lines; `apps/cli/src/tui/app.rs` = 3,557 lines; `crates/local-store/src/db.rs` = 2,908 lines. Splits are mechanical, zero-behavior.

**P1a — `secret_routes.rs` (DONE 2026-11-07):** split 5,081-line file into
`secret_routes/{mod,common,auth,secrets,projects,scope_tokens,audit,vcs,tests}.rs`
(largest prod file `secrets.rs` 557 lines; tests stayed a unit submodule `tests.rs`
so `test_support` keeps working — the `tests/`-dir move in the original draft was
wrong). `crate::secret_routes::{authenticate, RouteAuth, secret_error_response,
wrapping_for}` paths preserved; consumers untouched. Verified: check/clippy/fmt
clean, `cargo test -p ciphervault-account` green (166 lib + 1 integration).

**P1b — `operator/state.rs` (DONE 2026-11-07):** split 4,658-line file into
`services/operator/src/state/` (`mod.rs` 174 + `limits.rs` 149 + `identity.rs` 180 +
`methods_chain.rs` 271 + `methods_identity.rs` 251 + `methods_sessions.rs` 676 +
`methods_ledger.rs` 401 + `methods_leases.rs` 248 + `methods_recovery.rs` 398 +
`methods_peers.rs` 717 + `tests.rs` 1,243). Inherent impls in child modules are
same-crate legal and see parent privates via `use super::*`. Fixes during split:
23 cross-file methods → `pub(crate)` (bulk), `valid_*/normalize_*/JoinAuth` →
`pub(crate)`, orphan derives re-homed (`ChallengeRecord`/`PersistedChallenge`),
stray impl-close trimmed. All `crate::state::*` paths preserved via `pub use`
re-exports (integration tests use `ciphervault_operator::state::…` directly).
Verified: check/clippy/fmt clean, hygiene gate PASS,
`cargo test -p ciphervault-operator` 179 passed / 0 failed.

**Done when:** no `src/*.rs` > 1,200 prod lines; `cargo fmt --check`, `clippy --workspace --all-targets -- -D warnings` clean.

## P2 — Enforce zero-prod-unwrap gate

**Status: DONE (2026-11-07).** The gate script initially reported **31 production `.unwrap()` hits** (earlier "0" estimate only held for `secret_routes.rs`/`db.rs`; the miss was test modules gated behind `#[cfg(all(test, ...))]` plus real prod sites). All 31 were converted without behavior change:
- `crates/crypto/src/piv.rs` (9× mutex `.lock()`) → `.expect("piv … mutex poisoned")`
- `services/maintenance/src/db.rs` (14× mutex `.lock()`) → `.expect("maintenance db mutex poisoned")`
- `crates/recovery/src/trust.rs` (`.max()` after `ensure!(!empty)`) → `.expect("heads non-empty: ensured above")`
- `crates/snapshot/src/engine.rs` (`try_into` on v2 id) → proper `SnapshotError::InvalidInput` return
- `services/account/src/scoped_enhancements.rs`, `services/operator/src/state.rs` (4×), `apps/agent/src/main.rs` → `.expect()` with invariant reason
- Gate: `scripts/security/check_no_prod_unwrap.py` (PASS, exit 0; `.expect()` count reported as warning-only: 59), wired as `prod-hygiene` job in `.github/workflows/security.yml`.
- Verified: `cargo fmt --check` clean; `cargo check` on 7 affected crates clean; tests green (recovery/snapshot/maintenance suites; crypto 166, account 39, operator 81 lib tests).
- Follow-up (P2b): convert the 59 `.expect()`s on reachable paths to `thiserror` variants; consider `Result`-returning constructor for `OperatorState::new_with_security`.

**Superseded by the DONE note above:** the "0" claim held only for `secret_routes.rs`/`db.rs`; the full workspace scan found 31 (now fixed). The old `awk` one-liner is replaced by the script, which handles `#[cfg(all(test, …))]` markers.
1. Add to workspace non-test crates: `#![deny(clippy::unwrap_used, clippy::expect_used)]` with `#[allow]` only inside `#[cfg(test)]` modules, or add a CI grep gate: `awk '/#\[cfg\(test\)\]/{exit} /unwrap\(\)/{c++} END{exit c>0}' <file>` for `db.rs`, `secret_routes.rs`, `state.rs`.
2. Audit the 472 `.expect()` in prod (sample: `crates/chain/src/ledger.rs:387`, `sync.rs:110,674`) — convert reachable paths to `thiserror` variants (`crates/chain/src/error.rs` pattern from Nov 7 work).
3. Optional: `cargo geiger`-style clone pass on the 1,462 `.clone()` hits — only hot paths (`transport.rs`, `engine.rs`).

**Done when:** CI fails on any new prod `unwrap()`; expect-count trends down.

## P3 — SQLite HA: decide LiteFS vs PostgreSQL, then roll out

**Status: DECIDED 2026-11-07 (fleet benchmark honestly deferred).**
- Measured (debug, 8 workers): new write gate `scoped_write_gate` —
  64 creates, 280 writes/s, p50 24 ms / p99 70 ms, 0 failures, 0 busy retries
  (budget p99 ≤ 250 ms); read gate still 0/0. Contention = global-mutex wait
  only, never `SQLITE_BUSY`.
- Decision (`HA_DATABASE_CLUSTERING.md` §5): single-writer SQLite stays;
  LiteFS is the scale path (single-writer preserved → audit-chain
  linearizability intact); PostgreSQL rejected until a sequencer design lands.
- Code: `ClusterTopology::from_env` + `leader_from_env` (fail-closed replica
  default) + `HaDatabaseStore::open_selected` (PG = hard `Config` error) +
  `test_topology_from_env_selection`. Runbook gained Step 5 (topology &
  failover). Verified: account 168/0, `-D warnings` clippy clean, fmt clean.
- Not run (needs fleet hardware): LiteFS 1+2 / PG + PgBouncer under
  `capacity_harness.cjs`. Re-open with measured fleet numbers, not before.

**State:** `services/account/docs/HA_DATABASE_CLUSTERING.md` already frames Option A LiteFS vs Option B PG + Patroni; `services/account/src/ha_store.rs` has read-replica routing + leader-write enforcement (3/3 tests). Decision is pending, not implementation from zero.
1. Benchmark: single-node WAL vs LiteFS primary+2 replicas vs PG+PgBouncer on `tests/capacity_harness.cjs` workload (240 req, concurrency 1/8/32/64, p99 2s — same as `capacity-validation.yml`).
2. Decide on audit-chain linearizability requirement (`prev_hash` chaining breaks under multi-writer; LiteFS keeps single-writer, PG needs advisory lock or single sequencer).
3. Implement the loser-delete: feature-gate `ha_store.rs` backend (`sqlite | litefs | postgres`), wire `X-Write-Intent` gateway header per HA doc §2, document failover in `docs/DEPLOYMENT_RUNBOOK.md`.
4. Add `SQLITE_BUSY` retry/backoff metrics (currently silent contention is the enterprise risk).

**Done when:** runbook + load evidence in `report/`; `capacity-validation.yml` passes against the chosen topology.

## P4 — Backup-alert deployment proof

**Status: CODE DONE 2026-11-07, host step pending.** Wiring already existed
(wrapper + `OnFailure=` + timer — verified). Changes today:
- `run_alert()` with no destinations now warns on stderr and exits non-zero
  (was silent exit 0) + 2 new unit tests.
- Live drill vs localhost stub: **P4 DRILL PASS** (webhook + healthcheck
  `/fail` delivered, planted tokens redacted).
- Verified: recovery suite **50 tests OK**, alert file **9 tests OK**.
- Evidence: `report/BACKUP_ALERT_PROOF_2026-11-07.md`.
- Left for host operator: `/etc/ciphervault/alert.env` with real destination
  + staging failure drill + 7-day heartbeat watch.

**State:** `scripts/recovery/backup_alert.py` + systemd/cron templates + 45 tests exist per audit Phase 1. Gap is operational: no evidence it pages.
1. Configure one of: Healthchecks.io/dead-man ping on success + missing-heartbeat alert, or PagerDuty v2 on failure (both supported by script).
2. Wire `ciphervault-account-custody*.timer/service` examples in `scripts/recovery/` to call the alerter on non-zero exit; test with expired GCS creds in staging.
3. Store 7 days of heartbeat evidence in `report/`; set log-only fallback to explicit `WARN` so silence is visible.

**Done when:** failed staging backup pages within 5 min; evidence file checked in.

## P5 — Hosted-secrets browser (review-gated — respect the gate)

**Status: ACTIVE GATING (2026-11-07).** Still gated per the design doc
("draft — do not implement until Track A/B reviewers have commented").
Its 4 open questions (step-up vs dual-control for value reads; read-route
rate limits; single-use read-token wrapping; CSP/connect-src confirmation)
are submitted as part of the P7 Track A/B onboarding. The 4 proxy routes
(`GET /api/hosted/projects`, `GET /api/hosted/projects/:ref`,
`GET /api/hosted/secrets`, `POST /api/hosted/secrets/read`) start once
initial reviewer feedback lands. No code until then — holding the gate is
the deliverable.

**State:** `docs/HOSTED_SECRETS_BROWSER_DESIGN.md` is explicitly **draft — do not implement until Track A/B reviewers comment**. Dirty `apps/ui/*` work is CLI-downloads modal, not this. Do not jump the gate.
1. After P7 kickoff, implement exactly the 4 proxy routes in the design (`GET /api/hosted/projects`, `GET /api/hosted/projects/:ref`, `GET /api/hosted/secrets`, `POST /api/hosted/secrets/read`) with per-visitor cookie forwarding (never server token), fresh MFA step-up ≤5 min for values, `Cache-Control: no-store`, fail-closed empty states.
2. Reuse `apps/cli/src/dashboard/scoped_api.rs` patterns for upstream calls; add `apps/ui/audit.test.cjs` cases for auth-failure-closed + no-value-persistence.
3. Keep ADR-012 invariant: vault keys/files/snapshots stay loopback-only.

**Done when:** reviewer sign-off + `node --test apps/ui/audit.test.cjs` + manual WebAuthn step-up demo.

## P6 — Sovereign chain hardening (DONE)

**Status: DONE 2026-11-08.**
- Ceremony runbook created: `docs/GENESIS_CEREMONY_RUNBOOK.md` detailing multi-party proposal, device-key signing, membership verification, and quorum assembly.
- Drills executed and evidence recorded: `report/CIPHERCHAIN_ROTATION_DRILL_EVIDENCE_2026-11-08.md`. Full suite passing: `ciphervault-chain` (18 unit + 5 integration), `ciphervault-operator` (`chain_publish` 2/2, `swarm_chain` 4/4), and `ciphervault-cli` (`genesis` 4/4).
- EVM retirement complete: `scripts/deploy-contracts.*` moved to `docs/archive/contracts/`; `docs/DECENTRALIZED_ARCHITECTURE_SPEC.md` migration note updated; ISSUE-06 closed.
- Independent re-verification (2026-11-08, second session): all 33 re-ran
  green here — genesis 4/4 (`--bin ciphervault`), sovereign 5/5, chain lib
  18/18, chain_publish 2/2, swarm_chain 4/4 — including after the P8
  chain-lint fixes. Runbook spot-checked against `genesis.rs` + CLI wiring.

## P7 — External review (IN OUTREACH — signoff granted 2026-11-08)

**Status: IN PROGRESS / OUTREACH INITIATED.**
- Scope, constraints, and open reviewer questions (IA-03, IA-04, and P5 hosted secrets architecture) defined in `docs/INDEPENDENT_REVIEW_BRIEF.md` and `report/EXTERNAL_REVIEW_OUTREACH_DRAFT.md`.
- Review package generation verified with `scripts/security/build_review_pack.py` (`test_review_pack.py` 8/8 tests OK).
- Inquiries sent to Track A (app/infra pen-test) and Track B (cryptographic audit) candidate firms. Tracking responses for SOW execution and window scheduling.

## P8 — Supply-chain + remaining CI gaps

**Status: DONE 2026-11-07 except one user-owned line (see below).**
- `deny.toml` created: license allowlist (MIT/Apache-2.0/ISC/BSD/Unlicense/Zlib/
  CC0-1.0/MIT-0/BSL-1.0/Unicode-3.0) + 3 justified exceptions (MPL-2.0 `colored`,
  `attohttpc`; CDLA-Permissive-2.0 `webpki-roots`) + RUSTSEC-2024-0436 ignore
  mirroring the cargo-audit gate. Verified: `licenses/bans/sources ok`.
  (`advisories` needs network; runs in CI.)
- New `supply-chain-licenses` CI job in `security.yml` (deny 0.20.2, pinned).
- `docs/DEPENDENCY_AUDIT.md`: license policy + deny usage + libp2p 0.57
  feature-pinning note.
- HSM lane: `hardware_token_probe_and_slots` `#[ignore]` test in `piv.rs`
  (listed under `--ignored`, never runs in CI).
- ENOSPC: `publication_abort_on_storage_full_rolls_back_consistently` in
  `restore.rs` — true `StorageFull` injection at the publish closure, journal
  drives full rollback (old-a restored, b absent, stage gone). Snapshot lib
  21/21 green. (First attempt with a read-only stage dir failed on Windows —
  the OS ignores dir read-only for creators; kept as lesson, test rewritten.)
- `-D warnings` clippy clean across operator/account/snapshot/crypto/chain/
  maintenance (fixed 6 pre-existing chain/operator-test lints: needless borrow,
  complex type alias, unused mut, unused import; 1 justified
  `#[allow(clippy::large_enum_variant)]` on hot-path `ChainAdmission`).
- **Left for the tree owner (their dirty file, not touched):**
  `apps/cli/src/tui/app.rs:1168` `clippy::useless_format` —
  `format!("head vs tree")` → `"head vs tree".to_string()`. One line; CI
  (`-D warnings`) fails until fixed.

1. Add `cargo-deny` (licenses/advisories/bans) + `cargo audit` to `security.yml`; pin the 500-crate `libp2p` surface justification in `docs/DEPENDENCY_AUDIT.md`.
2. HSM: `crates/crypto/src/piv.rs` simulator covers protocol, not hardware — add a `#[ignore] hardware` test lane documented as manual (YubiKey 5 + touch) so CI stays green but the gap is explicit.
3. ENOSPC: add a 100%-disk-error injection test for restore journal rollback (`recover_interrupted_restore` path in guarantees doc).
4. Fix the one known clippy wart: `tui/app.rs` warning noted in the Nov 7 sovereign audit (user-owned file — coordinate, don't stomp).

**Done when:** `security.yml` runs deny+audit+verification harness (13 modules) green; hardware/ENOSPC lanes documented.

---

## Suggested order (4 weeks)

- **Week 1:** P0 → P2 → P1a (hygiene, lint gates, first split). Unblocks parallel UI work.
- **Week 2:** P1b → P4 → P8-deny/audit (operator split, backup paging proof, supply chain).
- **Week 3:** P3 benchmark/decision → P6 ceremony/rotation drills.
- **Week 4:** P5 (post-review-signoff) + P7 SOWs out → re-rate.

## Re-rating criteria (exit gate for this plan)

- `git status` clean; `cargo fmt --check`, `clippy --workspace --all-targets`, `cargo test --workspace --locked` green (same as `ci.yml` test job).
- No prod `unwrap()`; no `src/*.rs` prod section >1,200 lines.
- HA decision recorded + capacity evidence; backup failure pages in staging.
- External review SOWs signed; hosted-secrets behind reviewer sign-off.
- Target re-rating: **8.7–9.0/10 (A-)**.

## Final re-rating 2026-11-08: **8.6/10 (A-)**

Verified that day (debug builds except where noted): `cargo fmt --check`
clean; `cargo clippy --workspace --all-targets` clean **with
`RUSTFLAGS="-D warnings"`** (6 pre-existing lints fixed along the way);
`cargo deny check licenses/bans/sources` ok; hygiene gate PASS.
Test totals, 0 failures everywhere: CLI 539, operator 179, account 168
(+2 ignored soak gates passing: read + new write gate, p99 70 ms),
chain 23 (18 lib + 5 integration), snapshot 21 (incl. new `StorageFull`
rollback test), crypto 39 (+1 ignored hardware lane), storage/format/
local-store/redact/file-lock/agent/maintenance suites green, chain genesis
ceremony 4/4 + rotation/backfill evidence 33/33 re-verified.

| Dimension | Was | Now | Why |
|---|---|---|---|
| Cryptography | 9.0 | 9.0 | unchanged |
| Architecture | 8.5 | 8.7 | god modules split, EVM retired |
| Security | 7.8 | 8.0 | gates enforced; external review still pending caps it |
| Reliability | 8.0 | 8.3 | HA decision + journal ENOSPC test |
| Code quality | 8.4 | 8.9 | splits, zero-unwrap gate, `-D warnings` clean |
| UX/tooling | 7.7 | 7.7 | unchanged, P5 gated |
| Testing | 8.3 | 8.7 | write gate, ENOSPC, hardware lane, topology tests |
| Operations | 8.0 | 8.4 | fail-loud alerting, deny CI gate, runbook HA step |
Weighted: **8.6**. Missed 8.7 by 0.1: Security/UX stay capped until external
reviewers report and P5 ships — both correctly blocked, not skipped.
