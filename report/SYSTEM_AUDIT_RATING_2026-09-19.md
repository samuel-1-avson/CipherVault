# CipherVault System Deep-Dive, Analysis & Rating — 2026-09-19

**Verdict: strong security-focused beta, overall 7.4/10 (up from 6.0/10 on 2026-09-18). Not production-ready.**
64 commits since the last audit closed every P0, finished the audit backlog
(`4670ef5`), shipped beta.5, and added two user-facing features (TUI explorer,
in-app update). Remaining production blockers are narrow and listed in §9:
server panic paths, ledger restart semantics, manual promotion (the live site
is one release stale), and unproven storm-resistance claims.

## 1. Method, coverage, limits

- **Inspected deeply this session (by hand, with executed verification):**
  `apps/cli/src/dashboard/*` (router, guard, account proxy, collectors,
  finality, fastcdc/files APIs — full read), `apps/cli/src/tui/*` (full
  read + extension), `apps/cli/src/commands/update.rs` (authored via
  extraction), `apps/cli/src/commands/run.rs` unix clippy root cause,
  `services/operator/tests/nat.rs` (flake fix), all four CI/release
  workflows, `services/account/src/guards.rs` (ID format), `scripts/gcp/*`
  promotion scripts, live deployment probes (`/api/*`, UI markers).
- **Measured repo-wide (read-only scans):** test inventory (86 files with
  tests, 41 integration suites), production `unwrap()` census (71),
  TODO/FIXME (2), crate/service/CLI line counts (~52.5k), docs inventory
  (27 files), commit history (64 since 2026-09-18), CI conclusions via API.
- **Carried from the 2026-09-18 audit (not re-verified):** crypto primitive
  review, swarm DoS layers, voucher/Shamir batteries, DHT/record details,
  Solidity contract internals. Carried items are marked as such.
- **Not covered:** external penetration test, cryptographic proof review,
  load/chaos runs beyond the committed suites, mobile or third-party clients.

## 2. Score

| Scope | Score | Basis |
|---|---|---|
| Overall system | **7.4/10** | Mean of the eight categories below; beta, P0s closed, narrow P1s open |
| Cryptography & integrity | 8.5/10 | Prior deep review stands; HSM `Drop` wart removed; schema battery landed |
| Storage / repair / swarm | 7.5/10 | Solid + chaos-tested; NAT flake fixed; storm slices claimed, not re-verified |
| Operator / account services | 7.0/10 | Auth freshness fixed; 51 production unwraps in `state.rs` cap the score |
| CLI / TUI / UX | 8.0/10 | Rich surface, self-update, TUI explorer; e2e binary tests |
| Dashboard / explorer (web) | 7.0/10 | Well-built + documented; live deployment is one release stale |
| Testing & gates | 8.0/10 | 86 test files, 3-OS CI, strict clippy/fmt; one bounded Foundry flake |
| Documentation | 7.5/10 | 27 docs + 2 API references; operator playbooks still missing |
| Release / deploy / ops | 6.0/10 | Manual promotion, stale live site, no deploy-verification gate |

Delta driver (+1.4): P0 closure (+0.5), beta.5 + CI stability (+0.3),
backlog completion incl. schema battery (+0.3), TUI explorer + updater +
dashboard docs (+0.3). The score is capped by §5 items, not by breadth.

## 3. Pros (strengths, all verified)

- **Crypto core is the strongest area (carried + extended).** Domain-separated
  custom KDF, XChaCha20-Poly1305, SHA-256 CIDs, ed25519 repair receiver with
  digest verify and 429 budgets. Since 09-18: the HSM `Drop`-copies-secret
  wart is gone, and `crates/format/tests/schema_battery.rs` (518 lines)
  closed the schema coverage P1.
- **Auth surface hardened.** Peer-announce freshness bounds (24h age / 1h
  skew), recovery-read documented as intended capability design, account
  IDs strictly validated (`cvacct_<32 hex>`) at the dashboard proxy before
  any upstream URL is built (this session, `465d910`).
- **Real bugs are found and fixed with tests.** This session alone:
  unix-only clippy failure root-caused to a split-stranded import (fixed,
  CI green); management proxy routes returning 500 (extractor arity,
  fixed + regression test); NAT AutoNAT test flake (serialized + relay
  dial + retry, green); upstream-path smuggling shape (validation).
- **Gates are strict and green.** `clippy -D warnings` + `fmt --check` on
  three OSes in CI; RUSTFLAGS denies warnings workspace-wide; CI run
  `f389701` is fully green (5/5 jobs). 86 files carry tests; CLI bin suite
  is at 55 tests and rising with every fix.
- **User experience materially improved.** `ciphervault update` existed and
  was verified live; it now has a shared engine (plus a musl-target fix)
  and a TUI popup (startup check, `U` key, locked installing state).
  The TUI gained a 7th tab: a network explorer reusing the web explorer's
  collectors (cluster health, checkpoints, PoS object-quorum lookup).
- **Dashboard API is well-built and now documented.**
  `docs/DASHBOARD_API_REFERENCE.md` covers all 61 router paths across
  private/public/account modes, verified against code; private responses
  carry no-store/nosniff/DENY, sessions are HttpOnly + vault-bound with
  1800s TTL, and unknown private API paths return a JSON envelope.
- **Release engineering is real.** 6-target matrix (gnu/musl/mac/win),
  multi-arch GHCR images, SHA256SUMS on every release, cosign identity
  pinning on promotion, standalone updater binaries for direct download
  (added this session).

## 4. Cons and gaps (prioritized)

### P1 — fix before any production claim
- **Production `unwrap()` density in the operator server (verified, new).**
  71 `unwrap()`s sit outside test modules; 51 are in
  `services/operator/src/state.rs` production paths (mutex locks, fs
  persists, JSON encode), 8 in `services/maintenance/src/db.rs`, 9 in
  `crates/crypto/src/piv.rs`. No `catch_panic` layer exists anywhere, so a
  poisoned lock or a failed persist aborts request handling (and a poisoned
  state lock cascades: every later `lock().unwrap()` panics too). Fix
  sketch: `lock().unwrap_or_else(poison → recover-or-500)` + `Result`
  returns on persist paths + `CatchPanicLayer` returning 500 JSON (the
  poison-recovery pattern already exists in `audit_event`; spread it). M.
- **Live deployment is one release stale (verified, new).** Probes today:
  `/api/explorer/*` → `403 PRIVATE_API_DISABLED` (fallback = unrouted),
  served `/app.js` lacks the Explorer tab (181 KB vs 197 KB in tree, no
  `initExplorer`). The explorer shipped in-repo at `36a9525`/beta.5 but was
  never promoted. Promotion is manual (`promote-immutable-web.ps1`) with no
  post-promote version/endpoint verification gate. Promote + add a live
  `/api/context` + route-smoke check to the pipeline. S/M.
- **Memory-only voucher ledger + repair budget (carried P2, still open).**
  Fresh defaults on boot; voucher double-spend across restart is
  quota-bounded but real. Persist the ledger or document restart semantics
  as a deployment constraint. M.
- **Storm-resistance claims unproven (carried, partially superseded).**
  `4670ef5` claims "Phase 4 gates" landed; the 10-node chaos evidence was
  not re-verified in this audit. Re-run and attach the run IDs, or keep
  the claims marked pending. M.

### P2 — hardening backlog
- **Test-global hazards, now with a proven flake (verified, new).**
  Router tests share the process-global UI session and mutate
  `CIPHERVAULT_ACCOUNT_PATH`; adding a second private-router test flaked
  the suite this session (order-dependent 401). Worked around by folding
  assertions into one test, but the module can never safely hold two
  private-server tests without a serializer. Add a `#[serial]`-style
  guard or per-test session injection. S.
- **Phantom-route test assertions (verified, new, open).** The public
  router test asserts 403 for `/api/secrets/inspect`,
  `/api/guardians/split`, `/api/guardians/reconstruct`, which exist in no
  router — they pass via the generic fallback and prove nothing. Remove
  or mark planned. S.
- **Foundry suite flaked once (verified, bounded).** `6f7a43f` failed only
  the Solidity job while all Rust jobs passed; the same suite passed on
  the commits before and after, and no Solidity file changed in between.
  Transient — but track it; a second occurrence needs a test-level fix. S.
- **Operator playbooks + ADRs still missing (carried P2).** API references
  now exist for operator and dashboard HTTP; runbooks for rotation,
  recovery, and incident response do not. M.
- **Prior P2s carried open (not re-checked):** RPC/kad-record size caps,
  per-request client retry policy, DHT republication when the path goes
  live, quorum-3 parameterization (feature, not fix), CLI lease/voucher
  convenience wrappers.

## 5. Areas that are well developed

- **Cryptography & integrity primitives** — consistently domain-separated,
  tested (incl. constant-time audit tests), spec-accurate since 09-18.
- **CLI command surface** — ~40 commands with e2e binary tests
  (`chaos_federation_drill`, `e2e_workflow`), completions generation
  tested, self-update verified live.
- **TUI** — 7 tabs with consistent keybindings, help modal, background
  polling, and now headless render tests; newest code is the best-tested.
- **Dashboard server** — mode separation verified programmatically
  (23 private-only / 4 public-only paths, nothing leaked), guard tested,
  proxy semantics documented.
- **CI strictness** — 3-OS clippy/fmt/test, Foundry, release bench;
  `-D warnings` enforced via RUSTFLAGS so even bench builds fail on lint.
- **Audit responsiveness** — every prior P0 and the P1 battery closed
  within a day, each with a regression test and a green gate.

## 6. Areas that need improvement (roadmap order)

1. **Server panic paths** (§4 P1): locks + persists + `CatchPanicLayer`.
   Biggest robustness win; blocks any prod claim.
2. **Promotion automation + live verification** (§4 P1): promote beta.5+,
   then add a pipeline step that probes the live site's version and key
   routes. Ends "shipped but not live" drift.
3. **Voucher ledger decision** (§4 P1): persist or document.
4. **Storm evidence refresh** (§4 P1): attach current chaos run IDs.
5. **Test hygiene** (§4 P2): serializer for router tests; drop or mark
   phantom-route assertions; watch the Foundry suite.
6. **Ops docs** (§4 P2): rotation/recovery/incident playbooks + ADRs.
7. **Explorer v2** (deferred by maintainer decision): depth work parked;
   revisit after 1–4.

## 7. Progress since 2026-09-18 (64 commits)

- **47 split refactors** — `services/account` (19) and `apps/cli` (27+1)
  decomposed per SPLIT_PLAN, one module per commit, completions-stable.
- **Features:** web explorer (`36a9525`), TUI explorer (`f389701`),
  TUI self-update popup (`2b58416`), update engine extraction + musl fix
  (`578e01a`), audit-backlog completion incl. schema battery (`4670ef5`).
- **Fixes:** unix clippy (`edde95b`), proxy 500s (`9492677`), account-ID
  validation (`465d910`), private 404 envelope (`6f7a43f`), NAT flake
  (`25ef5d3`), PS 5.1 promotion (`f6dc88f`), verify script (`a55b681`).
- **Docs/CI:** dashboard API reference (`1c5c015`), standalone release
  binaries (`545c1bb`), beta.5 cut + published images.
- **Backlog verdicts moved:** schema battery done, HSM `Drop` removed,
  `persist_sessions`/`persist_challenges` now route through
  `persist_atomic_secure` (fsync + 0600), NAT flake fixed, `--pos`
  removal holding.

## 8. Production-readiness checklist

| Requirement | Status |
|---|---|
| No known auth bypass / freshness hole | ✅ Closed 09-18, holding |
| Secrets handling (0600, fsync, zeroize) | ✅ Verified in touched paths |
| No dead / dishonest CLI surface | ✅ (`--pos` removal holding) |
| Strict gates green on 3 OSes | ✅ (`f389701` 5/5) |
| Server panic-safety | ❌ §4 P1 (71 unwraps, no catch layer) |
| Restart-safe quotas/ledgers | ❌ §4 P1 (or documented constraint) |
| Automated, verified promotion | ❌ §4 P1 (manual, site is stale) |
| Storm/chaos evidence current | ❌ §4 P1 (re-verify `4670ef5` claim) |
| Independent crypto/pen review | ❌ Never claimed; still self-audited |

## 9. Evidence inventory (this audit)

- CI API: `f389701` success 5/5; `6f7a43f` Foundry-only failure with
  green neighbors (transient, bounded); `2b58416` in progress at audit time.
- Live probes: `/`, `/api/context` (public, 200), `/api/operators`,
  `/api/anchors`, `/api/relayer/checkpoints`, `/api/fleet`,
  `/api/operators/history|jobs` (200); `/api/explorer/*` 403 JSON
  `PRIVATE_API_DISABLED`; `/app.js` 181,168 bytes, no explorer markers.
- Repo scans: 86 files with tests; 41 integration suites; 71 production
  `unwrap()` (51 `operator/state.rs`); 0 `todo!`; 2 TODO comments;
  ~52.5k lines (crates 11.6k / services 20.8k / CLI 15.2k / agent 0.7k /
  UI JS 4.1k); 27 docs; 1 Solidity contract.
- Executed: `ciphervault update --check` live (correctly reports latest);
  UI audit harness green; full CLI suite green (55 bin tests);
  Windows + Linux `clippy -D warnings` clean on touched crates.

*Method note: ratings are the auditor's judgment from the evidence above.
“Verified” means observed in this session; “carried” means inherited from
the 2026-09-18 report without re-checking; bounds and failures are stated
where the evidence ran out.*
