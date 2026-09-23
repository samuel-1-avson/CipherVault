# CipherVault Progress & Project Rating — 2026-09-23

Evidence-based assessment of the just-completed My Data work and of the
project as a whole. Scale is 1–10 per dimension. Evidence window: repo
state at `main` (`ea99037`), releases through v1.0.12, and the live fleet
(`op1/op2/op3.cipherv.online`) as verified 2026-09-22/23.

## Snapshot

| Scope | Score | One line |
|---|---|---|
| Recent progress (My Data plan + 1.0.11/1.0.12) | 9 | 5/5 units shipped, released, promoted, verified live |
| Whole project | 8 | Production-grade open network; ops automation lags the code |

Facts behind the scores: 253 commits; ~60k lines of Rust in 157 files;
tests in 90 files (16 CLI + 18 operator integration suites plus unit,
conformance, crypto-audit, and UI contract tests); 51 docs pages;
5 CI/CD workflows; 6 stable releases from 1.0.7 to 1.0.12; a live
3-node fleet plus dashboard and account service.

## Part 1 — Progress rating: 9/10

### What shipped

- **Unit 1–3** (prior turns): lease receipt log, `status --overview`
  (+ `--json`), local dashboard Overview tab + `/api/overview`.
- **Unit 4** (`317c85e`): session- + vault-scoped `GET /v1/leases`
  (HTTP + P2P), `lease list` with local-log merge,
  `CIPHERVAULT_DISABLE_LEASE_LIST` kill-switch.
- **Unit 5** (`653c7b6`): API reference, operator runbook §11 (abuse
  bounds), user walkthrough §9.
- **1.0.11** (`2914afa`, `cceee73`, tag `v1.0.11`): released, fleet
  promoted node-by-node with rollback refs, verified live (anonymous
  `GET /v1/leases` went 405 → 401 on all three nodes).
- **1.0.12** (`d36b904`, `6735144`, tag `v1.0.12`): push/repair
  receipts now filed at replication time; released with filled
  manifest hashes (hash verified against the served zip).

### Verification observed (not assumed)

- `cargo check`, `clippy -D warnings`, `cargo fmt --check`: clean.
- New tests green, incl. the highest-risk two-vaults-plus-anonymous
  auth scoping test; no regressions (CLI 106/106, CLI integration
  12/12, storage conformance 6/6, operator conformance 36/36,
  operator lib 69/69).
- Local single-node e2e: create → list → overview → 401, plus
  restart persistence.
- Live e2e on the release binary: push 3/3, lease create/list on all
  three operators, overview parity on a second device, byte-identical
  `recover`.
- Release artifacts: hashes filled from SHA256SUMS and spot-verified
  against downloads.

### Why not 10

Two plan-vs-reality gaps shipped and were caught only by live e2e:

1. Push committed a lease per replica (`pool.rs`) but never logged a
   receipt — Unit 1's plan text said push writes receipts. Fixed in
   1.0.12; `lease list` had already backfilled the gap.
2. Plan D4 claimed "recover plus pull rebuilds the store" — `recover`
   restores files only and creates no store. Corrected in the plan;
   the real flow (`.ciphervault` copy + `pull`) is verified and
   documented.

Both were found by the plan's own validation steps, fixed or
corrected within the same release cycle, and neither affected user
funds or data. The process worked; the −1 is for the drift reaching
a release in the first place.

## Part 2 — Whole-project rating: 8/10

| Dimension | Score | Basis |
|---|---|---|
| Architecture & decentralization | 9 | E2E encryption holds end to end; operators see opaque CIDs; local-first overview adds no central index; account service is IDs-only and optional; public explorer untouched |
| Security posture | 8 | Session-scoped auth, vault isolation tests, kill-switches, chaos/DoS suites, Trivy gates, cosign + SLSA provenance — but no HTTP rate limiting and no per-user quota on an open-write network |
| Reliability & operations | 7 | Fleet healthy with runbooks and verified rollback refs — but promotion is manual per-node source rebuilds (~1–1.5 h each on e2-micro), nodes run locally-built images instead of signed GHCR digests |
| Release engineering | 7 | Signed 6-target matrix, updater, manifests — but ~90 min billable builds, manual post-release hash fill (which once corrupted a brew hash via sloppy sed), winget upstream still pending |
| Code quality | 8 | `clippy -D warnings`, fmt, 90 test files, ADRs, honest error envelopes — minus for 10-argument pool APIs and 60k-LOC single-workspace complexity |
| Documentation | 8 | 51 pages: runbooks, ADRs, testing guides, API references — minus for the two plan/reality drifts above; docs need verification passes, not just reviews |

### What is genuinely strong

- **The decentralization story is real, not marketing.** The overview
  work is the proof: full data visibility with zero new server-side
  knowledge, enforced by construction (local aggregation) and covered
  by auth-scoping tests.
- **Release discipline.** Signed, scanned, provenance-attested
  artifacts; CI green required before tags; digests recorded;
  hashes verified against served bytes.
- **Test culture.** Conformance suites pinning memory↔HTTP↔P2P
  parity, crypto audit tests, chaos/DoS tests, and UI contract
  tests that catch public-explorer drift.

### Biggest risks (ordered)

1. **No per-user quota on an open-write network.** Disk growth is
   unbounded by design today; this is the top abuse vector. Watch
   fleet disk; quotas or stronger voucher economics are the fix.
2. **No HTTP rate limiting.** The P2P path has a pre-auth limiter;
   HTTP relies on the kill-switch + external L7. Fine for now,
   explicit tech debt.
3. **Manual fleet promotion.** Each release costs ~3–4 h of attended
   node rebuilds over flaky-tunneled SSH (one session dropped
   mid-build this cycle). A GHCR-pull rolling update would cut this
   to minutes and use the signed artifacts the release already
   produces.
4. **Release toil.** ~90 min matrix + manual hash fill. The hash step
   already corrupted one manifest historically; it belongs in the
   workflow.
5. **Recovery UX gap.** `recover` restores files but no store, so a
   wiped device cannot `pull` or see an overview. Either build
   recover-then-rebuild or bless copy+pull as the documented flow
   everywhere (walkthrough already does).

## Recommendations (priority order)

1. Design quotas/voucher economics before the next growth push (risk 1).
2. Automate fleet promotion from signed GHCR digests (risks 3, partly 4).
3. Move manifest hash fill into `release.yml` (risk 4).
4. Add HTTP rate limiting or document the L7 requirement per node (risk 2).
5. Close the recovery loop: store rebuild from kit, or one canonical
   documented new-device flow (risk 5).
6. Submit winget upstream; kill the stale debug operator (PID 26364,
   running since 9/20, locks the local debug binary).

## Method note

Scores are the author's judgment against the evidence listed above,
not test output. Supporting artifacts: git history (`d36b904` …
`ea99037`), tags `v1.0.7` … `v1.0.12`, workflow runs for the 1.0.11
and 1.0.12 releases, live probe results (405 → 401 cutover, 3/3
replication, byte-identical recovery), and the plan file
`.agents/plans/2026-09-22-my-data-overview.md` (D4 as corrected).
Re-rate after the next release or any quota/promotion work.
