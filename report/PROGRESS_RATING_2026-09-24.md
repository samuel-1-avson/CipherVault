# Progress Rating: 2026-09-24

Follow-up to [PROJECT_RATING_2026-09-23](PROJECT_RATING_2026-09-23.md) (overall 8/10).
Covers everything shipped 2026-09-23 → 2026-09-24: releases 1.0.11/1.0.12/1.0.13/1.0.14,
the repair-flake fix, per-user quotas, recover-then-rebuild, GHCR-pull promotion,
release automation, and the winget submission. All claims below were verified
against live systems, CI, or test runs in this cycle — not taken from plans.

## What shipped since the last rating

| Item | Evidence |
|---|---|
| 4 releases in ~3 days (1.0.11–1.0.14), 25 assets each | GitHub releases API, all published |
| 1.0.14 matrix fully green (13/13 jobs) incl. hash-fill | Release run 35956134244, `success` |
| Hash-fill automation proven (no manual fix for 1.0.14) | Auto-commit `4f8dc48` on main |
| Fleet on 1.0.14 via signed GHCR digests (was: source rebuilds) | `docker inspect` digest match, 3/3 `--version` + `/healthz` |
| HTTP rate limiter live-verified (600x200 + 100x429, exact trip) | Live burst test vs op2 |
| Per-user quotas (uniform cap, off by default, persistent) | 7 ledger unit + 1 HTTP integration test, gates green |
| `repair_backfills` flake root-caused and fixed | Reproduced locally (4 pushes vs 2), 3/3 suite green after fix |
| `recover` rebuilds a working store (was: files only) | Chaos drill step 11b: `pull --dry-run` on virgin machine passes |
| GHCR-pull rolling promotion with auto-rollback (R5) | Live full-fleet roll in minutes, runbooked |
| Winget PR #439617: install failure + schema fixed, CLA signed | Pushed `bfa19c88e`, `winget validate` passes, agree posted |

## Disposition of the 09-23 top-5 risks

1. **No per-user quota (was #1)** — CLOSED in code: uniform per-holder lifetime
   cap, spend aggregated across vouchers, persistent across restarts, 429 on
   exhaustion. Policy choice (confirmed): fleet stays open, so the cap ships
   unenforced until an operator sets `--user-quota-bytes`. The remaining step
   is a one-line policy decision, not engineering.
2. **No HTTP rate limiting (was #2)** — CLOSED and live-verified on the fleet.
   Residual note from the work stands: keying is XFF-aware, documented.
3. **Manual fleet promotion (was #3)** — CLOSED: `promote-operators-ghcr.ps1`
   rolls the fleet from verified GHCR digests in minutes with pre-health gates
   and automatic rollback. Proven on the live fleet (1.0.14 re-promote).
4. **Release toil (was #4)** — CLOSED: hash-fill runs in the workflow and
   committed `4f8dc48` by itself for 1.0.14. The ~90 min matrix remains (build
   cost, not toil).
5. **Recovery UX gap (was #5)** — CLOSED: `recover` rebuilds vault.db +
   operators + device identity from kit-rooted trust; the drill proves a wiped
   device pulls immediately after. Copy+pull remains documented as the
   full-fidelity path when a device survives.

## Updated whole-project rating: 9/10 (was 8/10)

| Dimension | Was | Now | Basis for the move |
|---|---|---|---|
| Architecture & decentralization | 9 | 9 | No change; E2E story still holds (see honesty note below) |
| Security posture | 8 | 9 | Limiter + quotas both shipped; kill-switches, chaos/DoS suites, Trivy, cosign/SLSA unchanged |
| Reliability & operations | 7 | 9 | Fleet runs signed GHCR digests; promotion is minutes with auto-rollback; runbooks extended (R5) |
| Release engineering | 7 | 8 | Hash-fill automated and proven; 4 clean releases; winget still with Microsoft |
| Code quality | 8 | 8 | Flake fixed at root, quotas/rebuild well-tested, gates held; workspace complexity unchanged |
| Documentation | 8 | 9 | Rating, quota playbook, R5 runbook, recovery walkthrough all landed and verified |

Honesty notes (why not 10, and what the scores assume):

- The P2P swarm (repair mesh, heartbeats, gossip) is built and heavily tested
  but **not enabled on the live fleet** — nodes run HTTP-only (`--port
  --data-dir --operator-id`, no `--enable-p2p`). Federation today is HTTPS +
  dashboard probing. The decentralization score reflects the architecture and
  the local-first guarantees, not a live mesh.
- The fleet is single-cloud (GCP), three e2-micro nodes. No multi-region or
  multi-provider failure evidence yet.
- Two commits (`9e14404` recover-rebuild, `9b1870d` R5 script) were committed
  but not pushed at rating time, so CI has not validated them yet. All local
  gates (check/clippy/fmt/unit/integration/drill) are green.
- No external users or third-party operators yet — every number above is
  first-party verification. External adoption is the next validator.

## Residual risks (ordered)

1. **Single-cloud fleet, no external operators.** Everything runs on the
   project's GCP account. The join flow exists and is tested, but no
   independent party has joined.
2. **Winget pending on Microsoft.** Fix pushed, CLA signed, local validation
   passes; merge timing is out of our hands.
3. **Web UI trails releases** (dashboard reports build 1.0.9 while the fleet
   is on 1.0.14). Cosmetic drift today; needs a release-train rule.
4. **Quota policy undecided for the fleet.** Code is ready; the open-fleet
   choice should be revisited before any growth push.
5. **P2P mesh unproven in production.** Enabling it fleet-wide is a project
   in itself (NAT, bootstrap, monitoring) — correctly deferred, not forgotten.
