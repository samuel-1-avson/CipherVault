# CipherVault — Final hackathon review (post-remediation)

**Date:** 2026-11-09 · **Commit:** `71a59408259fbeb7a01671fd3b621c4d13688a8e` · **Release:** v1.0.31
**Supersedes the verdict of** `HACKATHON_DEEP_DIVE_AUDIT_2026-11-08.md` (kept for the record).

## Verdict: GO for Nov 11

Every P0/P1 finding from the deep-dive audit is fixed, verified, and
shipped. The remaining work is the three submission mechanics that only
you can do (catalog PR, ≤90s demo video, Typeform) — packages for all
three are prepared in this folder.

## What changed since the audit (5.3/10 → now)

**Shipped-artifact fidelity (was the score-killer)**
- `dist/bin` rebuilt from v1.0.31 source (was Sep-16 v1.0.0); sums regenerated.
- v1.0.31 GitHub release published with checksummed Windows bundles.
- Plugin bootstrap downloads that release, verifies a SHA-256 **pinned
  in plugin source** + release sums — proven in a clean-room `HERMES_HOME`.

**Plugin contract (was: dead scan, prose parsing)**
- Real JSON contracts: `status --json` (incl. no-vault `vault:false`),
  `hook check --deep --json`, `run --json`.
- New agent bridge: `ciphervault redact` (stdin filter), `export-env`
  (machine-only, refuses terminals).
- Guards are hooks, not prompts: `pre_tool_call` leak guard,
  `transform_tool_result` scrub, `tool_request` middleware — output is
  scrubbed against the injected values themselves.
- Secret source verified live; CLI subcommands fixed
  (`setup_fn` receives the subparser) and clean-room proven.
- 25 pytest tests, validator clean (16 checks), doctor: 6 tools/2 hooks.

**Core & network hardening**
- Threshold-aware Shamir combine, recovery-kit v2 (SHA-256) checksums,
  zeroizing PIN/KEK, random keystore salt, DB permission lockdown,
  chunk-v2-by-default with v1-write deprecation, legacy-KDF KAT + ADR.
- Operator loopback default bind, short-token startup refusal, signed
  PoS dedup verification, Windows secret-file ACLs, gossip caps,
  Merkle suffix root, Guardian/healer actually wired, MCP timeouts+scrub.
- Private anchor commitments (v2, opt-in, backward compatible),
  honest quorum reporting, ADR-013 on chain liveness.
- `-D warnings` clippy gate green workspace-wide; **1,163 tests pass**.

**Polish & honesty**
- Canonical 5-minute quickstart (local-first) in README/SETUP/WHAT_IS;
  landing no longer advertises unpublished brew/winget/scoop installs;
  versions single-sourced (`scripts/sync-version.cjs`); dashboard
  defaults to Overview; TUI first-run guide; docs state limits plainly
  (PoS = possession check, account plane = single-writer SQLite).

## Ratings (Hermes hackathon rubric)

| Criterion | Audit | Now | Why |
|---|---|---|---|
| Usefulness | 6 | **9** | Solves a real agent-era problem end-to-end (scan → vault → run → recover), incl. Hermes' own env |
| Reliability | 3 | **8.5** | JSON contracts, 1,163 tests, clean-room install proof; capped by billing-blocked multi-platform CI |
| Polish | 5 | **8.5** | Live desktop pane, honest docs, demo script; demo video still yours to record |
| Creativity | 7 | **9** | Exact-value output scrubbing + hook-level leak guard + secret source is beyond prompt/skill territory |
| **Overall** | **5.3** | **≈8.8** | A credible top-5 contender; 10/10 needs the external crypto audit + a few months of fleet soak, which no 7-day hackathon entry has |

Underlying product: **6.8 → 8.2/10**.

## What's left (yours, ~1 hour)

1. Open the catalog PR with `report/plugin-catalog-ciphervault.yaml`
   (text in `report/CATALOG_PR_DESCRIPTION.md`).
2. Record the ≤90s demo from `plugins/ciphervault/DEMO.md`, post on X
   tagging @NousResearch.
3. Submit both links via the Typeform before **5PM EST Nov 11**.
4. When Actions billing is restored: re-run the release workflow for
   Linux/macOS + attested sums; bump the catalog SHA in a follow-up PR.
