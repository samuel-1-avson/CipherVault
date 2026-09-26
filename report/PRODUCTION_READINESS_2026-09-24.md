# Production Readiness: 2026-09-24

How live CipherVault is, how well it runs, and how ready outside developers
and users are to adopt it. Evidence collected 2026-09-24 against the live
fleet, dashboard, CI, and releases.

## Live state (verified today)

- **Fleet:** op1/op2/op3.cipherv.online all `ready`, `storage_ready`, on
  operator 1.0.14, running the cosign-verified GHCR digest
  `sha256:6313...ebb1efc`. Edge latency ~0.7–0.9 s from the probe location.
- **Dashboard:** vault.cipherv.online serves 200 (83 KB); `/api/context`
  reports build 1.0.9; `/api/operators` shows all 3 nodes reachable with
  pinned, verified identities.
- **Releases:** v1.0.11–v1.0.14 published, 25 assets each (6 platform
  binaries, bundles, SBOMs, signatures, installers). v1.0.14 matrix 13/13
  green including automated manifest hash-fill.
- **CI:** all workflows green on the 1.0.14 bump (`08eaae3`): Continuous
  Integration, Security Scans, Zero-Disk Secret Runner, Edge Images.
- **Supply chain:** release images carry SLSA provenance + SBOM, Trivy
  HIGH/CRITICAL gate, keyless cosign signatures bound to the release
  workflow. Fleet promotes verify the signature before pulling.

## Reliability evidence

- Rolling promotes are health-gated per node with automatic rollback to a
  snapshotted previous image (proven live on the 1.0.14 GHCR roll).
- Repair mesh, heartbeat liveness, chaos/DoS suites, and the 10-node chaos
  gates exercise failure modes in CI; the disaster-recovery drill
  (wipe → guardian shares → recover → pull) passes end to end.
- 366 test functions across the workspace; `clippy -D warnings`, fmt, and
  unit/integration/drill gates enforced.
- Known-flaky `repair_backfills` was root-caused (periodic scanner racing
  exact-count asserts) and fixed at the test-design level, not skipped.

## Can a new user start today? Yes — with caveats

Working install paths (in README, tested this cycle):

- Windows: `irm .../dist/scripts/install.ps1 | iex` (pinned-hash variant
  documented), plus `winget install --manifest` from the in-repo manifests.
- Any platform with Rust: `cargo install --git ... ciphervault-cli`.
- Release zips/tarballs for 6 targets with SHA256SUMS.

First-run flow: `init` (guided, reaches the default fleet, prints the paper
recovery kit) → `track` → `push` → `pull` on a second machine. Disaster
recovery from kit or guardian shares restores files **and** rebuilds a
working store, verified by e2e. The walkthrough in WORKFLOW_GUIDE covers
init → push → pull → recovery → rekey against the live fleet.

Caveats:

- Winget upstream listing is pending Microsoft (fix + CLA done on our side).
  No brew tap / scoop bucket submission yet — manifests exist in-repo only.
- The fleet is open (no voucher requirement), which is good for trial and
  means no account or payment stands between a user and `push`.
- No external-user soak time: all flows above are first-party verified.
  Expect rough edges (error-text clarity, Windows path quirks) that only
  real users surface.

## Can an outside developer contribute today? Yes

- Repo builds with `cargo check/test/clippy/fmt`; CI mirrors the same gates.
- 50+ docs: architecture, ADRs, API reference, workflow guide, runbooks,
  testing guides. Recent additions (quotas, R5 promotion, recovery) were
  written alongside the code, not after.
- Good first areas: the residual list in PROGRESS_RATING_2026-09-24 (web
  release train, P2P fleet enablement, package-manager submissions), all
  with tested seams to extend.
- Caveat: the workspace is large (~60k LOC single workspace, 10-arg pool
  APIs in places). New contributors should start from the docs hub
  (docs/README.md) and the e2e drills, not the dashboard.

## What stands between here and GA

1. Push the two pending commits and watch CI green on them.
2. Winget (and ideally brew/scoop) listings merged upstream.
3. First independent operator joining via the ticket flow (proves the DON
   story outside our GCP account).
4. A user-soak window: real vaults, real recoveries, real support load.
5. Web UI on the release train (currently reports 1.0.9 vs fleet 1.0.14).
6. P2P mesh decision: enable fleet-wide with monitoring, or explicitly
   bless HTTP federation as the production topology.

Verdict: **strong public beta**. Safe to invite technical users and
contributors now; premature to promise GA stability or support SLAs.
