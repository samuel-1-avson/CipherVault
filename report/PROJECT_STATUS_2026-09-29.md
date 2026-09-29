# CipherVault — Project Status Report

- **Date (UTC):** 2026-09-29
- **Scope:** Entire project — codebase, releases, production deployments, fleet, security posture, health, risks, next steps.
- **Method:** Evidence-first. Every production claim below was verified live during the 2026-09-28/29 sessions (API probes, container inspection, release-asset checks). Items not directly re-verified are marked *(last-known)*.

## 1. Executive Summary

CipherVault is a decentralized, zero-knowledge secret backup and version control system for confidential development files. It is **healthy and fully deployed**: the workspace, public explorer, and landing page are all on **v1.0.25** (released 2026-09-29), CI is green, the 3-node storage fleet is reachable with verified identities, and the release pipeline (signed binaries, signed container images, cosign-verified immutable promotions with rollback) is proven across three consecutive releases (1.0.23 → 1.0.24 → 1.0.25).

Recent work delivered: a local-dashboard auto sign-in (1.0.24), an explorer UI polish pass (1.0.25), and a production fleet fix (client device enrollment unblocked `push` to 3/3 replicas). No blocking issues remain. The main watch items are routine: the operator fleet intentionally trails on 1.0.21, local disk pressure on the dev machine, and a small backlog of hygiene items listed in §10.

## 2. What CipherVault Is

Git tracks source code; CipherVault protects everything Git leaves behind (`.env` files, API keys, certificates, credentials). Core properties:

- **Zero-knowledge:** XChaCha20-Poly1305 AEAD encryption happens client-side; operators store opaque ciphertext chunks addressed by SHA-256 content hashes. File names, structure, and plaintext never leave the device.
- **Efficient:** FastCDC content-defined chunking (~4/16/64 KiB) gives high dedup ratios; small edits replicate small slices.
- **Sovereign recovery:** Clean-machine disaster recovery from an offline paper kit or M-of-N guardian shares — no cloud login required.
- **Permissioned fleet:** Since the 2026-09-26 re-close, all production operators run `STRICT_AUTH` + `REQUIRE_ENROLLMENT`; only enrolled device keys can write. Anonymous parties get health/metrics/anonymous recovery reads only.
- **L2 anchoring:** Checkpoints anchor via an Arbitrum pipeline (Sepolia rollup in current config) with finality tracking and reorg alarms.

## 3. Repository Map

Workspace: 13 Rust crates plus web UIs, contracts, and deployment tooling.

| Area | Members / paths | Role |
|---|---|---|
| Client | `apps/cli` (CLI, TUI, local dashboard server) | User-facing binary: vault ops, TUI, `ui --local`/`--serve` |
| Agent | `apps/agent` | Watcher/background agent |
| Libraries | `crates/crypto`, `storage`, `snapshot`, `local-store`, `recovery`, `format`, `redact`, `file-lock` | Crypto, FastCDC, chunk store, account store, recovery kits |
| Services | `services/operator`, `services/account`, `services/maintenance` | Storage nodes, hosted account service, maintenance jobs |
| Explorer UI | `apps/ui` (`index.html`, `app.js`, `styles.css`) | Served by the dashboard container; public + local-private modes |
| Landing | `apps/landing` | Marketing site at `cipherv.online` (auto-deploys on `main`) |
| Chain | `contracts/`, `broadcast/` | Anchor contracts and relayer artifacts |
| Deploy | `deploy/gcp`, `deploy/docker`, `scripts/gcp` | Immutable promotions, compose/Caddy, startup scripts |
| Docs | `docs/` (runbooks, specs, ADRs), `report/` (status/audit reports) | Operations and review history |

## 4. Version & Release State

- **Current version:** 1.0.25 (workspace `Cargo.toml` + `Cargo.lock`, 13 member crates).
- **Release pipeline** (`.github/workflows/release.yml`, proven 3×): mandatory pre-release gate → 6 platform builds → signed GitHub Release (26 assets: full/dev/node archives per platform, bare binaries, `SHA256SUMS.txt` + Ed25519 `.sig`) → manifest hash fill (Homebrew/Scoop/Winget via PR) → 4 signed multi-arch GHCR images (operator, maintenance, dashboard, account) with SBOM/SLSA + keyless cosign signatures bound to the release workflow identity.
- **Updater trust:** `ciphervault update` verifies the Ed25519 envelope against pinned key `b625994c0c3f53a6` before checksum-verifying and installing. Windows installs stage `.new` binaries and swap after process exit (a held file lock only delays the swap — observed and resolved in-session).
- **Bump discipline (learned):** a release bump must touch the full surface in one commit — Cargo files, landing, Homebrew/Scoop URLs, a fresh `winget/<version>/` dir, installer scripts, issue template, promote-script usage — or the manifest-fill job fails. 1.0.25 did this correctly; all 13 jobs green first try.

## 5. Production Deployment State (verified live 2026-09-29)

| Surface | Address | Version | Detail |
|---|---|---|---|
| Public explorer | `https://vault.cipherv.online` | **1.0.25** | Dashboard image `72e4c78a…f1d548`, account image `9b218c12…42f03` (exact digests confirmed via `docker inspect` on `cv-web-ui`); rollback = 1.0.24 digests |
| Landing | `https://cipherv.online` | **v1.0.25** | Auto-deployed from `main`; 26-asset badge corrected this cycle |
| Operator fleet | `op1/2/3.cipherv.online` | **1.0.21 images** *(last-known, unchanged)* | All `reachable`, identities `verified`/`pinned`; intentionally held (no operator-code changes since) |
| CLI (user machine) | local install | 1.0.24+ | Self-update path proven working |

Explorer behavior is honest by design: the public site shows only the 4 public tabs (Operators, Explorer, Anchor, Recovery); the 8 vault-plaintext tabs stay local-only and appear in full via `ciphervault ui --local`. Account flows (device-key ceremony hidden remotely, TOTP/WebAuthn proxied) are gated rather than faked.

## 6. Client Interfaces & Account Model

- **CLI:** Full vault lifecycle (`init/track/push/pull/restore/diff/run`), leases, vouchers, invites, node wizard, `doctor` self-checks, `update` self-update. `push` currently replicates 3/3 on the dev vault (~6 s).
- **TUI** (`ciphervault tui`, overhauled in 1.0.23): 7 tabs (Overview, Files, History, Operators, FastCDC, HardwareToken, Explorer), operator inspector with PROBING vs OFFLINE states, snapshot modal, full keyboard nav. No account required; local account session is optional (`l`).
- **Local dashboard** (`ciphervault ui --local`): loopback-only, all 12 tabs. **New in 1.0.24:** the server auto-establishes the device-bound account session at startup and reports it in the banner — the browser opens signed in. Runs once at startup (never on the 30 s poll) so explicit logout keeps working; accountless/unlinked setups are untouched no-ops.
- **Accounts (two planes):** local OS-protected account (device enrollment, vault links, 30-min sessions) and hosted account service (passkeys, TOTP, invitations, memberships) proxied through the dashboard. Linking a vault (`vault link`) binds the two for device-bound operations; it is optional for push, which authorizes on the enrolled device key.

## 7. Security Posture Notes

- Fleet closed to anonymous writes (2026-09-26, evidence in `docs/FLEET_RE-CLOSE_EVIDENCE.md`); enrollment is service-token gated per node with unique tokens; all promotions are digest-pinned with cosign verification and automatic rollback on failed live probes.
- Client device enrollment for the dev vault was completed 2026-09-29 (one record per node, verified via authenticated `GET /v1/identities`); service tokens never left the nodes (remote-side scripts).
- Release signing key `b625994c0c3f53a6` is pinned in the updater and verified on every self-update; `SHA256SUMS.txt.sig` is verified for every release before promotion.
- Pre-commit secret scanning is active (hook installed; commits gated in-session).

## 8. Health & Quality Gates

- **Rust:** `cargo fmt --check` clean; `cargo clippy --workspace --all-targets --locked -- -D warnings` clean; `cargo test -p ciphervault-cli` 196 unit tests green plus all integration suites including `node_wizard` 6/6 (P2P peering included).
- **Web:** `apps/ui/audit.test.cjs` green (honesty regressions, WCAG 2.1 AA, enhancement tests); `scripts/verify_landing.cjs` green; `node --check` on shipped JS.
- **CI:** All workflows green on `main` (Continuous Integration, Security Scans, Zero-Disk Runner Validation, Edge Images, Landing Deploy) and on release tags.
- **Live probes:** post-promotion script asserts `build_version` + operator/explorer routes with auto-rollback; independent re-verification (API + container digests + served-asset markers) performed for both 1.0.24 and 1.0.25.

## 9. Recent Changes (2026-09-28 → 29)

| Commit / release | Content |
|---|---|
| `feat(dashboard)` + 1.0.24 | `ui --local` auto sign-in at startup with banner status; unit-tested no-op paths; live-verified in an isolated sandbox (sign-in, logout-sticks, manual re-login) |
| `fix(landing)` | Asset-count badge 25 → 26 (true for both 1.0.23 and 1.0.24) |
| Fleet ops (no release) | Enrolled dev-vault device on op1–op3; `push` went from 0/3 quorum deficit to 3/3 RemoteDurable; `pull` finds remote snapshots again |
| `feat(explorer)` + 1.0.25 | Account modal sections/icons, role-matrix pills, approval-queue badges, light-mode rules; class cross-check passed |
| Process fix | 1.0.24's bump initially missed the manifest surface (fill job failed, fixed, re-ran green); 1.0.25 shipped the full surface in one commit — 13/13 jobs green first try |

## 10. Known Issues, Risks & Open Items

1. **Fleet trails on 1.0.21 images** — deliberate (no operator-code changes warrant a rolling restart), but the skew should be closed on the next operator-code release. No action now.
2. **Dev-machine disk pressure** — C: filled during builds before; ~19 GB of reclaimable cargo targets were removed. Builds currently fit (~8.5 GB free at last check) but this will recur; consider a larger `CARGO_TARGET_DIR` volume.
3. **README badges stale** — the README shield still says v1.0.17 and "63 Suites"; the project is at 1.0.25 with 196 CLI unit tests alone. Cosmetic; worth a refresh pass.
4. **Bot PRs fail DCO** — automated manifest-fill PRs lack sign-off and are merged `--admin`. Accepted workflow, but rules technically bypassed each release.
5. **CI deprecation notices** — Node.js 20 deprecation and `ubuntu-latest` migration warnings appear as annotations. No failures yet; migrate runners before 2026-10-19 (Ubuntu) and the Node 20 removal.
6. **Firewall-rule deletion still HELD** — per the re-close evidence doc, removing `ciphervault-allow-public-api` would sever client/dashboard access with no substitute. Reachability control, not writability; parked decision, not a vulnerability.
7. **Session UX edges** — local account sessions last 30 min; long dashboard/TUI sessions re-prompt for sign-in (by design). The 1.0.24 auto sign-in covers startup only, deliberately.
8. **Untracked review files** — `docs/CIPHERVAULT_NETWORK_TOPOLOGY.md` + 3 new diagrams predate this session's work and were intentionally left untouched; decide whether to commit or discard.
9. **`ciphervault run` deprecation** — snapshot-mode `run` warns `LEGACY_PATH_DEPRECATED`; users must migrate (`migrate plan`) or pass `--legacy`. Docs should steer new users to the current path.

## 11. Recommendations / Next Steps

1. Refresh README badges + test counts to 1.0.25 reality (small, visible win).
2. Migrate CI off Node 20 actions and pin off `ubuntu-latest` before the forced migrations.
3. Decide the fate of the untracked topology doc/diagrams.
4. On the next operator-code change, roll the fleet to current images (closes the 1.0.21 skew) and re-verify enrollment records post-restart.
5. Consider a `CIPHERVAULT_VERSION`-aware disk-cleanup note in the contributor docs (cargo target growth on Windows).
6. Optional UX: in-link the dev vault to the Alice account (`vault link`) so local sessions are device-bound end to end; optional product copy: document the 30-min session + re-sign-in rhythm in the dashboard account panel.

## 12. Evidence Log (this reporting window)

- `cargo test -p ciphervault-cli`: 196 passed / 0 failed; `node_wizard` 6/6 after workspace rebuild.
- `node apps/ui/audit.test.cjs`, `node scripts/verify_landing.cjs`: all PASS.
- Release runs fully green: v1.0.24 after one fill-job rerun; v1.0.25 13/13 first try. Manifest PRs #11, #12 merged after independent hash cross-checks.
- `ciphervault release verify` valid for both tags (key `b625994c…`); archive SHA-256 spot-checks matched.
- Promotions verified by digest inspect on `cv-web-ui` plus live `/api/context` (`1.0.24`, then `1.0.25`), operator telemetry (3/3 reachable, identities verified), and served-asset markers for the new UI.
- Fleet enrollment: `POST /v1/identities` → 204 on all 3 nodes; 1 record/node confirmed; `push` → RemoteDurable 3/3.

*End of report. Saved for review; not committed.*

