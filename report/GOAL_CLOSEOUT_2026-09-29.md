# CipherVault — Goal Closeout Report

- **Date (UTC):** 2026-09-29
- **Goal:** Resolve the "Known Issues, Risks & Open Items" (§10) and "Recommendations / Next Steps" (§11) from `report/PROJECT_STATUS_2026-09-29.md`.
- **Outcome:** Complete. All actionable items implemented, committed to `main`, pushed, and verified. Two items were explicitly no-action/parked per the objective itself.
- **Production state at closeout:** explorer + landing on **1.0.25** (live, re-verified); fleet on 1.0.21 images (deliberate hold); HEAD at `583fa74` with all CI green.

## 1. Item Disposition

| # | Objective item | Disposition | Evidence |
|---|---|---|---|
| 1 | Fleet trails 1.0.21 | **No action** (explicit in objective) | Rolls on next operator-code release; enrollment records healthy |
| 2 | Dev-machine disk pressure | **Done (docs)** | New "Disk Space & Build Artifacts" section in `CONTRIBUTING.md` (`CARGO_TARGET_DIR`, reclaimable-only cleanup); physical volume move is local-env, owner's call |
| 3 | README badges stale | **Done** | `v1.0.25` shield, `707 tests` shield (counted from tree), test-section comment refreshed; grep confirms zero stale refs |
| 4 | Bot PRs fail DCO | **Done** | `signoff: true` added to the manifest-fill PR step; input verified to exist in `peter-evans/create-pull-request@v7` upstream `action.yml`; takes effect on next tag |
| 5 | CI deprecation notices | **Done** | `ubuntu-24.04` pinned in all 7 workflows (18 sites); first-party actions bumped after per-major changelog review; `Rust Test Suite (ubuntu-24.04)` green; Node 20 annotation gone |
| 6 | Firewall-rule deletion HELD | **Parked** (explicit in objective) | Reachability control, not a vulnerability; no substitute path exists |
| 7 | Session UX edges | **Done (docs)** | 30-min rhythm note added to the sign-in modal; `audit.test.cjs` green; startup-only auto sign-in behavior unchanged by design |
| 8 | Untracked topology files | **Done (committed)** | User approved; `docs/CIPHERVAULT_NETWORK_TOPOLOGY.md` + SVGs 08–10 committed in `19da3d9` (1,029 insertions) |
| 9 | `run` deprecation docs | **Done** | Migration steer callout added to README quickstart (`migrate plan` vs `--legacy`) |
| R4 | Fleet roll (next op change) | **Future conditional** | Nothing to do until operator code changes |
| R6 | Vault link + session copy | **Done** | `vault link --alias dev-workspace` → 4 links, session authenticated (verified via `auth status`); modal copy shipped |

Held with documented reason: `upload-pages-artifact@v3` (v4+ drops the `.nojekyll` dotfile the landing deploy depends on) and `windows/macos-latest` runners (no forced migration date; changing them risks toolchain drift). Third-party actions (docker/*, rust-cache, foundry, softprops, cloudflare, cosign-installer, trivy) left at current pins — upstream-owned, out of the Node 20 first-party scope.

## 2. Commits Landed

- `19da3d9` docs: add network topology spec and architecture diagrams
- `799e765` ci: pin ubuntu-24.04 runners and migrate first-party actions off Node 20
- `bcc2b29` docs(ui): refresh badges, run steer, disk note, session copy
- `583fa74` ci(release): sign off automated manifest-fill PRs for DCO

## 3. Verification Log

- Workflow YAML: all 7 files parse (`yaml.safe_load`).
- UI: `node apps/ui/audit.test.cjs` green after the modal copy change.
- CI on final HEAD `583fa74`: Continuous Integration success (5/5 incl. `ubuntu-24.04`, Windows, macOS, Foundry, bench), Security Scans success, Zero-Disk Runner Validation success. Landing + Edge green on the immediately preceding HEAD with byte-identical workflow content for those paths (only tag-triggered `release.yml` changed since).
- Action bumps de-risked by reading upstream major release notes: one real breaker found and cleared (`download-artifact` v5 by-ID path rule — repo uses pattern downloads) and one hold justified (pages-artifact dotfiles).
- Vault link verified live (`auth status`: 4 devices, 4 links, authenticated).
- Production untouched by design (docs/CI-only changes): explorer still serving verified 1.0.25.

## 4. Residual Notes for Next Cycle

- The `release.yml` changes (artifact v7/v8, checkout v7, `signoff`) execute only on tags — first exercised at the v1.0.26 release. Watch the fill job + manifest PR DCO status there.
- Fleet roll + enrollment re-verification still gated on the next operator-code change.
- `windows-latest` / `macos-latest` and third-party actions remain unpinned; revisit when vendors announce forced migrations.

*End of report. Saved for review; not committed.*
