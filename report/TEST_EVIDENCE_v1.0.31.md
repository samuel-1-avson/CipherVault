# Test evidence — v1.0.31 (2026-11-08/09)

All runs on the maintainer workstation (Windows 11, Rust stable,
Hermes v0.23.0) against commit `71a5940` unless noted.

## Rust workspace

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | ✅ pass |
| Lints | `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked -- -D warnings` | ✅ pass |
| Tests | `RUSTFLAGS="-D warnings" cargo test --workspace --locked` | ✅ **1,163 passed, 0 failed, 5 ignored, 90 suites** |

Notable suites: core crypto/format/snapshot/local-store/recovery,
chain (incl. new `private_v2_tx_hides_preimage_and_verifies`),
operator chain/swarm integration, CLI (incl. `run_injection`,
`watch_dry_run`, hook `--deep --json`, status JSON), account/MFA.

## Web surfaces

| Gate | Result |
|---|---|
| `node apps/ui/audit.test.cjs` | ✅ pass (expected version now derived from Cargo.toml) |
| `node tests/dashboard_container_contract.cjs` | ✅ pass |
| `node scripts/verify_landing.cjs` | ✅ pass |
| `python3 tests/release_package_manifests.py` | ✅ pass |
| `node scripts/sync-version.cjs --check` | ✅ in sync at 1.0.31 |
| `cargo deny check licenses bans sources` | ✅ ok |

## Hermes plugin

| Gate | Result |
|---|---|
| `hermes plugins validate … --install-deps` | ✅ passed, 16 checks, no warnings |
| `hermes plugins doctor ciphervault` | ✅ 6 tools, 2 hooks |
| `python3 -m pytest plugins/ciphervault/tests -q` | ✅ 25 passed |
| Secret source (live, demo vault) | ✅ working-copy + snapshot fetches return vault keys; values verified |
| Clean room | ✅ fresh `HERMES_HOME` → copy plugin → `hermes ciphervault bootstrap` downloaded v1.0.31 `ciphervault.exe` from GitHub Releases, SHA-256 `d31e7864…a717` verified against source-pinned hash + release `SHA256SUMS.txt`; `doctor` returned live status (`cli_version 1.0.31`) |

## Release

- `main` pushed; tag `v1.0.31` pushed. GitHub Actions is billing-locked
  on this account (pre-release gate job fails in 2s, same as v1.0.30),
  so Windows assets were built locally from the tagged tree and
  published with `gh release create`:
  https://github.com/samuel-1-avson/CipherVault/releases/tag/v1.0.31
  (3 bundle zips + `ciphervault.exe` + `cv.exe` + `SHA256SUMS.txt`).
- `dist/bin` rebuilt from v1.0.31 source; `dist/SHA256SUMS.txt`
  regenerated (the stale `ciphervault-tui-fixed.exe` entry removed).
- Once Actions billing is restored, tag pushes run the full matrix
  (Linux/macOS + attested provenance) unchanged.

## Known non-green / not-run

- Multi-platform release legs (Linux/macOS) — blocked on Actions
  billing; site copy keeps those assets labeled v1.0.28.
- Release `SHA256SUMS.txt` is unsigned locally (signing key lives in
  Actions secrets).
- External crypto audit: still outstanding (unchanged from v1.0.30).
