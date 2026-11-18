# Test evidence — v1.0.32 (2026-11-09)

Release commit `dc45dd6` (tag `v1.0.32`); plugin pin commit `49da57f`
(plugin v0.4.2, catalog re-pin `73c1983`).

## Gates

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | ✅ pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked` | ✅ 0 errors |
| Rust tests (all 14 workspace crates, incl. new `verified_remote_push_clears_its_pending_upload`) | ✅ green, 0 failures |
| `python3 -m pytest plugins/ciphervault/tests -q` | ✅ 38 passed |
| `node apps/ui/audit.test.cjs`, dashboard container contract, release package manifests, verify_landing | ✅ pass |
| `node scripts/sync-version.cjs --check` | ✅ in sync at 1.0.32 |

## Live-fleet verification (production op1–op3.cipherv.online)

- Exact release binary (SHA-256 `d0cc7b37…38c`): `push` →
  RemoteDurable 3/3 verified and read back; audit anchor confirmed
  by 3 operators; pending-upload count unchanged by a successful
  push (previously grew by one per push).
- Exact **published** GitHub asset re-downloaded and re-verified:
  hash matches `SHA256SUMS.txt`; `agent-log verify-remote` → local
  head matches fleet anchor (7 entries, 3 operators); `lease list`
  authenticates.
- Re-test of the published v1.0.31 asset also authenticates fine —
  the earlier HTTPS failure was transient during the fleet
  token-rotation restart, not a binary defect.

## Clean room

Fresh `HERMES_HOME`: copy plugin → `hermes plugins enable
ciphervault` → `hermes ciphervault bootstrap` downloaded the
v1.0.32 asset, verified the in-source pinned SHA-256, `doctor`
returned live vault status; validator clean; doctor 7 tools /
3 hooks.

## Release

https://github.com/samuel-1-avson/CipherVault/releases/tag/v1.0.32
(3 Windows bundle zips + `ciphervault.exe` + `cv.exe` +
`SHA256SUMS.txt`; built locally from the tagged tree — GitHub
Actions billing-locked; `SHA256SUMS.txt` unsigned locally as in
v1.0.31; Linux/macOS prebuilt assets remain at v1.0.28.)
