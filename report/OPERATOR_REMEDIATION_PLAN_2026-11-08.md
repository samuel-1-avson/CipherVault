# Operator Remediation Plan — 2026-11-08

Source: `report/OPERATOR_AUDIT_2026-11-08.md`. Status legend: `[ ]` open, `[~]` in progress, `[x]` done (rebuilt + verified).

## P0 — demo blockers (rebuild dist from source)

- [x] **R1. Rebuilt from current source.** Green; fresh binary contains identities route, cursor pagination, both bypass warnings. **Plus: version identity shipped** — `/v1/info` now reports `binary_version` + `build_sha` (unsigned informational fields; old clients unaffected via serde defaults). Live-verified: `{"binary_version":"1.0.29","build_sha":"unknown"}` on ad-hoc builds; Docker bakes the SHA via `ARG GIT_SHA`.
- [x] **R2. Default fleet — resolved, no source change needed.** Fresh-source CLI already points at the working fleet (`op1/2/3.cipherv.online`); the dead `vault.cipherv.online` endpoints came from the stale dist binary. Verified in fresh binary strings (5 hits vs 0). Fix = ship rebuilt `dist/bin` (R1).

## P1 — fail-open auth: DONE (all verified)

- [x] **R3/R4.** Bypass warnings + case-insensitive Bearer. Live-verified.
- [x] **R5/R6.** Token-strength warning + FLEET_ADMIN split (`CIPHERVAULT_OPERATOR_ALLOW_FLEET_ADMIN_GRANT`). Live-verified both directions (0x10003 → 0x3 without opt-in, kept with it).
- [x] **R7/R8.** Fail-closed voucher profile (`--max-voucher-quota-bytes`); retention cap 36500 + checked_add. Live-verified boot refusal; suite green.

## P2 — economics, retention, exposure: DONE (all verified)

- [x] **R9.** Recovery GET 60/min tier (`CIPHERVAULT_RECOVERY_READ_LIMIT_PER_MIN`). Live-verified: 60 ok / 5×429 burst.
- [x] **R10.** Metrics loopback gate (`CIPHERVAULT_METRICS_PUBLIC` opt-out). Live-verified: 200 loopback / 403 LAN.
- [x] **R11.** `dist/config/operator-*.toml` → `.toml.example` with reference-only headers.
- [x] **R12.** `put_raw_record` env-gated (test opts in, suite green); P2P-without-trusted-keys boot warning; repair election requires routing membership.
- [x] **R13.** Per-key 64-challenge cap. Live-verified: 64 ok / 65th quota-rejected. Plus lease-list owner comparison made case-insensitive (was silently empty for upper-hex vault IDs); lib suite re-greened (81 passed).
- [x] **Drift visibility (re-architecture Phase 1).** Maintenance daemon records `binary_version`/`build_sha` per heartbeat (new columns + migration), prints versions, warns on fleet skew; dashboard fleet API exposes both fields. Live-verified end-to-end (v1.0.29 recorded, no false skew); old DBs migrate cleanly.

## Verification gate (every item)

`cargo test -p <crate>` for touched crates → `cargo build` → fresh-binary live checks (enroll round-trip, cursorless GET, push, drill) → `hermes plugins validate` (plugin untouched, regression only).

## Started 2026-11-08

- R1 build running in background; R3/R4 queued next (smallest, safest diffs).
- Untouched by plan: user-owned parallel edits (see `git status`; only operator/CLI/storage files below will be modified).
