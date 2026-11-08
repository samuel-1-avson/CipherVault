# Operator Remediation Plan — 2026-11-08

Source: `report/OPERATOR_AUDIT_2026-11-08.md`. Status legend: `[ ]` open, `[~]` in progress, `[x]` done (rebuilt + verified).

## P0 — demo blockers (rebuild dist from source)

- [~] **R1. Rebuild `dist/bin` from current source.** Root cause of 5 audit findings (missing enroll/pagination/rate-limit/health/P2P routes). `cargo build -p ciphervault-operator -p ciphervault-cli` → replace dist binaries → re-run: enroll, cursorless GET, push, drill. (In progress in background.)
- [ ] **R2. Fix default fleet.** Fresh `init` writes dead `vault.cipherv.online/op/*` (`apps/cli/src/util.rs` `DEFAULT_PRODUCTION_OPERATORS`). Point at reachable fleet or fail loudly with enrollment instructions. Verify: fresh `init` → push succeeds without hand-editing `operators.json`.

## P1 — fail-open auth (source fixes, small + safe)

- [ ] **R3. Loud startup/runtime warning on non-strict bypass.** `require_control_auth` / `approval_scope` (`handlers.rs:83-87`, `118-135`) return `Ok` silently. Add `eprintln!` + metric every time the bypass is taken. Files: `services/operator/src/handlers.rs`.
- [ ] **R4. Case-insensitive `Bearer` parsing.** `extract_token` strips only exact `"Bearer "`; RFC-valid `bearer` silently downgrades to anonymous. (`handlers.rs:51-57`.) Verify: both cases authenticate.
- [ ] **R5. Service-token strength floor.** Presence-checked, strength never checked. Warn loudly at boot if `< 32` chars / low entropy (don't fail-closed: existing deployments). (`services/operator/src/main.rs:244-256`.)
- [ ] **R6. Split enroll vs grant-admin.** Service-token holder can self-grant `FLEET_ADMIN` on any vault via caller-controlled `permissions`. Require a separate, explicit admin-grant flag/env from enrollment. (`handlers.rs:147-159`, `methods_identity.rs:101-160`.)

## P2 — economics, retention, exposure (needs product decisions)

- [ ] **R7. Single voucher/quota profile.** Replace three knobs (`--require-write-vouchers`, max-quota, user-quota) with one documented profile; defaults stay as-is until decided. (`methods_chain.rs:66-68`.)
- [ ] **R8. Enforce retention bounds.** Reject `term_days=0` (done) *and* cap max; add expiry/GC or drop the "90-day minimum" copy. (`methods_leases.rs:52-63`; `handlers.rs:246`.)
- [ ] **R9. Scope anonymous recovery reads.** Strictest rate-limit tier + per-locator read audit counter on `GET …/records`. (`handlers.rs:625-638`.)
- [ ] **R10. Separate metrics listener.** Serve `/metrics` on loopback-only port (or gate); stop binding it to `0.0.0.0` by default. (`main.rs:38-43`; `handlers.rs:992-1000`.)
- [ ] **R11. `dist/config/operator-*.toml` — parse or delete.** Nothing reads TOML; launcher uses different ports. Either wire a config loader or remove the files so reviewed config == running config.
- [ ] **R12. P2P hardening trio.** Require `CIPHERVAULT_TRUSTED_PEER_KEYS` with repair on; gate `put_raw_record` behind `#[cfg(test)]`/flag; require holders be routing-table members before rendezvous election. (`methods_peers.rs:72-81`; `swarm/mod.rs:484-488`, `1153-1192`.)
- [ ] **R13. `term_days` overflow + `checked_add` on create path; per-key (not just global) challenge/session rate limits; `reject-new` instead of `evict-oldest` at 5k capacity.** (`methods_leases.rs`; `methods_sessions.rs:371-379`, `496-507`.)

## Verification gate (every item)

`cargo test -p <crate>` for touched crates → `cargo build` → fresh-binary live checks (enroll round-trip, cursorless GET, push, drill) → `hermes plugins validate` (plugin untouched, regression only).

## Started 2026-11-08

- R1 build running in background; R3/R4 queued next (smallest, safest diffs).
- Untouched by plan: user-owned parallel edits (see `git status`; only operator/CLI/storage files below will be modified).
