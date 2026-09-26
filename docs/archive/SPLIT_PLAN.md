# Module Split Plan: `apps/cli/main.rs` + `services/account/lib.rs`

Done-condition from the deep-dive (§12, Phase 4): **no file > 2.5k lines in
`apps/`**, coverage deltas reported per release, zero behavior change.

> Why a plan instead of the split: moving ~16k lines across two files without
> a compiler to check each step risks landing an unbuildable workspace. Every
> step below is sized so one move + one gate fits in a single reviewable
> commit. Do not batch steps.

## 0. Shared rules for every step

1. One module per commit; commit message names the source line range moved.
2. After each move: `cargo check -p <pkg>`, `cargo clippy -p <pkg>
   --all-targets -- -D warnings`, `cargo test -p <pkg>`, `cargo fmt`.
3. No behavior change per step: before starting, snapshot `cargo test
   --workspace` pass counts and `ciphervault completions bash` output; diff
   both after each step (completions output must be byte-identical).
4. Move tests with their code (unit tests stay `#[cfg(test)]` in the new
   module). Router-level account tests may graduate to `tests/` later.
5. Final gate per crate: full standing gate (fmt/clippy/test locked,
   node UI checks, forge) before merging the sequence.

## 1. `apps/cli/src/main.rs` (~10,600 lines)

`main.rs` keeps only: `Cli`/`Commands` (+subcommand) enums, `main`/`run`
dispatch, `cmd_completions`, the thin `cmd_watch` wrapper, (~900 lines).

Move in this order (shared leaves first, then command groups, dashboard last):

| Step | New module | Source lines | ~Size | Contents |
|---|---|---|---|---|
| 1 | `util.rs` (seed) | 1987–2168, 2266–2368, 7177–7222 | ~450 | gitignore helpers, `mask_operator_endpoint`, operator config + pool + regions, service-token request builder, `resolve_hardware_token`, UI host/browser helpers |
| 2 | `commands/auth.rs` | 1124–1165, 1178–1872 | ~750 | token-reader prefs, device identity, auth/device/vault-link commands, hosted revocation sync (leave `configured_operator_pool`, moved in 1) |
| 3 | `commands/track.rs` | 2627–2771 | ~150 | track/untrack |
| 4 | `commands/inspect.rs` | 2772–3046 | ~280 | status (+`StatusReport`), doctor (+`DoctorCheck`) |
| 5 | `commands/retention.rs` | 3285–3491 | ~210 | history, prune (+selection), rekey (+status) |
| 6 | `commands/init.rs` | 2368–2627 | ~260 | init |
| 7 | `commands/push.rs` | 3046–3285 | ~240 | push |
| 8 | `commands/restore.rs` | 3491–3603, 4190–4382 | ~310 | restore, pull |
| 9 | `commands/run.rs` | 3603–3934 | ~330 | run |
| 10 | extend `diff.rs` | 3939–4190 | ~250 | diff report + diff cmd (module already exists) |
| 11 | `commands/recover.rs` | 4382–4794 | ~410 | recover, peers |
| 12 | `commands/approvals.rs` | 4794–5049 | ~255 | approve list/sign/status |
| 13 | `commands/recovery_kit.rs` | 5049–5214 | ~165 | recovery export/test/split |
| 14 | `commands/anchor.rs` | 5214–5671 | ~460 | anchor, verify-anchor |
| 15 | `commands/feed.rs` | 5671–5810 | ~140 | public feed build/publish |
| 16 | `commands/hook.rs` | 5810–5886 | ~80 | hook install/check |
| 17 | `commands/token.rs` | 5886–6166 | ~280 | token subcommands |
| 18 | `commands/fleet_cli.rs` | 6166–6299 | ~135 | audit, repair |
| 19 | `dashboard/session.rs` | 6299–6457 | ~160 | private UI sessions, capabilities, context |
| 20 | `dashboard/account_proxy.rs` | 6457–6874 | ~420 | account proxy client + handlers |
| 21 | `dashboard/router.rs` | 6874–7222 | ~350 | shell/private/public routers (+`ui_router_tests`) |
| 22 | `dashboard/server.rs` | 7222–7324 | ~100 | `cmd_ui` server bring-up |
| 23 | `dashboard/handlers.rs` | 7324–7654, 8959–9655 | ~1,050 | private `api_*` handlers + guard (two regions merge) |
| 24 | `dashboard/collectors.rs` | 7654–8343 | ~690 | operator collector, telemetry persist, public ops handlers |
| 25 | `dashboard/finality.rs` | 8343–8911 | ~570 | feed verify, finality, canary, reorg, relayer/fleet handlers |
| 26 | `dashboard/fastcdc_api.rs` | 9655–9942 | ~290 | FastCDC inspection endpoints |
| 27 | `dashboard/files_api.rs` | 9942–end | ~320 | diff/files/restore/manifest/activity/workspaces endpoints |

Largest result (`dashboard/handlers.rs`, ~1,050) stays well under the cap.

## 2. `services/account/src/lib.rs` (~5,500 lines)

`lib.rs` keeps: `create_router` + re-exports (~150 lines).
Sibling `totp.rs` already exists — audit it in step 1 and merge or keep
side by side with `handlers/totp.rs`.

| Step | New module | Source lines | ~Size | Contents |
|---|---|---|---|---|
| 1 | `state.rs` + `error.rs` | 1–556 | ~560 | imports, views, `AccountState`, schema, `AccountServiceError` |
| 2 | `guards.rs` | 557–682 | ~130 | role defaults/rank, membership + `account_role_for`, strong sessions, id decode |
| 3 | `webauthn_crypto.rs` | 817–1097 | ~280 | CBOR/authenticator/attestation parsing + signature verify |
| 4 | `http.rs` | 1097–1481 | ~385 | error responses, rate limit + lockout alerts, CSRF, cookies, sessions |
| 5 | `db.rs` | 1481–1616 | ~135 | account/challenge views (or fold into `state.rs`) |
| 6 | `handlers/totp.rs` | 3773–4235 | ~460 | TOTP enroll/verify/revoke/options (+totp crypto fns at 712–751) |
| 7 | `handlers/webauthn.rs` | 3226–3773 | ~550 | WebAuthn registration + authentication |
| 8 | `handlers/revocation.rs` | 3006–3226 | ~220 | device/WebAuthn revoke + hosted propagation |
| 9 | `handlers/teams.rs` | 2466–3006 | ~540 | vault-link, invitations, memberships, recovery codes |
| 10 | `handlers/sessions.rs` | 2064–2466 | ~400 | login, sessions, handoff |
| 11 | `handlers/accounts.rs` | 1616–2064 | ~450 | account CRUD, capabilities, audit, device enroll |
| 12 | tests | 4349–5500 | ~1,150 | move each test with its module |

Leaf-first within handlers (totp has no intra-crate callers; accounts/sessions
are imported by others) keeps each step compiling.

## 3. Scheduling

- The two splits are independent crates: parallelizable across two workers.
- Suggested: account split first (fewer steps, smaller blast radius), then CLI.
- Report per-step: lines moved, `cargo test -p` counts before/after, clippy
  clean. Anything that changes behavior is a bug in the step, not the plan.
