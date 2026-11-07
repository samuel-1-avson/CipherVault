# CipherVault CLI + TUI — Audit, Rating & Analysis

**Date:** 2026-11-07 (UTC)
**Scope:** `apps/cli` — Clap CLI (`src/main.rs`, `src/commands/*`) + Ratatui TUI (`src/tui/{mod,app,events,ui}.rs`) + `ciphervault tui --help`, built help output, and test suite (`cargo test -p ciphervault-cli --bins`).
**Method:** static read of all TUI sources (~6,000 lines), full `Commands` enum + `HELP_TEMPLATE` review, live `ciphervault --help` / `tui --help` runs, background-task and key-handling trace, `TestBackend` unit-test inventory. No screenshots — headless audit.
**Verdict: B+ (8.1/10).** The CLI is excellent. The TUI is a well-engineered *monitor + 3-action console* (track / push / anchor), not a CLI replacement — its biggest gap is coverage parity, not craftsmanship.

## Implementation status (2026-11-07)

Items 1, 2, and the pull half of 4 are implemented and tested (`cargo test -p ciphervault-cli --bins`: 227/227 on both binaries, +5 new tests):

- **Quit guard (rec. 1 / finding T2):** `[q]` quits immediately when idle; while push/pull/track/anchor/update runs, the first `[q]` arms a 5 s two-stroke guard and the second confirms. `Ctrl-C` stays unconditional. Read-only probes never arm the guard; the arm clears when mutations complete.
- **Logout confirm (rec. 2 / finding T6):** `[o]` now stages a `ConfirmAction::Logout` (`[y]/[Enter]` confirms, `[n]/[Esc]` cancels) instead of revoking immediately; no session → info status, no modal.
- **Pull action (rec. 4 / finding T1, partial):** `[d]` runs the read-only dry-run check (no confirm, writes nothing); `[D]` stages the real pull behind the confirm modal and applies with `force=false`, so dirty files abort with `pull --force` guidance. Runs as a background task with in-flight guard, status-line result, and local-state refresh on success. Footer (`[d/D]`), help modal, and confirm modal updated; 80-col footer kept exact-fit by moving `[u]` to roomy-only + single-space roomy separators.
- Still open from this batch: `restore` and `diff` actions (next highest-leverage coverage adds).

## Implementation status — restore + diff (2026-11-07)

TUI coverage went from ~7 to ~9 of ~42 CLI ops (`cargo test -p ciphervault-cli --bins`: 233/233 on both binaries, +6 tests):

- **Restore (`[R]`):** Snapshots tab or inside the snapshot inspector stages `ConfirmAction::Restore` (red OVERWRITTEN warning + "Push first to keep uncommitted work"); `[y]` runs `cmd_restore(id, to=None, dry_run=false)` via `spawn_blocking` in a background task, refreshes local state on success. In-flight restores report instead of stacking and arm the quit guard.
- **Diff (`[F]`):** read-only, no confirm. Snapshots tab: selected snapshot vs head (head itself diffs against the working tree to surface uncommitted changes); Files tab: selected file, head vs working tree. `generate_diff_report(..., reveal=false)` runs off-loop; results open a scrollable masked diff modal (`↑↓/j/k`, PgUp/PgDn, Home/End) with `+`/`-`/`~` color coding (bold fallback under `NO_COLOR`), a 1500-line cap with overflow notice, and per-line terminal-escape sanitizing.
- Discovery without footer cost: snapshot inspector footer line (`[R] restore · [F] diff vs head`), help modal `R / F` entry, confirm `y/Enter` line updated. Global footer untouched (still exact-fit at 80 cols).
- Still open: track-input completion, yank-CID, snapshot-modal push-message line — the remaining quick wins.

---

## 1. Scores

| Area | Score | Grade | One-line justification |
|---|---|---|---|
| CLI information architecture & help | 9.2/10 | A | Role-grouped `HELP_TEMPLATE` (Developer / Node runner / Fleet / Account / App), `cv`↔`ciphervault` alias handled, ~42 functional subcommands + `help`. Verified live. |
| CLI consistency & safety | 8.0/10 | B+ | Strong flag conventions, `--dry-run`/`--force`/`--local` discipline; `Drop` vs `prune`, `recover` vs `recovery` naming is the main wart. |
| TUI visual design & layout | 8.5/10 | A− | 7-tab header + badge + footer, rounded bordered cards, latency-tier colors, responsive tab-strip windowing and footer fallback. |
| TUI keyboard interaction | 8.0/10 | B+ | Full vim+arrow+PgUp/PgDn+Home/End tables, `1–7`/`Tab`, `[?]` help, confirm-gated destructive keys. `q`-quits-anywhere is the main risk. |
| TUI functional coverage vs CLI | 5.0/10 | C | ~6 of ~42 CLI operations are executable in-TUI; everything else is read-only or absent (see §4). By design, but undocumented in-app. |
| TUI robustness (async, terminal) | 9.0/10 | A | Every blocking call (operator poll, PC/SC, FastCDC, push/anchor, update) in `JoinSet` background tasks with in-flight guards; panic hook restores terminal; `MIN 62×16` fallback. |
| TUI accessibility / degraded terminals | 8.0/10 | B+ | `NO_COLOR` + `dumb`-TERM honored, inverse-video selection fallback, text-not-color status signals, `sanitize_cell` strips control chars. No mouse/screen-reader path. |
| TUI security hygiene | 9.0/10 | A | TUI never handles vault plaintext beyond what the store already exposes; hosted TOTP stays in browser; object probe is presence-only; confirm modal for L2-cost anchor; single-shot confirm. |
| Testability | 7.0/10 | B− | 222/222 bin tests pass; ~20 `TestBackend` render tests in `ui.rs` (tabs, modals, tab-strip, probing-vs-offline, sanitize). No TUI integration test (no PTY run) and `cargo test -p ciphervault-cli tui` matches 0 test names. |
| **Overall** | **8.1/10** | **B+** | Ship-quality monitor; promote to A− by closing the coverage-signposting + quit-guard + track-input gaps. |

---

## 2. What was audited

**CLI surface (verified via `cargo run --bin ciphervault -- --help`):**

- Developer vault & secrets (22): `init, track, untrack, status, push, pull, history, prune, rekey, restore, recover, recovery, diff, hook, repo, context, project, secret, migrate, audit, repair, lease`
- Run & automate (6): `run, watch, anchor, verify-anchor, approve, token`
- Node operator (2): `node (setup/start/stop/status/backup/standing/p2p-info), peers`
- Fleet (3): `invite, voucher, publish-public-feed`
- Account & devices (3): `auth, device, vault`
- App (6): `update, release, ui, tui (--poll-ms, default 3000), doctor, completions`
- Sources: `apps/cli/src/main.rs` (2,672 lines), `src/commands/*` (~40 files), `src/dashboard/*`.

**TUI sources (measured):**

| File | Size | Lines | Role |
|---|---|---|---|
| `tui/app.rs` | 105 KB | 2,819 | `TuiApp` state, 7 tabs, 5 tables, background spawns, `drain/apply_task_out` |
| `tui/ui.rs` | 101 KB | 2,780 | `draw` + 7 tab renderers + 5 modals + tab-strip/footer/small-terminal helpers + ~20 tests |
| `tui/events.rs` | 10 KB | 270 | single `handle_key_event` dispatcher |
| `tui/mod.rs` | 3.7 KB | 111 | raw-mode/alternate-screen setup, panic hook, 50 ms tick loop |

---

## 3. CLI audit

### Strengths (confirmed)

1. **Help is grouped by persona, not alphabet.** `HELP_TEMPLATE` splits "Developer: vault & secrets", "Developer: run & automate", "Node operator", "Fleet administration", "Account & devices", "App" — with a "Two roles, one binary" preamble and per-invocation `@@BIN@@` substitution so `cv` help never shows the wrong name (`bin_name_for_argv0`, `help_template_for`). A test asserts every subcommand appears in the template.
2. **Sane, repeated flag vocabulary.** `--dry-run` (pull/prune/restore), `--force` (init/untrack/pull/recover), `--json` (status/diff/doctor), `--local` (push/ui), `--replicas/--concurrency` (push/repair). Low surprise across 42 commands.
3. **`tui` command itself is minimal and correct:** one flag, `--poll-ms` (default 3000 ms). Poll loop honors it via `TuiApp::new(Duration::from_millis(poll_interval_ms))`.
4. **`doctor` + `update` + `completions` round out operability.** Self-checks, signed self-update (also wired into the TUI modal), and shell completions for both binary names.

### Issues

| # | Severity | Finding |
|---|---|---|
| C1 | Low | `recover` (kit/shares → dir) vs `recovery` (subcommands) vs `repair` vs `prune` are easy to confuse; help lines disambiguate but names don't. Consider `recover` → `restore-vault` alias or cross-references in descriptions. |
| C2 | Low | `history` takes zero flags (no `--limit/--json`), inconsistent with `status --json / --overview` and `diff --json`. DAG consumers must parse human text. |
| C3 | Info | `ui` has four mutually-aware modes (`--local/--serve`/default/cloud `--url`); correct `conflicts_with` wiring, but `--local` + `--serve` confusion deserves an example line in long help. |

---

## 4. TUI audit

### 4.1 Tabs — what each does and how well

| # | Tab | Type | Rating | Notes |
|---|---|---|---|---|
| 1 | Overview | Dashboard | 9/10 | Vault identity (elided `vault_id/head/locator`), epoch, protected volume, snapshot count, operator/token/account health, zero-knowledge axioms card. Honest empty states ("No operators configured", "Polling…", "Not Initialized (Run 'ciphervault init')"). `elide_hex` passes non-hex status strings through unmangled (tested). |
| 2 | Files | Table + actions | 8/10 | `#/path/size/file-id/disk-status` with `✓ Present / ✗ Missing`. `[t]` track modal, `[x]` confirm-gated untrack, `[Enter]` jumps to FastCDC chunks. Missing: multi-track, rename hint, `pull`/`restore`/`diff` entry points for a selected file. |
| 3 | History (Snapshots) | Table + inspector | 7/10 | CID/parent/message/timestamp/`[HEAD]` badge; `[Enter]` opens read-only Snapshot Inspector (id/parent/message/time/"sealed files (encrypted manifest)"/head?). Honest `files_count: None → "unknown"` (encrypted manifest, can't count without decrypt — correct call). Missing: restore-by-snapshot, diff-by-snapshot, prune from here. |
| 4 | Operators | Table + detail | 9/10 | Best tab. `ONLINE/OFFLINE/PROBING` (never labels unpolled as offline — `polls_completed==0` → `PROBING`/`POLLING…`, tested), median-of-5 latency window + raw samples (`41 43 1200`), `last_error` retention, tiered latency colors with text fallback. `[r]` re-poll. |
| 5 | FastCDC | Inspector | 8/10 | Real chunker data: index/offset/length/CID/Gear fingerprint/boundary (`S/L/max/tail`)/entropy/dedup flag + metrics header. 64 MiB `MAX_INSPECT_BYTES` cap with explicit notice instead of freeze (tested). Cache-aware (`InspectCacheKey` path+size+mtime). Missing: profile switcher in-app (uses `config_from_env`). |
| 6 | Token | Status | 7/10 | Readers/slots 9C+9D readiness/last-error; blocking PC/SC correctly off-loop via `spawn_blocking`. Honest "No PIV Token / not probed" vs "Probing PC/SC bus…" (tested). But: status-only — no slot/PIN/select actions (those live under CLI `token`), so the tab can feel dead on machines without hardware. |
| 7 | Explorer | Mirror of web explorer | 8/10 | Cluster health, anchor-feed head, presence-only object quorum (`SATISFIED`, `2/3 present`), operators + checkpoints tables, `[/]` CID search modal. 30 s telemetry / 60 s feed caches; auto-refresh while visible. Correctly never fetches object bytes. |

### 4.2 Keybindings (from `events.rs` + `render_help_modal` + footer)

`1–7` direct · `Tab/←/→` cycle · `j/k/↑/↓` move · `PgUp/PgDn` page · `Home/End` edges · `Enter` inspect · `p` push · `a→y/Enter` anchor-confirm · `t` track · `x→y` untrack-confirm · `r` refresh · `l/o` account login/logout · `u` update check · `/` object find · `?` help · `q` / `Ctrl-C` quit · `Esc` dismiss-only (never quits — deliberate and correct).

Modal precedence is right: `help > snapshot > confirm > track > explorer-search > update > global`, with `confirm` single-shot (`take()` — double-`Enter` can't double-fire an L2 transaction).

### 4.3 Architecture: why the TUI feels snappy

- **Never blocks the event loop.** Operator polls, explorer refresh, object probe, token probe, push, anchor, track, update check/apply, and FastCDC inspection all run in a `JoinSet<TuiTaskOut>`; the 50 ms tick loop only `try_join_next()`s via `drain_tasks()`. Verified in `mod.rs` + `app.rs:1226–1430`.
- **Duplicate-work guards per task kind** (`poll_in_flight`, `token_in_flight`, `push_in_flight`, `anchor_in_flight`, `track_in_flight`, `update_in_flight`, `inspect_in_flight`, `object_probe_in_flight`). Rapid `[p]`/`[t]`/`[a]` mashes report "already running" instead of stacking store writes or L2 submissions.
- **Stale-result rejection.** `OperatorsPolled` carries the polled endpoint list and drops itself if config changed mid-flight; inspection carries an index and drops if selection moved. No late-write clobbering.
- **Terminal hygiene.** Raw mode + alternate screen + hidden cursor, panic hook restores cooked mode on crash, clean `LeaveAlternateScreen` + `show_cursor` on `q`. `stdin().is_terminal()` gate with a clear bail message outside a TTY.
- **Responsive chrome.** Tab strip windows around the selection with `◀ ▶` markers (column-counted, tested at width 38); footer collapses from labeled hints to keys-only below 115 inner columns so `[q]`/`[1-7/Tab]` survive at 80 columns (tested); sub-`62×16` terminals get an explicit "Terminal too small … `WxH`" screen instead of a panic on zero-height tables.

### 4.4 Honesty details worth keeping

- Unpolled operators say `PROBING`, not `OFFLINE`; header badge says `POLLING…`, not `0/N RESPONDING` (unit-tested both).
- Snapshot file counts say `unknown`, not today's tracked count (encrypted manifests — architecturally unavoidable, correctly surfaced).
- Token tab distinguishes "not probed" from "no token".
- Update boot-check is silent on failure (offline is normal); manual `[u]` always reports.
- `sanitize_cell` strips control chars (incl. `ESC`) from paths/endpoints/feed text/status before render — terminal-spoofing safe; `use_color()` honors `NO_COLOR` and `TERM=dumb` with bold/reverse fallbacks so signals survive monochrome.

---

## 5. Findings (TUI)

| # | Severity | Finding | Evidence | Recommendation |
|---|---|---|---|---|
| T1 | **Medium** | **Coverage gap: TUI executes ~6 of ~42 CLI ops.** Push/track/untrack/anchor/refresh/update/login only. `pull`, `restore`, `diff`, `prune`, `rekey`, `repair`/`audit`, `run`, `watch`, `secret/project` scoping, `hook`, `lease`, `approve`, `recover` have no in-TUI path; Snapshot Inspector is view-only. Users must drop to shell mid-flow (e.g. push in TUI → pull/restore in CLI). | `events.rs` action arms; `spawn_*` inventory (`push/anchor/track/update/object-probe/token-probe/explorer`) | Either (a) document the TUI as "monitor + quick-push console" in the Overview tab + `--help`, or (b) add the three highest-leverage actions first: `pull (dry-run aware)`, `restore (snapshot → dir, confirm-gated)`, `diff (selected snapshot vs head, read-only)`. |
| T2 | Medium | **`q` quits instantly from anywhere**, including mid-push/mid-anchor with background tasks in flight. No dirty-state guard. | `events.rs: q → should_quit = true` unconditionally | Confirm on `q` while `push_in_flight \|\| anchor_in_flight \|\| track_in_flight \|\| update_in_progress`, or at minimum a "tasks running — [q] again to quit" two-stroke. |
| T3 | Low | Track modal is a bare single-line input: no tab-completion, no directory listing, no multi-path, no existence pre-check (failure surfaces only after background task completes). | `render_track_modal`, `spawn_track` | Add `fs`-based completion + "file exists / will add" preview line; accept space-separated paths. |
| T4 | Low | Snapshot Inspector shows synthetic `message` ("Epoch #N (Counter…)") not the user `--message` from `push`; no manifest size/chunk count per snapshot (manifests encrypted — understandably absent, but the inspector doesn't say what *would* require decryption). | `refresh_local_state` message format; `render_snapshot_modal` | Show push message when available; add one "why file list is sealed" footnote line in the modal. |
| T5 | Low | No mouse click, no copy-to-clipboard for CIDs/commitments, no scrollback search inside tables. CID transcription is manual. | No mouse handling in `events.rs`; no clipboard dep in `apps/cli/Cargo.toml` | Add `y`/`Y` yank-selected-CID-to-clipboard (via `arboard`/`clipboard`) + mouse-click row select as opt-in. |
| T6 | Low | `[l]` login / `[o]` logout sit on the global map next to table nav with no `[o]`-conflict but high typo adjacency to `[p]` push; logout is immediate, no confirm, and revokes the local session. | `events.rs: l/o` arms | Confirm-gate `o` like `x`/`a`, or move session actions behind a modifier. |
| T7 | Info | FastCDC profile is env-driven (`config_from_env`) with no in-TUI indicator control beyond the metrics header line; large-file cap (64 MiB) message exists but the threshold isn't shown until hit. | `render_fastcdc_tab`, `MAX_INSPECT_BYTES` | Show active profile + cap in the tab title bar persistently. |
| T8 | Info | `TERM`-unset environments default to color-on (`unwrap_or(true)`); correct per `NO_COLOR` spec, fine — noted for SSH-without-TERM edge cases. | `use_color()` | No change; consider `CLICOLOR`/`CLICOLOR_FORCE` for completeness. |

**What was checked and cleared (no bug):** explorer-search buffer lifecycle — `spawn_object_probe()` clones `explorer_search_buffer` into the async task *before* `events.rs` clears the buffer, so the probe uses the typed CID (ordering verified in `events.rs:69–76` + `app.rs:1257–1273`).

---

## 6. Recommendations (priority order)

1. **Close or signpost the coverage gap (T1).** Cheapest high-value fix: one Overview-card line + `tui --help` long-about stating "TUI monitors and quick-pushes; pull/restore/diff/secret ops stay in CLI." Then add `pull` → `restore` → `diff` actions in that order.
2. **Quit guard during in-flight mutations (T2).** ~15 lines in `handle_key_event`.
3. **Track-input completion + yank-CID (T3+T5).** Biggest daily-UX wins for a secrets tool.
4. **Snapshot modal honesty line (T4).** One sentence explaining sealed manifests.
5. **Logout confirm (T6).** Reuse the existing `ConfirmAction` pattern.
6. **TUI integration test (Test §):** one PTY/`TestBackend` script test driving `1–7/p/?/q` + a `cargo test` name filter that actually matches (current `tui` filter matches 0 test names since tests live in `--bins`).

---

## 7. Verification appendix

- `cargo run --bin ciphervault -- --help` → exit 0; role-grouped help with all command groups rendered (§2 list).
- `cargo run --bin ciphervault -- tui --help` → exit 0; single `--poll-ms <POLL_MS> [default: 3000]` option.
- `cargo test -p ciphervault-cli --bins` → **222 passed / 0 failed** (×2 binaries, `ciphervault` + `cv`), including the `ui.rs` `TestBackend` render suite (explorer/quorum/checkpoints, search modal, update modal + install-lock, file-window scrolling + `rows a–b of N` label, token absent/probing, FastCDC boundary column + cap notice, overview honesty, tab-strip windowing/markers, footer narrow fallback, probing-vs-offline, operator detail samples + error, snapshot modal, `elide_hex` passthrough).
- `cargo test -p ciphervault-cli tui` → 0 matched (filter matches no test *names*; suite is reached via `--bins`). Filed as rec. 6.

---

*Report saved from live audit of `apps/cli/src/main.rs`, `apps/cli/src/tui/*`, `apps/cli/src/dashboard/*`, and executed CLI/test output. Ratings are reviewer judgment against CLI/TUI peers (lazygit, k9s, gh-dash class): craftsmanship is high, parity is the gap.*
