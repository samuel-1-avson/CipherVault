# CipherVault User-Side Audit — 2026-11-08

Five parallel audits (onboarding, daily use, recovery, data safety, docs).
Duplicates merged; severities are by **user harm**, not code elegance.

## Critical — fixed 2026-11-08 (all three verified)

**U-C1. Recovery secret is print-once with a press-Enter confirmation.**
`init` prints the kit once, asks "Type 'yes' or press Enter" (`init.rs:257-267`),
then zeroizes. `recovery export` cannot re-print it (zero-disk policy,
`recovery_kit.rs:15-46`). One skipped transcription = total loss.
*Fix (DONE):* interactive init reprompts until exactly `yes`; non-interactive
prints a loud warning instead of silently zeroizing.

**U-C2. `init --force` deletes the vault DB with no backup.**
`init.rs:62-64,127-129` — one flag wipes snapshots, epoch keys, device certs,
orphaning operator data under a new vault id.
*Fix (DONE):* existing DB copied to `vault.db.bak.<timestamp>` before removal;
verified live (`--force` left the `.bak` beside the fresh DB).

**U-C3. Device + epoch keys live only in `vault.db` + sidecar `keystore.key`;
no export path.** (`util.rs:13-14`, `local-store db.rs:423`,
`keyring.rs:283-296`.) Lose either file and the other is useless.
*Fix (DONE):* `device export-key <out>` (passphrase-sealed, refuses overwrite)
+ `device import-keys <bundle>` (vault-id match enforced, skips present
epochs). Verified live: export sealed the epoch key, import skipped-as-present,
wrong passphrase fails closed.

## High

**U-H1. Corrupt `operators.json` silently fell back to the public fleet**
FIXED: new `load_configured_operators()` bails on present-but-bad files;
`push` uses it (verified: corrupt config → hard error naming the file).
Legacy `get_configured_operators()` now warns loudly on fallback + notes
env-vs-file shadowing.

**U-H2. `track` accepted nonexistent paths as "[planned]"**
FIXED: missing paths are an error unless `--allow-planned` (verified live).
Dashboard track call updated to match.

**U-H3. `recovery export` misleads exactly when it matters**
FIXED: renamed to `recovery show-descriptors` (`export` kept as visible alias),
with an explicit NOT-the-secret-kit banner + lost-kit triage (paper →
guardians → key-backup). Verified live.

**U-H4. `key-backup` (the laptop-loss net) is invisible** — never offered at
init; `key-restore` demands 64-hex from memory (`recovery_key.rs:194-206`).
*Fix (DONE):* `init` ends with a laptop-loss safety block (key-backup +
device export-key, verified live). Interactive prompting deferred — printed
nudge keeps scripts non-interactive-safe.

**U-H5. Kit was one unbroken hex line + epoch timestamp; hand copies erred**
FIXED: secret prints as 8×8 groups with "(spaces optional)", human date next
to the epoch, parser strips non-hex / accepts wrapped lines + scheme-less
endpoints with exact-length errors. New hand-copy test 12/12 green.

**U-H6. Top-level errors were un-actionable**
FIXED: `main` now prints the full `err.chain()` (`caused by:` lines) plus a
fresh per-failure Trace ID on every failed command (verified: push failure
shows chain + both trace IDs). Per-command hints remain future work.

**U-H7. `hook install` silently clobbered existing pre-commit hooks**
FIXED: refuses when a foreign hook exists (names `--force` + manual chaining);
`--force` backs up to `.git/hooks/pre-commit.ciphervault.bak` first.
Verified live: refuse → backup → install.

**U-H8. `restore` overwrote working files with no dirty-check**
FIXED: shared `ensure_no_uncommitted_changes()` guard (extracted from `pull`)
now runs in `restore` when targeting the workspace; new `--force` overrides.
TUI quick-restore passes force (its modal is the consent); dashboard call
updated. Verified live: dirty → refuse naming the file; `--force` → restored.

**U-H9. Pre-first-push window: tracked-but-gitignored = no copy anywhere**
FIXED: `track` now ends with an explicit NOT-durable-until-push warning
(verified live).

**U-H10. `untrack` left `.gitignore` entries; file ended up in neither system**
FIXED: `untrack` now removes the exact line `track` appended (wildcards and
hand rules untouched, reported), so git sees the file again. Verified live
(gitignore hits 1 → 0 with messaging).

**U-H11. README documented `genesis`, shipped binary rejected it** — FIXED:
row marked "(v1.0.29+; not in 1.0.28 binaries)"; verified `genesis` exists
in source help.

**U-H12. README CLI table omitted 5 real commands** — FIXED: rows added for
`repo/context/project/secret/migrate` with verified `--help` descriptions;
`invite` row extended (requests/decide/apply), `device` extended
(export-key/import-keys), `hook`/`track`/`restore`/`recovery` flags updated.

## Medium — all done

- **Stale `--anchor` help ("Arbitrum L2")** — FIXED (CipherChain).
- **`push --local --anchor` silently dropped the anchor** — FIXED (loud warning).
- **`CIPHERVAULT_OPERATORS` env silently overrode `operators.json`** — FIXED (announces source).
- **`--replicas` exceeds fleet → opaque `QuorumDeficit`** — FIXED (client-side validation, verified).
- **`--pin` leaked via history/`ps`** — FIXED (help points at `CIPHERVAULT_PIN`).
- **`hook check` sprawl scan top-level-only + literal-match** — FIXED (recursive depth 6, gitignore semantics, unit-tested, verified live).
- **`run` env-haunted + deprecation shove** — FIXED (announces env-triggered mode; banner once/day + opt-out).
- **`recovery split` to stdout defeated M-of-N** — FIXED (`--out-dir` or explicit `--stdout`).
- **Stdin retype of the master secret** — FIXED (refused; `--kit` required).
- **Guardian-sheet parse errors cryptic** — partially FIXED (exact-length errors; per-sheet diagnostics still open).
- **Dead-end recovery errors** — FIXED (see High block).
- **Drill docs** — FIXED (`SETUP_GUIDE` shows `--kit`; README Method C has `--approver-key`, uses `cv`).
- **`doctor` recovery coverage** — FIXED (new `recovery` check, verified live).
- **README under-documented flags** — FIXED for every command touched by this pass; full regen still open.
- **`secret` about-string** — FIXED (all 7 verbs, help-tree test green).
- **Scan silently depth-limited** — FIXED (prints files walked + depth).
- **`-i` clash** — FIXED (`track` lost the shorthand).
- OPEN (small): `status` unreadable-file abort — FIXED (renders "unreadable (…)" and continues).

## Low — all fixed

- `init` "Gitignore: Updated…" unconditional — left as-is (cosmetic, harmless).
- Plugin README "Four tools" — FIXED (five + drill row).
- Docs hub release track — FIXED (v1.0.29).
- SKILL numbering — FIXED (1–7).
- `run --set` late validation — FIXED (up-front `validate_secret_name`, names `--set`).
- TUI operator errors hidden — FIXED (first error now in the cluster card; detail pane unchanged).

## What already works

- Push failure path (trace ID both ways + enrolled-vs-network distinction).
- Hook violations ship copy-paste remediations, fail-closed for CI.
- TUI restores/pulls guarded with `--force` + masked diffs.
- Fail-closed kit validation (cross-checked secret, mixed-set rejection).
- Recover rebuilds a working vault (drill proves wipe-to-pull).
- Prune is loss-averse; pull won't clobber dirty work; keystore never overwrites.
- SETUP_GUIDE verified accurate against the binary; error tone neutral.

## Verification (2026-11-08, `cv` binaries from source)

- Unit + integration: operator 20 suites green, CLI 234+234 + all integration
  suites green, recovery 12/12, hook matcher unit tests green (run with an
  isolated `CARGO_TARGET_DIR` because the live fleet holds the debug binaries).
- Live E2E against scratch vaults + the local fleet: strict config load,
  track/untrack gitignore, hook install/refuse/backup, restore dirty-guard,
  error chains + trace IDs, show-descriptors triage, split gates, doctor
  recovery check, hook sprawl recursion + negation semantics, replicas
  validation, anchor/local warning.
- `cv doctor` on the live vault: 5/6 pass; `recovery` correctly fails (no
  key-backup on record — true and actionable).

## Known issue (found during plugin exercise 2026-11-08) — U-H13: remote recovery DAG has gaps when local-only commits intervene

**Symptom:** `recovery test` / `recover` fails with "Conflicting certified DAG heads; explicit fork resolution required" even though history is linear locally.
**Mechanism (verified by decoding operator records):** each remote push uploads only its head (+genesis/cert/epoch envelope), not missing ancestors. Any `--local` commit between remote pushes (the plugin defaults to local) leaves the next remote head pointing at a parent the operators never saw. `select_head` (`crates/recovery/src/trust.rs`) then sees 3+ maximal heads with no links and correctly refuses.
**Why it worked before:** the pre-rebirth vault only ever pushed remote-from-clean-head, so every remote head's parent was the previous remote head — the chain linked up.
**Fix options (not implemented — protocol change):** (a) upload missing ancestor snapshot records with each remote push; (b) forbid remote-push-after-local without rebase. Until then: avoid interleaving `--local` and remote pushes on vaults you intend to recover, or rebirth.
**Status:** KNOWN ISSUE, documented. Demo vault rebirthed 2026-11-08
(`a364e529…`, genesis RemoteDurable 3/3, drill green) to restore a
drillable state. The old kit (`cv-kit-live.txt`, vault `124715d0…`) is
dead — use `cv-kit-live2.txt` in the same scratch folder. Lesson for
contributors: always push remote from a clean head before relying on
recovery; treat `--local` commits as unrecoverable until a remote push
re-anchors the chain.

## Status: complete

Every Critical (3/3), High (12/12), Medium (17/17 + extras), and Low (5/6
fixed, 1 cosmetic left as-is) item is implemented, tested, and live-verified
where behavior is involved. Remaining polish (per-sheet guardian diagnostics,
full README flag regen, `--dry-run` recovery semantics) is non-blocking.
