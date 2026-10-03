# Explorer + TUI Deep-Dive Audit (2026-10-03)

Scope: the hosted Explorer at `https://vault.cipherv.online` (dashboard
backend `apps/cli/src/dashboard`, frontend `apps/ui`) and the terminal
UI (`apps/cli/src/tui`). Method: full read of `apps/ui/index.html`
(1,915 lines) and the dashboard routers/guards/handlers, targeted
reads of `apps/ui/app.js` (~6,100 lines) at every trust seam (rendering,
fetch, auth, secrets, guidance), live probing of production endpoints,
and executed test suites. No issue below is speculative — each cites a
file, line, and the evidence checked.

## Verdict

No blocking issue. The Explorer is safe to keep serving daily users:
private APIs are unreachable from the internet (proven live, not just
in tests), output encoding is systematic, the CSP is strict with zero
browser violations, and the TUI has no crash or secret-display paths.
The findings are one medium display-trust issue (F1), a handful of
low-severity correctness/UX items, and hardening notes. Fixing F1–F4
is the recommended bar before inviting outside users.

## Findings at a glance

| ID | Severity | Area | Issue |
|----|----------|------|-------|
| F1 | Medium | UI display | Health score defaults to 100% / ✓ VERIFIED with zero data |
| F2 | Low-Med | UI secrets | TOTP enrollment secret stays in hidden DOM after confirm |
| F3 | Low | UI docs | Shortcuts help lists wrong tab order/count for 1–8 |
| F4 | Low | UI docs | Recovery tab omits required `--to` from `recover` command |
| F5 | Low | UI wording | "Anchor … to Arbitrum One" while chain is Sepolia |
| F6 | Low (UX) | UI controls | Reveal Secret / Copy Key buttons confuse; copy is dead |
| F7 | Low (a11y) | UI a11y | Anchor-tx copy button lacks `aria-label` |
| H1 | Low (hardening) | UI XSS defense | 4 unescaped `truncateHash` interpolations (safe today via server charset checks) |
| B1 | Low | Backend | `api_vault_handler` mints a signing key just to discard it on error path |
| T1 | Note | TUI | Track-modal disk write runs on the event thread (small, acceptable) |
| T2 | Trivial | TUI | Help-modal comment says "any key", code closes on Esc/?/Enter only |

## What was verified working

**Backend isolation (live, 2026-10-03 ~20:21 UTC).**
`GET /api/context|operators|explorer/overview|vault` → 200 in
231–842 ms; `GET /api/guardians` and `POST /api/snapshots` → 403;
unknown path → 404; `/metrics` exposes version + public telemetry
only. Headers: strict CSP, `no-store`, `nosniff`, `SAMEORIGIN`, HSTS
with preload. This matches the `public_router_allows_only_explicit_public_api_routes`
test, so prod behavior and test coverage agree.

**Router/guard design** (`router.rs`, `handlers.rs:327-475`, `server.rs`).
Separate private/public routers; private mode refuses non-loopback
bind; compose binds `127.0.0.1:8080` behind Caddy; private mutations
require loopback Host + matching Origin + session cookie + account
session; public side has per-IP rate limits (30 obj / 600 general per
min) with a correct rightmost-XFF trust model behind Caddy's
single-value `X-Forwarded-For`; 2 MiB body cap both routers with 413
before upstream contact. Rate limiting fails open past 10k clients —
deliberate and documented, accepted.

**Operator data sanitization** (`handlers.rs:551-583`, `collectors.rs:17-27`).
Signing keys must be 64-hex or become `INVALID_KEY_FORMAT`; operator
IDs are charset-filtered; retention terms are escaped client-side
(`app.js:1863`). Combined with `script-src 'self'`, there is no
operator-driven script-execution path; see H1 for the residual note.

**Frontend test suites (executed).** `node --test apps/ui/audit.test.cjs`
→ pass; `node --test apps/ui/csp.browser.test.cjs` → pass in real
Chromium with zero policy violations. `cargo test -p ciphervault-cli
--bin ciphervault dashboard::` → 59 passed. `... tui` → 43 passed.

**TUI safety.** Zero non-test `unwrap/expect/panic` (the three
`expect`s are inside `#[cfg(test)]` chunker-verification helpers);
panic hook restores the terminal; TTY preflight; network/smartcard
work runs on background tasks with duplicate-spawn guards; the TUI
never renders secret values (no decrypt-to-screen path exists).

**New explorer guidance.** `renderHostedSessionSummary` (`app.js:432`)
requires `authenticated === true` with a non-empty account id, uses
`textContent` only, and degrades vault counts to "loading…" — no
spoof or injection surface.

## Finding details

### F1 — Health score is green before any evidence (medium)

`apps/ui/index.html:516-542` hardcodes `100%` plus `✓ VERIFIED /
✓ FRESH / ✓ VALID / ✓ PASS`. `renderSecretHealth` (`app.js:5292-5363`)
starts at `score = 100` and only subtracts; a fresh vault, an empty
response, or a failed load all keep the green defaults. Users (and
screenshots) see "verified" with no verification behind it.
Fix: default the markup to unknown (`--`, "Not assessed") and only
render a score/status after data arrives; treat empty/failed loads as
"unknown", never 100%.

### F2 — TOTP secret lingers in hidden DOM (low-medium)

`confirmTotpEnrollment` (`app.js:1232-1255`) hides the enrollment
panel but never clears `totp-enrollment-uri`, `totp-enrollment-secret`,
or the code input. The one-time secret stays in the DOM (and browser
memory) until page reload. Fix: clear all three fields plus
`state.totpEnrollment` on confirm, cancel, and modal close.

### F3 — Shortcuts help describes wrong keys (low)

The modal (`index.html:1896`) claims `1-8` map to "Operators, DAG,
Diff, Files, Guardians, Relayer, Fleet, FastCDC". The handler
(`app.js:5138-5146`) maps `1-9` positionally over *visible* tabs, whose
order is Operators, Explorer, Relayer, Fleet, My Data, Tracked
Secrets, DAG, Diff, FastCDC, … — different order, different count,
mode-dependent. Fix the help text to describe positional 1–9 over
visible tabs (and note tabs past 9 need clicks).

### F4 — Recovery command missing required flag (low)

The Recovery tab (`index.html:1169`) shows
`ciphervault recover --kit recovery_kit.txt`, but `recover --help`
requires `--to <DIR>`. Copy-paste fails. Fix: append
`--to <RESTORE_DIR>` (and mirror it in the copy button's `data-code`).

### F5 — "Arbitrum One" button title (low)

`index.html:306` titles the Anchor action "…to Arbitrum One".
Anchoring runs on Sepolia (chain 421614); mainnet promotion is gated
(`docs/MAINNET_PROMOTION_EVIDENCE.md`). The page is otherwise careful
("Arbitrum Relayer", Sepolia noted in scripts). Fix: title it
"…to Arbitrum".

### F6 — Dead/confusing secret buttons (low, UX)

`btn-toggle-secret` reveals an explanatory sentence (safe,
`textContent`-only, `app.js:3474-3498`), but `btn-copy-secret` has no
listener at all — a dead control next to a "Zero-Knowledge" banner.
Fix: remove the copy button (or wire it to copy the `recover`
command) and rename the toggle to something truthful such as "Why is
this hidden?".

### F7 — Icon-only button without accessible name (low, a11y)

`#btn-copy-anchor-tx` (`index.html:880`) has `title` but no
`aria-label`, unlike its sibling `#btn-copy-vault-id`. One-line fix
for screen-reader parity.

### H1 — Unescaped truncated hashes (low, hardening)

Four interpolations render `truncateHash(...)` output without
`escapeHtml`: `app.js:1850` (operator pk, operator-influenced),
`app.js:2145-2147` (snapshot/manifest/device truncations),
`app.js:2499` (guardian pk). Safe today because the server
charset-validates keys/ids before serving — but the client should not
depend on that invariant. Fix: wrap all four in `escapeHtml` (or
charset-check inside `truncateHash`).

### B1 — Key minted to be thrown away (low)

`handlers.rs:492-496`: on `get_device_state` failure the fallback
tuple calls `generate_signing_key()` and binds it to `_signing_key`.
Harmless (dropped immediately) but wasteful and misleading in
security-critical code. Fix: use a zeroed placeholder or propagate
the failure explicitly.

### T1/T2 — TUI notes

- `events.rs:29-66`: the track-file write runs synchronously on the
  key-event thread. The op is a small local SQLite write, so this is
  acceptable; noted only so a future slow backend moves it to a task.
- `events.rs:6-8`: comment says "any key closes" the help modal; code
  closes on Esc/`?`/Enter. Align comment or behavior.

## Recommended fix order

1. F1 (display trust), F2 (secret residue), F4 (broken documented
   command) — one short session, all user-visible correctness.
2. F3, F5, F6, F7, H1, B1 — second pass; each is a one-to-three-line
   change with an obvious test.
3. T1/T2 — opportunistic; no user impact today.

## Evidence index

- Live probes: context/operators/overview/vault 200; guardians +
  snapshot-POST 403; metrics shape; security headers (this session).
- `node --test apps/ui/audit.test.cjs` → pass.
- `node --test apps/ui/csp.browser.test.cjs` → pass, zero violations.
- `cargo test -p ciphervault-cli --bin ciphervault dashboard::` →
  59 passed; `... tui` → 43 passed.
- Full markup read: `apps/ui/index.html` (1,915 lines).
- Full router/guard read: `router.rs` routes + guards, `server.rs`,
  `handlers.rs:186-475,551-602`, `metrics.rs`, `collectors.rs:14-71`,
  `Caddyfile.web.gcp`, `docker-compose.web.yml` wiring.
- Targeted `app.js` reads: fetch wrapper, escaping, diff masking,
  TOTP flow, guidance, shortcuts, health, secret toggle, SSE setup.
- TUI: panic-surface scan, secret-display scan, `mod.rs` lifecycle,
  `events.rs` input handling, test counts.
