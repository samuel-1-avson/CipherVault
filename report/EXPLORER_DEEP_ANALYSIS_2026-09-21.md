# CipherVault Explorer — Deep Analysis

**Date:** 2026-09-21
**Scope:** Public cluster explorer + private vault dashboard (web UI, embedded Axum backend, deployment, tests, TUI mirror)
**Method:** Source inspection of the serving backend (`apps/cli/src/dashboard/`), frontend (`apps/ui/`), container/deploy contracts, and existing test suites. No code was changed. Prior audit `docs/WEB_DASHBOARD_EXPLORER_AUDIT_2026-09-13.md` and its `*_IMPLEMENTATION_PROGRESS_2026-09-14.md` follow-up were used as baseline.
**Baseline:** `main` at `45c478b` (post v1.0.7-beta.10).

---

## 1. Executive summary

The explorer is in genuinely good shape. The September 13 audit's core complaint — one dashboard confusingly serving both public-cluster and private-vault concerns — has been structurally fixed: there are now two separate Axum routers (private vs public), a fail-closed frontend, and contract tests that forbid regressions of the boundary. Telemetry, checkpoint, and object-lookup pipelines are honest about unknown states, use cryptographic verification (PoS presence proofs, signed checkpoint feeds, pinned identities) rather than trust-on-first-use, and never move secret bytes to the public side.

Remaining work is hardening, not repair. The two findings that deserve attention are the absence of rate limiting on the public explorer (the object-lookup endpoint fans out to every operator per request) and the absence of a Content-Security-Policy (the app leans entirely on `escapeHtml` discipline across ~70 `innerHTML` sinks). Everything else is low-severity polish.

**Verdict: sound architecture, strong boundary enforcement, ship-ready with the two medium findings scheduled.**

## Remediation status (2026-09-21, same day)

All eight findings were implemented and verified. CLI suite 92/92, `audit.test.cjs` green, container contract green, workspace clippy + fmt clean, plus a live pass against both modes (public `--serve` probing the production fleet; private `--local` on a populated scratch vault).

- **F1** — Partially implemented: 60 s per-CID probe cache + 16-permit global probe semaphore in `finality.rs` (shipped, live proof: repeat object lookup 785 ms → 26 ms). The Caddy `rate_limit` zones were REMOVED same-day: stock Caddy has no such directive at all (verified on the pinned v2.11.4: rejected, no rate module, docs 404) - the zones crash-looped the edge during the 1.0.7 promotion. Per-client limiting must be implemented in-app (dashboard middleware), not at the edge.
- **F2** — Implemented: strict same-origin CSP on the shell document + router test asserting it. Verified no inline scripts/styles/handlers or dynamic code injection in the bundle.
- **F3** — Implemented: `escapeHtml` now escapes single quotes + `audit.test.cjs` §18 (proven to fail before, pass after).
- **F4** — Implemented: `nosniff` on every public response via middleware; `public, max-age=30` on telemetry endpoints; private side already had `no-store`/`nosniff`/`DENY` (confirmed live). Router test covers all four cases.
- **F5** — Implemented: explicit 2 MiB `RequestBodyLimitLayer` on both routers (no new dependency — `tower-http/limit` was already in the tree); `DASHBOARD_API_REFERENCE.md` records the intentional public mounting; router test proves 413-before-upstream (with a 502 control). Correction: bodies were never unbounded — axum 0.7 defaults buffering extractors to 2 MiB; the layer pins that behavior explicitly.
- **F6** — Implemented: `formatBytes` coerces/clamps, extended to EiB, `'--'` fallback + `audit.test.cjs` §18 cases.
- **F7** — Implemented: access-log hygiene + edge-limit documentation in `DEPLOYMENT_RUNBOOK.md` §6.
- **F8** — Done: live spot-check found no duplicate snapshots (1 push → 1 entry, 2 pushes → 2 entries, keyed by `snapshot_id_hex`); private session flow, header posture, 403 boundary, and 413 limit all confirmed against running servers.

---

## 2. What "the explorer" is

Three serving modes, one binary (`apps/cli/src/dashboard/server.rs`):

| Mode | Command | Binds | Serves |
|---|---|---|---|
| Cloud pointer (default) | `ciphervault ui` | nothing; opens browser | Just opens the configured cloud URL (`https://vault.cipherv.online`) |
| Private workspace | `ciphervault ui --local` | loopback only (refuses anything else) | Full vault dashboard: files, snapshots, diff, restore, guardians, fleet, recovery |
| Public explorer | `ciphervault ui --serve` | any host incl. `0.0.0.0` | Read-only cluster explorer: operator telemetry, checkpoints, object presence |

The UI shell (`apps/ui/index.html`, `styles.css`, `app.js` — ~350 KB total) is compiled into the CLI via `include_str!` (`apps/cli/src/main.rs:1710-1712`), so the explorer has zero static-asset deployment: one binary, one port. The same shell renders both modes and adapts from `/api/context`.

---

## 3. Architecture and data flow

```text
Browser (one SPA shell, both modes)
  │  GET /api/context  →  { mode, access_mode, capabilities, build_version }
  ▼
┌─ Private router ──────────────────────────────┐  ┌─ Public router ───────────────────────────────┐
│ guard: loopback Host + Origin + session cookie │  │ no guard; strict allowlist + 403 fallback     │
│ vault / snapshots(+mutations) / files / diff   │  │ vault STUB (no identity)                      │
│ guardians / anchors(+POST) / relayer(+POST)    │  │ operators / history / jobs (cached telemetry) │
│ fleet(+audit) / token / activity / workspaces  │  │ anchors+checkpoints (signed feed, verified)   │
│ fastcdc / stream(SSE) / account* (local+proxy) │  │ fleet STUB (counts only) / stream(SSE, public)│
└────────────────────────────────────────────────┘  │ explorer/overview + explorer/object/:cid      │
                                                    │ account* (proxied to hosted service)          │
                                                    └───────────────────────────────────────────────┘
        │                                                     │                      │
        ▼                                                     ▼                      ▼
  Local vault DB (.ciphervault)              Background collector (30s): probes     Signed checkpoint feed file
  + live operator probes                       operators, persists telemetry +      (opt-in publisher sidecar) +
                                               JSONL history/jobs                   optional Arbitrum RPC receipts
```

Key backend modules (`apps/cli/src/dashboard/`):

- `router.rs` — the two routers + `ui_shell_router` (static assets). Security-critical allowlist.
- `handlers.rs` — private handlers, public stubs/fallbacks, and `private_ui_request_guard`.
- `collectors.rs` — background telemetry collector (30s cadence, 3s probe timeout, 3 attempts w/ backoff), 30s in-memory cache with a shared-measurement mutex, persisted snapshot + JSONL history (288 cap) + jobs log (1000 cap), trust-registry identity pinning.
- `finality.rs` — signed checkpoint-feed verification (Ed25519 over canonical CBOR, 1000-record cap, 7-day freshness, publisher-key pinning, RPC-backed finality + reorg detection), explorer overview/object handlers, public fleet stub + public SSE.
- `session.rs` — `UiServerMode`, 30-min vault-bound HttpOnly SameSite=Strict session with rotation, capability map.
- `account_proxy.rs`, `files_api.rs`, `fastcdc_api.rs`, `server.rs` — account pass-through, private file ops, chunk inspector, CLI bring-up.

---

## 4. Endpoint inventory

### 4.1 Public explorer (`public_ui_router`, `router.rs:237-355`)

| Endpoint | Data | Notes |
|---|---|---|
| `GET /api/context` | mode/capabilities/build version | No session; drives frontend gating |
| `GET /api/vault` | stub only | Explicitly no `vault_id_hex`; `private_vault_access: false` |
| `GET /api/operators` | cached telemetry | Shared-measurement cache; identity status pinned-or-unverified |
| `GET /api/operators/history|jobs` | persisted collector logs | Bounded files; 404-safe when unconfigured |
| `GET /api/anchors`, `/api/relayer/checkpoints` | verified checkpoints | Empty/unavailable states when no feed; never synthesizes data |
| `GET /api/fleet` | stub counts | Empty inventory/audit arrays by design |
| `GET /api/stream` | SSE telemetry | 30s cadence off the same cache |
| `GET /api/explorer/overview` | totals + anchor head | Powers the Explorer tab cards |
| `GET /api/explorer/object/:cid` | PoS presence per operator | 64-hex CID only; **presence only, bytes never fetched** |
| `/api/account/*` (~15 routes) | proxied to hosted account service | Same handlers as private; strict `cvacct_*` ID validation |

Anything else under `/api/*` → `403 PRIVATE_API_DISABLED` (`handlers.rs:187-203`).

### 4.2 Private workspace (additions over public)

Full vault API: snapshots (list/create/manifest/restore), files (track/untrack), diff (masked by default, `reveal` opt-in), guardians, anchors POST, relayer POST, fleet + fleet-audit POST, token, activity, workspaces (list/switch/scan), fastcdc inspect/vault-files, session revoke, local account login/logout. Unknown paths → `404 PRIVATE_API_NOT_FOUND` JSON envelope.

---

## 5. Security boundary analysis

The boundary is enforced in four independent layers — this is the strongest part of the design:

1. **Structural route split.** Public and private are different routers; private handlers are unreachable in `--serve` mode regardless of frontend behavior. `public_router_allows_only_explicit_public_api_routes` (`router.rs:434-541`) asserts 403s on guardians, manifests, workspaces, snapshot/file mutations.
2. **Private request guard** (`handlers.rs:257-375`). Requires loopback `Host`; mutations additionally require a matching loopback `Origin`; non-bootstrap API calls require the session cookie plus a valid account session. Sets `no-store`, `nosniff`, `DENY`. `private_router_requires_loopback_origin_for_mutations` (`router.rs:688-792`) covers cross-origin rejection, missing-session 401s, revocation, and cookie attributes.
3. **Fail-closed frontend** (`app.js:17-20, 860-928`). Starts in `restricted` mode; private tabs/actions carry `data-private-surface`/`data-private-action` and are hidden until `local_private` is proven; switching to public wipes private state from memory and returns to the Operators tab.
4. **Deployment contracts** (`tests/dashboard_container_contract.cjs`). The dashboard image must exec `ui --serve`, must never run `init/track/push/anchor`, must not create secret demo files, must run as non-root; compose files must wire telemetry persistence, regions, WebAuthn, and secure cookies; cluster probes must use public endpoints only.

Correctness notes on the guard: cookie theft requires loopback access already; `SameSite=Strict` + HttpOnly blocks cross-site exfiltration; DNS-rebinding GETs without `Origin` still fail the session check; `Host` parsing handles bracketed IPv6 and rejects non-loopback. The `/api/context` bootstrap necessarily precedes authentication, but it only mints the session — it exposes no vault data.

---

## 6. Data accuracy and honesty

A clear step-change since the September 13 audit's "trust in displayed information" complaint:

- Telemetry is labeled reachability observation with `observed_at_utc`, never "quorum" or "proof".
- Identity states are four-valued (`verified` / `expiring_soon` / `expired` / `unverified`), and pinning is opt-in-explicit — without `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES` the UI says unverified rather than silently trusting (`collectors.rs:29-95`).
- Checkpoint feed: signature + version + size + freshness + publisher-pin checks precede display; RPC-backed finality degrades to `unverified` without an RPC URL; reorg suspects are surfaced, not hidden (`finality.rs:208-260`, `690-772`).
- Explorer object lookup proves possession per operator with a fresh PoS nonce and displays presence/quorum only (`finality.rs:61-152`).
- Empty states everywhere (`No anchors published yet`, `unavailable`, `missing`) instead of successful-looking defaults.

---

## 7. Frontend analysis (`apps/ui/`)

- **Shape:** dependency-free vanilla SPA (~4,500 lines `app.js`, single HTML shell, one stylesheet). No build step, no npm supply chain — a deliberate and defensible choice for a security tool.
- **Freshness:** 30s polling (paused when tab hidden) + SSE stream with visibility-aware reconnect (`app.js:66-77, 3012`). Sensible and cheap against the cached backend.
- **XSS posture:** all dynamic rendering flows through `escapeHtml` (double-quote style attributes throughout); external links go through `checkpointExplorerUrl`, which allowlists `https://*.arbiscan.io/tx/0x…​` and otherwise builds URLs only from numeric chain IDs (`app.js:1670-1683`). No `eval`/`new Function`.
- **Accessibility:** skip link, tablist roles, `aria-live` regions, dialog focus handling; covered by `audit.test.cjs` (§15 WCAG checks) and the `data-private-surface` aria toggling.
- **Secret handling:** diff masks values by default with an explicit reveal toggle (regression-tested both ways, `audit.test.cjs:333-364`); search modal truncates hashes; vault ID copy is disabled in public mode.
- **Gaps:** no Content-Security-Policy (see Finding 2); `escapeHtml` omits single quotes (Finding 3); `formatBytes` mishandles non-positive input (Finding 6).

---

## 8. Deployment and operations

- **Image** (`deploy/docker/Dockerfile.dashboard`): pinned base digests, multi-stage (only the CLI binary + entrypoints ship), non-root `ciphervault` user, `HEALTHCHECK` against the public `/api/vault` stub, CRLF-tolerant entrypoints.
- **Entrypoint** (`entrypoint-dashboard.sh`): execs `ciphervault ui --serve --host 0.0.0.0 --port 8080 --no-browser` — and nothing else, enforced by the container contract test.
- **Publisher isolation:** the checkpoint publisher is an opt-in compose profile sharing only the data volume; the signing key never enters the explorer process (`CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX` only in the publisher).
- **Edge headers:** Caddy adds HSTS (preload), `X-Frame-Options`, `Referrer-Policy`; nginx covers the operator API similarly. TLS terminates at this layer (rate limiting should live here too — see Finding 1).
- **State:** JSON snapshot + JSONL history/jobs under the UI volume, atomic tmp-file + rename writes, bounded sizes (288 history / 1000 jobs entries).
- **TUI mirror:** `apps/cli/src/tui` tab 7 ("Explorer") re-implements cluster telemetry, checkpoints, and CID search for terminal users, reusing the same backend contracts.

---

## 9. Test coverage map

| Layer | Suite | What it pins |
|---|---|---|
| Router boundary | `router.rs` tests (5) | Public allowlist + 403s, malformed-CID rejection, overview shape, account-ID validation/proxy reachability, private Origin/session/revoke flow |
| Crypto/verify | `finality.rs`, `collectors.rs` tests | CID parser, feed verification (time-bomb-safe), pinning, identity states, collector restart semantics |
| Frontend regressions | `apps/ui/audit.test.cjs` (vm-harness, no DOM lib) | 17 sections: masking, quorum badges, checkpoints/arbiscan links, reorg states, explorer classification + quorum render, a11y, keyboard, workspaces |
| Deploy contracts | `tests/dashboard_container_contract.cjs` | Entrypoint mode, no vault bootstrap, publisher secrecy, compose wiring × 3 files, verify-script endpoint hygiene |
| CI gates | `ci.yml` | `node --check`, both `.cjs` suites, fmt/clippy/workspace tests, Foundry |

Notable absences: no live end-to-end test of `--serve` against real operators (all public handler tests run with zero endpoints configured); no load/benchmark for the object-probe fan-out; no CSP to test.

---

## 10. Findings (ranked)

### F1 — No rate limiting on the public explorer [Medium]
`GET /api/explorer/object/:cid` fans out to **every** configured operator on **every** request (8s timeout each, `join_all`, no cache — `finality.rs:127-130`). Telemetry endpoints are protected by the shared-measurement mutex (`collectors.rs:610-611`), but object probes are not. A single client can loop CIDs and turn the explorer into an amplifier against the operator fleet; SSE connections are likewise unbounded (cheap individually, but unbounded).
**Recommend:** per-IP rate limit at the edge (Caddy `rate_limit`) **and** in-app: a short (60s) negative/positive probe cache keyed by CID + a semaphore cap on concurrent outbound probes. Add a backend test asserting the second identical lookup within TTL performs no new probe.

### F2 — No Content-Security-Policy [Medium]
Neither the app nor the proxies set CSP. The frontend is careful (Finding: ~70 `innerHTML` sinks, all observed flows escaped), but one future unescaped interpolation becomes stored/reflected XSS with no backstop — and the public explorer embeds the same bundle that handles private secrets in `--local` mode.
**Recommend:** `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` on the shell routes (the bundle is a separate same-origin file, so no inline-script exemption is needed). Assert the header in the router tests.

### F3 — `escapeHtml` omits single quotes [Low]
`app.js:2955-2962` escapes `&<>"` but not `'`. Safe today (all dynamic attributes are double-quoted), brittle tomorrow.
**Recommend:** add `.replace(/'/g, '&#39;')` + one `audit.test.cjs` case.

### F4 — Public responses lack hardening headers [Low]
Only the private guard sets `Cache-Control: no-store`, `X-Content-Type-Options`, `X-Frame-Options`; public API/stub responses carry none (relying on the edge for framing/HSTS only).
**Recommend:** `X-Content-Type-Options: nosniff` on all API JSON in both routers, and `Cache-Control: public, max-age=30` on public telemetry (matching the collector cadence) instead of `no-store`.

### F5 — Public router mounts the full account surface [Low — confirm intentional]
~15 `/api/account/*` routes (registration, TOTP/WebAuthn ceremonies, invitations, recovery codes) are served from the public explorer as proxies. ID validation is strict and tested (`INVALID_ACCOUNT_ID` matrix in the router tests), and buffering extractors inherit axum 0.7's 2 MiB default cap (verified: an oversized-body probe is rejected even with the explicit layer removed) — but this is a materially larger public surface than "read-only explorer" implies, and every proxy handler is reachable pre-authentication by design.
**Recommend:** record the decision (hosted account UX requires it) in `DASHBOARD_API_REFERENCE.md`, pin the 2 MiB cap explicitly on both routers, and add one test asserting oversized proxied POST bodies are rejected before upstream contact. *(Implemented 2026-09-21: `RequestBodyLimitLayer` on both routers + `account_proxy_rejects_oversized_bodies_before_upstream`.)*

### F6 — `formatBytes` mishandles edge inputs [Low / cosmetic]
`app.js:2930-2936`: negative or non-numeric input yields `NaN` → renders "undefined". Operator-reported `size_bytes` is untrusted input.
**Recommend:** coerce with `Number.isFinite` + clamp ≥ 0, defaulting to `'--'` like the callers already do for non-numbers.

### F7 — CID path segments land in edge access logs [Info]
`/api/explorer/object/:cid` puts the 64-hex capability in the URL path, which Caddy/nginx log by default. Presence requires prior knowledge of the CID, so impact is minimal — but log retention then equals CID retention.
**Recommend:** one line in the deployment runbook noting log rotation/redaction for explorer access logs.

### F8 — Prior-audit leftovers to spot-check live [Info]
The 09-13 audit's structural items are resolved (no vault-ID-in-URL, honest states, split routers). Two behavioral items from that audit (duplicate snapshots in the DAG feed, drawer accessibility specifics) can only be confirmed against a live vault — recommend a 10-minute live pass of `ui --local` on a populated vault before the next release note claims them fixed.

---

## 11. Suggested roadmap

**Quick wins (hours):** F3 (one line + test), F6 (clamp), F4 (two headers + tests).
**Next sprint:** F1 (edge rate limit immediately; in-app probe cache + cap with the release after), F2 (CSP + test), F5 (doc note + body-limit test), F8 (live spot-check).
**Bigger bets (only if the explorer becomes a flagship):** live e2e test of `--serve` against ephemeral operators; a read-only operator-admin view (the 09-13 audit's third recommended surface, still absent); Prometheus-format telemetry export alongside the JSONL logs.

---

## 12. Appendix

### Files reviewed
`apps/cli/src/dashboard/{mod,server,session,router,handlers,collectors,finality,account_proxy,files_api,fastcdc_api}.rs` (router/handlers/session/server/collectors/finality in full; remainder skimmed) · `apps/ui/{index.html,app.js,audit.test.cjs}` (app.js: init/gating/polling/SSE/explorer/account/diff paths) · `tests/dashboard_container_contract.cjs` · `deploy/docker/{Dockerfile.dashboard,entrypoint-dashboard.sh,entrypoint-public-feed-publisher.sh}` · `deploy/caddy/Caddyfile`, `deploy/nginx/operator.conf`, `deploy/gcp/*` (headers/profiles skimmed) · `docker-compose.yml`, `deploy/docker-compose.prod.yml` (dashboard service) · `apps/cli/src/tui/app.rs` (explorer tab surface) · `docs/{DASHBOARD_API_REFERENCE,WEB_DASHBOARD_EXPLORER_AUDIT_2026-09-13,WEB_DASHBOARD_EXPLORER_IMPLEMENTATION_PROGRESS_2026-09-14}.md`

### Prior art
This report supersedes nothing: the 09-13 audit diagnosed the problem and the 09-14 pass implemented the split. This analysis verifies the current state of that implementation and finds the core diagnosis resolved.
