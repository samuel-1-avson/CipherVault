# Hosted secrets browser: design draft (for the review loop)

Status: draft — do not implement until Track A/B reviewers have commented
(see `report/EXPLORER_FEATURE_PARITY_2026-10-03.md` §5.c).

## Problem

Signed-in online-explorer users can manage their account but cannot see any
secrets. The account service already stores server-side project secrets and
can serve them decrypted to authorized sessions; the dashboard exposes them
only via `/api/scoped/*`, which authenticates with a single
`CIPHERVAULT_SCOPE_TOKEN` from the server environment — mounting that on the
public router would let any visitor query with the operator's token.

## Constraints (non-negotiable)

1. Per-visitor auth only: every upstream call carries the visitor's own
   session cookie. No server-side token may act for a visitor.
2. Vault custody untouched: this surfaces account-service secrets only. Local
   vault keys, files, and snapshots stay loopback-only (ADR-012).
3. Values are step-up-gated: metadata lists on session auth; any value
   render requires a fresh MFA step-up (≤5 min) and dual-control where the
   API already demands it (bulk export stays dual-controlled + paged).
4. No value persistence in the browser beyond the DOM: no localStorage,
   no clipboard without explicit click, `Cache-Control: no-store` on all
   new routes (proxy already stamps this).
5. Fail closed: any auth/proxy failure renders an honest empty state, never
   a partial list.

## Proposed API (new public-mounted proxy routes)

| Dashboard route | Upstream | Auth | Notes |
|---|---|---|---|
| `GET /api/hosted/projects` | `GET /v1/projects` | session cookie | metadata only |
| `GET /api/hosted/projects/:ref` | `GET /v1/projects/:ref` | session cookie | env list, no values |
| `GET /api/hosted/secrets?project=&environment=` | scoped secrets metadata | session cookie | names/versions/rotation state, no values |
| `POST /api/hosted/secrets/read` | value read | session cookie + fresh step-up | single value, audited, rate-limited |

All four forward only the caller's `Cookie` (never `Authorization: Bearer`
operator tokens), pass upstream statuses verbatim, and cap bodies at the
existing 2 MiB proxy limit. Reuse `account_proxy_http_client` and the
`ACCOUNT_SERVICE_*` error mapping.

## Proposed UI

New "Hosted Secrets" tab, visible only when `hosted_account_proxy` is true
AND a hosted session exists (both modes; local keeps everything else).
Contents: project picker → environment picker → secret table (name, version,
updated, rotation state) → per-row "Reveal" (step-up modal, value shown once
with copy button, re-hidden on tab switch). Empty states name the exact
missing precondition (signed out / no projects / step-up expired).

## Explicitly out of scope

- Mounting `/api/scoped/*` publicly (server-token auth — unsafe by design).
- Hosted *writes* (create/rotate) from the browser in v1 — reads first.
- Any change to local-vault tabs, recovery ceremony, or custody split.

## Open questions for reviewers

1. Is session-cookie + step-up sufficient for single-value reads, or should
   value reads require dual control like bulk export?
2. Rate limits for the read route: per-session bucket sizes and lockout
   behavior on step-up guessing (note `failed_step_up_guesses_are_limited`
   already exists server-side).
3. Whether the value-read response should be further wrapped (e.g.
   single-use read tokens) given browser XSS blast radius.
4. CSP/connect-src implications of the new tab (same-origin proxy — expected
   none, confirm in `csp.browser.test.cjs`).
