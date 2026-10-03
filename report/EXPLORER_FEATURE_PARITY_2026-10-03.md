# Explorer online vs local: feature-visibility report (2026-10-03)

## Verdict

No bug. The online explorer shows fewer features **by design, enforced in
three layers, covered by regression tests, and documented**. The online
explorer is a public cluster dashboard plus a hosted-account console — it is
not a remote vault viewer and cryptographically cannot become one without a
new decryption/relay design (see `docs/ACCOUNT_PLANE_DECENTRALIZATION.md`).

Two small UX papercuts and one medium enhancement were identified; (a) and
(b) are implemented (§5, "Status: done"), (c) remains a follow-up.

## 1. How the split works (mechanism)

1. **Server bind-time mode.** The online deployment runs
   `ciphervault ui --serve --host 0.0.0.0:8080`
   (`deploy/docker/entrypoint-dashboard.sh`), which builds the **public
   router** (`apps/cli/src/dashboard/router.rs`,
   `public_ui_router_with_limiter`). Local runs (`ui --local`, loopback-only)
   build the private router. Mode is a server property, never a per-session
   flag.
2. **Capability advertisement.** `GET /api/context` returns
   `mode` + `capabilities` (`apps/cli/src/dashboard/session.rs`,
   `ui_capabilities()`). Live prod (`https://vault.cipherv.online`,
   build 1.0.28, probed 2026-10-03) returns `mode: "public_explorer"` with
   every vault capability `false` and `hosted_account_proxy: true`.
3. **Server-side enforcement.** Anything under `/api/*` not explicitly on the
   public router returns `403 PRIVATE_API_DISABLED`
   (`api_public_fallback_handler`). The UI cannot reach around this.
4. **UI gating.** `applyAccessContext()` hides 28 `data-private-surface` /
   `data-private-action` elements and the audit suite asserts the gating
   (`apps/ui/audit.test.cjs`: My Data hidden, no device-key offer, no private
   fetches in public mode).

## 2. What is visible where

| Surface | Local (`ui --local`) | Online explorer |
|---|---|---|
| Operators / Block explorer / Arbitrum relayer | yes | yes (public telemetry + signed checkpoint feed) |
| Maintenance Fleet tab | yes | hidden (fleet inventory is private-only; `GET /api/fleet` returns empties) |
| My Data / Tracked Secrets / Snapshots / Diff / FastCDC | yes | hidden (need local vault DB + keys) |
| Guardians / Activity | yes | hidden (same reason) |
| Recovery tab | yes (recovery sheet) | **visible but empty** (see §5.a) |
| Snapshot / anchor / audit / fleet-audit actions | yes | hidden + server-403 |
| Workspace switcher, scope banner, sync-health badge | yes | hidden (need local store) |
| Sign in (passkey / TOTP / CLI handoff) | yes | yes (device-key card correctly hidden: no local keystore) |
| Account management modal (memberships, MFA policy, TOTP, recovery codes) | yes | yes, via `/api/account/*` proxy |
| Linked Vaults + key-backup locators (ADR-012 step 3b) | yes | yes, via proxy (locators are non-sensitive) |
| Hosted projects / secrets browser | scope banner only (operator token) | none (see §5.c) |

## 3. Why ADR-012 does not change this

ADR-012 (`docs/adr/012-unified-login-split-custody.md`) unified the **login
UX** while explicitly preserving split custody: vault keys never leave the
device, the CLI never hands a hosted token to vault crypto, and there is no
server-side unwrap. The online explorer never receives vault keys, so it
cannot decrypt or list vault contents — showing those tabs online is not a
missing feature, it is cryptographically out of reach. What ADR-012 *did*
enable online works: the account-held locator and the Linked Vaults panel
are served through the public-mounted `/api/account/*` proxy.

## 4. Ruled out (checked, no issue)

- Stale deployment: prod serves build 1.0.28 with `public_checkpoint_metadata:
  true` and a fully capable account service (TOTP, WebAuthn, MFA policy).
- Broken sign-in online: all ceremony routes (challenge/login/handoff,
  WebAuthn, TOTP enroll/verify/revoke, MFA get/patch/recovery-reset) are
  mounted on the public router and proxied with caller cookies
  (`docs/DASHBOARD_API_REFERENCE.md`, "Hosted-account routes").
- Mounting `/api/scoped/*` publicly as-is: unsafe — those handlers use a
  single `CIPHERVAULT_SCOPE_TOKEN` from the **server environment**, so any
  visitor would query with the operator's token. Correctly private-only.
- Silent JS failures in public mode: fetchers degrade to empty states;
  gating is assertion-tested.

## 5. Improvements worth making

a. **Recovery tab empty-state (tiny).** The tab is visible online but
   renders an empty sheet (`fetchVault` → static disclosure has no
   `initialized`). Show "Recovery sheets live in your local vault — open
   `ciphervault ui --local`" instead of blank.
b. **Signed-in online home (small).** After hosted sign-in online, nothing
   visibly unlocks except the account modal. Add a signed-in panel: account
   id, MFA status, linked-vault count, and links into the working surfaces.
c. **Hosted secrets browser (medium, needs security review).** The account
   service already supports server-decrypted scoped secrets; the dashboard
   has no per-user UI for it (scoped routes are operator-token-based and
   UI-unused except the banner). New public-mounted proxy routes bound to
   the *visitor's own session cookie* (values only after step-up) plus a
   "Hosted Secrets" tab would close the biggest expectation gap without
   touching vault custody.

## 6. Suggested order

(a)+(b) implemented 2026-10-03 (`apps/ui/index.html`, `apps/ui/app.js`,
`apps/ui/styles.css`, `apps/ui/audit.test.cjs` §24; UI audit + Chromium CSP
green; embedded binary verified serving both in `--serve` mode). Local CLI
install pending dashboard restart (binary running at build time). Online
explorer picks (a)+(b) up on the next dashboard image rollout. Design (c)
as a follow-up with the independent review in the loop, since it puts
secret values one click further from the browser.
