# CipherVault Web Dashboard Explorer Implementation Progress

Date: 2026-09-14  
Scope: follow-up implementation after the web dashboard and explorer audit in [WEB_DASHBOARD_EXPLORER_AUDIT_2026-09-13.md](./WEB_DASHBOARD_EXPLORER_AUDIT_2026-09-13.md)

## Current result

The dashboard now has an explicit local/private mode and a separate public read-only explorer mode. The public server no longer reads a local vault database, exposes private routes, or presents local vault identity as public cluster data. The browser fails closed while serving context is unknown, and private mutations require a loopback `Host` plus a matching loopback `Origin`.

The explorer displays operator response telemetry as reachability observations. It does not call those observations a quorum, durability proof, identity verification, or chain finality. Unknown, unavailable, and unverified values are rendered as such instead of being replaced with successful-looking defaults.

## Completed in this implementation pass

### Serving boundary and launch behavior

- Split the embedded Axum router into local private and public explorer route sets.
- Made `ciphervault ui` open the configured cloud explorer without appending a local vault ID.
- Added `ciphervault ui --local` for a private loopback workspace and `--serve` for a public read-only server.
- Refused to bind the private workspace to a non-loopback address.
- Added a public API fallback that returns `403 PRIVATE_API_DISABLED` for unlisted `/api/*` routes.
- Added private response headers for `no-store`, MIME sniffing protection, and frame denial.
- Added Host and Origin checks to private requests; mutation requests without a matching loopback Origin are rejected.
- Added a per-process, vault-bound HttpOnly private session cookie issued by `/api/context`; private API calls without the session receive `401 PRIVATE_SESSION_REQUIRED`.
- Added a 30-minute session TTL with rotation when the active vault changes or the TTL elapses. Added `POST /api/session/revoke`, which invalidates the current token and expires the browser cookie.

### Public explorer data safety

- Public `/api/vault` returns only explorer mode, capabilities, and an explicit private-access message.
- Public anchors and relayer checkpoints no longer fall back to `.ciphervault/vault.db`.
- Added an opt-in signed public checkpoint feed via `CIPHERVAULT_PUBLIC_CHECKPOINT_FEED`; the feed is canonicalized and Ed25519-verified before publication. Chain receipt/finality is still displayed as unverified.
- Added `ciphervault publish-public-feed --output <path>` to build that feed from verified local checkpoint evidence. It uses the deployment-only `CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX` secret, signs canonical CBOR, and replaces the feed through a temporary file.
- Without that feed, public checkpoint metadata remains empty and explicitly unavailable.
- Added the feed path environment variable to the development, production, and GCP dashboard Compose definitions; operators must mount the signed feed file explicitly.
- Added an opt-in `public-feed` Compose profile and a separate publisher entrypoint. The publisher can share the vault/feed volume while receiving `CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX` only in its own container; the dashboard receives only the generated feed path. The profile is disabled by default until a vault source, key secret, and feed path are configured.

To enable the publisher profile, configure `CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX` as a 32-byte Ed25519 seed, set `CIPHERVAULT_PUBLIC_CHECKPOINT_FEED` to the generated JSON path as seen by the dashboard, mount the vault workspace at `/var/lib/ciphervault-ui`, and run `docker compose --profile public-feed up`. The publisher emits no private key material to logs.
- Public operator probes are shared through a 30-second cache so each browser view does not fan out a fresh probe to every operator.
- Public serving mode now starts a persistent collector when `CIPHERVAULT_PUBLIC_OPERATOR_TELEMETRY_FILE` is configured. It writes an atomic JSON observation projection every 30 seconds, and API/SSE reads use that persisted projection when it is fresh (90-second freshness bound) instead of probing per request. Compose supplies a shared-volume default path.
- Public operator records include the shared observation timestamp so the explorer can show freshness alongside response counts.
- Public operator records use `reachable`/`unreachable` and `identity_verification: unverified`/`not_observed`.
- Removed hardcoded geographic gateway labels and the fabricated `2-of-3` quorum role from private operator responses.
- Private operator responses expose observed transport configuration (`https` or `http_or_unknown`) rather than calling an endpoint shielded or identity-verified.

### Explorer UI and interaction behavior

- Private tabs, cards, dialogs, drawers, and mutation controls are hidden until local-private context is confirmed.
- Public navigation is reduced to operator telemetry, public checkpoint status, and neutral service/fleet messaging.
- Operator summaries use the actual configured count and say that probe response is not quorum or durability verification.
- Removed static GCP region and topology claims from the operator view.
- Removed fabricated latency values and stale success labels from empty/error states.
- Snapshot inspection fetches only the selected snapshot manifest and never substitutes the current vault inventory after a failed request.
- Snapshot drawers now manage `aria-hidden`, `inert`, body scroll state, focus return, and keyboard focus trapping.
- Keyboard shortcuts ignore active dialogs/drawers and target the actual search controls.
- SSE telemetry is opened only after context resolution, closed while the page is hidden, and uses the shared observation timestamp.
- Audit execution is explicit and uses `POST /api/audit`; it is no longer run on every dashboard refresh.
- Failed refreshes clear stale vault, snapshot, guardian, fleet, activity, and workspace state.
- FastCDC inspection requires an explicit local tracked-file/content request, has bounded input/results, and always disables plaintext previews.
- Empty or unverified checkpoint rows no longer fabricate a transaction, block, explorer link, or finality confirmation.

### Verification completed

- JavaScript syntax check passed: `node --check apps/ui/app.js`.
- Dashboard regression, accessibility, and explorer behavior tests passed: `node apps/ui/audit.test.cjs`.
- Container deployment contract checks passed: `node tests/dashboard_container_contract.cjs`.
- CLI unit/router tests passed: `cargo test -p ciphervault-cli --bin ciphervault --locked --target-dir .codex-target-backend-boundary` (16 tests).
- Signed-feed, publisher conversion, private-session boundary, expiry-rotation, and revoked-token rejection tests passed as part of that CLI suite.
- Chain anchoring integration tests passed, including independent receipt verification: `cargo test -p ciphervault-cli --test chain_anchoring --locked --target-dir .codex-target-chain` (3 tests).
- Storage unit tests passed: `cargo test -p ciphervault-storage --lib --locked --target-dir .codex-target-storage` (4 tests).
- Built-server smoke test passed: public `/api/context`, `/api/vault`, and `/api/relayer/checkpoints` returned 200; private `/api/snapshots` returned 403.
- Local-store database tests passed where they do not require Windows DPAPI. Four keyring/database tests remain environment-blocked because this host's Windows DPAPI service returned `CryptProtectData failed`; no insecure fallback was added.

## Remaining work

### P0: identity and authorization

- Bind the private session to an authenticated user/device ceremony and persist identity, expiry, and revocation state across process restarts. The current per-process cookie is vault-bound, rotates after 30 minutes, and supports explicit revocation, but it is not a complete user identity system and a restart invalidates all sessions.
- Scope every private request and event stream to the authorized vault. Vault switching must cancel in-flight requests and clear prior private state before loading the next workspace.
- Version and validate API response contracts at the boundary, with stable error codes and correlation IDs.

### P0/P1: truthful public evidence

- Deploy and operate the signed public checkpoint publisher/feed. The loader, signature verification, and publisher command are implemented, but no production feed is configured yet. The deployment must mount the generated feed and keep the signing secret out of the dashboard container. It must publish network, contract, commitment, snapshot reference, receipt state, verification time, and evidence provenance.
- Add independent receipt/finality verification and signed operator identity/health evidence. Reachability probes alone cannot support durability or quorum claims.
- Define the public explorer's privacy policy for operator IDs, endpoint masking, retention terms, and freshness.

### P1: durable operations

- Extend the persistent collector into a durable job/event model with retry/backoff and failure history. The dashboard now has a persistent timestamped projection and a 90-second freshness guard, but the collector still runs in the dashboard process and does not yet persist a structured event history across restarts.
- Add durable backup/audit/restore jobs with progress, idempotency keys, structured failures, and an activity cursor that survives reloads and reconnects.
- Persist recovery-drill acknowledgements and show last drill scope/result without exposing recovery secrets.
- Replace any remaining fleet read path that opens a writable maintenance database with a strictly read-only projection or collector-owned API.

### P1/P2: owner workflow and information architecture

- Make the owner overview answer four questions first: what is protected, what changed, when the last capture completed, and whether recovery was verified.
- Add pending changes/file coverage, snapshot-scoped file history, pagination, sorting, filtering, and deep links for large vaults.
- Add conflict-aware restore preview and a clean-machine recovery drill with one operator excluded.
- Add persistent actionable notifications for failed capture, stale telemetry, expired retention, and incomplete recovery evidence.

### P2/P3: design and release quality

- Complete responsive and accessibility acceptance at 320/390/768/1280px, zoom/reflow, reduced motion, screen readers, contrast, and touch targets.
- Establish a small design system for status colors, evidence states, loading/error/empty patterns, tables, drawers, and mobile navigation.
- Add clean-checkout Docker/Compose build and deployment smoke tests. Docker is not installed on this host, so image build and production deployment remain unverified here.
- Add version/schema/readiness endpoints and a rollback smoke test to the release workflow.

## Recommended next implementation order

1. Complete authenticated user/device identity, expiry, revocation, and vault-scoped authorization tests.
2. Deploy the signed public checkpoint publisher and add independent receipt/finality verification.
3. Replace request-driven probes with a persistent collector and job/event model.
4. Finish owner workflow gaps: coverage, history, restore preview, recovery drill, and alerts.
5. Run responsive/accessibility review and the clean Docker deployment validation.

The original audit remains the source of the full finding inventory and acceptance matrix. This file records what has actually changed and what still needs architectural or deployment work; an item should only be marked complete when the behavior and its displayed meaning are both verified in the deployed build.
