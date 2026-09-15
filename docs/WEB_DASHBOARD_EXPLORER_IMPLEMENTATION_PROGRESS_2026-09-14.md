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
- Each collector cycle now records a bounded durable job outcome alongside the observation and latency history (`*.jobs.jsonl`), exposed through the read-only `/api/operators/jobs` endpoint with succeeded/degraded/failed status and reachable/failure counts.
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

### Cloud deployment verification (2026-09-14)

- Deployed the pinned release archive for commit `2b6c0d4` directly to the existing `cv-web-ui` VM in `us-east1-b` (`104.196.14.85`). The archive SHA-256 was verified before extraction: `1a78bd665769ff4fb8f9f41db8bd021970a07f7c337559e2c8057d257c5be085`.
- Kept the previous checkout at `/opt/ciphervault-ui/repo-backup-2b6c0d4` for rollback, built `ciphervault-ui:gcp`, and restarted `ciphervault-ui.service` only after the image completed successfully. The active image digest is `sha256:e11a562fb77617a40bde1d767b1dd9b5ffa7ce8f904614a6e5a22f04ff32f30e`.
- Verified the container is healthy behind Caddy and that `https://vault.cipherv.online/` serves the new public explorer. Browser inspection showed `3/3 operators responding (identity unverified)`, an active telemetry stream, truthful latency, and no public vault identity or file inventory.
- Verified the production API boundary from the VM and through HTTPS: `/api/context` returns `mode: public_explorer`; `/api/vault` returns the sanitized public contract; `/api/snapshots` returns `403 PRIVATE_API_DISABLED`; `/api/operators` returns the live observation projection.

The cloud verification above covers the earlier dashboard deployment. The operator-authentication, key-permission, healthcheck, and Compose changes in the section below are currently validated in the workspace and build configuration; they have not been rolled out to the production operators in this pass. Production rollout therefore still requires provisioning the service token and identity trust material, rotating the existing operator keys, rebuilding the immutable images, and repeating the HTTPS smoke tests.

An operator image was subsequently built from the reviewed workspace archive on `cv-operator-1` (`ciphervault-operator:hardening-20260914`, manifest digest `sha256:a2f6af0d0ed77e34e78d9dfdb12ae11e39b44e11eeaea9816a6112384ea7890d`) and the prior source tree was retained for rollback. The production container was not restarted because the deployment review gate requires explicit approval for this exact live image/authentication change; the other operators were not mutated.

### Docker validation

- The cloud Docker build and Compose restart completed successfully against the pinned archive.
- A local image build could not be run because Docker CLI/daemon is not installed on this Windows host. The repository-level container contract test still passes (`node tests/dashboard_container_contract.cjs`), but a local clean-checkout Docker build remains outstanding.

### Latency investigation (2026-09-14)

- Five direct samples from the dashboard VM (`cv-web-ui`, `us-east1-b`) to the configured private operator addresses measured approximately 70–74 ms for `cv-operator-1` and 70–80 ms for `cv-operator-2` (`us-central1`), versus 2–4 ms for `cv-operator-3` (`us-east1-b`). All responses returned HTTP 200.
- The displayed value is collector-side backend RTT, not the visitor's browser RTT. The cross-region network path is the main floor; the first sample also pays a new TCP connection because the probe created and dropped a fresh HTTP client for every operator and cycle.
- The collector and private operator endpoint now share a pooled `reqwest` client, reuse idle connections, and probe in parallel. SSE probes also run in parallel. This removes repeated TCP setup and avoids sequential probe delay, but it cannot remove the physical cross-region latency. The change is workspace-validated and still needs a dashboard image rollout before it affects `vault.cipherv.online`.

### Operator hardening implementation (2026-09-14)

- Bound operator challenges to a validated 32-byte vault ID and device public key. A session response is now created only when the redeemer signs with the exact key that requested the challenge.
- Added a persisted enrolled-device registry (`identities.json`) with service-token-protected `GET/POST /v1/identities` and `POST /v1/identities/revoke` administration routes. When strict operator auth is enabled, challenge issuance and redemption require an active identity enrollment; revoking an identity also invalidates its active sessions. The registry is stored with restrictive permissions and survives operator restart.
- Enrolled identities can now carry the optional `cvacct_…` account ID and 32-byte device ID. Strict challenge issuance accepts the same identifiers in the challenge payload or `X-CipherVault-Account-Id`/`X-CipherVault-Device-Id` headers and rejects mismatches; the storage client and CLI operator pool propagate the binding when a linked local account is active.
- Added vault scope to operator sessions and an `X-CipherVault-Id` request header. Object, PoS, lease, renewal, and recovery-write handlers reject missing, expired, or out-of-scope session credentials.
- Persisted operator sessions (including expiry, public key, and vault scope) in `sessions.json`, added explicit self-revocation at `POST /v1/sessions/revoke`, and wrote a private `events.log` audit trail for challenge/session events.
- Added operator identity signatures to `/v1/info`, with storage-side verification support. Public telemetry now reports `verified` only when the identity signature is valid **and** the key matches the independently configured `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES` registry (`operator-id=public-key` or bare public-key entries); an absent registry remains explicitly unverified.
- Added `/healthz`, restrictive signing-key creation/permission checks, `--rotate-key`, and healthchecks to both the GCP and local production Compose definitions.
- Removed permissive operator CORS, added a global body limit, bounded recovery response serialization, enforced relayer checkpoint capacity, filtered/limited peer state, and validated peer endpoint schemes. Strict control-route authentication is available through `CIPHERVAULT_OPERATOR_STRICT_AUTH` and is enabled by default in production Compose.
- The Nginx ingress template already applies a 50 requests/second per-IP limit and 4 MiB body cap; the Caddy templates apply security headers and body caps but do not provide an equivalent rate limiter. The service itself now has a bounded body limit, while request concurrency and per-route rate limits remain deployment work.
- Hardened the explorer against malformed operator payloads, labels stale observations, and displays operator identity verification independently from response liveness.
- Operator hardening tests pass 8/8; federation discovery, approval, and fail-closed integration tests pass. The chaos and maintenance drills remain blocked on this host's Windows DPAPI `CryptProtectData` failure before operator replication begins.

## Remaining work

### P0: identity and authorization

- Added an optional local-first account registry with a separate `cvacct_…` account ID, OS-protected account signing key, device enrollment/revocation, vault links, and 30-minute device-bound sessions. The CLI now exposes `auth init/login/logout/status`, `device list/revoke`, and `vault link/unlink`; the private dashboard context reports account binding and enforces the account session once a vault is linked.
- Account authentication is intentionally separate from vault decryption: the account contains no plaintext vault keys or offline recovery secret. Public explorer access and the accountless CLI remain available.
- Added a durable `ciphervault-account` Axum control-plane service with SQLite account/device/session/vault-link records, account-signed device enrollment proofs, revocable bearer sessions, operator revocation propagation through configured service-token endpoints, and WebAuthn `none` attestation/assertion verification for Ed25519 and ES256 credentials. WebAuthn credentials are device-bound, independently revocable, and login responses issue an HttpOnly session cookie for same-origin clients. The hosted dashboard now proxies the WebAuthn ceremony and exposes passkey sign-in/registration controls. Invitation, membership-role, and one-time recovery-code APIs are durable and audited; email delivery, policy approval, and production provisioning remain follow-up work.
- Added optional region-labelled public collector configuration through `CIPHERVAULT_OPERATOR_REGIONS` (`region=url1,url2;other-region=url3`). Region labels are persisted with operator observations and collector job records so a later multi-region deployment can retain provenance.
- Hardened the CLI TUI operator telemetry: probes now run concurrently with a bounded 3-second request deadline (and a 1-second connect deadline), while failures retain a diagnostic label (`timeout`, `connect failed`, or HTTP status) instead of collapsing every condition into `Timeout`. A persistent pooled HTTP client now reuses DNS/TCP/TLS connections across refreshes, avoiding a repeated cold handshake that inflated every row to roughly one second. The TUI now uses the canonical CLI operator resolution (environment, vault config, then production defaults), reports operator responses rather than claiming quorum from liveness, and leaves retention as `Not observed` until `/v1/info` supplies it. The release binary in `dist/bin/ciphervault.exe` was rebuilt from this workspace.
- The rebuilt TUI was smoke-tested in a pseudo-terminal: it starts, switches to the Operators tab, shows `connect failed`/`Not observed` diagnostics when this sandbox blocks outbound sockets, and exits cleanly with `q`. Because an existing TUI process held `dist/bin/ciphervault.exe` open during the final rebuild, the pooled-client binary is also available as `dist/bin/ciphervault-tui-fixed.exe` for the next launch; replace the main binary after that process exits.
- Added authenticated account metadata/audit retrieval at `/v1/accounts/:account_id` and `/audit`, durable event records for account creation, device enrollment/revocation, session lifecycle, and vault linking, plus private dashboard sign-in/sign-out controls. The CLI now attempts hosted device revocation through a short-lived account-key session when `CIPHERVAULT_ACCOUNT_ENDPOINT` is configured; failures are surfaced as warnings because the local revocation has already taken effect.
- Extend the local account/device binding to the same remote identity registry used by operators once the hosted control-plane API is deployed. The dashboard cookie remains a local transport session, while account authentication now gates linked private vault requests.
- The durable enrolled-identity registry and service-token-protected enrollment/revocation routes now exist in the workspace. Remaining work is the owner-controlled enrollment ceremony, provisioning the registry on each production operator, and binding the dashboard's private session to the same device identity.
- Scope every private request and event stream to the authorized vault. Vault switching must cancel in-flight requests and clear prior private state before loading the next workspace.
- Version and validate API response contracts at the boundary, with stable error codes and correlation IDs.

### P0/P1: truthful public evidence

- Deploy and operate the signed public checkpoint publisher/feed. The loader, signature verification, and publisher command are implemented, but no production feed is configured yet. The deployment must mount the generated feed and keep the signing secret out of the dashboard container. It must publish network, contract, commitment, snapshot reference, receipt state, verification time, and evidence provenance.
- Independent RPC receipt verification is now implemented in the anchoring verifier and covered by integration tests. The remaining work is to operate the signed public feed in production, populate `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES` with independently reviewed fingerprints, and publish signed storage/health evidence; reachability probes alone cannot support durability or quorum claims.
- Define the public explorer's privacy policy for operator IDs, endpoint masking, retention terms, and freshness.

### P1: durable operations

- Extend the persistent collector into a durable job/event model with retry/backoff and failure history. Operator authentication events now have a private append-only log, but the dashboard collector still runs in the dashboard process and does not yet persist structured probe history across restarts.
- Close the unauthenticated recovery read path with an explicit recovery capability or owner-approved pull token. It is currently bounded for availability, but remains public by design for emergency pull compatibility.
- Add in-process or ingress-backed concurrency and rate limits to all control and recovery endpoints, with per-client quotas and 429/Retry-After responses.
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
- Add a clean-checkout Docker/Compose build and local deployment smoke test. The cloud image build and production deployment are verified; Docker is not installed on this host, so local image execution remains unverified here.
- Make Caddy and cloud firewall policy private by default, and enable mutual authentication for operator-to-operator traffic where the deployment supports it. The checked-in Nginx mTLS stanza is still optional and the GCP host-network Compose path still needs a reviewed firewall/VPC policy.
- Add version/schema/readiness endpoints and a rollback smoke test to the release workflow.

## Recommended next implementation order

1. Finish the enrolled identity registry, independent operator key pinning, strict control-route authentication migration, and end-to-end vault-scope tests.
2. Deploy the signed public checkpoint publisher and expose independently verified identity, receipt, and finality evidence.
3. Move probes and operator workflows into a durable collector/job/event service with restart recovery and alert history.
4. Complete owner workflows: coverage, history, restore preview, recovery drill, and actionable alerts.
5. Harden production networking/release pinning, then complete responsive/accessibility review and clean Docker validation.

The original audit remains the source of the full finding inventory and acceptance matrix. This file records what has actually changed and what still needs architectural or deployment work; an item should only be marked complete when the behavior and its displayed meaning are both verified in the deployed build.
