# CipherVault Dashboard API Reference

Source of truth: `apps/cli/src/dashboard/router.rs` (routes),
`apps/cli/src/dashboard/{handlers,account_proxy,collectors,finality,fastcdc_api,files_api}.rs`
(handlers), `apps/cli/src/dashboard/{server,session}.rs` (modes, sessions).
Generated 2026-09-19 from the 1.0.7-beta.5 tree; when in doubt the code wins.

## Conventions

- Served by `ciphervault ui`. Defaults: `http://127.0.0.1:8080`
  (`--host`, `--port`/`-p`). The container image enters public mode via
  `ciphervault ui --serve --host 0.0.0.0 --port 8080 --no-browser`.
- Two modes, selected by flag (`ui_router`):
  - `--local` → `local_private`: loopback-bound only (startup refuses a
    non-loopback host). Full vault workspace APIs.
  - `--serve` → `public_explorer`: public read-only cluster explorer.
    Unknown `/api/*` paths fall back to `403 PRIVATE_API_DISABLED`;
    unknown non-API paths are 404.
  - Neither flag opens the cloud URL (`--url`,
    default `https://vault.cipherv.online`) instead of serving.
- Static shell (both modes): `GET /` (HTML), `GET /styles.css`,
  `GET /app.js`. All JSON bodies are `application/json`.
- Private-mode guard (`private_ui_request_guard`, `handlers.rs`):
  - `Host` must be loopback; mutations (POST/PUT/PATCH/DELETE) require an
    `Origin` header matching the host, and any request carrying a
    mismatched `Origin` is rejected (`403 LOCAL_ORIGIN_REQUIRED`).
  - `/api/*` except `/api/context` and the account bootstrap allowlist
    requires the `ciphervault_private_session=<token>` HttpOnly cookie
    (`401 PRIVATE_SESSION_REQUIRED`). The token is a 32-byte hex value
    issued (and rotated on vault switch or expiry) by `GET /api/context`,
    TTL 1800 s (`Max-Age=1800`, `SameSite=Strict`).
  - Once a vault is linked to a local account, private calls additionally
    require a live account session for the current device (fails closed).
  - Account bootstrap allowlist (no private cookie): `status`, `register`,
    `login`, `logout`, `capabilities`, `session`, `session/handoff`,
    `sessions/challenge`, `sessions/login`, `sessions/handoff`,
    `webauthn/authentication/{options,verify}`,
    `totp/authentication/{options,verify}`, `*/webauthn/registration/*`,
    `*/devices/challenge`, `*/devices`.
  - Every private response carries `Cache-Control: no-store`,
    `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.
- Error shape (dashboard-raised): `{ status: "error", code, error }`.
  Handler fallbacks that return 200 with `{ success: false, error }` are
  noted per route below.
- SSE routes emit `telemetry` events (`text/event-stream`).

## Private workspace routes (`--local` only)

### Context and session

- `GET /api/context` → `{ mode: "local_private", access_mode: "private",
  capabilities, session: { scheme: "http_only_cookie", vault_bound,
  ttl_seconds: 1800, revocation_endpoint }, account }`. Sets the session
  cookie. No prior session required.
- `POST /api/session/revoke` → `{ status: "ok", revoked: true, message }`.
  Rotates the server session and clears the cookie (`Max-Age=0`).

### Vault, operators, approvals

- `GET /api/vault` → full workspace inventory: `{ initialized, mode,
  access_mode, capabilities, vault_id_hex, device_id_hex, device_counter,
  epoch, tracked_files: [{ path, file_id_hex, size_bytes, chunks_count }],
  operators: [<masked endpoints>], recovery: { available,
  recovery_signing_pk_hex, recovery_encrypt_pk_hex, recovery_locator_hex,
  offline_secret_secured } }`. Uninitialized vault:
  `{ initialized: false, message, mode, access_mode, capabilities }`.
- `GET /api/operators` → array, one live `/v1/info` probe per configured
  operator: online `{ endpoint, target_url, status: "online", operator_id,
  operator_signing_pk_hex, latency_ms, retention_terms,
  transport_security: "https"|"http_or_unknown", identity_verification:
  "verified"|"unverified", identity_expires_at_utc,
  identity_signature_present }`; offline `{ endpoint, target_url, status:
  "offline", error, transport_security, identity_verification:
  "not_observed" }`. Endpoints are masked.
- `GET /api/approvals` → `{ operators: [{ endpoint, status:
  "online"|"unavailable", error?, challenges: [{ challenge_id, action,
  vault_id_hex, requester_device_id_hex, created_at_utc, expires_at_utc,
  details }] }] }`. Read-only; approvals are submitted via the CLI
  guardian ceremony, never the browser.

### Snapshots and anchors

- `GET /api/snapshots` → array of `{ snapshot_id_hex, parent_ids_hex,
  manifest_cid_hex, device_id_hex, device_counter, epoch, timestamp_utc,
  is_head }`. No vault store: `[]`.
- `POST /api/snapshots` `{ message?, anchor? }` → runs `push`
  (`{ status: "ok", success: true, snapshot_id_hex, message }`, or 200
  `{ status: "error", success: false, error }`).
- `GET /api/snapshots/:id/manifest` (`:id` = 64-hex, `0x` tolerated) →
  decrypted manifest `{ status: "ok", success: true, snapshot_id_hex,
  epoch, device_counter, timestamp_utc, files_count, total_bytes, files:
  [{ path, size_bytes, file_id_hex, chunk_count, chunk_cids,
  is_deleted }] }`, or 200 `{ status: "error", success: false, error }`.
- `POST /api/snapshots/restore`
  `{ snapshot_id?, to?, hardware_token?, reader?, pin? }` → restores via
  `cmd_restore` (default `to: "."`), records a `SNAPSHOT_RESTORE` activity
  event (`{ status: "ok", success: true, message }`, or 200 error shape).
- `GET /api/anchors` → local checkpoint evidence array `[{ commitment_hex,
  salt_hex, head_record_cid_hex, chain_id, contract_address_hex ("0x…"),
  tx_hash_hex ("0x…"), block_number, timestamp_utc }]`. No store: `[]`.
- `POST /api/anchors` → runs `cmd_anchor` (no relay)
  (`{ status: "ok", success: true, message }`, or 200 error shape).

### Audit, guardians, relayer, fleet

- `POST /api/audit` → `{ success, report, message }` (or 200
  `{ success: false, error }`). Healthy message: "Complete recovery set
  verified on at least three operators".
- `GET /api/guardians` → `{ initialized, vault_id_hex,
  recovery_signing_pk_hex, recovery_encrypt_pk_hex, recovery_locator_hex,
  operator_endpoints, message }`. No ceremony state is stored; recover via
  the CLI offline procedure.
- `GET /api/relayer/checkpoints` → `{ status: "ok", relayer_status:
  { operational: null, status: "unverified", target_network: "Arbitrum
  checkpoint metadata", verification_status: "unavailable" }, checkpoints:
  [{ commitment(_hex), salt_hex, head_record_cid_hex, chain_id,
  contract_address_hex, tx_hash(_hex), explorer_url/arbiscan_url,
  reported_block_number, timestamp_utc, is_relayed, confirmed: false,
  inclusion_verified: false, verification_status:
  "not_submitted"|"receipt_unverified", status:
  "not_submitted"|"submitted" }], count }`. No store: `not_configured`
  shape with `checkpoints: []`.
- `POST /api/relayer/anchor` → runs `cmd_anchor` with relay
  (`{ status: "ok", success: true, verification_status: "unverified",
  message }`, or 200 error shape). No sequencer receipt is verified.
- `GET /api/fleet` → maintenance inventory from `.ciphervault/fleet.db`
  (`{ status: "ok", success: true, summary, fleet_summary:
  { total_tracked_vaults, healthy_vaults, degraded_vaults,
  total_audits_recorded, audits_completed, online_operators,
  active_operators, total_operators, avg_latency_ms }, vaults: [{ vault_id,
  locator_hex, label, head_cid: null, status, replica_count,
  registered_at, storage_allowance_bytes: null }], operator_nodes:
  [{ operator_id: "Operator N", endpoint (masked), status:
  "Online"|"Offline", is_healthy, latency_ms, last_heartbeat,
  last_seen_utc }], audit_history: last 20 [{ id, vault_id, status:
  "Healthy"|"Degraded", healthy, healthy_objects, degraded_objects,
  repaired_objects: null, timestamp, duration_ms: null }] }`). Read-only:
  never registers vaults or probes. Missing DB: null summary with an
  explanatory message.
- `POST /api/fleet/audit` → runs `audit_current`, registers the vault and
  records the audit in `fleet.db` (`{ success, healthy, report, message }`,
  or 200 `{ success: false, error }`).

### Token, stream, diff, files, workspaces

- `GET /api/token` → `{ pcsc_available: true, readers,
  hardware_token: { reader, slot_9c, slot_9d, ready: true } | null }`.
- `GET /api/stream` → SSE `telemetry` every 3 s:
  `{ timestamp, operators: [{ endpoint (unmasked), online, latency_ms
  (999 when offline) }], token_attached }`.
- `GET /api/diff?snapshot_a=&snapshot_b=&file=&reveal=` →
  `{ status: "ok", success: true, report }` (or 200 error shape).
- `POST /api/files/track` `{ path }` → tracks via `cmd_track` and appends
  to `.gitignore` (`{ status: "ok", success: true, message }`; missing file
  or failure: 200 error shape).
- `POST /api/files/untrack` `{ path }` → untracks via `cmd_untrack`
  (same response shapes).
- `GET /api/workspaces` → `{ status: "ok", active_workspace_db, count,
  workspaces }`.
- `POST /api/workspaces/switch` `{ db_path? | workspace_path? }` →
  validates and activates the vault DB (`{ status: "ok", message,
  active_workspace_db }`, or 200 `{ status: "error", error }`). One of the
  two keys is required.
- `POST /api/workspaces/scan` → `{ status: "ok", message, count,
  workspaces }` (re-discovers vault workspaces).
- `GET /api/activity` → `{ status: "ok", success: true, events }` (last 50
  activity events; no store: `{ status: "ok", events: [] }`).

### FastCDC inspection

- `GET /api/fastcdc/vault-files` → `{ success: true, files: [{ path,
  exists: true, size_bytes, file_id (4-byte hex) }] }`. Only tracked files
  resolving inside the workspace root are listed.
- `POST /api/fastcdc/inspect`
  `{ content? | file_path?, min_size?, avg_size?, max_size? }` →
  `{ success: true, source, config: { min_size, avg_size, max_size },
  metrics: { total_bytes, total_chunks, unique_chunks, duplicate_chunks,
  unique_bytes, saved_bytes, dedup_savings_pct, fixed_chunks_count,
  boundary_shift_resilient: true }, chunks: [{ index, offset, length,
  cid_hex, gear_fingerprint, entropy, is_duplicate, preview }] }`
  (or 200 `{ success: false, error }`). Exactly one of `content` /
  `file_path` is required; `file_path` must exactly match a tracked file
  inside the workspace root. Limits: input ≤ 2 MiB (scaled by config),
  ≤ 512 chunk records, `64 <= min <= avg <= max <= 1 MiB`. Chunk previews
  are always `"Content previews are disabled."`.

## Public explorer routes (`--serve`)

No session cookie; all routes are unauthenticated reads (account proxy
routes pass through caller `Cookie`/`Authorization` headers, see below).

- `GET /api/context` → `{ mode: "public_explorer", access_mode: "public",
  capabilities }` (no `session` object).
- `GET /api/vault` → static disclosure `{ mode, access_mode, capabilities,
  service, private_vault_access: false, message }`. Never exposes vault
  identity, files, snapshots, or recovery material.
- `GET /api/operators` → cached collector telemetry array (each entry gains
  `observed_at`). Probes run in the background (`3 s` timeout, `30 s`
  cache TTL, `90 s` persisted max age); identity `verified` only against
  the independently pinned registry (`CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES`),
  otherwise `unverified`/`expired`/`expiring_soon` (6 h threshold).
- `GET /api/operators/history` → `{ samples: [{ observed_at, operators }],
  sample_limit: 288 }` (persisted JSONL ring,
  `CIPHERVAULT_PUBLIC_OPERATOR_TELEMETRY_FILE`).
- `GET /api/operators/jobs` → `{ jobs, job_limit: 1000, message }`.
  Observational telemetry only; collector restarts mark in-flight jobs
  `interrupted`.
- `GET /api/anchors` → signed public checkpoint feed with per-checkpoint
  finality (`[]` when unconfigured; `503 { status: "error",
  verification_status: "invalid", error }` when the feed fails to load).
- `GET /api/relayer/checkpoints` → `{ status: "ok", access_mode: "public",
  relayer_status: { public_read_only: true, target_network,
  verification_status: "publisher_signed"|"unavailable"|"invalid",
  finality_status: "independent_rpc"|"unverified" (RPC configured via
  `CIPHERVAULT_ARBITRUM_RPC_URL`), canary_status,
  reorg_suspected, reorg_suspect_tx_hashes, canary_max_age_secs
  (default 86400, `CIPHERVAULT_CHECKPOINT_CANARY_MAX_AGE_SECS`),
  newest_checkpoint_at_utc }, checkpoints, count, message }`.
  Feed source: `CIPHERVAULT_PUBLIC_CHECKPOINT_FEED`; optional publisher pin
  `CIPHERVAULT_PUBLIC_CHECKPOINT_PUBLISHER_KEY`; finality confirmations
  default 12 (`CIPHERVAULT_FINALITY_CONFIRMATIONS`), 60 s cache.
- `GET /api/fleet` → `{ status: "ok", access_mode: "public",
  fleet_summary: { total_operators }, operator_nodes: [], vaults: [],
  audit_history: [], message }`. Fleet inventory stays private-only.
- `GET /api/stream` → SSE `telemetry` every cache TTL (30 s) from cached
  telemetry: `{ timestamp, operators: [{ operator, online,
  identity_verification, latency_ms }] }`.
- `GET /api/explorer/overview` → `{ observed_at_utc, operators: { total,
  reachable }, anchors: { count, head } }`.
- `GET /api/explorer/object/:cid` (`:cid` = 64-hex, case-insensitive) →
  `{ cid (normalized lowercase), checked_at_utc, quorum: { present,
  checked, required: 3, satisfied }, replicas, note }`. Replicas are
  PoS-presence probes (8 s timeout, anonymous token); object bytes are
  never fetched. Malformed CID: `400 { status: "error", code:
  "INVALID_CID", error }`; no operators: `503 NO_OPERATORS_CONFIGURED`; over budget: `429` + `Retry-After` (30/min per client on this route, 600/min elsewhere).

## Hosted-account routes (both modes unless noted)

All `/api/account/*` routes except `status`, `login`, and `logout` are
byte proxies to the hosted account service at `CIPHERVAULT_ACCOUNT_ENDPOINT`
(shared pooled client, 8 s timeout). The proxy forwards `Cookie`,
`Authorization`, and `Content-Type` (defaulting to `application/json` for
non-empty bodies), returns the upstream status verbatim, passes through
`Set-Cookie`, and stamps `Cache-Control: no-store`. No endpoint configured:
`404 ACCOUNT_SERVICE_NOT_CONFIGURED`; unreachable/bad response:
`502 ACCOUNT_SERVICE_UNAVAILABLE` / `ACCOUNT_SERVICE_RESPONSE_INVALID`.

> Design note: these proxy routes are intentionally mounted on the **public**
> router as well as the private one — hosted account UX (register, login,
> TOTP/WebAuthn ceremonies, invitations) must work from the public explorer.
> Request bodies are capped at 2 MiB on both routers and oversized bodies
> are rejected with `413` before any upstream contact.

| Dashboard route | Upstream | Notes |
|---|---|---|
| `GET /api/account/status` | local | `current_account_context()` from the local `AccountStore` (no proxy). |
| `GET /api/account/capabilities` | `GET /v1/capabilities` | No caller headers forwarded. |
| `POST /api/account/register` | `POST /v1/accounts` | Bootstrap; service derives the account ID from the supplied public key. |
| `GET /api/account/session` | `GET /v1/sessions` | |
| `POST /api/account/sessions/challenge` | `POST /v1/sessions/challenge` | |
| `POST /api/account/sessions/login` | `POST /v1/sessions` | |
| `POST /api/account/sessions/handoff` | `POST /v1/sessions/handoff` | No body forwarded. |
| `POST /api/account/session/handoff` | `POST /v1/sessions/handoff/consume` | Consume side of the handoff. |
| `GET /api/account/:account_id` | `GET /v1/accounts/:account_id` | |
| `GET /api/account/:account_id/invitations` | `GET /v1/accounts/:id/:resource` | Same handler serves `POST` for invitations/vaults, `GET` for memberships. |
| `POST /api/account/:account_id/invitations` | `POST /v1/accounts/:id/:resource` | |
| `POST /api/account/:account_id/vaults` | `POST /v1/accounts/:id/:resource` | |
| `GET /api/account/:account_id/memberships` | `GET /v1/accounts/:id/:resource` | |
| `POST /api/account/:account_id/memberships/:member_account_id/revoke` | `POST /v1/accounts/:id/memberships/:member/revoke` | No body forwarded. |
| `POST /api/account/:account_id/recovery/codes` | `POST /v1/accounts/:id/recovery/codes` | |
| `POST /api/account/invitations/accept` | `POST /v1/invitations/accept` | |
| `POST /api/account/login` (private only) | local | Binds the local vault-linked account session: `404 ACCOUNT_NOT_CONFIGURED`, `400 VAULT_NOT_INITIALIZED`, `403 VAULT_NOT_LINKED`, `401 ACCOUNT_LOGIN_FAILED`, or `{ status: "ok", account }`. |
| `POST /api/account/logout` | `POST /v1/sessions/revoke` or local | Hosted revoke when an endpoint is configured and a `ciphervault_account_session` cookie is present; else local `AccountStore` logout plus private-session revocation (`{ status: "ok", authenticated: false }`, or `404 ACCOUNT_NOT_CONFIGURED`). |
| `POST /api/account/webauthn/authentication/options` | `POST /v1/webauthn/authentication/options` | |
| `POST /api/account/webauthn/authentication/verify` | `POST /v1/webauthn/authentication/verify` | |
| `POST /api/account/:account_id/webauthn/registration/options` | `POST /v1/accounts/:id/webauthn/registration/options` | No body forwarded. |
| `POST /api/account/:account_id/devices/challenge` | `POST /v1/accounts/:id/devices/challenge` | |
| `POST /api/account/:account_id/devices` | `POST /v1/accounts/:id/devices` | |
| `POST /api/account/:account_id/webauthn/registration/verify` | `POST /v1/accounts/:id/webauthn/registration/verify` | |
| `POST /api/account/totp/authentication/options` | `POST /v1/totp/authentication/options` | |
| `POST /api/account/totp/authentication/verify` | `POST /v1/totp/authentication/verify` | |
| `POST /api/account/:account_id/totp/enrollment` (private only) | `POST /v1/accounts/:id/totp/enrollment` | No body forwarded. |
| `POST /api/account/:account_id/totp/enrollment/verify` (private only) | `POST /v1/accounts/:id/totp/enrollment/verify` | |
| `POST /api/account/:account_id/totp/revoke` (private only) | `POST /v1/accounts/:id/totp/revoke` | No body forwarded. |
