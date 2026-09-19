# CipherVault Operator API Reference

Source of truth: `services/operator/src/lib.rs` (router),
`services/operator/src/handlers.rs` (HTTP), `services/operator/src/swarm/behaviour.rs`
(P2P RPC), `crates/storage/src/{client,transport,types}.rs` (client).
Generated 2026-09-18 from the 1.0.7-beta.2 tree; when in doubt the code wins.

## Conventions

- Base URL: `http://<operator>:8201`. All JSON bodies are `application/json`.
- Auth headers:
  - `Authorization: Bearer <session>` — device session from
    `POST /v1/challenges` + `POST /v1/sessions` (challenge bound to
    vault + device key, single-use, 5-minute TTL).
  - `X-CipherVault-Id: <64-hex vault id>` — required with a session;
    every session is vault-scoped.
  - `X-CipherVault-Service-Token: <token>` — operator administration
    (`CIPHERVAULT_OPERATOR_SERVICE_TOKEN`). Required for identity and
    voucher admin; accepted as an alternative on control routes.
  - `X-CipherVault-Voucher: <json>` — staged write voucher (D4) when the
    operator runs with `--require-write-vouchers`.
- Errors: every text/plain failure is rewritten by the
  `json_error_envelope` middleware into

  ```json
  { "code": 403, "error": "write voucher required" }
  ```

  (`ApiErrorBody` in `crates/storage/src/types.rs`). Clients must accept
  raw text too (proxies, 413 body-limit rejections).
- Idempotent reads (GET) retry up to 3 attempts with linear backoff on
  transport failure and 408/429/502/503/504. Writes never retry
  client-side; the pool fails over across operators instead.

## Size and rate limits

| Limit | Value | Where |
|---|---|---|
| Object put | 4 MiB (`MAX_OBJECT_SIZE`) | HTTP + P2P + memory |
| Recovery record | 64 KiB (`MAX_RECOVERY_RECORD_SIZE`) | all legs |
| Recovery readback | 16 MiB total | HTTP + P2P caps |
| RPC request / response | 8 MiB / 32 MiB | P2P codec |
| Gossipsub message | 64 KiB | mesh |
| Kademlia peer record | 64 KiB (`MAX_PEER_RECORD_BYTES`) | reader + local store |
| RPC rate | 50/s per peer, 429 before auth | swarm |
| Repair budget | 8 MiB/s shared, 429 past it | receiver |
| Sessions / challenges | 5,000 each max | operator state |

## HTTP routes

### Meta (public)

- `GET /healthz` → `{ status, operator_id, ... }`. No auth.
- `GET /v1/info` → signed `OperatorInfo` (id, PK, retention terms).
  No auth. Clients verify `identity_signature_hex`.
- `GET /metrics` → Prometheus exposition. No auth.

### Auth

- `POST /v1/challenges` `{ vault_id_hex, public_key_hex, ... }` →
  `{ challenge_id, nonce_hex, expires_at_utc }`. No auth (rate-limited).
- `POST /v1/sessions` `{ challenge_id, signature_hex, ... }` →
  `{ token, expires_at_utc }`. Binds vault + device key.
- `POST /v1/sessions/revoke` (session) → 204.

### Identities (service token)

- `GET /v1/identities`, `POST /v1/identities` (enroll),
  `POST /v1/identities/revoke`. Persisted to `identities.json` (0600).

### Vouchers (service token)

- `POST /v1/vouchers`
  `{ holder_pk_hex, quota_bytes, ttl_secs }` → `WriteVoucher`
  `{ version, issuer_pk_hex, holder_pk_hex, quota_bytes, expires_utc,
  nonce_hex, signature_hex }`. Self-issued (barter model, D4).

### Objects (session + optional voucher)

- `PUT /v1/objects/:cid` (octet-stream, ≤4 MiB) → 200. PoS readback
  before quorum accept; idempotent re-PUT bills zero quota.
- `GET /v1/objects/:cid` → bytes. 404 when absent.
- `POST /v1/objects/:cid/challenge` `{ nonce_hex }` →
  `ProofOfStorageReceipt` (461-byte readback proof).

### Leases (session + optional voucher)

- `POST /v1/leases`
  `{ closure_digest_hex, byte_count, term_days }` → `LeaseReceipt`.
- `POST /v1/leases/:id/renew` `{ additional_days, byte_count }` →
  `LeaseReceipt`. CLI: `lease create|renew`.

### Recovery log

- `POST /v1/recovery/:locator/records` (session, octet-stream) →
  `{ sequence, status }`. Ed25519-gated on the vault recovery key.
- `GET /v1/recovery/:locator/records` → `{ records_hex }`.
  **Anonymous by design**: the locator is a 256-bit KDF capability;
  clean-machine bootstrap has no session. Locked by
  `services/operator/tests/recovery_auth.rs`.

### Peers

- `GET /v1/peers/self` → fresh self-signed `PeerDescriptor`. Public.
- `GET /v1/peers` (control auth) → verified routing table.
- `POST /v1/peers/announce` (control auth, `PeerDescriptor` body) →
  `{ status, peer_count }`. Freshness: ≤24 h old, ≤1 h future skew.
  CLI: `peers --mesh` announces every self descriptor to every node.

### Approvals (out-of-band, R14)

- `POST /v1/auth/challenges`, `GET /v1/auth/challenges/pending`
  (service token), `GET /v1/auth/challenges/:id`,
  `POST /v1/auth/challenges/:id/approve`. CLI: `approve list|sign|status`.

### Relayer

- `POST /v1/relayer/checkpoints`, `GET /v1/relayer/checkpoints/:commitment`.
  L2 anchor receipts.

## P2P RPC (`/ciphervault/operator/1.0.0`, CBOR)

One `OperatorRpcBody` variant per transport operation, reusing the HTTP
wire types; `P2pAuth { bearer_token, vault_id_hex, service_token,
voucher }` rebuilds the header map server-side so auth semantics are
identical to HTTP by construction. Responses mirror HTTP including
`Err { status, message }` (→ `ServerError`).

| RPC body | HTTP equivalent |
|---|---|
| RequestChallenge / RedeemSession / RevokeSession | `/v1/challenges`, `/v1/sessions`, `/v1/sessions/revoke` |
| GetInfo | `GET /v1/info` |
| PutObject / GetObject / ProveStorage | object routes |
| CommitLease / RenewLease | lease routes |
| AppendRecovery / GetRecovery | recovery routes |
| AnnouncePeer / GetPeers / GetPendingApprovals | peer + approval routes |
| RepairPush (P2P-only) | none — mesh repair, operator-signed, budget-paced |

`RepairPush` is NOT session-authed: the receiver checks known-sender +
ed25519 + digest, then spends repair budget (`put_repair_object`, 429
past budget). No voucher/quota path is involved. Details:
`docs/REPAIR_PROTOCOL.md`.

## Gossipsub control topic

`CONTROL_TOPIC` carries signed liveness heartbeats
(`swarm/liveness.rs`, Strict validation, 5 s emission / 15 s timeout)
and repair coordination. Forged gossip is dropped without effect
(`swarm_liveness.rs` 7-class injection test).

## DHT records

`signed PeerDescriptor` JSON under `ciphervault/peer/1/<pk>` (D5).
Readers fail closed on undecodable bytes, key mismatch, bad signature,
age >7 days, or >1 h future skew. Same-key garbage can blank a record
until the owner republishes — live deployments must republish on a
period well under `MAX_PEER_RECORD_AGE_SECS`.
