# CipherVault Operator Audit

**Date:** 2026-09-14  
**Scope:** the operator service, operator-to-operator discovery, storage client behavior, public dashboard telemetry, and the three production operator VMs behind `https://vault.cipherv.online/`.

## Executive assessment

The three production operators are running and responding to the dashboard probe. The cryptographic building blocks are present: Ed25519 challenge signatures, proof-of-storage signatures, signed leases, digest-checked object writes, and signed peer descriptors. The dashboard also describes its current signal accurately: `RESPONDED` means that the public `/v1/info` probe returned, not that storage durability, quorum health, or receipt finality was verified.

The federation is not ready to be treated as a private, vault-scoped operator network. The highest-risk gaps are live production issues:

1. Session issuance is not bound to a vault or an enrolled device identity. The challenge endpoint ignores the supplied vault and public-key fields, so any newly generated key can obtain a one-hour session token.
2. The operator signing key is mode `0644` on all three VMs. A local user or process that can read the data volume can copy the key and forge operator-signed evidence.
3. Several state-changing or data-returning routes have no authentication middleware, including recovery-record reads, relayer checkpoints, peer registration/listing, and out-of-band approval routes.
4. Operator identity is self-attested by an unauthenticated JSON response and is not pinned or independently signed. Clients use the key returned by the same endpoint as their trust anchor.

These items should be closed before exposing operator administration, recovery workflows, or signed public checkpoint evidence as authoritative.

## Evidence collected

- Live production dashboard: `https://vault.cipherv.online/`.
- Public operator routes tested through the dashboard proxy: `/op/1/v1/info`, `/op/1/v1/peers`, `/op/1/v1/recovery/<locator>/records`, and `/op/1/v1/challenges`.
- VPC reachability tested from the dashboard VM to each operator's port `8201`.
- VM inspection of Docker status, listening sockets, data-volume size, key-file permissions, and UFW state.
- Source review of `services/operator`, `crates/storage`, `apps/cli`, the dashboard assets, and GCP compose/startup files.
- `cargo test -p ciphervault-operator --locked --target-dir .codex-target-operator-audit`: **7 passed, 0 failed**. These tests exercise state-level cryptography and lease/PoS/peer/approval behavior; they do not cover the HTTP authorization matrix, CORS, rate limiting, persistence, or key-file permissions.

## Current production posture

| Area | Observed behavior | Assessment |
|---|---|---|
| Operator availability | All three configured operators responded to `/v1/info` during the capture. | Reachable, but only a liveness signal. |
| Public identity | Operator ID and public key are returned by `/v1/info`; dashboard labels identity `unverified`. | No independent trust anchor. |
| Public API exposure | Public proxy returns wildcard CORS headers. `peers` and recovery-record routes returned `200` without a bearer token. | Overexposed. |
| Session state | Challenges, sessions, session keys, relayer checkpoints, peer registry, and approval challenges are held in process memory. | Restart loses security and workflow state. |
| Object storage | Object writes enforce CID/digest checks and a 4 MiB limit; writes are persisted atomically. | Good primitive, incomplete authorization and abuse controls. |
| Runtime | Operator listens on `0.0.0.0:8201`; GCP compose has no Docker healthcheck; UFW is inactive. | Needs hardening and readiness checks. |
| Signing key | `/opt/ciphervault/data/operator.key` is present with mode `0644` on all three VMs. | Critical key-protection defect. |

## Findings and required work

### O-01 — P0: sessions are not vault-scoped or identity-scoped

`POST /v1/challenges` accepts `vault_id_hex` and `public_key_hex` in the request type, but the handler ignores both values. The server issues a challenge without checking an enrolled device, vault, or operator policy. `POST /v1/sessions` then verifies only that the requester signed the nonce and creates a one-hour bearer token. The token has no vault scope, device binding, origin binding, or durable revocation record.

The result is that any generated Ed25519 key can obtain a session. That token can pass the current write-session check for object, lease, and recovery operations. A process restart also discards the in-memory session and key maps.

**Required fix:** define an explicit vault/device identity record; bind the challenge to vault ID, public key, and expiry; require an allowlisted or certificate-backed key; persist sessions with revocation and rotation; include vault scope and permissions in the token or server-side session record; apply the same middleware to every protected route.

### O-02 — P0: signing key files are world-readable

All three production VMs reported mode `0644` for `operator.key` (the host displayed an unmapped owner as `UNKNOWN:UNKNOWN`). The operator startup code writes the raw private key with a normal file write, which does not request restrictive permissions or perform an atomic, locked install.

Anyone who can read the mounted data directory can copy the signing key and produce apparently valid operator identity, lease, PoS, checkpoint, or receipt signatures. The existing key should be considered potentially exposed until the access history is known.

**Required fix:** rotate the operator keys, publish the new fingerprints through an independent trust channel, create the file with mode `0600` under the runtime UID, verify ownership and permissions at startup, and fail closed if the key is group/world-readable. Write and fsync a temporary file before an atomic rename.

### O-03 — P0/P1: unauthenticated recovery, relayer, peer, and approval routes

The following handlers do not enforce a bearer session in the current router:

- `GET /v1/recovery/:locator/records`
- `POST /v1/relayer/checkpoints` and `GET /v1/relayer/checkpoints/:id`
- `POST /v1/peers/announce` and `GET /v1/peers`
- out-of-band approval create, pending, status, and submit routes

The public proxy currently exposes these routes with `Access-Control-Allow-Origin: *`. A recovery-record request for a zero locator returned `200` without authentication, and peer listing also returned `200`. Recovery records are opaque encrypted records, but the endpoint still exposes existence, counts, and unbounded response work; relayer and approval endpoints allow state pollution or replay pressure; peer registration can influence discovery.

**Required fix:** publish an allowlist of intentionally public routes; require operator- or vault-scoped authorization everywhere else; restrict CORS to the dashboard and approved origins; add request size, concurrency, and rate limits; paginate recovery records; require idempotency keys for relayer and approval mutations; audit every authorization decision.

### O-04 — P1: operator identity is not independently authenticated

`GET /v1/info` returns the operator ID and signing public key, but the response is not signed by a higher-level registry or tied to a pinned fingerprint. The storage client obtains the key from the same endpoint it is contacting and then uses it to validate leases and proofs. This is a trust-on-first-use pattern without a pinning, certificate, or independent receipt feed.

**Required fix:** create a signed operator identity descriptor containing operator ID, key fingerprint, endpoint, supported protocol version, and validity interval. Pin or verify that descriptor against vault configuration or a separately signed public registry. Make receipt verification accept only the independently trusted key and report key changes as a security event.

### O-05 — P1: anonymous object reads and missing abuse controls

The read path accepts the special `recovery_anonymous` token. That may be necessary for a recovery flow, but it currently has no capability restriction, per-client budget, rate limit, or audit trail. Object IDs are content-addressed, so any party that learns a CID can repeatedly download the object. Challenge issuance and proof generation also have no visible application-level rate limit.

**Required fix:** replace the global anonymous value with short-lived, locator- and CID-scoped recovery capabilities; enforce byte, request, and concurrency budgets at Caddy and the service; record caller, vault, CID, and outcome; add backpressure and circuit breakers.

### O-06 — P1: peer discovery accepts untrusted endpoints

Peer descriptors have a valid signature check, but there is no trust-root allowlist for the signing key, no validation that the advertised endpoint uses an approved scheme/host/port, and no pool size cap in discovery. The registration path removes old peers only when another peer is registered, while the listing path returns all stored values without filtering expiry. The storage pool can therefore expand toward attacker-controlled endpoints and retain stale peers.

**Required fix:** authorize peer keys through the signed operator registry; validate endpoint syntax and network policy; cap the peer set; filter expiry on reads; require mutual authentication for operator-to-operator traffic; add replay protection and peer-removal events.

### O-07 — P1: relayer, approvals, and collector state are not durable

Sessions, peer records, approval challenges, and relayer checkpoints are held in memory. The public collector persists its latest telemetry snapshot, but there is no durable job/event model for operator probes, checkpoint publication, recovery drills, or alert delivery. The relayer checkpoint map also defines a maximum constant without enforcing a corresponding insertion quota in the observed path.

**Required fix:** persist an append-only event stream or transactional job store with idempotent event IDs, retry/dead-letter handling, retention limits, and restart recovery. Persist session revocation and checkpoint finality state. Add a background collector that records probe, PoS, lease, and checkpoint evidence with timestamps and signatures.

### O-08 — P1: readiness and dashboard telemetry prove too little

The production dashboard probe measures an HTTP response and round-trip time from `/v1/info`. It does not check disk headroom, key readability, object read/write, PoS signature verification, lease freshness, retention policy, peer quorum, or checkpoint finality. The UI wording is truthful, but a `RESPONDED` card can still be read as “healthy” by an operator.

The GCP compose file has no Docker healthcheck, so the containers show as running without a machine-readable readiness status.

**Required fix:** add authenticated operator health/readiness endpoints with separate liveness, storage, cryptographic, and replication checks; have the collector verify signed evidence independently; display freshness, last successful PoS, lease age, disk headroom, quorum, and error history; add Docker and load-balancer healthchecks with startup grace periods.

### O-09 — P1/P2: network and release hardening is incomplete

The service binds to `0.0.0.0:8201`. The GCP firewall permits all TCP/UDP ports between VPC hosts, and the default SSH and RDP rules allow `0.0.0.0/0`. UFW is inactive on the operator VMs. The GCP startup path clones/pulls the latest repository and builds a mutable `gcp` image rather than requiring a signed, immutable release digest.

**Required fix:** bind the service to the private interface or enforce host firewall rules; remove broad SSH/RDP defaults and use an identity-aware bastion; restrict operator-to-operator ports to explicit sources; publish and deploy immutable image digests; record the release commit and migration state for rollback.

### O-10 — P2: operator explorer contract and observability gaps

The dashboard assumes the `/api/operators` response is an array and calls `filter` without validating the payload. A malformed or partial response can leave the explorer in an error state. Public cards intentionally show “Not reported” for endpoint, public key, retention, location, and quorum role, but there is no staleness badge, historical latency view, percentile latency, or signed evidence link. The current latency bars are RTT bands, not storage-health scores.

**Required fix:** validate the response schema and render an explicit degraded state; show capture age and probe source; add history and p50/p95 latency; separate liveness, storage readiness, cryptographic verification, and quorum status into independent fields; link each operator to its signed identity and latest verified evidence.

## What is already solid

- Object writes validate CID format and content digest, enforce a 4 MiB limit, and use atomic persistence.
- Challenge nonces are random, expire after five minutes, and are removed after successful use.
- Ed25519 signatures are verified for challenge responses, leases, PoS proofs, peer descriptors, and recovery records where those code paths are reached.
- The runtime image uses a non-root container user.
- The dashboard’s public copy explicitly says that reachability is not durability or quorum verification, and it marks current identity verification as unverified.
- The public telemetry collector has a 30-second probe cadence and a bounded freshness window.
- Operator state-level tests pass (7/7), giving a useful cryptographic baseline for the next HTTP and persistence test layer.

## Recommended implementation order

1. Rotate and protect all operator signing keys; add startup permission checks and incident evidence collection.
2. Implement vault-scoped, device-bound authentication with an enrolled identity registry, persistent sessions, expiry, and revocation.
3. Put every route through an authorization matrix; close unauthenticated recovery, peer, relayer, and approval paths; restrict CORS and add rate/size/concurrency limits.
4. Ship a signed, independently verifiable operator identity and checkpoint feed with key pinning and finality receipts.
5. Add durable collector/job/event persistence and restart/recovery-drill handling.
6. Harden peer discovery, endpoint validation, mutual authentication, and peer expiry/quota behavior.
7. Add readiness/health checks, immutable image deployment, private networking, and restrictive firewall policy.
8. Update the explorer to display verified evidence, freshness, storage/crypto/quorum dimensions, history, and degraded states.

## Acceptance tests for the next release

- A challenge signed by a key not enrolled for the requested vault is rejected; a token for vault A cannot read or write vault B.
- Expired and revoked sessions fail on every protected route, including after a service restart.
- Recovery, peer, relayer, and approval routes return `401/403` without the required capability and enforce bounded pagination and payload sizes.
- CORS allows only configured origins, and rate limits return a documented `429` with audit events.
- A client rejects an operator whose identity descriptor or key fingerprint is not independently trusted, even if `/v1/info` is internally consistent.
- Every operator VM fails startup when the signing key is group/world-readable; the installed key is mode `0600` and owned by the runtime UID.
- A readiness check fails when object read/write, PoS verification, lease freshness, disk headroom, or required replication is unhealthy.
- Restarting an operator and the collector preserves sessions/revocations, checkpoints, peer expiry, jobs, and audit history according to the retention policy.
- Discovery rejects invalid schemes/hosts, stale peers, duplicate identities, and peers beyond the configured cap.
- The dashboard handles malformed, stale, partial, and unreachable operator payloads without throwing, and distinguishes liveness from verified storage and quorum evidence.

## Release decision

The current production deployment can be reviewed as a reachable dashboard and operator liveness demonstration. It should not yet be advertised as a private authorized federation or as an independently verified checkpoint/retention service. The P0 items (identity-scoped authorization, key permissions, and route protection) are release blockers; the signed identity feed, durable collectors, readiness checks, network hardening, and explorer evidence model are the work required to make the operator view authoritative.
