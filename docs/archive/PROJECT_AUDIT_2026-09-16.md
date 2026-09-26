# CipherVault project audit

**Audit date:** 2026-09-16
**Repository:** `samuel-1-avson/CipherVault`
**Audited revision:** `d7f5a80` (`fix(ui): expose authenticator login to anonymous users`) plus the current working-tree hardening changes
**Branch:** `main`
**Scope:** Rust workspace, web dashboard and explorer, CLI/TUI, account and operator services, storage and recovery libraries, Solidity registry, Docker/GCP deployment, CI/release configuration, and the live production endpoint.

## Executive verdict

CipherVault has a substantial, well-structured foundation. The cryptographic primitives, signed recovery structures, operator request bounds, local account/session controls, dashboard route separation, and accessibility regression suite are real implemented controls. The public explorer is currently functional and truthful about what it can prove: it reports reachability and latency, while marking operator identity and checkpoint evidence as unverified.

The project is **not yet production-complete for private, hosted, multi-user vault management**. The highest-impact remaining gaps are missing production identity/checkpoint evidence, distributed abuse controls, durable collector/job history, secret-manager-backed key rotation, and reproducible immutable deployment. The TUI plaintext preview, relay confirmation weakness, role bypasses, and local strict-Clippy failures identified during the initial audit are fixed in the current working tree, but those fixes are not a production rollout until they are committed, promoted, and verified on a clean host. The live deployment remains on its prior derived hotfix tag; this working tree now prepares a signed digest promotion, but no new image has been promoted yet.

The correct status is **security-focused beta / public explorer operational; private hosted account and evidence plane still in hardening**. Do not describe the system as “hardened production ready” or “10/10 production readiness” until the release blockers and evidence gaps below are closed.

## How the audit was performed

- Read the application, service, library, contract, deployment, CI, and documentation sources.
- Inspected the live HTTPS deployment at `https://vault.cipherv.online/` through its public API surface.
- Ran the dashboard audit and accessibility suite, dashboard container contract test, Rust formatting, targeted crate tests, and the CLI security gate.
- Attempted the full workspace test and strict workspace Clippy commands under Windows.
- Inspected tracked release artifacts and ignored local state by filename and metadata only; no ignored secret file was opened or copied.

This is a source and operational audit, not an independent penetration test. No production private account, physical hardware token, live chain deployment, sustained load test, or third-party cryptographic review was performed.

## Current production evidence

The public deployment is reachable over HTTPS and currently serves the public explorer. The account, dashboard, and Caddy containers were healthy at the time of the live check. The public API reported:

| Area | Observed result | Meaning |
|---|---|---|
| Explorer mode | `mode=public_explorer`, `access_mode=public` | Anonymous read-only explorer is available. |
| Operator telemetry | Three configured operators responded; latency varied by region | Reachability is working; this does not prove durability or quorum. |
| Operator identity | `unverified`, `identity_self_signature=invalid`, `identity_signature_present=false`, `identity_trust=not_pinned`, expiry `0` | Production identities are not currently trusted or independently verifiable. |
| Checkpoint feed | `/api/anchors` returned `[]` | No signed public checkpoint feed or finality receipt is being published. |
| Account session | `/api/account/session` without a cookie returned `401` | Anonymous requests do not receive a private account session. |
| Capabilities | `webauthn=true`, `totp=true`, managed session cookie and invitation/recovery capabilities reported | Code paths are present, but no complete production account flow was exercised. |
| Private vault | Public `/api/vault` reported no private vault access | Private data is not exposed through the public explorer. |
| Security headers | HSTS preload, `nosniff`, `SAMEORIGIN`, and strict referrer policy observed | Baseline browser hardening is present. |

The public explorer therefore works as a sanitized telemetry view, but its most important trust indicators are currently unavailable. A green operator response badge must not be presented as proof that the operator is an authorized storage participant.

The latest HTTPS spot check during this audit returned all three operators as reachable at 38 ms, 44 ms, and 4 ms; `/api/anchors` remained empty; `/api/context` remained in `public_explorer` mode with private capabilities disabled; and `/api/account/session` returned `401` without a cookie. The hosted account capability endpoint advertises TOTP, WebAuthn, invitations, recovery codes, and managed sessions, but those flows were not exercised against a real production account.

## System map

- **Web/UI:** `apps/ui/app.js`, `index.html`, and `styles.css` render the public explorer, account controls, operator telemetry, and private-mode surfaces.
- **Dashboard/API and collector:** `apps/cli/src/main.rs` serves the dashboard proxy, public/private route guards, operator polling, history, jobs, and signed-feed verification. The dashboard collector is process-owned and persists bounded JSON state.
- **Account service:** `services/account` provides SQLite-backed accounts, devices, sessions, WebAuthn/passkeys, TOTP, invitations, memberships, recovery codes, and audit events.
- **Operator service:** `services/operator` exposes health, control, peer, relayer, and storage paths; it keeps identities and sessions on disk but several routing and checkpoint structures in memory.
- **Storage/recovery:** `crates/storage`, `crates/recovery`, `crates/local-store`, `crates/crypto`, and related crates implement encrypted objects, signed leases/proofs, threshold recovery, and local key handling.
- **Chain registry:** `contracts/CipherVaultRegistry.sol` records commitments on chain; Foundry coverage is currently small.
- **Deployment:** Dockerfiles, Compose, Caddy, GCP startup scripts, systemd units, and CI/release workflows build and run the services.

## What is working well

### Cryptography and recovery

- XChaCha20-Poly1305 uses random nonces, authenticated additional data, and has tamper/wrong-AAD tests.
- Recovery structures include signed device certificates, signed heads/snapshots/envelopes, trust selection, Shamir threshold handling, and redaction/tamper tests.
- The HSM/PIV abstraction and physical-token wrapper provide a path to high-assurance signing; the software simulator is clearly identifiable and must remain unavailable to production selection.
- Digest, lease, proof-of-storage, and client verification types are validated in the storage crate.

### Account and session service

- SQLite uses WAL and foreign keys; the database is restricted to mode `0600` on Unix.
- Session and challenge expiry, token hashing, device binding, revocation, WebAuthn origin/RP checks, user-presence/verification checks, algorithm parsing, signature verification, sign counters, and account-signed device enrollment proofs are implemented.
- TOTP uses RFC 6238 SHA-1, six digits, 30-second steps, constant-time comparison, encrypted secret storage, and a last-used-step replay barrier.
- Session cookies are `HttpOnly`, `Secure` when configured, and `SameSite=Lax`.

### Operator and dashboard controls

- Operator startup checks strict authorization configuration, key ownership/mode, storage paths, and health readiness.
- Service-token control authentication, vault-scoped sessions, bounded request bodies, object/recovery limits, atomic writes, proof/signature validation, and enrollment requirements are present.
- Public and private dashboard routes are separated. The web inspector intentionally disables plaintext previews.
- Dashboard audit/accessibility tests pass, including the public/private UI distinction and truthful labels such as “identity unverified.”
- Docker runtime containers run as unprivileged users and have health checks; the publisher is opt-in.

## Findings and required work

Severity uses **High** for release-blocking or trust-boundary issues, **Medium** for material reliability/operational gaps, and **Low** for cleanup or process improvements.

### High findings

#### H1 — Strict Clippy was red on a CI-enforced gate (resolved in the working tree)

The original audit found `account_session_for` returning a very large `Response` error variant. The working tree now boxes that error boundary, and `cargo clippy --workspace --all-targets --locked -- -D warnings` passes. Keep the Linux CI run as the release proof.

#### H2 — Production operator identity is not trusted or verifiable

The live `/api/operators` response reports invalid/missing self-signatures, no pinned trust, and no expiry. Provision each production operator identity, rotate keys from a controlled ceremony, publish the trusted fingerprints to the dashboard configuration, and add expiry/revocation monitoring. The UI should distinguish “responding” from “authenticated operator.”

#### H3 — No signed public checkpoint feed or independent finality receipt is live

`/api/anchors` is empty and `/api/context` reports `public_checkpoint_metadata=false`. The verifier in `apps/cli/src/main.rs:7056+` has useful signature, age, future-skew, count, and field-length checks, but there is no production feed to verify. Deploy a publisher, pin its key, include chain/network/contract identity, and serve independently queried transaction receipts and finality status. Add a canary checkpoint and an automated verification alarm.

#### H4 — Relay accepted client-supplied “confirmed” chain evidence (fixed locally; production verifier still to provision)

The relay path now stores every new submission as `QueuedForRelay`, regardless of client-supplied transaction fields. A new confirmation method accepts only a report from the RPC verifier; that verifier now rejects chain-ID and registry-address mismatches, requires a successful receipt at the registry block, and treats a no-transaction observation as pending. The production RPC, registry address, and receipt-publisher job still need to be provisioned.

#### H5 — Membership roles were stored but not enforced across hosted operations (fixed locally; matrix expansion remains)

Role-aware authorization now checks active membership, enforces owner/admin hierarchy, blocks owner delegation and self-revocation, limits vault linking and recovery-code issuance to a strong owner session, and permits membership views only to active members. Expand the integration matrix to cover every route and each role in CI.

#### H6 — TOTP and recovery-code verification lacked online abuse controls (fixed locally; distributed limiting remains)

TOTP and recovery verification now use a bounded per-account/source failure window with a five-attempt lockout, stale-key pruning, and reset on success. The limiter is persisted in the account SQLite database, so failure windows survive a service restart; a multi-replica deployment still needs a genuinely shared database/Redis-style backend and an alert sink. Tests cover repeated-failure blocking and restart persistence.

#### H7 — Recovery-code redemption grants a marked recovery session (partially fixed)

Recovery redemption still accepts an unauthenticated account ID and one-time code, but sessions are now marked `auth_method=recovery`; account-scoped mutations reject that method and require device/passkey/hardware step-up. Add explicit recovery-session expiry/notifications and a controlled device re-enrollment workflow.

#### H8 — Signing and secret deployment are not under a single protected source of truth

The live production TOTP key is still stored in `/opt/ciphervault-ui/.env` (mode `0600`). The working tree now defines a read-only secret mount, startup validation before binding the account port, and a dedicated runtime service account with access scoped to the existing account TOTP secret. The service-account binding and secret fetch have not been applied to the live VM yet; rotate the current value and prove that logs, images, archives, and crash output cannot contain it. Apply the same ceremony to operator signing keys.

#### H9 — Release image provenance is not reproducible (workflow partially fixed)

The live dashboard uses a derived `ciphervault-ui:gcp-totp-fix6` image containing a binary hotfix over the source-built image. The working tree removes GCP web source checkout/build helpers, requires digest-pinned GHCR images, stages reviewed Compose/Caddy configuration, and supplies a signed-image promotion/rollback tool. The release workflow now emits SBOM/provenance attestations and signs the published multi-architecture digest, but no release tag has produced a candidate or promoted one to the live VM yet. Build from a commit in CI, then run the preflight and controlled promotion from an authenticated host.

### Medium findings

#### M1 — TUI displayed plaintext from a tracked local file during refresh (fixed)

The TUI no longer creates or renders ASCII/hex content previews. The FastCDC table reports `Masked` for the content column while retaining chunk size, entropy, digest, and deduplication metrics. Add a dedicated source-level regression assertion in the next UI test pass.

#### M2 — Full workspace tests require bounded parallelism on Windows

The default parallel Windows run previously exhausted resources. A single-job run (`cargo test --workspace --locked --jobs 1`) now completes successfully. Keep Linux as the release platform, retain bounded-job guidance for Windows, and document the resource requirement.

#### M3 — Storage pool and recovery reads were sequential (partially fixed)

Authentication, recovery-record queries, and object reads now run concurrently through the pooled client. Snapshot replication itself still processes each operator and object sequentially, so bounded per-operator concurrency, quorum-aware cancellation, and regional collectors remain required for production latency.

#### M4 — Collector/job state is only partially durable

The dashboard keeps bounded history and jobs in JSON files. Collector jobs now write a `running` record before probing, upsert the same ID with completion, and mark abandoned `running` records as `interrupted` on restart; retry state, alert events, and durable leases are still incomplete. Relayed checkpoint receipts persist atomically and restore after an operator restart; operator peers and approval challenges remain in memory. Add a durable job/event schema, idempotent job IDs, collector leases, restart recovery, and alert retention tests.

#### M5 — Peer discovery lacks mutual authentication and network binding

Peer registration checks signatures, URL syntax, optional trusted keys, expiry, and a maximum count, but does not provide mTLS, DNS/IP rebinding protection, network/port allowlists, per-peer quotas, or persistence across restart. Add endpoint resolution safeguards, authenticated transport, quotas, expiry sweeps, and durable peer state.

#### M6 — Operator authorization had an unsafe source-default fallback (fixed locally)

Strict operator control authorization now defaults to enabled in the handler and binary configuration. Local migration tests explicitly set `CIPHERVAULT_OPERATOR_STRICT_AUTH=false`; production must continue to supply a service token and enrollment policy, and direct-startup fail-closed behavior should be covered by deployment smoke tests.

#### M7 — CSRF and proxy policy now enforce request origins (proxy pooling remains)

Account POST routes now reject an `Origin` outside the configured allowlist (or the configured WebAuthn origin fallback). SameSite cookies remain an additional layer. The dashboard account proxy still creates a client per request and needs pooling, explicit upstream allowlisting, and cross-site integration tests.

#### M8 — Key derivation and fallback storage need stronger guarantees (partially fixed)

`crates/local-store/src/keyring.rs` now derives arbitrary portable passphrases with Argon2id and a stable or explicitly supplied 16-byte salt; raw 32-byte keys remain supported. Add a versioned parameter envelope for future migration, audit the non-Windows fallback that writes a random key file to ensure permissions/ACLs are restrictive on every supported platform, and prevent accidental selection of the software HSM simulator in production.

#### M9 — Chain registry policy and tests are underspecified

`CipherVaultRegistry.publish(bytes32)` accepts any sender and uses first-writer-wins semantics. That may be intentional, but there is no canonical publisher authentication or anti-front-running policy. Add an explicit design decision, network/chain binding, event assertions, authorization or signed publisher proof if required, and tests for unauthorized publishers, replay, spam bounds, and receipt/finality evidence.

#### M10 — Deployment perimeter and image bases are mutable (partially fixed)

The working tree pins the Rust and Debian base manifests and the Caddy image digest. Live apt repositories remain mutable, and startup scripts install Docker and clone `main` at deployment time. Caddy has direct operator proxy paths that need review. Pin package inputs, build once in CI, remove build tools from runtime, restrict operator ingress to private networking or mTLS, and validate that `/op/*` cannot become an unintended public control surface.

### Low/process findings

#### L1 — Documentation overstates readiness

`docs/SYSTEM_WORKFLOW.md` labels the system “Hardened Production Ready,” `docs/README.md` advertises a “10.0/10.0 production readiness scorecard,” and archived audit/rollout material contains contradictory deployment status. Mark documents with an audit date and evidence status, remove absolute readiness claims, and make the release checklist the authoritative status source.

#### L2 — Dependency and container security scanning was absent (workflow added; execution pending)

The working tree now defines scheduled and push-request Rust dependency auditing plus Trivy source-tree scanning, and release images are scanned for high/critical vulnerabilities, misconfiguration, and secrets before signing. The new workflows still need to run in GitHub and retain scan artifacts with an exception process.

#### L3 — Contract, cross-platform, and operational validation are incomplete

The registry has only three focused tests. No physical YubiKey path, Linux/macOS TUI run, live chain publish, sustained load/chaos test, or independent recovery drill was executed in this audit. Add a disposable canary environment and scheduled recovery drill before calling the system production ready.

## UI and information-display assessment

The explorer’s public/private distinction is clear and the dashboard correctly uses “responding” and “identity unverified” language. Keep those labels and make the following states first-class:

1. **Identity:** pinned fingerprint, signature validity, key age, expiry, and revocation status.
2. **Evidence:** checkpoint commitment, publisher signature, receipt block, confirmations/finality, chain/network/contract, and last verified time.
3. **Storage:** replication coverage, last successful proof/readback, retention expiry, and recovery readiness.
4. **Freshness:** sample age, collector status, retry count, and whether data is stale or unavailable.
5. **Quorum:** policy threshold and verified members, separately from raw response count.
6. **Degraded states:** partial region failure, pending evidence, stale collector, revoked device, or recovery-only session.

Do not show a green “operator responding” badge alongside an implied durability claim. Provide a details drawer with the verification reason and an evidence timestamp, and keep private vault filenames, history, recovery material, and administrative actions behind an authenticated private workspace.

## Implementation update in the current working tree

The first release-hardening slice is implemented locally and covered by tests:

- Strict workspace Clippy is clean with warnings denied.
- Relay submissions are pending by default; chain ID and registry address are bound to the configured verifier, and independent receipt verification is required before confirmation.
- Relayed checkpoint receipts persist atomically and are restored after an operator restart.
- Account roles, vault linking, invitations, membership revocation, recovery-code issuance, CSRF origin checks, and local TOTP/recovery abuse throttling are enforced.
- Authentication throttling is persisted in SQLite and survives an account-service restart; it remains a single-database control until a shared multi-replica backend is provisioned.
- Direct deployments ignore spoofable forwarded headers; forwarded client identity is accepted only when the trusted-proxy setting is explicitly enabled.
- Recovery sessions are marked and cannot perform account mutations without a stronger device/passkey step-up.
- Portable passphrases use Argon2id with a stable or explicitly supplied salt.
- The TUI no longer renders plaintext file previews; content is masked while chunk metrics remain visible.
- Pooled storage authentication, recovery reads, and object reads run concurrently.
- Collector jobs record a durable running intent and update that record on completion, while bounded telemetry/history remain restart-readable.
- Collector restart reconciliation marks abandoned jobs `interrupted` with a durable reason; the behavior has a focused regression test.
- Rust and Debian Docker base manifests plus Caddy are pinned by digest; Cargo image builds enforce the workspace lockfile.
- GCP web Compose now requires signed GHCR digest references and a protected account TOTP secret file; the boot script refuses a missing staged release, Git checkout, mutable tag, missing private operator list, or invalid secret.
- `scripts/gcp/promote-immutable-web.ps1` verifies candidate and rollback signatures, preflights image pulls, stages configuration, and can switch the VM to the least-privilege runtime service account during a controlled restart.
- Tagged container releases now request SBOM/provenance attestations and keyless Cosign signatures for each published digest.
- CI now defines scheduled Rust dependency auditing and Trivy source/image scans; the first hosted run remains pending.
- `scripts/gcp/verify-immutable-deployment.sh` provides a read-only authenticated-host check for Cosign signatures, image digests, unprivileged containers, health, and public contracts; it is ready for the first signed candidate but has not run because no production digest inputs exist yet.

These are source changes awaiting the production promotion process. They do not change the live deployment until committed, built as an immutable image, and verified on the cloud host.

## Recommended implementation order and acceptance criteria

1. **Provision trust evidence.** Complete H2–H3: rotate production operator keys, pin fingerprints, deploy the signed checkpoint publisher, and add independently verified receipts/finality. Acceptance: a disposable production checkpoint is verifiable from a clean client and mismatches are rejected.
2. **Finish authorization tests.** Expand H5–H7 and M7 coverage to every route and role; add distributed rate limiting, recovery notifications, and device re-enrollment. Acceptance: revoked devices lose sessions, cross-origin mutations fail, and abusive TOTP/recovery attempts are throttled and audited.
3. **Protect and rotate secrets.** Implement H8 and M8. Acceptance: no signing/TOTP secret is present in source, tracked archives, image layers, or logs; startup fails on weak/missing key configuration.
4. **Make collection durable and fast.** Complete M3–M5 with parallel replication, regional collectors, durable jobs/events, retry/backoff, and restart recovery. Acceptance: a collector restart preserves history and in-flight job intent; p95 regional latency and stale-data alarms are visible.
5. **Harden deployment.** Complete M6/M10 and the deployment secret migration, then build/publish an immutable signed image digest with rollback. Acceptance: a clean host reproduces the image from a recorded commit and health/readiness checks fail closed.
6. **Finish verification and documentation.** Add L1–L3 gates, run a canary account with passkey/TOTP/invitation/recovery flows, test TUI on supported OSes, run a recovery drill, and update status docs with evidence links.

## Verification record

Passed during this audit:

- `node apps/ui/audit.test.cjs` — dashboard regressions, WCAG 2.1 AA checks, and enhancement tests passed.
- `node tests/dashboard_container_contract.cjs` — passed (including the lockfile-enforced account image contract).
- `cargo fmt --all -- --check` — passed.
- `cargo test -p ciphervault-account --locked -- --test-threads=1` — 7 passed, including persisted rate-limit state across a reopened account database.
- `cargo test -p ciphervault-operator --locked` — library and HTTP-auth tests passed (8 library, 3 integration).
- `cargo test -p ciphervault-crypto --locked` — 25 library and 4 constant-time tests passed.
- `cargo test -p ciphervault-cli --test security_beta_gate --locked` — 7 passed; CLI binary unit suite now has 18 passing tests including collector restart reconciliation.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — passed after the account error-boundary and proxy-header changes.
- `cargo test --workspace --locked --jobs 1` — all workspace, integration, and doc tests passed after the latest account authorization changes.
- `cargo test -p ciphervault-storage --locked` — 5 passed after relay verification and pooled-read changes.
- `docker compose --env-file deploy/gcp/.env.example -f deploy/gcp/docker-compose.web.yml config --quiet` — passed with digest and secret-file placeholders.
- `docker compose --env-file deploy/docker/.env.example -f deploy/docker-compose.prod.yml config --quiet` — passed with the protected secret-file contract.
- Production-mode account image startup without a key mount — failed closed before accepting traffic, as required.
- `docker compose -f deploy/docker-compose.prod.yml build --progress plain` — all six production service images built successfully; the final dashboard/account/operator/maintenance rebuilds used `cargo build --release --locked`.
- `docker compose -f deploy/docker-compose.prod.yml build account` — final account image rebuild passed after the proxy-header trust change.
- `docker compose -f deploy/docker-compose.prod.yml build dashboard` — final dashboard image rebuild passed with collector restart reconciliation included.
- Built runtime images run as the unprivileged `ciphervault` user; dashboard and account images expose health checks.
- Tracked-file secret scan — no literal 32-byte TOTP/checkpoint signing-key assignments or PEM private keys found; environment variable names remain by design.
- Security workflow execution — configured in `.github/workflows/security.yml` and the release image job, but not executed from this uncommitted checkout.

Not passed or not completed:

- Live passkey registration/login, TOTP login, invitations, recovery, device revocation propagation, physical-token operation, receipt/finality verification, cloud rollout, and immutable image signing/attestation — not executed in this audit. Local Docker builds and health/Compose contracts passed. A least-privilege runtime service account was created and granted access to the account TOTP secret, but it is not attached to the running VM until a signed candidate and rollback image are available.

## Release decision

Keep the public explorer available as an explicitly unverified telemetry view. The local release gate is now green, but hold the next private hosted-account release until production identities/checkpoints, secret migration, full authorization evidence, durable collection, and immutable deployment are proven from a clean host. The project has enough working functionality for continued controlled testing, but current production evidence does not support a claim of complete production readiness.
