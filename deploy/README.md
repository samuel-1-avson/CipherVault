# CipherVault — Dockerized Staging Cluster & Service Deployment

This directory contains the production-grade containerization and orchestration definitions for running **CipherVault** in an isolated multi-node environment.

---

## 1. Architecture

```text
Host Network (127.0.0.1)
  │
  ├── 8201 ──> [ciphervault-operator-1] (Volume: op1_data)
  ├── 8202 ──> [ciphervault-operator-2] (Volume: op2_data)
  └── 8203 ──> [ciphervault-operator-3] (Volume: op3_data)
                    ▲           ▲           ▲
                    │           │           │
             [ciphervault-maintenance] (Autonomous Self-Repair)
                 (Internal Bridge Network: ciphervault-net)
             [ciphervault-account] (Durable control-plane identity service)
```

### Security & Invariants
- **Non-Root Execution**: Every daemon runs under the unprivileged `ciphervault` user (UID 10001, GID 10001).
- **Persistent Cryptographic Identities**: Operator signing keys (`operator.key`) are generated on first startup and persisted into named Docker volumes (`op1_data`, `op2_data`, `op3_data`), preventing key churn across container recycles.
- **Health Probes**: Built-in `HEALTHCHECK` probes query `GET /healthz` every 5 seconds and report storage/key readiness.
- **Operator Route Protection**: Production Compose enables `CIPHERVAULT_OPERATOR_STRICT_AUTH=true`. Internal maintenance, peer gossip, and relayer calls may use the shared `CIPHERVAULT_OPERATOR_SERVICE_TOKEN`; vault-scoped object and lease calls use a challenge session plus the `X-CipherVault-Id` header.
- **Signing-Key Protection**: Keys are created with mode `0600` on Unix. Existing keys are checked and repaired at startup; use `--rotate-key` to move the current key to a timestamped backup and generate a replacement after publishing the new fingerprint.
- **Autonomous Repair**: The `maintenance` container continuously audits the cluster, discovers reachable nodes, and monitors retention runways.
- **Hosted Account Service**: The optional `account` container persists account/device/session metadata in SQLite, verifies account-signed device enrollment proofs, and propagates device revocations to configured operators. It stores no vault plaintext or private vault keys.

---

## 2. Quickstart

### Launch the Cluster
```bash
docker compose up -d
```

The local Compose file starts the account service on `127.0.0.1:8300`; the
production file keeps it on the private Compose network. Set
`CIPHERVAULT_OPERATOR_ENDPOINTS` and `CIPHERVAULT_OPERATOR_SERVICE_TOKEN` for
revocation propagation. WebAuthn credentials are verified for `none`
attestation (Ed25519 or ES256) when the RP ID and origin are configured; they
are never accepted as vault-key signatures by this service.

For a browser client, set `CIPHERVAULT_WEBAUTHN_RP_ID` (for example,
`vault.example.com`), `CIPHERVAULT_WEBAUTHN_ORIGIN` (the exact HTTPS origin),
and `CIPHERVAULT_ACCOUNT_ALLOWED_ORIGINS` to the same allowlisted origin(s).
The defaults are suitable only for local development (`localhost` and
`http://localhost:8300`).

To label probes by region, set `CIPHERVAULT_OPERATOR_REGIONS` to entries such
as `us-central=https://op-a,https://op-b;eu-west=https://op-c`. The collector
persists the region on each observation and job while retaining the existing
`CIPHERVAULT_OPERATORS` fallback.

The account API is intentionally private in the production Compose topology.
It exposes `/healthz`, capability discovery at `GET /v1/capabilities`, account
creation at `POST /v1/accounts`, challenge-based
device enrollment and login under `/v1/accounts/*` and `/v1/sessions/*`, and
authenticated audit retrieval at `GET /v1/accounts/:account_id/audit`. WebAuthn
credentials can be independently revoked at
`POST /v1/accounts/:account_id/webauthn/credentials/:credential_id_hex/revoke`.
The hosted dashboard proxies passkey options and verification through
`/api/account/webauthn/*`, preserving the HttpOnly session cookie. Invitations
and membership roles are available through
`/v1/accounts/:account_id/invitations`, `/v1/invitations/accept`, and
`/v1/accounts/:account_id/memberships`; one-time recovery codes use
`/v1/accounts/:account_id/recovery/codes` and `/v1/recovery/redeem`.
Authenticator-app MFA uses RFC 6238 six-digit codes. In production, set
`CIPHERVAULT_ACCOUNT_TOTP_KEY_FILE` to a protected file containing one unique
32-byte hex wrapping key and leave
`CIPHERVAULT_ACCOUNT_REQUIRE_TOTP_KEY=true`. The account container mounts that
file read-only at `/run/secrets/account-totp-key`; no TOTP wrapping secret is
placed in the Compose environment. `CIPHERVAULT_ACCOUNT_TOTP_KEY` remains only
as a local-development compatibility input. TOTP seeds are stored as
AES-256-GCM envelopes in the account database and are never logged or returned
after enrollment. The dashboard exposes authenticator sign-in and
account-management enrollment controls through the same-origin
`/api/account/totp/*` proxy.
Keep the
service behind the private network until a managed browser session, production
origin policy, and per-client rate limits have been provisioned.

Successful account-key and WebAuthn logins also issue an HttpOnly
`ciphervault_account_session` cookie for same-origin browser clients. Set
`CIPHERVAULT_ACCOUNT_COOKIE_SECURE=true` whenever the service is reached over
HTTPS; it defaults to an insecure cookie only for the local `localhost` origin.
The GCP startup script reads the `webauthn-rp-id`, `webauthn-origin`, and
`account-allowed-origins` instance attributes and writes these values to the
private Compose environment; set them explicitly before enabling browser
access.

### Inspect Container Status & Health
```bash
docker compose ps
```

For a hosted release, do not promote a mutable tag or build from a VM checkout.
The release workflow publishes signed GHCR digests. Phase 1/2 promotion stages
the reviewed Compose and Caddy files, attaches the dedicated runtime service
account, retrieves the TOTP wrapping key only from Secret Manager, and starts
the VM with digest-pinned images. It requires a signed candidate and a signed
rollback pair:

```powershell
.\scripts\gcp\promote-immutable-web.ps1 `
  -DashboardImage 'ghcr.io/samuel-1-avson/ciphervault-dashboard@sha256:<candidate>' `
  -AccountImage 'ghcr.io/samuel-1-avson/ciphervault-account@sha256:<candidate>' `
  -RollbackDashboardImage 'ghcr.io/samuel-1-avson/ciphervault-dashboard@sha256:<rollback>' `
  -RollbackAccountImage 'ghcr.io/samuel-1-avson/ciphervault-account@sha256:<rollback>' `
  -OperatorEndpoints 'http://10.x.x.x http://10.x.x.x http://10.x.x.x' `
  -RuntimeServiceAccount '<runtime-service-account>'
```

The command above is a signature and pull preflight. Add `-Apply` only after
the candidate, rollback images, private endpoint list, and release commit have
been recorded. The tool never accepts or prints a secret value.

After the cloud host has been promoted, run the read-only verification script
from an authenticated operator workstation:

```bash
export CIPHERVAULT_DASHBOARD_IMAGE='ghcr.io/samuel-1-avson/ciphervault-dashboard@sha256:<digest>'
export CIPHERVAULT_ACCOUNT_IMAGE='ghcr.io/samuel-1-avson/ciphervault-account@sha256:<digest>'
export COSIGN_CERTIFICATE_IDENTITY_REGEX='https://github.com/samuel-1-avson/CipherVault/.github/workflows/release.yml@refs/tags/.*'
export INSTANCE_NAME=cv-web-ui
export ZONE=us-east1-b
./scripts/gcp/verify-immutable-deployment.sh
```

The check verifies keyless Cosign signatures, local digest identity, cloud
container digests, unprivileged runtime users, container health, and the public
explorer/account contracts. It does not accept or print production secrets and
does not perform a rollout.

Set the internal service token before starting a strict cluster and keep it in the deployment secret manager rather than committing it to `.env`:

```bash
export CIPHERVAULT_OPERATOR_SERVICE_TOKEN="$(openssl rand -hex 32)"
export CIPHERVAULT_OPERATOR_STRICT_AUTH=true
docker compose up -d
```

Before issuing a strict-mode session, enroll the vault device public key through
the service-token-protected identity registry. The registry is persisted in the
operator data volume and survives restarts; revoking an identity also revokes
its active sessions:

```bash
curl -X POST http://127.0.0.1:8201/v1/identities \
  -H "X-CipherVault-Service-Token: $CIPHERVAULT_OPERATOR_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vault_id_hex":"<64-hex-vault-id>","public_key_hex":"<64-hex-device-key>"}'
curl -H "X-CipherVault-Service-Token: $CIPHERVAULT_OPERATOR_SERVICE_TOKEN" \
  http://127.0.0.1:8201/v1/identities
```

For a linked account, include the same `cvacct_…` account ID and enrolled
device ID in the identity record. The client then repeats those identifiers on
challenge issuance; strict mode rejects a missing or mismatched binding:

```json
{"vault_id_hex":"<64-hex-vault-id>","public_key_hex":"<64-hex-device-key>","account_id":"cvacct_<32-hex>","device_id_hex":"<64-hex-device-id>"}
```

The account/device fields are optional during migration. Production should
provision them through the owner-controlled enrollment ceremony before making
the binding mandatory.

The public explorer independently pins operator identity keys with
`CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES`, using comma-separated
`operator-id=public-key` entries (or bare public keys). Without this registry,
operator responses remain explicitly unverified.

Example Output:
```text
NAME                     IMAGE                      STATUS                    PORTS
ciphervault-operator-1   ciphervault/operator:latest   Up (healthy) 8201->8201/tcp
ciphervault-operator-2   ciphervault/operator:latest   Up (healthy) 8202->8202/tcp
ciphervault-operator-3   ciphervault/operator:latest   Up (healthy) 8203->8203/tcp
ciphervault-maintenance  ciphervault/maintenance:latest Up
```

### Stream Live Maintenance Logs
```bash
docker compose logs -f maintenance
```

---

## 3. Automated Cluster Verification Drill

To run the automated acceptance drill verifying 3-way replication, container fault injection, and clean-machine paper recovery:

### Windows (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-cluster.ps1
```

### Linux / macOS:
```bash
./scripts/verify-cluster.sh
```

---

## 4. Disaster Simulation & Recovery Commands

### Simulate Losing an Operator
```bash
docker compose stop operator-1
```
*Client continues to function normally using 2-of-3 quorum.*

### Clean Machine Recovery (Without Coordinator)
```bash
ciphervault recover --kit printed_recovery_kit.txt --to ./restored_secrets/
```

### Recover the Operator
```bash
docker compose start operator-1
```
*The maintenance service automatically detects the restored operator and triggers self-repair to sync any missed chunks.*

### Teardown & Reset
```bash
# Stop containers
docker compose down

# Stop containers and erase all volume state
docker compose down -v
```
