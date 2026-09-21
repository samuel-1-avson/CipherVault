# CipherVault: Master Production Deployment & Operations Runbook

**Document ID:** `CV-OPS-2026-v1.0`  
**Classification:** Enterprise Production Operations & Infrastructure Runbook  
**Version:** `1.0.0` (Production Milestone)  

---

## Executive Overview

This runbook specifies the production deployment architecture, provisioning automation, cost model, ingress security, and disaster recovery procedures for operating **CipherVault Storage Operator Clusters**, **Autonomous Maintenance Daemons**, and **Ingress Gateways**.

CipherVault supports two primary production deployment models:
1. **Cloud VPS Cluster (Recommended for Production)**: Multi-region Google Cloud Platform (GCP) Compute Engine instances providing true geographic failure isolation across Iowa and South Carolina at ~$0.97/day.
2. **Private VPC / On-Premise Enterprise (Docker Compose)**: Containerized deployment within corporate datacenters, internal VPCs, or behind VPN/Tailscale overlays.

---

## 1. Cloud Architecture & Quorum Topology

To guarantee continuous availability, zero single points of failure, and partition resilience, storage operators are deployed across **multiple independent availability zones and regions**:

```text
                           DEVELOPER CLIENTS / CI/CD
                           
             ┌─────────────────────────┬────────────────────────┐
             │                         │                        │
             ▼ HTTP/HTTPS              ▼ HTTP/HTTPS             ▼ HTTP/HTTPS
    ┌──────────────────┐      ┌──────────────────┐     ┌──────────────────┐
    │   cv-operator-1  │      │   cv-operator-2  │     │   cv-operator-3  │
    │  Region:         │      │  Region:         │     │  Region:         │
    │  us-central1-a   │      │  us-central1-b   │     │  us-east1-b      │
    │  (Iowa, USA)     │      │  (Iowa, USA)     │     │  (S. Carolina)   │
    ├──────────────────┤      ├──────────────────┤     ├──────────────────┤
    │ Caddy (TLS 443)  │      │ Caddy (TLS 443)  │     │ Caddy (TLS 443)  │
    │ Operator (:8201) │      │ Operator (:8201) │     │ Operator (:8201) │
    │ 20GB Persistent  │      │ 20GB Persistent  │     │ 20GB Persistent  │
    └────────┬─────────┘      └────────┬─────────┘     └────────┬─────────┘
             │                         │                        │
             └─────────── P2P Gossip / Quorum Consensus ────────┘
```

### High Availability Invariants
* **Regional Fault Isolation**: `us-central1` (Iowa) and `us-east1` (South Carolina) are approximately 1,000 miles apart. If a hurricane or power grid failure takes down the Midwest region, the South Carolina node survives.
* **Byzantine Quorum**: The system requires a 2-of-3 quorum. If one node experiences maintenance or hardware crash, developer pushes, pulls, and restores continue without interruption.
* **Persistent Cryptographic Identity**: Each operator generates its Ed25519 node signing key (`operator.key`) on a persistent SSD volume (`/opt/ciphervault/data/`) that survives reboots, image updates, and container recreations.
* **Ingress Filtering**: Ingress is strictly firewalled to TCP ports 80 and 443. The operator process (port 8201) binds to `127.0.0.1` behind the Caddy reverse proxy.

---

## 2. Active Cloud Cluster Status & Endpoints

The official CipherVault operator quorum is active and verified on Google Cloud Platform:

| Node | GCP Region | Geographical Location | Availability Zone | Machine Type | Shielded Gateway Endpoint | Status |
|---|---|---|---|---|---|---|
| **`cv-operator-1`** | `us-central1` | Council Bluffs, Iowa | `us-central1-a` | `e2-micro` | `https://vault.cipherv.online/op/1` | **`200 OK` (TLS Shielded)** |
| **`cv-operator-2`** | `us-central1` | Council Bluffs, Iowa | `us-central1-b` | `e2-micro` | `https://vault.cipherv.online/op/2` | **`200 OK` (TLS Shielded)** |
| **`cv-operator-3`** | `us-east1` | Moncks Corner, SC | `us-east1-b` | `e2-micro` | `https://vault.cipherv.online/op/3` | **`200 OK` (TLS Shielded)** |

### Client Connection String
```bash
ciphervault init --operators https://vault.cipherv.online/op/1 https://vault.cipherv.online/op/2 https://vault.cipherv.online/op/3
```

---

## 3. Sizing & Cost Model

| Component | Sizing per Node | Unit Rate | Cost per Node / Mo | 3-Node Cluster Total |
|---|---|---|---|---|
| **Compute Engine (`e2-micro`)** | 2 vCPUs (shared), 1.0 GB RAM | ~$0.0084 / hour | ~$6.13 / month | **~$18.39 / mo** |
| **Always Free Tier Credit** | 1 free `e2-micro` VM per month | — | -$6.13 / month | **-$6.13 / mo** |
| **Boot Disk (`pd-balanced` SSD)**| 20 GB SSD | $0.10 / GB / month | $2.00 / month | **$6.00 / mo** |
| **In-Use External IPv4** | 1 Standard Public IP | $0.005 / hour | ~$3.65 / month | **~$10.95 / mo** |
| **Network Egress (Bandwidth)** | First 100 GB/mo free | $0.00 | $0.00 | **$0.00** |
| **Total Estimated Cost** | — | — | — | **~$29.21 / month** |

> **Daily Burn Rate**: Approximately **~$0.97 / day** across all 3 nodes.

---

## 4. Cloud VPS Deployment Automation (GCP)

CipherVault provides one-click provisioning scripts that handle authentication, cloud firewall configuration, multi-region instance creation, and cloud-init bootstrap in under 3 minutes.

### One-Click Provisioning

#### Windows (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File scripts/gcp/deploy-operators.ps1
```

#### Linux / macOS (Bash)
```bash
bash scripts/gcp/deploy-operators.sh
```

### Automated Cloud-Init Bootstrap (`deploy/gcp/startup.sh`)
When each VM launches, `startup.sh` executes idempotently:
1. **Swapfile Configuration**: Configures a 4GB swapfile (`/swapfile`) on the root SSD, preventing Out-Of-Memory (OOM) errors during container execution or builds on small instances.
2. **Docker Engine Installation**: Installs Docker CE, containerd, and Docker Compose plugin.
3. **Storage Layout & Non-Root Permissions**: Creates `/opt/ciphervault/data`, `/opt/ciphervault/caddy_data`, and sets ownership to non-root UID 10001 (`ciphervault`).
4. **Metadata Resolution**: Extracts instance name from GCP metadata server (`http://metadata.google.internal`) to dynamically assign Operator ID (`cv-operator-1`, etc.).
5. **Caddy Ingress Setup**: Configures reverse proxy with HSTS, `nosniff`, `DENY`, and 5MB max payload limits.
6. **Container Launch**: Launches `ciphervault-operator` and `caddy` services with `restart: always`.

### One-Click Cluster Teardown
To permanently decommission the cluster and immediately halt all GCP billing:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/gcp/teardown-operators.ps1 -DeleteFirewall
```

---

## 5. Private VPC / On-Premise Deployment (Docker Compose)

For corporate environments requiring all nodes to remain inside a private network or internal datacenter:

### Step 1: Clone Repository
```bash
git clone https://github.com/samuel-1-avson/CipherVault.git /opt/ciphervault
cd /opt/ciphervault
```

### Step 2: Configure Environment
Create `/opt/ciphervault/.env`:
```ini
ACME_EMAIL=security@yourdomain.com
TLS_MODE=acme
OPERATOR_DOMAIN_1=node1.ciphervault.internal
OPERATOR_DOMAIN_2=node2.ciphervault.internal
OPERATOR_DOMAIN_3=node3.ciphervault.internal
DASHBOARD_DOMAIN=dashboard.ciphervault.internal
```

### Step 3: Launch Stack
```bash
docker compose -f deploy/docker-compose.prod.yml up -d
```

### Step 4: Verify Services
```bash
docker compose -f deploy/docker-compose.prod.yml ps
```
All containers (`ciphervault-ingress`, `operator-1`, `operator-2`, `operator-3`, `maintenance`, `dashboard`) should report `healthy` or `running`.

---

## 6. Ingress Hardening, Security Headers & Rate Limiting

### Caddy Reverse Proxy Configuration (`deploy/gcp/Caddyfile.gcp`)
Each operator ingress enforces:
- **Strict Security Headers**:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **Request Body Guard**: Caps request bodies at 5 MiB (`max_size 5MB`), preventing buffer exhaustion attacks.
- **Connection Keepalives**: Reuses persistent TCP connections between Caddy and the operator backend.

### Cloudflare / Edge WAF Rate Limiting Policy
If deploying behind an edge CDN (Cloudflare or Google Cloud Armor):
- `POST /v1/challenges`: 30 req/min per IP.
- `POST /v1/auth`: 15 req/min per IP.
- `POST /v1/objects/*`: 120 req/min per authenticated caller.
- `GET /v1/objects/*`: 300 req/min per IP.

### Public explorer per-client limits (in-app, not the edge)
Do NOT put `rate_limit` in `deploy/gcp/Caddyfile.web.gcp`: stock Caddy has no such directive (verified on the pinned v2.11.4 image - `list-modules` shows no rate module and the docs page 404s). The 1.0.7 promotion proved that adding it crash-loops the edge and takes the site down, and no version bump can fix that. Per-client bounding therefore lives in the dashboard as middleware (shipped in 1.0.8: fixed 60 s windows, 429 + `Retry-After`, fails open; `CIPHERVAULT_TRUST_XFF=1` behind the edge proxy so the limiter keys on the Caddy-appended XFF address, unset for direct `--serve` so it keys on the TCP peer and ignores spoofable XFF). Budgets:
- `GET /api/explorer/object/*`: 30 req/min per IP - each lookup fans out to every operator, so this budget stops the explorer being used as an amplifier.
- Everything else on the site: 600 req/min per IP (covers the 30 s UI polling plus bursts).
Every promotion runs `caddy validate` against the pinned image before the VM stops, and keeps a last-good config snapshot for rollback (see the promote script); both exist because of this incident.

### Explorer access-log hygiene
`GET /api/explorer/object/:cid` carries the 64-hex content ID in the URL path,
so reverse-proxy access logs record every CID a visitor looks up. Presence
still requires prior knowledge of the CID (the endpoint only answers "which
operators hold it"), so impact is minimal — but treat explorer access logs as
CID-bearing: keep rotation tight and redact `:cid` path segments before
shipping logs anywhere operators or visitors cannot already see.

---

## 7. Monitoring, Health Probing & Maintenance

### Real-Time Cluster Health Verification
Run the cluster verification script to validate all nodes, P2P peer tables, and cryptographic responses:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-cluster.ps1
```

### Inspecting Operator Logs on GCP
Connect to any node via `gcloud` to view real-time container logs:

```bash
# Node 1
gcloud compute ssh cv-operator-1 --zone=us-central1-a --command="sudo docker logs -f ciphervault-operator"

# Ingress Proxy
gcloud compute ssh cv-operator-1 --zone=us-central1-a --command="sudo docker logs -f ciphervault-caddy"
```

### Autonomous Self-Repair (Maintenance Daemon)
The maintenance daemon (`ciphervault-maintenance`) continuously:
1. Pings operator health endpoints (`/v1/info`) every 30 seconds.
2. If an operator reports degraded durability, triggers a Proof-of-Storage audit across all stored CIDs.
3. Automatically replicates missing chunk replicas from surviving quorum nodes to restore 3-of-3 durability.

## 8. Operator Identity Ceremony & Rotation

### Provisioning a new operator identity
1. Start the operator once so it generates `operator.key` (mode `0600`) in its data directory.
2. Print the trust-registry entry offline (no ports bound, no service token needed):
   ```sh
   ciphervault-operator --data-dir ./data/op1 --operator-id op_8201 --print-identity
   # op_8201=<64-hex-public-key>
   ```
3. Append the entry to the dashboard environment `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES`
   (comma-separated `operator-id=key` entries or bare keys), then restart the dashboard.
4. Confirm the explorer operator card flips from `Unverified` to `Verified` for that node.

### Rotation (also the revocation procedure)
1. Rotate and print the replacement entry in one step (the old key moves to a
   timestamped `operator.key.previous-*` backup):
   ```sh
   ciphervault-operator --data-dir ./data/op1 --rotate-key --print-identity
   ```
2. Add the new fingerprint to `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES` alongside the old
   one, restart the dashboard, and confirm `Verified`.
3. Remove the old fingerprint from the registry. Registry removal **is** revocation at this
   scale: if the retired key ever reappears, the dashboard reports `Unverified`.

### Monitoring
- `/api/operators` reports `identity_status`: `verified`, `expiring_soon` (< 6h to expiry),
  `expired`, `unverified`, or `not_observed` (unreachable). Cards render amber `Expiring soon`.
- Identity self-signatures expire 24h after issuance (`/v1/info`); expiry affects display
  freshness only, never lease validity. Persistent `expired` on a reachable node means its
  clock or `/v1/info` signer is broken - investigate before rotating.

## 9. Checkpoint Publisher, Finality & Canary

### Deploying the signed publisher
1. Generate a dedicated Ed25519 publisher key offline; fund nothing - it only signs feed JSON.
2. Set `CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX` on the publisher worker and run
   `deploy/docker/entrypoint-public-feed-publisher.sh` (default 60 s refresh into the file
   referenced by the dashboard's `CIPHERVAULT_PUBLIC_CHECKPOINT_FEED`).
3. Pin the publisher on the dashboard with `CIPHERVAULT_PUBLIC_CHECKPOINT_PUBLISHER_KEY`
   (64-hex of the publisher verifying key). A feed signed by any other key is rejected.
4. Confirm `/api/anchors` returns records with `verification_status: publisher_signed`.

### Independent finality (optional but recommended)
- Set `CIPHERVAULT_ARBITRUM_RPC_URL` to a trusted Arbitrum RPC endpoint. The dashboard then
  queries `eth_getTransactionReceipt` per checkpoint transaction plus `eth_blockNumber`,
  and reports `finality_status`: `finalized` (>= `CIPHERVAULT_FINALITY_CONFIRMATIONS`,
  default 12), `confirmed`, `pending`, `failed` (reverted receipt), or `unknown` (RPC error).
- Receipts are fetched in bounded batches and cached for 60 s; without an RPC URL the feed
  keeps the legacy `unverified` finality and nothing else changes.

### Canary alarm
- `relayer_status.canary_status` is `ok`, `stale`, or `missing`, computed from the newest
  checkpoint age against `CIPHERVAULT_CHECKPOINT_CANARY_MAX_AGE_SECS` (default 86400 = 24h).
- The explorer renders amber `STALE` and red `MISSING` badges; treat either as a paging
  alarm: the anchor daemon, publisher worker, or feed mount is broken.
- Tune the max age to roughly 3x the anchor daemon interval (default daemon: 3600 s).

### Reorg alarm
- The dashboard remembers finalized receipts across refreshes. A checkpoint whose
  finalized receipt vanishes or re-mines at another block flips to
  `finality_status: reorg_suspected`, the feed reports `reorg_suspected: true`
  with the suspect tx hashes, and the dashboard host logs a stderr alarm line.
- The alarm is sticky until the receipt re-finalizes; checkpoints removed from
  the publisher feed never alarm. Treat a live alarm as a paging event: verify
  the RPC endpoint first (a wedged node mimics a reorg), then the chain.

## 10. Secret Cutover, Rotation & Signed Promotion (R3/R4)

All tooling below already exists; this section is the execution checklist for the
live `vault.cipherv.online` cutover. Perform in order; stop on the first red check.

### R3: TOTP key cutover to Secret Manager
1. Create/rotate the secret: `gcloud secrets create ciphervault-account-totp-key
   --replication-policy=automatic` (or `add-version` with 32 fresh random bytes).
2. Grant the web runtime service account `secretmanager.secretAccessor` on that secret only.
3. Set instance metadata `account-totp-secret=ciphervault-account-totp-key` on `cv-web-ui`.
4. Re-run `deploy/gcp/startup-web.sh` (or recreate the instance): it writes the key to the
   read-only mount `/run/secrets/account-totp-key` consumed by the compose files.
5. Delete the legacy value from `/opt/ciphervault-ui/.env`, rotate it (it was long-lived),
   and confirm no log, image layer, or crash dump contains the key material.
6. Apply the same ceremony to operator signing keys before calling rotation done.

### R4: first signed-digest promotion
1. Tag a release; confirm `release.yml` published GHCR digests with SBOM + SLSA provenance
   and a cosign signature (keyless, identity-bound to the release workflow).
2. Record the current live digests as rollback images.
3. Dry-run: `scripts/gcp/verify-immutable-deployment.sh` with
   `CIPHERVAULT_DASHBOARD_IMAGE` / `CIPHERVAULT_ACCOUNT_IMAGE` set to the new
   `ghcr.io/...@sha256:...` digests plus `COSIGN_CERTIFICATE_IDENTITY_REGEX`.
4. Promote: `scripts/gcp/promote-immutable-web.ps1 -DashboardImage ... -AccountImage ...
   -RollbackDashboardImage ... -RollbackAccountImage ... -OperatorEndpoints ...
   -RuntimeServiceAccount ... -ExpectedBuildVersion <cli-crate-version> -Apply`
   (omit `-Apply` for a plan-only run).
5. Verify live: the script already asserts the live `/api/context`
   `build_version` plus `/api/operators` and `/api/explorer/overview`
   (mismatch rolls back automatically). Independently confirm the explorer
   loads and `docker inspect` on the VM reports the promoted digests.

### Phase 1 exit criteria
- R1: dashboard env pins all 3 operator identities; cards show Verified; rotation drilled.
- R2: publisher deployed + key pinned; RPC finality live; canary ok; alarm tested (stale).
- R3: live TOTP key served from Secret Manager mount; legacy value rotated away.
- R4: live VM runs CI-built signed digests; rollback path tested.

## 11. Multi-Replica Account Service & Abuse Alerts

The account service is deployed as a single instance by default; the authentication
rate limiter (`auth_rate_limits`) then needs no coordination beyond its SQLite store.
For multi-replica deployments, all replicas MUST share one `CIPHERVAULT_ACCOUNT_DATA_DIR`
volume so failure windows and lockouts stay consistent. SQLite single-writer semantics
serialize concurrent limiter writes (WAL + busy timeout absorb bursts); if lock contention
appears in logs, scale vertically or shard by account range - a Redis-backed limiter is
future work, not implemented.

Every fresh lockout emits two alert signals: an `auth_rate_lockout` row in `audit_events`
(per-account, queryable via the account audit API) and a stderr line
`account auth rate lockout: ceremony=... source=... blocked_until_utc=...`. Ship stderr
to the log aggregator and page on lockout spikes per source; the audit row is the
per-account source of truth for incident review.

### Team role matrix + approval queue (R14)

The hosted account modal shows a role matrix (owner/admin/editor/viewer/recovery
minimums per capability, enforced by the account service) and a read-only
approval queue aggregating pending out-of-band challenges from every configured
operator (GET /api/approvals on the private dashboard only; never exposed on
the public explorer). The queue needs CIPHERVAULT_OPERATOR_SERVICE_TOKEN on
the dashboard host; without it each operator reports unavailable. Approvals
themselves are submitted through the CLI guardian ceremony, never the browser.

## 12. Performance Tuning (Caps + Chunking)

Three operator caps are runtime-tunable via environment (plain bytes or `KB`/`MB`
suffixes); invalid or below-floor values warn on stderr and fall back to defaults:

- `CIPHERVAULT_MAX_OBJECT_SIZE` (default 4 MiB, floor 512 KiB): largest single
  chunk/manifest object. Lower it to bound memory on small nodes.
- `CIPHERVAULT_MAX_RECOVERY_RECORD_SIZE` (default 64 KiB, floor 4 KiB).
- `CIPHERVAULT_MAX_RECOVERY_RESPONSE_BYTES` (default 16 MiB, floor 1 MiB).

Verified-join knobs (ADR-008; durations in seconds, invalid or below-floor
values warn and fall back to defaults):

- `CIPHERVAULT_FLEET_KEY` (no default): fleet public key (hex) that
  `/v1/peers/join` verifies tickets against. Unset = join fails closed;
  set the same pin on every fleet node that admits community operators.
- `CIPHERVAULT_PROBATION_SECS` (default 86400 = 24 h, floor 60): minimum
  fleet-visible life before a ticket joiner can graduate.
- `CIPHERVAULT_JOIN_LIVENESS_GRACE_SECS` (default 7200 = 2 h, floor 60):
  how recent a joiner's last proof of life must be at graduation time.

Chunking profile via `CIPHERVAULT_CHUNK_PROFILE`: `small` (2/8/32 KiB) for tiny
secret files, `default` (4/16/64 KiB), `large` (16/64/256 KiB) for big blobs.
Pairing rule: the `large` profile needs the default 4 MiB object cap (or at least
512 KiB); lowering the cap below a profile's max chunk rejects uploads.

Replication throughput via `ciphervault push --concurrency N` (1-32, default 4):
bounds how many objects upload and verify concurrently per operator. Raise toward
16 on fast remotes, lower toward 1 on lossy links. Operators always replicate
concurrently, and stragglers are abandoned once the remaining operators cannot
reach quorum.

### Proving push throughput (bench + soak)

`apps/cli/tests/push_bench.rs` (ignored perf test) replicates 48 x 16 KiB
objects across 3 loopback operators at concurrency 1 vs 8 and prints a JSON
summary with the speedup. CI runs it release-mode on Linux (`bench` job):

```sh
cargo test -p ciphervault-cli --release --test push_bench -- --ignored --nocapture
```

- `CIPHERVAULT_BENCH_OBJECTS` / `CIPHERVAULT_BENCH_OBJECT_KB`: workload size.
- `CIPHERVAULT_BENCH_SOAK_ITERS` (default 2): extra concurrent quorum runs;
  every iteration must reach quorum (catches `busy_timeout`/flake regressions).
- `CIPHERVAULT_BENCH_ASSERT=1`: fail unless concurrent is >=2x faster than
  sequential. Default is warn-only so shared CI runners never flake the build.

Phase 3 done-condition: p50 `push` >=2x on a 3-node cluster. Record the
maintainer-run numbers here: sequential ___s, concurrent ___s, speedup ___x,
date/runner ___.

## 13. Metrics, Tracing & Repair Lag (R8/R11)

Operator disk I/O is sharded across 64 per-key striped locks (R8): concurrent
uploads for different CIDs no longer serialize. One `identities.json` lock and
one `events.log` leaf lock remain; both are low-traffic admin paths.

### Operator Prometheus endpoint

Every operator serves `GET /metrics` (same unauthenticated posture as
`/healthz`; firewall it or scrape via loopback/Caddy allowlist):

- `ciphervault_operator_objects_put_total` + `put_latency_ms` histogram:
  push-side store rate and latency.
- `ciphervault_operator_pos_challenges_total` / `pos_failures_total` +
  `pos_latency_ms`: Proof-of-Storage rate.
- `ciphervault_operator_requests_total` (+ `_4xx`/`_5xx`) and
  `request_latency_ms`: request plane.
- Lease, recovery, and `auth_failures_total` counters, plus `uptime_seconds`.
- `ciphervault_swarm_peer_joins_total` /
  `ciphervault_swarm_peer_graduations_total`: verified community joins
  admitted into probation and probation-to-full graduations (ADR-008).
  Standing per peer: `GET /v1/peers/membership` (service token).

Scrape example (all three operators):

```yaml
scrape_configs:
  - job_name: ciphervault-operators
    static_configs:
      - targets: ['op1:8201', 'op2:8202', 'op3:8203']
```

### Request tracing

`ciphervault push` generates a 32-hex trace ID per replication, sends it as
`X-CipherVault-Trace-Id` on every operator request, and prints it with the
replication latency. Operators echo the ID back on every response and, with
`CIPHERVAULT_TRACE_LOG=1`, emit one JSON span per request on stderr:

```json
{"span": "operator_request", "route": "object", "trace_id": "ab...",
 "status": 200, "elapsed_ms": 3}
```

Correlate across the quorum by trace ID; correlate fleet repairs by closure
digest (see below), since the daemon mints its own spans.

### Fleet repair lag

`ciphervault-maintenance --fleet-status` now reports repairs recorded and the
last repair lag (detection-to-repaired seconds). For Prometheus, run:

```sh
ciphervault-maintenance --db fleet.db --metrics > /var/lib/node_exporter/ciphervault_fleet.prom
```

`ciphervault_fleet_last_repair_lag_seconds` is the repair-lag signal;
`repairs_recorded_total` / `repair_failures_total` count sweep outcomes.
Repairs are recorded via `record_repair` by CLI-driven repair flows; the
daemon loop audits but does not yet repair autonomously (it carries no vault
credentials), so daemon-only deployments show zero repairs until autonomous
repair lands.

## 14. Snapshot Retention & Rotation (R18/R13)

### Retention (R18)
`ciphervault prune --keep-last N --keep-days D` (defaults 10 / 30) deletes old
local snapshots: snapshot rows, recovery sets, and chunks unreferenced by any
retained recovery set. Always protected: the active head, snapshots younger
than the policy, and unreplicated snapshots (pending uploads). Chunk GC is
skipped for the run if any retained snapshot lacks a recovery set. `--dry-run`
prints targets without deleting. Remote operator copies are untouched; prune
only reclaims local disk.

### Rotation (R13)
`ciphervault rekey --check` reports every epoch key's age (warns past
`--warn-days`, default 90); `ciphervault rekey` mints epoch N+1 and points new
snapshots at it. Old epoch keys are retained so existing snapshots stay
readable; device-key rotation remains manual (new device certificate ceremony).
Pre-migration keys show unknown age and always warn: rotate once to baseline.

## 15. File Watcher Inspector (R15)

`ciphervault watch --dry-run` (or `ciphervault-agent --dry-run`) runs the
watcher as an inspector: filesystem events still debounce and verify, but each
trigger only builds the snapshot in memory and reports files/chunks/bytes plus
whether replication would run. Nothing is persisted, no counters move, and
pending-upload retries are skipped. Real captures record `WATCH_SNAPSHOT` /
`WATCH_SYNC_FAILED` / `WATCH_CAPTURE_FAILED` rows in the vault activity log,
visible in the dashboard activity feed (`/api/activity`).

## 16. Platform Support & Editor Integration (R16/R17)

Hardware-token support is Windows-only today (WinSCard PC/SC); macOS and Linux
return an empty reader list with a clean platform error. OS key protection is
DPAPI on Windows and a 0600 file-backed keystore elsewhere. The full support
matrix, parity requirements, and the VS Code/git integration spec (gutter data
contract over `ciphervault status --json`) live in
`docs/PLATFORM_SUPPORT.md`.
