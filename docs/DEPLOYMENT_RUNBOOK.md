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
