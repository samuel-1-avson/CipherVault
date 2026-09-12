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
```

### Security & Invariants
- **Non-Root Execution**: Every daemon runs under the unprivileged `ciphervault` user (UID 10001, GID 10001).
- **Persistent Cryptographic Identities**: Operator signing keys (`operator.key`) are generated on first startup and persisted into named Docker volumes (`op1_data`, `op2_data`, `op3_data`), preventing key churn across container recycles.
- **Health Probes**: Built-in `HEALTHCHECK` probes query `GET /v1/info` every 5 seconds.
- **Autonomous Repair**: The `maintenance` container continuously audits the cluster, discovers reachable nodes, and monitors retention runways.

---

## 2. Quickstart

### Launch the Cluster
```bash
docker compose up -d
```

### Inspect Container Status & Health
```bash
docker compose ps
```

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
