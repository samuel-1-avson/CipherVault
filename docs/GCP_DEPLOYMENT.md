# CipherVault Production Deployment Runbook: Google Cloud Platform (GCP VPS)

This runbook specifies the production deployment architecture, provisioning automation, cost model, and operations for running **CipherVault Storage Operators** on **Google Cloud Platform (GCP) Compute Engine Virtual Private Servers (VPS)**.

---

## 1. Cloud Architecture & Quorum Topology

To achieve true disaster recovery, fault tolerance, and zero single points of failure, CipherVault operators are deployed across **multiple independent availability zones and regions**:

```text
                           DEVELOPER CLIENTS / CI/CD
                           
             ┌─────────────────────────┬────────────────────────┐
             │                         │                        │
             ▼ HTTP/HTTPS              ▼ HTTP/HTTPS             ▼ HTTP/HTTPS
    ┌──────────────────┐      ┌──────────────────┐     ┌──────────────────┐
    │   cv-operator-1  │      │   cv-operator-2  │     │   cv-operator-3  │
    │  Region:         │      │  Region:         │     │  Region:         │
    │  us-central1-a   │      │  us-central1-b   │     │  us-east1-b      │
    │  (Iowa)          │      │  (Iowa)          │     │  (S. Carolina)   │
    ├──────────────────┤      ├──────────────────┤     ├──────────────────┤
    │ Caddy (TLS 443)  │      │ Caddy (TLS 443)  │     │ Caddy (TLS 443)  │
    │ Operator (:8201) │      │ Operator (:8201) │     │ Operator (:8201) │
    │ 20GB Persistent  │      │ 20GB Persistent  │     │ 20GB Persistent  │
    └────────┬─────────┘      └────────┬─────────┘     └────────┬─────────┘
             │                         │                        │
             └─────────── P2P Gossip / Quorum Consensus ────────┘
```

### High Availability Invariants
* **Zone Isolation**: If Google Cloud experiences an incident in `us-central1-a`, nodes `cv-operator-2` and `cv-operator-3` retain a 2-of-3 quorum, allowing developers to continue pushing, pulling, and recovering without interruption.
* **Persistent Identity**: Each VM generates its Ed25519 signing key (`operator.key`) into a persistent SSD volume (`/opt/ciphervault/data/`) that survives reboots and container upgrades.
* **Ingress Security**: Ingress is filtered through GCP Cloud Firewall, admitting only TCP ports 80 and 443. All other ports (including internal port 8201) remain bound to `127.0.0.1` behind the Caddy reverse proxy.

---

## 2. Compute Sizing & Cost Model

| Resource | Specification | Monthly Cost (Est.) | Notes |
|---|---|---|---|
| **VM Instance Type** | `e2-small` (2 vCPUs, 2 GB RAM) | ~$13.50 / node | Optimal balance of memory, CPU, and network throughput. |
| **Alternative (Free Tier)** | `e2-micro` (2 vCPUs, 1 GB RAM) | **$0.00** (Free Tier eligible in `us-central1`, `us-west1`, `us-east1`) | Great for community beta and light testing. |
| **Boot & Data Disk** | 20 GB `pd-balanced` SSD | ~$2.00 / node | Fast read/write IOPS for FastCDC chunk retrieval. |
| **Public IP & Egress** | Standard Cloud Egress | ~$0.20 - $1.00 / mo | Minimal network bandwidth thanks to Proof-of-Storage 461-byte challenges. |
| **Total 3-Node Cluster** | 3x `e2-small` + Disks | **~$45.00 / month** | Complete enterprise-grade quorum across 3 availability zones. |

---

## 3. One-Click Provisioning

CipherVault provides an automated provisioning script that checks authentication, configures firewall rules, and provisions all three instances with cloud-init metadata in under 3 minutes.

### Windows (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File scripts/gcp/deploy-operators.ps1
```

### Optional Custom Parameters
```powershell
powershell -ExecutionPolicy Bypass -File scripts/gcp/deploy-operators.ps1 `
    -Project "gen-lang-client-0022105784" `
    -MachineType "e2-small" `
    -DiskSize "30GB" `
    -Zones @("us-central1-a", "us-central1-b", "us-central1-c")
```

### Provisioning Output
```text
=======================================================
  GCP STORAGE OPERATOR CLUSTER PROVISIONED
=======================================================

Node Name           Zone          MachineType ExternalIP     HTTPS_URL
---- ----           ----          ----------- ----------     ---------
1    cv-operator-1  us-central1-a e2-small    34.121.88.10   https://34.121.88.10
2    cv-operator-2  us-central1-b e2-small    35.202.45.22   https://35.202.45.22
3    cv-operator-3  us-central1-c e2-small    34.41.112.5    https://34.41.112.5

Ready-to-use CipherVault Client Initialization Command:
ciphervault init --operators https://34.121.88.10 https://35.202.45.22 https://34.41.112.5
```

---

## 4. Custom DNS & Automated Let's Encrypt TLS

While IP-based internal TLS works out of the box (`tls internal`), you can easily bind public DNS domain names for production use:

1. **Create DNS A Records**:
   - `op1.yourdomain.com` $\to$ External IP of `cv-operator-1`
   - `op2.yourdomain.com` $\to$ External IP of `cv-operator-2`
   - `op3.yourdomain.com` $\to$ External IP of `cv-operator-3`

2. **Update Caddyfile on Instances**:
   SSH into the instance:
   ```bash
   gcloud compute ssh cv-operator-1 --zone=us-central1-a
   ```
   Edit `/opt/ciphervault/Caddyfile`:
   ```caddyfile
   op1.yourdomain.com {
       import operator_security
       reverse_proxy 127.0.0.1:8201
   }
   ```
   Reload Caddy:
   ```bash
   cd /opt/ciphervault && docker compose restart caddy
   ```
   Caddy will automatically obtain and renew signed Let's Encrypt certificates via ACME on port 443!

---

## 5. Operations & Health Probing

### Probing Operator Health
From any computer or monitoring service:
```bash
curl -k https://<EXTERNAL_IP>/v1/info
```

Response:
```json
{
  "operator_id": "cv-operator-1",
  "operator_signing_pk_hex": "4f9a88e...",
  "supported_version": 1,
  "retention_terms": "90-day immutable retention minimum"
}
```

### Inspecting VM Startup & Docker Logs
```bash
# View cloud-init boot logs:
gcloud compute ssh cv-operator-1 --zone=us-central1-a --command="sudo journalctl -u google-startup-scripts.service -f"

# View live operator container logs:
gcloud compute ssh cv-operator-1 --zone=us-central1-a --command="sudo docker logs -f ciphervault-operator"

# View Caddy ingress logs:
gcloud compute ssh cv-operator-1 --zone=us-central1-a --command="sudo docker logs -f ciphervault-caddy"
```

---

## 6. Teardown & Resource Decommissioning

To cleanly delete the 3 instances and stop cloud billing:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/gcp/teardown-operators.ps1
```

To also remove the Cloud Firewall rule:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/gcp/teardown-operators.ps1 -DeleteFirewall
```
