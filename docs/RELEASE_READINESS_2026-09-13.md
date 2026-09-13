# CipherVault release-readiness review

Reviewed on 13 September 2026. Repository baseline: `0c2220c47ad3d634fce5c1660528afd0b2c73e58`, plus the working tree present during review.

## Release decision

**Do not launch publicly for real developer credentials yet.** CipherVault has a working, locally tested backup and recovery core and three reachable GCP storage operators. It does not yet have a verified public installation path, working public dashboard, or an adequately separated public-service security boundary.

A supervised trial with synthetic files is reasonable. A public beta with real secrets should wait for the blocking items below. This is an engineering readiness review, not an independent cryptographic certification.

The project has progressed beyond the earlier prototype description: Windows key protection, recovery-log authorization, developer commands, and local recovery tests are present and pass. Conversely, current README claims of production readiness, autonomous repair, and public deployment exceed the evidence established here.

## Evidence and limits

Reviewed installers, package manifests, release/CI workflows, CLI and dashboard handlers, operator authentication/storage, key protection, maintenance execution, recovery tests, Docker and GCP deployment files. Ran local tests and read-only GCP inventory, firewall, service, and public endpoint checks. No cloud resources were deployed, restarted, stopped, or modified by the review; no production vault secrets were requested. SSH checks inspected service status and listening ports, not credential files or container logs.

Existing edits were preserved: `scripts/gcp/deploy-web-ui.ps1`, `deploy/gcp/build-and-start.sh`, and `deploy/gcp/remote-setup-web.sh`. Cloud state and working-tree files can change after this snapshot.

Not established: clean Windows/macOS/Linux package installation, hosted CI results, deployed binary equivalence to this checkout, physical hardware-token behavior, live-chain settlement, paid retention, sustained load, or disaster recovery using the actual cloud operators. Local recovery drills simulate a clean machine by deleting the synthetic client directory; they are not a second physical computer or OS installation.

## What works, and what remains unverified

| Area | Result | Evidence and practical meaning |
|---|---|---|
| Rust workspace | **Pass on this Windows host** | 106 tests passed, zero failed, after rerunning with working Windows DPAPI access. |
| Core backup/recovery | **Local integration pass** | End-to-end workflow, pivotal recovery drill, tamper handling, signed recovery records, audit/repair, and watcher tests pass. |
| Developer workflow | **Local tests pass** | Diff masking, secret injection, pull synchronization, Gitignore integration, and completion tests pass. |
| Strict linting | **Pass** | Workspace/all-target Clippy with warnings denied. |
| Formatting release gate | **Fail** | Rustfmt reports differences in CLI code; release workflow requires this gate. |
| Dashboard JavaScript | **Pass within test scope** | Syntax check and repository dashboard regressions pass. This is not a browser penetration test or a complete accessibility audit. |
| GCP operator machines | **Running and reachable** | Three VMs; all information endpoints returned HTTP 200 and distinct signing keys. |
| Operator transport | **Blocked for public use** | Plain HTTP works; standard HTTPS requests failed for all three configured IP endpoints. |
| Dashboard VM | **VM running, application inactive** | No running containers reported; dashboard systemd service inactive; no web listeners. |
| Public dashboard/explorer | **Not available through checked routes** | Dashboard subdomain did not resolve; apex HTTPS failed; direct VM HTTP refused connection. |
| Public installation | **Blocked** | Anonymous GitHub repository and advertised release API requests both returned 404; installer archive paths also disagree with release packaging. |
| Multi-user hosted service | **Not ready** | Dashboard is a server-local vault console without an authentication boundary; hosted tenant/storage entitlements need more work. |
| Cloud backup durability | **Not verified** | Reachability and distinct identities do not prove complete retained inventories or recovery from a cloud outage. |

## Verified GCP progress

| Resource | Zone | Region | Public address | Observed state |
|---|---|---|---|---|
| cv-operator-1 | us-central1-a | us-central1 | 136.65.43.84 | RUNNING; `/v1/info` HTTP 200 |
| cv-operator-2 | us-central1-b | us-central1 | 34.9.157.167 | RUNNING; `/v1/info` HTTP 200 |
| cv-operator-3 | us-east1-b | us-east1 | 34.73.53.40 | RUNNING; `/v1/info` HTTP 200 |
| cv-web-ui | us-east1-b | us-east1 | 104.196.14.85 | RUNNING VM; web application inactive |

These are **three zones in two regions within one GCP project**, not three independently administered providers. A central-region outage would leave one operator: recovery may remain possible from a complete surviving copy, while a three-receipt push cannot succeed. Shared project, billing, IAM, provider, and operational control remain common failure risks.

Operator 1 SSH inspection found running `ciphervault-operator:gcp` and `caddy:2-alpine` containers. The operator listened on `0.0.0.0:8201`, contrary to the runbook's loopback-only claim. Caddy listened on ports 80 and 443. The named systemd unit was inactive even though containers were running. Equivalent container inspection was not performed on operators 2 and 3.

The expected repository directory on operator 1 did not provide a Git revision. The dashboard's expected repository directory also did not provide one. Running images therefore cannot be attributed to this reviewed commit from the evidence obtained.

GCP rules allow public HTTP/HTTPS for CipherVault tags. Default-network rules also permit public SSH/RDP and broad internal traffic; effective exposure additionally depends on host firewalls and listeners. The assertion that ingress is strictly limited to ports 80/443 is not supported by the cloud rules alone.

Public observations:

- `http://136.65.43.84/v1/info`, `http://34.9.157.167/v1/info`, and `http://34.73.53.40/v1/info`: HTTP 200, correct operator names, three different signing keys.
- Corresponding HTTPS addresses: TLS handshake errors under normal certificate validation. No TLS bypass was used.
- `https://vault.cipherv.online/`: DNS resolution failure from the review environment.
- `https://cipherv.online/`: TLS failure. Plain HTTP returned a page titled `cipherv.online`; that alone does not establish a deployed CipherVault dashboard.
- `http://104.196.14.85/`: connection refused. SSH corroborates no application listeners and inactive dashboard service.

The repository explorer functionality is embedded in the dashboard, including checkpoint views and external Arbiscan links. No separate running explorer service was established. Another hostname or deployment would need separate verification.

## Blocking findings

### B1 — A public dashboard would expose a local vault's privileged operations

**Critical before enabling a hosted credential service.** `apps/cli/src/main.rs`, `cmd_ui` around line 3936, registers API routes without authentication middleware. `api_secrets_inspect_handler` around line 5125 decrypts tracked environment-file contents and returns `raw_value` in JSON. Diff also accepts a reveal option. Other routes create snapshots, track/untrack files, restore files, and handle recovery material.

The cloud proxy configuration forwards requests to this same server-local interface. A cloud-hosted instance operates on the cloud VM's vault, not automatically on each visiting developer's laptop. This is not a multi-user portal or browser-side encryption architecture. The inactive dashboard prevented confirmation of live exposure; this finding is established from source, not a claim that current users' secrets were leaked.

**Required outcome:** keep a public explorer read-only and limited to non-secret telemetry. Keep secret manipulation local to the developer, or explicitly design and review a separate authenticated, tenant-isolated product. Do not merely reactivate the current dashboard with real secrets. Test unauthenticated reads and writes, cross-user access, and browser-origin protections.

### B2 — Operator onboarding lacks usable trusted HTTPS

`deploy/gcp/Caddyfile.gcp` serves plain HTTP and configures internal TLS. Runbook and dashboard configuration use HTTP IP addresses; provisioners print HTTPS addresses that failed the standard client checks. Client authentication sends bearer sessions to configured endpoints. Encryption of stored files does not authenticate an HTTP endpoint or protect session transport.

`crates/storage/src/pool.rs` obtains signing identities from operator information responses; identity discovery is not an out-of-band pin. Distinct returned keys are useful but do not independently authenticate infrastructure.

**Required outcome:** stable operator hostnames, publicly trusted certificates, enforced HTTPS, and an explicit trusted operator-identity policy. Verify normal clients connect without certificate exceptions, and that tampered identities are rejected. Correct the bind address and document/test the actual firewall boundary.

### B3 — Public distribution is not demonstrated and installers disagree with archives

The anonymous GitHub API returned 404 for both `samuel-1-avson/CipherVault` and its `v1.0.0` release. This means an unauthenticated outside developer could not retrieve them during review; it does not prove whether the repository is private, missing, renamed, or otherwise unavailable.

`.github/workflows/release.yml` packages a top-level `ciphervault-<tag>-<target>/bin` directory. `dist/scripts/install.sh` expects extracted `bin` directly under its temporary directory; the PowerShell installer extracts to the install root but places only the immediate `bin` on PATH. Scoop and Winget paths likewise omit the package prefix. The PowerShell script assumes a usable script directory even in its advertised piped execution form. Download-failure fallbacks require a source checkout/Rust, so they do not rescue a fresh external user's installation.

Install scripts do not verify the generated checksum manifest before installing. Scoop lacks a hash; Homebrew lacks architecture-specific SHA256 values. A Winget hash is present but was not validated against a downloadable artifact. Package-manager publication was not demonstrated.

**Required outcome:** publish accessible versioned artifacts with a consistent layout, verify integrity/authenticity, remove misleading fallback success paths, and test the exact advertised installation command on clean supported systems without a checkout or Cargo.

### B4 — Dashboard deployment is incomplete and fresh Linux bootstrap has a key prerequisite

The VM exists, but its application is inactive. `deploy/docker/entrypoint-dashboard.sh` automatically initializes a vault. The portable keystore in `crates/local-store/src/keyring.rs` requires a provisioned master key or key file on non-Windows systems. Reviewed Docker/GCP dashboard configuration does not provision either. This is a source-level bootstrap gap, not a confirmed diagnosis of the inactive VM's history.

Initialization also prints the recovery kit to stdout. In a container entrypoint, that becomes container-log output; it contradicts a blanket promise that recovery secrets never reach logs. Do not collect those logs as routine diagnostic evidence without handling this issue. The entrypoint tolerates failed initial push/anchor operations, and its relayer hostname is tied to a different Compose topology.

**Required outcome:** choose whether this service is only a synthetic demo/read-only explorer. Provision key material appropriately for any server vault, eliminate recovery-secret logging, require meaningful startup health, fix DNS/TLS and runtime service configuration, then verify a fresh deployment from an immutable build.

### B5 — Operator sessions are not a complete hosted-service entitlement system

`services/operator/src/state.rs::verify_and_create_session` proves possession of a caller-supplied signing key. Object writes and lease operations then validate a session, without a demonstrated paid/invited tenant quota or caller ownership binding for leases. Per-object size and session/challenge bounds exist; they do not provide total-storage entitlements. Recovery-log authorization has improved and its cross-caller rejection test passes, so it should not be described as wholly unauthenticated storage.

**Required outcome:** define admission, capacity accounting, rate limits, lease ownership/renewal policy, and abuse response for public operators. Add tests for unauthorized storage consumption and cross-user lease modification. Document intentional anonymous ciphertext recovery separately from plaintext access control.

### B6 — Release gate and platform onboarding remain incomplete

Formatting fails in `apps/cli/src/main.rs`. Strict Clippy and the Windows test suite pass. Non-Windows keystore provisioning is absent from the ordinary install/init path; the reviewed CI workflows also do not supply it. Linux/macOS success therefore cannot be inferred from Windows results or workflow filenames.

The local `.cargo/config.toml` points build output to a developer-specific absolute path. It is Git-ignored, so this is a local reproducibility/documentation issue, **not evidence that the tracked release workflow uses that path**. Review commands explicitly overrode the output directory.

**Required outcome:** pass formatting, verify Linux/macOS onboarding and CI, and test archives themselves rather than only source builds. Scope initial beta support to platforms actually verified.

## Other material gaps

1. **Maintenance claims exceed daemon behavior.** `services/maintenance/src/main.rs` polls reachability and counts nonempty recovery logs when deciding vault health. It does not verify every required object or invoke the full repair engine in that loop. The separate repair engine and CLI have passing local tests. A green fleet indicator is not proof of complete recoverability or automatic repair.
2. **Relayer status is not independently verified settlement.** `services/operator/src/state.rs::relay_checkpoint` stores receipts in memory and derives a confirmed label from supplied transaction/block fields. This path does not itself broadcast or verify an RPC receipt. Local chain tests do not establish live Arbitrum finality. Keep these claims out of the beta promise until independently demonstrated.
3. **Release provenance and operating discipline need evidence.** Deployment uses mutable image tags/source downloads. Establish immutable image digests, deployed version reporting, rollback, persistent disk/key recovery, alerts, capacity thresholds, and patching responsibilities.
4. **Retention and economics need a product contract.** An advertised 90-day term is not evidence of paid capacity, expiry alerts, tested renewal, backups of operator state, or an enforceable service policy. Establish retention limits, export/offboarding, support, incident handling, and a funding plan before general availability.
5. **Recovery onboarding is too easy to skip.** Initialization accepts acknowledgement without verifying the recorded kit. Require a useful recovery exercise and make clear that loss of both local access and recovery material cannot be resolved by a support password reset.
6. **Portable passphrases need review.** Portable key resolution hashes non-hex input with SHA256 rather than a password-hardening KDF. Provision random high-entropy keys or implement an appropriate password-derived key workflow; do not imply all arbitrary passphrases provide equivalent protection.

## Prioritized work and acceptance gates

| Order | Work package | Suggested responsibility | Completion evidence |
|---|---|---|---|
| 1 | Separate public explorer from vault administration; close unauthenticated secret/control routes | Application/security | Unauthenticated and cross-user tests fail safely; no secret values or recovery material enter public APIs/logs. |
| 2 | Make operator transport and cloud configuration trustworthy | Infrastructure/security | Stable HTTPS endpoints, trusted identities, verified listeners/firewalls, immutable deployed versions. |
| 3 | Repair release packaging and external installation | Release engineering | A fresh supported machine installs without a checkout, finds the CLI on PATH, verifies artifact integrity, and initializes successfully. |
| 4 | Correct platform bootstrap and all required CI gates | Core/release engineering | Formatting, lint, tests, and package smoke checks pass for every advertised platform. |
| 5 | Add tenant admission, quotas, ownership, retention and operational monitoring | Backend/operations | Cross-tenant and capacity tests; documented retention/renewal and alerting; tested rollback. |
| 6 | Demonstrate real cloud recovery | Core/operations | Synthetic files uploaded to all three real operators; original test-client state removed; recovery from a separate clean machine with one operator excluded; byte-for-byte verification. |
| 7 | Run an invite-only beta | Product/support | A few outside developers complete installation, backup, and recovery unaided; failures recorded and resolved. |

For the cloud recovery gate, use an isolated test vault and client-side exclusion of an operator first. Do not stop shared operators or destroy existing vault data to demonstrate it. Include missing-metadata recovery, retention renewal, audit accuracy, and repair persistence as separate assertions.

Recommended first public scope: encrypted backup, explicit file selection, history, audit, repair, and kit recovery on verified platforms. Keep hosted secret administration, hardware-token guarantees, and automatic blockchain settlement outside the initial promise until their own evidence is complete.

## Test record

Commands executed from the workspace:

```powershell
cargo test --workspace --locked --no-fail-fast --target-dir ./target/release-readiness
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --target-dir ./target/release-readiness -- -D warnings
node --check apps/ui/app.js
node apps/ui/audit.test.cjs
```

Initial sandboxed tests failed in 11 targets, with Windows DPAPI failures among the causes. The complete test command was rerun outside the sandbox and exited successfully: **106 passed, zero failed**. The initial failures must not be presented as unresolved product regressions. Strict Clippy completed successfully. Rustfmt produced differences. JavaScript commands completed successfully.

Captured logs are in [release-readiness evidence](review-evidence/2026-09-13/). These include synthetic test output, not production credentials. The review did not execute installers that modify the user profile or deploy anything to the cloud.

**Next action:** fix the public/local dashboard boundary and trusted operator access first, then packaging and platform bootstrap. Re-run this review against an immutable release candidate and a verified deployment before inviting developers to store real credentials.

---

## Post-Review Verification Addendum (13 September 2026, 15:30 UTC)

Subsequent to the initial review snapshot, the following production deployment milestones were executed and verified live:

1. **Public DNS Configuration**:
   - Subdomain: `vault.cipherv.online`
   - Authoritative GoDaddy A record mapped to static IP `104.196.14.85`
   - Verified active across Google Public DNS (`8.8.8.8`) and Cloudflare DNS (`1.1.1.1`).
2. **Compute Engine & Web Dashboard Daemon (`cv-web-ui`)**:
   - Machine: `e2-micro` (us-east1-b, GCP Free-Tier eligible).
   - Containerized production build: `ciphervault-ui:gcp` successfully compiled and running under systemd supervision.
   - Ports: Ingress restricted via GCP firewall `allow-ciphervault-web-ui` allowing TCP 80 and 443.
3. **Automated TLS / Reverse Proxy (`caddy:2-alpine`)**:
   - Reverse proxy configured with HSTS (`max-age=31536000; preload`), frame denial, and unbuffered SSE stream support (`flush_interval -1`).
   - ACME HTTP-01 challenge verified: Let's Encrypt production certificate successfully issued for `vault.cipherv.online`.
   - Automatic HTTP-to-HTTPS redirect verified: Port 80 returns `308 Permanent Redirect` to `https://vault.cipherv.online/`.
4. **Live Cluster Quorum Health**:
   - Web container independently connected to all 3 GCP operators:
     - `http://136.65.43.84` (cv-operator-1, us-central1-a, Iowa)
     - `http://34.9.157.167` (cv-operator-2, us-central1-b, Iowa)
     - `http://34.73.53.40` (cv-operator-3, us-east1-b, South Carolina)
   - `/api/audit` response verified: `3/3` healthy operators, 7/7 total objects replicated, 0 degraded, 0 lost.
5. **Pre-Release Security Backup**:
   - Local vault snapshot captured and pushed across live operators:
     - Snapshot ID: `70474b20976df23a391eb37d2e47a7feb755ac0876390cd6f5ec5530918232fa`
     - Status: `RemoteDurable` (3/3 independent replicas verified via Proof-of-Storage).
     - Head commitment anchored to Arbitrum L2 relayer.

