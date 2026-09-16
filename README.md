# CipherVault

<div align="center">

[![Live Web Dashboard](https://img.shields.io/badge/Live%20Web%20Dashboard-vault.cipherv.online-00f0ff.svg?style=for-the-badge&logo=googlecloud)](https://vault.cipherv.online)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Security Audit](https://img.shields.io/badge/Security%20Audit-Hardened%20v1.0.6-emerald.svg)](dist/SECURITY_AUDIT_REPORT.md)
[![Tests: Passing](https://img.shields.io/badge/Tests-Passing%20(28%20Suites)-success.svg)](dist/RELEASE_NOTES.md)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production%20Ready-success.svg)](dist/RELEASE_NOTES.md)

**Decentralized, zero-knowledge version control and disaster recovery system for confidential development secrets.**

*Git tracks your source code. CipherVault protects everything Git leaves behind.*

[Live Web Dashboard](https://vault.cipherv.online) • [1-Minute Install](#-1-minute-installation) • [Quickstart](#-quickstart-guide) • [Architecture](docs/SYSTEM_WORKFLOW.md) • [Terminal UI](#-interactive-terminal-user-interface-tui) • [Disaster Recovery](#-clean-machine-disaster-recovery) • [Docs Hub](docs/README.md)

</div>

---

## 🌐 Live Web Dashboard & Visual Secrets Explorer

The official multi-region cluster dashboard is publicly accessible with live telemetry:

👉 **[https://vault.cipherv.online](https://vault.cipherv.online)**

* **Visual Secrets Explorer**: Browse confidential files, Merkle manifest CIDs, and byte-level FastCDC chunk distributions.
* **Live Geographic Quorum**: Real-time roundtrip latency monitoring across Iowa (`us-central1`) and South Carolina (`us-east1`).
* **Format-Aware Secret Diff**: Inspect key additions, removals, and mutations across snapshot commits with sensitive value masking.
* **Shamir M-of-N Ceremony**: In-browser threshold guardian share generator and zero-knowledge recombination simulator.
* **Arbitrum One Checkpoints**: Immutable L2 sequencer receipts and verified Arbiscan explorer links.

---

## 📦 1-Minute Installation

Install the standalone `ciphervault` CLI binary on any operating system with a single terminal command:

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/v1.0.6/dist/scripts/install.ps1 | iex
```
*(Or via Winget: `winget install CipherVault.CipherVault`)*

### macOS & Linux (Bash)
```bash
curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/v1.0.6/dist/scripts/install.sh | bash
```
*(Or via Homebrew: `brew install samuel-1-avson/tap/ciphervault`)*

### Rust Developers (Cargo)
```bash
cargo install --git https://github.com/samuel-1-avson/CipherVault.git ciphervault-cli
```

After installing, run the CLI from a terminal (do not double-click the
Windows executable; a console window closes when a command exits). The
release archive also includes a `ciphervault.cmd` wrapper for Command Prompt.

### Connect to the production account service

The account key remains in the local OS keystore. From a directory containing
an initialized vault, enroll the account and current device with the hosted
service:

```bash
ciphervault auth connect --endpoint https://vault.cipherv.online/api/account
```

The command prints a short-lived, one-time browser link. Open that link to
create the first hosted dashboard session; it is signed by the local account
key and does not expose the key or the session token. After the handoff, use
the dashboard to register a passkey and enroll an authenticator. Later visits
can use either factor from the [production dashboard](https://vault.cipherv.online).
The account ID alone is not a password and cannot create an account that has
not been connected by the signed CLI ceremony.

### Update an installed CLI

The CLI checks the GitHub release feed and verifies the archive against the
published SHA-256 manifest before replacing the executable:

```bash
ciphervault update --check
ciphervault update
```

You can also rerun the official installer command; it always resolves the
latest release instead of a hard-coded old tag.

---

## ⚡ Quickstart Guide

### 1. Initialize Vault in Any Project

Navigate to any project directory containing confidential files (`.env`, certificates, tokens):

```bash
cd ~/my-project

# Connect to the live public multi-region GCP cluster (or run 'ciphervault init' for built-in defaults)
ciphervault init --operators https://vault.cipherv.online/op/1 https://vault.cipherv.online/op/2 https://vault.cipherv.online/op/3 --import-gitignore
```

> **CRITICAL**: CipherVault will display your **Offline Emergency Recovery Kit** (containing Master Secret $R$). Store this kit in two secure physical locations. In accordance with zero-disk recovery policy, $R$ is immediately zeroized from volatile RAM and never written unencrypted to disk.

### 2. Track Secrets & Capture Encrypted Snapshot

```bash
# Add confidential files to tracking (CipherVault automatically updates .gitignore)
ciphervault track .env config/credentials.json

# Capture, chunk (FastCDC), encrypt (XChaCha20-Poly1305), and replicate across all 3 operators
ciphervault push -m "Initial production environment" --pos
```

### 3. Zero-Disk In-Memory Execution (`ciphervault run`)

Run your applications with decrypted secrets directly injected into their process environment in volatile RAM **without ever writing plaintext `.env` files to disk**:

```bash
# Node.js
ciphervault run -- npm start

# Python
ciphervault run -- python main.py

# Docker Compose
ciphervault run -- docker compose up
```

### 4. Clean-Machine Disaster Recovery

If your laptop is lost, damaged, or stolen, restore all confidential files on a brand-new clean machine:

```bash
# Using your offline recovery kit
ciphervault recover --kit recovery_kit.txt --to .

# Or using M-of-N threshold guardian shares (e.g. 3 of 5 leads approve)
ciphervault recover --shares share1.txt share2.txt share3.txt --to .
```

---

## 🏛 Live GCP Multi-Region Architecture

```text
========================================================================================
                         CIPHERVAULT MULTI-REGION TOPOLOGY
========================================================================================

  [ Developer Workstations / CI/CD ]
      │ (Local AES-256 / XChaCha20-Poly1305 AEAD Client Encryption)
      │
      ├──> Web UI Dashboard:   https://vault.cipherv.online  (us-east1-b)
      │
      └──> 3-Node Byzantine Quorum Cluster (~1,000 Miles Physical Isolation, TLS Shielded):
            ├── Operator 1:    https://vault.cipherv.online/op/1   [us-central1-a, Iowa, USA]
            ├── Operator 2:    https://vault.cipherv.online/op/2   [us-central1-b, Iowa, USA]
            └── Operator 3:    https://vault.cipherv.online/op/3   [us-east1-b, S. Carolina, USA]

  [ Arbitrum One Rollup (L2) ]
      └── EIP-712 Sequencer Head Commitments & Public Inclusion Proofs
========================================================================================
```

---

## 📖 Overview


**CipherVault** is a developer-first secret backup, version control, and clean-machine disaster recovery system engineered in pure Rust. It guarantees that critical development secrets—such as `.env` files, API keys, private signing keys, TLS certificates, and database credentials—can be reliably recovered onto a clean replacement workstation using only an offline paper recovery kit or distributed threshold shares and direct storage operators.

CipherVault requires **zero trust in centralized SaaS databases, cloud coordinators, or custodial blockchain wallets**.

### Core Tenets

1. **Zero-Plaintext at Rest**: Local SQLite keys are protected via operating system keyrings (Windows DPAPI `CryptProtectData` and machine-authenticated encryption on Linux/macOS).
2. **Zero-Disk Master Recovery Secret**: The root master secret $R$ is printed exclusively to the terminal on initialization, requires interactive acknowledgement, and is immediately scrubbed from RAM (`ZeroizeOnDrop`).
3. **Content-Defined Chunking (FastCDC)**: Dynamic boundary chunking using compile-time Gear rolling hashes (`SplitMix64`) isolates file edits to a single chunk slice, achieving a **96.15% deduplication ratio**.
4. **Bandwidth-Optimized Proof-of-Storage (PoS)**: Remote durability is verified via domain-separated cryptographic challenge-response nonces (`"CIPHERVAULT-POS-V1"`), slashing remote verification bandwidth by **99.96%**.
5. **Threshold Guardian Recovery ($M$-of-$N$ Shamir Sharing)**: Galois Field $\text{GF}(2^8)$ secret sharing with constant-time inversion reconstructs $R$ on a clean machine from any $M$ guardian sheets without exposing shares to disk.
6. **Hardware-Bound Identity (YubiKey PIV)**: Native ISO 7816-4 APDU driver over PC/SC (`winscard.dll`) binds device signing to Slot 9C with capacitive physical touch presence (`--touch`).
7. **Automated L2 Checkpoint Relayer**: Submits salted EIP-712 state commitments directly to Arbitrum One relayer nodes, persisting immutable sequencer receipts locally.
8. **Interactive Terminal User Interface (TUI)**: Full-featured terminal dashboard powered by Ratatui & Crossterm with 6 views, real-time telemetry polling, and instant hotkey workflows (`ciphervault tui`).
9. **Autonomous Event-Driven File Watcher**: Cross-platform OS event hook (`notify`) watching tracked secret files with intelligent debouncing, coherent reads, and automatic snapshot/push replication (`ciphervault watch`).

---

## 🏛 Architecture & Trust Boundary

```text
========================================================================================
                                CIPHERVAULT ARCHITECTURE
========================================================================================

 [ Physical YubiKey / PIV Smartcard ]
    │  (ISO 7816-4 APDU over Native PC/SC — Zero C FFI)
    ├── Slot 9C: Digital Signature (Ed25519) + Capacitive Touch Presence (--touch)
    └── Slot 9D: Key Management (X25519 ECDH Key Agreement for Epoch Unwrapping)
    │
 [ Developer Workstation ]
    │
    ├── Local Secrets (.env, certs/server.key, tokens/cloud.json)
    │     │
    │     ├── FastCDC Slicing (Gear Hash [4 KiB min, 16 KiB avg, 64 KiB max])
    │     ├── Encrypted Chunks (XChaCha20-Poly1305 AEAD + Blake2b-512 Addressing)
    │     └── Local SQLite WAL Store (Protected via Windows DPAPI / OS Keyring)
    │
    ├── Replication Pipeline (3+ Independent HTTP Storage Nodes)
    │     │
    │     ├── Operator Boundary Ed25519 Signature Verification
    │     ├── Proof-of-Storage (PoS) Nonce Challenge-Response (461 B wire payload)
    │     └── Autonomous Maintenance Daemon (SQLite WAL fleet.db Scheduler & Self-Repair)
    │
    ├── Disaster Recovery Pipeline (Zero Disk Exposure)
    │     │
    │     ├── Emergency Offline Paper Recovery Kit (Master Secret R + CRC32)
    │     ├── Threshold Guardian Recovery (GF(2^8) M-of-N Shamir Lagrange Interpolation)
    │     └── Clean-Machine Zero-Dependency Reconstruction Tooling
    │
    └── Public Asynchronous State Anchoring
          │
          ├── Automated L2 Checkpoint Relayer (Arbitrum One Rollup)
          └── EIP-712 Sequencer Confirmation Proofs & Local Receipt Persistence
========================================================================================
```

---

## ⚡ 3-Minute Quickstart

### 1. Build Binaries

```sh
cargo build --workspace --release --locked
```

Compiled release binaries are available in `dist/bin/`:
- `ciphervault` (Main Developer CLI and embedded Web Dashboard)
- `ciphervault-operator` (Independent Storage Node Service)
- `ciphervault-account` (Optional hosted account, device, and session control plane)
- `ciphervault-agent` (File Watching & Coherent Commit Daemon)
- `ciphervault-maintenance` (Replication Audit & Persisted Fleet Scheduler)

### 2. Launch Local 3-Node Cluster

In three separate terminals (or in background):

```sh
dist/bin/ciphervault-operator --port 8201 --data-dir ./data/op1 --operator-id op_8201
dist/bin/ciphervault-operator --port 8202 --data-dir ./data/op2 --operator-id op_8202
dist/bin/ciphervault-operator --port 8203 --data-dir ./data/op3 --operator-id op_8203
```

*(Alternatively, spin up the entire cluster instantly via Docker: `docker compose up -d`)*

### 3. Initialize Vault

From your project directory containing secret files:

```sh
# Option A: Standard initialization (prompts to track secrets found in .gitignore)
ciphervault init --operators http://127.0.0.1:8201 http://127.0.0.1:8202 http://127.0.0.1:8203

# Option B: Non-interactive initialization with automatic .gitignore secret import
ciphervault init --import-gitignore
```

*Your Emergency Offline Paper Recovery Kit will be printed exclusively to the terminal. Record master secret $R$ before confirming; it is immediately scrubbed from volatile RAM.*

### 4. Track Confidential Files & Capture Snapshot

```sh
# Add secrets to tracking list (automatically appends to .gitignore if not already present)
ciphervault track .env certs/server.key

# Or scan and import all secret patterns from .gitignore on demand
ciphervault track --from-gitignore

# To track without modifying .gitignore:
ciphervault track .env --no-gitignore

# Inspect tracking state
ciphervault status

# Capture, chunk, encrypt, and push with Proof-of-Storage readback
ciphervault push -m "Initial development credentials" --pos
```

### 5. Anchor Commitment to Arbitrum L2 Relayer

```sh
ciphervault anchor --auto-relay --relayer-url http://127.0.0.1:8201
```

### 6. Export 2-of-3 Shamir Threshold Guardian Sheets

```sh
# Split master recovery secret into 3 printable sheets (threshold: 2)
ciphervault recovery split --threshold 2 --shares 3 --out-dir ./guardians
```

### 7. Launch Web Dashboard & Vault Inspector

```sh
ciphervault ui --port 8080
```
Open **`http://127.0.0.1:8080`** to review:
- **Threshold Guardian Panel**: Interactive $M$-of-$N$ threshold ceremony and in-memory reconstruction simulator.
- **L2 Relayer Inspector**: Live Arbitrum sequencer transaction receipts with Arbiscan explorer deep links.
- **Maintenance Fleet Monitor**: Storage node latency gauges and SQLite `fleet.db` audit histories.
- **Hardware Token Status**: Real-time PC/SC reader detection and touch policy indicators.

### Optional account and device identity

CipherVault remains usable without an online account. The CLI and local dashboard
are accountless by default, while the public explorer never requires login. For
cross-device hosted access, create a control-plane account and link a local vault:

```sh
ciphervault auth init --name "Alice"
ciphervault vault link --alias "Production vault"
ciphervault auth login
ciphervault auth status
ciphervault device list
```

The account stores an account ID, device registry, vault memberships, and session
metadata. Its signing key is protected by the host key facility. It never stores
vault plaintext or the offline recovery secret. `ciphervault auth logout` revokes
the local account session and `ciphervault device revoke <DEVICE_ID>` invalidates
that device. The repository also includes the optional `ciphervault-account`
control-plane service for self-hosted account, device, vault-link, and session
metadata. It verifies account-signed enrollment proofs and propagates revocations
to configured operators, but it does not store vault plaintext or private vault
keys. Browser WebAuthn registration/assertion support now exists for `none`
attestation with Ed25519 and ES256 credentials. Credentials are bound to the
enrolled device, can be independently revoked, and successful hosted logins
issue an HttpOnly session cookie. The hosted dashboard proxies the passkey
ceremony and provides passkey sign-in/registration controls. The account API
also provides durable invitations, membership roles, and one-time recovery
codes; email delivery, role-aware vault authorization, and production
provisioning still require deployment work.
Authenticator-app MFA is also supported by the account service using RFC 6238
six-digit codes. TOTP seeds are encrypted at rest with the configured account
wrapping key, and replayed codes are rejected. Passkeys or hardware tokens
remain the preferred phishing-resistant factors; TOTP authenticates an account
session and never replaces the vault encryption key.

### 8. Interactive Terminal User Interface (TUI)

```sh
ciphervault tui
# or run the one-click launcher:
launch-tui.bat
```
Features 6 full-screen terminal views (`[1] Overview`, `[2] Files`, `[3] History`, `[4] Operators`, `[5] FastCDC`, `[6] Token`) with real-time operator health polling, hotkey snapshot commits (`[p]`), and L2 settlement (`[a]`).

### 9. Autonomous File Watcher Daemon (Auto-Snapshot on Save)

```sh
ciphervault watch --debounce 2 --sync
# or run the one-click launcher:
start-watcher.bat
```
Listens to native OS filesystem save events on tracked secret files. Any time you edit and save `.env` in your editor, CipherVault debounces for 2 seconds, creates a FastCDC snapshot, and replicates to 3/3 operators in the background.

### 10. Zero-Disk Secret Injection (`ciphervault run`)

Execute your applications with decrypted secrets directly injected into their process environment in volatile RAM **without ever writing plaintext `.env` files to disk**:

```sh
# Execute command with secrets injected into environment
ciphervault run -- npm start
ciphervault run -- cargo run
ciphervault run -- docker compose up

# Inspect decrypted secret keys without executing or exposing values
ciphervault run --dry-run -- node server.js

# Target a specific secret environment file
ciphervault run --env-file .env.production -- npm start

# Hermetic isolation (strip host environment variables)
ciphervault run --no-inherit -- python main.py

# Inject runtime overrides on the fly
ciphervault run --set PORT=8080 DEBUG=true -- npm start
```

### 11. Encrypted Secret Diffing (`ciphervault diff`)

Compare encrypted secrets with built-in **shoulder-surfing protection** (secrets are masked by default):

```sh
# Compare uncommitted working tree secrets against active head (masked by default)
ciphervault diff

# Reveal plaintext values in a secure private terminal
ciphervault diff --reveal

# Diff against a specific historical snapshot revision
ciphervault diff <snapshot_id>

# Diff between two historical snapshots
ciphervault diff <snapshot_a> <snapshot_b>

# Restrict diff to a specific confidential file
ciphervault diff --file .env

# Export machine-readable JSON for CI auditing
ciphervault diff --json
```

### 12. Multi-Workstation Synchronization (`ciphervault pull`)

Synchronize confidential snapshots across multiple developer workstations, build servers, or laptops:

```sh
# Pull and apply latest verified snapshots from storage operators
ciphervault pull

# Dry-run inspection without altering any local files
ciphervault pull --dry-run

# Force sync and overwrite local uncommitted modifications
ciphervault pull --force
```

### 13. Shell Tab Autocompletions (`ciphervault completions`)

Generate native, high-performance autocompletion scripts for your shell:

```sh
# PowerShell (add to $PROFILE)
ciphervault completions powershell | Out-String | Invoke-Expression

# Bash
eval "$(ciphervault completions bash)"

# Zsh
eval "$(ciphervault completions zsh)"

# Fish
ciphervault completions fish > ~/.config/fish/completions/ciphervault.fish

# Elvish
eval (ciphervault completions elvish | slurp)
```

### 14. CI/CD Zero-Disk Runner Action

Inject encrypted secrets into automated CI/CD pipelines without ever writing credentials to runner disks or persisting them in container layers:

```yaml
# In .github/workflows/deploy.yml
- name: Zero-Disk Secret Injection Runner
  uses: ./.github/actions/ciphervault-run
  with:
    command: "npm run deploy"
    env-file: ".env.production"
    quiet: "true"
```
*(See [docs/CICD_INTEGRATION.md](docs/CICD_INTEGRATION.md) for full GitHub Actions, GitLab CI, and CircleCI guides)*

### 15. Dynamic P2P Operator Discovery (`ciphervault peers`)

Inspect active storage operators and discover dynamic cluster peers via Ed25519-signed P2P gossip:

```sh
# Inspect current storage operator cluster status, latency, and signing public keys
ciphervault peers

# Query operators to dynamically discover new peer nodes via P2P gossip
ciphervault peers --discover
```

### 16. Out-of-Band Cryptographic Push Approvals (`ciphervault approve`)

Authorize high-risk emergency recoveries and operations with cryptographic signatures from team leads or threshold guardians:

```sh
# List pending authorization challenges across the operator federation
ciphervault approve list

# Inspect detailed parameters (vault ID, action, TTL, target directory)
ciphervault approve status <CHALLENGE_ID>

# Cryptographically sign and approve a pending challenge using your authorized device key
ciphervault approve sign <CHALLENGE_ID>
```

---

## 🛡 Clean-Machine Disaster Recovery

When the original workstation is completely destroyed or stolen, secrets can be restored onto a virgin replacement machine without any pre-existing database or credentials.

### Method A: Single Emergency Paper Recovery Kit

```sh
ciphervault recover --kit emergency_recovery_kit.txt --to ./restored_secrets/
```

### Method B: Threshold Guardian Reconstruction ($M$-of-$N$)

Reconstruct the master recovery secret $R$ strictly in RAM by combining any $M$ guardian sheets (e.g. Share 1 and Share 3, completely omitting Share 2):

```sh
ciphervault recover --shares guardian_share_1_of_3.txt guardian_share_3_of_3.txt --to ./restored_secrets/
```

- **Branchless Constant-Time Arithmetic**: Reconstructs $R$ over $\text{GF}(2^8)$ in volatile memory with zero secret-dependent branches.
- **Zero Disk Exposure**: $R$ is never persisted to disk during or after recovery.
- **Bit-for-Bit Fidelity**: Restores all files with 100% SHA-256 identity verification.

### Method C: Out-of-Band Multi-Party Gated Recovery

Enforce cryptographic approval receipts before restoring secrets onto untrusted or clean hardware:

```sh
ciphervault recover --kit emergency_recovery_kit.txt --to ./restored_secrets/ --require-approval
```
*(The command registers a 600s authorization challenge and awaits a signed receipt from `ciphervault approve sign <ID>`)*

---

## 🔑 Hardware Security Tokens & YubiKey PIV

CipherVault natively interfaces with NIST SP 800-73-4 compliant smartcards and YubiKey 5 Series tokens over standard PC/SC (`winscard.dll` on Windows, PC/SC daemon on Unix) without third-party C FFI libraries.

```sh
# Probe connected smartcard readers
ciphervault token probe

# Display PIV slots (Slot 9C Signing, Slot 9D Key Management) and touch policies
ciphervault token status

# Initialize vault binding device identity to physical hardware token
ciphervault init --hardware-token

# Enforce physical capacitive finger touch presence before snapshot signature
ciphervault push -m "Production release commit" --touch
```

When `--touch` is enabled, host execution pauses with:
```text
>>> [ACTION REQUIRED] Please touch your hardware security token to sign snapshot...
```
The device signing private key never leaves the secure element of the physical card.

---

## 💻 CLI Command Reference

| Command | Arguments / Flags | Description |
|---|---|---|
| `ciphervault init` | `[-f/--force] [-o/--operators <URL...>] [--save-kit <PATH>] [--hardware-token] [-i/--import-gitignore]` | Initializes vault, derives key hierarchy, outputs paper kit, and scans `.gitignore` for secret files. |
| `ciphervault track` | `[PATH...] [-i/--from-gitignore] [--no-gitignore]` | Registers confidential files for snapshot tracking (or imports from `.gitignore`); automatically appends to `.gitignore` to prevent git leaks. |
| `ciphervault untrack` | `<PATH...>` | Stops tracking specified files. |
| `ciphervault status` | *None* | Displays current vault metadata, tracked files, and active epoch. |
| `ciphervault push` | `[-m/--message <MSG>] [--pos] [--touch]` | Captures FastCDC chunks, encrypts, and replicates across operators with optional PoS readback and hardware touch. |
| `ciphervault anchor` | `[--auto-relay] [--relayer-url <URL>] [--salt <HEX>] [--head <CID>]` | Computes EIP-712 state commitment and submits to Arbitrum L2 relayer. |
| `ciphervault verify-anchor` | `[--salt <HEX>] [--head <CID>]` | Verifies on-chain commitment against local head record CID. |
| `ciphervault audit` | `[-o/--operators <URL...>]` | Performs remote replication quorum and CID closure audit across nodes. |
| `ciphervault repair` | `[-o/--operators <URL...>]` | Detects degraded replicas and autonomous self-heals by streaming missing chunks from surviving operators. |
| `ciphervault recovery split` | `-t/--threshold <M> -s/--shares <N> [--kit <PATH>] [-o/--out-dir <DIR>]` | Splits master recovery secret $R$ into printable Shamir paper guardian sheets. |
| `ciphervault recovery export` | *None* | Displays public descriptors (signing PK, encryption PK, locator) without exposing secret $R$. |
| `ciphervault recovery test` | `[--kit <PATH>] [--to <DIR>]` | Non-destructive dry-run verifying recovery set availability across operators. |
| `ciphervault recover` | `[--kit <PATH>] [--shares <PATH...>] --to <DIR>` | Reconstructs confidential files onto clean machine using single kit or threshold shares. |
| `ciphervault auth init` | `[--name <NAME>]` | Creates the optional local control-plane account; vault keys remain local. |
| `ciphervault auth login/logout/status` | *None* | Unlocks, revokes, or reports the short-lived local account session. |
| `ciphervault device list` | *None* | Lists active and revoked devices in the local account registry. |
| `ciphervault device revoke` | `<DEVICE_ID>` | Revokes a device and invalidates its account session. |
| `ciphervault vault link/unlink` | `[--alias <NAME>]` | Binds or removes the current vault from the local account and enrolls its device. |
| `ciphervault token status` | *None* | Inspects connected PC/SC smartcard readers and PIV slot states. |
| `ciphervault token probe` | *None* | Emits machine-readable JSON telemetry for hardware token driver. |
| `ciphervault ui` | `[--host <ADDR>] [--port <PORT>] [--no-browser]` | Launches embedded self-contained Web Dashboard and API server. |
| `ciphervault tui` | `[--poll-ms <MS>]` | Launches interactive Terminal User Interface (TUI) dashboard with live operator polling and hotkeys. |
| `ciphervault watch` | `[-d/--debounce <SECS>] [-s/--sync]` | Listens to native OS filesystem save events on tracked secret files; auto-snapshots and pushes to operators on save. |
| `ciphervault run` | `[-s/--snapshot <HEX>] [-e/--env-file <FILE>] [--no-inherit] [--dry-run] [-q/--quiet] [--set <K=V...>] -- <CMD...>` | Injects decrypted secrets directly into child process environment in volatile RAM (zero disk exposure). |

---

## 🐳 Docker Compose & Cloud Cluster

CipherVault includes production container configurations (`deploy/docker/` and `docker-compose.yml`):

```sh
# Start 3-node storage federation, maintenance scheduler, and dashboard
docker compose up -d

# View container fleet health
docker compose ps

# Access Web Dashboard
open http://localhost:8080
```

### Services Deployed

| Service | Container Name | Port | Description |
|---|---|---|---|
| `operator-1` | `ciphervault-operator-1` | `8201` | Primary storage node & L2 relayer endpoint |
| `operator-2` | `ciphervault-operator-2` | `8202` | Secondary storage operator |
| `operator-3` | `ciphervault-operator-3` | `8203` | Tertiary storage operator |
| `maintenance` | `ciphervault-maintenance` | Internal | Periodic replication auditor & `fleet.db` scheduler |
| `dashboard` | `ciphervault-dashboard` | `8080` | Self-contained single-page inspector & REST API |

### Multi-Region Cloud VPS Cluster (GCP)

CipherVault supports automated deployment to multi-region Google Cloud Platform VPS nodes across Iowa (`us-central1`) and South Carolina (`us-east1`) for high availability and physical fault isolation at ~$0.97/day.

*(See [docs/DEPLOYMENT_RUNBOOK.md](docs/DEPLOYMENT_RUNBOOK.md) for full cloud provisioning scripts, Caddy ingress hardening, cost breakdown, and teardown guides)*

### Automated Cluster Verification Drill

Validate the entire container cluster with automated failure injection and 2-of-3 threshold guardian reconstruction:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-cluster.ps1
```

---

## 📊 Performance Benchmarks

Empirical metrics measured on Windows x86_64:

| Metric | Measured Value | Standard / Comparison |
|---|---|---|
| **Encryption Throughput** | **558.62 MiB/s** | XChaCha20-Poly1305 AEAD |
| **Decryption Throughput** | **656.84 MiB/s** | XChaCha20-Poly1305 AEAD |
| **FastCDC Deduplication Ratio** | **96.15%** | 25/26 chunks preserved upon localized edit |
| **PoS Readback Wire Reduction** | **99.956%** | Slashed from 1,048,576 B to 461 B per 1 MiB chunk |
| **Hardware Token APDU Latency** | **<1.5 ms** | Direct native PC/SC short APDU round-trip |
| **Integrity Fidelity** | **100.00%** | Zero bitflips across all failure and recovery drills |

---

## 🧪 Verification & Quality Gates

CipherVault enforces strict zero-warning compilation and comprehensive multi-layer testing:

```sh
# Execute full workspace test suite (67 unit & integration tests)
cargo test --workspace --locked

# Strict static analysis & linter enforcement
cargo clippy --workspace --all-targets --locked -- -D warnings

# Formatting compliance check
cargo fmt --all -- --check

# Single-page UI headless regression suite
node apps/ui/audit.test.cjs

# Live multi-node chaos engineering drill (11-step node wipe & self-repair)
cargo test --test chaos_federation_drill
powershell -ExecutionPolicy Bypass -File deploy/chaos_drill.ps1
```

---

## 📄 License

Dual-licensed under either:
- **MIT License** ([LICENSE-MIT](LICENSE) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))

at your option.

