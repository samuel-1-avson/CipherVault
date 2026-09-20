# 🛡️ CipherVault

<div align="center">

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Deduplication: FastCDC 96.15%](https://img.shields.io/badge/FastCDC%20Deduplication-96.15%25-brightgreen.svg)](#-performance-benchmarks)
[![Cryptography: XChaCha20-Poly1305](https://img.shields.io/badge/Cryptography-XChaCha20--Poly1305%20AEAD-purple.svg)](docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md)
[![Hardware: YubiKey PIV](https://img.shields.io/badge/Hardware%20Token-YubiKey%20PIV%20Native-teal.svg)](#-hardware-security-tokens--yubikey-piv)
[![Tests: Passing](https://img.shields.io/badge/Tests-Passing%20(63%20Suites)-success.svg)](#-verification--quality-gates)
[![Status: Beta](https://img.shields.io/badge/Status-Beta-yellow.svg)](dist/RELEASE_NOTES.md)

**Decentralized, zero-knowledge secret backup, version control, and clean-machine disaster recovery for confidential development files.**

*Git tracks your source code. CipherVault protects everything Git leaves behind.*

[The Problem It Solves](#-the-problem-ciphervault-solves) • [Architecture](#-system-architecture--trust-boundaries) • [Key Features](#-important-features) • [Installation](#-installation-guide) • [Setup Guide](docs/SETUP_GUIDE.md) • [Quickstart Guide](#-quickstart-guide) • [CLI Reference](#-complete-cli-command-reference) • [Disaster Recovery](#-clean-machine-disaster-recovery) • [Docker Deployment](#-docker-compose--self-hosting) • [Docs Hub](docs/README.md)

</div>

---

## 🎯 The Problem CipherVault Solves

### The Developer's Dilemma
Modern software development requires dozens of confidential credentials: `.env` files, API keys, database connection strings, TLS certificates, service account tokens, and private signing keys. 

Developers are taught from day one: **never commit secrets to Git**. We dutifully add them to `.gitignore`. But once secrets are excluded from Git, developers face four critical vulnerabilities:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               THE SECRETS DILEMMA                                      │
├───────────────────────────────┬────────────────────────────────────────────────────────┤
│ The Vulnerability             │ The Real-World Risk & Impact                           │
├───────────────────────────────┼────────────────────────────────────────────────────────┤
│ 1. Accidental Git Leaks       │ One careless git commit or git push leaks credentials  │
│                               │ permanently into commit histories and public mirrors.  │
├───────────────────────────────┼────────────────────────────────────────────────────────┤
│ 2. The Clean-Machine          │ When a developer's laptop is lost, damaged, stolen,    │
│    Disaster Nightmare         │ or wiped, Git only restores source code. All unbacked  │
│                               │ local credentials, environment configs, and private   │
│                               │ keys are gone, causing days of manual resets.          │
├───────────────────────────────┼────────────────────────────────────────────────────────┤
│ 3. The Centralized SaaS Trap  │ Centralized cloud vaults (AWS Secrets Manager,         │
│                               │ 1Password, HashiCorp Vault) introduce custodial risks, │
│                               │ subscription costs, internet lock-in, and single       │
│                               │ points of failure for development workflows.           │
├───────────────────────────────┼────────────────────────────────────────────────────────┤
│ 4. Plaintext Disk Exposure &  │ Leaving .env files unencrypted on local disks exposes   │
│    Shoulder Surfing           │ secrets to malware, unauthorized terminal observers,  │
│                               │ and compromised dependency build scripts.              │
└───────────────────────────────┴────────────────────────────────────────────────────────┘
```

---

### How CipherVault Solves It (In Plain English)

Think of CipherVault as a **sovereign, decentralized safety deposit box and time machine for confidential files**:

1. **Military-Grade Local Encryption**: Before any file leaves your computer, CipherVault encrypts it using state-of-the-art cryptography (`XChaCha20-Poly1305`). Your encryption keys never leave your device.
2. **Smart Puzzle Slicing (FastCDC)**: Instead of re-uploading entire files when you change a single line, CipherVault chops files into content-defined chunks. Changing one API key only touches a tiny 4 KiB slice, achieving a **96.15% deduplication ratio**.
3. **Untrusted Storage Operators**: Encrypted chunks are replicated across a federated network of independent storage nodes. The nodes only see opaque random-looking ciphertext addressed by cryptographic hashes (BLAKE2b). They cannot read your file names, folder structures, or secrets.
4. **Sovereign Clean-Machine Disaster Recovery**: If your computer is destroyed tomorrow, you can reconstruct every single secret file onto a virgin machine using **only an offline paper recovery kit** or **$M$-of-$N$ team guardian shares** (e.g., any 2 of 3 team leads). No cloud logins, no blockchain wallets, and zero external trust required.
5. **Zero-Disk Execution**: You never need to keep plaintext `.env` files sitting on your disk. CipherVault can decrypt secrets directly into the memory of your running application (`npm start`, `python main.py`, `docker compose up`) and immediately zeroize them when finished.

---

## 🏛 System Architecture & Trust Boundaries

```text
===================================================================================================
                                     CIPHERVAULT ARCHITECTURE
===================================================================================================

  [ Physical Hardware Token ]
      │  (Optional YubiKey 5 PIV via native PC/SC — Zero C FFI)
      ├── Slot 9C: Digital Signature (Ed25519) + Capacitive Touch Presence (--touch)
      └── Slot 9D: Key Management (X25519 ECDH Key Agreement for Epoch Unwrapping)
      │
  [ Developer Workstation / CI/CD Runner ]
      │
      ├── Local Confidential Files (.env, certs/server.key, config/credentials.json)
      │     │
      │     ├── 1. FastCDC Chunking (Gear Rolling Hash [4 KiB min, 16 KiB avg, 64 KiB max])
      │     ├── 2. Client-Side AEAD Encryption (XChaCha20-Poly1305 + SHA-256 Addressing)
      │     └── 3. Local SQLite WAL Store (Keyring-Protected via Windows DPAPI / OS Keyring)
      │
      ├── Federated Storage Replication (3+ Independent Storage Operators)
      │     │
      │     ├── Ed25519 Operator-Signed Boundary Verification & Dynamic P2P Peer Gossip
      │     ├── Proof-of-Storage (PoS) Nonce Challenge-Response (461-byte wire readback)
      │     └── Self-Healing Maintenance Daemon (fleet.db scheduler & degraded chunk repair)
      │
      ├── Clean-Machine Sovereign Disaster Recovery
      │     │
      │     ├── Method A: Emergency Offline Paper Recovery Kit (Master Secret R + CRC32)
      │     ├── Method B: M-of-N Shamir Threshold Guardians (GF(2^8) Lagrange Interpolation)
      │     └── Method C: Out-of-Band Cryptographic Multi-Party Push Approvals
      │
      └── Public Asynchronous State Anchoring (Optional)
            │
            ├── Salted EIP-712 State Commitments submitted to Arbitrum One Rollup (L2)
            └── Sequencer Confirmation Proofs & Local Receipt Persistence
===================================================================================================
```

### Core Security Invariants

* **Zero-Plaintext at Rest**: Local keys and database credentials are sealed with hardware-backed or operating system keyrings (Windows DPAPI `CryptProtectData` or machine-entropy AEAD on Linux/macOS).
* **Zero-Plaintext to Storage Operators**: All chunk slicing, manifest generation, and encryption happen strictly on the client workstation. Storage operators receive opaque ciphertext blobs addressed by SHA-256 content identifiers (CIDs).
* **Zero-Disk Master Secret ($R$)**: The 256-bit root recovery secret $R$ is printed exclusively to your terminal upon initialization, requires interactive acknowledgement, and is immediately purged from RAM using memory-zeroizing fences (`ZeroizeOnDrop`).
* **Cryptographic Proof-of-Storage (PoS)**: Remote replica durability is verified using domain-separated nonce challenge-response protocols (`"CIPHERVAULT-POS-V1"`), slashing verification bandwidth by **99.96%** (461 bytes instead of 1 MiB per chunk).
* **Deterministic Key Hierarchy**: All operational keys (epoch encryption keys, device identity keys, operator authentication tokens, and content locators) are cryptographically derived from Master Secret $R$ via the custom domain-separated Blake2b KDF (ADR-001).

---

### Workspace Component Anatomy

CipherVault is engineered as a high-performance modular Rust workspace (11 crates and services) with zero external C FFI dependencies:

| Component | Path | Language / Tech | Primary Responsibility |
|---|---|---|---|
| **CLI & Host** | `apps/cli` | Rust (Clap, Tokio, Axum) | Developer CLI (36 commands), embedded dashboard server, and Ratatui TUI host. |
| **Agent Daemon** | `apps/agent` | Rust (Notify) | Autonomous background file watcher with debounced coherent snapshot capture. |
| **Web Dashboard** | `apps/ui` | HTML5, CSS3, Vanilla JS | Embedded visual secrets explorer, telemetry viewer, diff viewer, and Shamir simulator. |
| **Crypto Core** | `crates/crypto` | Rust (XChaCha20, Ed25519, Dalek) | AEAD primitives, custom Blake2b KDF, constant-time $\text{GF}(2^8)$ Shamir, sealed boxes, PC/SC PIV driver. |
| **Wire Format** | `crates/format` | Rust (Canonical CBOR) | Canonical deterministic serialization for Genesis, Head, Snapshot, and Manifest records. |
| **Snapshot Engine** | `crates/snapshot` | Rust (FastCDC, Gear Hash) | Content-defined chunking (4/16/64 KiB), deduplication, encryption, and atomic restores. |
| **Local Store** | `crates/local-store` | Rust (Rusqlite WAL, DPAPI) | Local SQLite state, tracked file registry, snapshot DAG, and device keyrings. |
| **Recovery Primitives** | `crates/recovery` | Rust (Shamir, CRC32) | Paper kit derivation, threshold guardian generation, and out-of-band challenge approval. |
| **Storage Client** | `crates/storage` | Rust (Reqwest, Futures) | Concurrent multi-operator replication pool, PoS verification, and relayer clients. |
| **Storage Operator** | `services/operator` | Rust (Axum, Tokio) | Zero-knowledge chunk store, PoS challenge responder, P2P peer gossip, and relayer proxy. |
| **Maintenance Fleet** | `services/maintenance` | Rust (Tokio, Rusqlite) | Periodic replication auditor, node latency monitor, and autonomous self-repair scheduler. |
| **Account Service** | `services/account` | Rust (Axum, WebAuthn) | Optional self-hosted multi-device synchronization, passkey enrollment, and TOTP MFA. |
| **L2 Registry** | `contracts/` | Solidity 0.8.28 (Foundry) | Immutable EIP-712 state commitment anchor contract deployed on Arbitrum One. |

---

## ✨ Important Features

### 🔐 Cryptographic Sovereignty
* **Authenticated Client Encryption**: All confidential payloads are encrypted using `XChaCha20-Poly1305` (256-bit key, 192-bit nonce) with domain-separated custom Blake2b key derivation (ADR-001).
* **Deterministic Content Addressing**: Chunks are addressed exclusively by their SHA-256 content hashes, completely obscuring original file names, directory paths, and file sizes from storage operators.
* **Volatile Memory Scrubbing**: Sensitive cryptographic key buffers implement `Zeroize` and `ZeroizeOnDrop` compiler fences to prevent plaintext leaks in core dumps or swap memory.

### 🧩 Content-Defined Chunking (FastCDC)
* **Gear Rolling Hash**: Byte-level sliding window with compile-time `SplitMix64` lookup tables dynamically determines chunk boundaries (4 KiB min, 16 KiB avg, 64 KiB max).
* **96.15% Deduplication**: Local edits to a single credential or environment variable only modify the containing chunk; all other chunks remain identical, drastically slashing network traffic and storage overhead.

### 📜 Clean-Machine Disaster Recovery
* **Emergency Offline Paper Recovery Kit**: Generates an interactive terminal recovery sheet containing Master Secret $R$ and a CRC32 checksum. Print or write this down once to restore your entire secret vault onto any new computer.
* **$M$-of-$N$ Shamir Threshold Guardians**: Split Master Secret $R$ across $N$ trusted teammates (e.g. 3-of-5). Any $M$ guardian shares can reconstruct the vault in memory using constant-time $\text{GF}(2^8)$ polynomial interpolation.
* **Out-of-Band Multi-Party Approvals**: Require cryptographic signatures from designated team leads before executing high-risk recoveries on clean or untrusted hardware (`ciphervault approve`).

### 🚀 Zero-Disk Process Execution (`ciphervault run`)
* **In-Memory Environment Injection**: Launch child processes (`npm start`, `cargo run`, `python app.py`, `docker compose up`) with decrypted secrets directly injected into their volatile process environment.
* **Zero Plaintext on Disk**: No plaintext `.env` files ever touch physical storage media.
* **Hermetic Isolation**: Strip existing host environment variables (`--no-inherit`) or inject runtime overrides (`--set PORT=8080`).

### 👁️ Shoulder-Surfing Safe Secret Diffing (`ciphervault diff`)
* **Masked by Default**: Inspect additions, deletions, and key modifications between snapshots or your working tree without exposing plaintext secret values on screen.
* **Private Reveal Mode**: Explicitly reveal unmasked values only when working in a secure environment with `--reveal`.
* **Auditable JSON Output**: Generate structured machine-readable reports for security pipelines and CI audits (`--json`).

### 🔑 Hardware Security Tokens (YubiKey PIV)
* **Native ISO 7816-4 APDU Driver**: Direct communication over platform PC/SC (`winscard.dll` on Windows, pcsc-lite on Linux/macOS) with zero external C dependencies.
* **Hardware-Bound Signing**: Private identity keys are locked in YubiKey PIV Slot 9C and never exported.
* **Capacitive Touch Presence**: Enforce physical finger touch on the security key before signing snapshot commits (`ciphervault push --touch`).

### 🖥️ Dual User Interfaces
* **Interactive Terminal UI (TUI)**: Fast, full-screen terminal interface powered by Ratatui and Crossterm with 6 views: Overview, Files, History, Operators, FastCDC chunk distribution, and Hardware Token telemetry (`ciphervault tui`).
* **Embedded Web Dashboard & Explorer**: Self-contained local web dashboard with zero tracking or external CDN dependencies for visually exploring chunk graphs, diffing secrets, and simulating Shamir ceremonies (`ciphervault ui`).

### ⏱️ Autonomous File Watcher Daemon (`ciphervault watch`)
* **OS-Level File Event Hook**: Listens to native filesystem change notifications using the `notify` crate.
* **Intelligent Debouncing & Coherent Reads**: Waits for writes to settle (default: 2 seconds) and verifies coherent reads before automatically creating FastCDC snapshots and replicating them to operators.

### 🚫 Git Leak Prevention Hook (`ciphervault hook`)
* **Automated `.gitignore` Sync**: Adding confidential files via `ciphervault track` automatically ensures they are excluded in `.gitignore`.
* **Pre-Commit Enforcement**: Installable Git pre-commit hook blocks accidental staging or committing of confidential files.

### ⛓️ Tamper-Evident L2 State Anchoring
* **Arbitrum One Rollup Commitments**: Anchor cryptographic state commitments to an on-chain Solidity registry contract using salted EIP-712 hashes.
* **Immutable Sequencer Receipts**: Persist on-chain transaction receipts locally to mathematically prove vault state integrity at any historical point in time.

---

## 📦 Installation Guide

### Prerequisites
* **Operating System**: Windows 10/11, macOS (Apple Silicon or Intel), or Linux (Ubuntu, Debian, Fedora, Arch).
* **Rust Toolchain**: Rust `1.80.0` or newer (if building from source).
* **PC/SC Smartcard Service**: (Optional, only for YubiKey PIV hardware token features). Enabled by default on Windows (`winscard`); install `pcscd` on Linux.

---

### Option 1: Install Pre-Built Binary

#### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex
```

#### macOS & Linux (Bash)
```bash
curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash
```

> Private repo: the commands above need a token until the repo is public.
> Create a fine-grained personal access token with **Contents: read-only**
> on this repo, export it as `CIPHERVAULT_GITHUB_TOKEN` (`GH_TOKEN` /
> `GITHUB_TOKEN` also work), and add the auth header to the bootstrap
> fetch — the installer reuses the variable for the release download:
>
> ```powershell
> $env:CIPHERVAULT_GITHUB_TOKEN = '<paste-token-here>'
> $h = @{ Authorization = "Bearer $env:CIPHERVAULT_GITHUB_TOKEN" }
> irm -Headers $h https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex
> ```
>
> ```bash
> export CIPHERVAULT_GITHUB_TOKEN='<paste-token-here>'
> curl -fsSL -H "Authorization: Bearer $CIPHERVAULT_GITHUB_TOKEN" \
>   https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash
> ```
>
> `ciphervault update` reads the same variable.

---

### Option 2: Install via Cargo (Recommended for Rust Developers)

Install the standalone `ciphervault` CLI binary directly from Git into your Cargo bin path:

```bash
cargo install --git https://github.com/samuel-1-avson/CipherVault.git ciphervault-cli
```

Ensure `~/.cargo/bin` (or `%USERPROFILE%\.cargo\bin` on Windows) is in your system's `PATH`.

---

### Option 3: Build From Source

Clone the repository and compile optimized release binaries for the entire workspace:

```bash
git clone https://github.com/samuel-1-avson/CipherVault.git
cd CipherVault

# Compile all workspace binaries with release optimizations
cargo build --workspace --release --locked
```

Compiled binaries will be available in `target/release/`:
* `ciphervault` — Main developer CLI, embedded web dashboard, and Ratatui TUI.
* `ciphervault-operator` — Zero-knowledge federated storage node service.
* `ciphervault-maintenance` — Autonomous replication auditor and self-repair daemon.
* `ciphervault-agent` — Background filesystem watcher daemon.
* `ciphervault-account` — Optional self-hosted account and device identity service.

---

### Shell Autocompletions

Generate native, high-performance autocompletions for your shell:

```bash
# PowerShell (add to your $PROFILE)
ciphervault completions powershell | Out-String | Invoke-Expression

# Bash
eval "$(ciphervault completions bash)"

# Zsh
eval "$(ciphervault completions zsh)"

# Fish
ciphervault completions fish > ~/.config/fish/completions/ciphervault.fish
```

---

## ⚡ Quickstart Guide

### 1. Start a Local 3-Node Storage Cluster

CipherVault replicates encrypted chunks across independent storage operators. For local development or testing, spin up a 3-node cluster using Docker Compose:

```bash
# Start 3 storage operators, maintenance scheduler, and dashboard
docker compose up -d
```

*(Alternatively, run three local operator instances manually: `ciphervault-operator --port 8201 --data-dir ./data/op1 --operator-id op_8201`)*

---

### 2. Initialize a Vault in Any Project

Navigate to any project directory containing confidential files (`.env`, certificates, tokens):

```bash
cd ~/my-project

# Initialize vault with the local 3-node operator cluster
ciphervault init --operators http://127.0.0.1:8201 http://127.0.0.1:8202 http://127.0.0.1:8203 --import-gitignore
```

> [!IMPORTANT]
> **RECORD YOUR EMERGENCY RECOVERY KIT!**
> CipherVault will display your **Offline Emergency Recovery Kit** (containing Master Secret $R$). Write this key down and store it in a secure location. In accordance with CipherVault's zero-disk recovery policy, $R$ is immediately scrubbed from volatile RAM and is never written unencrypted to disk.

---

### 3. Track Confidential Files & Capture Encrypted Snapshot

```bash
# Track confidential files (automatically adds them to .gitignore)
ciphervault track .env certs/server.key config/credentials.json

# Check vault status and tracked files
ciphervault status

# Slice (FastCDC), encrypt (XChaCha20-Poly1305), and replicate snapshot across all 3 operators
ciphervault push -m "Initial production environment"
```

Every push performs a per-object **Proof-of-Storage** challenge readback, both as pre-upload dedup (objects with a valid proof are not re-uploaded) and as mandatory post-upload verification before a replica counts toward quorum.

---

### 4. Zero-Disk In-Memory Execution (`ciphervault run`)

Run your applications with secrets directly injected into their process environment in volatile RAM **without ever writing plaintext `.env` files to disk**:

```bash
# Node.js
ciphervault run -- npm start

# Python
ciphervault run -- python main.py

# Docker Compose
ciphervault run -- docker compose up

# Hermetic isolation (strip host environment variables)
ciphervault run --no-inherit -- python script.py

# Dry-run inspection (view decrypted variable keys without exposing values)
ciphervault run --dry-run -- node server.js
```

---

### 5. Safe Secret Diffing (`ciphervault diff`)

Compare changes in your confidential files with automatic shoulder-surfing protection:

```bash
# View masked diff against active snapshot head (values hidden)
ciphervault diff

# Reveal plaintext values in a secure private terminal
ciphervault diff --reveal

# Diff between two historical snapshot revisions
ciphervault diff <snapshot_id_1> <snapshot_id_2>
```

---

### 6. Interactive Terminal User Interface (TUI)

Launch the full-screen terminal dashboard:

```bash
ciphervault tui
```

* **`[1] Overview`**: Active snapshot head, epoch age, tracked file count, and storage quorum status.
* **`[2] Files`**: Browse tracked confidential files, byte sizes, and modification timestamps.
* **`[3] History`**: Interactive snapshot DAG history with commit messages and CIDs.
* **`[4] Operators`**: Real-time roundtrip latency gauges, healthy/degraded replica states, and PoS status.
* **`[5] FastCDC`**: Content-defined chunk distributions and deduplication efficiency graphs.
* **`[6] Token`**: Hardware token reader presence, PIV slot status, and touch policies.
* **Hotkeys**: Press `[p]` to commit and push a new snapshot; press `[a]` to anchor to L2; press `[q]` to quit.

---

### 7. Embedded Web Dashboard & Secrets Explorer

Launch the local web dashboard for visual exploration:

```bash
ciphervault ui --port 8080
```

Open **`http://127.0.0.1:8080`** in your browser to inspect chunk graphs, review telemetry, and test recovery ceremonies.

---

### 8. Autonomous File Watcher Daemon (`ciphervault watch`)

Run the background file watcher to automatically capture snapshots whenever you save a tracked secret:

```bash
# Watch with 2-second debounce and auto-sync replication
ciphervault watch --debounce 2 --sync
```

Whenever you modify and save `.env` in your code editor, CipherVault debounces for 2 seconds, verifies a coherent read, creates a FastCDC snapshot, and replicates the encrypted chunks to all operators automatically.

---

### 9. Hardware Security Token Signing (YubiKey PIV)

Bind snapshot commit signatures to a physical YubiKey 5 Series hardware token:

```bash
# Probe attached smartcard readers
ciphervault token probe

# Initialize vault binding device identity to physical token
ciphervault init --hardware-token

# Push snapshot requiring physical capacitive touch
ciphervault push -m "Hardware-verified commit" --touch
```

When `--touch` is enabled, host execution pauses until you physically touch the metal contact on your YubiKey. The private signing key never leaves the smartcard secure element.

---

### 10. Vault Health Check (`ciphervault doctor`)

Run an automated self-diagnostic check on your local vault configuration, OS keyring security, operator reachability, quorum consistency, and anchor freshness:

```bash
ciphervault doctor
```

---

## 🛡 Clean-Machine Disaster Recovery

If your workstation is lost, stolen, or destroyed, CipherVault enables complete secret restoration onto a clean replacement computer without access to any prior databases or cloud coordinators.

### Method A: Single Emergency Paper Recovery Kit

Restore all confidential files using your printed Master Secret $R$:

```bash
ciphervault recover --kit emergency_recovery_kit.txt --to ./restored_secrets/
```

CipherVault contacts the storage operators, downloads the encrypted chunks, reconstructs the key hierarchy in memory, decrypts each file, and restores them with bit-for-bit fidelity.

---

### Method B: Threshold Guardian Reconstruction ($M$-of-$N$ Shamir)

For team environments, split the master recovery secret so that no single person can recover the vault alone:

```bash
# Generate 3 printable guardian sheets where any 2 are required to recover
ciphervault recovery split --threshold 2 --shares 3 --out-dir ./guardians
```

To recover on a clean machine, combine any $M$ guardian shares:

```bash
ciphervault recover --shares guardian_share_1_of_3.txt guardian_share_3_of_3.txt --to ./restored_secrets/
```

* **Constant-Time $\text{GF}(2^8)$ Arithmetic**: Polynomial Lagrange interpolation executes entirely in volatile memory with zero secret-dependent branches.
* **Zero Disk Exposure**: Secret $R$ is never written to disk during or after recovery.
* **100% Bit-for-Bit Identity**: All restored files are verified against original SHA-256 digests.

---

### Method C: Out-of-Band Multi-Party Gated Recovery

Enforce cryptographic approval receipts before restoring secrets onto untrusted hardware:

```bash
# Initiates a 600-second authorization challenge on the operator cluster
ciphervault recover --kit emergency_recovery_kit.txt --to ./restored_secrets/ --require-approval
```

An authorized team lead signs and approves the challenge from their enrolled device:

```bash
# Team lead inspects and approves the challenge
ciphervault approve list
ciphervault approve sign <CHALLENGE_ID>
```

---

## 💻 Complete CLI Command Reference

| Command | Key Arguments & Flags | Description |
|---|---|---|
| `ciphervault init` | `[-f/--force] [-o/--operators <URL...>] [--save-kit <PATH>] [--hardware-token] [-i/--import-gitignore]` | Initializes a new vault, derives key hierarchy, prints paper recovery kit, and scans `.gitignore` for secrets. |
| `ciphervault track` | `[PATH...] [-i/--from-gitignore] [--no-gitignore]` | Registers confidential files for snapshot tracking; automatically appends to `.gitignore` to prevent leaks. |
| `ciphervault untrack` | `<PATH...>` | Stops tracking specified confidential files. |
| `ciphervault status` | `[--json]` | Displays active vault metadata, tracked files, and active epoch. |
| `ciphervault push` | `[-m/--message <MSG>] [--touch] [--local] [--anchor] [--concurrency <N>] [--replicas <N>]` | Slices files with FastCDC, encrypts, and replicates across operators with mandatory PoS readback verification; hardware touch optional. |
| `ciphervault pull` | `[--dry-run] [--force]` | Pulls and applies latest verified snapshots from storage operators. |
| `ciphervault history` | *None* | Displays the snapshot commit DAG history. |
| `ciphervault run` | `[-s/--snapshot <HEX>] [-e/--env-file <FILE>] [--no-inherit] [--dry-run] [--set <K=V...>] -- <CMD...>` | Injects decrypted secrets directly into child process environment in volatile RAM (zero disk exposure). |
| `ciphervault diff` | `[<SNAPSHOT_A>] [<SNAPSHOT_B>] [-f/--file <PATH>] [--reveal] [--json]` | Compares confidential file changes with shoulder-surfing masking enabled by default. |
| `ciphervault restore` | `[-s/--snapshot <HEX>] [--to <DIR>] [--hardware-token]` | Restores confidential files from a historical snapshot to disk. |
| `ciphervault recover` | `[--kit <PATH>] [--shares <PATH...>] --to <DIR> [--require-approval]` | Reconstructs confidential files on a clean machine using a paper kit or $M$-of-$N$ threshold guardian shares. |
| `ciphervault recovery split` | `-t/--threshold <M> -s/--shares <N> [--kit <PATH>] [-o/--out-dir <DIR>]` | Splits master recovery secret $R$ into printable Shamir paper guardian sheets. |
| `ciphervault recovery export` | *None* | Displays public descriptors (signing PK, encryption PK, locator) without exposing secret $R$. |
| `ciphervault recovery test` | `[--kit <PATH>] --to <DIR>` | Non-destructive dry-run verifying recovery set availability across operators. |
| `ciphervault prune` | `[--keep-last <N>] [--keep-days <D>] [--dry-run]` | Cleans up historical snapshots and performs chunk garbage collection per retention policy. |
| `ciphervault rekey` | `[--check] [--warn-days <D>]` | Rotates the vault epoch key and re-encrypts envelopes. |
| `ciphervault doctor` | `[--json]` | Runs comprehensive local diagnostics across vault state, OS keyring, operators, and quorum health. |
| `ciphervault tui` | `[--poll-ms <MS>]` | Launches interactive full-screen Terminal User Interface dashboard. |
| `ciphervault ui` | `[--host <ADDR>] [--port <PORT>] [--no-browser] [--local]` | Launches embedded Web Dashboard and Visual Secrets Explorer. |
| `ciphervault watch` | `[-d/--debounce <SECS>] [-s/--sync] [--dry-run]` | Listens to OS filesystem save events on tracked secrets; auto-snapshots and pushes on save. |
| `ciphervault anchor` | `[--head <CID>] [--auto-relay] [--relayer-url <URL>] [--daemon]` | Computes EIP-712 state commitment and submits to Arbitrum One L2 rollup. |
| `ciphervault verify-anchor` | `[--head <CID>] [--rpc <URL>]` | Verifies on-chain commitment and finality on Arbitrum One. |
| `ciphervault publish-public-feed` | `-o/--output <PATH> [--network <LABEL>]` | Publishes a signed public checkpoint feed from local vault evidence for the public explorer. |
| `ciphervault audit` | `[-o/--operators <URL...>]` | Performs remote replication quorum and CID closure audit across operators. |
| `ciphervault repair` | `[-o/--operators <URL...>] [--replicas <N>]` | Detects degraded replicas and self-heals by streaming missing chunks from surviving operators. |
| `ciphervault peers` | `[--discover] [--mesh]` | Queries operators to inspect active nodes, dynamically discover peers via P2P gossip, or mesh routing tables via announce. |
| `ciphervault lease create/renew` | `<CLOSURE|LEASE_ID> [--operator <URL>]` | Commits or renews a storage lease on one operator (device session auth). |
| `ciphervault voucher issue` | `<HOLDER_PK> <QUOTA> [--operator <URL>]` | Issues a write voucher from an operator (service token admin). |
| `ciphervault invite pubkey/issue/join/refresh` | `<NODE_PK> --fleet-key-file <PATH> [--ttl <S>] [--keys-file <PATH>] [--out <PATH>] [--node <URL>] [--via <URL...>]` | Fleet-signed join tickets: print the fleet pin, issue a ticket offline (single key or batch file, `--out` writes UTF-8 directly), present it to join a fleet (probation), or refresh liveness toward graduation. |
| `ciphervault node setup/start/stop/status/backup/standing/p2p-info` | `[--data-dir <DIR>]` | Run a storage node: guided first-run wizard, lifecycle, plain-language health and fleet-standing reports, identity backup, and P2P peering info. |
| `ciphervault approve list/sign/status`| `<CHALLENGE_ID>` | Out-of-band cryptographic push authorization for high-risk operations. |
| `ciphervault token status/probe/slots`| `[--reader <NAME>]` | Inspects attached PC/SC smartcard readers, PIV slots, and touch policies. |
| `ciphervault hook install/check` | *None* | Installs or checks Git pre-commit hook to prevent secret leaks. |
| `ciphervault auth init/login/logout` | `[--name <NAME>]` | Manages optional local account and device identity. |
| `ciphervault device list/revoke` | `<DEVICE_ID>` | Lists or revokes enrolled devices in the local account registry. |
| `ciphervault vault link/unlink` | `[--alias <NAME>]` | Binds or removes the local vault from the account registry. |
| `ciphervault completions` | `<SHELL>` | Emits native shell autocompletion script (bash, zsh, fish, powershell, elvish). |
| `ciphervault update` | `[--check]` | Checks for and installs latest signed GitHub release. |

---

## 🐳 Docker Compose & Self-Hosting

CipherVault includes production container configurations for running a fully self-hosted, sovereign storage federation:

```bash
# Start 3-node storage federation, maintenance scheduler, and dashboard
docker compose up -d

# Check cluster status and health checks
docker compose ps

# Access embedded Web Dashboard
open http://localhost:8080
```

### Services Deployed

| Service | Container Name | Port | Description |
|---|---|---|---|
| `operator-1` | `ciphervault-operator-1` | `8201` | Primary zero-knowledge storage node & L2 relayer endpoint |
| `operator-2` | `ciphervault-operator-2` | `8202` | Secondary zero-knowledge storage operator |
| `operator-3` | `ciphervault-operator-3` | `8203` | Tertiary zero-knowledge storage operator |
| `maintenance` | `ciphervault-maintenance` | Internal | Periodic replication auditor & SQLite `fleet.db` self-repair daemon |
| `account` | `ciphervault-account` | `8300` | Optional self-hosted account plane with WebAuthn passkeys & TOTP MFA |
| `dashboard` | `ciphervault-dashboard` | `8080` | Self-contained visual explorer & dashboard |

### Self-Hosted Multi-Server Deployment
For production deployments across independent servers or private clouds, deploy `ciphervault-operator` across 3+ distinct physical or virtual machines behind an HTTPS reverse proxy (such as Caddy or Nginx) with mutual TLS or bearer token authorization. Each operator requires only a persistent data directory and a single open port.

### Join the Fleet as an Operator
New operators start with the guided wizard (`ciphervault node setup` answers three questions, then starts the node), send their node public key to a fleet admin, and present the resulting ticket (`ciphervault invite join`) to enter probation — full trust after a day of uptime. Full ceremony: [operator playbook §10](docs/OPERATOR_PLAYBOOKS.md), [workflow guide Part 3](docs/WORKFLOW_GUIDE.md), and the [public testnet notes](docs/TESTNET.md).

---

## 📊 Performance Benchmarks

Empirical performance metrics measured on x86_64 architecture:

| Metric | Measured Value | Benchmark Description / Comparison |
|---|---|---|
| **Encryption Throughput** | **558.62 MiB/s** | Client-side `XChaCha20-Poly1305` AEAD encryption |
| **Decryption Throughput** | **656.84 MiB/s** | Client-side `XChaCha20-Poly1305` AEAD decryption |
| **FastCDC Deduplication Ratio** | **96.15%** | 25/26 chunks preserved upon localized secret edit |
| **PoS Readback Wire Reduction** | **99.956%** | Reduced from 1,048,576 bytes to 461 bytes per 1 MiB chunk |
| **Hardware Token APDU Latency** | **< 1.5 ms** | Direct native PC/SC short APDU round-trip latency |
| **Integrity Fidelity** | **100.00%** | Zero bitflips across all chaos failure and recovery drills |

---

## 🧪 Verification & Quality Gates

CipherVault enforces strict zero-warning compilation and comprehensive multi-layer testing across cryptography, networking, and UI:

```bash
# Execute workspace test suite (63 suites, ~290 tests, all passing as of 2026-09-18)
cargo test --workspace --locked

# Strict static analysis & linter enforcement (zero warnings policy)
cargo clippy --workspace --all-targets --locked -- -D warnings

# Formatting compliance check
cargo fmt --all -- --check

# Single-page UI headless regression suite
node apps/ui/audit.test.cjs

# Solidity L2 registry test suite (Foundry)
forge test
```

---

## 📚 Further Documentation

For deep technical specifications, audit reports, and deployment guides, explore the documentation hub in [`docs/`](docs/README.md):

* [**`WORKFLOW_GUIDE.md`**](docs/WORKFLOW_GUIDE.md) — Operator network overview, day-to-day user flow, and the run-a-node guide (Part 3).
* [**`OPERATOR_PLAYBOOKS.md`**](docs/OPERATOR_PLAYBOOKS.md) — Fleet operations: restart, mesh, vouchers, backup/restore, and the verified-join ceremony (§10).
* [**`TESTNET.md`**](docs/TESTNET.md) — Public testnet endpoints, join flow, and known issues.
* [**`SYSTEM_WORKFLOW.md`**](docs/SYSTEM_WORKFLOW.md) — Comprehensive architectural deep dive, cryptographic key hierarchy, and end-to-end sequence diagrams.
* [**`CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`**](docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md) — Mathematical specifications, constant-time $\text{GF}(2^8)$ arithmetic, and threat boundary models.
* [**`DEPLOYMENT_RUNBOOK.md`**](docs/DEPLOYMENT_RUNBOOK.md) — Production operations, multi-node deployment, reverse proxy hardening, and TLS configuration.
* [**`CICD_INTEGRATION.md`**](docs/CICD_INTEGRATION.md) — Zero-disk secret injection guides for GitHub Actions, GitLab CI, and CircleCI.
* [**`SECURITY_AUDIT_REPORT.md`**](dist/SECURITY_AUDIT_REPORT.md) — Security review findings and verification evidence.

---

## 📄 License

Dual-licensed under either of:

* **Apache License, Version 2.0** ([LICENSE](LICENSE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
* **MIT License** ([LICENSE](LICENSE) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

at your option.
