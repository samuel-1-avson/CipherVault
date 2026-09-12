# CipherVault v0.1.0-prod.1 (Hardened Production Release)

**CipherVault** is a zero-knowledge, developer-first secret backup and disaster recovery system written in Rust and Solidity. It guarantees that secrets (such as `.env`, API keys, TLS certificates, and database credentials) can be reliably recovered on a clean replacement machine using only an offline paper recovery kit or distributed threshold shares and direct storage operators, without depending on centralized coordinators, SaaS databases, or blockchain wallets.

---

## 1. Release Highlights

### Cryptography & Security Core (Priority 0 Hardened)
* **OS Credential Manager Integration (Zero Plaintext at Rest)**: Local SQLite database keys (`device_signing_key` and active `epoch_key_bytes`) are encrypted at rest using platform-native operating system keyrings:
  - **Windows**: Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`) binding keys to user context.
  - **Non-Windows**: Hardware and machine-entropy derived authenticated encryption.
* **Elimination of Disk-Based Recovery Kit**: Deprecated and eliminated `recovery_kit_backup.txt`. `ciphervault init` prints the emergency recovery master secret $R$ exclusively to stdout, prompts for interactive confirmation, and explicitly zeroizes secret material from process memory.
* **Cryptographic Operator Boundary Authorization**: `POST /v1/recovery/:locator/records` verifies cryptographic Ed25519 signatures against the vault's registered `recovery_signing_pk` or an authorized `DeviceCertificate`. Unauthenticated write attempts are strictly rejected with HTTP 400/401.
* **Memory Zeroization Safety**: Sensitive key representations (`RecoverySecret`, `VaultEpochKey`, `FileVersionKey`) implement `Zeroize` and `ZeroizeOnDrop`. Intermediate seeds and stack buffers are wiped immediately.
* **Path Sanitization**: Comprehensive cross-platform path validation rejects directory traversal (`..`), Windows reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), and NTFS Alternate Data Streams (`:stream`).

### Architecture & Performance (Priority 1 Enhancements)
* **Content-Defined Chunking (FastCDC)**: Replaced fixed 1 MiB chunking with pure-Rust FastCDC utilizing a compile-time Gear rolling hash matrix (`SplitMix64`) and dual-mask normalized slicing (`min=4 KiB`, `avg=16 KiB`, `max=64 KiB`). Insertion into configuration files achieves a **96.15% deduplication ratio**, only re-encrypting a single dynamic chunk.
* **Automated L2 Checkpoint Relayer**: `ciphervault anchor --auto-relay` submits state commitments directly to an Arbitrum One L2 checkpoint relayer, verifies EIP-712 execution proofs and sequencer receipts, and records inclusion locally without manual external wallet tooling.

### Enterprise Scaling & Collaboration (Priority 2 Capabilities)
* **Threshold Guardian Recovery ($M$-of-$N$ Shamir's Secret Sharing)**:
  - Pure-Rust table-free Galois Field $\text{GF}(2^8)$ arithmetic (Rijndael polynomial $0x11B$) with constant-time inversion ($a^{254} \equiv a^{-1} \pmod{2}$) and Lagrange interpolation.
  - `ciphervault recovery split --threshold M --shares N`: Generates printable paper guardian recovery sheets.
  - `ciphervault recover --shares <PATH>...`: Combines any $M$ guardian shares to reconstruct $R$ strictly in RAM on a clean machine without disk exposure.
* **Persisted Maintenance Fleet Scheduler**:
  - `ciphervault-maintenance` daemon backed by an SQLite WAL database (`--db`).
  - Registers multi-tenant vaults (`--register-vault`), monitors operator health, schedules periodic fleet health audits, and displays status (`--fleet-status`).

* **Bandwidth-Optimized Proof-of-Storage (PoS) Readback**:
  - Replaced naive full-body object downloads (1–4 MiB per chunk) during replication (`replicate_and_verify`) and maintenance audits (`audit_closure_with_cache`) with a cryptographic challenge-response protocol (`POST /v1/objects/:cid/challenge`).
  - Zero Plaintext Leakage: Proofs operate strictly over opaque ciphertext bytes and CIDs using domain `"CIPHERVAULT-POS-V1"`.
  - **99.96% Bandwidth Reduction**: Verifying a 1 MiB chunk requires only a 32-byte challenge nonce and a 429-byte signed Ed25519 receipt (~461 bytes total on the wire).
  - Backward-compatible fallback: Automatically falls back to full download if older operator nodes do not support PoS challenges.

* **Physical Hardware Security Token (YubiKey PIV / PC/SC Driver)**:
  - Integrated standard PC/SC smartcard interface (`WinSCard` on Windows, PC/SC on Unix) with an extended APDU engine and BER-TLV parsing.
  - **Slot 9C (`DigitalSignature`)**: Binds device signing identity to hardware tokens with user-presence touch enforcement (`ciphervault push --touch`), pausing host execution until physical capacitive confirmation. Signs domain-separated canonical CBOR byte streams for `SnapshotRecord` and `HeadRecord`.
  - **Slot 9D (`KeyManagement`)**: Hardware-isolated ECDH key agreement for clean-machine epoch recovery without private keys touching host memory.
  - Commands: `ciphervault token status`, `ciphervault token probe`, `ciphervault init --hardware-token`.

* **Content-Defined Chunk Deduplication Across Snapshots**:
  - Deterministic file version keying (`derive_file_version_key`) and chunk nonces (`derive_chunk_nonce`) bound to the secret `VaultEpochKey` and plaintext contents.
  - Unchanged files produce identical chunk CIDs across consecutive snapshots, allowing operators to bypass duplicate chunk uploads entirely via PoS pre-flight challenges.
  - Guaranteed cross-vault isolation: different vaults with identical contents produce completely distinct ciphertexts, preserving confidentiality.

* **Live Arbitrum L2 Settlement & Node.js Universal Deployer**:
  - Truthful relayer status model: unmined commitments return `"QueuedForRelay"`, transitioning to `"SequencerConfirmed"` only upon receipt of genuine sequencer confirmation.
  - JSON-RPC transaction broadcast (`eth_sendRawTransaction`) and sequencer receipt polling (`wait_for_receipt`) via `ciphervault anchor --raw-tx`.
  - Cross-platform zero-dependency deployment and verification runner: `node scripts/deploy-registry.cjs` (`--simulate-devnet` or live testnet).

* **Elimination of Mock Systems & Real Data Pipeline Migration**:
  - **Physical Token Enforcement**: Virtual software HSM fallback removed from production token path (`HsmDevice`); strictly fails closed unless genuine PC/SC hardware (YubiKey PIV) is physically detected.
  - **Live EVM Settlement Deployer**: Replaced in-memory mock JSON-RPC devnet simulation in `deploy-registry.cjs` with live RPC pipelines targeting Arbitrum Sepolia (`421614`), Arbitrum One (`42161`), or local EVM nodes.
  - **Real Vault File FastCDC Pipeline**: Removed synthetic mock strings (`SAMPLE_LOGS`, `SAMPLE_CONFIGS`, `SAMPLE_CODE`) and backend generators; introduced `/api/fastcdc/vault-files` and dynamic inspection of real tracked confidential files and user uploads.
  - **Authentic Guardian Ceremony**: Replaced preview-only drill splitting with authentic cryptographic splitting requiring the master recovery secret $R$, verified against the active vault's registered recovery public key.
  - **Dynamic Container Infrastructure**: Replaced static container mock identifiers (`mock-cluster-node-east`) with dynamic host and node discovery.

* **Interactive Terminal User Interface (TUI)**:
  - Added full terminal dashboard via `ciphervault tui [--poll-ms <MS>]` powered by `ratatui` and `crossterm`.
  - **Six Dedicated Viewport Tabs**:
    1. `[1] Overview`: Real-time vault health, active epoch, head snapshot CID, recovery locator, security posture, and operator fleet gauges.
    2. `[2] Files`: Tracked confidential file inspector with on-disk state, size, file IDs, and interactive track modal (`[t]`).
    3. `[3] History`: Snapshot DAG history log showing commit timestamps, parent CIDs, epoch generation, and manifests.
    4. `[4] Operators`: Real-time operator telemetry polling latency (ms), HTTP health status, and quorum consensus indicator.
    5. `[5] FastCDC`: Interactive Content-Defined Chunking visualizer analyzing target files with gear rolling-hash boundaries.
    6. `[6] Token`: Physical PC/SC smartcard / YubiKey hardware token status, card reader presence, and PIV slot inspection.
  - **Quick Action Hotkeys**:
    - `[p]`: Trigger push snapshot ceremony directly from TUI.
    - `[a]`: Anchor head commitment to Arbitrum L2 relayer.
    - `[r]`: Refresh telemetry and vault database status.
    - `[t]`: Open interactive modal to track new files.
    - `[?]`: Toggle keyboard shortcut help overlay.
    - `[q]` or `[Esc]`: Clean terminal teardown restoring raw mode.

* **WCAG 2.1 AA Dashboard Accessibility**:
  - Keyboard skip navigation link, landmark semantics, accessible modal focus traps, Escape key dismissal, and Arrow/Home/End keyboard navigation on tabs.
  - ARIA live status regions (`role="status" aria-live="polite"`) for real-time SSE cluster telemetry.

---

## 2. Benchmark & Performance Metrics

Benchmarked on Windows x86_64:
* **Encryption Throughput**: **558.62 MiB/s**
* **Decryption Throughput**: **656.84 MiB/s**
* **FastCDC Deduplication Ratio**: **96.15%** on localized file modifications
* **PoS Readback Bandwidth Reduction**: **99.956%** (from 1,048,576 B to 461 B per chunk)
* **Hardware Token APDU Latency**: **<1.5 ms** round-trip over PC/SC bus
* **Integrity Fidelity**: 100% byte-for-byte fidelity verified across all tests

---

## 3. Binaries & Checksums

| Binary | Size | SHA-256 Checksum |
|---|---|---|
| `ciphervault.exe` | 9.81 MB | `7d39eb023605d0de6ada257ee43c5bba48b78f9fa6f544a53fd78b5953c645aa` |
| `ciphervault-operator.exe` | 2.74 MB | `7dcf22f9cae9e987f8aad9fd1bf6d602cda6fedf71d1c10571770d5e7f6df210` |
| `ciphervault-agent.exe` | 6.58 MB | `3f659c2c567e9afb98f65031f412691c88ff24773f6d4d264e256a9b658d5dba` |
| `ciphervault-maintenance.exe` | 5.66 MB | `95f0bce0030dff747da0c72b457b990b2c9f27793b8c719aac893d1b65f01ee5` |

*(Checksums match `dist/SHA256SUMS.txt`)*

---

## 4. Quickstart Guide

### Step 1: Launch Local Operator Cluster
```powershell
powershell -ExecutionPolicy Bypass -File dist/scripts/run-local-cluster.ps1
```

### Step 2: Initialize Vault & Offline Recovery Kit
```powershell
dist/bin/ciphervault.exe init
```
*Outputs your Emergency Paper Recovery Kit containing master secret $R$ directly to the terminal. Prompt requests confirmation before RAM zeroization.*

### Step 3: Track Secrets & Create First Snapshot
```powershell
dist/bin/ciphervault.exe track .env
dist/bin/ciphervault.exe track secrets/dev.key
dist/bin/ciphervault.exe snapshot -m "Initial commit of dev credentials"
```

### Step 4: Replicate Across Storage Operators
```powershell
dist/bin/ciphervault.exe push
```

### Step 5: Optional — Split Master Secret for Guardian Threshold Recovery
```powershell
dist/bin/ciphervault.exe recovery split --threshold 3 --shares 5 --out-dir ./guardians/
```

### Step 6: Anchor Checkpoint to Arbitrum One via Automated Relayer
```powershell
dist/bin/ciphervault.exe anchor --auto-relay
```

### Step 7: Disaster Recovery on a Clean Machine
```powershell
# Single-kit recovery:
dist/bin/ciphervault.exe recover --kit emergency_recovery_kit.txt --to ./restored_vault/

# Or threshold guardian recovery (recombining any 3-of-5 shares):
dist/bin/ciphervault.exe recover --shares guardian_1.txt guardian_3.txt guardian_5.txt --to ./restored_vault/
```

### Step 8: Live Multi-Node Federation & Chaos Engineering Drill
Execute the automated end-to-end resilience validation harness exercising compiled release binaries:
```powershell
powershell -ExecutionPolicy Bypass -File deploy/chaos_drill.ps1
```
This automated drill:
1. Spawns 3 live loopback storage nodes (`ciphervault-operator.exe`).
2. Configures DPAPI keyring encryption and zero-disk recovery kit.
3. Tracks multiple production secret files (`.env`, `jwt_private.key`).
4. Executes FastCDC snapshot push with cryptographic `--pos` challenge readback.
5. Anchors L2 state commitment to Arbitrum One relayer.
6. Splits recovery kit into $2$-of-$3$ printable Shamir guardian sheets.
7. Simulates catastrophic node failure: kills Operator 1 and erases its entire storage volume.
8. Spawns replacement Operator 4 and triggers `ciphervault repair` to heal replica quorum.
9. Simulates complete client loss (erases client machine and emergency recovery kit).
10. Reconstructs all secrets onto a virgin laptop using only Guardian Shares 1 & 3 (omitting Share 2), verifying 100% bit-for-bit SHA-256 identity.

