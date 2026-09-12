# CipherVault v0.1.0 (Security Beta Gate Release)

**CipherVault** is a zero-knowledge, developer-first secret backup and disaster recovery system written in Rust and Solidity. It guarantees that secrets (such as `.env`, API keys, certificates, and database credentials) can be reliably recovered on a clean replacement machine using only a paper recovery kit and direct storage operators, without depending on centralized coordinators, SaaS databases, or blockchain wallets.

---

## 1. Release Highlights

### Cryptography & Security Core
* **Client-Side Authenticated Encryption**: XChaCha20-Poly1305 AEAD with 192-bit extended nonces and domain-separated AAD binding vault ID, epoch, and chunk index.
* **Key Hierarchy & Sealed Box**: Vault epoch keys are wrapped to the offline recovery key via X25519 anonymous sealed boxes. Normal backups require no online master recovery secret.
* **Deterministic Canonical CBOR**: RFC 8949 compliant binary serialization ensuring byte-stable cryptographic hashing.
* **Memory Zeroization Safety**: Sensitive key representations (`RecoverySecret`, `VaultEpochKey`, `FileVersionKey`) implement `Zeroize` and `ZeroizeOnDrop`. Intermediate seeds and stack buffers are wiped immediately.
* **Path Sanitization**: Comprehensive cross-platform path validation rejects directory traversal (`..`), Windows reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), and NTFS Alternate Data Streams (`:stream`).

### Distributed Storage & Self-Repair
* **Three-Way Independent Replication**: Snapshots are replicated across 3 discrete operator daemons with full readback verification before reporting `RemoteDurable`.
* **Zero-Knowledge Self-Repair**: The `ciphervault-maintenance` engine continuously audits closure health across operators, retrieves missing chunks from healthy peers with mandatory SHA-256 digest validation, and self-heals degraded storage.
* **Automated Lease Runway**: Operators issue signed 90-day `LeaseReceipt`s. The maintenance engine automatically triggers renewal requests when remaining term drops below 30 days.

### On-Chain Anchoring & Automated Watcher
* **Arbitrum Checkpoint Anchoring**: `CipherVaultRegistry.sol` provides immutable, idempotent on-chain checkpoint publishing. Client-side salted commitments `SHA-256("CIPHERVAULT-ANCHOR-V1" || salt || head_cid)` prove inclusion without revealing vault IDs, filenames, or plaintexts.
* **Coherent File Watcher**: `ciphervault-agent` watches local tracked directories, validates pre-read/post-read file metadata to reject concurrent writes mid-capture, debounces changes (5-second window), and pushes automated snapshots.
* **Git Pre-Commit Guard**: `ciphervault hook install` configures a pre-commit hook that blocks Git commits if confidential tracked secrets are staged, preventing public repository leaks.

---

## 2. Benchmark & Performance Metrics

Benchmarked on Windows x86_64 (`cargo test --release --test throughput_benchmark`):
* **Payload Size**: 10.00 MiB across 10 discrete 1 MiB chunks with padding
* **Encryption Throughput**: **558.62 MiB/s** (17.90 ms total)
* **Decryption Throughput**: **656.84 MiB/s** (15.22 ms total)
* **Integrity Fidelity**: 100% byte-for-byte fidelity verified

---

## 3. Binaries & Checksums

| Binary | Size | SHA-256 Checksum |
|---|---|---|
| `ciphervault.exe` | 7.36 MB | `d6ba1ac41406a4c16869aaa95441abcf5897409f0e9145e04573318102ad0201` |
| `ciphervault-operator.exe` | 2.57 MB | `208ff70e9dbb2b5f8a05d0f19b3eddd849bacd6d422f1b839a64b44db7c5485f` |
| `ciphervault-agent.exe` | 6.50 MB | `f78397f98fc4618d5a7f5c3465c849138fb3bb49ea6f8ea566c7007535bf44a3` |
| `ciphervault-maintenance.exe` | 0.98 MB | `58b5c07568d5eac89cec4771d8265f997275c995dbdab0ce54d03808336abed1` |

---

## 4. Quickstart Guide

### Step 1: Launch Local Operator Cluster
```powershell
powershell -ExecutionPolicy Bypass -File dist/scripts/run-local-cluster.ps1
```

### Step 2: Initialize Vault & Offline Recovery Kit
```powershell
dist/bin/ciphervault.exe init --print-kit
```
*Prints your Emergency Paper Recovery Kit containing master secret $R$, CRC32 checksum, and operator locators.*

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

### Step 5: Install Git Pre-Commit Hook
```powershell
powershell -ExecutionPolicy Bypass -File dist/scripts/install-git-hook.ps1
```

### Step 6: Disaster Recovery on a Clean Machine
```powershell
dist/bin/ciphervault.exe recover --kit printed_emergency_recovery_kit.txt --to ./restored_vault/
```
