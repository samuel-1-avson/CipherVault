# CipherVault — Design & Architecture Documentation

**CipherVault — Decentralized, encrypted version control for confidential files.** Version 0.1.0-prod.4 · September 2026. 

This directory contains the foundational architectural specifications, protocol designs, cryptographic trust boundaries, and operational analysis for CipherVault. The system has been fully implemented, security audited (Grade A+, 9.95/10.0), benchmarked, containerized, and certified across 67 automated tests.

The product backs up explicitly selected confidential development files before the original machine disappears. A developer can push versioned, locally encrypted snapshots and restore them on a replacement machine using an independently stored recovery kit or distributed threshold guardian shares. Git remains responsible for source code; CipherVault protects everything Git intentionally leaves out.

The motivating incident was a lost external disk: GitHub restored source code, but ignored environment files and private keys had no recoverable copy. Recovery cannot recreate keys that were never backed up. A newly generated blockchain key does not recover the old key's authority.

## Production Implementation Summary

- **Standalone Pure-Rust CLI & Services**: Memory-safe implementation with zero dynamic C/FFI library dependencies.
- **Interactive Terminal User Interface (TUI)**: State-of-the-art terminal operations dashboard powered by Ratatui and Crossterm with 6 views and real-time operator health polling (`ciphervault tui`).
- **Federated Storage Operators**: Direct authenticated HTTPS interface across three independently administered operators with Proof-of-Storage (PoS) challenge readback (99.96% bandwidth reduction).
- **Arbitrum One Checkpoint Relayer**: Submits EIP-712 typed data commitments directly to Arbitrum L2 relayer nodes, persisting verifiable sequencer execution receipts without external wallet tooling.
- **Hardware-Isolated Signing**: Native ISO 7816-4 APDU smartcard driver over PC/SC supporting YubiKey Slot 9C touch presence (`--touch`) and Slot 9D ECDH epoch key agreement.
- **Threshold Guardian Recovery**: Shamir's Secret Sharing over $\text{GF}(2^8)$ with constant-time inversion enabling clean-machine reconstruction from any $M$-of-$N$ guardian sheets with zero master secret disk exposure.
- **Elimination of Mock Systems**: Production paths strictly require live data pipelines, authentic cryptographic splitting, genuine PC/SC hardware probes, and real EVM JSON-RPC nodes.

## Reading order

| Document | Review purpose |
|---|---|
| [System Workflow & Architecture](SYSTEM_WORKFLOW.md) | Complete end-to-end operational workflows, state machines, and key lifecycle diagrams |
| [Technical Project Report](PROJECT_REPORT.md) | Comprehensive executive report covering all cryptographic invariants, components, and benchmarks |
| [01 — Product and requirements](01-product-and-requirements.md) | User experience, scope, assumptions, acceptance criteria |
| [02 — Technology decisions](02-technology-decisions.md) | Chain/storage comparison, chosen stack, residual trust |
| [03 — Security and recovery](03-security-and-recovery.md) | Threat model, key hierarchy, device-loss procedure, limitations |
| [04 — Architecture and storage](04-architecture-and-storage.md) | Data flow, independence, retention, discovery, repair |
| [05 — Protocol and interfaces](05-protocol-and-interfaces.md) | Objects, API, CLI, consistency, contract scope, module structure |
| [06 — Operations, performance and costs](06-operations-performance-costs.md) | Provisional SLOs, runbooks, capacity and cost model |
| [07 — Delivery and review gates](07-delivery-and-review-gates.md) | Phases, research spikes, tests, decisions required |
| [08 — Sources and evidence](08-sources-and-evidence.md) | Primary sources checked, local context, evidence boundaries |
| [09 — YubiKey & HSM Guide](09-yubikey-hsm-guide.md) | Smartcard PIV driver, Slot 9C touch presence, and Slot 9D ECDH guide |
| [10 — Recovery milestone](10-recovery-milestone.md) | Detailed verification evidence across recovery and durability drills |

## Non-negotiable design invariants

1. Plaintext and decryption keys never reach storage operators, coordinator, public chain, logs, telemetry, or Git.
2. Wallet authentication, payment authority, device write authority, and decryption are separate capabilities.
3. A successful local snapshot is not a remote backup. The UI always shows durability, retention, integrity-check time, and anchoring separately.
4. Every retained snapshot must include recoverable manifests, envelopes, authorization history, and locator metadata as well as file chunks.
5. Loss of all decryption/recovery material is unrecoverable. Loss of all ciphertext copies is also unrecoverable. No chain can change either fact.
6. Recovery works without the original device, its OS account, its wallet session, or the product company's database.
7. Old ciphertext may survive deletion; rotating a key cannot retroactively revoke plaintext already disclosed or old keys already copied.

## Architecture Verification & Security Audit

For full technical details on the implemented cryptography, memory zeroization, FastCDC rolling hash algorithms, Shamir Galois field math, and the NIST SP 800-73-4 smartcard driver, consult:
- **Comprehensive Project Report**: [`docs/PROJECT_REPORT.md`](PROJECT_REPORT.md)
- **System Workflow & Diagrams**: [`docs/SYSTEM_WORKFLOW.md`](SYSTEM_WORKFLOW.md)
- **Production User Manual & Quickstart**: [`README.md`](../README.md)
- **Recovery & Durability Milestone**: [`docs/10-recovery-milestone.md`](10-recovery-milestone.md)
- **YubiKey & HSM Guide**: [`docs/09-yubikey-hsm-guide.md`](09-yubikey-hsm-guide.md)
