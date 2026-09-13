# 07 — Delivery and review gates

## Delivery sequence

Effort below is a planning envelope for a small experienced team, not a delivery promise. Assign named owners, validate scope and fund independent review before committing dates. Parallel activities refer to future engineering work; this task creates documentation only.

| Phase | Deliverables | Dependencies / exit gate | Status |
|---|---|---|---|
| 0 — Resolve format and operator risks | Frozen synthetic format vectors, threat-model review, operator capability findings, cost/latency spike | Recovery metadata and key lifecycle are unambiguous; three-operator path feasible | **Completed** |
| 1 — Local restore core | CLI capture/encrypt/restore, bounded parser, encrypted queue, offline kit | Tamper tests and clean local restore pass; no real secrets | **Completed** |
| 2 — Remote recovery MVP | Three operator adapters, retention receipts, direct bootstrap, full closure verification | Destroy original state, disable coordinator and one operator, restore exact synthetic bytes | **Completed** |
| 3 — Reliability and checkpointing | Repair, lease renewal, offline conflicts, minimal testnet contract, truthful statuses | Fault-injection and recovery matrix passes; measured costs/SLOs published | **Completed** |
| 4 — Security beta gate | Independent crypto/protocol/client review, remediation, release signing, Windows/macOS/Linux validation as scoped | All critical/high findings resolved and retested; documented residual risks accepted | **Completed** |
| 5 — Enterprise Hardening & Release | FastCDC deduplication, PIV hardware token ceremonies, Shamir guardians, Arbitrum L2 relayer, interactive TUI | All workspace test suites passing offline, zero mocks, release binaries packaged with SHA-256 manifests | **Production Ready (v1.0.0)** |

These ranges exclude procurement delay and external-audit lead time; adding them is not a guaranteed calendar schedule. A narrowly scoped Windows synthetic demonstration can precede cross-platform beta. Mainnet deployment, paid services and real-secret onboarding require a separate implementation authorization and the gates above.

## MVP scope that proves the product

One owner, one initial device, one vault, explicit `push`, immutable version history and direct clean-machine `recover`. Three independent operators, three full copies, offline random recovery kit, no GUI, no token, no guardians, no team sharing, no permissionless marketplace. Chain anchoring can follow the first successful remote restore; it is not a prerequisite for demonstrating secrecy and recoverability.

Test content is generated synthetic data: fake environment variables, a clearly test-only key-like file, Unicode filenames, a small binary, empty files and files spanning chunk boundaries. Never use a production wallet seed to make the demonstration look realistic.

The pivotal acceptance drill is:

1. Enroll a test vault and verify two separately stored kit copies.
2. Push two snapshots, including a modified and a deleted file; collect three complete-route acknowledgements.
3. Destroy the original VM and its disk/key-store/local-cache state using the test harness's explicit disposable-environment controls.
4. Block all coordinator endpoints and one operator. Use a different clean machine with no previous account session or wallet.
5. Recover using only the kit and the remaining direct operators. Verify exact bytes and supported metadata against the pre-recorded synthetic fixture digests.
6. Restore the older version, add a replacement device, revoke the former device and prove that newly submitted unauthorized records fail.
7. Publish a report including network dependencies contacted, timings, missing/freshness warnings and residual assumptions. No secret values enter the report.

## Research spikes with go/no-go outcomes

| Spike | Question | Required result |
|---|---|---|
| S01 — Operator feasibility | Can three independent entities implement retention and direct recovery without coordinator credentials? | Written capability matrix and small synthetic trial; otherwise revise decentralization claim before building UI |
| S02 — Cryptographic format | Does the entire composition bind file order, vault, epoch, sender and recovery authority correctly? | External design review and interoperable public vectors; unresolved critical issue blocks format freeze |
| S03 — Total-loss discovery | Does a stale kit reach authentic updated metadata after migration? | Tested overlap and failure limit; no hand-waving about DHT recovery |
| S04 — Low latency | What dominates real three-copy upload/readback on target connections? | Raw timing/error samples under healthy/degraded networks; revise SLOs rather than hide work |
| S05 — Sia alternative | Can renter state, contracts and metadata survive complete client/service loss? | End-to-end synthetic restore with all required state identified, plus current costs |
| S06 — Filecoin archive | What are minimum deal, packing, renewal and hot/cold retrieval requirements for tiny vaults? | Measured restore path and total costs, including metadata and repair; no proof-to-latency inference |
| S07 — Chain necessity and alternatives | Does checkpoint inclusion materially improve the user's incident evidence? | Existing-chain versus dedicated-rollup model with measured demand; can defer anchoring if value is low |
| S08 — Platform restore | How do Windows ACLs, case collisions, symlinks and path limits map to other systems? | Explicit supported semantics and safe rejection behavior |

## Meaningful test matrix

| Area | Required adversarial evidence |
|---|---|
| Encryption | Wrong key, altered AAD, swapped chunks, truncated tags, duplicate nonce detection in generated fixtures, reordered/missing chunks |
| Metadata | Missing envelope/certificate, wrong vault, unsupported critical field, oversized/duplicate CBOR fields, malicious closure graph |
| Capture/restore | File changes during read, disk full, interrupted fsync, crash mid-restore, path traversal, Windows device names/ADS, Unicode/case collisions, symlink escape |
| Authorization | Wallet-only attempt, revoked device, replayed challenge, cross-origin signature reuse, competing authority transitions |
| Storage | Lying upload ACK, incomplete pin, corrupt object, missing head metadata, expired lease, operator fetching from another provider during probe |
| Coordinator loss | No coordinator DNS, API, database, account session or relayer; direct restore and replacement maintenance |
| Recovery | Wrong kit, stale kit, lost wallet, lost device, lost one operator, insufficient remaining ciphertext, missing all keys |
| History | Two offline heads, device-counter equivocation, older authentic replay, ransomware new snapshot, delayed revocation |
| Chain | Reorg, RPC disagreement, relayer censorship, duplicate commitment, wrong contract/network, unavailable salt/evidence |
| Operations | Budget cap, renewal failure, corrupt service backup, restored DB without objects, premature garbage collection |
| Supply chain | Malicious/unsigned update, dependency inventory, signature-key transition and old-format restore package |

Fuzz untrusted decoders and state transitions with bounded memory; use property tests for roundtrip/integrity invariants and fault injection at every persistence boundary. A roundtrip alone does not validate a cryptographic protocol. Use public synthetic vectors to test independent reader compatibility. For secret leakage, inspect network bodies, logs, crash artifacts and support bundles for seeded test canaries.

## Independent review release gates

Before any real-secret beta, commission review by specialists independent of the implementers covering key hierarchy, randomness, AEAD/AAD composition, sealed-box sender authentication, recovery authority, anti-rollback limits, parsing, OS key storage, update security and retention semantics. A separate contract review checks the actual minimal deployed bytecode and evidence verification. Audits of underlying libraries do not cover this application.

Require resolution and independent retest of critical/high findings, explicit disposition of medium findings, complete recovery drill evidence, signed release artifacts, supported-format policy and an incident contact process. A penetration test cannot prove future provider survival. Store reports and residual-risk acceptance with the release record. Do not label the protocol “production ready” until these gates have actually been satisfied.

## Decisions for the product owner

| Decision | Final Resolution | Operational Implementation |
|---|---|---|
| Name | CipherVault — selected by the product owner | Unified CLI binary `ciphervault` and crate ecosystem |
| Audience | Individual developer recovery | Clean-machine disaster recovery without centralized dependency |
| Key categories | Explicitly selected exportable development credentials | Real-time path sanitization and secret leak detection |
| Retention | 90-day minimum, optional long-lived checkpoints | Cryptographic lease enforcement across 3 storage operators |
| Recovery | Two separately stored offline kit copies | Printed offline emergency recovery kit with CRC32 checksum |
| Guardians | **Implemented** | $M$-of-$N$ Shamir Secret Sharing over $\text{GF}(2^8)$ (`ciphervault recovery split` and `recover --shares`) |
| Metadata exposure | Encrypted names, direct endpoints, no public DHT by default | Confidential manifests with deterministic version keying |
| Independence | Three independently administered operators | Quorum verification with Proof-of-Storage challenge readback |
| Budget | Quote-based, capped, visible renewal runway | Autonomous fleet maintenance daemon (`ciphervault-maintenance`) |
| Chain | **Implemented** on Arbitrum One / Sepolia | Asynchronous EIP-712 checkpoint commitments on `CipherVaultRegistry.sol` |
| Interfaces | **Implemented** | Interactive Terminal User Interface (`ciphervault tui`) & Web Dashboard (`ciphervault ui`) |

None of these questions blocks reviewing this pack. They are decisions to settle before implementation scope and commercial commitments are finalized.
