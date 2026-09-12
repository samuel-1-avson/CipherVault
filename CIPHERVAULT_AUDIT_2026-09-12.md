# CipherVault — evidence-based architecture, security and quality audit

**Review date:** 12 September 2026  
**Verdict:** Functional MVP with experimental extensions; not production-ready for confidential backups.  
**Overall current quality:** **4.1/10**.  
**Scope:** Local working tree based on commit `e7612791ded26125ecd742f57814446c00d3f8d3`, including existing modified and untracked source files. This is not a certification of that commit or the bundled release executables.

## Executive summary

CipherVault implements a meaningful encrypted backup core. It has client-side encryption, signed recovery records, a recovery trust root derived from an offline secret, multi-operator object verification, local history, and executable failure/recovery drills. Freshly compiled code passed **68 Rust tests**, strict Clippy, formatting, and the JavaScript regression script in this review. This is substantially more than a UI mockup.

Its advertised readiness exceeds its implementation. The highest concerns are predictable non-Windows storage encryption keys, incomplete operator authorization, simulated blockchain confirmation presented as real, incomplete hardware-token integration, and a maintenance daemon that can report healthy backups without checking their ciphertext. Local persistence and watcher retry behavior also fall short of a dependable backup system.

The dashboard has concrete frontend/backend contract mismatches. Its guardian split endpoint creates shares of a new random demonstration secret, not the active vault's recovery secret. FastCDC exists, but fresh encryption keys and file-version identifiers prevent its plaintext boundary reuse from delivering the claimed encrypted-storage deduplication.

**Release recommendation:** Continue development and controlled trials with synthetic or independently backed-up data. Do not make this the sole recovery mechanism for real secrets. A limited Windows-first release could eventually exclude experimental hardware and automatic anchoring, but the authorization, persistence, recovery, and status-truthfulness issues still need resolution.

The earlier audit file and README's A+/9.95, certification, and benchmark badges were treated as project claims, not independent evidence. The existing audit was preserved; this report is separate.

## 1. Scope, method and limitations

Reviewed the ten-member Rust workspace, CLI and watcher, six library crates, operator and maintenance services, static dashboard and regression script, Solidity registry and test sources, Cargo manifests/lockfile, README and documentation pack, CI/release workflows, Docker/Compose, Caddy, and service configuration. Review depth concentrated on secret handling, trust boundaries, persistence, recovery, advertised integrations, and deployed execution paths. This was targeted source review, not exhaustive line-by-line formal verification.

Methods included source tracing, comparison of requirements to executable behavior, fresh compilation and existing checks, vendor documentation verification for PIV metadata, and a temporary Rust probe linked against the reviewed libraries. No project source, tests, configuration, dependencies, or prior report were edited. Build artifacts, logs and the probe were placed in the Windows temporary directory; this Markdown report is the review deliverable.

Evidence labels used below:

- **Executed:** Observed through a command, test or temporary probe during this review.
- **Source-verified:** The code directly establishes the behavior. This does not claim a full user journey was exercised.
- **Risk/inference:** A plausible impact or failure scenario derived from the implementation, with its conditions stated.
- **Not assessed:** Insufficient runtime or external evidence.

Limitations: no Docker or Foundry executable was available; no real smartcard signing ceremony, Linux/macOS runtime, deployed blockchain contract, live production operators, public penetration test, independent infrastructure inventory, browser visual/keyboard/screen-reader session, sustained load test, or formal cryptographic review was performed. `cargo-audit` was unavailable, so current transitive vulnerability status is **Not assessed**, not “clean.” Existing dependency versions alone are not evidence of exploitable vulnerabilities. No changes or deployment to external services were performed.

File references below are repository paths and one-based line numbers at review time. Subsequent edits may move them.

## 2. Project purpose and architecture

The useful product contract in [docs/01-product-and-requirements.md](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/docs/01-product-and-requirements.md) is backup and clean-machine recovery for explicitly selected confidential developer files. It is not a runtime secrets manager or a replacement for Git.

| Component | Implemented responsibility | Assessment |
|---|---|---|
| `crates/crypto` | XChaCha20-Poly1305 encryption, Ed25519 signatures, X25519 envelopes, key derivation, recovery sharing, PIV transport | Reasonable standard primitives; custom integration and secret lifecycle need further work. |
| `crates/format` | CBOR structures, signatures, object digests, recovery inventories and checkpoint evidence | Centralizing protocol types is useful; the strict canonical profile described in docs is not enforced by the generic serializer/deserializer. |
| `crates/snapshot` | File capture, FastCDC slicing, encryption, manifest generation and restoration | Real implementation with tamper and path defenses; whole-file buffering and restore semantics constrain scale and safety. |
| `crates/local-store` | SQLite metadata, protected keys, snapshots, chunks, heads and recovery sets | Useful persisted recovery inventory; multi-step operations lack enclosing transactions and durable retry state. |
| `crates/recovery` | Offline kits, threshold kits and independent certificate/head/envelope verification | Strongest architectural boundary: operator data cannot nominate a new recovery trust root. |
| `crates/storage` | HTTP operator access, digest verification, replication quorum and RPC helpers | Validates fetched bytes and signed receipts. Work is mostly sequential; operator identity is learned from the endpoint. |
| `services/operator` | Ciphertext files, append logs, signed leases, sessions, PoS and relayer endpoint | Has durable-write safeguards, but authorization is not consistently vault-scoped and resource budgets are missing. |
| `services/maintenance` | Repair/audit library plus a separate fleet daemon | The daemon does not use the full recovery-set audit/repair workflow. |
| `apps/agent` | Polling, hashing, debounce, snapshot capture and optional replication | Shares snapshot machinery, but duplicates orchestration and does not retry a failed sync without another detected change. |
| `apps/cli` and `apps/ui` | Commands plus an embedded HTTP API and dashboard | Easy distribution, but roughly 2,900 lines of CLI/API orchestration and independently shaped JS models produce integration drift. |
| [contracts/CipherVaultRegistry.sol](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/contracts/CipherVaultRegistry.sol) | Minimal idempotent public commitment registry | Appropriately small and non-custodial; deployed operation is unverified and the local relayer does not submit transactions. |

### Key workflows

**Initialize:** Generate a recovery secret, derive authority keys and locator, issue genesis and a device certificate, store a device key and epoch key, and print/export the kit. Windows protection calls DPAPI. Non-Windows protection uses the weak derivation described in F01.

**Push:** Read tracked files, produce encrypted chunks and manifest, sign a snapshot, store local state, build a complete recovery set, sign a head, then upload to operators. The pool checks leases, challenges object possession (or downloads as fallback), publishes bootstrap records before the head, and verifies discovery readback. Success requires three distinct operator public keys. See [apps/cli/src/main.rs:705](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/main.rs:705) and [crates/storage/src/pool.rs:57](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/storage/src/pool.rs:57).

**Recover:** Parse the offline kit or shares, derive the trust root, collect operator records, select a certified head, verify its snapshot, unwrap its epoch key, fetch digest-checked objects, decrypt, verify plaintext integrity, and publish restored files. See [apps/cli/src/main.rs:1002](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/main.rs:1002) and [crates/recovery/src/trust.rs:8](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/recovery/src/trust.rs:8). Existing clean-machine-style tests remove the original client state, but run on the same host; this is not a separate-OS drill.

**Maintain:** The library can inspect recovery sets and repair objects. The installed daemon instead polls `/v1/info` and counts nonempty recovery logs. This architectural split is a material reliability gap, not just a naming concern.

The crate boundaries fit the core goal. The main unnecessary complexity is the number of partially integrated extensions around a still-incomplete durable backup lifecycle. Three public keys are also not proof of independent administration or failure domains: the supplied three-node Compose cluster shares one host.

## 3. Findings table

Severity reflects practical consequences for confidential backup use. “Critical” means the intended protection can be fundamentally defeated under a realistic stated condition; “High” means a release-blocking security, recovery, or false-assurance problem; “Medium” means material limitations that need a bounded release policy or correction.

| ID | Severity | Finding and practical impact | Evidence |
|---|---|---|---|
| F01 | Critical on non-Windows | Local key protection uses SHA-256 of a fixed label plus `USER` and `HOME`. Someone with a copied DB and these guessable values can reconstruct the wrapping key and decrypt stored epoch/device keys. This is not an OS credential store or machine authentication. | Source-verified: [crates/local-store/src/keyring.rs:132](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/local-store/src/keyring.rs:132); encryption inputs contain no secret. Non-Windows execution not performed. |
| F02 | High | An authenticated but uncertified caller can append a self-signed head/envelope/snapshot to an existing vault log because verification against `caller_pk` is sufficient. Log pollution and resource abuse are possible. Recovery's separate certificate checks prevent interpreting this alone as a decryption or full recovery-authentication bypass. | Executed probe accepted an attacker-signed head after owner genesis registration. [services/operator/src/state.rs:334](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/operator/src/state.rs:334), especially caller-key branches after line 414; HTTP passes session key in `handlers.rs:207` onward. |
| F03 | High | Automatic relaying fabricates a transaction hash and block number locally, labels them `SequencerConfirmed`, and keeps them only in a HashMap. Users can believe an external immutable checkpoint exists when it does not. | Source-verified: [services/operator/src/state.rs:578](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/operator/src/state.rs:578); [apps/cli/src/main.rs:1354](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/main.rs:1354). Chain integration tests pass against this local behavior. |
| F04 | High | Physical-token integration is inconsistent: metadata TLV tags are wrong, initialization stores an unrelated software signing key while certifying the token public key, snapshots still use the software key, and `--touch` signs a digest where normal head verification expects unsigned CBOR bytes. | Source/vendor-verified: [crates/crypto/src/piv.rs:544](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/crypto/src/piv.rs:544), [apps/cli/src/main.rs:469](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/main.rs:469), `:705`, `:782`, [crates/format/src/schema.rs:320](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/format/src/schema.rs:320). No physical ceremony executed. |
| F05 | High | Fleet daemon health means nonempty recovery logs, not complete verified ciphertext. Zero configured clients also satisfy its healthy condition. It invokes neither object repair nor lease renewal, despite deployment documentation claiming autonomous repair. | Source-verified: [services/maintenance/src/main.rs:162](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/maintenance/src/main.rs:162) onward; contrast [services/maintenance/src/engine.rs:58](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/maintenance/src/engine.rs:58), `:301`, `:446` and [deploy/README.md](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/deploy/README.md). |
| F06 | High | Snapshot rows, chunks, recovery sets, counters and active heads are separate SQLite writes. `set_head` clears the previous head before inserting the new one without a transaction. Crash/concurrency can leave incomplete snapshots or inconsistent state. | Source-verified: [crates/local-store/src/db.rs:325](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/local-store/src/db.rs:325), `:391`, `:641`; crash/concurrent-writer impacts are inference, not reproduced here. |
| F07 | High | Watcher clears pending-change state before capture/sync. Failed upload or transient capture failure is only logged; unchanged files do not trigger another attempt. A locally saved snapshot can remain remotely unprotected indefinitely. | Source-verified: [apps/agent/src/watcher.rs:78](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/agent/src/watcher.rs:78), `:216` onward; no reconnect-without-edits test observed. |
| F08 | High | Recovery-secret exposure claims are inaccurate. Kits hold secret hex in ordinary `String` fields with derived `Debug`, no Drop wiping; printed/read strings also remain ordinary allocations. Docker initialization saves a plaintext kit and guardian shares beside the vault and prints the kit into container logs. | Source-verified: [crates/recovery/src/kit.rs:11](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/recovery/src/kit.rs:11), [apps/cli/src/main.rs:546](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/main.rs:546), `:1002`, [deploy/docker/entrypoint-dashboard.sh:12](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/deploy/docker/entrypoint-dashboard.sh:12). Explicit CLI export is legitimate, but unattended packaging contradicts “zero-disk” guarantees. |
| F09 | High when exposed | Dashboard binds a caller-specified address and exposes state-changing APIs without authentication or a Host/Origin boundary. Any reachable client can request pushes/anchors and read metadata. Root Compose binds its host port to loopback, which reduces exposure; `--host 0.0.0.0` and internal container access do not. | Source-verified: [apps/cli/src/main.rs:1996](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/main.rs:1996), [docker-compose.yml](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/docker-compose.yml), dashboard entrypoint. Remote-access scenario inferred; DNS rebinding exploit not tested. |
| F10 | High for public operators | Any self-generated signing key can obtain a write session. No admission/quota policy or expiry cleanup bounds challenges, sessions, log growth or aggregate object storage. Anonymous relayer requests also grow memory. | Source-verified: [services/operator/src/state.rs:53](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/operator/src/state.rs:53), `:69`, `:144`, [services/operator/src/lib.rs:18](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/operator/src/lib.rs:18). Individual object limits exist; aggregate exhaustion was not load-tested. |
| F11 | High for guardian workflow | Guardian split uses a random drill secret despite active-vault wording. UI expects `status: 'ok'`, backend returns `success`; reconstruction expects `verified_signing_pk_matches`, backend returns `matches_vault`. Fleet UI expects `fleet_summary`, backend returns `summary`. | Source-verified: [apps/cli/src/main.rs:2349](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/main.rs:2349), `:2418`, `:2532`; [apps/ui/app.js:1188](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/ui/app.js:1188), `:1265`, `:700`. Stubbed rendering tests do not exercise these contracts. |
| F12 | Medium | FastCDC does not yield cross-snapshot encrypted chunk reuse: each capture creates a fresh file key, version ID and AEAD nonce. Repeated unchanged files consume new storage/upload work. README's 96.15% figure concerns boundaries, not actual backup deduplication. | Executed probe: identical plaintext produced unequal chunk CIDs. [crates/snapshot/src/chunker.rs:28](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/snapshot/src/chunker.rs:28), [crates/snapshot/src/engine.rs:82](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/snapshot/src/engine.rs:82); pool uploads every object. |
| F13 | High for secret restoration | Restored plaintext is created with inherited/default permissions, without explicit owner-only protection. Files are published one at a time, tombstones are skipped, and no overwrite consent is enforced by the restore engine. A later failure can leave an incomplete destination; restoring into an existing tree can leave deleted files behind. | Source-verified: [crates/snapshot/src/engine.rs:232](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/snapshot/src/engine.rs:232), `:255`, `:350`; effective Unix mode and ACL behavior not runtime-tested. Symlink checks exist, but check/use races are not eliminated. |
| F14 | Medium | Capture reads an entire file before applying its 256 MiB limit, copies buffers, retains all encrypted chunks, and restore scans/re-hashes the entire chunk list for each expected CID. Large vaults risk high memory, quadratic restore work and slow serial uploads. | Source-verified: [crates/snapshot/src/engine.rs:72](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/snapshot/src/engine.rs:72), `:271`; `chunker.rs:34`; [crates/storage/src/pool.rs:87](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/storage/src/pool.rs:87). No production-scale benchmark performed. |
| F15 | Medium | Production maintenance volume ownership is not prepared by its image for `/var/lib/ciphervault`; the systemd maintenance service defaults to writing `maintenance.db` in `/etc/ciphervault` under `ProtectSystem=strict`. Configuration suggests startup/write failures. | Configuration-verified risk: [deploy/docker/Dockerfile.maintenance](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/deploy/docker/Dockerfile.maintenance), [deploy/docker-compose.prod.yml](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/deploy/docker-compose.prod.yml), [deploy/systemd/ciphervault-maintenance.service](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/deploy/systemd/ciphervault-maintenance.service). Docker/systemd execution unavailable. |
| F16 | Medium | Release publishing has no dependency on successful quality/security gates; binaries and containers are built with floating toolchains/images and without `--locked`. No release signing/attestation or vulnerability gate was found in the reviewed workflows. | Source-verified: [.github/workflows/release.yml](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/.github/workflows/release.yml), [.github/workflows/ci.yml](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/.github/workflows/ci.yml), `deploy/docker/Dockerfile.*`. Hosted CI and published artifacts not inspected. |
| F17 | Medium | Strict canonical decoding, complete schema bounds and safe handling of corrupted lengths are incomplete. Generic CBOR helpers check byte size but do not enforce the documented canonical profile; several decoded/database vectors use unchecked `copy_from_slice`. | Source-verified: [crates/format/src/canonical.rs:10](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/format/src/canonical.rs:10), `:26`; [crates/snapshot/src/engine.rs:267](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/snapshot/src/engine.rs:267); [crates/local-store/src/db.rs:140](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/local-store/src/db.rs:140). Malicious/corrupt input panic and allocation scenarios need fuzzing. |
| F18 | High for release confidence | Documentation presents experimental or absent behavior as certified: A+ score, automatic L2 confirmation, cross-platform PIV, deduplication, zero-disk/zeroized secrets, and autonomous repair. It also advertises `untrack`, absent from the command enum. | Source-verified comparison: [README.md](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/README.md), [docs/10-recovery-milestone.md](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/docs/10-recovery-milestone.md), [apps/cli/src/main.rs](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/cli/src/main.rs). Current suite has 68 tests, not the README's 67. |

### Important security distinctions

**Hardware details:** Yubico documents metadata tag `02` as PIN/touch policy, `03` as origin, and `04` as public key. The implementation interprets `02` as key bytes and `03` as touch policy. Fixing this parser alone would not resolve the key/certificate and signed-message inconsistencies. Non-Windows reader enumeration returns an empty vector and transport returns an inactive error. A successful signature also does not prove physical touch unless the actual token policy is verified. [Yubico PIV metadata specification](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/metadata.html).

**Authorization:** Random challenges, domain-separated signatures and token expiry checks are implemented. They prove possession of a key; they do not establish permission to mutate a particular vault. The probe used the same caller-key argument supplied by the HTTP route, but did not perform an external-network exploit. Genesis registration also needs an authenticated locator-ownership design and serialization of authorization with append to avoid first-write/race ambiguities.

**Confidentiality:** Anonymous retrieval of ciphertext by known CID is an intentional recovery feature, not by itself plaintext disclosure. However, local SQLite tracked paths are plaintext metadata (`tracked_files`), and ciphertext headers expose some structure. “Zero knowledge” should name its exact leakage and threat model. Windows DPAPI passed outside the sandbox; it does not protect secrets from code already running as the same user.

**Retention and freshness:** Signed lease receipts do not independently guarantee future storage, payment or infrastructure independence. The push path verifies immediate possession; its receipts are not persisted as a complete ongoing retention ledger. Recovery selects the highest available authenticated head and does not establish that operators disclosed the latest head. It also offers no clean-machine historical selection in `cmd_recover`. Treat freshness and historical recovery UX as incomplete, not proven rollback resistance. RPC verification helpers exist separately, but recovery does not consume them.

**Finality:** [crates/storage/src/chain.rs:228](C:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/storage/src/chain.rs:228) assigns named finality stages from L2 block-count thresholds. No observation of parent-chain data finality or assertion settlement appears in that function. Those labels need evidence-specific semantics, even after real transaction submission is implemented.

**Cryptographic assurance:** The standard primitives are a strength. The custom Shamir arithmetic and PIV driver require independent review and external vectors. `gf_mul` contains input-dependent branches; source inspection alone does not establish or refute compiled constant-time execution. Do not certify constant-time behavior from the fixed inversion schedule or unit tests.

## 4. Implementation, reliability and product quality

### What is well built

- Recovery independently derives the authority key from the offline secret, checks signed certificates, snapshot/head linkage and recipient-bound envelopes. Existing negative tests reject self-authorization and tampering.
- `OperatorClient::get_object` verifies the requested digest before returning bytes, allowing the pool to try another operator on corruption.
- The replication pool verifies signed lease fields and counts distinct operator public keys, rather than equating successful HTTP upload with protection.
- Operator object/lease publication uses synced temporary files and atomic rename. Recovery-log appends have a lock and rollback-on-write-error logic. These are meaningful local durability measures.
- Restore rejects numerous traversal and Windows-special paths, verifies file integrity and uses unpredictable staging names. These are useful defenses despite F13's remaining issues.
- Non-root containers, persistent operator identities, restart policies, TLS ingress templates and cross-platform CI definitions provide a useful starting point.

### Completeness and maintainability

The backup core is coherent, but behavior is duplicated among CLI push, watcher sync, maintenance library, daemon and API. Their different definitions of success are now observable product defects. A shared application service for capture/persist/replicate/audit would remove more risk than another dashboard panel.

Local snapshot storage duplicates record and manifest rows under both logical snapshot ID and record CID. There is no schema-version migration framework in `LocalVaultStore::init_tables`; `CREATE TABLE IF NOT EXISTS` is not an upgrade strategy. Local-vault WAL mode is claimed in the README but not enabled in that store; the separate fleet DB does enable WAL. WAL alone would not fix F06's missing transactions.

Snapshot messages are printed by CLI push rather than retained as encrypted history metadata. `--pos` is accepted but discarded in dispatch; the pool uses PoS regardless. The parser silently accepts/defaults some configuration failures (for example the agent's manual line-based TOML-like reader). These are smaller examples of interfaces and documentation drifting from implementation.

### User journeys and value

The explicit file selection and familiar push/history/restore model solve a credible problem: secrets omitted from Git need independent backups. CLI clean-machine recovery works in the synthetic scenarios exercised by the suite. A small product focused on this journey has clear value without a blockchain or hardware-token extension.

The dashboard renders operator, snapshot, recovery and fleet information, escapes many strings, includes labels, dialog roles and an `aria-live` toast container, and clears stale durability state in its existing regression. These are positive source observations. The guardian and fleet payload mismatches undermine actual usability; passing render tests with hand-shaped data is insufficient.

Onboarding does not verify that the user recorded the recovery kit: any line/Enter satisfies its prompt and noninteractive input skips it. The container makes the independent/offline recovery problem worse by co-locating kit, shares and vault. This can leave a user with an attractive dashboard but no independent recovery material after host loss.

Visual quality, responsive layout, keyboard focus trapping, tab semantics, contrast, screen-reader behavior and user comprehension are **Not assessed through runtime interaction**. Static ARIA attributes do not establish accessibility compliance. No customer interviews or market research were conducted; product potential is qualitative, not part of the numeric score.

## 5. Checks performed and operational readiness

Environment: Windows, PowerShell, Rust/Cargo 1.98.1, Node v24.20.0. Fresh debug artifacts used `CARGO_TARGET_DIR=%TEMP%/ciphervault-audit-target`; dependencies were resolved from the existing cache with `--locked --offline`.

| Check | Result | What it establishes / does not establish |
|---|---|---|
| `cargo test --workspace --locked --offline --no-fail-fast` outside sandbox | **PASS: 68 passed, 0 failed, exit 0** | Executes existing unit/integration suites, including E2E, chaos federation, pivotal recovery, maintenance library, watcher, crypto and boundary tests. Does not prove every advertised feature or true infrastructure independence. |
| Initial sandboxed full test attempt | **58 passed, 10 failed across 7 targets** | DPAPI-related failures disappeared in the outside-sandbox run. They are not counted as confirmed project defects. Initial default-target attempt also hit a build-lock permission error, resolved by temporary target directory. |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | **PASS, exit 0** | Static lint cleanliness; does not validate business/security invariants. |
| `cargo fmt --all -- --check` | **PASS, exit 0** | Formatting only. |
| `node --check apps/ui/app.js` | **PASS, exit 0** | JavaScript syntax only. |
| `node apps/ui/audit.test.cjs` | **PASS, exit 0** | VM/stubbed-DOM regression checks. No actual browser or HTTP frontend/backend integration. |
| Temporary linked-library probe | **Confirmed F02 and F12** | Printed `Uncertified caller head accepted into existing owner log: true` and `Identical plaintext chunk CID reused: false`. Used synthetic data and temporary storage. |
| Docker build/Compose, systemd | **Not assessed at runtime** | Executables/runtime unavailable; configuration inspected. No live volume deletion drill performed. |
| Foundry Solidity tests | **Not assessed at runtime** | `forge` unavailable. Contract and test source reviewed. |
| Real hardware-token signing/recovery | **Not assessed** | Tests include APDU construction and software fallback; passing these is not proof of physical-token compatibility. |
| Live Arbitrum deployment/settlement | **Not assessed** | Local relayer tests do not submit a transaction. |
| Dependency vulnerability audit | **Not assessed** | `cargo audit --version` reported no such command. No full lockfile-to-advisory comparison performed. |
| Real load, cost, retention endurance, cross-platform recovery | **Not assessed** | Existing throughput tests are not representative end-to-end capacity or recovery-time evidence. |

The executed suite includes 21 CLI integration tests, 22 crypto tests, 1 format test, 5 local-store tests, 1 maintenance-library test, 5 operator tests, 5 recovery tests, 5 snapshot tests and 3 storage tests. There were no ignored tests in that run. Test count is not line/branch coverage; no coverage percentage was measured.

The project needs tests of actual daemon behavior and real UI payloads. The relayer test currently affirms the local simulated response. Operator authorization tests call the helper without the authenticated caller argument used by HTTP, leaving F02 uncovered. The temporary probe demonstrated why that distinction matters.

Logging is primarily console output; no end-to-end alert delivery, metrics backend, audit-log retention policy, or tested operator-volume backup/restore procedure was established. Health endpoints measure reachability, not guaranteed backup integrity. Recovery drills are valuable, but operator key-loss, full-host loss, disk-full during local commit, long disconnection, poisoned logs, corrupted DB rows and multi-process writer races need explicit coverage.

Release builds should use the locked dependency graph and supported pinned build inputs, and publish only after required gates. Add a maintained dependency advisory check using the [RustSec advisory database](https://rustsec.org/) and artifact provenance; this recommendation is not a claim that the current lockfile contains a known vulnerability.

## 6. Transparent ratings

Scoring scale: **0–2** absent or materially misleading/unsafe; **3–4** significant implemented work with serious gaps; **5–6** useful MVP with meaningful evidence but incomplete safeguards; **7–8** release-capable with measured operational evidence and minor gaps; **9–10** mature, independently validated operation with exceptional evidence. Scores are engineering judgment, not a security certification or statistical probability.

| Area | Score / 10 | Weight | Evidence-based rationale |
|---|---:|---:|---|
| Architecture | 6 | 15% | Good trust-root and crate separation; divergent orchestration and unfinished extensions weaken consistency. |
| Implementation and completeness | 4 | 20% | Working core and recovery inventory; broken hardware/guardian contracts, missing retries, simulated relay and duplicated persistence. |
| Security | 3 | 20% | Standard primitives and independent recovery verification; predictable non-Windows key protection, operator authorization gaps and secret-handling issues block real use. |
| Reliability and performance design | 4 | 15% | Operator atomic writes and digest verification help; local transactions, retry, truthful fleet audits and bounded scale are incomplete. |
| Testing and QA | 6 | 10% | 68 tests and strict checks pass; meaningful failure drills, but important deployed paths and platform claims are not tested. |
| Operational/release readiness | 3 | 10% | Deployment templates and CI exist; daemon behavior, permissions, observability, independent recovery and release gating need work. |
| UX and delivery of product value | 4 | 5% | Useful core CLI journeys; dashboard contract errors and recovery ceremony ambiguity. Visual/accessibility runtime quality is excluded. |
| Documentation accuracy | 2 | 5% | Thoughtful original requirements, but current claims of certification and completed integrations materially contradict code. |
| **Overall** | **4.1** | **100%** | Weighted arithmetic mean shown below. |

Calculation: `6×0.15 + 4×0.20 + 3×0.20 + 4×0.15 + 6×0.10 + 3×0.10 + 4×0.05 + 2×0.05 = 4.10`.

Physical interoperability, deployed-chain operation, current dependency vulnerability status, real-world SLOs, browser accessibility and customer desirability are **Not assessed** and receive no standalone numeric score. Gaps in the project's validation are reflected in QA/readiness, rather than treating unknown external outcomes as demonstrated failures. The weighted score does not override release-blocking findings.

**Potential:** Promising as a focused encrypted backup tool. Potential is separate from current implementation quality; no speculative future score is assigned.

## 7. Actionable roadmap

Effort estimates are approximate **engineer-days**, excluding procurement, independent audit turnaround and sustained observation time. They assume familiarity with Rust and the relevant subsystem. They overlap and should not be summed into a delivery promise. Each item references findings with supporting source locations above.

### Immediate priorities — essential before real-secret or public release

| Priority | Issue / impact | Recommended action | Effort, dependencies and trade-offs | Acceptance criteria |
|---|---|---|---|---|
| P0.1 | F01: copied DB can expose keys on non-Windows | Replace environment-derived wrapping with a real OS secret store or a secret-derived encrypted keystore; fail closed when unavailable. Provide an explicit migration/re-key plan. | 4–8 days plus platform validation. Depends on supported-platform policy; headless deployments need a separately provisioned secret rather than silent fallback. | A copied DB plus username/home cannot be decrypted on a clean host; unavailable credential service fails safely; migration and Windows/Linux/macOS behavior are tested for supported targets. |
| P0.2 | F02/F10: unscoped mutation and resource exhaustion | Bind sessions and all mutations to enrolled vault authority and rights; remove caller-key authorization shortcuts; authenticate genesis enrollment; add quotas, TTL eviction and rate limits. | 5–10 days. Requires capability/enrollment design. Preserve intentional anonymous ciphertext recovery without granting writes. | HTTP tests show two unrelated users cannot append to each other's locator or alter leases; forged heads/envelopes rejected; expired entries evicted; bounded load/disk budgets hold. |
| P0.3 | F03/F04/F18: false security assurances | Remove production claims and feature-gate automatic relaying/hardware binding until they work. Mark simulation explicitly in API and UI. Replace audit badges with dated, reproducible evidence. | 1–3 days for containment. Full implementations are separate, optional scope. Removing an unfinished feature is cheaper and safer than delaying the backup core. | No simulated receipt is called confirmed; unsupported platforms/features fail clearly; CLI examples execute as written; docs distinguish shipped, experimental and planned behavior. |
| P0.4 | F08/F09/F13: avoidable secret exposure | Stop unattended kit/share persistence and secret-bearing container logs; use secret-safe types/redacted Debug and wipe temporary buffers; protect exports/restores with owner-only access; add local dashboard token and Host/Origin validation or prohibit remote bind. | 4–8 days. Requires explicit offline-kit UX and platform ACL choices. Browser memory cannot honestly guarantee complete secret erasure. | Canary checks cover logs and export paths; default deployment holds no plaintext recovery kit; restore permissions exclude other users; unauthorized dashboard requests fail; export remains deliberate and documented. |
| P0.5 | F11: guardian UI can misrepresent recovery setup | Align real API response schemas with UI consumers; disable active-vault split until the genuine kit is provided through a deliberate local ceremony; label drill outputs and prevent their acceptance as vault recovery evidence. | 2–4 days. Depends on recovery-input design. Do not solve this by storing the root secret permanently. | An actual frontend/API test splits and recombines synthetic genuine-vault material; wrong-vault shares fail visibly; demo shares are unmistakable; fleet fields display actual server data. |

### Near-term improvements — essential for a dependable supported MVP

| Priority | Issue / impact | Recommended action | Effort, dependencies and trade-offs | Acceptance criteria |
|---|---|---|---|---|
| P1.1 | F06/F07: interrupted backups can remain incomplete | Introduce transactional local capture/head/counter updates and a persisted upload queue with retry/backoff and durable receipts. Reuse one application service from CLI, agent and API. | 6–12 days. Includes DB migration and writer serialization. Keep remote I/O outside long SQLite transactions. | Kill the process at each commit boundary: restart exposes a complete old/new state or recoverable pending job. Disconnect, edit once, reconnect without editing: remote durability is reached automatically. Concurrent writers cannot reuse a counter. |
| P1.2 | F05: unattended monitoring is misleading | Have the actual daemon audit persisted recovery closures, invoke repair under a scoped capability, renew/persist leases and expose expiry/last-verified age. Empty client lists and DB errors must be unknown/degraded. | 5–10 days after P0.2/P1.1. Decide how an independent daemon obtains signed inventories without decryption keys. | Run the installed daemon, remove an object/envelope/log in a disposable cluster, observe degraded state and verified repair. Stopping renewal shows an expiry alert; zero operators never reports healthy. |
| P1.3 | F13/F17: restore and recovery hardening | Validate all lengths/counts before allocation/copy, use safe relative-handle/no-follow operations where available, preflight destination collisions and define tombstone behavior. Verify/stage the requested snapshot before publication and display partial-failure state accurately. | 5–10 days. Cross-platform filesystem differences matter. Require an empty destination initially if robust overwrite semantics are too costly. | Corrupt manifests/DB rows return errors without panic or huge allocations; traversal/link/collision tests pass; a late integrity failure leaves no falsely completed restore; permissions and deletion behavior match documented policy. |
| P1.4 | F15/F16: deployment/release uncertainty | Fix writable paths/ownership, exercise fresh volumes and service units, pin tested inputs, require locked builds and test/advisory gates before publishing, and produce verifiable release provenance. | 3–6 days plus CI setup. Depends on Docker/Linux runners and release credentials. | Clean deployment starts as non-root; maintenance writes/restarts correctly; failing tests block release publication; checksums/provenance verify; supported-platform release artifacts recover a fixture. |
| P1.5 | F14/F17: scale and protocol uncertainty | Bound network response/history sizes, paginate logs, index chunks once during restore, enforce file limits before reads and define a supported vault envelope. Freeze canonical encoding with external vectors and fuzzing. | 5–10 days. Streaming is a larger follow-up; do not alter wire format without migration/read compatibility. | Representative maximum supported vault completes within declared memory/time bounds; hostile length/depth/count inputs fail safely; independent encoding vectors and old-format fixtures pass. |
| P1.6 | F05/F18 and operational gaps | Add integrity/expiry/retry/disk alerts, operator identity backup and replacement procedures, independent-host restore drills and a truthful status model including possibly stale recovery. Provide historical recovery selection or document its absence. | 4–8 days plus observation time. Requires separate failure domains and an alert destination. | An operator/host loss is detected, documented recovery is completed without original credentials/DB, alerts are delivered, and stale/unknown state never appears fully verified. |

### Longer-term enhancements — optional, after the essential gates

| Priority | Opportunity | Recommended action | Effort, dependencies and trade-offs | Acceptance criteria |
|---|---|---|---|---|
| P2.1 | F12: reduce storage and bandwidth | Start with reuse of unchanged file versions; consider encrypted chunk reuse only with a reviewed privacy/nonce/key design. Measure real bytes uploaded and retained rather than plaintext boundaries. | 5–12 days; advanced chunk reuse may take longer and need format migration. Equality leakage and nonce safety matter more than a benchmark badge. | Repeated unchanged push adds negligible object bytes; localized edits have measured savings; fresh-machine recovery and cross-vault privacy tests still pass. |
| P2.2 | F04: optional physical signing | Correct vendor metadata parsing, unify signing providers across snapshot/head/envelope/session operations, verify PIN/touch policy and implement supported-platform transport. | 10–20 days plus hardware procurement/review. Depends on exact token/firmware support; safely omitting this feature is viable. | Real supported tokens complete init/push/restart/recover; signatures match certified keys and exact protocol bytes; absent token, wrong PIN, denied touch and unplugging fail safely. |
| P2.3 | F03: optional external checkpoints | Implement real RPC transaction submission, persistent pending jobs, receipt/contract/chain verification, and evidence-based settlement states. | 8–15 days plus testnet/settlement time. Requires configured contract and transaction funding; core backup must work without chain availability. | A transaction is independently queryable on a configured testnet; restart preserves pending work; RPC failure or reorg downgrades status; no fabricated hash can reach confirmed state. |
| P2.4 | UX and independent assurance | Run task-based onboarding/recovery studies, browser contract and accessibility tests, and commission focused external protocol/security review. | 4–8 engineering days plus specialist review. Schedule after essential design fixes to avoid auditing immediately obsolete code. | Users recover a fixture without developer intervention; keyboard/screen-reader flows pass documented criteria; external findings are triaged and retested. |

## 8. Final verdict and five most important next steps

**Best classification: MVP.** The working encrypted recovery core and passing drills justify more than “prototype.” The security and durability gaps, unfinished integrations and inaccurate status claims prevent a beta or production-ready verdict for real confidential data.

The strongest parts are the offline-rooted recovery verification, explicit recovery inventory, digest checking, operator write durability and executable recovery drills. The parts needing substantial work are authority-scoped writes, non-Windows key protection, local crash/retry behavior, actual daemon maintenance, truthful interfaces, and recovery-secret handling.

The five most important next steps are:

1. Replace predictable non-Windows key protection and define supported secret-storage/migration behavior.
2. Enforce vault-scoped operator authorization and bounded public-service resource use.
3. Remove false confirmations and unsupported hardware/guardian claims; align dashboard/API contracts.
4. Make local commit, upload retry, full-closure maintenance and retention state durable and consistent.
5. Prove supported deployment and independent recovery with real API/browser, crash, permissions and release-gate tests, after reducing kit/log exposure.

These are release blockers, not optional polish. Passing all existing tests is valuable evidence; the targeted probe and interface review show why it is insufficient to support the repository's current certification claims.

## Appendix: reproducibility notes

Temporary logs retained at review time:

- `C:/Users/samue/AppData/Local/Temp/ciphervault-audit-unrestricted-tests.log` — successful full suite.
- `C:/Users/samue/AppData/Local/Temp/ciphervault-audit-all-tests.log` — sandboxed no-fail-fast run.
- `C:/Users/samue/AppData/Local/Temp/ciphervault-audit-clippy.log` — strict lint run.
- `C:/Users/samue/AppData/Local/Temp/ciphervault-audit-fmt.log` — formatting check.
- `C:/Users/samue/AppData/Local/Temp/ciphervault-audit-probe.rs` — temporary linked-library probe for F02/F12.

These paths are temporary and may be cleaned by the OS. The essential observations are reproduced in this report. The authorization probe registered owner-signed genesis at a synthetic locator, signed a head with an unrelated key, and called `append_authorized_recovery_record` with that unrelated caller key: it returned success. The deduplication probe called `chunk_and_encrypt_file` twice for the same vault/epoch/plaintext and compared the first wire-object CIDs: they differed.

No existing project source or report was changed to obtain these results.

