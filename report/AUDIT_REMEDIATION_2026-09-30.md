# CipherVault audit remediation report

**Date:** 30 September 2026 (Africa/Accra)

**Branch:** `codex/audit-remediation-2026-09-30`

**Baseline:** `a9df97dfee9ae64f9c82ce48d9c4ddc67176dc78`, released version 1.0.25

**Original assessment:** [Project audit](PROJECT_AUDIT_2026-09-30.md)

## Result and scope

The priority findings F01-F21 have corresponding source changes and local regression coverage. The final Windows workspace run passed **804 tests, 0 failures, 3 existing ignored tests** across 80 result blocks. The original baseline passed 737 tests: this branch adds 67 passing tests. Formatting, strict Clippy across all targets, and a workspace/all-targets check on the declared Rust 1.89 minimum pass. Real Chromium dashboard CSP and independent Bash/PowerShell installer-signature checks pass.

The initial remediation checks below were performed before publication. The subsequent release work and live outcomes are tracked in [the deployment ledger](DEPLOYMENT_2026-09-30.md). A release does not rewrite historical remote ciphertext or replace independent security review. The original audit remains a historical assessment; its rating has not been inflated based on implementation alone.

Most priority defects are corrected and locally verified. F13/F21 have an implemented opt-in v2 construction, with independent cryptographic review and coordinated reader/writer rollout still required. **Default captures remain v1 and retain the candidate-confirmation and encrypted-reuse limitations.** V2 readers can ship while writers remain gated. Provider/CI attestation functionality now fails explicitly when unavailable rather than trusting caller assertions. Broader roadmap recommendations remain separately tracked below.

## Priority finding disposition

| Finding | Implemented behavior | Verification / remaining boundary |
|---|---|---|
| **F01 - token issuance and production gates** | Sensitive credential operations require signing-key/passkey proof within five minutes. Tokens retain source-session/device/passkey revocation context. Human production elevation is bounded to the original freshness window. Handoffs preserve original age/expiry. Caller branch assertions cannot establish trusted production authority. | Recovery/TOTP/stale-session denial, active-device recovery login, replay/revocation and source-context tests pass. Verified CI branch attestation remains unavailable; supplied branch returns 503. Key possession is not advertised as multi-factor proof. |
| **F02 - scope widening** | Environment/repository/service restrictions cannot disappear on broader administrative targets. Bound-secret moves/rebindings authorize both ends; cross-tenant/project associations are rejected. | Negative management/resource tests pass, while legitimate fresh human administration remains usable. |
| **F03 - fleet control permissions** | Ordinary storage read/write credentials do not carry fleet administration. Explicit permissions are enforced on HTTP and P2P operations. Historical all-bits enrollment is narrowed to ordinary read/write. | Permission and negative fleet-control tests pass. Administrators require deliberate capability enrollment or the trusted service-token path. |
| **F04 - bound operator sessions** | Account/device bindings persist and are revalidated with key/vault enrollment on every authorized operation. | Real login -> PUT -> GET -> restart -> revoke regression passes. |
| **F05 - security defaults** | One startup security configuration is shared across state, HTTP and P2P. Strict authentication and enrollment default on; malformed security flags fail closed. | Configuration matrix passes. Transport-only fixtures explicitly choose local legacy mode; production defaults are exercised separately. |
| **F06 - workspace isolation** | Immutable request context couples database, filesystem root, operator settings and scope context. Workspace switching does not mutate process-global selection. Relative restore destinations use the selected root. The browser cookie protects the process session; each selected vault still receives account/device authorization. | Concurrent task-local and actual HTTP tests verify two roots/databases/gitignores. Workspace switching retains the cookie; malformed selection and revoked cookies are rejected. The old global vault override has been removed. |
| **F07 - keystore provisioning** | Exclusive, protected, synced staging and atomic winner publication avoid truncating an existing master key. Standard OS file locks replace the former Windows no-op lock. | Twelve racing provisioners obtain one durable key; malformed existing keys remain unchanged. Unix-specific behavior remains subject to cross-platform CI. |
| **F08 - watcher acknowledgment** | Dirty detection is read-only until committed capture bytes are acknowledged. Polling catches ignored/missed native events. Bounded queues/coalescing and a dedicated worker isolate hashing/capture/uploads from event reception and shutdown. Pending retries retain the exact signed head and immutable recovery closure. | Actual polling-only changes, failed certified capture/retry, native event bursts, dry-run non-persistence and hanging-HTTP cancellation pass. Capture uses certified authority generation rather than hard-coded generation 1. |
| **F09 - unattended maintenance** | A pinned, authenticated inventory connects the daemon to real closure/discovery audits, persisted jobs/backoff, repair and verified lease renewal. Locator-only registration remains unverified; missing write credentials retain deficits. | Missing-chunk/persisted job tests and real CLI export -> restart -> read-only daemon job pass. Availability of ciphertext does not substitute for a full plaintext recovery rehearsal. |
| **F10 - recovery head selection** | Certified ancestry determines the authenticated maximal head. Device-local counters no longer order different devices. Forks, ambiguity and cycles fail explicitly. | Multi-device ancestry, forks/cycles and forged authority tests pass. |
| **F11 - recovery truncation** | HTTP/P2P recovery responses carry monotonic byte-offset continuation cursors. Clients collect complete bounded results and reject legacy truncated prefixes. | Records beyond the first page are exercised. Limits: 1 MiB raw per page, 64 MiB/10,000 records per stream. Compaction/checkpoints remain future work. |
| **F12 - append races/crash tails** | A locator lock covers scan, first-authority validation and append. Incomplete trailing frames are repaired before durable append; over-cap logs fail explicitly. | Concurrent first-genesis and torn-tail/restart tests pass. |
| **F13 - encrypted chunk reuse** | New v2 chunk key/nonce/header derivations bind vault, epoch and keyed padded-content identifiers, allowing unchanged chunks to retain encrypted CIDs. Position/order and whole-file identity stay authenticated in the encrypted manifest. V1 and v2 readers remain enabled; writers default to v1 pending independent review. | Stable encrypted reuse, tampering/isolation and repeated-chunk round trips pass. Fixed percentage savings are not promised. **Independent cryptographic review and upgraded readers are release gates.** |
| **F14 - historical epochs** | Restore, pull, diff and snapshot-backed run resolve each requested record's epoch key. Local consumers verify certified snapshot signatures. | Actual CLI capture -> rekey -> capture -> old restore/cross-epoch diff/old in-memory run passes. |
| **F15 - restore publication and permissions** | Protected staging/backups and a synced publication journal support rollback and recovery after interruption. External edits during rollback are preserved for inspection. Windows plaintext files receive restrictive owner ACLs. | Late destination failure, publication rollback, restart recovery/external edit and Windows ACL tests pass. This is journaled merge publication, not one indivisible multi-file filesystem transaction. |
| **F16 - voucher lifetime totals** | Lifetime consumption survives voucher expiry and restart; bounded refunds preserve quota conservation. Corrupt persistent ledgers fail closed. | Expiry/restart/conservation and enforcement tests pass. |
| **F17 - lease ownership** | Durable ownership prevents renewal from reassigning a lease to another vault/principal. Verified receipt persistence failures fail the operation. | Cross-vault renewal/ownership and receipt tests pass. |
| **F18 - release bootstrap trust** | Installers verify tag-bound V2 checksum manifests with an independently installed OpenSSL 3 and embedded trust keys before checksums/extraction/replacement. The updater uses the same signature domain and refuses downgrade. Legacy V1 requires exact version plus explicit compatibility opt-in. | Fourteen actual Bash/PowerShell verifier cases pass: valid, modified checksums/tag, wrong key, unsigned, default legacy denial and explicit historical acceptance. Rust updater tamper/signature tests pass. Publication verification is recorded in the deployment ledger. |
| **F19 - dashboard CSP** | Inline handlers/styles were replaced by delegated actions, CSS classes and CSSOM updates; strict CSP remains enabled. Signature labels use backend observed verification. | Actual Chromium tests verify forwarded controls, push modal/layout, truthful labels, no script errors and zero CSP violations. This is not accessibility certification. |
| **F20 - abuse/source identity** | Operator limiting uses the direct peer IP; forwarded identity is honored only for configured trusted proxy IPs. Account challenge reservations are atomic/shared across methods and independent SQLite connections. | Source-spoofing/quota/configuration tests pass. Larger principal-specific policies and production load characterization remain enhancements. |
| **F21 - complete-file candidate oracle** | V2 file/chunk identifiers are secret-keyed and domain separated; public vault/epoch fields no longer reproduce candidate identifiers without the epoch key. | Candidate-confirmation/isolation regressions pass. Default v1 captures and existing remote v1 objects retain their limitation; equality/length/count/access-pattern leakage remains in opt-in v2. **Independent review is required before broad production claims.** |

## Added improvements beyond the priority fixes

- **Atomic scoped execution:** one authorized SQLite transaction materializes up to 100 names / 128 KiB, checks a selected-set revision and appends access events. Stale/denied/corrupt/partial results never start the child. Empty batches still authorize and validate revision; hex revisions accept either case. The revision does not pin unrelated environment membership.
- **Safer automation:** secret set/rotate support `--value-stdin` with exact UTF-8 preservation and a 64 KiB limit. A process-level test checks whitespace/newlines and oversized rejection. CipherVault control credentials are stripped from inherited child environments. Owned secret buffers use zeroizing containers in additional error/lifetime paths.
- **Restore preview:** `restore --dry-run` verifies content and reports create/replace/unchanged without creating plaintext, staging or the destination. Merge semantics retain unrelated files. Dirty-file checks fail on unreadable/oversized/nonregular inputs instead of silently allowing overwrite.
- **Versioned hosted KEKs:** historical key lookup, immutable key fingerprints and bounded audited DEK rewrap preserve value ciphertext/version identity. Missing historical material and changed material under the same key ID fail closed. This is a local KEK implementation, not an external managed KMS.
- **Honest rotation/provider behavior:** manual replacement returns `provider_verified: false`; idempotency replays the original input-bound receipt. External provider verification, repository ownership checks and CI branch attestation report unavailable until real adapters exist.
- **Trust integration:** per-vault operator pins and independent discovery registries are applied. Operator/relayer/P2P service credentials require explicit endpoint/peer allowlists; control clients refuse redirects. Repair tries alternate integrity-verified sources; object fetch returns the first verified success.
- **Bounded P2P work:** up to 16 inbound RPC workers move blocking state/disk work out of the swarm networking loop; saturation returns 503. A held real state lock no longer stalls unrelated networking/commands.
- **Local persistence:** account-file replacement is atomic and owner restricted. Recovery shares validate set descriptors and reconstructed identity. Hardware-signed snapshots now obtain hardware-signed recovery envelopes; persisted recovery sets are immutable across repeated/concurrent preparation.
- **Build/security maintenance:** Ratatui now resolves patched `lru` 0.18.5. Rust 1.89 is declared and locally checked; CI includes the minimum toolchain and browser CSP. Compact CI debug/test artifacts address the observed disk bottleneck. Supported-release/confidentiality/MFA/restore/dedup/commitment claims have been corrected in current documentation.

## Verification evidence

| Check | Result |
|---|---|
| `cargo test --workspace --locked --no-fail-fast --offline` | **804 passed, 0 failed, 3 ignored**, 80 result blocks; exit 0 |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | Pass |
| `cargo fmt --all -- --check` | Pass |
| `cargo +1.89.0 check --workspace --all-targets --locked --offline` | Pass on Windows; final source rechecked |
| `node --check apps/ui/app.js` | Pass |
| `node apps/ui/audit.test.cjs` | Pass: DOM/behavior/accessibility contracts, not WCAG certification |
| `node apps/ui/csp.browser.test.cjs` | Pass in real Chromium with strict production CSP |
| `node scripts/verify_landing.cjs` | Pass: landing contracts and crypto vectors |
| `node tests/dashboard_container_contract.cjs` | Pass |
| `node tests/release_installer_signatures.cjs` | **14 passed** across Bash and PowerShell/OpenSSL |
| `cargo audit --deny unsound --deny unmaintained --ignore RUSTSEC-2024-0436` | Pass; no known vulnerabilities in the resolved lockfile; one explicit maintenance exception |
| `git diff --check` and changed-text UTF-8 validation | Pass |

Full local logs are retained in the ignored `.agents/audit-2026-09-30/` directory, especially `remediation-complete-tests.log`, `remediation-clippy.log`, `remediation-msrv-final.log`, and `remediation-dependency-policy.json`. Earlier failed build/test logs are preserved for traceability; the completed run supersedes them. The build initially exhausted disk with large debug artifacts, then completed after cleaning only the verified generated project cache and using compact debug/test artifacts.

The ignored tests are existing performance/load tests, not newly disabled security checks. New fixtures use temporary vaults, synthetic credentials and loopback services. Hardware tests include simulation and PC/SC subsystem smoke checks; they do not prove a real-token ceremony. Linux/macOS execution and hosted CI were not run locally. Solidity source was unchanged; Foundry was not executed in this remediation.

## Rollout requirements

1. Review the diff and this ledger. Preserve recovery kits, historical epoch keys, protected device state and account/KEK backups before any upgrade.
2. Independently audit the new chunk construction and authorization/recovery/release boundaries. Upgrade readers before enabling v2 writers; old binaries cannot read new v2 chunks. Existing v1 history remains readable by the new implementation.
3. Enroll storage devices with explicit capabilities; issue fleet-administrator capability deliberately. Configure independent operator trust pins and only the required service-token endpoint/peer allowlists.
4. Rotate account scope-token signing material to invalidate earlier issuance. Keep historical KEKs and verify bounded rewrap plus isolated control-plane restoration before removing keys.
5. Export pinned maintenance inventories; distinguish read-only verification from authenticated repair/renewal and full plaintext recovery drills.
6. Publish signed V2 manifests only after release gates pass. Old V1-only updaters need a verified bootstrap reinstall. Automatic latest bootstrap deliberately rejects old V1 signatures unless exact-version historical compatibility is explicitly selected.
7. Rehearse recovery and failover on isolated infrastructure before production rollout. Production changes and their exact verification are recorded separately in the deployment ledger.

The practical settings and commands are in [current security guarantees](../docs/CURRENT_SECURITY_GUARANTEES.md), [account behavior](../services/account/README.md), [v2 chunk design](../crates/snapshot/CHUNK_PROTOCOL_V2.md), and [installer verification](../dist/INSTALLER_SIGNATURES.md).

## Work still open

| Work | Why it remains / next evidence |
|---|---|
| Independent crypto/security audit and production rollout | Local passing tests cannot certify the new deterministic construction or a deployed fleet. Retest independent findings before broad release. |
| Linux/macOS CI and real hardware | The source includes platform-specific regressions, but this host executed Windows. Run the matrix and real YubiKey/PCSC ceremonies. |
| Unmaintained `paste` dependency | Linux libp2p/if-watch/netlink still depends on `paste` 1.0.15. No reported exploitable vulnerability was found; abandonment remains an open maintenance risk. Only RUSTSEC-2024-0436 is excepted through **31 December 2026**; CI expires the exception. See [dependency policy](../docs/DEPENDENCY_AUDIT.md). |
| Trusted workload identity and enforced MFA | Branch attestations/provider identity adapters are deliberately unavailable. Device/passkey proof is not automatically two factors; WebAuthn UV is configuration-dependent. Implement verified issuer/audience/ref context and an explicit factor policy. |
| Real provider and managed KMS integration | Runtime adapters are unavailable; manual replacement and local versioned KEKs are explicit. Complete external verification, revocation, reconciliation and managed custody using real integration fixtures. |
| Hosted control-plane disaster rehearsal | Protected consistent backup and isolated restore tools now validate integrity, audit history, every retained secret version and TOTP seed, and revoke copied sessions. The deployment ledger records any live rehearsal; independent backup custody and ongoing scheduling remain operational requirements. |
| Production capacity and retention | The account DB mutex still serializes work. Full-log scan/compaction, aggregate snapshot memory, inode/byte lifecycle ceilings, safe expiry cleanup and realistic networked p95/p99 remain to measure/design. Limits now fail visibly; they are not a production capacity certificate. |
| Recovery rehearsal / placement policy | `audit --recovery-drill` now reconstructs plaintext from pinned remote operators in memory without local ciphertext fallback. It uses local protected keys, so clean-machine offline recovery and verified region/organization diversity remain separate requirements. |
| UX and interface consolidation | Complete accessibility testing, simplify onboarding, finish watcher supervision dashboards, exact-versus-merge restore controls, and modularize large UI/backend files. Current code adds focused safety features without a wholesale rewrite. |

The recommended order is independent review and rollout rehearsal, then production capacity/control-plane backup work, followed by verified workload/provider adapters and interface simplification. New chain/economic features remain deferred because they do not resolve these outstanding backup and authorization risks.

## Subsequent completion work for 1.0.26

- Account `backup` uses a consistent SQLite snapshot and a protected receipt. `restore-rehearsal` validates historical envelopes and TOTP without starting HTTP, copying keys, or changing production; copied sessions are revoked. Startup protects the data directory and SQLite sidecars.
- Private SSE telemetry now shares bounded probes per immutable vault/operator context: 16 active samplers, 64 subscribers each, 32 endpoints, one retained latest observation, bounded native/blocking work, and cancellation after the last subscriber. Open streams recheck authorization. The accessible backlog reports durable pending uploads; hardware presence no longer claims verified slot readiness.
- `audit --recovery-drill` requires independent pins and certified discovery, downloads integrity-checked remote objects and verifies plaintext with the historical epoch key in memory. It fails on missing/corrupt objects or pins and does not publish plaintext.
- New captures preserve v1 reader compatibility unless `CIPHERVAULT_CHUNK_V2_WRITE=1` is explicitly selected; malformed flags fail closed. V2 remains pending independent review.
- Release packaging selects each full archive exactly, rejects absent/empty standalone executables, and checksums all 18 bundles and six standalone binaries. A real packaging regression executes the workflow step against isolated role bundles and a missing executable.

Final tests, commit, CI, signed artifacts, backups and fleet promotion outcomes are recorded in [DEPLOYMENT_2026-09-30.md](DEPLOYMENT_2026-09-30.md).
