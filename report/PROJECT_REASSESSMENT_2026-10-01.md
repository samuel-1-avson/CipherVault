# CipherVault post-remediation project report

**Date:** 1 October 2026 (UTC / Africa/Accra)

**Assessed release:** v1.0.26

**Released source:** `4966a5ce057b81ac0ee8795881133cad91f8c3ac`

**Workspace reference before this report:** `07425272c67049f3a981a41c1f77eb7ae17269ac`
**Latest public service checks:** 1 October 2026, 07:39 UTC

## Assessment

**Overall project rating: 7.6/10, up from 6.3/10.** CipherVault now has substantially stronger authorization boundaries, safer capture and restore behavior, better recovery validation, and a verified signed release running on the hosted fleet. These changes address failures that previously undermined otherwise useful features.

**Broad production readiness: 6.5/10, up from 4.5/10.** Controlled use with documented limitations, protected recovery keys, verified backups, and an operator able to respond to failures is reasonable. The evidence does not yet support presenting the project as an independently audited, unattended, high-assurance service for broad sensitive multi-tenant use.

The original audit identified 21 priority findings. **Nineteen have implemented corrections and regression evidence; two remain partially addressed because their improved construction is opt-in.** This is an implementation disposition, not a claim that 19 areas have received independent security sign-off. Default v1 captures still permit candidate-file confirmation and do not preserve encrypted chunk reuse across changed file versions. V2 addresses these mechanisms in source, but remains gated pending independent review and coordinated reader deployment.

The largest remaining needs are independent cryptographic review, enforced multi-factor policy, independently retained backup/key custody, sustained capacity measurements, and recovery protocol work. The project should spend its next development cycle on these foundations and simpler user workflows.

## Basis and limits of this report

This is a post-remediation reassessment of the whole project's engineering and operational position. It compares the [original audit](PROJECT_AUDIT_2026-09-30.md), [remediation ledger](AUDIT_REMEDIATION_2026-09-30.md), current source and guarantee documents, retained test logs, GitHub CI/release results, and the [deployment ledger](DEPLOYMENT_2026-09-30.md). Source spot checks cover security defaults, database serialization, capture bounds, protocol compatibility, and dependency policy.

The current tracked checkout contains **517 files, including 210 Rust source files, across 13 workspace members**. These counts describe scope, not code quality. The initial audit's 486-file/196-Rust-file counts describe its earlier baseline.

The full test suite was completed during release preparation on 30 September; it was not rerun for this documentation-only reassessment. Public health/version checks and GitHub release/CI status were freshly checked on 1 October. Container digest, key rotation, backup, and restore evidence comes from the recorded deployment ceremony; this report does not claim a new privileged inspection of production volumes or containers.

No independent penetration test, cryptographic certification, physical-token ceremony, WCAG certification, or sustained production-capacity certification is claimed. The audit's synthetic reproductions are not evidence that a live compromise occurred. Ratings are subjective engineering judgments using the original weights, not measured probabilities or formal certifications.

## Updated ratings

| Dimension | Weight | Original /10 | Current /10 | Basis for the current score |
|---|---:|---:|---:|---|
| Architecture and product foundation | 10% | 8.0 | 8.0 | Useful problem and sensible crate boundaries remain; the broad product scope still adds integration complexity. |
| Security and authorization | 25% | 5.0 | 7.0 | Token issuance, scope narrowing, operator capabilities, session bindings, and workspace isolation are corrected. Default v1 privacy limits, MFA policy, and independent review remain significant. |
| Data integrity, recovery, and reliability | 20% | 5.5 | 7.8 | Durable watcher acknowledgment, ancestry-based heads, pagination, historical epochs, journaled restore, and isolated account restoration improve reliability. Independent disaster recovery and protocol renewal limits remain. |
| Maintainability | 10% | 6.5 | 7.0 | Explicit context and bounded workers reduce fragile coupling. Large UI/account modules, duplicated interfaces, and a wide dependency surface remain. |
| User experience and functionality | 10% | 7.0 | 7.5 | CSP fixes, restore previews, safer secret input, consistent scoped execution, and truthful status displays help. Onboarding and browser scoped workflows need consolidation. |
| Testing and verification | 10% | 7.5 | 8.5 | More meaningful negative, concurrency, crash, browser, installer, and recovery tests; passing cross-platform CI. Physical hardware and sustained networked load evidence remain incomplete. |
| Operations and distribution | 10% | 7.5 | 8.0 | Signed artifacts, immutable deployment, live checks, rollback images, and verified off-host backup copies are established. Scheduled recovery policy, independent custody, and human review remain gaps. |
| Documentation and claim accuracy | 5% | 5.5 | 8.0 | Current guarantees distinguish confidentiality models, actual MFA, v1/v2 behavior, restore semantics, and unavailable adapters. Historical reports must be read with their dates and later completion evidence. |
| **Weighted overall** | **100%** | **6.3** | **7.6** | Unrounded totals: **6.275 → 7.610**; improvement **1.3 points** at displayed precision. |

The separate readiness score improved because the major authorization/data-loss defects received fixes, release checks passed, and deployment included backup and rollback evidence. It remains lower than the overall score because continuing recovery, factor enforcement, custody independence, and production limits are not established.

## Original priority findings: current disposition

“Addressed” below means the specific baseline defect has a correction and automated regression evidence. Remaining assurance or capability gaps are stated separately.

| Finding | Current disposition | Result and remaining boundary |
|---|---|---|
| F01 — Credential issuance bypasses | Addressed | Recent signing-key/passkey authentication and source-session revocation context now apply. Caller-declared branches cannot grant production trust; a real CI adapter is still unavailable. |
| F02 — Workload scope widening | Addressed | Narrow restrictions cannot disappear on administrative targets; moves/rebindings authorize both ends. |
| F03 — Vault sessions gain fleet control | Addressed | Storage access and fleet administration have explicit separate capabilities, enforced over HTTP and P2P. |
| F04 — Lost operator account/device binding | Addressed | Bindings survive login/restart and are revalidated on operations and revocation. |
| F05 — Inconsistent strict defaults | Addressed | Startup shares one configuration; strict authentication/enrollment default on and malformed flags fail closed. |
| F06 — Cross-workspace dashboard context | Addressed | Immutable request context binds database, root, operators, and scope; process-global selection was removed. |
| F07 — Master-key provisioning overwrite | Addressed | Exclusive protected publication and OS locks preserve existing keys and handle racing creators. |
| F08 — Watcher acknowledges before capture | Addressed | Acknowledgment follows committed capture; bounded queues, fallback scans, durable upload retries, and cancellation improve supervision. |
| F09 — Misleading maintenance health | Addressed | Pinned inventory drives actual closure audits, persisted jobs, repair, and verified renewal. Ciphertext checks alone still do not prove full disaster recovery. |
| F10 — Incorrect multi-device head order | Addressed | Certified DAG ancestry selects a unique maximal head; forks/ambiguity fail explicitly. Withholding of all newer history still needs an independent freshness expectation. |
| F11 — Truncated long recovery histories | Addressed | Continuation cursors collect complete bounded results; limits fail visibly. Indexing, checkpoints, and compaction remain work. |
| F12 — Recovery append races/torn tails | Addressed | A locator lock covers validation and append; incomplete tails are repaired before durable append. |
| F13 — No encrypted reuse across edits | **Partial; open for default v1** | V2 supports stable encrypted CIDs within one vault/epoch. Writers remain v1 by default; external review and reader rollout precede broader v2 use. |
| F14 — Current key used for historical data | Addressed | Restore, diff, pull, and snapshot execution resolve the recorded epoch and verify signing authority. |
| F15 — Restore publication/permissions | Addressed | Protected staging, synced journal, rollback, restart recovery, and Windows ACLs are implemented. Directory-wide simultaneous atomic visibility is not promised. |
| F16 — Lifetime quota lost on expiry/restart | Addressed | Durable lifetime totals and bounded refunds preserve conservation; corrupt ledgers fail closed. |
| F17 — Lease renewal lacks ownership | Addressed | Persisted ownership prevents reassignment; receipt persistence failure fails the operation. |
| F18 — Unsigned bootstrap checksum trust | Addressed | Installers independently verify tag-bound signed V2 checksum manifests before installation; historical compatibility requires explicit selection. |
| F19 — Dashboard conflicts with CSP | Addressed | Delegated actions and CSS changes work under strict CSP; real-browser regressions pass. This does not certify accessibility. |
| F20 — Spoofed/collapsed rate-limit source | Addressed | Direct peer identity and explicit trusted proxies govern operator limits; account reservations are atomic across methods/connections. Production abuse/load tuning remains. |
| F21 — Complete-file candidate oracle | **Partial; open for default v1** | V2 uses secret-keyed identifiers. Default v1 and existing remote v1 history retain the oracle; even v2 exposes equality, lengths, counts, and access patterns. |

Enabling v2 does not rewrite v1 history. Old readers cannot consume v2 chunk objects. Keep the writer gate explicit until independent review and compatibility checks are complete. See [the v2 protocol](../crates/snapshot/CHUNK_PROTOCOL_V2.md) and [current guarantees](../docs/CURRENT_SECURITY_GUARANTEES.md).

## Improvements beyond those findings

- **Scoped execution:** one authorized transaction materializes the requested secret set, validates its revision, and records access. Denied, stale, corrupt, or partial batches do not launch a child. Limits are 100 names and 128 KiB total values; the revision covers the selected set, not unrelated environment membership.
- **Safer automation:** `--value-stdin` preserves exact UTF-8 input within a 64 KiB bound; control credentials are removed from inherited child environments. Additional owned secret buffers are zeroized, without promising complete OS/process memory erasure.
- **Restore preview:** `restore --dry-run` verifies and previews create/replace/unchanged actions without writing plaintext. Merge restore retains unrelated files; unreadable or nonregular inputs fail safe.
- **Hosted key lifecycle:** versioned local KEKs, immutable key fingerprints, historical lookup, and audited bounded DEK rewrap preserve retained versions. This is not managed KMS custody.
- **Trust and repair:** per-vault operator pins, independent discovery registries, explicit privileged credential allowlists, redirect refusal, alternate verified repair sources, and first verified fetch success improve integration safety.
- **Recovery and supervision:** hardware recovery envelopes use the certified signer; share descriptors and reconstructed identity are checked. Shared bounded SSE telemetry rechecks authorization and displays durable upload backlog. The plaintext recovery drill fetches pinned remote objects without local ciphertext fallback.
- **Distribution and dependencies:** Rust 1.89 is checked, patched LRU and newer bundled SQLite dependencies are adopted, and release packaging/installer trust have regression coverage. The time-limited `paste` maintenance exception remains explicit.

## Verification and live deployment

| Evidence | Result | Limit |
|---|---|---|
| Final retained local workspace test log | **826 passed, 0 failed, 3 ignored**, 81 result blocks | Recounted from `release-complete-tests.log`; tests were run during release preparation. |
| Formatting, strict all-target Clippy, Rust 1.89 check | Passed during release work | Static checks do not establish threat-model completeness. |
| Released commit's [CI run](https://github.com/samuel-1-avson/CipherVault/actions/runs/36777835485) | Windows, Ubuntu, macOS, Rust 1.89, Foundry, real-browser CSP, and dedicated push-throughput job all succeeded | This establishes automated platform coverage, not physical hardware or sustained fleet capacity. |
| Installer and cloud bootstrap regressions | 14 installer-signature cases and 30 bootstrap cases passed | Isolated integration fixtures; no new cloud ceremony is implied by those cases. |
| Released commit's security checks | Passed; recorded RustSec audit reported no known vulnerabilities under the stated policy | Point-in-time scan; `paste` abandonment advisory is excepted through 31 December 2026. |
| [Release workflow](https://github.com/samuel-1-avson/CipherVault/actions/runs/36779365526) | Successful pre-release gate, six binary targets, four image builds, scans, signatures, and publication | Successful packaging/signing is not independent security review. |
| Fresh dashboard check, 1 October 07:39 UTC | HTTP 200; `build_version: 1.0.26` | Public build/health evidence, not inspection of all protected workflows. |
| Fresh account checks | Capabilities HTTP 200; anonymous account session HTTP 401 | Confirms route availability and this anonymous denial only. |
| Fresh operator checks | All three `/healthz` endpoints HTTP 200, `ready`, `storage_ready: true` | Readiness does not prove every retained object is recoverable or future durability. |

The three default-suite ignored tests are the scoped load gate, sequential/concurrent push benchmark, and ten-node chaos gate. CI separately ran the push-throughput benchmark successfully. Do not interpret that as sustained production evidence for all three workloads. Earlier remediation counts of 804, and intermediate logs with 822/824, are superseded by the final complete 826-test run. The initial audit's baseline was 737 passing tests.

Release [v1.0.26](https://github.com/samuel-1-avson/CipherVault/releases/tag/v1.0.26) is published. [PR #13](https://github.com/samuel-1-avson/CipherVault/pull/13) merged the remediation; [PR #14](https://github.com/samuel-1-avson/CipherVault/pull/14) merged package hashes. The optional edge-image workflow was cancelled; the successful signed release workflow supplies the deployment evidence. [PR #15](https://github.com/samuel-1-avson/CipherVault/pull/15) remains open for the earlier deployment documentation, with its automated checks successful when checked for this report. This new report is a separate local review artifact.

Recorded deployment verification established pinned signed operator/dashboard/account images, non-root web containers, preserved operator identities, scope-token signing-key rotation, healthy promotion, and signed rollback candidates. Fresh public checks are consistent with that recorded release. See the [deployment ledger](DEPLOYMENT_2026-09-30.md) for exact digests and ceremony details.

Pre- and post-deployment account backups were created, restored into isolated offline directories, and verified. Copies were uploaded to a private versioned GCS bucket and downloaded with matching hashes. The rehearsal decrypted the retained TOTP seed and revoked copied sessions without changing production. **There were no retained scoped-secret versions in the live database**, so real production secret-value decryption was not exercised; synthetic tests cover that code path. Keys were retained separately and excluded from the backup bundles.

The backup bucket is in the same GCP project. Protected workstation copies improve off-host recovery, but independently governed custody, ongoing scheduling, and tested disaster promotion are still required. A checksum receipt checks corruption; it is not an authenticity signature.

## Strengths and disadvantages

| Strengths to preserve | Remaining disadvantages |
|---|---|
| Concrete user value: protecting secrets outside Git while retaining history and recovery. | Scope spans backup, hosted secrets, identity, P2P, recovery, chain commitments, CLI, TUI, and dashboard; maintenance burden is substantial. |
| Useful crate boundaries, standard cryptographic primitives, authenticated manifests, and certified device authority. | Custom protocol composition and deterministic encryption still need independent scrutiny. |
| Negative authorization and crash/restart regressions now cover important transitions. | Passing tests cannot establish all security, hardware, operational, or accessibility properties. |
| Verified restore before publication, durable upload state, pinned operators, and distinct-key quorum checks. | Quorum keys do not prove independent organizations/clouds; the deployed fleet remains concentrated in one GCP project. |
| Signed releases, immutable promotion, rollback evidence, and an isolated account restore rehearsal. | One deployment ceremony is not a continuous backup/restore service-level guarantee. |
| CLI, TUI, and browser serve useful audiences; automation is safer. | Users still face modes, scopes, epochs, leases, keys, and recovery choices; onboarding is too demanding. |
| Current documentation is more candid about guarantees. | Historical documents contain earlier pending states/counts and must be reconciled using the release ledger. |

The two confidentiality models remain materially different: file-backup clients encrypt before operators receive data; the hosted account service receives and decrypts scoped-secret values using its KEK. Product copy must preserve this distinction. Portable file-backed keys are also not equivalent to native credential-service or TPM protection.

## Remaining issues and priorities

P1 below means work needed before expanding sensitive production use. P2 means reliability/capacity or product improvement; P3 means lower-impact maintenance. These are current priorities, not a repetition of already-fixed baseline defects.

| Priority | Remaining issue | Why it matters | Acceptance evidence |
|---|---|---|---|
| P1 | Default v1 privacy/reuse limits and independent crypto review | F13/F21 remain relevant to current writes/history; v2 changes a security-sensitive deterministic construction. | Independent review of identifiers/KDFs, envelopes, authorization and recovery; fixes retested; upgraded readers demonstrated; v1-history exposure/migration explicitly documented before writer rollout. |
| P1 | Enforced MFA and policy-based step-up | TOTP is alternate login; recent key/passkey proof is not automatically two factors. | Session-bound, expiring, one-time factor proof; replay/revocation tests; policy enforced across sensitive operations; recovery/lockout ceremony exercised. |
| P1 | Independent backup/key custody and scheduled recovery | Same-project cloud backups and existing local keys share administrative failure risks; one-off rehearsals do not bound future data loss. | Defined RPO/RTO and owners; scheduled backups with stale/failure alerts; separately governed key/archive custody; clean-machine recovery and isolated promotion with retained historical keys. |
| P1 | Same-key authority recertification ambiguity | HeadRecord v1 lacks authority generation; newest-certificate selection can make an older head fail its generation check. This fails closed but can block legitimate historical recovery. | Reviewed generation binding/certificate-selection migration; repeated-key/multi-generation historical recovery and fork/rollback tests; compatibility policy before renewal is offered. |
| P1 | Human release-review process | Administrator overrides merged PRs #13/#14; #13 had no qualifying human peer review. Automated reviews do not replace independent review. | Available human reviewer and enforced review path before the next release; exceptions documented rather than routine. |
| P2 | Sustained capacity and storage lifecycle | Global account DB mutex, full-log work, aggregate memory, and unbounded retention growth remain structural risks. | Networked sustained load/chaos results with p95/p99, lock/queue wait, RSS, disk/inodes, and rejection rates; documented supported envelope; safe retention/compaction gates. |
| P2 | Verified workload/provider/KMS adapters | CI identity, provider verification, and repository ownership verification are unavailable; KEKs remain local. | Issuer/audience/ref/freshness checks and replay denials; real provider failure/revocation fixtures; managed-key historical lookup and isolated restoration. |
| P2 | Full offline vault recovery and physical hardware | Remote plaintext drill uses retained local keys; simulated token composition does not prove real-device operation. | Fresh-machine recovery from independently retained material, missing-node/fork cases, and actual token ceremonies on supported platforms. |
| P2 | Onboarding, scoped browser workflows, accessibility, and modularity | Safety controls are harder to use and maintain when context and workflow are spread across large modules. | Simple first-success/recovery journey, manual keyboard/screen-reader checks, real browser journeys, and smaller modules with unchanged security regressions. |
| P3 | `paste` maintenance exception | Abandoned transitive macro remains in the Linux networking graph. | Replace via a compatible upstream path or formally review before **31 December 2026**; rerun Linux discovery/network tests. |
| P3 | Caddy warnings and report synchronization | Non-fatal config warnings and duplicated historical status add operational noise. | Clean validation output and one clearly linked latest guarantee/evidence source. |

The same-key renewal limitation is documented in [current security guarantees](../docs/CURRENT_SECURITY_GUARANTEES.md). There is no evidence here that the deployed fleet encountered it. Avoid presenting generalized same-key renewal as complete until the protocol decision is reviewed.

## Bottlenecks: what improved and what remains

| Area | Current assessment | Next measurement or improvement |
|---|---|---|
| Changed-file upload/storage | Default v1 still replaces encrypted chunk identity across versions; opt-in v2 improves reuse. | Measure encrypted CIDs, actual uploaded bytes, and retained disk cost across inserts/edits; publish format-specific results. |
| Hosted account concurrency | [AccountState](../services/account/src/state.rs) still holds one `Arc<Mutex<Connection>>`; WAL alone does not remove application serialization. | Instrument mutex/queue wait; benchmark concurrent materialization, audit, rotation, and backup with full durability; choose a bounded DB execution design from evidence. |
| Recovery history | Pagination and explicit caps fix silent truncation; total collection remains bounded to 64 MiB/10,000 records and append scans remain costly. | Near-cap concurrent/restart tests; indexes and authenticated checkpoints/compaction; visible exhaustion guidance. |
| Snapshot/restore memory | Prechecked bounded 256 MiB file reads remove the earlier allocation-before-rejection problem. Aggregate multi-file memory still needs characterization. | Measure peak RSS for many near-limit files; apply aggregate budgets and streaming/staging where needed. |
| P2P, watcher, fetch latency | Bounded 16-worker RPC handling, capture queues, retries, and first verified fetch reduce identified stalls. | Saturation/backpressure tests with slow disks and endpoints; track queue depth, timeouts, event-loop lag, and shutdown time. |
| Dashboard work | Shared telemetry reduces per-tab probes; limits include 16 samplers, 64 subscribers each, and 32 endpoints. Other panel refresh/scan costs remain. | Compare idle/active/multiple-tab CPU, request count, and filesystem scans; use cached/on-demand work. |
| Storage retention | Object lifecycle, byte/inode ceilings, safe expiry, and ownership inventory need a coherent policy. | Forecast capacity/lease deadlines; rehearse safe cleanup without deleting recovery closure; define retention contracts. |
| Build and modules | Compact build artifacts mitigated disk exhaustion; dependency and compilation footprint remain large. | Measure image/build duration/cache use; decompose large modules without a wholesale rewrite. |

Current physical sizes reinforce maintainability concerns: `apps/ui/app.js` is **5,763 lines / 248,817 bytes**, CSS is **152,266 bytes**, and `services/account/src/secret_routes.rs` is **4,653 lines / 168,721 bytes**. Size alone does not prove runtime slowness. These are refactoring candidates because broad behavior is concentrated in a few integration files.

## Features to add, improve, simplify, or defer

| Recommendation | Action | Benefit and condition |
|---|---|---|
| Recovery readiness dashboard | Extend | Show last successful isolated restore, backup age, tested head/epoch, missing objects, lease deadlines, and custody status; keep ciphertext availability distinct from full recovery. |
| Scheduled backup/restore service | Add | Automate protected exports, integrity/authenticity verification, retention, and failure alerts. Define ownership and RPO/RTO before promising unattended recovery. |
| Explicit MFA/step-up policy | Add | Protect reveals, exports, token issuance, device changes, and recovery administration without mislabeling alternate login. |
| Verified CI/workload authentication | Add after core assurance | Replace static/shared automation credentials with bounded verified issuer/repository/ref context. Keep unavailable paths explicit until real adapters work. |
| Versioned managed KMS adapter | Extend | Reduce server-local custody risk and support historical recovery/rewrap, with real failure and key-unavailability rehearsals. |
| Capacity/retention forecasting | Add | Warn about byte/inode pressure, unrecoverable closure risk, and upcoming lease expiry before failures. |
| Guided onboarding and scoped browser management | Improve | Lead through project/environment selection, protect/import, run, and recovery rehearsal. Add audited reveal/edit/rotate workflows only with appropriate factor policy. |
| Conflict-aware restore and history controls | Extend | Preserve working dry-run and journaled merge; offer exact-restore mode only with reviewed deletion/conflict semantics and preview. |
| Operator failure-domain placement | Extend | Require verified regional/organizational diversity where needed; unique signing keys alone are insufficient. |
| Interface/service consolidation | Simplify | Share context and command behavior; split large JS/CSS/account modules. Retain useful CLI/TUI/browser interfaces. |
| Incomplete provider integrations | Hide or clearly disable | Prevent users treating manual replacement (`provider_verified: false`) or unavailable reconciliation as completed integration. |
| Unsupported absolute claims | Remove from active product copy | Avoid universal zero-knowledge, enforced MFA, fixed dedup savings, whole-tree atomic restore, complete erasure, or certified accessibility claims beyond evidence. |
| New staking/token/settlement functionality | Defer | Adds complexity without closing the current assurance, capacity, and recovery gaps. |
| Legacy snapshot/recovery support | Retain with explicit mode selection | Removing it before verified migration would risk historical data access. |

Do not re-add already delivered features as new roadmap items: stdin input, batch materialization, restore dry-run, bounded telemetry, local versioned KEKs, and the remote plaintext drill are implemented. Their remaining work is usability, assurance, or production-scale validation.

## Recommended next development sequence

1. **Complete the release safety foundation:** restore human review, establish scheduled backup ownership/alerts and independent key custody, exercise clean-machine recovery, and define the same-key authority renewal protocol boundary.
2. **Close security assurance and policy:** commission independent review; implement enforced factor/step-up policy; retest findings; decide and rehearse the v2 reader/writer rollout while documenting old v1 exposure.
3. **Establish a measured operating envelope:** run sustained networked account/operator workloads and failure cases; publish supported sizes/concurrency; design compaction, retention, and aggregate memory controls from measurements.
4. **Improve daily use:** simplify onboarding, complete scoped browser journeys, perform manual accessibility checks, and decompose large modules while retaining negative security regressions.
5. **Expand integrations deliberately:** verified workload/provider/KMS adapters and independent placement follow the tested custody, policy, and capacity foundation. Revisit economic features afterward.

No calendar estimates are assigned because independent reviewers, actual workload targets, and custody owners have not been established. Each stage should close using the evidence in the priority table, rather than treating source implementation alone as completion.

## Review references

- [Original project audit and baseline ratings](PROJECT_AUDIT_2026-09-30.md)
- [Finding-level remediation details](AUDIT_REMEDIATION_2026-09-30.md)
- [Release, deployment, backup, and process ledger](DEPLOYMENT_2026-09-30.md)
- [Current security and operational guarantees](../docs/CURRENT_SECURITY_GUARANTEES.md)
- [V2 chunk construction and compatibility](../crates/snapshot/CHUNK_PROTOCOL_V2.md)
- [Account backup and recovery procedure](../docs/ACCOUNT_BACKUP_AND_RECOVERY.md)
- [Account authorization and scoped behavior](../services/account/README.md)
- [Dependency exception policy](../docs/DEPENDENCY_AUDIT.md)
- [HTTP response and discovery limits](../crates/storage/HTTP_RESPONSE_LIMITS.md)
- [Platform support and hardware boundaries](../docs/PLATFORM_SUPPORT.md)

The original audit remains the historical baseline. This report is the current reassessment, and the dated deployment ledger supplies the completed production evidence that supersedes earlier statements about pending rollout or unexecuted cross-platform CI.
