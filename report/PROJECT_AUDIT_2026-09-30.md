# CipherVault: Whole-Project Audit and Improvement Report

**Review date:** 30 September 2026, Africa/Accra (UTC)

**Audited commit:** a9df97dfee9ae64f9c82ce48d9c4ddc67176dc78

**Workspace version:** 1.0.25

**Overall assessment:** 6.3/10

**Readiness for broad production use:** 4.5/10

**Review type:** source-based engineering audit, local automated checks, and isolated reproductions; not an independent cryptographic certification.

## 1. Honest assessment

CipherVault is a substantial, functioning software project with a useful purpose: protecting confidential development files, retaining their history, and enabling recovery without relying exclusively on a cloud account. Its Rust libraries, CLI, operator protocols, account service, tests, and deployment pipeline contain considerable real implementation. It is much more than a concept or a polished landing page.

The main weakness is **how the implemented mechanisms compose**. Authentication does not consistently preserve authorization scope; selecting another workspace does not consistently change the file root; recovery has unresolved history and log-growth problems; and the unattended maintenance executable does not perform the durability checks its name suggests. The existing tests exercise many individual mechanisms, but miss several important transitions between them.

A particularly important finding is that FastCDC plaintext boundary preservation does **not** translate into encrypted chunk reuse when a file changes. Whole-file-dependent encryption keys and wire metadata change all encrypted chunk identifiers. The advertised localized-edit deduplication benefit therefore needs correction or a protocol redesign.

An additional privacy finding was reproduced with synthetic data: an operator-visible, unkeyed file-version identifier permits offline confirmation of guessed complete-file contents. This does not decrypt arbitrary secrets, but it contradicts stronger opaque-object claims for predictable files.

My recommendation is to treat the current release as a **controlled beta with explicit limits**. Prioritize authorization, snapshot capture, recovery correctness, and honest health reporting before expanding the network, adding economic features, or presenting the system as enterprise-ready.

Earlier internal reports include 9+/10 ratings and production-ready language. Those are historical assessments, not proof of current correctness or independent certification. In particular, docs/SECURITY_AUDIT_READINESS.md explicitly says no external security audit has occurred, and docs/MAINNET_READINESS.md still lists external gates. The findings below explain why this review gives a lower score.

## 2. Scope, method, and limitations

### Coverage

The tracked repository contains **486 files**, including **196 Rust files with 98,352 physical lines**, two web applications, Solidity contracts, deployment assets, and extensive documentation. These counts describe size, not quality.

| Area reviewed | Components | Focus |
|---|---|---|
| Cryptography and formats | crypto, format, redact | Key derivation, encryption, secret containers, signed formats, trust boundaries |
| Local data and recovery | snapshot, local-store, recovery, file-lock | Persistence, path handling, capture, restore, guardian recovery, key lifecycle |
| Remote storage | storage, operator | HTTP/P2P authorization, quotas, leases, quorum, discovery, recovery logs |
| Hosted control plane | account | Sessions, scope tokens, roles, secret values, rotation, repository integrations |
| Automation | agent, maintenance | Watcher loop, retries, health reporting, audit/repair/renewal scheduling |
| User interfaces | CLI, TUI, dashboard, landing | Workspace handling, execution, user journeys, browser policy, accessibility checks |
| Distribution and operations | contracts, CI workflows, Docker, GCP, installers, service/runbook assets | Release trust, deployment posture, support claims, observability |
| Evidence | Rust tests, Node checks, selected operational reports and ADRs | Actual coverage versus stated assurance |

All 13 Rust workspace members were included. Review depth was concentrated on security and data-recovery boundaries, persistence, operational entry points, and user-facing integration. This was not a line-by-line formal verification of every source file. Archived binary/source bundles were inventoried, not reverse-engineered. Local vaults, private keys, credential files, and deployed fleet state were excluded from inspection.

The working tree was clean at the start. Application code was not changed. No production writes, deployments, messages, or destructive recovery exercises were performed.

### How to interpret findings

- **High priority / P1:** fix before relying on the affected feature for sensitive production workloads.
- **Medium priority / P2:** an important correctness, isolation, capacity, or operational gap.
- **Low priority / P3:** polish, maintainability, documentation, or a narrower hardening issue.
- **High confidence, source:** the relevant execution path is present in the audited code; the described scenario was not exploited against a live service.
- **Reproduced locally:** a synthetic, isolated test exercised the relevant behavior.

Source references below are repository-relative paths and one-based line numbers at the audited commit. Static findings describe code behavior and prerequisites; they do not imply that the current public deployment has been compromised.

## 3. Ratings and their basis

The overall rating is a weighted engineering judgment. Tests and feature breadth earn credit; unresolved security and recovery defects carry more weight than presentation.

| Dimension | Weight | Score /10 | Reason |
|---|---:|---:|---|
| Architecture and product foundation | 10% | 8.0 | Useful problem, sensible library separation, meaningful protocol and client implementation |
| Security and authorization | 25% | 5.0 | Strong primitives and guards, but scope issuance, narrowing, administration, and key lifecycle gaps |
| Data integrity, recovery, and reliability | 20% | 5.5 | Good verification foundations; missed captures, history selection, long logs, and misleading maintenance status |
| Maintainability | 10% | 6.5 | Modular workspace, large integration modules, duplicated execution paths and mutable global context |
| User experience and functionality | 10% | 7.0 | Rich CLI/TUI/dashboard; workspace hazards, browser policy defects, and incomplete scoped workflows |
| Testing and verification | 10% | 7.5 | Broad automated coverage; important cross-boundary, browser, crash, and long-history scenarios missing |
| Operations and distribution | 10% | 7.5 | Signed updates/images, non-root containers, deployment verification and rollback; installer trust parity and observability gaps |
| Documentation and claim accuracy | 5% | 5.5 | Extensive material, but stale support statements and security/performance claims exceed evidence |
| **Weighted total** | **100%** | **6.3** | Unrounded weighted result: 6.275 |

The separate **4.5/10 production-readiness rating** reflects whether the project can safely be entrusted with sensitive multi-user workloads and unattended recovery today. It is lower because a working happy path and a passing suite do not close the authorization and durability findings. Neither score is a formal standard, measured probability, or security certification.

## 4. Architecture and actual feature maturity

### Two confidentiality models must be explained separately

| Plane | What is implemented | Who can see plaintext? |
|---|---|---|
| Original file backup | Client-side encryption, signed snapshots, replicated ciphertext, offline-root recovery | The client that holds the keys; operators receive encrypted objects |
| Hosted scoped secret management | Projects/environments, roles, encrypted secret versions, server-side KEK, value retrieval, scope tokens, migration and audit | The account service processes plaintext and can decrypt scoped values |

The hosted scoped-secret plane is **not universally zero-knowledge to its server**. Its runtime loads a local KEK in services/account/src/secret_routes.rs:252 and unwraps values at :452. A general statement that vault plaintext never enters the service does not adequately describe both planes.

### Feature inventory

| Capability | Assessment |
|---|---|
| File snapshots, encrypted backup, local restore | Implemented; correctness concerns identified below |
| Operator confidentiality | Payload encryption exists; visible file metadata and complete-file candidate confirmation require correction |
| FastCDC | Implemented; raw chunk preservation is distinct from encrypted deduplication |
| Quorum replication and proof readback | Implemented; meaningful verification before counting successful replicas |
| Recovery kits, guardian shares, signed recovery trust | Implemented; multi-writer ordering and share-set validation need improvement |
| Scoped secrets and project/environment separation | Implemented today; older “no scoping” reports are outdated |
| Roles, token revocation, optional key binding, audit chains | Implemented; narrowing and credential-issuance rules need correction |
| Local/private dashboard and public explorer | Implemented with distinct route sets and useful guardrails |
| Scoped dashboard | Primarily read-only inventory; not full browser secret management |
| Automatic watcher | Implemented; fallback capture acknowledgment is incorrect |
| Maintenance engine | Stronger object audit/repair functions exist in the library |
| Maintenance daemon | Reachability and nonempty-log checks; full engine scheduling is not wired in |
| Provider credential rotation | Manual value/version replacement exists; runtime provider verification uses a no-op |
| Repository reconciliation | Scaffolding and tests exist; runtime ownership verification uses an unavailable provider client |
| TOTP | Alternate code-based login exists; enforced multi-factor policy is not established |
| Hardware token support | Windows PC/SC path exists; platform support is limited, as the support matrix acknowledges |
| Chain registry | Minimal opaque commitment publication; not an EIP-712 permission or settlement contract |
| Signed releases and image promotion | Implemented; bootstrap installers do not share updater signature enforcement |

The scoped CRUD, audit, migration, and role work should be preserved. Recommendations should strengthen it rather than re-propose features already present.

## 5. Priority findings

### F01 — Scope-token issuance can bypass authentication-strength and branch gates

**Priority:** P1. **Confidence:** high, source.

Recovery sessions are intended to enroll a device before making sensitive account changes (services/account/src/guards.rs:85). However, post_scope_token checks only an authenticated session and project membership (secret_routes.rs:991), not require_strong_session. It can issue a token for up to one hour (:1051).

The route also signs the caller-supplied branch string (:1063). The production policy treats branch == main as satisfying its gate (services/account/src/policy.rs:229). A member with a restricted recovery session can therefore request a production-scoped token with that branch claim and exercise the actions allowed by the member's project role. This does not create a role for a nonmember; it bypasses additional gates on an existing member.

**Improve:** require strong, recent authentication for credential issuance; bind issued credentials to their authentication context and appropriate revocation rules; derive branch/workload claims from a verified CI/provider identity. Add negative tests for recovery login → token mint and self-declared main-branch access.

### F02 — Narrow workload tokens can authorize broader project administration

**Priority:** P1. **Confidence:** high, source.

The central policy ignores environment restrictions when the target has no environment, and checks repository/service restrictions only when the target supplies those fields (policy.rs:205). Membership-management routes authorize a broad project target (secret_routes.rs:782 and :829).

A development-scoped token belonging to an admin can consequently retain project-wide membership-management power. A stolen narrow credential can affect access beyond its advertised scope.

**Improve:** separate human/project administration credentials from workload credentials. Reject narrowed tokens against broader targets unless an explicit capability permits that action. Test environment/repository/service-restricted tokens against every administration endpoint.

### F03 — Ordinary vault sessions receive operator fleet-control privileges

**Priority:** P1. **Confidence:** high, source.

services/operator/src/handlers.rs:53 accepts any valid vault session for require_control_auth. The same gate protects peer announcement, graduation, and global approval queries (:667, :828, :854). EnrolledIdentity.permissions is stored but not enforced during session authorization (services/operator/src/state.rs:568 and :1310).

An enrolled storage tenant should not automatically have fleet administration powers. Peer insertion impact depends on the configured trusted-peer allowlist, but the authorization boundary itself is too broad.

**Improve:** require explicit administrator capability or the service-token path for fleet controls, enforce permission bits on normal operations, and scope approval access to the caller's vault.

### F04 — Bound operator sessions lose their account/device identity after login

**Priority:** P1. **Confidence:** high, source.

The challenge validates account/device bindings (state.rs:1109 and :1163), but the persisted session does not carry that full binding (:993). Later authorization calls is_identity_enrolled with no account/device information (:1320), while enrollment matching requires those bound fields (:526).

In enrollment mode, a correctly bound user can obtain a token and then have ordinary object operations rejected. A test that ends at successful login misses this integration failure.

**Improve:** persist a complete typed session identity and use it for each authorization check. Test login → PUT → GET → restart → revoke for account/device-bound identities.

### F05 — Operator strict-auth and enrollment defaults disagree

**Priority:** P1 for affected configurations. **Confidence:** high, source.

Daemon startup and handlers default strict authentication to true (main.rs:233; handlers.rs:33). State enrollment enforcement only enables itself when an environment flag explicitly says true (state.rs:484).

**Affected setup:** SERVICE_TOKEN is configured, but STRICT_AUTH and REQUIRE_ENROLLMENT are unset. Startup succeeds, while an arbitrary signing key can obtain a vault session. Combined with F03, the effect extends beyond ordinary writes. Completely unconfigured startup does refuse to run; compose files explicitly enabling strict mode avoid this specific default mismatch.

**Improve:** parse one security configuration and share it across startup, HTTP, P2P, and state. Strict mode should require enrollment by default. Add a configuration-matrix test.

### F06 — Dashboard workspace selection can mix secrets between projects

**Priority:** P1. **Confidence:** high, source.

Workspace switching changes ACTIVE_VAULT_PATH (apps/cli/src/dashboard/files_api.rs:317 and :319), but push takes its source root from process current_dir (apps/cli/src/commands/push.rs:84). Restore defaults its destination to the process directory (restore.rs:47); tracking also uses that directory.

If the dashboard starts in project A, switches to B, and both track a relative .env file, pushing can put A's contents into B's vault. Restoring can write B's contents into A. Selection is also process-global across browser tabs.

**Improve:** pass an immutable VaultContext containing database path, vault ID, and project root through every operation. Bind requests to an explicit workspace ID. Test two projects with identical relative filenames and concurrent tabs.

### F07 — Portable keystore provisioning can replace an existing master key

**Priority:** P1. **Confidence:** high, source; chiefly non-Windows.

crates/local-store/src/keyring.rs:258 generates a new key on any resolve_key error. The fallback opens the key file with create and truncate (:272), rather than exclusively provisioning a missing key.

Concurrent first use can protect records with different keys while one process overwrites the other key file. Invalid/unreadable configuration also enters the replacement path. Previously protected epoch, device, or account material can become unreadable.

**Improve:** distinguish missing, malformed, and inaccessible key states. Use exclusive creation, lock provisioning, reread the winning key, and fail on existing-key errors. Never silently rotate a master key as error recovery.

### F08 — Watcher fallback polling can silently omit a snapshot

**Priority:** P1. **Confidence:** high, source.

check_for_changes immediately updates its digest cache (apps/agent/src/watcher.rs:110). Fallback polling invokes it (:564), then schedules debounce (:570). When debounce expires, a second check (:483) sees the already-updated cache and skips capture (:541).

This defeats the fallback for dropped native filesystem events. Advancing the cache before a capture that later fails creates a related acknowledgment problem.

**Improve:** maintain dirty/detected state separately from successfully committed hashes. Acknowledge content only after local persistence. Exercise the real loop in tests with polling-only changes and failed capture retries.

### F09 — The maintenance daemon's healthy label does not establish recoverability

**Priority:** P1. **Confidence:** high, source.

services/maintenance/src/main.rs:185 checks operator reachability. At :223 it counts any nonempty recovery log as a replica, and :232 turns those counts into a healthy result.

Three genesis-only logs can qualify while every manifest and encrypted chunk is missing. Duplicate operator identities/endpoints also need deduplication. The executable does not schedule the stronger MaintenanceEngine object audits, repair, or renewal functions.

**Improve:** distinguish reachable, metadata present, closure verified, and recoverable states. Schedule verified inventory audits, count distinct trusted operator identities, repair deficits, and verify renewed leases. Add a daemon-level test deleting a referenced chunk while retaining the recovery log.

### F10 — Recovery-head ordering is incorrect for independent device histories

**Priority:** P1/P2, especially for multiple writers. **Confidence:** high, source.

crates/recovery/src/trust.rs:50 sorts heads by authority generation and device_counter, and treats equal counters with different snapshots as a conflict. Counters are local to a device (crates/local-store/src/db.rs:546).

A newer descendant from device B at counter 1 can lose to device A's old head at counter 100. Equal counters on different devices can also create a false fork without inspecting parent links.

**Improve:** resolve authenticated maximal heads through DAG ancestry, compare counters within a device, and distinguish true concurrent forks from ordinary cross-device descendants. Test these exact cases.

This also affects successive clean-machine recovery by one user: recovery creates a new device and resets its local counter while retaining the authority generation (apps/cli/src/commands/recover.rs:483; local-store/db.rs:422). A later recovery can therefore prefer the previous device's older, higher-counter head.

### F11 — Long recovery logs hide newer records and create large memory spikes

**Priority:** P1. **Confidence:** high, source.

The HTTP response keeps the earliest records until a 16 MiB hex cap (operator handlers.rs:593), but the storage client ignores the truncated flag (crates/storage/src/transport.rs:528). There is no continuation cursor; the P2P response also lacks completeness signaling.

After roughly 8 MiB of raw prefix data, newer heads can be omitted indefinitely. Before enforcing the response cap, state.rs:2218 reads the complete log and copies complete records. Defaults permit 10,000 records of 64 KiB: approximately 625 MiB of log bytes plus 625 MiB of record copies for a near-limit read, excluding encoding overhead. Anonymous reads intentionally support clean-machine recovery, making efficient bounds important. Append validation also scans prior records.

**Improve:** streaming pagination with explicit completeness, current-head indexes, total byte limits, and authenticated checkpoints/compaction. Make clients fail explicitly when discovery is incomplete rather than trusting a prefix.

### F12 — Recovery-log append checks are not atomic, and torn tails are not recovered

**Priority:** P1/P2. **Confidence:** high, source; crash effects were not fault-injected.

Authorization/capacity checks read the log at state.rs:2001; the append lock is acquired later at :2168. Concurrent first-genesis writes can both observe an empty log, and concurrent writes can exceed capacity.

Length-prefix and payload writes are separate (:2179). A crash can leave an incomplete tail; reads stop there (:2225), while subsequent writes append after it without first recovering the tail. Later acknowledged records can remain invisible.

**Improve:** hold one locator lock across validation and append; track committed offsets or recover incomplete frames before accepting writes. Consider a transactional log. Add concurrent-genesis, capacity-race, and crash/restart tests.

### F13 — Localized edits do not preserve encrypted chunk identifiers

**Priority:** P1 for product claim/cost correctness; protocol work requires cryptographic review. **Confidence:** source-confirmed; isolated reproduction recorded in section 11.

crates/snapshot/src/chunker.rs:47 derives the file-version key from the hash of the whole plaintext. Each wire chunk also carries the whole-file version ID (:74), which influences authenticated metadata and its CID. An edit anywhere changes that key and metadata for every chunk.

FastCDC can preserve raw chunk contents while **all encrypted chunk CIDs change**. Unchanged whole files can still deduplicate. Those are different properties.

The existing encrypted dedup test uses an unchanged file (chunker.rs:131), while the boundary-preservation test compares raw slices (fastcdc.rs:199). Neither establishes the README's claim that a local edit uploads only a small slice or preserves 25/26 encrypted chunks.

**Improve:** immediately qualify the dedup claims. Add an encrypted end-to-end changed-file reuse benchmark. If cross-version chunk reuse is required, design a versioned, reviewed chunk encryption/addressing scheme whose stable identity does not depend on whole-file metadata or shifted positions. Do not make an ad hoc cryptographic change.

### F14 — Historical restore and snapshot execution select the current epoch key

**Priority:** P2, central to version-history functionality. **Confidence:** high, source.

apps/cli/src/commands/restore.rs:26 fetches the current device epoch key before selecting the record, then derives using record.epoch (:77). Snapshot-mode run similarly loads the current key at run.rs:252 and derives from the selected record's epoch at :277.

Different epochs have independent key bytes. Supplying an older epoch number to the current key does not recover the historical key, even though old keys are retained in the store.

**Improve:** select and verify the record first, then load get_epoch_key(record.epoch). Add historical restore, diff, and run tests across an actual key rotation.

### F15 — Restore safety has publication and Windows-permission gaps

**Priority:** P2; potentially high confidentiality impact in a shared destination. **Confidence:** high, source.

Restore verifies data before publishing, which is good. It then replaces files sequentially (crates/snapshot/src/engine.rs:426 and :432). A later filesystem failure can leave earlier replacements in place; this is not a transaction across all files.

Windows staging uses File::create (:478), inherits the destination DACL, and does not apply the existing protected-DACL mechanism before plaintext is written. A shared readable destination can expose restored secrets to other users.

**Improve:** stage the full restore and use a directory swap for fresh destinations or a journal/rollback for merges. Create owner-restricted plaintext staging files before writing. Test failures after the first publication and restrictive permissions on Windows. Describe restore as integrity-prevalidated until publication is transactional.

### F16 — Lifetime quota accounting does not survive expiry and restart correctly

**Priority:** P2. **Confidence:** high, source.

crates/storage/src/vouchers.rs:324 prunes expired voucher entries while retaining lifetime totals in memory. Persistence serializes the surviving entries (:333); restart reconstructs holder totals only from those entries (:355).

Expired spend can disappear from lifetime accounting although stored objects remain. Fresh vouchers can exceed the intended lifetime limit.

**Improve:** persist lifetime totals independently of expiring grants and migrate the ledger format. Test spend → expire → prune → persist → restart → new voucher.

### F17 — Lease renewal checks validity but not ownership

**Priority:** P2. **Confidence:** high, source.

The renewal handler checks the caller's session (operator handlers.rs:542), but renewal validates receipt identity/bytes rather than the owning vault (state.rs:1840). The handler subsequently overwrites the ownership sidecar with the caller's vault (handlers.rs:559).

A caller who learns another lease's random ID and byte count can renew it and change its listing ownership. This requires disclosure or knowledge; blind guessing is not a plausible prerequisite.

**Improve:** make ownership part of durable lease state, enforce it on renewal, and fail if owner persistence fails. Verify renewal signatures and binding before replacing a lease promise in the maintenance client as well.

### F18 — Bootstrap installers verify checksums without release signatures

**Priority:** P1 for the distribution trust model. **Confidence:** high, source.

The Rust updater verifies a pinned Ed25519 signature before archive checksums (apps/cli/src/commands/update.rs:531). The PowerShell and shell installers download the archive and SHA256SUMS and compare hashes, but never fetch or verify SHA256SUMS.txt.sig (dist/scripts/install.ps1:135 and :163; install.sh:69 and :98).

An attacker who can replace both release assets and their checksum file can satisfy those installers without possessing the signing key. HTTPS remains a transport safeguard, but it does not provide the updater's independent signer guarantee.

There is a narrower metadata issue: the updater signs the sums bytes, not the envelope tag (update.rs:303 and :335). Its exact tag-containing archive checksum lookup mitigates a simple old-archive replay, so this review does **not** claim a complete updater replay bypass.

**Improve:** use one pinned, independent verifier and a canonical signed manifest containing version, target, and artifact digests across installers and updater. Add tampered-archive-and-checksum bootstrap tests. Do not verify an untrusted download by executing that download.

### F19 — Dashboard CSP conflicts with shipped markup and breaks an action

**Priority:** P2. **Confidence:** reproduced in an isolated Chrome session.

apps/cli/src/dashboard/router.rs:42 permits self-hosted scripts/styles but not inline handlers/styles. The empty-state Calculate Diff button relies on onclick (apps/ui/index.html:730); the real listener is on another button (app.js:3947). Push Initial Snapshot also uses an inline generated handler (app.js:1709).

The browser reproduction confirmed that Calculate Diff did not forward its click under the exact CSP. Existing Node checks passed because their fake DOM does not enforce browser policy.

**Improve:** replace inline handlers with addEventListener and markup styles with classes. Keep the restrictive CSP. Test the actually served page, empty states, and console/security-policy errors. Direct element.style assignments are not automatically covered by this finding, and some hidden controls have valid stylesheet fallbacks.

### F20 — Operator rate-limit identity can be spoofed or collapse to one shared bucket

**Priority:** P2. **Confidence:** high, source.

services/operator/src/lib.rs:219 trusts the first X-Forwarded-For value from the request. The daemon's router serving path does not install ConnectInfo (main.rs:486). Direct callers without forwarding headers share an unknown bucket; callers supplying arbitrary headers can rotate apparent identities.

**Improve:** use actual connection metadata and trust forwarding headers only from configured proxy addresses. Combine source limits with authenticated principal/operation limits. Apply issuance quotas to account-key login challenges too; that path omits the account auth limiter used elsewhere (services/account/src/sessions.rs:29).

### F21 — Operator-visible file identifiers allow offline complete-file candidate confirmation

**Priority:** P1/P2, depending on file predictability. **Confidence:** source-confirmed and reproduced with synthetic data.

The client uploads the entire ChunkWireObject as plaintext CBOR around an encrypted payload (crates/local-store/src/db.rs:908; apps/cli/src/commands/push.rs:193). Its visible header includes vault ID, file-version ID, chunk index/count, declared padded length, and epoch (crates/format/src/schema.rs:153).

The file-version identifier is an unkeyed BLAKE2b hash of a domain string, public vault ID, public epoch, and the whole plaintext SHA-256 (crates/crypto/src/kdf.rs:75). An operator can compute the identifier for candidate full files and compare it with the uploaded header without knowing the encryption key.

For a known configuration template with a low-entropy value, this permits offline candidate confirmation. It does **not** decrypt arbitrary ciphertext or make high-entropy, unknown complete files guessable. Operators can also group chunks by file version and observe counts, positions, padded lengths, and epochs.

**Improve:** make identifiers secret-keyed or otherwise hide this confirmation oracle in a reviewed, versioned protocol. Review this together with F13, since privacy, stable addressing, deduplication, and authenticated metadata interact. Correct the confidentiality documentation immediately and add low-entropy candidate-confirmation regression tests for the replacement design.

## 6. Additional improvements and latent risks

These are worth tracking without obscuring the priority findings.

| Area | Evidence | Improvement |
|---|---|---|
| Account-file crash safety | local-store/account.rs:521 removes the old file before rename and lacks durable sync | Unique exclusive staging, platform atomic replacement, fsync, owner-restricted permissions |
| Capture symlink escape | snapshot/engine.rs:74 validates lexical path but metadata/open follow links | Reject symlinks/reparse points or use trusted directory-handle opens with an explicit external-file policy |
| Guardian share mixing | recovery/kit.rs:350 checks vault/threshold but not a splitting-set identity or reconstructed public descriptors | Add share-set ID; validate shared descriptors and reconstructed root-derived identity |
| Rotation idempotency | account/rotation.rs:75 returns today's version for a previously committed idempotency key | Persist and replay the original outcome and request digest |
| Memory cleanup | Recovery kit/share strings and intermediate plaintext/key buffers are ordinary containers | Use zeroizing ownership, reduce copies, qualify complete-memory-erasure claims |
| Child credential inheritance | cli/commands/run.rs:505 inherits parent environment, including scope credentials, by default | Strip CipherVault auth variables by default; permit explicit narrow passthrough |
| Safe noninteractive input | cli/commands/secret.rs:55 directs non-TTY callers to a plaintext value flag | Add value-stdin/protected-descriptor input; minimize token use in process arguments |
| Unverified UI label | ui/app.js:3033 hardcodes Ed25519 Verified without a backend verification result | Show observed verification status, provenance, and time |
| Repair source availability | maintenance/engine.rs:528 chooses the first surviving source | Try alternate verified sources and retain retry/job outcomes |
| Trust registry integration | storage/client.rs:148 implements get_info_pinned; inspected production paths use get_info | Apply trust pins in quorum, audit, discovery, and renewal |
| Discovery credential forwarding | storage/pool.rs:100 accepts self-signed discovery endpoints; transport.rs:239 can attach global service token | Restrict discovery and avoid sending admin credentials to untrusted endpoints; production use of expansion was not found |
| Storage lifecycle | Objects persist; lease metadata and retained disk usage need a coherent capacity policy | Enforce byte/inode ceilings, ownership inventory, retention terms, and safe cleanup |

The discovery issue is a **latent library integration risk**, not a demonstrated leak from the deployed system. Do not treat a self-signature as proof that an arbitrary endpoint is a trusted member.

## 7. Bottlenecks and performance limits

These conclusions distinguish structural bottlenecks from measured production behavior. This audit did not generate a production traffic profile.

| Bottleneck | Why it matters | Recommended change and measurement |
|---|---|---|
| Changed files produce entirely new encrypted chunks | Reduces the advertised upload/storage savings | Correct F13; measure encrypted CIDs and actual network bytes across edits |
| Account service has one global SQLite connection mutex | Requests serialize despite WAL; quota/audit writes share the bottleneck | Bounded DB actor/blocking workers, suitable read isolation, measure lock wait and networked p95/p99 |
| Blocking disk/crypto in async HTTP and the sole swarm loop | Slow disks/log scans can delay unrelated RPCs and heartbeats | Bounded worker queues; isolate recovery reads and fsync; measure event-loop stalls |
| Full-log scans and record copies | Recovery memory can exceed a gigabyte; repeated append scans grow cumulative work | Streaming cursors, indexes, compaction; test near-cap logs under concurrent reads |
| File-size checks happen after read_to_end | Oversized files can allocate before the 256 MiB rejection; snapshots/restores retain large aggregates | Precheck size, bounded reads, aggregate budgets, streaming staging; measure peak memory |
| Watcher queue and replication share one loop | Unbounded events plus slow uploads delay capture and shutdown | Coalesce bounded events, separate capture/upload workers, cancellation and backlog metrics |
| Recovery fetch waits for join_all | A healthy replica can be delayed by another endpoint's three 15-second timeout attempts | Return the first integrity-verified success; cancel excess work; inject one slow endpoint |
| Scoped run reads one secret at a time | Startup grows with secret count and may mix versions during rotation | Authorized batch materialization with revision pinning, pagination, bounded concurrency |
| Private SSE samples operators and PC/SC per client every few seconds | Multiple tabs duplicate expensive probing | Shared telemetry sampler and cached results; measure requests/probes per active client |
| Dashboard refresh loads many panels and rescans workspaces | Repeated filesystem/DB work exceeds what the visible tab needs | Registry/cache and on-demand panels; measure idle versus active refresh cost |
| Large frontend modules | Change risk and duplicate CSS/DOM logic increase as features grow | Modular vanilla JS and CSS by responsibility; framework migration is optional |
| Large build/dependency surface | Local debug builds require considerable disk and time | Publish disk guidance, bounded CI caches, intentional feature boundaries and reproducible toolchains |

Relevant anchors: account/state.rs:30 and :45; operator/swarm/mod.rs:1322; snapshot/engine.rs:93; watcher.rs:405 and :515; storage/pool.rs fetch_object_from_any; run.rs:142; dashboard/handlers.rs:1099.

UI app.js has **5,674 physical lines / 241,143 bytes**; its CSS is **133,330 bytes** and HTML **107,999 bytes**. Large files alone do not prove slow rendering, but they are clear refactoring candidates. Keep current hidden-tab polling pause behavior.

Existing load documentation records useful small local and paced fleet tests. Its in-process account load numbers and ten small fleet rounds do not establish a sustained multi-tenant production capacity envelope. Preserve FULL durability while measuring; weakening persistence just to improve a benchmark would hide the real tradeoff.

## 8. Strengths, disadvantages, and project direction

### Strengths to preserve

1. **Clear user value:** confidential files excluded from Git need history and recovery.
2. **Meaningful crypto foundations:** standard AEAD/signature libraries, random root/epoch keys, secret wrappers, domain-separated operations, encrypted manifests, and offline-root device certificates.
3. **Real integrity checks:** ciphertext addressing, signed receipts, proof readback, distinct operator identities in replication quorum, and all-file verification before restore publication.
4. **Good modular foundations:** the crate boundaries are useful even though some integration files have grown too large.
5. **Substantial testing:** authentication, signing/tampering, transport conformance, persistence, chaos, migration, recovery, watcher, and UI regressions are present.
6. **Helpful local security design:** loopback-only private dashboard, Origin/Host checks, expiring HttpOnly cookies, no-store responses, public/private route separation, and sanitized recovery descriptors.
7. **Thoughtful migration safeguards:** ledgered adoption, verification, quarantine, and checks before deleting legacy state.
8. **Operational investment:** non-root images, digest pinning in promotion paths, Cosign signatures, signed Rust updates, verification/rollback scripts, platform bundles, and runbooks.
9. **Practical interfaces:** CLI automation, TUI operation, and visual inspection each have a useful audience.

### Disadvantages and tradeoffs

- The scope now spans backup, hosted secret management, account identity, P2P storage, recovery governance, blockchain, and three interaction surfaces. Each adds failure modes and ongoing maintenance.
- End-to-end correctness has lagged behind feature count: many mechanisms work independently but compose incorrectly.
- The hosted secret model introduces server key custody alongside the original client-encrypted model; users need to choose deliberately.
- Permissioned membership, configured operators, and fleet administration mean operational independence is more limited than broad decentralization language suggests.
- A three-node count does not prove three independent organizations, clouds, or failure domains. September deployment reports describe a GCP-based fleet; current live diversity was not verified here.
- Portable file-backed keys are not equivalent to macOS Keychain/Linux secret-service protection. Hardware support is also uneven across platforms.
- Users must understand modes, scopes, account links, epochs, operators, leases, and migration. Onboarding currently asks for too much architecture knowledge.
- A custom KDF and deterministic chunk encryption require independent cryptographic review. This audit identifies a metadata confirmation oracle, not a break of the underlying AEAD or signature primitives.
- Immutable object retention without a complete policy creates disk/cost growth and complicates deletion expectations.
- Attractive diagrams and demos can overstate maturity unless unavailable features and observed evidence are clearly labeled.

### Documentation and claim corrections

| Current claim or inconsistency | More accurate treatment |
|---|---|
| Localized-edit 96.15% deduplication | Raw boundary preservation is not encrypted CID reuse; report changed-file encrypted measurements |
| Universal zero-knowledge / no server plaintext | Distinguish client-encrypted backup from server-decrypted scoped secrets |
| Autonomous maintenance / healthy replicas | Describe the daemon's actual checks until engine scheduling is wired in |
| TOTP MFA | Rename as alternate login or implement enforced multi-factor and step-up policy |
| Atomic restore | Distinguish integrity prevalidation and per-file replacement from a multi-file transaction |
| Complete zeroization or protection from all dumps/swap | State which owned buffers are wiped and what OS/process exposure remains |
| Operators cannot infer file sizes | They observe object lengths/counts and traffic; small-file padding does not remove all metadata leakage |
| Operator objects are opaque random-looking blobs | Wire headers reveal grouping/epoch/size metadata, and unkeyed file IDs permit candidate confirmation |
| EIP-712 checkpoints | The current registry publishes opaque commitments; it does not validate EIP-712 signatures |
| Rust 1.80+ | Resolved libp2p packages declare Rust 1.88; establish and test a real MSRV |
| Zero external C FFI dependencies | SQLite bundling, PC/SC, and platform APIs contradict an absolute no-FFI statement |
| Full WCAG 2.1 AA assurance from Node audit | Describe string/DOM regression checks; add real accessibility verification |
| SECURITY.md supports current v0.1.x pre-release | Update the supported-version policy for the 1.0.25 release line |
| Guaranteed forensic shredding | Explain filesystem, SSD, backup, and copy limitations; use precise removal terminology |

README examples and operational evidence should be generated from one release source where possible. Avoid maintaining contradictory “certified production-ready” and “external audit pending” statements.

## 9. Recommended features, enhancements, and removals

### Highest-value additions and enhancements

| Recommendation | Existing foundation to extend | Expected value | Relative effort |
|---|---|---|---|
| Verified recovery status and rehearsal | Recovery library, maintenance engine, explorer | Show last isolated restore, authenticated head, forks, missing objects/envelopes, lease expiry | Medium/large |
| Explicit workspace/scope context | Dashboard switching, context commands | Prevent cross-project mixing; clear project/environment in every action | Medium |
| Real workload identity and branch attestation | Scope tokens, optional key binding | Short-lived CI credentials without self-declared production claims | Large |
| Enforced step-up and credential capabilities | Passkeys, TOTP, account roles | Protect token issuance, reveals, exports, administration and recovery changes | Medium/large |
| Recovery log pagination/checkpoints | Signed log records | Reliable long-lived recovery with bounded memory | Large |
| Restore preview and resumable publication | Verified restore | Overwrite/conflict policy, exact-versus-merge mode, rollback/journal and permission checks | Medium/large |
| Batch scoped materialization | Scoped run, value routes | Consistent secret versions and faster app startup for larger environments | Medium |
| Versioned KEK/KMS integration | KEK service abstraction and wrapped DEKs | Safe rotation, historical key lookup, rewrapping, tested server backup/restore | Large |
| Safe stdin secret input and child token filtering | Protected prompts, run flags | Lower history/argument exposure and reduce child privileges | Small |
| Watcher health/backlog UI | Persistent retries and status surfaces | Users can see missed captures, local persistence, queued upload, and durability separately | Medium |
| Capacity and expiry forecasting | Metrics, leases, vouchers | Warn before disk/inode exhaustion or loss of retention | Medium |
| Complete provider integrations | RotationVerifier, ProviderClient, reconciliation seams | Verified repository ownership and provider-aware rotation without claiming scaffolding as complete | Large |
| Focused scoped browser workflow | Read-only inventory | Version history, audited step-up reveal, then create/edit/rotate after policy fixes | Medium/large |
| True failure-domain placement policy | Distinct operator-key quorum | Require regional/organizational diversity, not merely unique keys | Medium/large |

Relative effort is comparative, not a delivery commitment. Do not begin the large expansions before the high-priority correctness work is verified.

### Remove, restrict, simplify, or defer

- **Remove now:** inline event attributes conflicting with CSP; hardcoded verification labels; silent acceptance of truncated recovery results.
- **Restrict now:** normal vault sessions accessing fleet administration; narrowed workload credentials accessing project-wide management; admin service-token forwarding to arbitrary discovered endpoints.
- **Replace misleading labels:** metadata-present must not be shown as recoverable; manual secret replacement must not imply provider-verified rotation.
- **Hide unavailable integrations:** explicitly mark repository reconciliation/provider verification unavailable until real runtime clients exist.
- **Simplify onboarding:** default to choose project/environment → protect/import a secret → run an app → rehearse recovery. Put network, chain, and advanced crypto inspection behind an advanced view.
- **Defer new chain/economic features:** the commitment registry already provides a narrow useful function; staking, tokens, and settlement do not fix current backup/recovery risks.
- **Reduce duplicated interface behavior:** share context and command services between CLI/TUI/dashboard; retain useful surfaces but consolidate their implementation.
- **Keep legacy compatibility for now:** removing snapshot workflows before verified migration would increase data-loss risk. Make legacy/scoped mode selection explicit and documented.
- **Avoid a wholesale rewrite:** targeted boundary fixes and module decomposition are more valuable than replacing Rust, SQLite, or vanilla JavaScript wholesale.

## 10. Prioritized improvement plan

### Gate A — Correctness and access boundaries before broader deployment

1. Fix F01–F06: token issuance, scope narrowing, fleet permissions, bound sessions, consistent defaults, and workspace roots.
2. Fix F07–F12: safe key provisioning, watcher acknowledgment, actual recoverability checks, multi-device head resolution, paginated logs, and atomic durable append.
3. Address F14–F18: historical epoch lookup, restore publication/permissions, durable quotas, lease ownership, and installer signature verification.
4. Fix CSP behavior, address F21's metadata confirmation oracle, and correct high-impact product claims, especially F13 deduplication.

**Exit evidence:** isolated negative authorization tests; two-workspace and two-epoch tests; polling-only capture tests; missing-chunk maintenance tests; near-limit/paginated recovery tests; torn-tail restart tests; key-provisioning races; quota conservation; Windows ACL checks; bootstrap signature tampering; actual browser CSP flows.

### Gate B — Operational and UX reliability

1. Wire persisted repair/renewal jobs with retry, verified receipts, alternate sources, and observable backlog.
2. Add bounded streaming/blocking work and trusted-proxy rate-limit identities.
3. Test realistic histories and concurrency, including slow disks/endpoints, resource limits, rotation, revoked credentials, and restart boundaries.
4. Add safe input, child credential filtering, batch scope fetch, restore preview, and a simpler onboarding path.
5. Establish a browser/accessibility test suite and decompose large UI/backend integration modules.

**Exit evidence:** measured networked p95/p99, memory and disk usage, job recovery after restart, actual recovery drills, and documented workload/retention limits.

### Gate C — Expansion and independent assurance

1. Engage an independent audit covering crypto constructions, scope authorization, recovery, and release trust; retest fixes.
2. Complete versioned key lifecycle and tested backup/import for the hosted control plane.
3. Complete provider integrations and trustworthy CI identity.
4. Expand failure-domain diversity and define a supported operational capacity envelope.
5. Reconsider broader public network or settlement features only after these foundations are proven.

Do not use a version number, test badge, or deployment success as the sole release-readiness gate.

## 11. Verification performed and evidence limits

### Local environment

Windows/PowerShell; Rust 1.98.1; Cargo 1.98.1; Node 24.20.0. Cargo metadata resolves **502 packages**, including workspace packages. The dependency audit checked 502 lockfile packages against an advisory database last updated on 29 September 2026.

### Results

| Check | Result |
|---|---|
| cargo fmt --all -- --check | Passed |
| cargo test --workspace --locked --no-fail-fast | Passed: 737 tests, 0 failures, 3 ignored; exit 0 |
| cargo clippy --workspace --all-targets --locked -- -D warnings | Passed; exit 0 |
| node --check apps/ui/app.js | Passed |
| node apps/ui/audit.test.cjs | Passed |
| node scripts/verify_landing.cjs | Passed; element/CSS contract and algorithm vector checks |
| node tests/dashboard_container_contract.cjs | Passed |
| cargo audit --json | Exit 0; zero vulnerability-class entries; two unsound lru advisories and one unmaintained paste warning |
| Isolated Chrome CSP comparison | Defect reproduced; see below |
| Synthetic encrypted dedup probe | 10/11 raw chunks preserved; 0/11 encrypted chunk CIDs reused after edit; 11/11 unchanged-file CIDs reused |
| Synthetic operator metadata confirmation probe | Correctly distinguished 1 of 2 complete-file candidates using public header fields; no encryption key in confirmation |
| Foundry contract execution | Not run: forge is not available locally; contract source/tests were inspected |
| Production fleet health/soak | Not rerun; historical repository reports were treated as historical evidence |

**Browser reproduction:** the actual UI assets were served locally with synthetic API data and a fresh temporary Chrome profile. With the exact server CSP, clicking the Calculate Diff empty-state control forwarded **0** target clicks and produced **127 style-src-attr violations plus 1 script-src-attr violation**. The identical page without CSP forwarded **1** click with **0** violations. No real vault or credentials were used.

**Dedup reproduction:** an isolated Rust probe links the current snapshot/crypto libraries, uses fixed synthetic key material and the existing FastCDC test's generated configuration dataset, compares raw slices against encrypted CIDs, and verifies unchanged-file reuse. It performs no file backup or network upload. Probe source/logs are under the ignored .agents/audit-2026-09-30 directory.

The dataset changed from **230,000 to 230,032 bytes** by insertion. Both versions produced **11** chunks; **10** raw chunks matched, **0** encrypted CIDs matched, and an unchanged-file recapture matched **11/11** encrypted CIDs. This directly tests the encrypted addressing boundary, rather than interpreting raw slicing as network deduplication.

**Metadata confirmation reproduction:** a second isolated Rust probe serializes a synthetic encrypted chunk into the same CBOR wire object used for upload, parses its public header, and recomputes file-version identifiers for two possible complete configuration files. Exactly one candidate matches. The confirmation step uses only public vault/epoch/header fields and candidate hashes, with no encryption key.

**Dependency audit:** lru 0.12.5 enters through ratatui 0.29.0 → ciphervault-cli. RustSec classifies RUSTSEC-2026-0002 and RUSTSEC-2026-0253 as informational soundness advisories, so plain cargo audit succeeds. The latter requires specific panic/unwind/key-destructor conditions; their presence in the lockfile is not proof of a reachable project exploit. Upgrade the dependency chain or document a reachability assessment, and consider cargo audit --deny unsound in CI. paste 1.0.15 is also an unmaintained transitive dependency through ratatui.

The source contains **707 test attributes**, matching the README badge's counting method. The local run reported **737 passed, 0 failed, and 3 ignored across 75 result groups**, including documentation-test groups. Counts differ because source attributes and executed/generated/platform-gated tests are different measures. The ignored checks were scoped_load_gate, bench_push_sequential_vs_concurrent, and ten_node_chaos_gates; they were not counted as passes. Compilation took approximately 6 minutes; the entire workspace test command took approximately 13 minutes 18 seconds. Clippy took approximately 1 minute 36 seconds.

**Not established by this review:** full cryptographic soundness, constant-time behavior under all conditions, comprehensive WCAG conformance, Linux/macOS runtime behavior, installed hardware-token behavior, actual live secret/fleet custody, contractual availability, or sustained production capacity. Passing tests do not invalidate source-confirmed gaps outside their scenarios.

### Official references checked

- [RustSec: lru iterator soundness advisory](https://rustsec.org/advisories/RUSTSEC-2026-0002.html) and [lru panic-safety advisory](https://rustsec.org/advisories/RUSTSEC-2026-0253.html) support the dependency findings.
- [GitHub Actions secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use) recommends immutable commit-SHA action pins, minimal token privileges, and safer handling of untrusted script inputs. Many workflows still use mutable major-version action tags; release permissions should be narrowed per job.
- [Cargo rust-version documentation](https://doc.rust-lang.org/stable/cargo/reference/rust-version.html) supports declaring and testing a real minimum supported compiler. The current workspace omits that declaration while its resolved libp2p dependency declares 1.88.
- [Mozilla CSP script-src reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src) and [style-src reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src) describe the browser policy underlying F19.

These external references inform specific recommendations. Project findings are grounded in the local audited source and the isolated checks above.

## 12. Final recommendation

Keep building CipherVault, but redirect the next development cycle toward **trustworthy access boundaries and provable recovery**. The strongest improvements are fewer misleading success states, explicit contexts and capabilities, durable key/log/accounting transitions, and tests that cross real component boundaries.

The foundation is worth preserving. Its present feature breadth is ahead of its assurance. Closing the priority findings and validating unattended restore will improve the project more than adding another protocol, dashboard panel, or marketing claim.
