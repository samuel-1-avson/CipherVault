# CipherVault Decentralized Operator Network (DON) — Implementation Plan

**Status:** Phase 1 complete (2026-09-17); Phase 2 complete (2026-09-18); Phase 3 complete (2026-09-18, D3 barter + D6 redb decided) — static mode untouched.
**Parent spec:** `docs/DECENTRALIZED_ARCHITECTURE_SPEC.md` (reviewed; corrections folded into Phase 0)
**Target:** progressive, non-breaking path from the static federated cluster to a self-organizing operator mesh

## Goal

Deliver a decentralized CipherVault operator network in which independent operators discover each other, store content-addressed chunks, prove storage, and self-heal — while every static-mode workflow (`init --operators …`, private VPS clusters, local compose) keeps working byte-for-byte.

## Success Criteria

1. Static mode is untouched: the full workspace suite passes at every phase with zero test changes except additive ones.
2. Two operator nodes behind separate NATs discover each other and exchange a chunk end-to-end.
3. A 10-node containerized mesh survives 3 simultaneous node kills and returns every chunk to full replication without client involvement.
4. No permissionless write path exists without authorization and rate limits; disk-filling by an unauthenticated peer is demonstrated impossible.
5. A public testnet runs with independently operated nodes, published dashboards, and a chaos drill report.
6. Mainnet cutover (if approved) is staged with a proven per-phase rollback; production incidents attributable to the mesh are zero at 30 days.

## Context And Current Facts

- Replication today is an HTTP pipeline, not put/get: authenticate → PoS-dedup upload → lease commit → receipt-signature verify → readback verify → recovery-log append → discovery readback, with quorum early-exit (`crates/storage/src/pool.rs`, `replicate_and_verify`).
- HTTP peer gossip already exists and is signed: `announce_peer` / `get_peers` (`crates/storage/src/client.rs`), `PeerDescriptor` (`crates/storage/src/types.rs`), pool expansion (`discover_and_expand_peers`). The DHT identity/bootstrap layer should evolve from this, not start over.
- Content IDs are 32-byte **SHA-256** (`crates/format/src/canonical.rs`), not BLAKE2b — the parent spec's hash claims are corrected in Phase 0. Chunk encryption is XChaCha20-Poly1305 (`crates/crypto/src/aead.rs`).
- Chain access is hand-rolled JSON-RPC (`crates/storage/src/chain.rs`); the registry contract plus Foundry tests exist (`contracts/CipherVaultRegistry.sol`). Metrics are hand-rolled Prometheus exposition (`services/operator/src/metrics.rs`). A TUI surface exists (ratatui in workspace deps).
- No libp2p, QUIC, embedded-KV, or erasure-coding dependencies exist anywhere in the workspace today; all are additive.
- Live production is 3 GCE operator VMs plus an immutable web VM promoted by digest (`scripts/gcp/promote-immutable-web.ps1`). Any mesh rollout must plan around this topology.

## Constraints And Non-goals

- Constraints: static-mode CLI behavior frozen; `cargo test --workspace --locked`, clippy `-D warnings`, and `forge test` stay green on main at every merge boundary; one reviewable merge unit per phase.
- Non-goals: browser/WASM and mobile clients; token launch, liquidity, or exchange listings; additional chains; rewrites of `crypto`, `snapshot`, or `format` primitives; breaking changes to `vault.db` existing tables; removing the static operator mode.

## Key Decisions

- **D1 — Abstraction seam (recommended: transport-level, under the client).** Abstract the byte transport beneath `OperatorClient` (HTTP today, libp2p streams tomorrow) so leases, recovery logs, PoS fallback, readback, and quorum counting run identically on both paths. Rejected: the parent spec's 4-method pool trait — it cannot express the real pipeline and would fork the protocol.
- **D2 — P2P stack (recommended: rust-libp2p).** Kademlia + Gossipsub + request-response for chunk RPC; Noise + Yamux; QUIC with TCP fallback; relay + DCUtR + AutoNAT + identify + mDNS for connectivity; allow-block-list + connection-limits for DoS hygiene; libp2p-metrics for swarm telemetry. Rejected: a custom UDP/QUIC stack (re-implements NAT traversal and DHT security for no durable advantage). Other Rust P2P stacks were not evaluated; re-entry criterion is a failed Phase 2 connectivity spike.
- **D3 — Economics (decided 2026-09-18: barter/permissioned fleet first).** Operators allow-listed or stake-gated off-chain; on-chain settlement is a separable Phase 5 gated on a named gas payer, griefing analysis, and audit. Voucher issuer model: operators self-issue against their own quotas.
- **D4 — Write authorization (required before any public testnet).** Capability vouchers bound to operator quotas: no voucher, no bytes persisted. Rationale: an altruistic open-write mesh is disk-fillable on day one.
- **D5 — DHT record trust (recommended: signed records, client-side validation).** Provider/peer records carry ed25519 signatures over existing operator keys; unsigned or badly signed records are never trusted for reads or repair.
- **D6 — Object store (decided 2026-09-18: redb).** Spike measured redb 4.3.0 vs the file baseline at 1M objects on crash safety, throughput, build time, binary size, license fit (report: `docs/D6_OBJECT_STORE_SPIKE.md`): redb wins every measured column by 2.4x–840x with a 7/7 crash-probe record and a one-line license; RocksDB unmeasured (no host toolchain) and unneeded to break the tie. Carried conditions: re-baseline rates on Linux before capacity planning; RocksDB adapter kept in the spike crate if LSM behavior is ever needed.
- **D7 — Erasure coding (decided 2026-09-18: DECLINE for the 3-operator fleet).** Spike measured reed-solomon-simd 3.1.0 at (2,1)/(3,1)/(4,2)/(8,4)/(10,4) x 4KiB/64KiB/1MiB (report: `docs/D7_ERASURE_SPIKE.md`): codec runs GB/s with MIT+BSD licensing and a pure-Rust closure, but placement counting proves no (k, m) matches 3x durability below 3x overhead on 3 homes, and fragment repair costs k× reads (measured 2x/4x/10x) vs replication's 1x — failing the "without complicating repair" gate. Default stays 3x full replication. Revisit only with >= 5 placement homes + a large-blob tier + placement-aware repair.
- **D8 — Test harness (recommended: Testground plus containerized chaos nets).** In-memory swarms for unit tests only; every networking gate runs on multi-host containers with scripted kill/partition/latency faults.

## Recommended Approach

Reshape the parent spec's five phases into seven gated engineering phases below. The structural changes versus the parent spec: (1) transport-level seam instead of pool-level trait; (2) connectivity (NAT) proven before storage semantics move to P2P; (3) write authorization and DoS limits precede any public testnet; (4) economics deferred to an explicit decision gate; (5) production cutover planned from day one. Rough sizing assumes one senior Rust engineer with review (assumption, not a commitment): S ≤ 1 week, M 2–4 weeks, L 1–2 months.

## Work Plan

### Phase 0 — Corrections, telemetry baseline, decision prep (S)

- Publish a corrections appendix to the parent spec (SHA-256 CIDs, BFT terminology, trait reshape rationale).
- Extend existing Prometheus exposition with placeholder swarm metric names so later phases only fill values.
- Prepare the D3 economics decision packet (barter-fleet ops model vs staking/escrow mechanism sketch with gas-payer analysis).
- Gate: docs merged, metrics render unchanged output, D3 packet reviewed.
- ✅ Done: `docs/DON_SPEC_CORRECTIONS.md`, `docs/DON_ECONOMICS_DECISION.md`, swarm metric-name reservation + render golden test.

### Phase 1 — Transport seam + dual-transport conformance (M)

- New `crates/storage/src/transport.rs` (new): `OperatorTransport` trait expressing the existing wire operations (challenge, put, commit-lease, info, recovery append/read, peer announce/list) as request/response pairs.
- Port `OperatorClient` onto an `HttpTransport` with zero behavior change; `MultiOperatorPool` keeps its pipeline, early-exit, and error taxonomy intact.
- New loopback `MemoryTransport` enabling the full replication suite to run without sockets.
- New conformance suite: every replication scenario (push/pull/recover/repair, fault injection, quorum deficit) runs against both transports and asserts identical outcomes.
- Gate: `cargo test --workspace --locked` green with no modified tests; conformance suite green on both transports; clippy/fmt clean.
- ✅ Done (2026-09-17): `OperatorTransport` trait + verbatim `HttpTransport` port (`crates/storage/src/transport.rs`); `MemoryTransport` with real ed25519/PoS crypto and offline/put/append fault flags; dual suite `services/operator/tests/transport_conformance.rs` (12 cases × HTTP/memory legs, real Axum router vs memory) plus memory pool tests (`crates/storage/tests/transport_conformance.rs`: quorum deficit, failover, stats). Evidence: workspace suite 0 failures, `cargo clippy --all-targets -D warnings` clean, `cargo fmt --check` clean. No pre-existing test was modified; one Phase-1-new memory unit test was strengthened to match the authoritative renew-bytes rule. `forge test` not re-run locally (Foundry toolchain absent on this machine; no contract files touched by this phase).

### Phase 2 — libp2p swarm + proven connectivity (L)

- New `services/operator/src/swarm/` (new): Tokio swarm with Kademlia provider records, Gossipsub control topics, request-response chunk/get/PoS RPCs reusing CBOR codecs and existing auth envelopes; dual-stack QUIC+TCP, Noise, Yamux, identify, mDNS (LAN), relay client, DCUtR, AutoNAT.
- New `Libp2pTransport` implementing the Phase 1 trait; `--enable-p2p` dual mode (HTTP stays on its port).
- Signed DHT records per D5; rendezvous + signed bootstrap list for first contact.
- NAT ladder proof: two nodes behind separate NATs exchange chunks via relay→DCUtR upgrade, automated as a regression harness.
- Gate: conformance suite passes over the libp2p transport; hole-punch harness green; static-mode suite untouched.
- 🔶 In progress (2026-09-17): libp2p 0.57 pinned in workspace manifest; new `services/operator/src/swarm/` (identify, ping, Kademlia on `/ciphervault/kad/1.0.0`, Gossipsub control topic, mDNS toggle, `--enable-p2p` dual-mode daemon flag); full `/ciphervault/operator/1.0.0` CBOR RPC served from live `OperatorState` reusing the HTTP auth checks + state methods with identical status mapping (`swarm/serve.rs`); `Libp2pTransport` implementing the Phase 1 trait (`swarm/transport.rs`, dial-on-demand, vault-scope tracking, env service token); conformance suite extended to three legs — 12 cases × HTTP/memory/P2P, 36/36 green; `swarm.rs` two-node dial + RPC test green. Evidence: workspace exit 0 (53 suites), clippy `-D warnings` clean, fmt clean. NAT leg landed: relay client + DCUtR + AutoNAT behaviours wired, relay reservation + circuit-address dial + RPC-over-relay test, AutoNAT status + direct-vs-relayed observation test (3/3 `nat.rs` tests green; relay reservation gated on AutoNAT readiness per libp2p 0.57 API). Evidence: workspace exit 0 (54 suites, 0 failures), clippy `-D warnings` clean, fmt clean; `forge test` not re-run (Foundry absent; no contract changes). D5 signed DHT records landed: `swarm/records.rs` (same signed `PeerDescriptor` as HTTP gossip; key-match + signature + freshness validation, fail closed) with kad put/get plumbing in `swarm/mod.rs` and 5 unit + 2 two-node `dht_records.rs` tests (publish/verify, spoof/garbage drop, overwrite-blank + republish-restore). Evidence: workspace exit 0 (55 suites, 0 failures), clippy `-D warnings` clean, fmt clean. Signed bootstrap lists landed: `swarm/bootstrap.rs` (fleet-signed JSON, pinned-signer verification, boot refusal fail-closed) with 6 unit + 4 `bootstrap.rs` integration tests and a `sign-bootstrap-list` daemon subcommand. Rendezvous landed: client always-on + server behind `--p2p-rendezvous-server`, `ciphervault/1` namespace, register/discover/take handle methods with `--p2p-advertise-addr`, and a 3-node `rendezvous.rs` first-contact test (register→discover→dial→RPC). NAT drill runbook: `docs/NAT_HOLEPUNCH_DRILL.md` (automated harness, manual two-host drill, containerized chaos drill, rollback). Chunk provider records landed: `provide_chunk`/`get_providers` with `QueryId`-tracked lookups + 2 `providers.rs` tests (multi-provider resolve, empty unknown CID; bytes self-verify by CID hash, records are hints). Drill enablers landed: `--p2p-relay-reserve` (dial-then-reserve — circuit listen mid-dial fails fast) and `--p2p-probe-peer` daemon flags with 2 binary-spawning `drill_flags.rs` tests; event-loop state bundled into `LoopState` (arg-count lint). Drill executed multi-process (3 real daemons): seed `ReservationReqAccepted`, B circuit addr, A `P2P probe: OK operator=drill-b` — transcript in runbook §4 with honest scope (loopback mechanics; exclusivity from `nat.rs`). Docker-host run hardened: one-command `scripts/drill/nat-holepunch.sh` (build → isolated nets → seed → B reserve → A probe → isolation gate → seed kill → PASS/FAIL; `--keep` for debug), `bash -n` clean and verified against a fake-`docker` shim in pass + both failure modes; Dockerfile's exact release build exits 0 with drill flags confirmed in the artifact. Remaining engine-only risks (Linux build, bridge isolation, embedded DNS) are standard behaviors the script asserts at runtime. Phase 2 done; next is Phase 3 kickoff (vouchers/quotas, needs D3/D4 review). Also fixed a pre-existing flaky CLI fixture (`replication_concurrency` temp-dir nanos collision → pid+counter suffix; test-only, no assertions changed).

### Phase 3 — Write auth, quotas, DoS limits, object store (M)

- Capability vouchers: issuance, verification, per-key quotas, expiry; unauthenticated writes rejected before persistence; fuzz the verifier.
- Swarm DoS posture: connection limits, block-list wiring, gossip message validation/size caps, per-peer rate limits.
- Object-store spike per D6 then `ObjectStore` trait implementation behind measured choice; migration keeps existing on-disk layout readable.
- Gate: disk-fill attack drill fails (bounded usage); quota/voucher unit + integration tests; store benchmark report attached.
- 🔶 In progress (2026-09-18): D3 decided (barter; operators self-issue vouchers). Slice 1 landed: `crates/storage/src/vouchers.rs` (`WriteVoucher` issue/verify with lowercase-canonical hex rule, `VoucherLedger` spend accounting with terms pinning + expiry pruning, 403/429 mapping) with 8 tests including a 512-case seeded mutation battery — the battery caught a real case-malleability quota bypass (2^64 nonce spellings), fixed by canonical-form enforcement. Slice 2 landed: pre-persistence enforcement on all four write funnels via `_with_voucher` state siblings (legacy methods byte-identical when policy off via `require_voucher_legacy`); client attachment on all 3 legs (`set_write_voucher`: HTTP header, P2P envelope, memory staged); `POST /v1/vouchers` issuance (service-token); `--require-write-vouchers` daemon flag; idempotent re-PUTs billed zero via pre-check (content-addressed monotonicity); `Command::RpcRequest` boxed (enum-size lint); 8 `voucher_enforcement.rs` tests incl. the disk-fill drill (50×403 attacker, 0 bytes; holder bounded at quota). Vouchers are bearer capabilities by design (possession = authority); sender-constrained binding is future work. Slice 3 landed: connection caps via `connection_limits::Behaviour` (defaults 512 total / 8 per peer, `None`-selectable), operator block-list (`blocked_peers` boot seed + `block_peer`/`unblock_peer`/`is_blocked`; refused dials, bootstrap/mDNS skip, live-drop on block, close-at-establishment backstop — libp2p-swarm 0.48 has no `ban_peer_id`, so this is our own layer), per-peer sliding-window RPC limiter (default 50/s, 429 before auth/serve, 4096-peer tracker with fail-closed + idle-eviction hygiene), gossipsub `max_transmit_size` 64 KiB (Strict validation + signed authenticity pre-existing) with a `publish_control` path; 6 limiter unit tests + 5 `swarm_dos.rs` integration tests (cap-denial, block refuse/drop/release, boot-block bootstrap skip, 429-then-recover, oversize-publish; gossip positive control needed a 2-node mesh — solo publish fails `NoPeersSubscribedToTopic` since the size check runs before peer resolution). mDNS block-list skip is the one unenforced-by-test arm (mDNS stays off in tests for determinism). Slice 4 landed + D6 decided (redb): standalone `spikes/d6-objstore/` harness (own workspace; main gates untouched) measuring redb 4.3.0 vs faithful file-baseline model at 1M×1KiB objects — redb batched 144K puts/s + 197K gets/s, redb durable 1.2K puts/s + 165K gets/s, file 485 puts/s + ~197 gets/s (50K sample; full pass projects ~100 min; single-dir NTFS degrades 1,300→200 puts/s over the run), crash probes 7/7 PASS (dense prefix + full value verify; file orphans ≤1 `.tmp`/kill, redb zero debris), cold build +10 s / +1 MiB binary for redb, MIT/Apache license; RocksDB unmeasured (no C++ toolchain/libclang on host — build failure captured as evidence; adapter written for a Linux rerun). Report: `docs/D6_OBJECT_STORE_SPIKE.md`. Phase 3 gate holds (disk-fill drill bounded, voucher tests, benchmark attached). Phase 3 done; next is Phase 4 (authenticated repair + erasure spike + chaos gates).

### Phase 4 — Authenticated repair + erasure spike + chaos gates (L)

- Repair protocol: authenticated liveness gossip (signed heartbeats, no anonymous death claims), deterministic next-closest repair assignment, rate-limited backfill with backpressure.
- Erasure-coding spike per D7; adopt or explicitly decline with data.
- Chaos gates on containerized 10-node mesh and Testground plans: kill 3/10 mid-write, partition the mesh, assert full replication recovery and bounded repair bandwidth.
- Gate: chaos suite green three consecutive runs; repair telemetry complete; no repair storm under forged-gossip injection.
- 🔶 In progress (2026-09-18): repair protocol designed (`docs/REPAIR_PROTOCOL.md`: signed heartbeats + local-only failure detection, rendezvous-hash assignment, token-bucket backfill on the existing put path, telemetry, chaos plan). Slice 1 landed: `swarm/liveness.rs` (heartbeat sign/verify with version→skew→known-sender→signature→monotonic-seq order, upgrade-compatible control envelope, bounded tracker) wired to gossipsub Strict validation (Accept/Reject/Ignore per verdict class) with a 5s/15s emission/timeout ticker and 10 rendered telemetry series; 8 unit + 2 `swarm_liveness.rs` integration tests (live/timeout roundtrip, 7-class forged-gossip injection with victim view intact). Evidence: workspace 62/62 suites ok, clippy `-D warnings` clean, fmt clean. Note: the shared target dir needed a package clean mid-turn (stale artifacts caused E0463/ICE; resolved, no code impact). Slice 2 landed (2026-09-18): `swarm/repair.rs` (rendezvous-hash `plan_repair`: single lowest-score pusher, lowest-score recipients; `TokenBucket` sender pacing), receiver `RepairPush` RPC in `swarm/serve.rs` (known-sender + ed25519 + digest verify, dedicated repair budget with 429 via `put_repair_object` — no voucher/quota path), sender 429/transport backoff with jitter + per-CID cooldowns, 9 rendered repair telemetry series; 3 `swarm_repair.rs` integration tests (1→3 backfill, single-pusher agreement, 429-backoff-then-recover). Debug findings fixed in product: kad forced to server mode (auto-mode pinned loopback/NATed nodes to client, refusing all inbound kad), heartbeat/repair tickers to `MissedTickBehavior::Delay` (Burst catch-up spun a 100% CPU spiral under load). Evidence: swarm_repair 3/3 in ~3 s, workspace gate green (63 suites), clippy `-D warnings` clean, fmt clean. Slice 3 landed (2026-09-18): D7 spike (`spikes/d7-erasure/` standalone harness + `docs/D7_ERASURE_SPIKE.md`) — verdict DECLINE, 3x replication kept (see D7 line). Still to do: slice 4 chaos gates.

### Phase 5 — Economics + contracts (M, gated on D3)

- Only the mechanism D3 selects: staking registry extension, Merkle batcher with a named gas payer, and a complete challenge→evidence→adjudication→slash/payout loop with griefing analysis.
- Foundry unit + invariant/fuzz tests; external audit gate before any mainnet value at risk.
- Gate: audit issues resolved or risk-accepted in writing; escrow flows demonstrated on testnet with real challenges and payouts.

### Phase 6 — CLI/TUI/doctor + staged production cutover (M)

- `--p2p` / `--network` flags, swarm TUI view, `doctor` DHT/NAT diagnostics; docs and install flows updated.
- Staged cutover of the live network: shadow (mesh mirrors, HTTP authoritative) → canary (one operator dual-mode) → full, each with rollback to pinned static images via the existing promotion script.
- Gate: clean-machine recovery drill over the mesh only; 30-day production telemetry review.

## Validation Plan

- Every phase: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, `forge test` (contracts/).
- Phase 1: new conformance suite passes identically on HTTP and loopback transports (evidence: test output + coverage of fault-injection cases).
- Phase 2: NAT hole-punch harness (two NATted containers exchange a chunk) plus conformance over libp2p transport; expected evidence is harness logs, not unit-test-only claims.
- Phase 3: disk-fill drill report (attacker container, bounded operator disk); voucher/quota integration tests; object-store benchmark numbers.
- Phase 4: chaos gate logs (kill/partition/latency matrices), repair-bandwidth measurements, forged-gossip injection results.
- Phase 5: audit report, testnet escrow transcripts (challenge, evidence, payout/slash events).
- Phase 6: disaster-recovery drill recording over mesh-only networking; production dashboards before/after cutover.

## Risks / Rollback

- Protocol fork risk (two transports diverging): mitigated by the shared-pipeline design and the Phase 1 conformance suite, which stays mandatory forever.
- libp2p API churn: pin versions in the workspace manifest; isolate all libp2p surface in `swarm/` + `Libp2pTransport` so upgrades touch two modules.
- NAT reality worse than lab: hole-punch harness runs in CI against real NAT topologies; relay fallback keeps functionality degraded, never broken.
- Economic griefing: Phase 5 requires the griefing analysis as a gate artifact, not an afterthought.
- Rollback: every phase merges independently revertible units; production rollback is re-promotion of pinned static digests (existing script); testnet rollback is a documented wipe-and-rebootstrap procedure.

## Open Questions

1. ~~D3 economics model~~ — decided 2026-09-18: barter/permissioned fleet first (see `docs/DON_ECONOMICS_DECISION.md`).
2. If staking is chosen: staking asset and confirmation that Arbitrum One remains the settlement chain? — carried 2026-09-24 (ADR-009: stake-gating conditional on this; owner: product).
3. What operator scale must the first public testnet support (drives chaos-test sizing and bootstrap capacity)?
4. Has legal reviewed community operators storing third-party ciphertext in target jurisdictions? — carried 2026-09-24 (ADR-009: permissioned growth continues pending review; owner: legal).

## Sources

- https://docs.rs/crate/libp2p/latest
- https://libp2p.io/docs/hole-punching/
- https://libp2p.io/docs/discovery-routing-overview/
- https://github.com/testground/testground
- https://docs.rs/redb/latest/redb/
- https://docs.rs/rocksdb/latest/rocksdb/
- https://docs.rs/reed-solomon-simd/latest/reed_solomon_simd/
