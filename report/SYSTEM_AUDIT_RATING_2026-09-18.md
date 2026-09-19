# CipherVault System Audit & Rating — 2026-09-18

**Verdict: security-focused beta, overall 6.0/10. Not production-ready.**
Gates green (`cargo test --workspace --locked`: 63 suites / ~290 tests ok;
`clippy -D warnings` clean; `fmt --check` clean), but open P0s in auth,
spec accuracy, and CLI honesty block any production claim.

## 1. Method, coverage, limits

- Eight parallel read-only audit agents (crates, operator service, swarm/P2P,
  CLI+integration, docs currency, security) + skeptic critic + synthesis,
  run 2026-09-18. All agents shared one checkout; no writes.
- **Inspected (this session, by hand):** README badges/CLI table, repair
  receiver path (`serve.rs` RepairPush), recovery GET auth (`handlers.rs`),
  AEAD/KDF/CID primitives (`aead.rs`, `kdf.rs`, `canonical.rs`, `schema.rs`),
  `gf_mul`, metric series names, maintenance/operator ports and storage
  backends, compose port mappings, crate/suite counts, dead `--pos` flag.
- **Carried, NOT independently verified:** most P1/P2 items below came from
  child reports whose full bodies did not survive synthesis (`complete:false`;
  prior results 1–7 arrived bodyless). They are listed as *reported* so a
  follow-up can confirm or kill each one. Do not treat carried items as proven.

## 2. Score

| Scope | Score | Basis |
|---|---|---|
| Overall system | **6.0/10** | Audit synthesis; beta, gates green, P0s open |
| Per-area splits | n/a (not preserved) | Synthesis kept only the overall number; qualitative notes below |

Qualitative (auditor judgment, mixed verified/reported): cryptography
implementation is the strongest area; operator auth surface and spec
accuracy are the weakest; swarm/repair is now solid after the Phase 4
slice-2 fixes; docs were the stalest area and received the bulk of today's
corrections.

## 3. Pros (strengths)

Verified this session:
- Domain-separated custom KDF (`CipherVault-KDF-v1` prefix + 8-byte
  contexts) used consistently for subkeys, file keys, 24-byte chunk nonces.
- Repair receiver: known-sender + ed25519 + digest verify, dedicated
  budget with 429, `put_repair_object` — no client-credential path involved.
- Challenge-based device/session auth on the droning paths; voucher gate
  on all four write funnels (reported, partially inspected earlier).
- Workspace gate green: 63 suites, clippy `-D warnings`, fmt clean.

Reported by audit, not re-verified:
- Single-pusher rendezvous repair with token-bucket pacing and
  backoff+jitter; layered swarm DoS (connection caps, block-list, RPC
  rate limits, 64 KiB gossipsub cap); liveness verification order per spec.
- Voucher/Shamir/kit test batteries; pool heal-vs-3-operators; NAT drill
  doc matches drill scripts.

## 4. Cons and gaps (prioritized)

### P0 — block production
- [verified, DECIDED 2026-09-18: intended, documented] Anonymous GET
  recovery records (`handlers.rs`, mirrored in P2P `serve.rs`). The locator
  is a 256-bit KDF-derived capability (`derive_recovery_locator`,
  unenumerable without the recovery secret); clean-machine recovery has no
  session by definition, so gating would break bootstrap. Locked by
  `services/operator/tests/recovery_auth.rs` + handler doc comments.
- [verified, FIXED 2026-09-18] Peer registration had no freshness bound
  (sig + allowlist existed). `register_peer` now rejects announces older
  than 24h (`MAX_PEER_ANNOUNCE_AGE_SECS`, matching the prune window) and
  more than 1h in the future (`MAX_PEER_ANNOUNCE_SKEW_SECS`); covers the
  HTTP route and the P2P mirror. Locked by re-signed stale/future cases in
  `test_peer_gossip_registry`. Residual note: any session holder can still
  announce self-signed operators up to table capacity when no trust
  registry is configured — accepted as designed (permissioned deployments
  set `CIPHERVAULT_TRUSTED_PEER_KEYS`).
- [verified, FIXED 2026-09-18: removed] `push --pos` was a dead flag
  while `--help` advertised a PoS readback. Evidence forced removal over
  wiring: every push already runs mandatory per-object PoS readback
  (`pool.rs` R04, pre-upload dedup + post-upload verify-before-quorum), so
  the flag had no remaining honest meaning. Removed from the CLI surface,
  drill test, both ps1 scripts, runbook, diagram, workflow doc, and README
  (archive audit doc left as historical record). `chaos_federation_drill`
  green post-removal.
- [verified, FIXED TODAY in docs] Crypto spec §1–3 named the wrong AEAD
  (ChaCha20 vs XChaCha20), wrong KDF (HKDF vs custom Blake2b), wrong CID
  hash (BLAKE2b vs SHA-256). Spec now matches code.
- [verified, FIXED TODAY in docs] README/docs-hub claimed Production Ready /
  v1.0.0 and 67 suites. Now Beta / v1.0.7-beta.2 / 63 suites.

### P1 — fix before any rollout claim (mostly reported, spot-verified)
- `schema.rs` has zero direct tests (reported). M.
- `pool.rs:182` PoS-skip path needs adversarial review (inspected: proof is
  verified before skip; residual question is replay/freshness of the nonce).
  M.
- Ledger + repair budget memory-only (inspected state fields); persistence
  paths without fsync (reported); hardcoded `seq=1` (reported). M/S/S.
- Repair doc claimed voucher/quota path (verified wrong; FIXED TODAY).
  Same-key garbage blanking a DHT record (reported). S/M.
- CLI: no lease/voucher/announce commands, swallowed errors, quorum-3
  hardcode, no end-to-end binary tests (all reported). M each.
- Docs hub omitted 13+ documents; stale ports/backends/counts (verified;
  FIXED TODAY). Naming contradictions (reported). M/S.

### P2 — hardening backlog (reported unless noted)
- AAD variable-length concat (inspected `schema.rs:169-79`, ambiguous
  framing — low exploitability, worth length-prefixing). S.
- `Drop` impl copies secrets (inspected `hsm.rs:94-100`). S.
- anyhow-trust in client paths, dead code, `PlacementUpdate` gap,
  auth-failure + repair double-count metric gaps, unbounded `Vec`s,
  missing chunking (L), flaky tests incl. nat AutoNAT race (M),
  transport-conformance gaps, client timeout/retry/JSON polish, missing
  ADRs/API reference/playbooks (L).

## 5. Doc updates applied 2026-09-18 (all verified against code)

- `README.md`: Beta badge; 63 suites; `--pos` marked reserved (3 spots);
  suite command comment corrected.
- `docs/REPAIR_PROTOCOL.md`: data plane rewritten (dedicated RepairPush +
  repair budget, no voucher path); chaos claims marked pending slice 4;
  telemetry §4 lists the 9 landed series by exact name.
- `docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`: §1–3 corrected to
  XChaCha20-Poly1305/24B nonce, custom Blake2b-KDF (+ true context table),
  SHA-256 CIDs; branchless claim scoped to `gf_mul`.
- `docs/README.md`: Beta version; five-manual count; new DON working-docs
  table indexing 13 previously unlinked documents.
- `docs/SYSTEM_WORKFLOW.md`: operator store RocksDB→file-backed (+D6 redb
  note); maintenance :8200 HTTP→no HTTP surface (3 spots); test counts to
  6 crates / 20 CLI suites / 63 total.
- `docs/DON_IMPLEMENTATION_PLAN.md`: Phase 4 slice 2 marked landed with
  evidence (incl. kad server-mode + ticker-Delay findings).
- `crates/crypto/src/kdf.rs:12`: comment-only fix (not libsodium-compatible).

## 6. Recommended next work (in order)

1. Decide + fix the P0 auth items (recovery-read auth, peer-announce
   freshness). These are the only true blockers.
2. Wire or remove `--pos` (S) so CLI stops advertising a no-op.
3. Confirm-or-kill each carried P1/P2 (one pass, file-by-file); promote
   survivors into tracked issues.
4. Finish Phase 4 slice 3 (D7 erasure spike) and slice 4 (10-node chaos
   gates) — repair's storm-resistance claims are unproven until then.
5. Write the missing ADRs, HTTP/P2P API reference, and operator playbooks.

## 7. Confirm-or-kill verdicts (2026-09-18)

Every carried P1/P2 was re-checked against the tree. Verdicts:

**Confirmed, keep as backlog**
- P1 `schema.rs` zero direct tests — 0 `#[test]` in schema.rs, 1 in the
  whole format crate. Needs a test battery.
- P2 (was P1) memory-only voucher ledger + repair budget — fresh defaults
  on boot; voucher double-spend across restart is quota-bounded and needs
  an operator restart, and vouchers are opt-in (`vouchers_required` false
  by default). Persist ledger or document restart semantics.
- P2 (was P1) fsync residue — `persist_atomic` fsyncs file+dir and covers
  objects/leases/routing/recovery/approvals/checkpoints; only
  `persist_sessions`/`persist_challenges` hand-roll write+rename without
  fsync (ephemeral state). Fix sketch: route through `persist_atomic` and
  keep the 0600 perms.
- P2 (was P1) quorum-3 hardcode — matches the documented 3-operator
  topology everywhere (compose, docs, tests); parameterization is a
  feature, not a fix.
- P2 (was P1) CLI lease/voucher/announce gaps — HTTP API + server-side
  `voucher_enforcement` tests cover the flows; CLI lacks convenience
  wrappers (`Peers` list/discover exists).
- P2 (was P1) DHT-record blanking — production never publishes peer kad
  records (`publish_peer` used only by `dht_records` tests); readers fail
  closed. Needs periodic republication when the path goes live.
- P2 HSM `Drop` zeroizes a temp copy (`hsm.rs:94-100`) — harmless, remove.
- P2 ADRs/API reference/playbooks missing — confirmed, no such docs exist.
- P2 flaky tests — nat AutoNAT race already documented as known-flake.
- P2 P2P size caps — HTTP/object paths capped (axum default + 4 MiB
  `MAX_OBJECT_SIZE`); RPC/kad-record caps unconfirmed, verify.
- P2 client retry/JSON — 15 s timeout verified, pool failover exists;
  per-request retry policy + error JSON shape still open.

**Killed with evidence**
- `seq=1` — value ignored by all consumers (pool only checks `Err`).
  P2 polish at most (return real position; mind the held stripe lock).
- PoS-skip replay — pre-upload challenge uses a fresh random nonce per
  object and verifies the proof; post-upload readback re-verifies with a
  fresh nonce. No replay window.
- No e2e binary tests — `chaos_federation_drill` (+ `e2e_workflow`) drive
  the real binary via `Command`.
- Swallowed errors — sampled 4/23 `let _ =` (temp cleanup, flush,
  shutdown signal, preference save), all benign; money paths use `?`/`bail!`.
- AAD concat — both sides recompute AAD from the same canonical struct;
  no AAD parsing step exists, so split ambiguity is unreachable.
  Length-prefixing optional defense-in-depth.
- Dead code — 1 `allow(dead_code)` in the tree.
- `PlacementUpdate` — zero matches; phantom item.
- Auth-failure metric dark — wired (`state.rs:1012`) and rendered.
- Repair double-count — HELP explicitly documents dual-role feeding and
  tests assert per-role values; as designed.
- No chunking — FastCDC snapshot chunking exists; 4 MiB object cap enforced.
- anyhow-trust — no instance cited; `anyhow`/`bail!` used idiomatically for
  CLI control flow. Subsumed by the client-JSON item above.

**Still unconfirmed (no instance cited; kept narrow, confirm first)**
- Transport-conformance gaps (suites green 36/36 + storage suite).
- Further docs naming drift beyond the fixed `pool.rs` comment.
