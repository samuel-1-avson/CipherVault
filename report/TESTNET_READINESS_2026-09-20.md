# CipherVault — System Workflow, User Flows & Testnet Readiness

**Date:** 2026-09-20
**Codebase state:** `main` at `83fce7e`, workspace `v1.0.7-beta.7`
**Fleet state:** 3 GCP operators on beta.7 with `CIPHERVAULT_FLEET_KEY` pinned

---

## Part A — System workflow

### 1. Components and trust boundaries

| Component | Location | Role | Trust level |
|---|---|---|---|
| CLI + TUI + web dashboard | `apps/cli` | All secret handling: keys, encryption, chunking, signing, recovery | Trusted (user's machine) |
| Watcher agent | `apps/agent` | Background file-watch → auto-snapshot daemon | Trusted |
| Crypto / format / snapshot / recovery / local-store | `crates/` | Primitives, CBOR schemas, FastCDC, Shamir, DPAPI SQLite store | Trusted |
| Storage operators (×3 live) | `services/operator` | Opaque ciphertext storage, PoS answers, recovery envelopes, gossip/P2P | **Untrusted by design** |
| Maintenance daemon | `services/maintenance` | Heartbeats, quorum audits, PoS re-checks, self-repair; no HTTP surface | Trusted by whoever runs it |
| Account service | `services/account` | Passkeys, devices, vault links, sessions, revocation. Never sees plaintext or private keys | Semi-trusted control plane |
| Arbitrum registry | `contracts/` | `setCommitment` head-state anchors, tamper-evident history | Trustless (L2) |

Live topology today: 3 GCP `e2-micro` operators (Iowa ×2 zones,
South Carolina ×1) on `v1.0.7-beta.7` behind
`https://vault.cipherv.online`, plus a digest-pinned web VM. The client
connection string points at the three `/op/N` endpoints.

### 2. Cryptographic spine

One 32-byte master secret **R** derives everything via domain-separated
HKDF/BLAKE2b: Ed25519 recovery-signing key, X25519 recovery-encryption
key, public locator `L`, and epoch keys. Device keys live in DPAPI (or
YubiKey PIV slot 9C). Files are FastCDC-chunked (4/16/64 KB), encrypted
with XChaCha20-Poly1305, and addressed by SHA-256 CID. R exists only on
the printed paper kit and is zeroized from RAM after init. Recovery is R
directly, or M-of-N Shamir guardian shares over branchless GF(2⁸).

### 3. Core data workflows

- **Init** (`init`): generate R → derive identities → DPAPI-persist
  device/epoch keys → print paper kit → require confirmation → zeroize R
  → scan `.gitignore`, offer to track secrets. Nothing secret ever leaves
  the machine.
- **Push** (`push`/`track`/`status`): for each tracked file, FastCDC →
  per-chunk FileVersionKey + deterministic nonce → encrypt →
  **PoS-dedup challenge** (prove the operator already holds it and skip
  upload) → upload missing → build signed SnapshotRecord (software or
  `--touch` YubiKey) → replicate to quorum (default 3) → advance local
  head. Replication pipeline: authenticate → PoS challenge → lease commit
  → receipt verify → readback → recovery-log append → discovery readback,
  with quorum early-exit.
- **Pull** (`pull`): fetch quorum of signed head records → select
  authentic latest → dirty-tree guard (abort unless `--force`) → fetch
  missing CIDs → decrypt, verify digests → atomic restore.
- **Recover** (`recover --kit/--shares`): reconstruct R in RAM → derive
  locator → fetch signed recovery records → open epoch-key envelope →
  fetch head + chunks → verify SHA-256 per file → atomic move from staging
  → zeroize everything. Optional `--require-approval` gates this on
  out-of-band signed approval receipts from team leads.
- **Anchor** (`anchor`/`verify-anchor`): commitment =
  BLAKE2b(VaultID‖HeadCID‖Salt) → EIP-712 evidence → operator relayer
  queue → Arbitrum sequencer → receipt polling → recorded receipt +
  explorer URL.
- **Run** (`run -- cmd`): decrypt into RAM only, parse dotenv in memory,
  spawn child with injected env, zeroize buffers. Zero disk writes — the
  CI/CD path.
- **Watch** (`watch --sync`): kernel events (ReadDirectoryChangesW/inotify/
  FSEvents) → 2s debounce → coherent-read check → chunk/encrypt/replicate
  silently.
- **Diff** (`diff`): masked by default (`sk_live_***…a8f`), `--reveal` to
  unmask; key-level for dotenv, line-level otherwise.
- **Rekey / prune / audit / repair / doctor**: epoch rotation (old chunks
  stay readable), history pruning, replica-health inspection,
  operator-driven reheal, and full self-diagnostics.

### 4. Operator-network workflows

- **Boot**: first start generates persistent Ed25519 identity
  (`operator.key`, 0600). Flags cover ports, data dir, key rotation,
  identity printing.
- **Static gossip**: signed `PeerDescriptor` announces
  (`operator_peer_gossip` domain, 24h age / 1h skew bounds) → routing
  table → clients expand pools via `GET /v1/peers`.
- **Verified community join** (ADR-008, shipped in beta.7): joiner shows
  pubkey → admin signs offline ticket → `invite join` presents it (no
  service token) → lands in **probation** (stores data, gets no new
  replicas) → graduates after 24h fleet-visible life + recent liveness
  (P2P heartbeats or `invite refresh`), or admin override. Fleet pins
  `CIPHERVAULT_FLEET_KEY`; join fails closed without it (rogue join
  verified 403 on live fleet).
- **Write governance**: strict auth (challenge sessions + enrolled device
  keys), optional write vouchers bound to quotas (disk-fill drill proven:
  50×403 attacker, 0 bytes), leases + barter quotas; voucher ledger now
  survives restarts.
- **Liveness + repair**: signed heartbeats (5s/15s), rendezvous-hash repair
  assignment (single lowest-score pusher), token-bucket backfill on the put
  path with 429 backoff; repair bytes bounded and telemetered.
- **P2P dual mode** (`--enable-p2p`): libp2p 0.57 — Kademlia
  provider/peer records, gossipsub control, rendezvous first-contact, relay
  + DCUTR hole-punching + AutoNAT, signed bootstrap lists, block-lists,
  per-peer rate limits. HTTP stays authoritative alongside.
- **Maintenance loop**: every 15s probe `/v1/info` → quorum audit via PoS
  matrix → healthy/degraded verdict → self-repair (read survivors →
  re-replicate to replacement) → SSE telemetry to dashboard.
- **Control plane**: account service handles WebAuthn login, device
  enroll/revoke, vault links, sessions; dashboard serves private UI, public
  site, and the block-explorer-style object/anchor/operator explorer
  (PoS-proven, never fetches bytes).

---

## Part B — User flows

**Flow 1 — Solo developer (5 min to safe):** download release → run binary
(TUI opens) → `init --operators …` → write down paper kit, confirm →
`track .env` → edit → `push -m "…"` → new laptop: install,
`recover --kit`, everything back bit-for-bit. Daily: `push`/`pull`, or
`watch --sync` and forget.

**Flow 2 — Team:** `auth` + `device list|revoke` for membership; guardian
`recovery` ceremonies split recovery power M-of-N; `approve` flow gates
emergency recoveries on lead signatures; `rekey` rotates epochs without
breaking old reads.

**Flow 3 — CI/CD:** composite action → `ciphervault run -- <build>`;
secrets exist only in the runner's RAM, exit code propagates.

**Flow 4 — Operator:** fastest path is one binary +
`--port/--data-dir/--operator-id`, health at `/healthz`; or local 3-node
compose mirroring prod; or P2P mesh with bootstrap/relay flags; or
verified join to the fleet (ticket → probation → graduation per operator
playbook §10). Harden with strict-auth token + enrolled device keys, back
up the data dir and `operator.key`.

**Flow 5 — Auditor/observer:** public explorer — search CID →
replica/quorum proof; search `0x` receipt → anchor inspection; operator
id → telemetry. No vault identities, files, or snapshots are visible by
design.

---

## Part C — Testnet readiness

### Verdict: ready to *open* a testnet — the testnet itself isn't running yet

Mapping to the DON plan's own testnet criterion (§5: "public testnet runs
with independently operated nodes, published dashboards, and a chaos drill
report"):

| Requirement | Status |
|---|---|
| Chaos drill report | ✅ 10-node PASS 2026-09-19, all 3 gates (kill-3/10, 45s partition-heal, bandwidth cap), run ID + image digest logged |
| Published dashboard | ✅ Explorer shipped; fleet live at vault.cipherv.online on beta.7 |
| Independently operated nodes | ⚠️ Join protocol + docs + playbook shipped and rogue-join rejected live — but no external operator has joined yet |
| No permissionless disk-fill | ✅ Voucher/quota enforcement + disk-fill drill (0 bytes to attacker) |
| NAT'd nodes exchange chunks | ✅ Relay→DCUTR drill + scripted harness |
| Panic-safe servers | ✅ C1 (lock recovery, `Result` persists, panic-catch → 500 JSON) |
| Restart-safe quotas | ✅ C3 (ledger persisted; repair budget intentionally ephemeral) |
| Verified promotion | ✅ C2 script asserts live routes + build version (user-executed by design) |
| Operator runbooks | ✅ Rotation, recovery, incident, verified-join (§1–§10), ADR-001–008 |

### Blockers / risks before inviting external nodes

1. **Windows CI red** — fix (`83fce7e`) pushed, awaiting green. Don't
   onboard until 3-OS green on tip.
2. **Quorum writes fail during single-node restarts** (known issue).
   Testnet nodes *will* restart; decide: fix, or document as accepted
   testnet behavior with retry guidance. This is the sharpest edge.
3. **No external join dry-run yet** — do one rehearsal from a non-fleet
   machine (ticket → probation → refresh → graduate) before announcing.
4. **Fleet seed lives only in Secret Manager** — back it up; losing it
   bricks the testnet's trust root (can't mint tickets).
5. **Seed/relay hosts for P2P** — flags and code exist, but no public
   rendezvous/relay endpoints published yet. Static-HTTP testnet works
   without them; mesh testnet needs them.
6. **Wipe-and-rebootstrap procedure** — the plan promises a documented
   testnet reset path; write the one-pager before genesis so a bad launch
   is recoverable.
7. **Provisional answers needed**: target operator scale (drives chaos
   sizing) and legal review for community ciphertext storage — both open
   questions in the DON plan.
8. **Non-blocking but noted**: self-audited only (no external crypto/pen
   review — fine for testnet, required for mainnet); redb migration pending
   (file store in prod, NTFS degradation measured — fine at testnet scale);
   Foundry suite flaked once (watch item); economics deferred to barter
   (correct for testnet).

### Suggested testnet-open sequence

1. Confirm CI green on tip → tag testnet genesis (fleet already on beta.7
   + `FLEET_KEY` pinned).
2. Publish: signed bootstrap list, seed multiaddrs, fleet endpoints, join
   docs link, wipe/rebootstrap note.
3. Run the external join rehearsal; graduate the rehearsal node; then kill
   it to prove probation/repair behavior with real churn.
4. Announce with scale cap (e.g., 10–25 nodes), dashboard link, and
   known-issue list (restart-quorum behavior, redb pending).

### Sources

- `docs/SYSTEM_WORKFLOW.md` — architecture + 12 workflows
- `docs/WORKFLOW_GUIDE.md` — network operation + user/operator flows
- `docs/DON_IMPLEMENTATION_PLAN.md` — phase status (Phases 0–4 complete)
- `docs/OPERATOR_PLAYBOOKS.md` — runbooks §1–§10
- `docs/CHAOS_LOG.md` — 2026-09-19 10-node PASS entry
- `docs/API_REFERENCE.md` — operator HTTP/P2P surface
- `docs/adr/001–008` — incl. 007 ledger persistence, 008 verified join
- `report/SYSTEM_AUDIT_RATING_2026-09-19.md` — 7.4/10 baseline; all P1s
  since closed (C1–C6)
- `.agents/plans/2026-09-19-gap-remediation.md` — C1–C6 execution record
