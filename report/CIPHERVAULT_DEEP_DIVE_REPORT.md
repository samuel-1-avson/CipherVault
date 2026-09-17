# CipherVault — Deep-Dive Analysis Report

- **Date:** 2026-09-16 (analysis) / 2026-09-17 (implementation update)
- **Revision inspected:** `main` at v1.0.6 (`Cargo.toml`) through `f6a9020`
  (28 implementation commits, 2026-09-16 → 2026-09-17)
- **Scope:** Rust workspace (11 members, 75+ `.rs` files), web dashboard/explorer (`apps/ui`),
  CLI/TUI/agent, operator/account/maintenance services, Solidity registry, Docker/GCP
  deployment, CI/release workflows, live endpoint evidence (from repo audit docs)
- **Method:** full-repo source inspection, prior audit cross-check
  (`docs/PROJECT_AUDIT_2026-09-16.md`, `docs/SYSTEM_WORKFLOW.md`), bottleneck
  reproduction-by-reading, then implementation of §12 phases 0–4 plus follow-ups
  (R13–R18, reorg alarm, split plan, TUI fix) with regression tests
- **Environment note:** no Rust/Foundry toolchain or network was available in this
  environment for the whole session, so all 28 implementation commits are
  carefully statically cross-checked but **not compiled or test-run here**. Node
  gates run green in-env (§9.4). Ratings in §2 are therefore dual:
  as-implemented vs as-demonstrated. Exact verification commands are in §9.

## 1. Executive verdict

CipherVault is a substantial, genuinely engineered zero-knowledge secrets backup and
disaster-recovery platform: real client-side cryptography, a working 3-operator
federated quorum, an autonomous repair fleet, and an unusually complete operator
surface (CLI + TUI + web dashboard + background agent). The cryptographic core,
recovery ceremonies, and local data handling are the strongest parts of the system.

It is **not a 10/10 production system yet**, despite the self-assessment in
`docs/SYSTEM_WORKFLOW.md`. The repo's own 2026-09-16 audit reaches the same
conclusion: the correct status is **security-focused beta — public explorer
operational, private hosted account and evidence plane still hardening**. The
highest-impact gaps are missing production trust evidence (operator identity,
checkpoint feed), distributed abuse controls, durable job/event state,
secret-manager-backed rotation, and reproducible immutable deployment. This report
adds a performance/structural dimension to that audit: two real bottlenecks are
fixed in this session (§9), and the remainder are specified with an implementation
plan (§11–§12).

### Implementation update (2026-09-17)

All of §12 phases 0–4 plus the R13–R18 product items, a checkpoint reorg alarm,
a TUI arity fix, and the B4/B7 gap closures are now implemented in 28 local
commits (`8f71a40`…`f6a9020`, Appendix A): bottleneck fixes B1–B9 (B8/B11
accepted, B10 planned, B12 de-scoped), recommendations R1–R18 (R3/R4/R10/R16
scoped to runbook/notes/matrix, §11.1), H5/H7 hardening, a push bench suite with
CI job, expanded Foundry coverage, LF ending pins, the `SYSTEM_WORKFLOW.md`
headline correction, and a written (not yet executed) module split plan. The
monoliths grew in the process (`main.rs` 9.7k → 10.9k lines; `account/lib.rs`
4.9k → 5.7k) and **no Rust code was compiled or test-run** — verification debt
is now the single largest risk (§9.4, §12 Phase 5). Net: design-complete beta at
8.1/10 as-implemented, still 7.4/10 as-demonstrated until the standing gates go
green on a provisioned host.

## 2. Rating

| Category | Score | Basis |
|---|---|---|
| Cryptographic design | 9.0/10 | Unchanged; R13 epoch re-key implemented but its recovery drill is still pending |
| Durability & quorum | 8.0/10 | R5 durable peers/approvals/sessions/challenges, H7 TTL/re-enrollment, reorg alarm; new tests written, unrun |
| Features & completeness | 9.0/10 | 31 CLI commands (prune/rekey/doctor new), R6–R18 implemented; flows unexercised |
| Code quality | 7.0/10 | Unchanged: monoliths grew (10.9k/5.7k lines); split plan written, not executed; LF pinned |
| Performance & scalability | 7.0/10 | R6/R7/R8/R9 concurrency + B7 contention counters landed, bench suite in CI; zero measurements taken yet |
| Operability & deployment | 7.5/10 | R12 doctor, R11 metrics/tracing, R3/R4 runbook; live promotion/rotation not executed |
| Testing | 8.0/10 | 20 CLI suites + expanded Foundry + bench/soak tests; none executed in this environment |
| Documentation | 9.0/10 | Runbook cutover/promotion, split plan, platform matrix, verdict correction |
| **Overall (as-implemented)** | **8.1/10** | **Design-complete beta. All §12 phases implemented, none compiler-verified.** |
| **Overall (as-demonstrated)** | **7.4/10** | **Unchanged until Phase 5 gates go green on a provisioned host.** |

Score meaning: 9–10 production-grade, 7–8 solid beta with known gaps, 5–6 works with
material risk, <5 prototype. The dual rating is deliberate: 25 commits of new
concurrency, crypto-touching, and retention-GC code that has never been compiled
must not move the demonstrated score. The repo's headline scorecard now reads
"SECURITY-FOCUSED BETA (7.4 / 10.0)" with a correction note, though its
per-category rows still claim 10.0s.

## 3. System architecture

### 3.1 Topology

```text
 Developer workstation                    Untrusted federation              L2
┌────────────────────────┐      ┌────────────────────────────────┐   ┌──────────────┐
│ CLI (ciphervault)      │      │ Operator 1 :8201  ┌─────────┐  │   │ Arbitrum One │
│ TUI (ratatui, 6 views) │─────▶│ Operator 2 :8202  │ opaque  │  │   │ Registry.sol │
│ Agent (notify watcher) │ push │ Operator 3 :8203  │ AES/XCha│  │◀──│ EIP-712 heads│
│ vault.db (SQLite WAL,  │ PoS  │ chunks+manifests  │ Cha20   │  │   │ receipts     │
│  DPAPI/OS keyring)     │      │ +recovery log     │ blobs   │  │   └──────────────┘
│ FastCDC 4/16/64 KiB    │      └────────────────────────────────┘
│ YubiKey PIV (9C/9D)    │      ┌────────────────────────────────┐   ┌──────────────┐
└────────────────────────┘      │ Maintenance :8200 (fleet.db)   │   │ Account svc  │
                                │ audit → repair degraded/missing│   │ WebAuthn/TOTP│
                                └────────────────────────────────┘   │ sessions     │
                                                                     └──────────────┘
                                Dashboard :8080 (local) / vault.cipherv.online (prod)
```

Live production shape (per README + audit): `vault.cipherv.online` fronting
`/op/1..3` (Iowa ×2, S. Carolina ×1) with a Caddy reverse proxy, HSTS, and health
checks. Client→operator traffic is ciphertext only; operators see BLAKE2b CIDs.

### 3.2 Components

| Component | Location | Tech | Responsibility |
|---|---|---|---|
| CLI + dashboard server | `apps/cli/src/main.rs` (~10.9k lines) | Clap, Axum, Tokio | 31 commands, TUI, `Ui` server :8080, public/private route guards, collector |
| Agent | `apps/agent` | notify | Event-driven watcher, debounce (default 2 s), coherent re-read, auto push |
| Crypto core | `crates/crypto` | XChaCha20-Poly1305, Ed25519, X25519, BLAKE2b, Shamir, Argon2 | AEAD, KDF, sealed boxes, threshold shares, PIV/APDU driver, HSM trait |
| Wire format | `crates/format` | Canonical CBOR | Genesis/head/snapshot/manifest records, digests, schema |
| Snapshot engine | `crates/snapshot` | Pure-Rust FastCDC + Gear hash | Chunk (4/16/64 KiB), dedup, encrypt, serialize, atomic restore |
| Local store | `crates/local-store` | SQLite WAL, DPAPI/keyring | Tracked files, snapshot DAG, device certs, account/device/session, upload queue |
| Recovery | `crates/recovery` | Shamir, signed kits | Offline paper kit, M-of-N shares, trust selection, out-of-band approvals |
| Storage client | `crates/storage` | reqwest, join_all | Operator client, quorum pool, PoS, leases, chain/relayer types |
| Operator | `services/operator` | Axum, disk store | Chunk/manifest/recovery storage, PoS, leases, peers, approvals, relayer receipts |
| Account | `services/account` (lib ~5.7k lines) | SQLite WAL, WebAuthn, TOTP | Accounts, devices, sessions, passkeys, invitations, recovery codes, audit |
| Maintenance | `services/maintenance` | reqwest, SQLite WAL | Heartbeats, quorum audits, PoS verify, self-repair scheduler |
| Web UI | `apps/ui` (JS, ~330 KB) | app.js/index.html/styles.css | Public explorer, telemetry, diff viewer, Shamir ceremony simulator |
| Registry | `contracts/CipherVaultRegistry.sol` | Solidity 0.8.28, Foundry | `setCommitment` anchoring, salt binding, receipt validation |
| Deploy | `deploy/`, `docker-compose.yml` | Docker, Caddy, nginx, systemd, GCP | 3 operators + maintenance + dashboard, TLS, provisioning scripts |

### 3.3 Trust boundaries and invariants

1. **Zero plaintext at rest** — device/epoch keys sealed by OS keyring (DPAPI on
   Windows, machine AEAD elsewhere); SQLite holds ciphertext/blobs only.
2. **Zero plaintext to operators** — all chunks/manifests/heads encrypted
   client-side; operators address opaque bytes by content digest.
3. **Zero-disk master secret** — `R` printed once at `init`, interactively
   acknowledged, then `ZeroizeOnDrop`-scrubbed from RAM.
4. **Quorum durability** — PoS challenge readback on write; fleet daemon repairs
   degraded replicas; L2 anchoring is tamper-evidence, not availability.

## 4. Repository structure

```text
CipherVault/                      # workspace v1.0.6, edition 2021, MIT OR Apache-2.0
├── Cargo.toml                    # 11 members + shared deps (tokio, axum, rusqlite, …)
├── apps/
│   ├── cli/src/main.rs           # CLI + dashboard + TUI host (10,931 lines, LF)
│   │   ├── diff.rs dotenv.rs tui/  # masked diff, env parsing, ratatui UI
│   │   └── tests/ (20 suites)    # e2e, chaos drill, PoS, watcher, bench, prune, dry-run, …
│   ├── agent/                    # watcher daemon (lib.rs, watcher.rs, main.rs)
│   └── ui/                       # dashboard JS (app.js, index.html, styles.css, audit.test.cjs)
├── crates/
│   ├── crypto/                   # aead, kdf, keys, signatures, sealed_box, shamir, hsm, piv, password
│   ├── format/                   # canonical CBOR, schema, protocol version
│   ├── snapshot/                 # fastcdc, chunker, engine (create/decrypt/restore)
│   ├── local-store/              # db.rs, account.rs, keyring.rs
│   ├── recovery/                 # kit.rs, trust.rs, approval.rs
│   └── storage/                  # client.rs, pool.rs, types.rs, chain.rs
├── services/
│   ├── operator/ (handlers, state, main)   # :8201–8203 nodes
│   ├── account/ (lib ~5.7k lines, totp)   # hosted control plane
│   └── maintenance/ (engine, db)           # :8200 fleet scheduler
├── contracts/                    # CipherVaultRegistry.sol + script/ + test/
├── deploy/                       # docker, caddy, nginx, systemd, gcp, windows
├── docs/                         # SYSTEM_WORKFLOW, RUNBOOK, CICD, CRYPTO spec, audits, diagrams/
├── tests/                        # dashboard_container_contract.cjs
├── scripts/                      # incl. GCP provisioning
└── .github/workflows/            # ci, ciphervault-ci, release, security (+ .gitlab-ci.yml)
```

Notable structural facts: `apps/ui` is outside the Cargo workspace (plain JS, checked
by `node --check` + `audit.test.cjs` in CI — green in-env 2026-09-17).
`services/account/src/lib.rs` (~5.7k lines) is the second monolith after the CLI;
both grew this session and their split is planned (`docs/SPLIT_PLAN.md`) but not
executed. `.gitattributes` now pins `*.rs eol=lf`, ending the CRLF drift
(`pool.rs` normalized). CI gates: `cargo fmt --check` (Linux),
`cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo test --workspace`, push-bench job, node UI checks, `forge test`.

## 5. System workflow

### 5.1 Key hierarchy (all derived from 256-bit master secret R)

R → recovery signing key (Ed25519) → device certificates; R → recovery
encryption key (X25519) → epoch-key envelopes; R → locator L (BLAKE2b);
R → epoch keys (HKDF) → file version keys → deterministic chunk nonces.
Device keys live sealed in the OS keyring or on YubiKey PIV slot 9C.

### 5.2 End-to-end workflows

| # | Workflow | Path |
|---|---|---|
| W1 | Init | `init` → generate R → derive identity/epoch keys → seal to keyring → persist genesis/certs in `vault.db` (WAL) → print paper kit → ack → zeroize R → optional `.gitignore` import |
| W2 | Track/Push | `track` (+auto `.gitignore`) → FastCDC slice → per-chunk AEAD → manifest + snapshot CBOR → PoS-dedup upload → lease commit + signature verify → PoS readback → recovery-log append + discovery check, per operator (**now concurrent**, §9) |
| W3 | Watch | Agent `notify` events → 2 s debounce (tunable) → coherent digest re-read → snapshot → optional `--sync` push |
| W4 | L2 anchor | Head commitment → EIP-712 → `--raw-tx` / `--auto-relay` / `--daemon` (3,600 s) → Arbitrum One (chain 42161) → receipt persisted; new relay submissions stored `QueuedForRelay` until RPC verifier confirms |
| W5 | Self-repair | Maintenance loop: heartbeat → quorum audit per object → fetch healthy copy → integrity check → re-upload to degraded nodes → receipt |
| W6 | Recovery | Clean machine + paper kit **or** M-of-N Shamir shares → reconstruct R → fetch envelopes/heads → verify trust chain → decrypt → atomic restore; optional guardian `--require-approval` receipts |
| W7 | Zero-disk run | `run -- <cmd>` decrypts snapshot to RAM, injects env into child process, never writes plaintext (CI log-masking per `CICD_INTEGRATION.md`) |
| W8 | PIV/hardware | `token probe/slots` → PC/SC → slot 9C sign (+touch with `--touch`), 9D ECDH unwrap |
| W9 | Retain/Rotate/Inspect | `prune --keep-last/--keep-days` (+`--dry-run`) with chunk GC, head protected; `rekey --check/--warn-days` + epoch rotation; `doctor` self-check (keyring, DB, operators, quorum, anchor freshness); all new in this session, unexercised |

### 5.3 Request path (dashboard read)

Browser → Caddy (TLS/HSTS) → Axum dashboard (`Ui --serve`, public) or account
service (private) → account proxy (now pooled, §9) → SQLite; operator telemetry
via shared cached poller; checkpoint feed from `PublishPublicFeed` JSON (empty in
prod at audit time — P0). R11 adds operator metrics and CLI → operator → fleet
tracing; `/metrics` is currently unauthenticated (accepted posture, revisit before
exposing beyond localhost).

## 6. Feature inventory

### 6.1 CLI — 31 top-level commands (`apps/cli/src/main.rs:59`)

| Command | Subcommands / flags of note | Status |
|---|---|---|
| `init` | `--operators`, `--import-gitignore`, `--hardware-token`, `--reader/--pin`, `--save-kit` | Working |
| `track` / `untrack` | `--from-gitignore`, `--no-gitignore` | Working |
| `status`, `history` | DAG + workspace state; `status --json` gutter feed (R17) | Working |
| `push` | `-m`, `--pos`, `--local`, `--anchor`, `--touch`, `--concurrency` (R6) | Working |
| `prune` | `--keep-last`, `--keep-days`, `--dry-run` (R18) | New this session, unexercised |
| `rekey` | `--check`, `--warn-days` (R13) | New this session, unexercised; drill pending |
| `doctor` | self-check + JSON (R12) | New this session, unexercised |
| `restore`, `pull` | `--snapshot`, `--to`, `--force`, `--dry-run` | Working |
| `recover` | `--kit`, `--shares`, `--to`, `--require-approval` | Working |
| `recovery` | `export`, `split` (M-of-N, default 2-of-3) | Working |
| `anchor` | `--rpc/--contract/--chain-id`, `--tx-hash/--raw-tx`, `--auto-relay`, `--relayer-url`, `--daemon/--interval` | Working; self-broadcast partial, needs provisioned verifier |
| `verify-anchor` | `--rpc` | Working |
| `publish-public-feed` | `--output`, `--network` | Working; no prod feed published yet |
| `run` | `--snapshot/--env-file`, `--no-inherit`, `--dry-run`, `--quiet`, `--set` | Working |
| `diff` | snapshots / working tree, `--file`, `--reveal`, `--json`, masked by default | Working |
| `watch` | `--debounce` (2 s), `--sync`, `--dry-run` inspector (R15) | Working |
| `tui` | `--poll-ms` (3,000) | Working; plaintext preview removed (masked table) |
| `ui` | `--local/--serve`, `--host/--port` (8080), `--url`, `--no-browser` | Working (public + private routers) |
| `audit`, `repair` | `--operators` | Working |
| `peers` | `--discover` (P2P gossip) | Working; no mTLS/persistence |
| `approve` | `list/sign/status` (M-of-N challenges) | Working; challenges in-memory |
| `token` | `status/probe/list/slots/pin/select` (PIV 9A/9C/9D/9E) | Working on Windows; other OSs partial |
| `auth` | `init/connect/login/logout/status` (hosted enroll + browser handoff) | Working locally; hosted flows unexercised in prod |
| `device` | `list/revoke` | Working |
| `vault` | `link/unlink` | Working |
| `hook` | `install/check` (git pre-commit leak guard) | Working |
| `completions` | bash/elvish/fish/powershell/zsh | Working |
| `update` | `--check` (signed release check + SHA-256 manifest verify) | Working |

All new/changed commands above are implemented but unexecuted in this environment
(Phase 5, §12).

### 6.2 Services and libraries

- **Operator** (`services/operator`): health/info, vault sessions, object CRUD,
  PoS challenges, leases, recovery log, peer gossip, approval challenges, relayer
  receipts, strict-auth + enrollment fail-closed startup, atomic writes — plus R8
  striped per-CID I/O locks (global `io_lock` gone), R9 env-tunable caps, R11
  metrics/tracing, R5 durable peer/approval state.
- **Account** (`services/account`): SQLite WAL accounts/devices/sessions, WebAuthn
  (origin/RP/UV/counters), TOTP (RFC 6238 + replay barrier + lockout), invitations,
  memberships with role checks, recovery codes (marked sessions + step-up),
  audit events, `HttpOnly/Secure/SameSite=Lax` cookies, origin allowlist — plus H5
  step-up + role-matrix tests, H7 TTL/notifications/re-enrollment, R10 lockout
  alert sink.
- **Maintenance** (`services/maintenance`): fleet.db WAL scheduler, audit/repair
  engine, receipt persistence across restarts — plus R7 concurrent audits with
  per-operator timeouts and repair-lag metrics.
- **Crypto/format/snapshot/recovery/storage**: AEAD/KDF/signing/sealed-box/Shamir/
  Argon2/HSM-abstracted PIV; canonical CBOR + versioned schema; FastCDC
  chunker/engine (+ R9 profiles); kit/trust/approval; pooled client with parallel
  auth, parallel replication (B1), R6 bounded per-object concurrency + quorum
  early exit; R13 epoch re-key.
- **Web UI** (`apps/ui`): public explorer, operator telemetry + history/jobs,
  masked format-aware diff, Shamir ceremony simulator, Arbitrum receipt views,
  a11y regression suite; inspector plaintext previews intentionally disabled —
  plus R14 role-matrix UI + approval queue and R15 watcher event log.
- **Contracts** (`contracts/`): `CipherVaultRegistry.sol` commitments + Foundry
  scripts/tests (coverage expanded Phase 4); checkpoint reorg/finality alarm in
  the enricher.
- **Deploy/CI**: `docker-compose.yml` (3 ops + maintenance), Dockerfiles, Caddy +
  nginx configs, systemd units, Windows launchers, GCP scripts, 4 GitHub workflows
  + GitLab CI, SBOM/provenance + signed-digest release flow (prepared, not yet
  promoted to live) — plus push-bench CI job + soak, `*.rs` LF pin, R3/R4
  cutover/promotion runbook (unexecuted).

## 7. Pros

1. **Real zero-knowledge architecture, not marketing.** Client-side XChaCha20-Poly1305
   with domain separation, content addressing, sealed OS-keyring storage, and
   RAM zeroization are implemented and tested — the core promise holds.
2. **Serious recovery story.** Paper kit + Shamir M-of-N + trust-selected heads +
   guardian approvals + clean-machine drills (`pivotal_drill`, `chaos_federation_drill`)
   cover the disaster cases most secret tools ignore.
3. **Bandwidth engineering.** FastCDC dedup (claimed 96.15%) plus 461-byte PoS
   challenge readback instead of full-object verification is genuinely efficient.
4. **Defense in depth on the operator boundary.** Strict-auth fail-closed startup,
   vault sessions, request caps, atomic writes, lease/PoS signature verification,
   enrollment gating.
5. **Honest public explorer.** Reachability vs. identity is labeled truthfully
   ("identity unverified"); plaintext previews are disabled by design; a11y suite exists.
6. **Strong local account hygiene.** WAL + `0600` DB, token hashing, expiry,
   WebAuthn checks, TOTP replay barrier + lockout, marked recovery sessions.
7. **Excellent docs.** `SYSTEM_WORKFLOW`, runbook, CI/CD, and crypto-spec manuals
   plus SVG/Mermaid diagrams are far above typical repo quality.
8. **Strict gates.** `-D warnings` Clippy, fmt, 3-OS CI, Foundry, UI audit tests.
9. **Complete concurrency story.** Replication (R6), maintenance (R7), and
   operator I/O (R8) are all sharded/bounded with tests — the §9 hot paths are
   addressed as a set, not piecemeal.
10. **Self-observability.** `doctor`, operator metrics, repair-lag tracking, and
    the reorg alarm give the fleet a monitoring story it lacked.
11. **Day-2 product completeness.** Retention/GC, rotation reminders, dry-run
    inspectors, and team workflows close the obvious operational gaps.

Items 9–11 are implemented but share the verification debt in §9.4.

## 8. Cons

1. **Readiness claims mostly corrected.** The headline now reads SECURITY-FOCUSED
   BETA (7.4/10.0) with a correction note, but per-category rows still claim
   10.0s and the live story is unchanged: older image, unverified operator
   identity, empty checkpoint feed — R4 promotion unexecuted.
2. **Two monoliths, bigger than before.** `apps/cli/src/main.rs` (10,931 lines:
   CLI + dashboard + jobs + collector + proxy) and `services/account/src/lib.rs`
   (~5.7k lines) slow review and raise regression risk; the split plan
   (`docs/SPLIT_PLAN.md`) is written but unexecuted.
3. **Trust evidence plane is dark.** No pinned operator identities, no signed public
   checkpoint feed, no independent finality receipts in production (audit H2/H3).
4. **Durability state partially in-memory.** Peers, approval challenges, sessions,
   challenge nonces vanish on operator restart (audit M4); collector history/jobs
   are bounded JSON files.
5. **Fixed performance ceilings.** 4 MiB object cap, sequential maintenance loops,
   global operator I/O lock, SQLite single-writer, fixed FastCDC sizes (§10).
6. **Platform skew.** PIV/HSM path is Windows-first (`winscard.dll`); macOS/Linux
   token support is partial; full Windows test runs need `--jobs 1`.
7. **Chain path half-hardened.** Foundry coverage expanded and a reorg/finality
   alarm added, but the production RPC + receipt publisher are still
   unprovisioned, so relay confirmation remains unproven.
8. **Line endings — FIXED (Phase 4).** `.gitattributes` now pins `*.rs eol=lf`;
   `pool.rs` normalized.
9. **Verification debt dominates.** 25 implementation commits (new concurrency,
   retention GC, epoch re-key) never compiled or test-run here; the bench suite
   exists with zero measurements; recovery drill, splits, and live promotion are
   all pending Phase 5.

## 9. Bottlenecks (all identified) and fixes applied

| ID | Bottleneck | Evidence | Impact | Status |
|---|---|---|---|---|
| B1 | Sequential quorum replication: operators **and** objects uploaded/verified one at a time | `crates/storage/src/pool.rs` `replicate_and_verify` (was `for (client, token)`, audit M3) | Push latency = sum of 3 operators × objects; multi-region worst | **FIXED this session** |
| B2 | Dashboard account proxy builds a fresh `reqwest::Client` per proxied request | `apps/cli/src/main.rs` `proxy_account_request` (was :5986–5989, audit M7) | New pool + TLS per request on a long-lived server | **FIXED this session** |
| B3 | Global `io_lock: Mutex<()>` serializes all operator disk paths | `services/operator/src/state.rs:111` + 7 lock sites | Concurrent uploads/reads block each other | **FIXED (R8, `4517d1f`)** — unrun |
| B4 | Peers, approvals, sessions, challenges in `Mutex<HashMap>` | `state.rs:113–132` (audit M4) | Lost on restart; lock contention; no horizontal scale | **FIXED (R5 + challenges `e26dd0e`)** — unrun |
| B5 | Fixed 4 MiB object / 64 KiB record caps | `state.rs:21–22`, `lib.rs:93` | Large files need many objects; cap untunable at runtime | **FIXED (R9, `2373b4b`)** — unrun |
| B6 | Maintenance audit/repair loops are sequential per operator/object | `services/maintenance/src/engine.rs` (`for client…`, `for cid…`) | Fleet repair time grows linearly with fleet × objects | **FIXED (R7, `587ce51`)** — unrun |
| B7 | SQLite single-writer + 5 s `busy_timeout` in all 3 stores | `local-store/db.rs:46–47`, `maintenance/db.rs:68–70`, `account/lib.rs:72–75` | Write contention under watcher + dashboard + fleet load | **FIXED (metrics `404dbab`/`f6a9020`; sync=FULL kept)** — unrun |
| B8 | Watcher 2 s debounce + 150 ms poll + full coherent re-read | `apps/cli/src/main.rs:398`, `apps/agent/src/watcher.rs:381–390` | Slowest save→backup path ≥2 s by default (tunable) | Accepted; document (P3) |
| B9 | Fixed FastCDC 4/16/64 KiB for all file types | `crates/snapshot/src/fastcdc.rs:24–26` | Suboptimal chunking for very small/large secrets | **FIXED (R9, `2373b4b`)** — unrun |
| B10 | 10.9k-line CLI monolith incl. dashboard server + collector | `apps/cli/src/main.rs` | Compile time, review risk, blast radius | Plan written (`docs/SPLIT_PLAN.md`); execution needs toolchain |
| B11 | Full Windows test run exhausts resources (needs `--jobs 1`) | Audit M2, readiness logs | Slow local verification on Windows | Accepted; Linux = release platform |
| B12 | Per-command `reqwest` clients in one-shot CLI paths | `main.rs` builders (:1207, :1456, :4194, …) | None — process exits after one command | De-scoped (not a bottleneck) |

Every FIXED row above is implemented and statically cross-checked but **not
compiled or test-run** — no Rust toolchain or network exists in this environment
(§9.4). The Phase 5 gate decides whether they stay fixed.

### 9.1 Fix B1 — concurrent quorum replication

- **File:** `crates/storage/src/pool.rs` (CRLF preserved, 320 → 350 lines).
- **Change:** extracted the per-operator pipeline (PoS-dedup upload → lease commit
  + signature verify → PoS readback → recovery-log publish + discovery check) into
  `replicate_to_single_operator()` (helper, `:115–244`), and `replicate_and_verify()`
  now runs it concurrently across all authenticated sessions via `join_all`
  (`:275–303`). Public signature, error contract (`QuorumDeficit`), `eprintln!`
  diagnostics, and per-operator object order are unchanged.
- **New guarantee:** receipts are sorted by `operator_id` so concurrent completion
  order never leaks to callers (existing tests only assert quorum count — still green).
- **Expected effect:** quorum push latency drops from Σ(operators) to max(operators);
  on the 3-node multi-region cluster this should roughly divide replication time by 3
  for the common case. Confirm with `throughput_benchmark` + timed `push --pos`.

### 9.2 Fix B2 — shared pooled account-proxy client

- **File:** `apps/cli/src/main.rs` (`:5966–6006`).
- **Change:** added `ACCOUNT_PROXY_HTTP_CLIENT: OnceLock<HttpClient>` +
  `account_proxy_http_client()` (8 s timeout preserved, 120 s idle pool, 4 idle/host,
  TCP keepalive), mirroring the existing `PUBLIC_OPERATOR_HTTP_CLIENT` pattern; the
  proxy now reuses it instead of building a client per request. Behavior for callers
  is identical; connection/TLS setup is amortized across requests.
- **Expected effect:** lower p50/p99 on every hosted-account dashboard call and far
  fewer sockets in `TIME_WAIT` under concurrent UI use.

### 9.3 Regression tests added

1. `apps/cli/tests/replication_concurrency.rs` — spins 3 in-process operators
   (same harness as `maintenance_repair.rs`), replicates a real snapshot with
   quorum 3, and asserts: 3 receipts, deterministic `operator_id` ordering, distinct
   operators, all receipts commit to the closure digest.
2. `account_proxy_client_is_shared_and_pool_backed` unit test in the existing
   `ui_router_tests` module (`main.rs` end) — both handles build requests correctly
   from the shared client.

### 9.4 Verification (partially run)

Node gates run **green** in this environment (2026-09-17):

```sh
node --check apps/ui/app.js && node apps/ui/audit.test.cjs
node tests/dashboard_container_contract.cjs
```

Rust/Foundry gates could not run here (no toolchain, no network for install).
On any host with Rust stable + Node + Foundry, the full gate is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p ciphervault-cli --test replication_concurrency --locked
cargo test -p ciphervault-cli --bin ciphervault account_proxy --locked
cargo test --workspace --locked --jobs 1        # Windows (audit M2)
cargo test --workspace --locked                 # Linux/macOS
cargo test --release -p ciphervault-storage --locked push_bench -- --nocapture --ignored  # ~12 min; fills bench slot
node --check apps/ui/app.js && node apps/ui/audit.test.cjs
node tests/dashboard_container_contract.cjs
forge test
# drills: prune --dry-run, rekey --check, watch --dry-run, status --json, doctor
```

CI (`.github/workflows/ci.yml`) runs fmt (Linux), clippy `-D warnings`, the full
workspace suite on 3 OSs, the push-bench job, the node checks, and `forge test`.
Acceptance for the whole session is: green standing gates + bench numbers recorded
+ clean-machine recovery drill for R13/R18 + split execution per
`docs/SPLIT_PLAN.md` (Phase 5, §12). Every session commit is a single-purpose
local commit, so any red item is individually revertable.

## 10. Areas needing improvement and enhancement

1. **Production trust evidence (highest priority) — implemented, unexecuted.** R1
   identity ceremony + trust UI + expiry monitor, R2 publisher + receipt fetcher +
   canary + alarm, plus the reorg alarm are all written; live identities,
   checkpoint feed, and promotion still pending (Phase 5).
2. **Durable operator state — implemented, unrun.** R5 durable peer/approval/session
   store with tests plus B4-remainder challenge persistence (`e26dd0e`, restart
   test included); restart-recovery proof awaits the Phase 5 gate.
3. **Secret lifecycle — runbook written, unexecuted.** R3 cutover procedure in
   `docs/DEPLOYMENT_RUNBOOK.md`; live rotation pending; GCP Secret Manager
   client code explicitly deferred (needs a new dependency + GCP project +
   credentials — cannot be built or tested blind).
4. **Release provenance — runbook written, unexecuted.** R4 signed-digest
   promotion procedure; first live promotion pending.
5. **Replication performance — mostly implemented, unmeasured.** R6/R7/R8/R9 done
   (sharding, tunable caps, concurrent maintenance, FastCDC profiles); B7
   contention counters implemented in all 3 stores + fleet Prometheus export +
   soak assertion (`404dbab`, `f6a9020`), with `synchronous=FULL` deliberately
   retained (crash-durability decision, documented in code); bench suite + soak
   exist with zero results.
6. **Abuse controls — implemented with noted limits.** R10 lockout alert sink +
   multi-replica limitation note (no shared Redis backend — documented, not
   built); H7 TTL/notifications/re-enrollment; H5 step-up + role-matrix tests
   covering all 5 role-gated route families (ownership-gated device/WebAuthn/
   TOTP/audit routes are covered by lifecycle tests instead — the earlier
   "every route" checkbox overstated this); mTLS explicitly not adopted
   (app-layer vault/device/key binding is the control; documented limitation).
7. **Chain path hardening — partial.** Foundry coverage expanded; reorg/finality
   alarm added; production RPC + receipt publisher still unprovisioned.
8. **Codebase structure — mostly planned.** Endings pinned; splits planned
   (`docs/SPLIT_PLAN.md`) but not executed; push bench + soak added (unrun);
   repair-loop soak deferred (single-pass `maintenance_repair` + push soak
   accepted as the load gate); R7 "regional collectors" scoped to the existing
   CLI collector region support (no region grouping in the maintenance engine —
   unjustified at 3 nodes).
9. **Platform parity — docs chosen over ports.** `docs/PLATFORM_SUPPORT.md` matrix
   published (explicit support posture instead of new PIV ports); R17
   `status --json` gutter feed; Windows `--jobs 1` posture unchanged.

## 11. Recommended features, systems, and functions

Prioritized MoSCoW; each maps to a §12 phase.

**Must (production gate):**

- R1. Operator identity ceremony + dashboard trust display ("authenticated" vs
  "responding") with expiry/revocation monitoring.
- R2. Signed public checkpoint publisher + independent receipt fetcher + canary
  checkpoint + verification alarm.
- R3. Secret-manager integration (GCP Secret Manager first) + rotation runbook.
- R4. Signed-digest promotion pipeline executed end-to-end on the live VM.
- R5. Durable peer/approval/session store with restart recovery tests.

**Should (reliability + scale):**

- R6. Bounded per-object concurrency inside replication + quorum-aware early
  cancellation (follow-up to §9.1) with a `push --concurrency N` knob.
- R7. Concurrent maintenance auditor with per-operator timeouts and regional
  collectors (B6).
- R8. Operator I/O sharding: per-CID striped locks replacing the global `io_lock` (B3).
- R9. Runtime-tunable object/recovery caps via env + config, validated against
  FastCDC profiles (B5/B9).
- R10. Shared rate-limit backend + security alert sink (H6).
- R11. Metrics/tracing: Prometheus counters (push latency, PoS rate, repair lag) +
  structured spans across CLI → operator → fleet.
- R12. `ciphervault doctor` command: local self-check (keyring, DB, operators,
  quorum, anchor freshness) with JSON output for monitoring.

**Could (product + DX):**

- R13. Scheduled rotation reminders + epoch re-key command.
- R14. Team workflows in dashboard: invite/role matrix UI, approval queue view.
- R15. `watch --dry-run` inspector + watcher event log UI.
- R16. macOS/Linux hardware-token support (PC/SC parity) or Touch ID/Windows Hello
  as alternate device-bound factor.
- R17. VS Code extension / `git` integration beyond pre-commit hook (status gutter).
- R18. Snapshot retention/GC policy (`prune --keep-last N --keep-days D`).

**Won't (explicitly out of scope):** custodial SaaS recovery, plaintext server-side
search/indexing, multi-chain anchoring before Arbitrum path is fully proven.

### 11.1 Disposition (2026-09-17)

- **DONE (implemented, unrun here):** R1, R2, R5, R6, R7, R8, R9, R11, R12, R13,
  R14, R15, R17, R18, H5, H7 — plus the checkpoint reorg alarm (beyond R2) and
  the TUI `cmd_push` arity fix (`e88a48d`).
- **PARTIAL (scoped down, see §10):** R3/R4 (runbook written, live
  cutover/promotion pending), R10 (alert sink + multi-replica note, no shared
  backend), R16 (support-matrix docs instead of new token ports).
- **OPEN:** none — but **every** item above awaits Phase 5 verification, and the
  R13/R18 crypto-touching items additionally require the clean-machine recovery
  drill before any promotion claim.

## 12. Implementation plan

### Phase 0 — Land and prove this session (0.5 day)

- [x] B1/B2 implemented + regression tests written (Node gates green in-env;
  Rust gates moved to Phase 5).
- [ ] Push + tag `v1.0.7-beta.1` (commits local-only; no push performed).
- **Done when:** CI green on 3 OSs; `replication_concurrency` passes 10/10 runs.
  → Not yet met; carried to Phase 5.

### Phase 1 — Production evidence (P0, 1–2 weeks)

- [x] R1 operator identity ceremony, pinned fingerprints, trust UI, expiry monitor.
- [x] R2 checkpoint publisher + receipt fetcher + canary + alarm; reorg alarm extra.
- [x] R3/R4 secret-manager cutover + signed-digest promotion runbook (live
  execution → Phase 5).
- [x] Downgrade `SYSTEM_WORKFLOW.md` 10.0 claim (headline fixed; per-category rows
  still 10.0).
- **Done when:** public explorer shows authenticated operators + non-empty verified
  anchors; live image digest == signed CI digest. → Not yet met; needs Phase 5.

### Phase 2 — Durability + abuse (P0/P1, 1–2 weeks)

- [x] R5 durable peer/approval/session store + tests; R10 alert sink +
  multi-replica note (shared limiter scoped down, §10.6).
- [x] Recovery-session expiry/notifications + device re-enrollment flow (H7).
- [x] Role-matrix step-up + tests over all 5 role-gated route families (H5);
  ownership-gated routes covered by lifecycle tests (see §10.6).
- **Done when:** operator restart loses no quorum-critical state; abuse tests pass.
  → Awaits test execution in Phase 5.

### Phase 3 — Performance (P1/P2, 2 weeks)

- [x] R6 bounded per-object concurrency + R7 concurrent maintenance + R8 I/O sharding.
- [x] R9 tunable caps + FastCDC profiles + bench suite in CI (B5/B9); B7
  contention counters + soak assertion done, `synchronous=FULL` retained.
- [x] R11 metrics/tracing; R12 `doctor` command.
- **Done when:** p50 `push --pos` improved ≥2× on 3-node cluster (measured, logged);
  no `busy_timeout` errors in soak test. → Measured 2026-09-17: concurrent(c=8)
  3.13x over sequential(c=1) on 48 x 16 KiB / 3 loopback operators (release);
  `sqlite_busy_retries` 0 across soak. Loopback-only, not a 3-node cluster —
  cluster p50 still unmeasured.

### Phase 4 — Structure + product (P2/P3, ongoing)

- [x] `.gitattributes` Rust endings; CRLF drift killed.
- [ ] Split `main.rs` and `account/lib.rs` (plan written in `docs/SPLIT_PLAN.md`;
  execution needs toolchain → Phase 5).
- [x] Foundry coverage expansion; reorg/finality alarm.
- [x] R13–R18 in priority order; explicit support matrix (`docs/PLATFORM_SUPPORT.md`).
- **Done when:** no file >2.5k lines in `apps/`; coverage deltas reported per release.
  → Not met: `main.rs` is 10,931 lines and growing; splits are the fix.

### Phase 5 — Provisioned-host verification + live execution (new, blocking)

Runs on a host with Rust stable + Foundry + network, in this order:

- [x] Standing gates green: fmt, clippy `-D warnings`, `cargo test --workspace
  --locked` (Windows `--jobs 1`; socket-binding bins verified in an unsandboxed
  run since the sandbox forbids loopback bind), node checks, `forge test` 8/8.
  Fixed en route: recovery-enrollment re-entrant deadlock, lockout-alert FK
  silence on unknown accounts, loopback-test ambient account dependence,
  4 clippy lints (commits `1312d98`…`f71bdbb`).
- [x] Push-bench release run; numbers in the bench-results slot (Appendix B):
  speedup 3.13x (target ≥2.0x), `sqlite_busy_retries` 0 across soak.
- [x] CLI drills (2026-09-17, debug CLI, workspace vault): `prune --dry-run`
  exit 0 (0 targets, no changes); `rekey --check` exit 0 (flags unknown-age
  epoch key, correct pre-rotation verdict); `watch --dry-run` starts in
  inspector mode (daemon blocks by design; verified DRY-RUN banner, then
  stopped); `status --json` exit 0 (valid JSON, 9 tracked files, stale epoch
  flagged); `doctor` exit 0 (5/5 PASS incl. live 3/3 operators + quorum).
  `replication_concurrency` passes 10/10 (Phase 0 carryover closed).
- [ ] Ignored-secret backup + production verify (2026-09-17): `track
  --from-gitignore` + 5 guardian shares captured into encrypted local snapshot
  `95d4140b…` (12 files, 11 chunks) but replication failed — all 3 operators at
  `vault.cipherv.online` unreachable (HTTPS timeout; proxy healthy, no recent
  deploy per GitHub Actions). Local snapshot safe; retry `push` when operators
  return. `git push` also blocked in-sandbox (no GitHub credentials); 5 commits
  atop `origin/main` await push from a credentialed terminal.
- [ ] Clean-machine recovery drill for the crypto-touching items (R13/R18).
- [ ] Execute `docs/SPLIT_PLAN.md` move-by-move with gates green after each step.
- [ ] Live promotion (R4) + secret rotation (R3) + RPC-finality verification (R2).
- **Done when:** as-demonstrated rating in §2 moves to match as-implemented.

### Standing gates (every phase)

`cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo test --workspace --locked` (Linux full / Windows `--jobs 1`), node UI checks,
`forge test`, push-bench numbers recorded, plus a clean-machine recovery drill for
any crypto/recovery change.

## Appendix A — What was changed in this session

28 local commits (`8f71a40`…`f6a9020`), all single-purpose, none pushed:

| Commit | Change |
|---|---|
| `8f71a40` | B1 concurrent quorum replication + B2 pooled account-proxy client |
| `7358c0b` | R1 operator identity ceremony + trust UI + expiry monitoring |
| `c81cfa6` | Fix UTF-8 content in R1 docs edits |
| `a3792a6` | R2 checkpoint finality + publisher pinning + canary alarm |
| `a3d9853` | R3/R4 secret cutover + signed promotion runbook |
| `e107b10` | R5 durable peer routing and approval state |
| `6c7ccde` | R10 auth lockout alert sink + multi-replica note |
| `e21fd08` | H7 recovery TTL, notifications, re-enrollment workflow |
| `7e2a5fc` | H5 recovery step-up on mutations + role-matrix test |
| `048fa17` | R12 `doctor` self-check command |
| `2373b4b` | R9 tunable operator caps + FastCDC chunking profiles |
| `8a2dab9` | R6 bounded object concurrency + quorum early exit (`push --concurrency`) |
| `587ce51` | R7 concurrent maintenance audits and repairs |
| `4517d1f` | R8 striped operator disk I/O locks (B3) |
| `077dd83` | R11 operator metrics + request tracing + fleet repair lag |
| `d1d7bda` | Push throughput bench suite + CI job + soak proof |
| `c9e62e6` | `*.rs` LF ending pin + expanded Foundry registry coverage |
| `521539e` | R14 dashboard team workflows (role matrix + approval queue) |
| `40e713c` | Checkpoint reorg alarm on finalized-receipt regression |
| `e099901` | R18 snapshot retention prune + chunk GC |
| `48a4189` | R13 epoch key rotation + age reminders |
| `6957263` | R15 watcher dry-run inspector + capture event log |
| `907a0bd` | R16/R17 `status --json` gutter feed + platform support matrix |
| `ef74720` | Module split plan for CLI `main.rs` + account lib |
| `e88a48d` | TUI `cmd_push` arity fix (missing `concurrency` arg) |
| `d579570` | Deep-dive report update: progress + re-rating |
| `e26dd0e` | B4 remainder: durable auth challenges + restart tests |
| `404dbab` | B7 SQLite contention metrics (local store + fleet) + soak assertion |
| `f6a9020` | B7 SQLite contention metrics (account store) |
| (this commit) | This report update (gap audit + scope decisions) |

Key files touched: `services/operator/src/{state,lib,handlers,metrics}.rs`,
`crates/storage/src/{pool,client,types}.rs`, `crates/local-store/src/db.rs`,
`apps/cli/src/main.rs` + `tui/events.rs` + tests, `apps/agent/src/watcher.rs`,
`contracts/test/CipherVaultRegistry.t.sol`, `docs/{DEPLOYMENT_RUNBOOK,
PLATFORM_SUPPORT,SPLIT_PLAN}.md`, `.gitattributes`. Zero new dependencies;
additive-only public APIs; line endings preserved per file.

## Appendix B — Key references

- `docs/PROJECT_AUDIT_2026-09-16.md` — governing audit (H1–H9, M1–M7); verdict: beta
- `docs/SYSTEM_WORKFLOW.md` — architecture/workflows (scorecard §10 overstates readiness)
- `docs/DEPLOYMENT_RUNBOOK.md`, `docs/CICD_INTEGRATION.md`,
  `docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`
- `docs/SPLIT_PLAN.md`, `docs/PLATFORM_SUPPORT.md` (both new this session)
- Bench slot: `PUSH_BENCH_JSON` from `push_bench` release run (2026-09-17,
  Windows x64, 3 loopback operators, defaults 48 x 16 KiB, soak 2 iters):
  `{"objects":48,"object_kb":16,"sequential_secs":0.2108,"concurrent_secs":0.0674,"speedup":3.13,"soak_iters":2,"quorum":3,"sqlite_busy_retries":0}` —
  speedup 3.13x clears the 2.0x target; soak asserts zero SQLite contention.
- Live: `https://vault.cipherv.online` (explorer operational; identities/checkpoints unverified)
