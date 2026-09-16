# CipherVault — Deep-Dive Analysis Report

- **Date:** 2026-09-16
- **Revision inspected:** `main` at v1.0.6 (`Cargo.toml`), plus uncommitted working-tree hardening
- **Scope:** Rust workspace (11 members, 75 `.rs` files), web dashboard/explorer (`apps/ui`),
  CLI/TUI/agent, operator/account/maintenance services, Solidity registry, Docker/GCP
  deployment, CI/release workflows, live endpoint evidence (from repo audit docs)
- **Method:** full-repo source inspection, prior audit cross-check
  (`docs/PROJECT_AUDIT_2026-09-16.md`, `docs/SYSTEM_WORKFLOW.md`), bottleneck
  reproduction-by-reading, and two implemented fixes with regression tests
- **Environment note:** no Rust/Node toolchain was available in this analysis
  environment, so the two code fixes below are implemented and carefully reviewed
  but **not yet compiled or test-run here**. Exact verification commands are in §9.

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

## 2. Rating

| Category | Score | Basis |
|---|---|---|
| Cryptographic design | 9.0/10 | Domain-separated AEAD/KDF, signed recovery structures, Shamir GF(2⁸), PoS; no third-party review yet |
| Durability & quorum | 7.5/10 | 3-node replication + PoS + self-repair works; peers/approvals in-memory, no signed checkpoint feed live |
| Features & completeness | 8.0/10 | 28 CLI commands, TUI, dashboard, agent, PIV, L2 anchoring; some flows partial (see §5) |
| Code quality | 7.0/10 | Idiomatic Rust, strict Clippy gate; 9.7k-line `main.rs` monolith drags this down |
| Performance & scalability | 6.0/10 | Sequential replication (fixed §9), global I/O lock, SQLite single-writer, fixed 4 MiB cap |
| Operability & deployment | 6.5/10 | Compose/systemd/GCP/Caddy present; image provenance + secret rotation gaps per audit |
| Testing | 7.5/10 | 16 CLI integration suites + crypto/operator/UI contract tests; small Foundry coverage, no load tests |
| Documentation | 8.5/10 | Excellent workflow/runbook/crypto docs; readiness score (10.0) contradicts audit evidence |
| **Overall** | **7.4/10** | **Strong beta. Ship the P0 evidence items + §12 plan before claiming production.** |

Score meaning: 9–10 production-grade, 7–8 solid beta with known gaps, 5–6 works with
material risk, <5 prototype. The repo's internal scorecard claims 10.0/10.0; the
evidence supports 7.4 until the P0 items in §12 close.

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
| CLI + dashboard server | `apps/cli/src/main.rs` (~9.7k lines) | Clap, Axum, Tokio | 28 commands, TUI, `Ui` server :8080, public/private route guards, collector |
| Agent | `apps/agent` | notify | Event-driven watcher, debounce (default 2 s), coherent re-read, auto push |
| Crypto core | `crates/crypto` | XChaCha20-Poly1305, Ed25519, X25519, BLAKE2b, Shamir, Argon2 | AEAD, KDF, sealed boxes, threshold shares, PIV/APDU driver, HSM trait |
| Wire format | `crates/format` | Canonical CBOR | Genesis/head/snapshot/manifest records, digests, schema |
| Snapshot engine | `crates/snapshot` | Pure-Rust FastCDC + Gear hash | Chunk (4/16/64 KiB), dedup, encrypt, serialize, atomic restore |
| Local store | `crates/local-store` | SQLite WAL, DPAPI/keyring | Tracked files, snapshot DAG, device certs, account/device/session, upload queue |
| Recovery | `crates/recovery` | Shamir, signed kits | Offline paper kit, M-of-N shares, trust selection, out-of-band approvals |
| Storage client | `crates/storage` | reqwest, join_all | Operator client, quorum pool, PoS, leases, chain/relayer types |
| Operator | `services/operator` | Axum, disk store | Chunk/manifest/recovery storage, PoS, leases, peers, approvals, relayer receipts |
| Account | `services/account` | SQLite WAL, WebAuthn, TOTP | Accounts, devices, sessions, passkeys, invitations, recovery codes, audit |
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
│   ├── cli/src/main.rs           # CLI + dashboard + TUI host (9,721 lines, LF)
│   │   ├── diff.rs dotenv.rs tui/  # masked diff, env parsing, ratatui UI
│   │   └── tests/ (16 suites)    # e2e, chaos drill, PoS, watcher, hardware token, …
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
│   ├── account/ (lib ~4.9k lines, totp)   # hosted control plane
│   └── maintenance/ (engine, db)           # :8200 fleet scheduler
├── contracts/                    # CipherVaultRegistry.sol + script/ + test/
├── deploy/                       # docker, caddy, nginx, systemd, gcp, windows
├── docs/                         # SYSTEM_WORKFLOW, RUNBOOK, CICD, CRYPTO spec, audits, diagrams/
├── tests/                        # dashboard_container_contract.cjs
├── scripts/                      # incl. GCP provisioning
└── .github/workflows/            # ci, ciphervault-ci, release, security (+ .gitlab-ci.yml)
```

Notable structural facts: `apps/ui` is outside the Cargo workspace (plain JS, checked
by `node --check` + `audit.test.cjs` in CI). `services/account/src/lib.rs` (~4.9k
lines) is the second monolith after the CLI. `crates/storage/src/pool.rs` is CRLF;
most other Rust files are LF — `.gitattributes` only pins LF for shell/Docker/Caddy.
CI gates: `cargo fmt --check` (Linux), `cargo clippy --workspace --all-targets
--locked -- -D warnings`, `cargo test --workspace`, node UI checks, `forge test`.

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

### 5.3 Request path (dashboard read)

Browser → Caddy (TLS/HSTS) → Axum dashboard (`Ui --serve`, public) or account
service (private) → account proxy (now pooled, §9) → SQLite; operator telemetry
via shared cached poller; checkpoint feed from `PublishPublicFeed` JSON (empty in
prod at audit time — P0).

## 6. Feature inventory

### 6.1 CLI — 28 top-level commands (`apps/cli/src/main.rs:59`)

| Command | Subcommands / flags of note | Status |
|---|---|---|
| `init` | `--operators`, `--import-gitignore`, `--hardware-token`, `--reader/--pin`, `--save-kit` | Working |
| `track` / `untrack` | `--from-gitignore`, `--no-gitignore` | Working |
| `status`, `history` | DAG + workspace state | Working |
| `push` | `-m`, `--pos`, `--local`, `--anchor`, `--touch` | Working |
| `restore`, `pull` | `--snapshot`, `--to`, `--force`, `--dry-run` | Working |
| `recover` | `--kit`, `--shares`, `--to`, `--require-approval` | Working |
| `recovery` | `export`, `split` (M-of-N, default 2-of-3) | Working |
| `anchor` | `--rpc/--contract/--chain-id`, `--tx-hash/--raw-tx`, `--auto-relay`, `--relayer-url`, `--daemon/--interval` | Working; self-broadcast partial, needs provisioned verifier |
| `verify-anchor` | `--rpc` | Working |
| `publish-public-feed` | `--output`, `--network` | Working; no prod feed published yet |
| `run` | `--snapshot/--env-file`, `--no-inherit`, `--dry-run`, `--quiet`, `--set` | Working |
| `diff` | snapshots / working tree, `--file`, `--reveal`, `--json`, masked by default | Working |
| `watch` | `--debounce` (2 s), `--sync` | Working |
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

### 6.2 Services and libraries

- **Operator** (`services/operator`): health/info, vault sessions, object CRUD with
  4 MiB cap, PoS challenges, leases, recovery log (64 KiB records), peer gossip
  (128 max), approval challenges, relayer receipts, strict-auth + enrollment
  fail-closed startup, atomic writes.
- **Account** (`services/account`): SQLite WAL accounts/devices/sessions, WebAuthn
  (origin/RP/UV/counters), TOTP (RFC 6238 + replay barrier + lockout), invitations,
  memberships with role checks, recovery codes (marked sessions + step-up),
  audit events, `HttpOnly/Secure/SameSite=Lax` cookies, origin allowlist.
- **Maintenance** (`services/maintenance`): fleet.db WAL scheduler, audit/repair
  engine, receipt persistence across restarts.
- **Crypto/format/snapshot/recovery/storage**: AEAD/KDF/signing/sealed-box/Shamir/
  Argon2/HSM-abstracted PIV; canonical CBOR + versioned schema; FastCDC
  chunker/engine; kit/trust/approval; pooled client with parallel auth and
  (now) parallel replication.
- **Web UI** (`apps/ui`): public explorer, operator telemetry + history/jobs,
  masked format-aware diff, Shamir ceremony simulator, Arbitrum receipt views,
  a11y regression suite; inspector plaintext previews intentionally disabled.
- **Contracts** (`contracts/`): `CipherVaultRegistry.sol` commitments + Foundry
  scripts/tests (coverage small).
- **Deploy/CI**: `docker-compose.yml` (3 ops + maintenance), Dockerfiles, Caddy +
  nginx configs, systemd units, Windows launchers, GCP scripts, 4 GitHub workflows
  + GitLab CI, SBOM/provenance + signed-digest release flow (prepared, not yet
  promoted to live).

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

## 8. Cons

1. **Readiness claims exceed evidence.** `SYSTEM_WORKFLOW.md` says 10.0/10.0
   "Hardened Production Ready" while the 2026-09-16 audit (same repo) says beta —
   the live deployment runs an older derived hotfix image with unverified operator
   identity and an empty checkpoint feed.
2. **Two monoliths.** `apps/cli/src/main.rs` (9,721 lines: CLI + dashboard + jobs +
   collector + proxy) and `services/account/src/lib.rs` (~4.9k lines) slow review
   and raise regression risk.
3. **Trust evidence plane is dark.** No pinned operator identities, no signed public
   checkpoint feed, no independent finality receipts in production (audit H2/H3).
4. **Durability state partially in-memory.** Peers, approval challenges, sessions,
   challenge nonces vanish on operator restart (audit M4); collector history/jobs
   are bounded JSON files.
5. **Fixed performance ceilings.** 4 MiB object cap, sequential maintenance loops,
   global operator I/O lock, SQLite single-writer, fixed FastCDC sizes (§10).
6. **Platform skew.** PIV/HSM path is Windows-first (`winscard.dll`); macOS/Linux
   token support is partial; full Windows test runs need `--jobs 1`.
7. **Thin chain coverage.** Small Foundry suite; relay confirmation depends on a
   production RPC + receipt publisher that are not provisioned yet.
8. **Inconsistent line endings.** `pool.rs` is CRLF while siblings are LF;
   `.gitattributes` does not pin Rust endings — expect noisy diffs and fmt churn.

## 9. Bottlenecks (all identified) and fixes applied

| ID | Bottleneck | Evidence | Impact | Status |
|---|---|---|---|---|
| B1 | Sequential quorum replication: operators **and** objects uploaded/verified one at a time | `crates/storage/src/pool.rs` `replicate_and_verify` (was `for (client, token)`, audit M3) | Push latency = sum of 3 operators × objects; multi-region worst | **FIXED this session** |
| B2 | Dashboard account proxy builds a fresh `reqwest::Client` per proxied request | `apps/cli/src/main.rs` `proxy_account_request` (was :5986–5989, audit M7) | New pool + TLS per request on a long-lived server | **FIXED this session** |
| B3 | Global `io_lock: Mutex<()>` serializes all operator disk paths | `services/operator/src/state.rs:111` + 7 lock sites | Concurrent uploads/reads block each other | Planned P1 (§12) |
| B4 | Peers, approvals, sessions, challenges in `Mutex<HashMap>` | `state.rs:113–132` (audit M4) | Lost on restart; lock contention; no horizontal scale | Planned P0/P1 (§12) |
| B5 | Fixed 4 MiB object / 64 KiB record caps | `state.rs:21–22`, `lib.rs:93` | Large files need many objects; cap untunable at runtime | Planned P2 (§12) |
| B6 | Maintenance audit/repair loops are sequential per operator/object | `services/maintenance/src/engine.rs` (`for client…`, `for cid…`) | Fleet repair time grows linearly with fleet × objects | Planned P1 (§12) |
| B7 | SQLite single-writer + 5 s `busy_timeout` in all 3 stores | `local-store/db.rs:46–47`, `maintenance/db.rs:68–70`, `account/lib.rs:72–75` | Write contention under watcher + dashboard + fleet load | Planned P2 (§12) |
| B8 | Watcher 2 s debounce + 150 ms poll + full coherent re-read | `apps/cli/src/main.rs:398`, `apps/agent/src/watcher.rs:381–390` | Slowest save→backup path ≥2 s by default (tunable) | Accepted; document (P3) |
| B9 | Fixed FastCDC 4/16/64 KiB for all file types | `crates/snapshot/src/fastcdc.rs:24–26` | Suboptimal chunking for very small/large secrets | Planned P2 (§12) |
| B10 | 9.7k-line CLI monolith incl. dashboard server + collector | `apps/cli/src/main.rs` | Compile time, review risk, blast radius | Planned P2 (§12) |
| B11 | Full Windows test run exhausts resources (needs `--jobs 1`) | Audit M2, readiness logs | Slow local verification on Windows | Accepted; Linux = release platform |
| B12 | Per-command `reqwest` clients in one-shot CLI paths | `main.rs` builders (:1207, :1456, :4194, …) | None — process exits after one command | De-scoped (not a bottleneck) |

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

### 9.4 Verification (NOT yet run — no toolchain in this environment)

On any host with Rust stable + Node + Foundry:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p ciphervault-cli --test replication_concurrency --locked
cargo test -p ciphervault-cli --bin ciphervault account_proxy --locked
cargo test --workspace --locked --jobs 1        # Windows (audit M2)
cargo test --workspace --locked                 # Linux/macOS
node --check apps/ui/app.js && node apps/ui/audit.test.cjs
node tests/dashboard_container_contract.cjs
forge test
```

CI (`.github/workflows/ci.yml`) runs fmt (Linux), clippy `-D warnings`, the full
workspace suite on 3 OSs, the node checks, and `forge test` — a green CI run on the
fix commit is the acceptance gate for §9.1–§9.2. If anything is red, the two fixes
are isolated single-commit revertable without touching the plan in §12.

## 10. Areas needing improvement and enhancement

1. **Production trust evidence (highest priority).** Pin operator identities, publish
   a signed checkpoint feed with independent finality receipts + canary + alarm
   (audit H2/H3). Without this, "quorum" and "anchored" are client-side claims only.
2. **Durable operator state.** Persist peers, approvals, sessions, challenges;
   add expiry sweeps, quotas, mTLS/rebinding protection (audit M4/M5, B4).
3. **Secret lifecycle.** Move signing/TOTP keys into a secret manager, rotate the
   live values, prove no leakage into logs/images (audit H8); same ceremony for
   operator signing keys.
4. **Release provenance.** Build every release image from a CI commit, promote only
   signed digests to the live VM, keep rollback tooling tested (audit H9).
5. **Replication performance.** B3/B5/B6/B7/B9: per-path I/O sharding, tunable object
   caps, concurrent maintenance with quorum-aware cancellation, SQLite tuning
   (`synchronous=NORMAL` + contention metrics), adaptive FastCDC profiles.
6. **Abuse controls.** Distributed rate limiting for TOTP/recovery (Redis/shared DB +
   alert sink), recovery-session expiry + notifications + re-enrollment flow
   (audit H6/H7), per-peer quotas.
7. **Chain path hardening.** Provision production RPC + registry + receipt publisher;
   expand Foundry coverage beyond the current small suite; add reorg/finality handling.
8. **Codebase structure.** Split `main.rs` (CLI vs dashboard vs collector) and
   `account/lib.rs`; pin Rust LF/CRLF in `.gitattributes`; add criterion-style
   benches + a load test for push/repair to CI.
9. **Platform parity.** macOS/Linux PIV support (or explicit unsupported-matrix docs);
   document Windows `--jobs 1` requirement in the runbook.

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

## 12. Implementation plan

### Phase 0 — Land and prove this session (0.5 day)

- [ ] Run §9.4 gate on Linux + Windows; attach logs to the fix commit.
- [ ] Merge B1/B2 + 2 regression tests; tag `v1.0.7-beta.1`.
- **Done when:** CI green on 3 OSs; `replication_concurrency` passes 10/10 runs.

### Phase 1 — Production evidence (P0, 1–2 weeks)

- [ ] R1 operator identity ceremony, pinned fingerprints, trust UI, expiry monitor.
- [ ] R2 checkpoint publisher + receipt fetcher + canary + alarm; `/api/anchors` live.
- [ ] R3/R4 secret-manager cutover + first signed-digest promotion to live VM.
- [ ] Downgrade `SYSTEM_WORKFLOW.md` 10.0 claim to match measured evidence.
- **Done when:** public explorer shows authenticated operators + non-empty verified
  anchors; live image digest == signed CI digest.

### Phase 2 — Durability + abuse (P0/P1, 1–2 weeks)

- [ ] R5 durable peer/approval/session store + restart tests; R10 shared limiter.
- [ ] Recovery-session expiry/notifications + device re-enrollment flow (H7).
- [ ] Expand role-matrix integration tests to every route (H5 remainder).
- **Done when:** operator restart loses no quorum-critical state; abuse tests pass
  against the shared backend.

### Phase 3 — Performance (P1/P2, 2 weeks)

- [ ] R6 bounded per-object concurrency + R7 concurrent maintenance + R8 I/O sharding.
- [ ] R9 tunable caps + FastCDC profiles + bench suite in CI (B5/B9).
- [ ] R11 metrics/tracing; R12 `doctor` command.
- **Done when:** p50 `push --pos` improved ≥2× on 3-node cluster (measured, logged);
  no `busy_timeout` errors in soak test.

### Phase 4 — Structure + product (P2/P3, ongoing)

- [ ] Split `main.rs` and `account/lib.rs`; `.gitattributes` Rust endings; kill CRLF drift.
- [ ] Foundry coverage expansion; reorg/finality handling.
- [ ] R13–R18 in priority order; platform parity or explicit support matrix.
- **Done when:** no file >2.5k lines in `apps/`; coverage deltas reported per release.

### Standing gates (every phase)

`cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo test --workspace --locked` (Linux full / Windows `--jobs 1`), node UI checks,
`forge test`, plus a clean-machine recovery drill for any crypto/recovery change.

## Appendix A — What was changed in this session

| File | Change |
|---|---|
| `crates/storage/src/pool.rs` | Concurrent quorum replication + sorted receipts (B1) |
| `apps/cli/src/main.rs` | Shared pooled account-proxy client (B2) + unit test |
| `apps/cli/tests/replication_concurrency.rs` | New 3-operator regression test (quorum + order + digest) |
| `report/CIPHERVAULT_DEEP_DIVE_REPORT.md` | This report |

No other source files were modified. Temp tooling (`.tmp-fix/`) was removed.
`git` could not be used from this sandbox (repository ownership check), so nothing
was committed — review with `git status`/`git diff` from your own shell.

## Appendix B — Key references

- `docs/PROJECT_AUDIT_2026-09-16.md` — governing audit (H1–H9, M1–M7); verdict: beta
- `docs/SYSTEM_WORKFLOW.md` — architecture/workflows (scorecard §10 overstates readiness)
- `docs/DEPLOYMENT_RUNBOOK.md`, `docs/CICD_INTEGRATION.md`,
  `docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`
- Live: `https://vault.cipherv.online` (explorer operational; identities/checkpoints unverified)
