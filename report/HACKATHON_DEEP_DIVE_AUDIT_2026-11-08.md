# CipherVault — Full Deep-Dive Audit & Hackathon Review

**Date:** 8 November 2026
**Audited commit:** `b484156` — release v1.0.30 (branch `main`)
**Repository:** `github.com/samuel-1-avson/CipherVault` (public)
**Auditor method:** 5 parallel specialist audits (core crypto, operator network, user surfaces, Hermes plugin, testing/ops) + independent re-verification of every critical claim by the synthesizing auditor. No files were modified by the audit.
**Hackathon:** Hermes Agent Plugin Hackathon (Nous Research) — $20,000 in cash prizes, submissions due **5PM EST, Nov 11**, judged on **usefulness, reliability, polish, and creativity**, with explicit preference for plugins that *"do more than a prompt or a skill could."* Entry requirements: (1) PR adding the plugin to the Hermes plugin catalog, (2) demo video <90s on X tagging @NousResearch, (3) Typeform submission linking both.

---

## 1. Executive Verdict

**CipherVault the product is real, substantial, and far beyond hackathon-typical scope. CipherVault the hackathon entry is not yet submittable — and is fixable in roughly one focused day.**

This is not a wrapper around an API or a prompt in a trench coat. Underneath the plugin sits a 14-crate Rust workspace (~122,750 lines of Rust, 897 annotated Rust tests), a zero-knowledge encrypted backup engine with content-defined chunking, a sovereign consensus chain, a libp2p operator federation, hardware-token (YubiKey PIV) support, threshold recovery, and a RAM-only secret execution path. That depth is the entry's greatest asset: judges who look under the hood will find a real system.

But the plugin that judges will actually install and run wraps a **stale v1.0.0 binary from September 16** while the source tree is at **v1.0.30**. Against that binary, the plugin's flagship `scan` tool errors on its first flag, and the `run` tool — the demo's money shot — fails against the live vault with an authentication error. A catalog install on a clean machine cannot find any binary at all. The validator is green; the demo is not.

> **Go / No-Go for Nov 11: NO-GO as-is. GO after the 6-item minimum fix list in §8 (≈1 day of work).**

The honest one-liner: **the idea and the engine deserve a top-tier entry; the shipped artifact currently does not match either.**

---

## 2. Ratings

### 2.1 The hackathon judging criteria (for `plugins/ciphervault` as it stands today)

| Criterion | Score /10 | Why |
|---|---:|---|
| **Usefulness** | **6** | The problem is real and painful — AI coding agents leak `.env` files, and "scan + RAM-only run + recovery drill" is a genuinely useful toolkit. Docked because two of five tools fail against the shipped binary, so the usefulness is currently theoretical for a judge. |
| **Reliability** | **3** | Binary/source skew (v1.0.0 vs v1.0.30), `scan` dead on arrival (`--deep` rejected — verified live), `run` failing auth against the repo vault, standalone catalog install resolving to a binary that does not exist on PATH. Reliability is the entry's weakest axis and the one judges test first. |
| **Polish** | **5** | Validator fully green, README/DEMO structured, honest compat notes. Docked for a static desktop pane with hard-coded status dots, a `post_tool_call` hook that only `print()`s, and doc claims about a `cv.exe` that does not exist. |
| **Creativity** | **7** | The strongest criterion. Real subprocess tools a prompt/skill *cannot* replicate: subprocess execution, RAM-only env injection, scrub-before-context as an architectural principle, and a *recovery drill as a first-class agent action* — the most original idea in the entry. |
| **Weighted hackathon score (today)** | **5.3** | Pulled down by reliability, not by concept. |
| **Weighted hackathon score (after §8 fixes)** | **8.0–8.5 (projected)** | Reliability → ~7.5 and Polish → ~7 if the binary is rebuilt, discovery is fixed, the scrubber is hardened, and the demo is rehearsed end-to-end. This is a projection, not a measurement. |

### 2.2 The underlying product (CipherVault v1.0.30)

| Dimension | Score /10 | Basis (auditor) |
|---|---:|---|
| Cryptography & primitives | 7 | Standard XChaCha20-Poly1305 / Ed25519 / X25519, contributory-DH checks, Argon2id 64MiB/3/4. Docked for a custom unkeyed Blake2b legacy KDF and deterministic v2 chunk encryption (§5, A1-F2/F3). |
| Chunk protocol v2 | 7 | HKDF-SHA256 domain separation, thorough decrypt-time validation; equality leakage is a documented dedup trade-off. |
| Key derivation / recovery | 6 | Sound Argon2id + HKDF v2; legacy hierarchy, path-derived portable salt, unauthenticated `combine_shares` below the kit layer. |
| Architecture & modularity | 8 | Clean 14-member workspace; account plane is the strongest subsystem (8/10). |
| Services & operator network | 6 | Real BFT quorum, signed gossipsub, P2P↔HTTP auth parity. Docked for a broken multi-validator anchor path and an on-chain privacy leak (§5, A2-F1/F2). |
| Account / MFA / scoped secrets | 8 | TOTP + WebAuthn, step-up MFA binding, DPoP, denylist, quotas, audit chain. Best-engineered plane in the repo. |
| User surfaces (CLI/TUI/web) | 6 | 43 CLI commands, real TUI help modal, careful recovery-kit ritual. Docked for contradictory quickstarts and a first `push` that dead-ends on fleet enrollment. |
| Testing & verification | 7 | 897 annotated tests is real breadth (independently counted). No coverage/fuzz gate; the plugin itself has 0 tests. |
| CI / supply chain / release | 6 | Signed releases, cargo-deny/audit, Cosign+SBOM — but `main` currently **fails its own `-D warnings` gate** (verified). |
| Secret hygiene (git) | 8 | Tracked tree and full history verified clean of credential files. Local plaintext fixtures on disk are the residual risk. |
| **Overall product score** | **6.8 / 10** | A serious, working system with known, fixable defects — not a prototype. |

### 2.3 Trajectory — the progress you have actually made

| When | Score | What changed |
|---|---:|---|
| 30 Sep 2026 (prior audit baseline) | 6.3 | Critical authorization bypasses, race conditions, unpaged recovery histories. |
| 1 Oct 2026 (post-remediation) | 7.6 | 19 of 21 findings closed, atomic restore journal, signed releases. |
| Nov 2026 (prior audit, v1.0.28) | 8.19 (that audit's scale) | MFA negative check, CVKB1 envelopes, TUI hardening. *Note: that audit scored chunk-protocol/documentation claims that this audit found contradicted in two docs — treat 8.19 as generous.* |
| **8 Nov 2026 (this audit, v1.0.30)** | **6.8 (stricter scale)** | Sovereign chain shipped (EVM anchoring removed), operator hardening R1–R13, onboarding flow, Hermes plugin created and validator-green. Score dips on paper because this audit weighted *shipped-artifact fidelity* (stale binary, broken anchor flow, failing CI gate) more heavily — the codebase grew; the release discipline did not keep pace for three weeks. |

The trajectory is genuinely upward in capability. The gap this audit exposes is not "the system got worse" — it is "the system outgrew its release checklist."

---

## 3. Independently Verified Facts

These were re-run by the synthesizing auditor, not taken from subagent reports:

| Claim | Command | Result |
|---|---|---|
| Plugin validation passes | `hermes plugins validate plugins/ciphervault` | ✅ **Validation passed** (manifest, declared tools/hooks match `register()`, security scan safe, desktop surface in-SDK) |
| Shipped binary is stale | `./dist/bin/ciphervault.exe --version` vs `Cargo.toml:21` | ⚠️ Binary reports **`ciphervault 1.0.0`** (Sep 16); workspace is **1.0.30** |
| `scan` is broken on shipped binary | `./dist/bin/ciphervault.exe hook check --deep` | ❌ `error: unexpected argument '--deep' found` |
| Python scrubber leaks secret shapes | Direct `scrub()` calls in `plugins/ciphervault/__init__.py` | ❌ `Bearer abcdefghijklmnop` → **unredacted**; `BEGIN OPENSSH PRIVATE KEY` → **unredacted**; `aws_secret_access_key = wJalr…` → **unredacted**. (`API_KEY=…` and `password: …` do redact.) |
| `main` fails its own CI gate | `RUSTFLAGS="-D warnings" cargo check -p ciphervault-cli --locked` | ❌ 4 errors: unused imports `apps/cli/src/commands/recovery_kit.rs:3,6,8`, dead field `apps/cli/src/commands/recover.rs:1150` |
| No catalog entry exists yet | `ls plugin-catalog/` | ❌ Directory absent — no catalog YAML, no SHA pin, no video, no Typeform (DEMO.md:34-37 checklist fully unchecked) |
| Git tree is clean of secrets | `git ls-files \| grep -E '^secrets(/|\.env)'`, `git rev-list --all -- secrets.env` | ✅ No credential files tracked; 0 commits touch `secrets.env`; `secrets/` and `*.env` correctly gitignored (`.gitignore:23-26`) |
| Test count | `grep -rn '#[test]' / '#[tokio::test]'` over crates/apps/services | **670 + ~214–227 ≈ 897 annotated tests** (the old "826+" claim is stale, not inflated — the tree outgrew it) |
| Repo scale | `git ls-files` | 669 tracked files; 249 `.rs` (~122,750 LOC Rust), 165 `.md`, ~5,034 LOC Python |
| Subagent-executed suites | Various `cargo test -p …` | crypto/format/redact/file-lock ✅, snapshot/recovery ✅, local-store/storage ✅, chain (18) ✅, account (167) ✅, operator lib (81) ✅, agent/maintenance ✅. **Full workspace suite for v1.0.30 was not run to completion by any auditor (compile time) — unproven, not failing.** |

---

## 4. What Is Genuinely Great (with proof)

Credit where verified — these are the assets to lead the demo and the catalog PR with:

1. **The plugin does things a prompt/skill provably cannot.** It executes a real zero-knowledge CLI as a subprocess, injects decrypted env vars into a child process in RAM (`ciphervault run`), scrubs output *before* it enters model context, and restores a recovery kit to a temp dir for a drill. That is exactly the "more than a prompt or a skill could" bar the judges set.
2. **Secret-safety is designed in, not bolted on.** Kit/share *contents* are refused at the schema level (`plugins/ciphervault/__init__.py:202`, "Paths only"); `init` is deliberately never wrapped as an agent action because it prints the recovery secret R (`skills/ciphervault/SKILL.md:10-11`); every tool return passes through `scrub()` (`__init__.py:75,141-142`). The architecture treats the model itself as a potential adversary — a sophisticated, correct instinct.
3. **The recovery drill as an agent action is the most original idea in the entry.** Nobody else will submit "prove you can still recover your secrets" as a tool. It turns backup theatre into a verifiable habit.
4. **Consensus verification is genuinely strict.** Quorum ⌊2N/3⌋+1 with duplicate/unauthorized/proposer checks and domain-separated `verify_strict` (`crates/chain/src/consensus.rs:59-123`), equivocation evidence, fork rejection, validator rotation re-keying (`sync.rs:405-413,558-602`).
5. **The scoped-secrets plane binds token → session → MFA → DPoP in order** (`services/account/src/secret_routes/auth.rs:28-68`) with TOTP step-up and replay tracking (`mfa.rs:188-245`). This is production-grade auth design.
6. **Snapshot decryption validates everything before publication** — nonce, opaque IDs, lengths, ordering, whole-file SHA-256 (`crates/snapshot/src/engine.rs:610-696`) — with a journaled, atomic restore (`restore.rs:1-2`).
7. **The recovery-kit ritual respects humans.** `init` loops until the user types exactly `yes` ("a bare Enter must never count as 'recorded'", `apps/cli/src/commands/init.rs:267-295`) and probes operator reachability without hard-failing.
8. **Honesty in the docs.** The plugin README/code openly admit `fix` is a compat no-op (`README.md:7,35`; `__init__.py:105-106`) instead of faking autofix. Judges notice this.

---

## 5. Findings (deduplicated, re-severed by user harm)

### CRITICAL — hackathon-blocking

**C1. Shipped plugin binary is v1.0.0; source is v1.0.30; `scan` is dead on arrival.**
`plugins/ciphervault/__init__.py:103` calls `hook check --deep`; the shipped `dist/bin/ciphervault.exe` rejects `--deep` (verified live, §3). The v1.0.30 source supports it (`apps/cli/src/commands/hook.rs:171`). DEMO.md shots 1, 3 depend on this. **Fix:** rebuild `dist/bin` from v1.0.30, confirm `--version` prints 1.0.30, re-verify every flag in README/DEMO against the rebuilt `--help`.

**C2. `ciphervault_run` — the demo's money shot — fails against the live vault.**
Live handler test returned `Error: Crypto error: Authentication tag verification failed: ciphertext or AAD tampered`. DEMO shots 2, 4, 5 all depend on this vault. **Fix:** repair or re-init the demo vault; rehearse against a throwaway vault built for the recording; never record against the real one.

**C3. A standalone catalog install can never find the binary.**
`__init__.py:20-37` derives the repo root from the plugin's location (`PLUGIN_DIR.parents[1]`), which only contains `dist/bin` inside a checkout. Installed via the catalog (e.g. `%LOCALAPPDATA%\hermes\plugins\ciphervault`), it falls back to a bare `ciphervault` on PATH that does not exist → every tool returns "binary not found." The validator cannot catch this (registration succeeds without the binary). **Fix:** vendor the binary per-platform, bootstrap-download a pinned release asset on first use, and make `ciphervault_status` fail loudly when no binary is present. Prove it from a clean install with the repo renamed away.

**C4. The secret scrubber leaks common secret shapes into model context.**
Verified live (§3): `Bearer <token>`, `BEGIN OPENSSH PRIVATE KEY`, and `aws_secret_access_key = …` all pass `scrub()` unredacted, and `run` pipes arbitrary child stdout through only this regex — a child that echoes a bare value leaks it verbatim. The MCP path has the same hole, worse: its "scrubbed of secret values" claim is false for bare values (`crates/redact/src/lib.rs:65-95` matchers are shape-based) and its non-JSON fallback forwards raw stdout/stderr (`services/mcp/ciphervault_mcp_server.py:210-215`). **Fix:** port the Rust `ciphervault-redact` matchers (Bearer/PEM/AWS/credential-URL) into the Python scrubber as a minimum; ideally have the CLI exact-match scrub against the injected values held in a `Zeroizing` list, and apply the same scrub in the MCP fallback. *One leaked token on camera ends the entry.*

### HIGH

**H1. Multi-validator anchoring cannot work; solo anchoring silently forks.**
The CLI locally commits *before* federating (`apps/cli/src/commands/anchor.rs:129-135`), then publishes the committed block as a proposal (`anchor.rs:187-198`); `commit_block` requires quorum (`crates/chain/src/consensus.rs:80-87`), so multi-validator anchoring always fails with one signature — while solo mode prints "100% Threshold Valid" for that same single signature on a private genesis the fleet will reject. **Fix:** publish proposal → collect votes via `ChainSyncHub` → commit on certificate; label solo mode explicitly.

**H2. The "opaque commitment" chain publishes the salt and head CID in plaintext.**
`CommitmentTx` carries plaintext `salt`, `head_cid`, `vault_id` (`crates/chain/src/types.rs:208-217`), and any unauthenticated peer can fetch full blocks (`services/operator/src/swarm/serve.rs:308-316`). Anyone watching learns exactly which vault snapshotted what, and when — defeating the commitment's purpose. **Fix:** put only the commitment (+ pseudonym, nonce, signature) on-chain; keep salt/head in local checkpoint evidence.

**H3. Legacy v1 chunk IDs permit public candidate-file confirmation.**
`derive_file_version_id` hashes only `vault_id‖epoch‖SHA256(plaintext)` with no secret key (`crates/crypto/src/kdf.rs:97-112`); v1 remains readable/opt-in (`crates/snapshot/src/chunker.rs:35-38`). An operator who guesses a file's contents can confirm it was vaulted. **Fix:** migrate/re-capture v1 to v2, warn on v1 writes, schedule v1 read deprecation.

**H4. First remote `push` dead-ends on an enrollment step no guide teaches.**
Following `docs/SETUP_GUIDE.md:103-112` ends in a remote `push`; reproduced live: `Push … Error: Quorum deficit: required 3 operators, only 0 succeeded` (device not enrolled). Enrollment is one unexplained sentence (`SETUP_GUIDE.md:116`); the code's own hint (`apps/cli/src/commands/push.rs:303-308`) never mentions `doctor` or `--local`. **Fix:** auto-enroll on `init`, or teach `push --local` as the first push with an explicit enroll command before any remote push.

**H5. Three contradictory quickstarts + a `ui` command that does the opposite of the docs.**
README requires Docker + explicit operator URLs (`README.md:338-360`); SETUP_GUIDE is bare `init/track/push` against the public fleet; WHAT_IS_CIPHERVAULT shows neither. And `README.md:450-453` documents `ciphervault ui --port 8080` → `127.0.0.1:8080`, but the default prints the **cloud** URL and exits, ignoring `--port` (`apps/cli/src/dashboard/server.rs:18-44`; default at `main.rs:781`). **Fix:** one canonical 5-minute path in all three docs; make bare `ui` serve local or document `ui --local`.

**H6. `main` fails its own CI gate right now.**
Verified (§3): `RUSTFLAGS="-D warnings" cargo check -p ciphervault-cli --locked` fails with 4 errors (`.github/workflows/ci.yml:19,64` enforces this). The next push/PR goes red. **Fix:** delete the three unused imports, use or `#[allow]` the dead field, re-run the exact CI command. Fifteen minutes.

**H7. Version skew ships in the web UI and its regression gate is red.**
Dashboard claims v1.0.30 (`apps/ui/index.html:1179-1181`) while Linux/macOS downloads point at v1.0.28 (`:1973-1986`); `node apps/ui/audit.test.cjs` **fails** (asserts v1.0.29). Landing mixes v1.0.29 claims (`apps/landing/index.html:1321`). **Fix:** single version source injected everywhere; update the test *with* the version.

### MEDIUM (condensed — full evidence in the area transcripts)

| # | Finding | Evidence |
|---|---|---|
| M1 | Legacy KDF is a custom unkeyed Blake2b construction (non-standard PRF under recovery/manifest/file keys) | `crates/crypto/src/kdf.rs:17-35` vs HKDF v2 at `chunk_v2.rs:7-27` |
| M2 | V2 deterministic key+nonce from chunk ID leaks intra-epoch chunk equality (documented dedup trade-off — never claim equality-hiding) | `crypto/src/chunk_v2.rs:52-68`; `snapshot/CHUNK_PROTOCOL_V2.md:21` |
| M3 | Stale docs claim "default captures remain v1" while code defaults to V2 — operators misjudge their privacy properties | `snapshot/src/chunker.rs:35-37`; `CHUNK_PROTOCOL_V2.md:23` vs `engine.rs:33-41` |
| M4 | `combine_shares` silently returns a *wrong* secret below threshold (kit layer mitigates; raw API does not) | `crypto/src/shamir.rs:181-209,305-307` |
| M5 | Recovery kits serialize the master secret as plaintext hex guarded only by CRC32 (any struct copy = full compromise) | `crates/recovery/src/kit.rs:12-17,60-95` |
| M6 | PIN cache is process-global clonable plaintext with env fallback and no expiry; local KEK not zeroized; key types `Clone` | `crypto/src/piv.rs:14,26-46`; `crypto/src/envelope.rs:118-121`; `keys.rs:14,61,102` |
| M7 | `LocalVaultStore::open` enforces no file permissions on DB/WAL — lockdown is caller best-effort | `crates/local-store/src/db.rs:116-129` |
| M8 | Portable-keystore password salt is deterministic from the key-file path → precomputed dictionary attacks | `crates/local-store/src/keyring.rs:260-281` |
| M9 | Operator HTTP API binds `0.0.0.0` by default; <32-char tokens only warn; legacy non-strict bypass branches remain | `services/operator/src/main.rs:39-41,252-268`; `handlers.rs:88-99,130-140` |
| M10 | "Proof-of-Storage" is a full-object hash (proves momentary possession to someone who has the data, not storage over time); dedup path skips receipt signature verification | `crates/storage/src/lib.rs:30-40`; `pool.rs:234-241` |
| M11 | Chain gossip state unbounded; block validation is O(history) per proposal; no liveness (split votes stall a height forever) | `crates/chain/src/sync.rs:171-176,247-251`; `ledger.rs:433-447,571-579` |
| M12 | Bare `ciphervault` opens a TUI that cannot initialize a vault — the "guided start" loops back to the CLI | `apps/cli/src/main.rs:2053-2055`; `tui/app.rs:832-833` |
| M13 | Desktop pane is static theatre: hard-coded status dots, buttons copy *prompts*, palette entry renders `null` and does nothing | `plugins/ciphervault/desktop/plugin.js:62-72,142-150` |
| M14 | `post_tool_call` hook only `print()`s — declares a hook, earns nothing | `plugins/ciphervault/__init__.py:192-195,234` |
| M15 | Recovery drill returns a readable plaintext directory and instructs the agent to `diff -r` it — contradicts the plugin's own "plaintext must NEVER enter context" rule and leaves a standing plaintext copy | `__init__.py:196-213` vs `skills/ciphervault/SKILL.md:7` |
| M16 | Account service serializes everything through one `Mutex<Connection>`; documented Postgres HA hard-errors as unimplemented; VCS reconcile is unwired placeholder | `services/account/src/state.rs:30-32`; `ha_store.rs:164`; `reconcile.rs:111-135` |
| M17 | Plugin has **zero tests** — including for the scrub regexes whose failure = secret leakage | `plugins/` (no `test_*`); `plugin.yaml:3-9` |
| M18 | cargo-deny warns instead of blocking (`multiple-versions="warn"`, `wildcards="allow"`); RUSTSEC exception hard-fails CI after 2026-12-31 (~7 weeks post-deadline); no Dependabot/CodeQL | `deny.toml:161,163,239,242`; `.github/workflows/security.yml:26,33-37` |
| M19 | Plaintext secret-shaped files sit in the repo root on disk (`secrets.env`, `secrets/credentials.json` — untracked/gitignored, lengths suggest fixtures, **unverified**); CI only refuses a *tracked* `secrets.env` | `security.yml:67,78-79`; `.gitguardian.yaml` unenforced in CI |
| M20 | `dist/` in git is stale (79 tracked files, zips from Sep, `SHA256SUMS.txt` lists a binary not on disk); no reproducible-build check | `dist/SHA256SUMS.txt`; `.github/workflows/release.yml` |

### LOW (selected)

- Chunk AAD concatenates variable-length fields without length prefixes (`crates/format/src/schema.rs:183-193`) — currently mitigated by decrypt-side length checks.
- Production-path `expect`s (HKDF expand, poisoned PIV mutexes) and unchecked Windows FFI lengths (`crypto/src/chunk_v2.rs:24-26`; `piv.rs:669,710,484-516`; `crates/file-lock/src/lib.rs:311-315`).
- Watcher dry-run mutates the in-memory baseline despite a "persists nothing" contract (`apps/agent/src/watcher.rs:200-201,239-241`).
- `LocalGuardian` and `PredictiveSwarmHealer` are exported, tested, and **never wired into their daemons** (`apps/agent/src/main.rs`; maintenance scheduler) — advertised subsystems that do not run.
- MCP server: no subprocess timeouts (a hung CLI hangs the host), forced `cwd`, stale version string `1.0.28` (`services/mcp/ciphervault_mcp_server.py:46,65,199`).
- TUI help still teaches removed Arbitrum anchoring ("on-chain cost…", `tui/ui.rs:1926`) though EVM anchoring was deleted.
- Landing hero's primary install pill is a multi-minute `cargo install` from source; `brew`/`winget` pills are unverified (manifests unpublished, still v1.0.28) (`apps/landing/script.js:2305-2312`; `dist/package-managers/homebrew/Formula/ciphervault.rb:4`).
- `status` tool returns full Vault/Device/Head IDs (stable identifiers; truncate) (`__init__.py` live output).
- `SECURITY.md:16` still says latest supported is v1.0.29; guarantees doc predates 1.0.30.
- `docker-compose.yml:12-13,36-37,60-61` publishes operators on all interfaces (account/dashboard are loopback-only — inconsistent).

---

## 6. Area Deep-Dives (summaries)

### 6.1 Core vault engine (crates/) — 6–8/10 across sub-dimensions, strongest on error handling
Fail-closed, oracle-free AEAD errors; sealed box rejects non-contributory X25519 on both seal and open with forgery tests (`sealed_box.rs:43-46,92-95,154-196`); redacted-by-default secret types with no `Display`/`Serialize` (`format/src/secret_value.rs:97-103`). The weaknesses are legacy-surface issues (v1 confirmation oracle, custom Blake2b KDF, plaintext-hex kit serialization) — all with clear migration fixes, none requiring redesign. 194 tests in this area alone, all executed green by the auditor.

### 6.2 Services & operator network — 6/10 overall (account plane 8, MCP 4)
The account/MFA plane is production-grade. The chain is real BFT with strict verification, but its headline flow (multi-validator anchoring) is broken by a commit-before-federate ordering bug (H1), and its privacy story is contradicted by plaintext on-chain fields (H2). `!Sync` store handling is correct-but-fragile: the watcher compensates with a dedicated thread + current-thread runtime (`watcher.rs:489-506`) rather than `tokio::spawn` — fails safe at compile time; leave a regression comment. Two advertised subsystems (Guardian, PredictiveSwarmHealer) never execute (M-area). Suite evidence: chain 18 ✅, account 167 ✅, operator lib 81 ✅.

### 6.3 User surfaces — onboarding 4/10, CLI breadth 8/10, TUI 7/10
43 top-level commands with an anti-drift help test (`main.rs:25-29`) is real breadth. The failure is sequencing: a first-time user following the docs hits Docker, a kit ritual, then an enrollment dead-end (H4/H5), and the documented `ui` command opens the cloud explorer instead of their vault. A prepared demo (prebuilt binary, pre-running operators, `push --local`) would demo very well; the as-documented cold path will not complete a first push in 5 minutes. Accessibility is above average for a TUI/CLI project (`focus-visible`, `prefers-reduced-motion`, `NO_COLOR`).

### 6.4 The hackathon entry (plugins/ciphervault) — see §2.1, §5 C1–C4
Validator-green, architecturally creative, secret-safety-conscious — and currently shipping a binary two months older than its own docs. Full verdict and fix list in §8.

### 6.5 Testing, ops & release — testing 7/10, CI 5/10, supply chain 7/10
897 tests, 3-OS matrix + MSRV + Chromium CSP job, Ed25519-signed checksums (fail-if-unsigned), Cosign+SBOM. Undermined by a red `-D warnings` gate on `main` *today* (H6), stale committed binaries (M20), warn-only cargo-deny (M18), and an untested plugin (M17).

---

## 7. Impact — the strongest honest case

**The problem is real, current, and growing.** Every AI coding agent session runs in a directory full of `.env` files, API keys, and certificates that Git is explicitly forbidden from protecting. Agents read them, echo them, log them, and — as this audit itself demonstrated with the scrub tests — leak them into model context through exactly the shapes nobody redacts. There is currently no standard answer to "how does an agent *use* secrets without *seeing* them, and how do I get them back after my laptop dies?"

CipherVault's answer is the most complete one in this hackathon field, because it is not a hackathon-week invention:

- **For agent users:** masked scan (find the sprawl), RAM-only `run` (use secrets without writing them to disk or, by design, into context), and a recovery drill (prove the backup works *before* the disaster). Each maps to a failure developers have actually had.
- **For the Hermes ecosystem:** it is a reference example of the plugin thesis — a plugin that changes what the agent can *safely do*, not what it says. It exercises tools, hooks, a desktop surface, and a bundled skill together, and its "treat the model as a potential adversary" discipline is a pattern other plugin authors should copy.
- **Beyond the hackathon:** the same engine serves non-agent users (sovereign backup, threshold recovery, operator federation), so the prize, if won, funds a product with a life after Nov 11 — not a demo that dies with the judging thread.

That is a 1st–5th-place *concept*. The gap to a 1st–5th-place *entry* is the reliability column in §2.1, and it is closable before the deadline.

---

## 8. Hackathon Readiness — Checklist & Minimum Fix List

### Submission checklist (per the Nous Research announcement + catalog rules in your screenshots)

| Requirement | Status |
|---|---|
| Public repository | ✅ `github.com/samuel-1-avson/CipherVault` (plugin files tracked) |
| `plugin.yaml` + loadable entrypoint at pinned commit | ✅ `__init__.py` + `desktop/plugin.js`; `provides_tools`/`provides_hooks` are top-level and match `register()` exactly |
| Public surfaces only (no core patching) | ✅ Validator: "no core override", "stays inside the plugin SDK surface" |
| Validation passes locally (`hermes plugins validate … --install-deps`) | ✅ Verified, full output in audit transcript |
| Catalog PR (`plugin-catalog/ciphervault.yaml`, full 40-char SHA) | ❌ Does not exist yet |
| Demo video <90s on X, tagging @NousResearch | ❌ Not recorded; DEMO.md shots 2/4/5 currently fail (C2) |
| Typeform submission linking PR + video | ❌ Blocked on the two above |
| Tools work from a clean catalog install | ❌ C1, C3, C4 |

### Minimum fix list to convert NO-GO → GO (≈1 day, in order)

1. **Rebuild `dist/bin/ciphervault.exe` from v1.0.30 source.** Confirm `--version` → 1.0.30 and `hook check --help` shows `--deep`. *(Fixes C1, most of the doc skew.)* Remember to stop any running fleet processes first — the Windows linker cannot replace a live `.exe`.
2. **Fix binary discovery for standalone installs** (bundle per-platform binary or bootstrap a pinned release asset) and prove it from a clean `hermes plugins install` with the repo directory renamed away. *(Fixes C3.)*
3. **Repair the demo vault** (or script an off-camera throwaway vault) and rehearse all five DEMO shots in one take, including a staged `.env` scan hit. *(Fixes C2.)*
4. **Harden `scrub()`**: port Bearer / PEM / OpenSSH / AWS-secret / credential-URL patterns (30–60 min). *(Fixes C4 for the plugin; note the same gap in the MCP/Rust run path for the post-hackathon list.)*
5. **Regenerate README/DEMO/SKILL flag claims from the new binary's real `--help`**; delete the false "`cv` and `ciphervault` are the same binary (stated in top-level `--help`)" claim or ship the alias. *(Fixes doc skew.)*
6. **Create `plugin-catalog/ciphervault.yaml` pinned to the full 40-char SHA** of the fixed commit, record the <90s video, open the PR, submit the Typeform.

**Also do (15 min, protects everything else):** fix the 4 `-D warnings` errors (H6) *before* cutting the pinned commit, so the catalog commit is CI-green.

**Post-submission (not blockers):** make the `post_tool_call` hook a real guard or drop it (M14); wire or cut the desktop pane's dead palette command (M13); hash-manifest drill instead of a plaintext tree (M15); plugin pytest suite (M17); operator/chain fixes H1/H2/M9–M11.

### Suggested 90-second demo arc (once fixed)

`0:00` staged project with a planted `.env` → `0:10` ask Hermes "is this project safe to share?" → `scan` flags paths (masked) → `0:30` "run the app" → `ciphervault_run` injects in RAM, app boots, no plaintext file, no value in chat → `0:55` "my laptop died yesterday — prove I can recover" → recovery drill passes → `1:20` close on the drill: *"backups you haven't rehearsed aren't backups."*

---

## 9. Final Honest Take

You have built the hard part. A zero-knowledge backup engine, a sovereign chain, threshold recovery, hardware-token support, and an agent plugin with a genuinely original safety model do not come from a weekend — the commit history (sovereign-chain phases, operator hardening R1–R13, audit-remediation cycles) shows months of disciplined, audit-driven work, and this audit's own test executions confirm the suites are real.

What you have not yet built is the *last mile*: the discipline that the artifact a stranger downloads is the artifact your docs describe. Every critical finding in this report is a last-mile failure — a stale binary, a doc written against a different version, a gate that went red unnoticed, a demo never rehearsed end-to-end. That is fixable in a day, and it is the difference between judges seeing a 5.3 and judges seeing an 8.5.

Fix the six items, rehearse the demo until it is boring, and submit. The concept deserves to be in the room.

---

## Appendix — Audit Trail

- **Subagent transcripts (full tool traces):** `C:\Users\samue\AppData\Local\hermes\cache\delegation\live\deleg_b05a8afc\task-0.log` … `task-4.log`
- **Prior audits referenced:** `PROJECT_AUDIT_AND_ANALYSIS_REPORT.md` (v1.0.28), `report/OPERATOR_AUDIT_2026-11-08.md`, `report/VAULT_USER_AUDIT_2026-11-08.md`, `report/TUI_AUDIT_2026-11-06.md`
- **Known unproven areas:** full `cargo test --workspace` for v1.0.30 (compile time exceeded audit windows — run this on the pinned submission commit and keep the log); operator integration suites under `services/operator/tests/` (swarm/chaos) rested on code inspection + passing lib suites; whether `secrets/` fixtures are real credentials (check and rotate if real — M19).
- **Working tree note:** audit read the on-disk state; `deploy/gcp/*` modifications and untracked `operator-architecture.html`, `scripts/deploy-web.sh` were present and untouched.
