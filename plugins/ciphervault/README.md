# CipherVault Hermes plugin

**Prove the model never saw it.** CipherVault is zero-knowledge secret
backup, native inside Hermes — and every guarded action lands in a
hash-chained, device-signed audit log (with the SHA-256 of each
scrubbed output, anchored to the operator fleet), so after a run you
don't have to trust that secrets stayed out of the model: you can
check. The plugin wraps the CipherVault CLI (a 14-crate Rust
workspace: XChaCha20-Poly1305, content-defined chunking, threshold
recovery, YubiKey PIV, sovereign operator chain) with agent-safe
surfaces — values are encrypted on your machine and never enter the
model context.

New here? `hermes ciphervault quickstart` runs the whole loop in a
throwaway vault in about two minutes.

## What registers

| Surface | What it does |
|---|---|
| `ciphervault_status` | Vault status as JSON: tracked file **paths**, sealed state (`working_tree_sealed`), head, operator count, CLI version, plus `workspace_posture`. Optional `history_limit` (1–50) adds recent snapshots, newest first: `snapshot_id`, `logical_id`, recorded time, epoch, head flag (`history --json`). Optional `watcher_health` adds watcher liveness, last detected change, last capture, upload queue, and the newest snapshot with a recorded remote verification, plus plain-language `summary` lines (`status --json --watcher`) |
| `ciphervault_scan` | Secret-sprawl scan of workspace + staged diffs, masked (`hook check --deep --json`; `fix` appends to `.gitignore`) |
| `ciphervault_run` | Run any command with secrets injected in RAM only (`--no-net` default on Linux, macOS, and Windows AppContainer; `--proxy` loopback credential proxy; `.ciphervault/policy.toml` `profile` support); output exact-value + shape scrubbed (`run --json`). **Every call passes Hermes's human-approval gate** (see Disclosure) |
| `ciphervault_push` | Encrypted snapshot of tracked secrets (local default; `shred_working_copy=true` or `[vault].sealed_mode=true` zero-fills and removes plaintext from disk after sealing; replicates when `local_only=false`) |
| `ciphervault_recovery_drill` | Restore kit/shares into a fresh temp dir the tool itself creates, return a **SHA-256 manifest**, then delete that temp dir. Pass `via` (must match the vault's configured operators and pass `tools.url_safety.is_safe_url`; private, loopback, link-local, and metadata hosts are refused) when the vault moved fleets after the kit was printed |
| `ciphervault_redact` | Mask text with vault-exact + shape redaction before quoting it |
| `ciphervault_audit` | Tamper-evident agent audit log (hash-chained, domain-separated device-signed, per-vault `audit_hmac.key` caller-authenticated): blocked reads, approval requests, scrubbed results, writes — plus chain verification and output-hash lookup (`check_text`) |
| `ciphervault_env_doctor` | Zero-knowledge environment & schema diagnostics (`ciphervault env-doctor --json`): compares code env references and `.env.example` against vault keys and detects structural value anomalies (`EMPTY_VALUE`, `WHITESPACE_WRAPPED`, `UNSTRIPPED_QUOTES`, `PLACEHOLDER_VALUE`, `INVALID_URL`, `INVALID_JSON`, `PREFIX_MISMATCH`) even on sealed/shredded vaults without exposing values; `sync_env_example` safely updates `.env.example` |
| `ciphervault_secret_generate` | In-vault CSPRNG secret provisioning (`base64url`, `hex`, `uuid`, `alphanumeric`): generates entropy in RAM, tracks and seals into the vault, and returns only `{name, format, length_chars, sha256_prefix, sealed}`. Only inside an existing vault, after Hermes approval; never replaces an existing key unless `overwrite=true` gets its own one-time approval |
| `ciphervault_diff` | Masked key-level diff between snapshots or against the working tree (`ciphervault diff --json`, never `--reveal`) |
| `ciphervault_restore_preview` | Read-only preview of restoring one snapshot (`snapshot_id` or `head`) into the active vault workspace (`restore --dry-run --json`): the CLI checks the record signature, epoch key, manifest, chunks, file integrity and destination paths, then lists each file as `create`, `replace` or `unchanged` with its size, plus counts and any uncommitted changes a real restore would need `--force` for. Writes nothing; the user runs the restore |
| `ciphervault_proxy_doctor` | Dry-run proxy route diagnostic: reports which vault keys map to built-in provider routes vs `.ciphervault/policy.toml` upstreams vs unmapped keys |
| `ciphervault_secret_prompt` | Out-of-band human secret request: queues requested key metadata in `.ciphervault/pending_secret_prompts.json` for the Hermes desktop Secret Entry Drawer (or reads via hidden TTY `getpass`) so users never paste secrets into chat. Only inside an existing vault, after Hermes approval; the TTY prompt asks again before replacing a key that already exists |
| `pre_tool_call` hook | **Leak guard:** blocks secret-file/policy reads & writes, secret-dumping CLI commands, secret-shaped payloads to other tools, and git add/commit/push while sprawl violations exist |
| `transform_tool_result` hook | Scrubs every other tool's result before it enters context across 256 KB chunks with 4 KB seam overlaps (up to 4 MB default via `CIPHERVAULT_MAX_RESULT_CHARS`), against every vault the call touches |
| `tool_request` middleware | Defaults the session cwd into `ciphervault_*` calls and attaches one-time ambient workspace posture |
| Secret source `ciphervault` | Hermes' own env vars sourced from a vault at startup (`secrets.ciphervault.*`) |
| `/ciphervault`, `hermes ciphervault` | Chat slash command; terminal `bootstrap`, `setup` (wizard for binary + `.ciphervault/policy.toml`; `--wire-hermes` prints the `hermes config set` commands for the secret source), `status`, `doctor`, `quickstart` |
| Desktop pane + page + chip | Live vault status, one-click **Seal & shred `.env`**, masked **Secret Entry Drawer** with pending prompt chips, **Env Health** card, and verified **Agent Audit** feed (`dashboard/plugin_api.py` + `desktop/plugin.js`) |
| Desktop Network Explorer | Open from the CipherVault pane or the command palette. Inspect public operator reports and anchor receipts, look up object replicas by CID, and switch to **Local CipherChain** for signed blocks in the active workspace. |
| Redaction patterns | `cvst1.*`, Stripe/GitHub/AWS key shapes added to Hermes' redactor |

Public network data works with the bundled CLI. An explicit object lookup sends
the entered CID to the public explorer at `vault.cipherv.online`. Local blocks
use a compatible CLI with the `chain-explorer` command. To preview the local
chain view with the source plugin, build the CLI and set its path with
`CIPHERVAULT_BIN` or the plugin's `binary_path`.

## Disclosure (catalog rule 13)

- **Shell commands:** the only process the plugin spawns is the
  `ciphervault` CLI (status/history/scan/run/push/recover/redact/export-env,
  and `restore --dry-run --json` for previews, which never writes).
  `ciphervault_run` asks that CLI to execute the command you approve,
  with vault secrets injected into its environment. **Approval:**
  every `ciphervault_run` call returns Hermes's `approve` directive
  from `pre_tool_call`, so it passes the same human-approval gate as
  dangerous shell commands — the plugin never routes around it.
  `ciphervault_secret_generate` and `ciphervault_secret_prompt` go
  through the same gate on every call; an approval to overwrite an
  existing key is one-time and never covered by an "always" grant.
  CLI subprocesses get a minimal allow-listed environment (Hermes
  provider keys are not passed down). Tool results scrubbed by the
  `transform_tool_result` hook are scanned in 256 KB chunks with 4 KB
  seam overlaps up to 4 MB (`CIPHERVAULT_MAX_RESULT_CHARS`); anything
  beyond that ceiling is truncated, not passed unscanned. Fail-closed
  withholding applies only where a vault is present in the workspace: with no vault,
  results pass through with the local shape scrub so the plugin
  never eats unrelated output Hermes-wide. A vault with a missing,
  incompatible, or timed-out CLI still fails closed. The
  recovery drill restores only
  into a fresh temp dir it creates itself and deletes only that dir.
  The plugin never spawns Hermes itself.
- **Network.** (1)
  `bootstrap` — only when *you* run `hermes ciphervault bootstrap`
  or `/ciphervault setup` — downloads the platform asset
  (`ciphervault.exe` on Windows x64, `ciphervault-linux-amd64` on
  Linux x64, `ciphervault-macos-arm64`/`-amd64` on macOS 13+) and
  `SHA256SUMS.txt` from the GitHub release pinned as `RELEASE_VERSION`
  in `binary.py` (the macOS binaries are ad-hoc signed on Apple
  Silicon but not notarized, which is fine for this download because
  it is not quarantined) of
  `samuel-1-avson/CipherVault`, verifies the SHA-256 against the
  per-platform pin in this source (an interrupted download is retried and
  resumed; nothing is installed unless the assembled file matches the
  pin), and installs into
  `$HERMES_HOME/plugins/ciphervault/bin/`. No binary is bundled in
  this repo (rule 17); no telemetry anywhere. (2) The audit anchor:
  on `ciphervault_run` approval requests and replicated pushes, the
  CLI sends a signed audit checkpoint (entry count + head hash
  only — no contents) to *your own configured operator fleet*, so
  the log's head exists outside the agent's machine. (3) The Desktop
  **Network Explorer** reads operator and checkpoint data from
  `vault.cipherv.online` when you open its public view. Object lookups send
  the CID you enter. Local CipherChain reads run entirely in the local CLI.
- **Reads outside its data:** vault metadata via the CLI in the
  workspace you point it at (paths/counts only, via `status --json`),
  tracked secret files *inside the CLI process* for exact-value
  redaction (values never enter the plugin process or the model).
- **Audit log:** guard decisions (blocked reads/payloads/git ops),
  `ciphervault_run` approval requests, scrubbed results, and
  write/exec tool completions are appended to a hash-chained,
  device-signed audit log inside the vault's local store
  (`ciphervault agent-log show|verify|export`). Scrubbed results
  record the SHA-256 of the exact output that reached the model, so
  any output can be checked later (`agent-log check`): a missing
  hash means it never passed the scrub. On every replicated push the
  chain head is anchored to the operator fleet as a signed,
  content-addressed checkpoint (`agent-log verify-remote`), moving
  the receipt outside the agent's control. Anchoring fires on every
  replicated push AND at the moment a `ciphervault_run` approval is
  requested (detached, best-effort), so the grant itself is
  checkpointed before the command runs. Entries contain
  tool/path/decision/counts/hashes only — never contents — so a
  session can later *prove* what the agent touched and what it
  never saw. Approval grants are scoped to the execution envelope:
  the approval rule key binds the program, profile, inline `-c`/`-e`
  code hash, network mode (`no_net`/`proxy`/`open`), and `allow_keys`,
  so approving an offline test run never covers inline code execution
  or wider secret/network access.
- **Writes outside its data:** `ciphervault_secret_generate` and
  `ciphervault_secret_prompt` write one env file, and only when the
  call's `cwd` is inside an existing vault and the file resolves
  (after symlinks) inside that vault, outside `.ciphervault/` and
  outside the Hermes home; anything else is blocked before approval
  is asked. They never replace an existing `NAME=` line without your
  yes. `hermes ciphervault setup` writes `.ciphervault/policy.toml`
  in the vault; it never edits Hermes's `config.yaml` (`--wire-hermes`
  only prints the `hermes config set` commands to run).
- **Credentials:** the plugin holds none. The secret source passes the
  CLI's `export-env` JSON output straight to Hermes' orchestrator.
- **Approvals/unattended:** tools fail with structured JSON errors when
  the binary or vault is missing; nothing prompts or hangs.

## Install

```bash
hermes plugins install ciphervault   # from the catalog
hermes plugins enable ciphervault
# Point the plugin at a compatible CLI (see below), then:
hermes ciphervault doctor
# restart Hermes — ciphervault_* tools appear
```

The catalog installs the version it pins, which can lag this repository (it was
v0.6.5 with 7 tools when last checked, 20 November 2026). For v0.8.0 and all 13
tools, copy `plugins/ciphervault/` into `$HERMES_HOME/plugins/ciphervault/`
(default `~/.hermes`), then run `hermes plugins enable ciphervault`.

### Snapshot history, restore preview, and watcher health (new in v0.8.0)

v0.8.0 adds a 13th tool, `ciphervault_restore_preview`, and the
`history_limit` and `watcher_health` options of `ciphervault_status`. All
three need CLI flags that no published CLI release has yet: `history --json
--limit`, `restore --dry-run --json`, and `status --json --watcher`. The
pinned v1.0.38 lacks them. With it, these options return
`error_code: "cli_unsupported"`, and the plain status and every other tool
work as before. `hermes ciphervault doctor` reports them under
`optional_capabilities` without failing. Until a CLI release ships them,
build the CLI from this source and point `CIPHERVAULT_BIN` at it.

A typical exchange: *"Show me a recent backup and tell me what restoring it
would change."* The agent calls `ciphervault_status` with `history_limit: 5`,
picks a `snapshot_id`, calls `ciphervault_diff` for the masked key changes
and `ciphervault_restore_preview` for the per-file actions. A passed preview
means the snapshot passed its checks against the local store at
`checked_at`. Errors are typed (`invalid_snapshot_reference`,
`snapshot_not_found`, `verification_failed` with `failed_check`,
`unsafe_destination`, `cli_unsupported`, …). The preview never restores,
stages, or writes plaintext; it returns the `ciphervault restore` command for
the user to run.

*"I changed a secret. Did the watcher actually back it up?"* The agent calls
`ciphervault_status` with `watcher_health: true`. The answer keeps three
events apart:

- **Save detected:** `last_change_detected_at`, when the watcher last found
  tracked content that differed from its last capture.
- **Snapshot captured:** `last_capture`, with its `snapshot_id`.
- **Backup verified:** `remote_verification`, the newest snapshot with a
  recorded quorum replication (from `push` or the watcher's sync) and when it
  was recorded. `head_verified: false` plus `newer_unverified_snapshots` says
  a newer local snapshot has none yet.

The watcher counts as `running` only on a heartbeat less than 120 s old from
this vault's own `.ciphervault/watcher-status.json`. A clean stop is
`stopped`. A missing, foreign, unreadable, or stale record is `unknown`, as
are watchers from releases before this record existed. Everything here is
recorded evidence (`live_check_performed: false`); the status call contacts
no operator, and starting or stopping the watcher stays with
`ciphervault watch` and the `ciphervault-agent` service.

This plugin version requires a CLI whose `redact --json` attests
`exact_values_complete` — every tracked working copy was loaded, so a
shape-blind vault value cannot slip through an unreadable file. The
pinned release ships that attestation, so
`hermes ciphervault bootstrap` installs it on Windows x64, Linux x64, and
macOS 13+ (Apple Silicon and Intel). Windows x64 is the verified platform: the
Linux and macOS binaries are cross-built and have not yet been run on real
hosts, so treat those platforms as unverified.
Older CLIs (v1.0.32 and earlier) lack it: the plugin withholds
vault-scoped output with them, so upgrade, or build the CLI from source
(`cargo build --release -p ciphervault-cli`) and set
`$CIPHERVAULT_BIN` or the `binary_path` setting to it. Vault
detection follows the CLI: the nearest `.ciphervault/vault.db` in the
working directory or a parent; a bare `.ciphervault/` (such as the
installer's `~/.ciphervault/bin`) is not a vault. Commands run in a
vault subdirectory are scrubbed and receipted at the vault root.
Since v0.6.3 the hooks also follow path arguments: a call whose working
directory is outside a vault but whose arguments name a path inside one
(`cat demo/settings.txt` from the parent directory, `read_file` on an
absolute path, `cd demo && …`) is exact-scrubbed, guarded, and receipted
against that vault, and fails closed like any vault-scoped call. A call
touching several vaults is checked against each in turn. Argument scans
are bounded (first 16 KB of each string, 256 tokens); URLs and `-flags`
are skipped.

`ciphervault_run` output is receipted as `scrubbed_result` too (since
v0.6.3; it bypasses `transform_tool_result`), and a failing command keeps
its structured `stdout`/`stderr`/`exit_code`. If the receipt cannot be
written, stdout/stderr are withheld; exit code and counts are kept.
Visible-text lookups (`check_text` on a terminal output, not the whole
result envelope) need a CLI whose `agent-log check` matches
`content_sha256`: v1.0.34 (pinned) or later. With v1.0.33, exact
whole-result lookups still work.

Binary resolution: plugin setting `binary_path` → `$CIPHERVAULT_BIN` →
bootstrapped copy → repo checkout (dev) → `PATH` (`ciphervault` only;
an unrelated `cv` binary is never used).

Run `hermes ciphervault doctor` if a tool is withheld or an installed CLI
is older than the plugin. It reports the resolved executable and source,
actual versus pinned version, every wrapped command/flag capability, and
a live redact-completeness probe; an incompatible CLI exits nonzero.
Status alone is not a compatibility check. Since v0.5.5 the plugin preserves
exact LF/CRLF bytes on Windows and
reports failed commands, redaction, and audit verification as failures.

For required-MFA accounts, use a CLI build containing hosted MFA step-up
support: `ciphervault auth connect` authenticates the account first and
asks for a fresh unused authenticator code in your own terminal, with
input hidden. Local `auth login` and browser MFA do not authorize that
CLI session. The pinned v1.0.34 release (and v1.0.33) includes this connection fix;
v1.0.32 and earlier do not. Never send codes
or session credentials through agent tools, chat, arguments, or environment
variables. Keep MFA enabled. Account linking is not proof of fleet backup;
only a verified replicated push and recovery drill prove recoverability.

Hermes secret source (optional):

```yaml
secrets:
  ciphervault:
    enabled: true
    vault_path: C:/path/to/project   # where .ciphervault/ lives
```

## Validate (same check catalog CI runs)

```bash
hermes plugins validate ./plugins/ciphervault --install-deps
hermes plugins doctor ciphervault
python3 -m pytest plugins/ciphervault/tests -q
```

## Demo

See `DEMO.md` for the rehearsed 90-second script.
