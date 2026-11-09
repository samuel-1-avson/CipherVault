# CipherVault Hermes plugin

Zero-knowledge secret backup, native inside Hermes. The plugin wraps
the CipherVault CLI (a 14-crate Rust workspace: XChaCha20-Poly1305,
content-defined chunking, threshold recovery, YubiKey PIV, sovereign
operator chain) with agent-safe surfaces — values are encrypted on your
machine and never enter the model context.

## What registers

| Surface | What it does |
|---|---|
| `ciphervault_status` | Vault status as JSON: tracked file **paths**, head, operator count, CLI version (from `status --json`) |
| `ciphervault_scan` | Secret-sprawl scan of workspace + staged diffs, masked (`hook check --deep --json`; `fix` appends to `.gitignore`) |
| `ciphervault_run` | Run any command with secrets injected in RAM only; output exact-value + shape scrubbed (`run --json`). **Every call passes Hermes's human-approval gate** (see Disclosure) |
| `ciphervault_push` | Encrypted snapshot of tracked secrets (local default; replicates when `local_only=false`) |
| `ciphervault_recovery_drill` | Restore kit/shares into a fresh temp dir the tool itself creates, return a **SHA-256 manifest**, then delete that temp dir |
| `ciphervault_redact` | Mask text with vault-exact + shape redaction before quoting it |
| `ciphervault_audit` | Tamper-evident agent audit log (hash-chained, device-signed): blocked reads, approval requests, scrubbed results (with the scrubbed output's SHA-256), writes — plus chain verification and output-hash lookup |
| `pre_tool_call` hook | **Leak guard:** blocks secret-file reads, secret-shaped payloads to other tools, and git add/commit/push while sprawl violations exist |
| `transform_tool_result` hook | Scrubs every other tool's result before it enters context |
| `tool_request` middleware | Defaults the session cwd into `ciphervault_*` calls |
| Secret source `ciphervault` | Hermes' own env vars sourced from a vault at startup (`secrets.ciphervault.*`) |
| `/ciphervault`, `hermes ciphervault` | Chat slash command; terminal bootstrap/status/doctor |
| Desktop pane + page + chip | Live vault status from the plugin backend (`dashboard/plugin_api.py`) |
| Redaction patterns | `cvst1.*`, Stripe/GitHub/AWS key shapes added to Hermes' redactor |

## Disclosure (catalog rule 13)

- **Shell commands:** the only process the plugin spawns is the
  `ciphervault` CLI (status/scan/run/push/recover/redact/export-env).
  `ciphervault_run` asks that CLI to execute the command you approve,
  with vault secrets injected into its environment. **Approval:**
  every `ciphervault_run` call returns Hermes's `approve` directive
  from `pre_tool_call`, so it passes the same human-approval gate as
  dangerous shell commands — the plugin never routes around it.
  CLI subprocesses get a minimal allow-listed environment (Hermes
  provider keys are not passed down). Tool results scrubbed by the
  `transform_tool_result` hook are capped at 256 KB; anything beyond
  that is truncated, not scanned. The recovery drill restores only
  into a fresh temp dir it creates itself and deletes only that dir.
  The plugin never spawns Hermes itself.
- **Network:** none, except `bootstrap`, which — only when *you* run
  `hermes ciphervault bootstrap` or `/ciphervault setup` — downloads
  `ciphervault.exe` and `SHA256SUMS.txt` from the pinned GitHub release
  (`v1.0.31`) of `samuel-1-avson/CipherVault`, verifies the SHA-256,
  and installs into `$HERMES_HOME/plugins/ciphervault/bin/`. No binary
  is bundled in this repo (rule 17); no telemetry anywhere.
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
  never saw. Approval grants are per-program: the approval rule key
  names the program (`ciphervault_run:<program>`), so a
  session/always grant never covers other commands.
- **Credentials:** the plugin holds none. The secret source passes the
  CLI's `export-env` JSON output straight to Hermes' orchestrator.
- **Approvals/unattended:** tools fail with structured JSON errors when
  the binary or vault is missing; nothing prompts or hangs.

## Install

```bash
hermes plugins install ciphervault   # from the catalog
hermes plugins enable ciphervault
hermes ciphervault bootstrap         # Windows: pinned, checksum-verified CLI
# restart Hermes — ciphervault_* tools appear
```

Binary resolution: plugin setting `binary_path` → `$CIPHERVAULT_BIN` →
bootstrapped copy → repo checkout (dev) → `PATH` (`ciphervault` only;
an unrelated `cv` binary is never used).

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
