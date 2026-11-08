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
| `ciphervault_run` | Run any command with secrets injected in RAM only; output exact-value + shape scrubbed (`run --json`) |
| `ciphervault_push` | Encrypted snapshot of tracked secrets (local default; replicates when `local_only=false`) |
| `ciphervault_recovery_drill` | Restore kit/shares to a temp dir, return a **SHA-256 manifest**, then delete the plaintext |
| `ciphervault_redact` | Mask text with vault-exact + shape redaction before quoting it |
| `pre_tool_call` hook | **Leak guard:** blocks secret-file reads, secret-shaped payloads to other tools, and git add/commit/push while sprawl violations exist |
| `transform_tool_result` hook | Scrubs every other tool's result before it enters context |
| `tool_request` middleware | Defaults the session cwd into `ciphervault_*` calls |
| Secret source `ciphervault` | Hermes' own env vars sourced from a vault at startup (`secrets.ciphervault.*`) |
| `/ciphervault`, `hermes ciphervault` | Chat slash command; terminal bootstrap/status/doctor |
| Desktop pane + page + chip | Live vault status from the plugin backend (`dashboard/plugin_api.py`) |
| Redaction patterns | `cvst1.*`, Stripe/GitHub/AWS key shapes added to Hermes' redactor |

## Disclosure (catalog rule 13)

- **Shell commands:** the plugin runs the `ciphervault` CLI as a local
  subprocess (status/scan/run/push/recover/redact/export-env). No other
  shell-outs. It never spawns Hermes itself and never touches the
  approval system.
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
bootstrapped copy → repo checkout (dev) → `PATH` (`ciphervault`/`cv`,
the same binary).

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
