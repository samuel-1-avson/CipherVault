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
| `ciphervault_status` | Vault status as JSON: tracked file **paths**, head, operator count, CLI version (from `status --json`) |
| `ciphervault_scan` | Secret-sprawl scan of workspace + staged diffs, masked (`hook check --deep --json`; `fix` appends to `.gitignore`) |
| `ciphervault_run` | Run any command with secrets injected in RAM only; output exact-value + shape scrubbed (`run --json`). **Every call passes Hermes's human-approval gate** (see Disclosure) |
| `ciphervault_push` | Encrypted snapshot of tracked secrets (local default; replicates when `local_only=false`) |
| `ciphervault_recovery_drill` | Restore kit/shares into a fresh temp dir the tool itself creates, return a **SHA-256 manifest**, then delete that temp dir. Pass `via` (current operator URLs) when the vault moved fleets after the kit was printed |
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
  that is truncated, not scanned. Fail-closed withholding applies
  only where a vault is present in the workspace: with no vault,
  results pass through with the local shape scrub so the plugin
  never eats unrelated output Hermes-wide. A vault with a missing,
  incompatible, or timed-out CLI still fails closed. The
  recovery drill restores only
  into a fresh temp dir it creates itself and deletes only that dir.
  The plugin never spawns Hermes itself.
- **Network:** none, except two user-initiated flows. (1)
  `bootstrap` — only when *you* run `hermes ciphervault bootstrap`
  or `/ciphervault setup` — downloads the platform asset
  (`ciphervault.exe` on Windows x64, `ciphervault-linux-amd64` on
  Linux x64, `ciphervault-macos-arm64`/`-amd64` on macOS 13+) and
  `SHA256SUMS.txt` from the pinned GitHub release (`v1.0.33`, published
  as a pre-release; the macOS binaries are ad-hoc signed on Apple
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
  the log's head exists outside the agent's machine.
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
# Point the plugin at a compatible CLI (see below), then:
hermes ciphervault doctor
# restart Hermes — ciphervault_* tools appear
```

This plugin version requires a CLI whose `redact --json` attests
`exact_values_complete` — every tracked working copy was loaded, so a
shape-blind vault value cannot slip through an unreadable file. The
pinned v1.0.33 release ships that attestation, so
`hermes ciphervault bootstrap` installs it on Windows x64, Linux x64, and
macOS 13+ (Apple Silicon and Intel).
Older CLIs (v1.0.32 and earlier) lack it: the plugin withholds
vault-scoped output with them, so upgrade, or build the CLI from source
(`cargo build --release -p ciphervault-cli`) and set
`$CIPHERVAULT_BIN` or the `binary_path` setting to it. Vault
detection follows the CLI: the nearest `.ciphervault/vault.db` in the
working directory or a parent; a bare `.ciphervault/` (such as the
installer's `~/.ciphervault/bin`) is not a vault. Commands run in a
vault subdirectory are scrubbed and receipted at the vault root.

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
CLI session. The pinned v1.0.33 release includes this connection fix;
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
