# CipherVault Model Context Protocol (MCP) Server

CipherVault lets AI coding assistants (Claude Code, Codex, Cursor, Antigravity, AutoGen) work in a project that has a vault with **no plaintext credential exposure**: secrets are injected into a child process in RAM (or via the streaming loopback credential proxy), everything that comes back to the model is exact-value + shape scrubbed, and `ciphervault_run` outputs are hash-chained with fail-closed `scrubbed_result` audit receipts.

**Use `ciphervault mcp` directly.** The legacy Python script (`services/mcp/ciphervault_mcp_server.py`) is now only a thin delegating compatibility shim that launches `ciphervault mcp` and translates legacy tool names.

---

## Native server: `ciphervault mcp` (recommended)

Add it to your agent's MCP configuration (for example `claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "ciphervault": {
      "command": "ciphervault",
      "args": ["mcp"]
    }
  }
}
```

It speaks MCP (JSON-RPC 2.0) over stdio. Run it from (or pass `cwd` pointing at) the project containing `.ciphervault/`.

### Security guarantees

- **Allowlisted minimal subprocess environment**: inherited provider credentials (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`, etc.) are stripped before invoking CLI subcommands; only essential OS variables and `CIPHERVAULT_*` configuration pass through.
- **Fail-closed exact-value scrubbing**: `ciphervault_redact` verifies complete loading of every tracked vault file (`exact_values_complete: true`) and refuses to release partial/unverified output.
- **Fail-closed audit receipts**: `ciphervault_run` records a `scrubbed_result` entry (`output_sha256`, `content_sha256`, `redactions`, `program`, `exit_code`) in the vault's hash-chained agent audit log; if the receipt cannot be written, stdout/stderr are withheld.
- **Network isolation by default**: `ciphervault_run` enables `--no-net` by default on Linux, macOS, and Windows (unless `proxy: true` or `no_net: false`). Agent-supplied `proxy_upstream` values are never accepted over MCP — configure custom upstreams in `.ciphervault/policy.toml`.
- **SSRF-protected recovery drills**: `ciphervault_recovery_drill` accepts file paths only, restores into an isolated temp directory created and deleted by the tool, returns only a SHA-256 manifest, and blocks private, loopback, link-local, cloud-metadata, or non-configured `via` endpoints.

### Available tools

| Tool | What it does |
|---|---|
| `ciphervault_status` | Vault status: tracked file **paths** (never contents), active snapshot head, operator count, keyring backend. |
| `ciphervault_scan` | Scans the workspace and staged Git diffs for confidential files, secret sprawl, and leaked credential shapes. `fix` appends findings to `.gitignore`. |
| `ciphervault_redact` | Fail-closed exact-value (raw, base64, percent-encoded, hex, JSON-escaped) + shape scrubber. Emits `exact_values_complete: true`. |
| `ciphervault_run` | Runs a command with secrets injected in RAM only; output is scrubbed and audit-receipted. Supports `allow_keys`, `profile`, `no_net`, `proxy`, `env_file`, `project`, `env`, `dry_run`, and `cwd`. |
| `ciphervault_push` | Creates an encrypted snapshot of tracked files. `shred_working_copy` removes plaintext after sealing. |
| `ciphervault_diff` | Masked key-level diff between snapshots or against the working tree (never reveals values). |
| `ciphervault_audit` | Reads and verifies the tamper-evident agent audit log. |
| `ciphervault_env_doctor` | Zero-knowledge environment diagnostics via `env-doctor --json` (code refs vs `.env.example` vs vault keys + in-memory value linting, never returns values). |
| `ciphervault_proxy_doctor` | Dry-run loopback proxy diagnostic: classifies vault keys into built-in providers, `.ciphervault/policy.toml` upstreams, and unmapped keys. |
| `ciphervault_recovery_drill` | Restores a recovery kit or guardian share paths into a fresh temp dir, returns a SHA-256 manifest, and deletes the temp dir. |
| `ciphervault_secret_generate` | Generates a cryptographically random secret directly inside the vault via `ciphervault vault generate --json` (preserving all existing sealed keys; never returns the value). |

For agents that support tool-call hooks, also wire `ciphervault hook agent-pre` and `agent-post` to block secret-file reads and unsafe commits and to scrub results. See [AI Agent Safety in the main README](../../README.md#-ai-agent-safety--the-hermes-plugin).

Using Hermes Agent instead? The [Hermes plugin](../../plugins/ciphervault/README.md) offers the same protections plus hooks, a secret source, and a desktop pane.

---

## Compatibility shim: `services/mcp/ciphervault_mcp_server.py`

Kept strictly for existing configurations that still invoke the Python script or call the legacy tool names. It spawns `ciphervault mcp` with an allowlisted minimal environment and translates legacy tool aliases to their native equivalents:

| Legacy alias | Delegates to |
|---|---|
| `ciphervault_run_in_memory` | `ciphervault_run` (maps `environment` -> `env`, strips `proxy_upstream`) |
| `ciphervault_scan_secrets` | `ciphervault_scan` |
| `ciphervault_list_secrets` | `ciphervault_status` |
| `ciphervault_create_snapshot` | `ciphervault_push` (`local_only` defaults to `true`) |

```json
{
  "mcpServers": {
    "ciphervault": {
      "command": "python",
      "args": ["services/mcp/ciphervault_mcp_server.py"],
      "env": {
        "NO_COLOR": "1"
      }
    }
  }
}
```

A ready-made example is in [`ciphervault-mcp.json`](./ciphervault-mcp.json). Its `CIPHERVAULT_OPERATORS` entry points at a local development operator; change it to your own fleet or remove it.

> **Limits:** scrubbing is exact-value plus credential-shape matching and cannot catch a child process that transforms a secret before printing it. Where possible keep `--no-net` on (or use `--proxy`), and see [`CURRENT_SECURITY_GUARANTEES.md`](../../docs/CURRENT_SECURITY_GUARANTEES.md#agent-safety-surfaces-v1032-to-v1035) for exactly what is and is not guaranteed.
