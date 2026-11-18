# CipherVault Model Context Protocol (MCP) Servers

CipherVault lets AI coding assistants (Claude Code, Codex, Cursor, Antigravity, AutoGen) work in a project that has a vault with **no plaintext credential exposure**: secrets are injected into a child process in RAM, and everything that comes back to the model is scrubbed first.

There are two MCP servers. **Use the native one for anything new.**

| | `ciphervault mcp` (recommended) | `services/mcp/ciphervault_mcp_server.py` (older) |
|---|---|---|
| Implementation | Built into the CLI (Rust, `apps/cli/src/commands/mcp.rs`) | Python wrapper that shells out to the CLI |
| Install | None beyond the CLI itself | Needs Python and a checkout of this repo |
| Tools | `ciphervault_status`, `ciphervault_scan`, `ciphervault_redact`, `ciphervault_run`, `ciphervault_push`, `ciphervault_diff`, `ciphervault_audit` | `ciphervault_run_in_memory`, `ciphervault_scan_secrets`, `ciphervault_list_secrets`, `ciphervault_create_snapshot` |
| `--no-net` by default | Yes on Linux, macOS and Windows (disable with `no_net: false`; cannot combine with `proxy`) | Yes on Linux, macOS and Windows (disable with `no_net: false`, or by enabling `proxy`) |
| Least privilege and profiles | `allow_keys`, `profile` (from `.ciphervault/policy.toml`), `proxy` | `allow_keys` and `proxy`; no `profile` |
| Agent-chosen proxy upstreams | Never forwarded | Not exposed |
| Audit log | `ciphervault_audit` reads and verifies the tamper-evident agent log | Not exposed |

Both servers run `ciphervault run --json`, so captured output is exact-value scrubbed before it reaches the model.

---

## Native server: `ciphervault mcp`

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

It speaks MCP over stdio. Run it from (or point `cwd` at) the project that contains the `.ciphervault/` vault.

| Tool | What it does |
|---|---|
| `ciphervault_status` | Vault status: tracked file **paths** (never contents), active snapshot head, operator count, keyring backend. |
| `ciphervault_scan` | Scans the workspace and staged Git diffs for confidential files, secret sprawl and leaked credential shapes. `fix` appends findings to `.gitignore`. |
| `ciphervault_redact` | Scrubs vault-exact values (raw, base64, percent-encoded, hex, JSON-escaped) and credential patterns from text. |
| `ciphervault_run` | Runs a command with secrets injected in RAM only; output is scrubbed. Supports `allow_keys`, `profile`, `no_net`, `proxy`, `env_file`, `project`, `env` and `dry_run`. |
| `ciphervault_push` | Creates an encrypted snapshot of tracked files. `shred_working_copy` removes plaintext after sealing. |
| `ciphervault_diff` | Masked key-level diff between snapshots or against the working tree (never reveals values). |
| `ciphervault_audit` | Reads and verifies the agent audit log. |

For agents that support tool-call hooks, also wire `ciphervault hook agent-pre` and `agent-post` to block secret-file reads and unsafe commits and to scrub results. See [AI Agent Safety in the main README](../../README.md#-ai-agent-safety--the-hermes-plugin).

Using Hermes Agent instead? The [Hermes plugin](../../plugins/ciphervault/README.md) offers the same protections plus five more tools, a secret source and a desktop pane.

---

## Older Python server

Kept for existing configurations. It requires a checkout of this repository.

1. **`ciphervault_run_in_memory`**: Executes build tools, test runners and dev servers with decrypted environment variables injected into memory only. Output is scrubbed before it returns to the agent.
2. **`ciphervault_scan_secrets`**: Scans the workspace and staged Git changes for secret sprawl (`.env` files, private keys, API tokens) and can append findings to `.gitignore`.
3. **`ciphervault_list_secrets`**: Lists active variable keys and snapshot status without disclosing values.
4. **`ciphervault_create_snapshot`**: Takes an encrypted snapshot after code changes. `shred_working_copy` removes plaintext after sealing.

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

> **Limits:** scrubbing is exact-value plus credential-shape matching and cannot catch a child process that transforms a secret before printing it. Where possible keep `--no-net` on, and see [`CURRENT_SECURITY_GUARANTEES.md`](../../docs/CURRENT_SECURITY_GUARANTEES.md#agent-safety-surfaces-v1032-to-v1035) for exactly what is and is not guaranteed.
