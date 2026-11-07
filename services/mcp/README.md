# CipherVault Model Context Protocol (MCP) Server

The **CipherVault MCP Server** allows autonomous AI coding assistants (such as Antigravity, Claude Code, Cursor, AutoGen) to pair-program and run tasks in CipherVault projects with **zero plaintext credential exposure**.

---

## Capabilities Provided to AI Agents

1. **`ciphervault_run_in_memory`**: Executes build tools, test runners, and dev servers with decrypted environment variables injected exclusively into memory (`RAM`). All output streams (`stdout`, `stderr`) are automatically redacted using `ciphervault_redact` before returning to the agent's LLM context window.
2. **`ciphervault_scan_secrets`**: Scans the workspace and staged Git changes for secret sprawl (`.env` files, private keys, API tokens) and optionally auto-fixes `.gitignore`.
3. **`ciphervault_list_secrets`**: Surfaces active variable keys and snapshot status without disclosing plaintext secret values.
4. **`ciphervault_create_snapshot`**: Takes a zero-leak encrypted snapshot after modifying code.

---

## Agent Configuration Setup

Add this block to your agent configuration file (e.g. `claude_desktop_config.json` or `.cursor/mcp.json`):

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
