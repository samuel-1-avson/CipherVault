#!/usr/bin/env python3
"""CipherVault Model Context Protocol (MCP) Server.

Enables autonomous AI coding assistants (Antigravity, Claude Code, Cursor, AutoGen)
to interact with CipherVault-managed environments with ZERO credential exposure.

All command executions are performed directly in-memory via `ciphervault run --json`,
and all output streams (stdout, stderr) are scrubbed of secret patterns before
returning to the LLM agent token window.
"""

import json
import os
from pathlib import Path
import subprocess
import sys


def find_ciphervault_binary():
    """Locate the ciphervault executable in workspace or system PATH."""
    repo_root = Path(__file__).resolve().parents[2]
    # Check debug/release build targets
    candidates = [
        Path(os.environ.get("CARGO_TARGET_DIR", "")) / "debug" / ("ciphervault.exe" if sys.platform == "win32" else "ciphervault"),
        Path.home() / ".cargo-targets" / "ciphervault" / "debug" / ("ciphervault.exe" if sys.platform == "win32" else "ciphervault"),
        repo_root / "target" / "debug" / ("ciphervault.exe" if sys.platform == "win32" else "ciphervault"),
        Path(shutil_which("ciphervault") or ""),
    ]
    for c in candidates:
        if c and c.is_file() and os.access(c, os.X_OK):
            return str(c)
    # Default to "ciphervault" CLI in PATH
    return "ciphervault"


def shutil_which(cmd):
    import shutil
    return shutil.which(cmd)


class CipherVaultMcpServer:
    """JSON-RPC 2.0 Model Context Protocol Server."""

    def __init__(self, binary_path=None, repo_root=None):
        self.binary_path = binary_path or find_ciphervault_binary()
        self.repo_root = repo_root or Path(__file__).resolve().parents[2]

    def handle_request(self, request: dict) -> dict:
        """Dispatch a single JSON-RPC 2.0 request."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {},
                    },
                    "serverInfo": {
                        "name": "ciphervault-mcp-server",
                        "version": "1.0.28",
                    },
                },
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "ciphervault_run_in_memory",
                            "description": "Execute a shell command with decrypted secrets injected into memory (zero disk exposure). Output is automatically scrubbed of secret values before returning.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Command and arguments to execute (e.g. ['python', 'app.py'] or ['npm', 'test'])",
                                    },
                                    "env_file": {
                                        "type": "string",
                                        "description": "Optional specific secret file to load (e.g. '.env.production')",
                                    },
                                    "project": {
                                        "type": "string",
                                        "description": "Optional project scope identifier",
                                    },
                                    "environment": {
                                        "type": "string",
                                        "description": "Optional environment name (e.g. 'staging', 'production')",
                                    },
                                    "dry_run": {
                                        "type": "boolean",
                                        "description": "List injected variable names without executing command",
                                    },
                                },
                                "required": ["command"],
                            },
                        },
                        {
                            "name": "ciphervault_scan_secrets",
                            "description": "Deep-scan workspace and staged Git changes for secret sprawl, untracked .env files, private keys, and token patterns.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "deep": {
                                        "type": "boolean",
                                        "default": True,
                                        "description": "Scan staged diffs and filesystem for untracked credentials",
                                    },
                                    "fix": {
                                        "type": "boolean",
                                        "default": False,
                                        "description": "Automatically append discovered sprawling secret files to .gitignore",
                                    },
                                },
                            },
                        },
                        {
                            "name": "ciphervault_list_secrets",
                            "description": "List tracked confidential files and active secret variables without exposing plaintext values.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "project": {"type": "string"},
                                    "environment": {"type": "string"},
                                },
                            },
                        },
                        {
                            "name": "ciphervault_create_snapshot",
                            "description": "Create an encrypted snapshot of tracked confidential files with zero plaintext exposure.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "message": {
                                        "type": "string",
                                        "description": "Descriptive commit message for the snapshot",
                                    },
                                    "local_only": {
                                        "type": "boolean",
                                        "default": True,
                                        "description": "Store snapshot locally without operator replication",
                                    },
                                },
                                "required": ["message"],
                            },
                        },
                    ]
                },
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            return self.dispatch_tool(req_id, tool_name, arguments)

        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found",
                },
            }

    def dispatch_tool(self, req_id, tool_name: str, args: dict) -> dict:
        """Execute the requested tool and format result."""
        try:
            if tool_name == "ciphervault_run_in_memory":
                cmd = args.get("command", [])
                env_file = args.get("env_file")
                project = args.get("project")
                environment = args.get("environment")
                dry_run = args.get("dry_run", False)

                cli_args = [self.binary_path, "run", "--json"]
                if dry_run:
                    cli_args.append("--dry-run")
                if env_file:
                    cli_args.extend(["--env-file", env_file])
                if project:
                    cli_args.extend(["--project", project])
                if environment:
                    cli_args.extend(["--env", environment])

                if cmd:
                    cli_args.append("--")
                    cli_args.extend(cmd)

                proc = subprocess.run(
                    cli_args,
                    cwd=str(self.repo_root),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )

                output_text = proc.stdout.strip()
                try:
                    payload = json.loads(output_text)
                except Exception:
                    payload = {
                        "raw_output": output_text,
                        "raw_stderr": proc.stderr.strip(),
                        "exit_code": proc.returncode,
                    }

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(payload, indent=2)}
                        ]
                    },
                }

            elif tool_name == "ciphervault_scan_secrets":
                deep = args.get("deep", True)
                fix = args.get("fix", False)

                cli_args = [self.binary_path, "hook", "check", "--json"]
                if deep:
                    cli_args.append("--deep")
                if fix:
                    cli_args.append("--fix")

                proc = subprocess.run(
                    cli_args,
                    cwd=str(self.repo_root),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )

                output_text = proc.stdout.strip()
                try:
                    payload = json.loads(output_text)
                except Exception:
                    payload = {"output": output_text, "stderr": proc.stderr.strip()}

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(payload, indent=2)}
                        ]
                    },
                }

            elif tool_name == "ciphervault_list_secrets":
                cli_args = [self.binary_path, "status", "--json"]
                proc = subprocess.run(
                    cli_args,
                    cwd=str(self.repo_root),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": proc.stdout.strip() or proc.stderr.strip()}
                        ]
                    },
                }

            elif tool_name == "ciphervault_create_snapshot":
                msg = args.get("message", "Agent snapshot")
                local_only = args.get("local_only", True)
                cli_args = [self.binary_path, "push", "-m", msg]
                if local_only:
                    cli_args.append("--local")

                proc = subprocess.run(
                    cli_args,
                    cwd=str(self.repo_root),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": proc.stdout.strip() or proc.stderr.strip()}
                        ]
                    },
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": f"Unknown tool name '{tool_name}'",
                    },
                }

        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32000,
                    "message": str(exc),
                },
            }

    def run_stdio(self):
        """Standard I/O event loop for MCP clients."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except Exception as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    server = CipherVaultMcpServer()
    server.run_stdio()
