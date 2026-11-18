#!/usr/bin/env python3
"""Thin compatibility shim that delegates MCP requests to `ciphervault mcp`.

The single hardened MCP implementation lives in the native Rust CLI
(`apps/cli/src/commands/mcp.rs`). This launcher exists only for existing
configurations pointing at `services/mcp/ciphervault_mcp_server.py` or calling
legacy tool names (`ciphervault_run_in_memory`, `ciphervault_scan_secrets`,
`ciphervault_list_secrets`, `ciphervault_create_snapshot`).

New setups should configure `ciphervault mcp` directly.
"""

import atexit
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import weakref

TOOL_TIMEOUT_SECS = 120

_ENV_KEEP = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "APPDATA",
    "LOCALAPPDATA",
    "COMSPEC",
    "PATHEXT",
)

LEGACY_TOOL_ALIASES = {
    "ciphervault_run_in_memory": "ciphervault_run",
    "ciphervault_scan_secrets": "ciphervault_scan",
    "ciphervault_list_secrets": "ciphervault_status",
    "ciphervault_create_snapshot": "ciphervault_push",
}

_LEGACY_DESCRIPTIONS = {
    "ciphervault_run_in_memory": "Legacy alias for ciphervault_run: execute a command with decrypted secrets injected in RAM only (zero disk exposure, output scrubbed, audit-receipted).",
    "ciphervault_scan_secrets": "Legacy alias for ciphervault_scan: scan workspace and staged Git changes for secret sprawl and credential patterns.",
    "ciphervault_list_secrets": "Legacy alias for ciphervault_status: list tracked confidential file paths and vault status without exposing values.",
    "ciphervault_create_snapshot": "Legacy alias for ciphervault_push: create an encrypted snapshot of tracked confidential files.",
}


def _minimal_env() -> dict:
    """Allowlisted environment for the native `ciphervault mcp` child process.

    Strips inherited provider keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.)
    while preserving essential OS variables and `CIPHERVAULT_*` configuration.
    """
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}
    env.update({k: v for k, v in os.environ.items() if k.startswith("CIPHERVAULT_")})
    env["NO_COLOR"] = "1"
    return env


def _validate_cwd(cwd):
    if cwd is None:
        return None, None
    if not isinstance(cwd, str):
        return None, "cwd must be a string"
    cleaned = cwd.strip()
    if not cleaned:
        return None, None
    if cleaned.startswith(("\\\\", "//", "\\??\\")) or "\x00" in cleaned:
        return None, "cwd cannot be a UNC or network share path"
    return cleaned, None


def find_ciphervault_binary() -> str:
    """Locate the native `ciphervault` executable in env, target dirs, or PATH."""
    exe = "ciphervault.exe" if sys.platform == "win32" else "ciphervault"
    repo_root = Path(__file__).resolve().parents[2]
    candidates = []
    env_bin = os.environ.get("CIPHERVAULT_BIN")
    if env_bin:
        candidates.append(Path(env_bin))
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target:
        candidates.extend([Path(cargo_target) / "debug" / exe, Path(cargo_target) / "release" / exe])
    candidates.extend([
        repo_root / "target" / "debug" / exe,
        repo_root / "target" / "release" / exe,
        Path.home() / ".cargo-targets" / "ciphervault" / "debug" / exe,
        Path.home() / ".cargo-targets" / "ciphervault" / "release" / exe,
    ])
    which = shutil.which("ciphervault")
    if which:
        candidates.append(Path(which))
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return "ciphervault"


def translate_legacy_tool_call(tool_name: str, args: dict):
    """Translate a legacy tool name + arguments to its native `ciphervault mcp` call.

    Returns `(native_name, native_args, error_message_or_None)`.
    Non-legacy tool names pass through unchanged.
    """
    args = dict(args) if isinstance(args, dict) else {}
    cwd, cwd_err = _validate_cwd(args.get("cwd"))
    if cwd_err:
        return None, None, cwd_err

    if tool_name not in LEGACY_TOOL_ALIASES:
        if cwd is not None:
            args["cwd"] = cwd
        return tool_name, args, None

    native_name = LEGACY_TOOL_ALIASES[tool_name]

    if tool_name == "ciphervault_run_in_memory":
        cmd = args.get("command")
        dry_run = bool(args.get("dry_run", False))
        if cmd is not None and not isinstance(cmd, list):
            return None, None, "command must be an array of strings"
        cmd_list = [str(c) for c in (cmd or [])]
        if not cmd_list and not dry_run:
            return None, None, "command must be a non-empty array of strings"

        allow_keys = args.get("allow_keys")
        cleaned_keys = None
        if allow_keys is not None:
            if not isinstance(allow_keys, list):
                return None, None, "allow_keys must be an array of variable names"
            cleaned_keys = [str(k).strip() for k in allow_keys if str(k).strip()]
            if not cleaned_keys:
                return None, None, "allow_keys cannot be empty when provided"

        proxy = bool(args.get("proxy", False))
        no_net_raw = args.get("no_net")
        if proxy and no_net_raw is True:
            return None, None, "proxy and no_net cannot both be enabled"

        native_args = {"command": cmd_list}
        if dry_run:
            native_args["dry_run"] = True
        if args.get("profile"):
            native_args["profile"] = str(args["profile"])
        if args.get("env_file"):
            native_args["env_file"] = str(args["env_file"])
        if args.get("project"):
            native_args["project"] = str(args["project"])
        env_val = args.get("env") or args.get("environment")
        if env_val:
            native_args["env"] = str(env_val)
        if cleaned_keys is not None:
            native_args["allow_keys"] = cleaned_keys
        if proxy:
            native_args["proxy"] = True
        if no_net_raw is not None:
            native_args["no_net"] = bool(no_net_raw)
        if cwd is not None:
            native_args["cwd"] = cwd
        # Agent-supplied proxy_upstream is intentionally dropped.
        return native_name, native_args, None

    if tool_name == "ciphervault_scan_secrets":
        native_args = {
            "deep": bool(args.get("deep", True)),
            "fix": bool(args.get("fix", False)),
        }
        if cwd is not None:
            native_args["cwd"] = cwd
        return native_name, native_args, None

    if tool_name == "ciphervault_list_secrets":
        native_args = {}
        if cwd is not None:
            native_args["cwd"] = cwd
        return native_name, native_args, None

    if tool_name == "ciphervault_create_snapshot":
        native_args = {
            "message": str(args.get("message") or "Agent snapshot"),
            "local_only": bool(args.get("local_only", True)),
            "shred_working_copy": bool(args.get("shred_working_copy", False)),
        }
        if cwd is not None:
            native_args["cwd"] = cwd
        return native_name, native_args, None

    return native_name, args, None


def _augment_tools_list(native_tools: list) -> list:
    """Keep every native tool and append legacy aliases derived from their schemas."""
    tools = list(native_tools)
    by_name = {t.get("name"): t for t in tools if isinstance(t, dict) and t.get("name")}
    for alias, target in LEGACY_TOOL_ALIASES.items():
        if alias in by_name or target not in by_name:
            continue
        base = by_name[target]
        schema = json.loads(json.dumps(base.get("inputSchema") or {"type": "object", "properties": {}}))
        props = schema.setdefault("properties", {})
        if alias == "ciphervault_run_in_memory" and "environment" not in props:
            props["environment"] = {
                "type": "string",
                "description": "Legacy alias for `env`",
            }
        tools.append({
            "name": alias,
            "description": _LEGACY_DESCRIPTIONS[alias],
            "inputSchema": schema,
        })
    return tools


class CipherVaultMcpServer:
    """Thin JSON-RPC 2.0 bridge delegating all MCP execution to `ciphervault mcp`."""

    def __init__(self, binary_path=None, repo_root=None):
        self.binary_path = binary_path or find_ciphervault_binary()
        self.repo_root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[2]
        self._proc = None
        self._lines = None
        self._reader = None
        self._lock = threading.Lock()
        self._ref = weakref.ref(self)
        atexit.register(CipherVaultMcpServer._cleanup_ref, self._ref)

    @staticmethod
    def _cleanup_ref(ref):
        inst = ref()
        if inst is not None:
            inst.close()

    def _ensure_native_process(self):
        if self._proc is not None and self._proc.poll() is None:
            return
        self.close()
        self._proc = subprocess.Popen(
            [self.binary_path, "mcp"],
            cwd=str(self.repo_root),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=_minimal_env(),
        )
        lines = queue.Queue()
        self._lines = lines

        def _read_loop(stdout_pipe, out_q):
            try:
                for line in stdout_pipe:
                    out_q.put(line)
            except Exception:
                pass
            finally:
                out_q.put(None)

        self._reader = threading.Thread(
            target=_read_loop, args=(self._proc.stdout, lines), daemon=True
        )
        self._reader.start()

    def close(self):
        proc = self._proc
        self._proc = None
        self._lines = None
        self._reader = None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _forward_to_native(self, request: dict, timeout: int = TOOL_TIMEOUT_SECS):
        """Send one JSON-RPC 2.0 message to the native `ciphervault mcp` process."""
        is_notification = request.get("id") is None or str(request.get("method") or "").startswith("notifications/")
        with self._lock:
            self._ensure_native_process()
            assert self._proc is not None and self._proc.stdin is not None and self._lines is not None
            try:
                self._proc.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
                self._proc.stdin.flush()
            except Exception as exc:
                self.close()
                raise RuntimeError(f"failed to write to native ciphervault mcp: {exc}") from exc

            if is_notification:
                return None

            try:
                line = self._lines.get(timeout=timeout)
            except queue.Empty as exc:
                self.close()
                raise TimeoutError(f"ciphervault mcp timed out after {timeout}s") from exc

            if line is None:
                self.close()
                raise RuntimeError("native ciphervault mcp process exited unexpectedly")
            return json.loads(line)

    def handle_request(self, request: dict):
        """Dispatch a JSON-RPC 2.0 request to the native `ciphervault mcp` binary."""
        if not isinstance(request, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request"},
            }
        req_id = request.get("id")
        method = request.get("method") or ""
        params = request.get("params") or {}

        if req_id is None or str(method).startswith("notifications/"):
            try:
                self._forward_to_native(request)
            except Exception:
                pass
            return None

        forwarded = request
        if method == "tools/call":
            tool_name = params.get("name") or ""
            arguments = params.get("arguments") or {}
            native_name, native_args, err = translate_legacy_tool_call(tool_name, arguments)
            if err is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": err},
                }
            forwarded = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": native_name, "arguments": native_args},
            }

        try:
            resp = self._forward_to_native(forwarded)
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32000, "message": str(exc)},
            }

        if method == "tools/list" and isinstance(resp, dict):
            result = resp.get("result")
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                resp = dict(resp)
                resp["result"] = dict(result, tools=_augment_tools_list(result["tools"]))
        return resp

    def run_stdio(self):
        """Standard I/O JSON-RPC 2.0 loop delegating to `ciphervault mcp`."""
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    request = json.loads(line)
                except Exception as exc:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {exc}"},
                    }
                    sys.stdout.write(json.dumps(err_resp) + "\n")
                    sys.stdout.flush()
                    continue
                response = self.handle_request(request)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
        finally:
            self.close()


if __name__ == "__main__":
    CipherVaultMcpServer().run_stdio()
