"""CipherVault Hermes plugin — native tools wrapping the prebuilt CLI.

Tools (model-facing, prefixed ciphervault_):
  scan   — deep-scan workspace + staged diffs for secret sprawl (masked)
  status — tracked files + snapshot head, keys only, no values
  run    — execute a command with decrypted env in RAM; output scrubbed
  push   — encrypted snapshot of tracked secrets (local or replicated)

Binary resolution: $CIPHERVAULT_BIN, then dist/bin beside the repo,
then PATH. Never prints secret values; run output is scrubbed before return.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent
# plugins/ciphervault/__init__.py -> repo root is parents[1]
_REPO_ROOT = PLUGIN_DIR.parents[1]


def find_binary():
    override = os.environ.get("CIPHERVault_BIN") or os.environ.get("CIPHERVAULT_BIN")
    if override:
        return override
    exe = "ciphervault.exe" if os.name == "nt" else "ciphervault"
    for candidate in (
        _REPO_ROOT / "dist" / "bin" / exe,
        _REPO_ROOT / "target" / "debug" / exe,
        _REPO_ROOT / "target" / "release" / exe,
    ):
        if candidate.is_file():
            return str(candidate)
    return shutil.which("ciphervault") or "ciphervault"


_TOKEN_RE = re.compile(
    r"(sk_live[\w-]+|sk_test[\w-]+|ghp_[\w]+|gho_[\w]+|xox[bpas]-[\w-]+|AKIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.?[A-Za-z0-9_-]*)"
)
_KV_RE = re.compile(r"(?i)((?:secret|token|password|passwd|pwd|api[_-]?key|private[_-]?key)\s*[=:]\s*)([^\s\"']+)")


def scrub(text):
    if not text:
        return text
    text = _TOKEN_RE.sub("***redacted***", text)
    return _KV_RE.sub(r"\1***redacted***", text)


def _run_cli(args, cwd):
    try:
        proc = subprocess.run(
            [find_binary()] + args,
            cwd=cwd or os.getcwd(),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return {"success": False, "error": "ciphervault binary not found (set CIPHERVAULT_BIN or install dist/bin)."}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "ciphervault timed out after 120s."}
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    # NOTE: some commands (e.g. recover) print "Error: ..." yet exit 0,
    # on either stream. The banner precedes it, so match at any line start.
    if re.search(r"(?m)^Error:", out) or re.search(r"(?m)^Error:", err):
        return {"success": False, "error": scrub(out + ("\n" + err if err else ""))}
    if proc.returncode != 0 and not out:
        return {"success": False, "error": scrub(err or f"exit {proc.returncode}")}
    return {"success": True, "output": scrub(out), "stderr": scrub(err), "exit_code": proc.returncode}


def register(ctx):
    def handle_status(params, **kwargs):
        cwd = (params or {}).get("cwd")
        res = _run_cli(["status"], cwd)
        return json.dumps(res)

    ctx.register_tool(
        name="ciphervault_status",
        toolset="ciphervault",
        schema={
            "name": "ciphervault_status",
            "description": "Show CipherVault tracked files and snapshot head. Keys only, never values.",
            "parameters": {
                "type": "object",
                "properties": {"cwd": {"type": "string", "description": "Workspace directory (default: session cwd)."}},
            },
        },
        handler=handle_status,
    )

    def handle_scan(params, **kwargs):
        params = params or {}
        # `--deep` enables the recursive workspace sprawl scan (staged-only
        # without it). `fix` is accepted for API compat but stays a no-op:
        # findings go in `.gitignore` manually (see note below).
        cmd = ["hook", "check", "--deep"]
        res = _run_cli(cmd, params.get("cwd"))
        if params.get("fix") and res.get("success"):
            res["note"] = "autofix not supported by this CLI build; add findings to .gitignore manually."
        return json.dumps(res)

    ctx.register_tool(
        name="ciphervault_scan",
        toolset="ciphervault",
        schema={
            "name": "ciphervault_scan",
            "description": "Check workspace and staged git diffs for staged confidential files (masked output).",
            "parameters": {
                "type": "object",
                "properties": {
                    "deep": {"type": "boolean", "default": True, "description": "Accepted for compat; current CLI always deep-checks."},
                    "fix": {"type": "boolean", "default": False, "description": "Accepted for compat; autofix unsupported — findings must be gitignored manually."},
                    "cwd": {"type": "string"}
                },
            },
        },
        handler=handle_scan,
    )

    def handle_run(params, **kwargs):
        params = params or {}
        cmd = params.get("command", [])
        if not cmd:
            return json.dumps({"success": False, "error": "command is required, e.g. ['npm','test']"})
        args = ["run", "-q"]
        if params.get("dry_run"):
            args.append("--dry-run")
        if params.get("env_file"):
            args += ["--env-file", params["env_file"]]
        args += cmd
        res = _run_cli(args, params.get("cwd"))
        # Belt and suspenders: scrub again — values must never reach context.
        if res.get("success"):
            res["output"] = scrub(res.get("output", ""))
            res["stderr"] = scrub(res.get("stderr", ""))
        return json.dumps(res)

    ctx.register_tool(
        name="ciphervault_run",
        toolset="ciphervault",
        schema={
            "name": "ciphervault_run",
            "description": "Run a build/test/dev server with secrets injected in RAM only. Stdout/stderr are scrubbed of secret values before return. Never prints plaintext.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "array", "items": {"type": "string"}, "description": "Command, e.g. ['npm','test']"},
                    "env_file": {"type": "string", "description": "Optional secret file, e.g. .env.production"},
                    "dry_run": {"type": "boolean", "default": False, "description": "List variable names without executing"},
                    "cwd": {"type": "string"},
                },
                "required": ["command"],
            },
        },
        handler=handle_run,
    )

    def handle_push(params, **kwargs):
        params = params or {}
        msg = params.get("message", "Agent snapshot")
        args = ["push", "-m", msg]
        if params.get("local_only", True):
            args.append("--local")
        res = _run_cli(args, params.get("cwd"))
        return json.dumps(res)

    ctx.register_tool(
        name="ciphervault_push",
        toolset="ciphervault",
        schema={
            "name": "ciphervault_push",
            "description": "Create an encrypted snapshot of tracked secrets after editing code. Client-side sealed; operators see ciphertext only.",
            "parameters": {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "default": "Agent snapshot"},
                    "local_only": {"type": "boolean", "default": True},
                    "cwd": {"type": "string"}
                },
            },
        },
        handler=handle_push,
    )

    def on_tool_call(tool_name, params=None, result=None, **kwargs):
        if isinstance(tool_name, str) and tool_name.startswith("ciphervault_"):
            print(f"[ciphervault] tool called: {tool_name}")

    def handle_drill(params, **kwargs):
        import tempfile
        params = params or {}
        kit = params.get("kit")
        shares = params.get("shares", [])
        if not kit and not shares:
            return json.dumps({"success": False, "error": "provide kit (path to kit file) or shares (list of share file paths). Paths only — never paste kit contents."})
        dest = params.get("to") or tempfile.mkdtemp(prefix="cv-drill-")
        args = ["recover", "--to", dest]
        if kit:
            args += ["--kit", kit]
        if shares:
            args += ["--shares"] + list(shares)
        res = _run_cli(args, params.get("cwd"))
        if res.get("success"):
            res["drill_dir"] = dest
            res["next"] = "Compare drill_dir against your working files (diff -r). Then delete drill_dir. Your kit/shares are proven."
        return json.dumps(res)

    ctx.register_tool(
        name="ciphervault_recovery_drill",
        toolset="ciphervault",
        schema={
            "name": "ciphervault_recovery_drill",
            "description": "Prove a recovery kit or guardian shares work by restoring into a temp directory (proof drill). Takes FILE PATHS only — never ask for or accept kit/share contents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "kit": {"type": "string", "description": "Path to kit file on disk"},
                    "shares": {"type": "array", "items": {"type": "string"}, "description": "Paths to guardian share files"},
                    "to": {"type": "string", "description": "Optional restore target dir (default: temp dir)"},
                    "cwd": {"type": "string"}
                },
            },
        },
        handler=handle_drill,
    )

    ctx.register_hook("post_tool_call", on_tool_call)
