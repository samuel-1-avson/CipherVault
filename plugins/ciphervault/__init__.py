"""CipherVault Hermes plugin — zero-knowledge secrets for AI agents.

Surfaces registered (see plugin.yaml):
  tools        ciphervault_status / scan / run / push / recovery_drill / redact
  hooks        pre_tool_call           (leak guard: blocks secret reads/exfil)
               transform_tool_result   (scrubs every non-CipherVault result)
  middleware   tool_request            (defaults ciphervault_* cwd)
  secret src   "ciphervault"           (Hermes env vars sourced from a vault)
  commands     /ciphervault (chat), `hermes ciphervault` (terminal)

Design rules (also in skills/ciphervault/SKILL.md):
  * File PATHS only for kits/shares — contents never enter model context.
  * `init` / secret-printing commands are never wrapped as agent tools.
  * Scrubbing is layered: exact-value inside `ciphervault run --json` /
    `redact` (values matched inside the CLI process), shape-based
    patterns here and in Hermes' own redactor as further layers.
  * The CLI binary is an upstream release asset fetched by bootstrap
    (pinned version + SHA-256 verified against the release
    SHA256SUMS.txt), never bundled in this repo (catalog rule 17).
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent
RELEASE_VERSION = "1.0.31"
# SHA-256 of the release ciphervault.exe, pinned in source (catalog rule
# 17: setup-time fetches must be checksum-pinned). bootstrap_binary()
# also cross-checks the release SHA256SUMS.txt against this value.
RELEASE_BINARY_SHA256 = "d31e7864ca78944f829ee339b9fdd3d3bd8552481e994d2c2f8cef92a0d4a717"
RELEASE_BASE = (
    "https://github.com/samuel-1-avson/CipherVault/releases/download/"
    f"v{RELEASE_VERSION}"
)
_ctx = {"ctx": None}


# ---------------------------------------------------------------- binary

def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))


def _data_bin_dir() -> Path:
    return _hermes_home() / "plugins" / "ciphervault" / "bin"


def find_binary():
    """Resolve the ciphervault CLI: configured path, env override,
    bootstrapped copy, repo checkout (dev), then PATH.
    Returns (path|None, source)."""
    ctx = _ctx.get("ctx")
    configured = None
    if ctx is not None:
        try:
            configured = ctx.get_config("binary_path", "")
        except Exception:
            configured = None
    for override in (configured, os.environ.get("CIPHERVAULT_BIN")):
        if override and Path(override).is_file():
            return str(override), "configured"
    exe = "ciphervault.exe" if os.name == "nt" else "ciphervault"
    bootstrapped = _data_bin_dir() / exe
    if bootstrapped.is_file():
        return str(bootstrapped), "bootstrapped"
    roots = [PLUGIN_DIR.parents[1]]
    if len(PLUGIN_DIR.parents) > 2:
        roots.append(PLUGIN_DIR.parents[2])
    for root in roots:
        for cand in (root / "dist" / "bin" / exe,
                     root / "target" / "debug" / exe,
                     root / "target" / "release" / exe):
            if cand.is_file():
                return str(cand), "repo checkout"
    found = shutil.which("ciphervault") or shutil.which("cv")
    if found:
        return found, "PATH"
    return None, "missing"


def bootstrap_binary(progress=print):
    """Download the pinned upstream release binary and verify it
    against the release SHA256SUMS.txt before installing it into the
    plugin data dir. User-invoked setup action (CLI/slash command);
    never runs automatically at plugin load (catalog rule 3/17)."""
    if sys.platform != "win32":
        return {
            "success": False,
            "error": (
                "Prebuilt CipherVault binaries are published for Windows only. "
                "On Linux/macOS build from source (cargo install --path apps/cli "
                "from https://github.com/samuel-1-avson/CipherVault) or set "
                "CIPHERVAULT_BIN / the binary_path plugin setting."
            ),
        }
    asset = "ciphervault.exe"
    sums_url = f"{RELEASE_BASE}/SHA256SUMS.txt"
    try:
        with urllib.request.urlopen(sums_url, timeout=60) as resp:
            sums = resp.read().decode("utf-8", "replace")
    except Exception as exc:
        return {"success": False, "error": f"could not fetch {sums_url}: {exc}"}
    expected = None
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == asset:
            expected = parts[0].lower()
    if not expected:
        return {"success": False, "error": f"{asset} not listed in release SHA256SUMS.txt"}
    if expected != RELEASE_BINARY_SHA256:
        return {
            "success": False,
            "error": (
                f"release SHA256SUMS.txt lists {expected} for {asset}, which does not "
                f"match the checksum pinned in this plugin ({RELEASE_BINARY_SHA256}). "
                "Refusing to install."
            ),
        }
    progress(f"Downloading CipherVault v{RELEASE_VERSION} ({asset})…")
    try:
        with urllib.request.urlopen(f"{RELEASE_BASE}/{asset}", timeout=300) as resp:
            data = resp.read()
    except Exception as exc:
        return {"success": False, "error": f"download failed: {exc}"}
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        return {
            "success": False,
            "error": f"SHA-256 mismatch for {asset}: expected {expected}, got {actual}. Refusing to install.",
        }
    dest_dir = _data_bin_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / asset
    dest.write_bytes(data)
    try:
        (dest_dir / "cv.exe").write_bytes(data)
    except Exception:
        pass
    progress(f"Verified SHA-256 {actual[:16]}… and installed to {dest}")
    return {"success": True, "binary": str(dest), "version": RELEASE_VERSION, "sha256": actual}


# ---------------------------------------------------------------- scrub

_TOKEN_RE = re.compile(
    r"(cvst1\.[A-Za-z0-9._~=-]+|sk_live[\w-]+|sk_test[\w-]+|ghp_[\w]+|gho_[\w]+|"
    r"xox[bpas]-[\w-]+|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.?[A-Za-z0-9_-]*)"
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~=-]+")
_PEM_RE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*-----", re.S)
_KV_RE = re.compile(
    r"(?i)((?:[A-Za-z0-9_-]*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_-]*)\s*[=:]\s*)([^\s\"']+)"
)
_URL_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:)[^\s/@]+(@)")


def scrub(text):
    """Local shape-based scrubbing. Last-resort layer: the CLI's
    exact-value scrubbing (`run --json` / `redact`) is primary."""
    if not text:
        return text
    text = _PEM_RE.sub("[REDACTED] PRIVATE KEY", text)
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _URL_RE.sub(r"\1[REDACTED]\2", text)
    text = _TOKEN_RE.sub("[REDACTED]", text)
    return _KV_RE.sub(r"\1[REDACTED]", text)


# ---------------------------------------------------------------- CLI

def _run_cli(args, cwd, timeout=120, input_text=None):
    binary, source = find_binary()
    if not binary:
        return {
            "success": False,
            "error": "ciphervault binary not found",
            "binary": "missing",
            "next": "Run `hermes ciphervault bootstrap` (Windows) or set CIPHERVAULT_BIN / the binary_path plugin setting.",
        }
    try:
        proc = subprocess.run(
            [binary] + args,
            cwd=cwd or os.getcwd(),
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"ciphervault timed out after {timeout}s", "binary": source}
    except OSError as exc:
        return {"success": False, "error": f"could not run ciphervault: {exc}", "binary": source}
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    # Some commands print "Error: …" yet exit 0, on either stream.
    if re.search(r"(?m)^Error:", out) or re.search(r"(?m)^Error:", err):
        return {"success": False, "error": scrub(out + ("\n" + err if err else "")),
                "binary": source, "exit_code": proc.returncode}
    if proc.returncode != 0 and not out:
        return {"success": False, "error": scrub(err or f"exit {proc.returncode}"),
                "binary": source, "exit_code": proc.returncode}
    return {"success": True, "output": out, "stderr": scrub(err),
            "exit_code": proc.returncode, "binary": source}


def _run_cli_json(args, cwd, timeout=120, input_text=None):
    res = _run_cli(args, cwd, timeout=timeout, input_text=input_text)
    if not res.get("success"):
        return res
    try:
        payload = json.loads(res["output"])
    except Exception:
        return {"success": False, "error": "ciphervault returned non-JSON output",
                "raw": scrub(res["output"])[:2000], "binary": res.get("binary")}
    return {"success": True, "data": payload, "binary": res.get("binary")}


def cli_redact(text, cwd, timeout=15):
    """Exact+shape redaction via the CLI (vault values are matched
    inside the CLI process; they never enter this process). Falls back
    to local shape scrubbing when the CLI is unavailable."""
    if not text:
        return text, 0
    res = _run_cli_json(["redact", "--json"], cwd, timeout=timeout, input_text=text)
    if res.get("success"):
        data = res["data"]
        return data.get("text", scrub(text)), int(data.get("redactions", 0))
    return scrub(text), 0


# ---------------------------------------------------------------- tools

def _tool_status(params, **kwargs):
    return json.dumps(_run_cli_json(["status", "--json"], (params or {}).get("cwd")))


def _tool_scan(params, **kwargs):
    params = params or {}
    args = ["hook", "check", "--json"]
    if params.get("deep", True):
        args.append("--deep")
    if params.get("fix"):
        args.append("--fix")
    return json.dumps(_run_cli_json(args, params.get("cwd")))


def _tool_run(params, **kwargs):
    params = params or {}
    cmd = params.get("command") or []
    if not cmd:
        return json.dumps({"success": False, "error": "command is required, e.g. ['npm','test']"})
    args = ["run", "--json"]
    if params.get("dry_run"):
        args.append("--dry-run")
    if params.get("env_file"):
        args += ["--env-file", params["env_file"]]
    if params.get("project"):
        args += ["--project", params["project"]]
    if params.get("env"):
        args += ["--env", params["env"]]
    args.append("--")
    args += list(cmd)
    return json.dumps(_run_cli_json(args, params.get("cwd"), timeout=300))


def _tool_push(params, **kwargs):
    params = params or {}
    args = ["push", "-m", params.get("message", "Agent snapshot")]
    if params.get("local_only", True):
        args.append("--local")
    res = _run_cli(args, params.get("cwd"), timeout=300)
    if res.get("success"):
        res["output"] = scrub(res["output"])
    return json.dumps(res)


def _tool_redact(params, **kwargs):
    params = params or {}
    cleaned, n = cli_redact(params.get("text") or "", params.get("cwd"))
    return json.dumps({"success": True, "text": cleaned, "redactions": n})


def _tool_drill(params, **kwargs):
    params = params or {}
    kit = params.get("kit")
    shares = params.get("shares") or []
    if not kit and not shares:
        return json.dumps({
            "success": False,
            "error": "provide kit (path to kit file) or shares (list of share file paths). Paths only — never paste kit contents.",
        })
    dest = params.get("to") or tempfile.mkdtemp(prefix="cv-drill-")
    args = ["recover", "--to", dest]
    if kit:
        args += ["--kit", kit]
    if shares:
        args += ["--shares"] + list(shares)
    res = _run_cli(args, params.get("cwd"), timeout=300)
    if not res.get("success"):
        return json.dumps(res)
    # Hash-then-delete: prove the restore by manifest (names + sizes +
    # SHA-256) without the agent reading plaintext, and leave no
    # standing plaintext copy on disk.
    manifest = []
    root = Path(dest)
    for path in sorted(root.rglob("*")):
        if path.is_file():
            manifest.append({
                "path": str(path.relative_to(root)).replace("\\", "/"),
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            })
    auto_delete = params.get("auto_delete", True)
    deleted = False
    if auto_delete:
        shutil.rmtree(root, ignore_errors=True)
        deleted = not root.exists()
    return json.dumps({
        "success": True,
        "binary": res.get("binary"),
        "files_restored": len(manifest),
        "manifest": manifest,
        "drill_dir_deleted": deleted,
        "note": (
            "Plaintext was hashed, verified into this manifest, and deleted; "
            "it never entered this chat. Compare hashes against a later restore to re-verify."
            if deleted else
            "Plaintext remains in the drill dir — delete it as soon as you have compared hashes."
        ),
    })


# ---------------------------------------------------------------- hooks

_SECRET_FILE_RE = re.compile(
    r"(?i)(^|[\s\\/\"'=])(\.env(\.[\w.-]*)?|[\w.-]+\.(pem|key)|id_rsa|id_ed25519|"
    r"credentials\.json|secrets\.json|recovery_kit[\w.-]*|[\w.-]+\.kit|[\w.-]*share[\w.-]*\.txt)"
)
_READ_CMD_RE = re.compile(r"(?i)\b(cat|type|get-content|gc|more|head|tail|less|bat)\b")
_GIT_DANGER_RE = re.compile(r"(?i)\bgit\s+(commit|push|add)\b")


def _iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


def on_pre_tool_call(tool_name, args, **kwargs):
    """Leak guard. Blocks secret-file reads into chat, secret-shaped
    content handed to other tools, and git add/commit/push while the
    CipherVault hook check reports violations. Fail-open on internal
    errors (Hermes isolates hook exceptions too)."""
    try:
        if not tool_name or tool_name.startswith("ciphervault_"):
            return None
        args = args or {}
        cwd = args.get("cwd") or args.get("workdir") or os.getcwd()
        texts = list(_iter_strings(args))

        if tool_name in ("terminal", "execute_code", "read_file", "browser_exec"):
            for text in texts:
                if _SECRET_FILE_RE.search(text) and (
                    tool_name == "read_file" or _READ_CMD_RE.search(text) or tool_name != "terminal"
                ):
                    return {"action": "block", "message": (
                        "CipherVault guard: reading a secret/kit file into the chat would leak it. "
                        "Use ciphervault_run (RAM-only injection), ciphervault_redact (masked), or "
                        "ciphervault_status (names only). Paths are fine; contents are not."
                    )}

        joined = "\n".join(texts)
        if joined:
            cleaned, n = cli_redact(joined, cwd, timeout=10)
            if n > 0 or cleaned != joined:
                return {"action": "block", "message": (
                    "CipherVault guard: this call contains secret material "
                    f"({n} exact/shape redaction(s)). Work with paths and names only, "
                    "seal values with ciphervault_push, run workloads via ciphervault_run."
                )}

        if tool_name == "terminal":
            for text in texts:
                if _GIT_DANGER_RE.search(text):
                    res = _run_cli_json(["hook", "check", "--deep", "--json"], cwd, timeout=30)
                    if res.get("success") and res["data"].get("violations_count", 0) > 0:
                        paths = ", ".join(
                            v.get("path", "?") for v in res["data"].get("violations", [])[:8]
                        )
                        return {"action": "block", "message": (
                            "CipherVault guard: secret sprawl is staged/detected "
                            f"({paths}). Unstage it, .gitignore it, or `ciphervault track` "
                            "it, then retry. Details: ciphervault_scan."
                        )}
                    break
        return None
    except Exception:
        return None


def on_transform_tool_result(tool_name, args, result, **kwargs):
    """Scrub every non-CipherVault tool result before it enters model
    context (exact vault values via the CLI, shapes locally)."""
    try:
        if not isinstance(result, str) or not result:
            return None
        if tool_name and tool_name.startswith("ciphervault_"):
            return None
        cwd = (args or {}).get("cwd") or (args or {}).get("workdir") or os.getcwd()
        sample = result[:262_144]
        cleaned, _n = cli_redact(sample, cwd, timeout=10)
        if cleaned != sample:
            suffix = "\n…[truncated by CipherVault scrub]" if len(result) > len(sample) else ""
            return cleaned + suffix
        return None
    except Exception:
        return None


def on_tool_request(tool_name, args, original_args, **kwargs):
    """Middleware: default the session cwd into ciphervault_* calls
    that omitted it, so tools act on the user's project, not the
    plugin host's cwd. Runs before hooks/approvals by design."""
    try:
        if tool_name and tool_name.startswith("ciphervault_") and isinstance(args, dict):
            if not args.get("cwd"):
                updated = dict(args)
                updated["cwd"] = os.getcwd()
                return {"args": updated, "source": "ciphervault",
                        "reason": "defaulted cwd to the session working directory"}
        return None
    except Exception:
        return None


# ---------------------------------------------------------------- secret source

def _make_secret_source():
    from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource

    class CipherVaultSecretSource(SecretSource):
        """Bulk source: contributes every var of a vault's latest
        snapshot (or one tracked file) as Hermes env vars. Values go
        from the CLI straight into FetchResult — never logged here."""

        name = "ciphervault"
        label = "CipherVault"
        shape = "bulk"
        scheme = "ciphervault"

        def fetch(self, cfg, home_path):
            result = FetchResult()
            try:
                cfg = cfg if isinstance(cfg, dict) else {}
                vault_path = cfg.get("vault_path") or os.getcwd()
                binary, _src = find_binary()
                if not binary:
                    result.error = "ciphervault binary not found; run `hermes ciphervault bootstrap`."
                    result.error_kind = ErrorKind.BINARY_MISSING
                    return result
                argv = [binary, "export-env"]
                if cfg.get("env_file"):
                    argv += ["--env-file", str(cfg["env_file"])]
                if cfg.get("allow_working_copy"):
                    argv.append("--allow-working-copy")
                # run_secret_cli has no cwd knob; replicate its posture
                # (minimal allowlisted env, stdin closed, timeout).
                keep = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMPDIR", "LANG", "LC_ALL")
                env = {k: os.environ[k] for k in keep if k in os.environ}
                env.setdefault("NO_COLOR", "1")
                try:
                    proc = subprocess.run(
                        argv, cwd=str(vault_path), capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=60,
                        stdin=subprocess.DEVNULL, env=env,
                    )
                except subprocess.TimeoutExpired:
                    result.error = "ciphervault export-env timed out after 60s"
                    result.error_kind = ErrorKind.TIMEOUT
                    return result
                except OSError as exc:
                    result.error = f"could not run ciphervault: {exc}"
                    result.error_kind = ErrorKind.BINARY_MISSING
                    return result
                if proc.returncode != 0:
                    result.error = f"ciphervault export-env exited {proc.returncode}: {(proc.stderr or '')[:200]}"
                    result.error_kind = ErrorKind.AUTH_FAILED
                    return result
                try:
                    values = json.loads(proc.stdout or "{}")
                except Exception:
                    result.error = "ciphervault export-env returned non-JSON output"
                    result.error_kind = ErrorKind.INTERNAL
                    return result
                if isinstance(values, dict):
                    result.secrets = {str(k): str(v) for k, v in values.items()}
                result.binary_path = Path(binary)
                return result
            except Exception as exc:  # fetch() must never raise
                result.error = str(exc)
                result.error_kind = ErrorKind.INTERNAL
                return result

        def config_schema(self):
            return {
                "vault_path": {"type": "str", "default": "",
                               "description": "Directory containing the vault (where .ciphervault/ lives)"},
                "env_file": {"type": "str", "default": "",
                             "description": "Optional single tracked secret file to export"},
                "allow_working_copy": {"type": "bool", "default": False,
                                       "description": "Export from working files instead of the latest snapshot"},
            }

        def remediation(self, kind, cfg):
            return ("Run `hermes ciphervault bootstrap`, then `ciphervault init` in your "
                    "project (or set secrets.ciphervault.vault_path).")

    return CipherVaultSecretSource()


# ---------------------------------------------------------------- commands

def _slash_ciphervault(raw_args, **kwargs):
    parts = (raw_args or "").strip().split()
    sub = parts[0] if parts else "status"
    tool_for = {
        "status": "ciphervault_status", "scan": "ciphervault_scan",
        "drill": "ciphervault_recovery_drill", "push": "ciphervault_push",
        "run": "ciphervault_run", "redact": "ciphervault_redact",
    }
    if sub in tool_for:
        try:
            return _ctx["ctx"].dispatch_tool(tool_for[sub], {})
        except Exception as exc:
            return f"ciphervault {sub} failed: {exc}"
    if sub in ("setup", "bootstrap"):
        return json.dumps(bootstrap_binary(), indent=2)
    if sub == "version":
        binary, source = find_binary()
        return f"plugin v{RELEASE_VERSION}; binary: {binary or 'missing'} ({source})"
    return (
        "Usage: /ciphervault <status|scan|push|drill|version|setup>\n"
        "Tools: ciphervault_status, ciphervault_scan, ciphervault_run, "
        "ciphervault_push, ciphervault_recovery_drill, ciphervault_redact."
    )


def _cli_setup(parser):
    # Hermes hands us the `hermes ciphervault` subparser itself.
    sp = parser.add_subparsers(dest="ciphervault_cmd")
    sp.add_parser("bootstrap", help="Download + verify the pinned CipherVault binary (Windows)")
    sp.add_parser("status", help="Binary resolution + vault status for the cwd")
    sp.add_parser("doctor", help="Check binary, vault, and wiring")


def _cli_handler(args):
    cmd = getattr(args, "ciphervault_cmd", None) or "status"
    if cmd == "bootstrap":
        result = bootstrap_binary()
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    binary, source = find_binary()
    print(f"binary: {binary or 'missing'} ({source})")
    if cmd == "doctor":
        if not binary:
            print("next: hermes ciphervault bootstrap")
            return 1
        proc = subprocess.run([binary, "--version"], capture_output=True, text=True)
        print((proc.stdout or proc.stderr).strip())
    print(json.dumps(_run_cli_json(["status", "--json"], os.getcwd()), indent=2))
    return 0


# ---------------------------------------------------------------- register

_TOOLS = [
    ("ciphervault_status", _tool_status,
     "Show CipherVault vault status for a workspace: tracked file PATHS (never contents), snapshot head, operator count, CLI version. Keys only.",
     {"cwd": {"type": "string", "description": "Workspace directory (default: session cwd)"}}),
    ("ciphervault_scan", _tool_scan,
     "Scan workspace + staged git diffs for secret sprawl (masked: paths and violation kinds only, never values).",
     {"deep": {"type": "boolean", "default": True},
      "fix": {"type": "boolean", "default": False, "description": "Append findings to .gitignore automatically"},
      "cwd": {"type": "string"}}),
    ("ciphervault_run", _tool_run,
     "Run a command with vault secrets injected into its environment in RAM only (nothing written to disk). Output is exact-value + shape scrubbed before return. Never prints plaintext secrets.",
     {"command": {"type": "array", "items": {"type": "string"}, "description": "Command, e.g. ['npm','test']"},
      "env_file": {"type": "string"}, "project": {"type": "string"}, "env": {"type": "string"},
      "dry_run": {"type": "boolean", "default": False, "description": "List variable names without executing"},
      "cwd": {"type": "string"}}),
    ("ciphervault_push", _tool_push,
     "Create an encrypted snapshot of tracked secret files (client-side sealed; operators store ciphertext only). Local by default; local_only=false replicates to configured operators.",
     {"message": {"type": "string", "default": "Agent snapshot"},
      "local_only": {"type": "boolean", "default": True}, "cwd": {"type": "string"}}),
    ("ciphervault_recovery_drill", _tool_drill,
     "Prove a recovery kit or guardian shares actually restore: restores into a temp dir, returns a SHA-256 manifest (names+sizes+hashes only), then deletes the plaintext. Takes FILE PATHS only — never accept kit/share contents.",
     {"kit": {"type": "string", "description": "Path to kit file on disk"},
      "shares": {"type": "array", "items": {"type": "string"}, "description": "Paths to guardian share files"},
      "to": {"type": "string", "description": "Restore target dir (default: temp dir)"},
      "auto_delete": {"type": "boolean", "default": True},
      "cwd": {"type": "string"}}),
    ("ciphervault_redact", _tool_redact,
     "Redact secret material from text before using it anywhere: vault values matched exactly (inside the CLI), plus credential shapes. Returns masked text + redaction count.",
     {"text": {"type": "string"}, "cwd": {"type": "string"}}),
]

_REDACTION_PATTERNS = [
    r"cvst1\.[A-Za-z0-9._~=-]+",
    r"sk_live[\w-]{8,}",
    r"sk_test[\w-]{8,}",
    r"ghp_[\w]{20,}",
    r"AKIA[0-9A-Z]{16}",
]


def register(ctx):
    _ctx["ctx"] = ctx
    for name, handler, description, props in _TOOLS:
        required = (["command"] if name == "ciphervault_run"
                    else ["text"] if name == "ciphervault_redact" else [])
        ctx.register_tool(
            name=name,
            toolset="ciphervault",
            schema={
                "name": name,
                "description": description,
                "parameters": {"type": "object", "properties": props, "required": required},
            },
            handler=handler,
        )
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_middleware("tool_request", on_tool_request)
    for registrar, fn in (
        ("register_redaction_patterns", lambda: ctx.register_redaction_patterns(_REDACTION_PATTERNS)),
        ("register_secret_source", lambda: ctx.register_secret_source(_make_secret_source())),
        ("register_command", lambda: ctx.register_command(
            "ciphervault", _slash_ciphervault,
            description="CipherVault: status/scan/push/drill/setup for zero-knowledge secrets",
            args_hint="<status|scan|push|drill|version|setup>")),
        ("register_cli_command", lambda: ctx.register_cli_command(
            "ciphervault",
            "CipherVault zero-knowledge secrets (bootstrap/status/doctor)",
            _cli_setup, _cli_handler,
            description="Download/verify the CipherVault binary and inspect vault status from the terminal.")),
    ):
        try:
            fn()
        except Exception:
            pass
