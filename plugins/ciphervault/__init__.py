"""CipherVault Hermes plugin — zero-knowledge secrets for AI agents.

Surfaces registered (see plugin.yaml):
  tools        ciphervault_status / scan / run / push / recovery_drill / redact /
               audit / env_doctor / secret_generate / diff
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

import atexit
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

PLUGIN_DIR = Path(__file__).resolve().parent
RELEASE_VERSION = "1.0.34"
# Per-platform release assets, SHA-256 pinned in source (catalog rule
# 17: setup-time fetches must be checksum-pinned). bootstrap_binary()
# also cross-checks the release SHA256SUMS.txt against these values.
# A platform absent here has no prebuilt asset in the pinned release.
# The macOS binaries are cross-built (minimum macOS 13); arm64 carries an
# ad-hoc signature, Intel is unsigned, as in v1.0.32. Neither is notarized:
# bootstrap's urllib download is not quarantined, so Gatekeeper allows it.
RELEASE_ASSETS = {
    "windows-amd64": (
        "ciphervault.exe",
        "25aaf9851eb94737bdd53c33992e8c16af276e11d9b340a484292feeab1f7865",
    ),
    "linux-amd64": (
        "ciphervault-linux-amd64",
        "86b407373f46edc91411d35d6348f10cc47c63a500ce96c0beaa4bc479caa6ae",
    ),
    "macos-arm64": (
        "ciphervault-macos-arm64",
        "7f6a1e66d87dd3bfaaa1ef9dacd94920b9acaad3e2f4ceb2ae1331fa77489a42",
    ),
    "macos-amd64": (
        "ciphervault-macos-amd64",
        "e5109defc338a9e5120ef5dd8d3e9beb039db8ef13e89657f12252459ae1089a",
    ),
}
# Backward-compatible alias for the Windows pin.
RELEASE_BINARY_SHA256 = RELEASE_ASSETS["windows-amd64"][1]
# Whether the pinned release ships `redact --json`'s
# `exact_values_complete` attestation, which this plugin requires before
# releasing vault-scoped output. v1.0.34 does; bootstrap refuses any pin
# where this is False rather than install a CLI whose output it withholds.
RELEASE_SUPPORTS_GUARD = True
_COMPATIBLE_CLI_HINT = (
    "Build the CLI from current source (cargo build --release -p ciphervault-cli "
    "in https://github.com/samuel-1-avson/CipherVault) or install a newer release "
    "whose notes confirm exact_values_complete, then point CIPHERVAULT_BIN or the "
    "binary_path plugin setting at it and rerun `hermes ciphervault doctor`."
)
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
    found = shutil.which("ciphervault")
    if found:
        return found, "PATH"
    return None, "missing"


_PLATFORM_LABELS = {
    "windows-amd64": "Windows x64",
    "linux-amd64": "Linux x64",
    "macos-arm64": "macOS arm64",
    "macos-amd64": "macOS Intel",
}


def _release_asset():
    """(asset_name, pinned_sha256, dest_name) for this platform, or
    None when the pinned release publishes no binary for it."""
    if sys.platform == "win32":
        key, dest = "windows-amd64", "ciphervault.exe"
    elif sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64"):
        key, dest = "linux-amd64", "ciphervault"
    elif sys.platform == "darwin":
        key = "macos-arm64" if platform.machine() == "arm64" else "macos-amd64"
        dest = "ciphervault"
    else:
        return None
    pinned = RELEASE_ASSETS.get(key)
    if pinned is None:
        return None
    return pinned[0], pinned[1], dest


_DOWNLOAD_ATTEMPTS = 6
_DOWNLOAD_RETRY_DELAY = 3  # seconds, multiplied by the attempt number
_DOWNLOAD_MAX_BYTES = 256 * 1024 * 1024


def _content_range_start(resp):
    """First byte offset of a 206 response's Content-Range, or None."""
    value = (getattr(resp, "headers", None) or {}).get("Content-Range") or ""
    parts = value.split()
    if len(parts) == 2 and parts[0] == "bytes":
        start = parts[1].split("-", 1)[0]
        if start.isdigit():
            return int(start)
    return None


def _download_resumable(url, progress):
    """Fetch `url` into memory, resuming with an HTTP Range request when
    the connection drops mid-transfer (slow links to GitHub's CDN drop
    long downloads). Integrity is NOT established here: the caller checks
    the assembled bytes against the SHA-256 pinned in source, so a
    resumed or restarted transfer cannot install anything unverified."""
    data = bytearray()
    last_error = None
    for attempt in range(1, _DOWNLOAD_ATTEMPTS + 1):
        headers = {"Range": f"bytes={len(data)}-"} if data else {}
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=300) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                if data and (status != 206 or _content_range_start(resp) != len(data)):
                    data.clear()  # server ignored or misanswered Range: start over
                    if status == 206:
                        raise OSError("server answered the resume with a different byte range")
                # HTTPResponse.read(amt) returns b"" when the peer closes
                # early, even with Content-Length unmet, so count bytes.
                length = str((getattr(resp, "headers", None) or {}).get("Content-Length") or "")
                expected_end = len(data) + int(length) if length.isdigit() else None
                while True:
                    chunk = resp.read(1 << 16)
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > _DOWNLOAD_MAX_BYTES:
                        raise OSError("download exceeds the size limit")
                if expected_end is not None and len(data) < expected_end:
                    raise OSError(f"connection closed early at {len(data)} of {expected_end} bytes")
            return bytes(data)
        except Exception as exc:
            last_error = exc
            if attempt < _DOWNLOAD_ATTEMPTS:
                reason = str(exc) or type(exc).__name__
                progress(f"Download interrupted at {len(data)} bytes ({reason}); "
                         f"resuming (attempt {attempt + 1}/{_DOWNLOAD_ATTEMPTS})…")
                time.sleep(_DOWNLOAD_RETRY_DELAY * attempt)
    raise OSError(f"{str(last_error) or type(last_error).__name__} "
                  f"(gave up after {_DOWNLOAD_ATTEMPTS} attempts)")


def bootstrap_binary(progress=print):
    """Download the pinned upstream release binary and verify it
    against the release SHA256SUMS.txt before installing it into the
    plugin data dir. User-invoked setup action (CLI/slash command);
    never runs automatically at plugin load (catalog rule 3/17)."""
    if not RELEASE_SUPPORTS_GUARD:
        # Refuse before any download: installing the pinned binary would
        # shadow a working configured/PATH CLI and then withhold every
        # vault-scoped result, while reporting setup as successful.
        return {
            "success": False,
            "error": (
                f"The pinned CipherVault v{RELEASE_VERSION} release is incompatible with "
                "this plugin: it predates the complete exact-value redaction attestation. "
                "Nothing was downloaded or replaced."
            ),
            "next": _COMPATIBLE_CLI_HINT,
        }
    selected = _release_asset()
    if selected is None:
        published = ", ".join(_PLATFORM_LABELS.get(k, k) for k in RELEASE_ASSETS)
        return {
            "success": False,
            "error": (
                f"No prebuilt CipherVault v{RELEASE_VERSION} binary is published for this "
                f"platform yet (prebuilt: {published}). Build from source "
                "(cargo install --path apps/cli from "
                "https://github.com/samuel-1-avson/CipherVault) or set "
                "CIPHERVAULT_BIN / the binary_path plugin setting."
            ),
        }
    asset, pinned_sha, dest_name = selected
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
    if expected != pinned_sha:
        return {
            "success": False,
            "error": (
                f"release SHA256SUMS.txt lists {expected} for {asset}, which does not "
                f"match the checksum pinned in this plugin ({pinned_sha}). "
                "Refusing to install."
            ),
        }
    progress(f"Downloading CipherVault v{RELEASE_VERSION} ({asset})…")
    try:
        data = _download_resumable(f"{RELEASE_BASE}/{asset}", progress)
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
    dest = dest_dir / dest_name
    dest.write_bytes(data)
    if os.name != "nt":
        try:
            dest.chmod(0o755)
        except Exception:
            pass
    try:
        alias = dest_dir / ("cv.exe" if os.name == "nt" else "cv")
        alias.write_bytes(data)
        if os.name != "nt":
            alias.chmod(0o755)
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
_PEM_RE = re.compile(r"-----BEGIN [^\n]{0,64}PRIVATE KEY-----[\s\S]{0,16384}?-----END [^\n]{0,64}-----")
_KV_RE = re.compile(
    r"(?i)\b((?:[A-Za-z0-9_-]{0,64}(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_-]{0,64})\s*[=:]\s*)([^\s\"']+)"
)
_URL_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]{0,32}://[^\s:/@]{1,64}:)[^\s/@]{1,1024}(@)")


def scrub(text):
    """Local shape-based scrubbing. Last-resort layer: the CLI's
    exact-value scrubbing (`run --json` / `redact`) is primary."""
    if not text:
        return text
    # Fast path: a PEM block needs both markers; without an END
    # anywhere there is nothing to redact, and scanning a long run
    # of BEGIN headers for one is the quadratic case.
    if "-----END" in text:
        text = _PEM_RE.sub("[REDACTED] PRIVATE KEY", text)
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _URL_RE.sub(r"\1[REDACTED]\2", text)
    text = _TOKEN_RE.sub("[REDACTED]", text)
    return _KV_RE.sub(r"\1[REDACTED]", text)


# ---------------------------------------------------------------- CLI

_ENV_KEEP = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR",
             "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
             "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT")


def _minimal_env():
    """Environment for CLI subprocesses: an allow-list, so Hermes
    provider keys (OPENAI_API_KEY etc.) never reach the CLI or the
    children it spawns. CipherVault's own CIPHERVAULT_* config passes."""
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}
    env.update({k: v for k, v in os.environ.items() if k.startswith("CIPHERVAULT_")})
    env.setdefault("NO_COLOR", "1")
    return env


_AUDIT_HMAC_KEY = secrets.token_bytes(32)


def _vault_audit_hmac_key_bytes(cwd=None):
    """Return the per-vault HMAC key from `<vault_root>/.ciphervault/audit_hmac.key`
    (creating it on first use so the Rust CLI enforces HMAC even if an attacker
    omits `CIPHERVAULT_AUDIT_HMAC_KEY` from its environment). Falls back to the
    in-memory key when no vault exists."""
    try:
        root = _vault_root(cwd)
    except Exception:
        root = None
    if root is None:
        return _AUDIT_HMAC_KEY
    key_path = Path(root) / ".ciphervault" / "audit_hmac.key"
    try:
        if key_path.is_file():
            raw = key_path.read_text(encoding="utf-8", errors="replace").strip()
            if len(raw) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw):
                return bytes.fromhex(raw)
            if raw:
                return raw.encode("utf-8")
        key_hex = secrets.token_bytes(32).hex()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(key_hex + "\n", encoding="utf-8")
        if os.name != "nt":
            try:
                key_path.chmod(0o600)
            except OSError:
                pass
        return bytes.fromhex(key_hex)
    except OSError:
        return _AUDIT_HMAC_KEY


def _audit_hmac_hex(tool, decision, path, detail_str, cwd=None):
    def _san(val):
        return str(val).replace("\n", " ").replace("\r", " ")

    key_bytes = _vault_audit_hmac_key_bytes(cwd)
    msg = f"{_san(tool)}\n{_san(decision)}\n{_san(path)}\n{_san(detail_str)}".encode("utf-8")
    return hmac.new(key_bytes, msg, hashlib.sha256).hexdigest()


def _run_cli(args, cwd, timeout=120, input_text=None, extra_env=None):
    binary, source = find_binary()
    if not binary:
        return {
            "success": False,
            "error": "ciphervault binary not found",
            "binary": "missing",
            "next": _COMPATIBLE_CLI_HINT,
        }
    env = _minimal_env()
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(
            [binary] + args,
            cwd=cwd or os.getcwd(),
            # Text-mode stdin rewrites LF to CRLF on Windows (and
            # CRLF to CRCRLF). Exact scrub comparisons and receipt
            # hashes must use the caller's original UTF-8 bytes.
            input=input_text.encode("utf-8") if input_text is not None else None,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"ciphervault timed out after {timeout}s", "binary": source}
    except OSError as exc:
        return {"success": False, "error": f"could not run ciphervault: {exc}", "binary": source}
    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
    err = (proc.stderr or b"").decode("utf-8", "replace").strip()
    # Some commands print "Error: …" yet exit 0, on either stream.
    if re.search(r"(?m)^Error:", out) or re.search(r"(?m)^Error:", err):
        return {"success": False, "error": scrub(out + ("\n" + err if err else "")),
                "binary": source, "exit_code": proc.returncode}
    if proc.returncode != 0:
        return {"success": False, "error": scrub(err or out or f"exit {proc.returncode}"),
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


_ORIG_RUN_CLI = _run_cli
_ORIG_RUN_CLI_JSON = _run_cli_json
_BRIDGE_LOCK = threading.Lock()
_BRIDGE_POOL = {}
_NO_STDIO_BINARIES = set()
_MAX_BRIDGES = 8


class _StdioBridge:
    """Persistent `ciphervault redact --stdio` worker with bounded
    per-request timeout via a background stdout reader thread."""

    def __init__(self, binary, cwd):
        self.binary = binary
        self.cwd = cwd
        env = _minimal_env()
        env["CIPHERVAULT_AUDIT_HMAC_KEY"] = _vault_audit_hmac_key_bytes(cwd).hex()
        self.proc = subprocess.Popen(
            [binary, "redact", "--stdio"],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
        )
        self._lines = queue.Queue()
        self._req_lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        try:
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                self._lines.put(line)
        except Exception:
            pass
        finally:
            self._lines.put(None)

    def request(self, payload, timeout=15):
        with self._req_lock:
            if self.proc.poll() is not None or self.proc.stdin is None:
                return None
            try:
                self.proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
                self.proc.stdin.flush()
                line = self._lines.get(timeout=timeout)
            except Exception:
                return None
            if line is None:
                return None
            try:
                resp = json.loads(line)
            except Exception:
                return None
            return resp if isinstance(resp, dict) else None

    def close(self):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
                self.proc.wait(timeout=2)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def _close_all_bridges():
    with _BRIDGE_LOCK:
        for bridge in _BRIDGE_POOL.values():
            bridge.close()
        _BRIDGE_POOL.clear()


atexit.register(_close_all_bridges)


def _bridge_request(cwd, payload, timeout=15):
    """Send one JSON request over a persistent `ciphervault redact --stdio`
    pipe. Returns None when unavailable or unsupported (e.g. legacy CLI or
    unit tests that monkeypatch `_run_cli` / `_run_cli_json`), so callers fall
    back cleanly."""
    if _run_cli is not _ORIG_RUN_CLI or _run_cli_json is not _ORIG_RUN_CLI_JSON:
        return None
    binary, _src = find_binary()
    if not binary:
        return None
    resolved_cwd = str(cwd or os.getcwd())
    key = (binary, resolved_cwd)
    with _BRIDGE_LOCK:
        if binary in _NO_STDIO_BINARIES:
            return None
        bridge = _BRIDGE_POOL.get(key)
        if bridge is not None and bridge.proc.poll() is not None:
            bridge.close()
            _BRIDGE_POOL.pop(key, None)
            bridge = None
        if bridge is None:
            if len(_BRIDGE_POOL) >= _MAX_BRIDGES:
                oldest_key = next(iter(_BRIDGE_POOL))
                _BRIDGE_POOL.pop(oldest_key).close()
            try:
                bridge = _StdioBridge(binary, resolved_cwd)
            except Exception:
                return None
            _BRIDGE_POOL[key] = bridge
    resp = bridge.request(payload, timeout=timeout)
    if resp is None:
        with _BRIDGE_LOCK:
            if _BRIDGE_POOL.get(key) is bridge:
                _BRIDGE_POOL.pop(key, None)
            bridge.close()
            # Probe failed before producing valid JSON (e.g. older CLI without --stdio).
            if payload.get("op") != "ping":
                _NO_STDIO_BINARIES.add(binary)
    return resp


_CLI_CAPABILITIES = (
    (("status",), ("--json",)),
    (("hook", "check"), ("--json", "--deep", "--fix")),
    (("run",), ("--json", "--dry-run", "--env-file", "--project", "--env")),
    (("push",), ("--local",)),
    (("recover",), ("--to", "--kit", "--shares")),
    (("redact",), ("--json",)),
    (("export-env",), ("--env-file", "--allow-working-copy")),
    (("agent-log", "record"), ("--tool", "--decision", "--path", "--detail")),
    (("agent-log", "show"), ("--json", "--limit")),
    (("agent-log", "verify"), ("--json",)),
    (("agent-log", "check"), ("--json", "--output-sha256")),
    (("agent-log", "anchor"), ()),
)


def binary_diagnostics(cwd=None):
    """Read-only version/help probes of the binary actually resolved.

    A working `status --json` alone is insufficient: older CLIs lack
    the exact scrub, JSON run, and signed-audit commands. Version drift
    is reported separately; capabilities, not a version guess, gate
    compatibility. This never bootstraps or changes the active binary.
    """
    binary, source = find_binary()
    out = {"success": False, "binary": binary, "binary_source": source,
           "target_cli_version": RELEASE_VERSION, "installed_version": None,
           "version_matches_target": False, "capabilities": {},
           "missing_capabilities": []}
    remediation = (
        _COMPATIBLE_CLI_HINT
        + " Vault outputs remain withheld until exact scrubbing and audit receipts work."
    )
    if not binary:
        out.update(error="ciphervault binary not found", next=remediation)
        return out
    version = _run_cli(["--version"], cwd, timeout=10)
    if version.get("success"):
        match = re.search(r"(?m)^ciphervault(?:\.exe)?\s+(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)\s*$",
                          version.get("output", ""))
        if match:
            out["installed_version"] = match.group(1)
    out["version_matches_target"] = out["installed_version"] == RELEASE_VERSION
    for command, flags in _CLI_CAPABILITIES:
        name = " ".join(command)
        probe = _run_cli([*command, "--help"], cwd, timeout=10)
        help_text = probe.get("output", "")
        missing = [flag for flag in flags if not re.search(
            r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])", help_text)]
        supported = bool(probe.get("success") and not missing)
        capability = {"supported": supported, "missing_flags": missing}
        if not probe.get("success"):
            capability["error"] = probe.get("error", "help probe failed")
        out["capabilities"][name] = capability
        if not supported:
            out["missing_capabilities"].append(name)
    # Flags alone cannot tell a CLI that attests complete exact-value
    # loading from one that silently skips unreadable tracked files.
    # Probe in an empty directory so workspace state cannot mask it.
    complete = False
    if out["capabilities"].get("redact", {}).get("supported"):
        with tempfile.TemporaryDirectory(prefix="cv-doctor-") as empty:
            probe = _run_cli_json(["redact", "--json"], empty, timeout=10,
                                  input_text="cv doctor probe")
        complete = bool(probe.get("success")
                        and _complete_redact_response(probe.get("data")))
    out["capabilities"]["redact completeness"] = {"supported": complete,
                                                  "missing_flags": []}
    if not complete:
        out["missing_capabilities"].append("redact completeness")
    out["success"] = bool(out["installed_version"] and not out["missing_capabilities"])
    if not out["version_matches_target"]:
        out["warning"] = (
            f"Resolved CLI version {out['installed_version'] or 'unknown'} differs "
            f"from the plugin's pinned CLI target {RELEASE_VERSION}."
        )
    if not out["success"]:
        out.update(error="resolved CipherVault CLI is incompatible or could not be inspected",
                   next=remediation)
    return out


def _audit(tool, decision, path="", detail=None, cwd=None):
    """Append one entry to the vault's tamper-evident agent audit
    chain via the CLI. Records paths/decisions/counts only, never
    contents. Returns True when the entry landed: callers whose
    correctness depends on the receipt (scrub proofs) must fail
    closed on False instead of letting absence go ambiguous."""
    try:
        vault_cwd = _vault_cwd(cwd)
        detail_str = json.dumps(detail)[:500] if detail else "{}"
        path_str = str(path)[:300]
        hmac_tag = _audit_hmac_hex(str(tool), str(decision), path_str, detail_str, cwd=vault_cwd)
        resp = _bridge_request(
            vault_cwd,
            {
                "op": "audit",
                "tool": str(tool),
                "decision": str(decision),
                "path": path_str,
                "detail": detail_str,
                "hmac": hmac_tag,
            },
            timeout=5,
        )
        if resp and resp.get("ok"):
            return True
        args = ["agent-log", "record", "--tool", str(tool), "--decision", str(decision)]
        if path:
            args += ["--path", path_str]
        if detail:
            args += ["--detail", detail_str]
        if _run_cli is _ORIG_RUN_CLI:
            args += ["--hmac", hmac_tag]
            res = _run_cli(
                args,
                vault_cwd,
                timeout=10,
                extra_env={"CIPHERVAULT_AUDIT_HMAC_KEY": _vault_audit_hmac_key_bytes(vault_cwd).hex()},
            )
        else:
            res = _run_cli(args, vault_cwd, timeout=10)
        return bool(res and res.get("success"))
    except Exception:
        return False


def _anchor_async(cwd=None):
    """Fire-and-forget fleet anchor of the audit head. Runs detached
    so a slow/unreachable fleet can never delay or break the guarded
    call; failures are silent (the next push re-anchors)."""
    try:
        binary, _src = find_binary()
        if not binary:
            return
        kwargs = {
            "cwd": _vault_cwd(cwd) or os.getcwd(),
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            kwargs["creationflags"] = (
                getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            )
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen([binary, "agent-log", "anchor"], **kwargs)
    except Exception:
        pass


def _complete_redact_response(data, require_vault=False):
    """A well-shaped response is not proof that all tracked files loaded."""
    return (isinstance(data, dict) and isinstance(data.get("text"), str)
            and type(data.get("redactions")) is int and data["redactions"] >= 0
            and type(data.get("exact_values_loaded")) is int and data["exact_values_loaded"] >= 0
            and data.get("exact_values_complete") is True
            and type(data.get("vault")) is bool
            and (not require_vault or data["vault"] is True))


def cli_redact(text, cwd, timeout=15):
    """Exact+shape redaction via the CLI (vault values are matched
    inside the CLI process; they never enter this process). Returns
    (text, redactions, exact_ok): exact_ok False means the CLI could
    not prove complete loading and only local shape scrubbing ran — callers that
    would hand text to the model must fail closed on that, because a
    shape-blind vault value (database URL, internal token) would
    pass through unlogged."""
    if not text:
        return text, 0, True
    vault_cwd = _vault_cwd(cwd)
    require_vault = _vault_present(cwd)
    resp = _bridge_request(vault_cwd, {"op": "redact", "text": text}, timeout=timeout)
    if resp and resp.get("ok") and _complete_redact_response(resp, require_vault=require_vault):
        return resp["text"], resp["redactions"], True
    res = _run_cli_json(["redact", "--json"], vault_cwd, timeout=timeout,
                        input_text=text)
    if res.get("success"):
        data = res.get("data")
        if _complete_redact_response(data, require_vault=require_vault):
            return data["text"], data["redactions"], True
    return scrub(text), 0, False


_ORIG_CLI_REDACT = cli_redact


def _call_cli_redact(text, cwd, timeout=15):
    """Call exact+shape redaction via `cli_redact` (preserving 3-tuple return)."""
    if not text:
        return text, 0, True
    return cli_redact(text, cwd, timeout=timeout)


# ---------------------------------------------------------------- tools

def _attach_posture(payload: dict, cwd):
    """Attach `workspace_posture` directly to tool result JSON so the model
    reliably receives the workspace posture even if middleware `reason` is not
    shown to the model."""
    if not isinstance(payload, dict):
        return payload
    try:
        if _vault_root(cwd) is not None:
            payload = dict(payload)
            payload["workspace_posture"] = _workspace_posture_summary(cwd)
    except Exception:
        pass
    return payload


def _tool_status(params, **kwargs):
    cwd = (params or {}).get("cwd")
    res = _run_cli_json(["status", "--json"], cwd)
    return json.dumps(_attach_posture(res, cwd))


def _tool_scan(params, **kwargs):
    params = params or {}
    args = ["hook", "check", "--json"]
    if params.get("deep", True):
        args.append("--deep")
    if params.get("fix"):
        args.append("--fix")
    return json.dumps(_run_cli_json(args, params.get("cwd")))


_KNOWN_PROVIDER_KEYS = frozenset({
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "STRIPE_API_KEY",
    "STRIPE_SECRET_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENROUTER_API_KEY",
    "HF_TOKEN",
    "HUGGINGFACE_TOKEN",
})


def _clean_proxy_upstreams(params):
    """Normalize proxy_upstream into non-empty stripped strings so blanks like
    [''] or ['  '] never act truthy for --no-net or approval UI display."""
    if not isinstance(params, dict):
        return []
    raw = params.get("proxy_upstream")
    if not raw:
        return []
    items = [raw] if isinstance(raw, str) else raw
    return [str(s).strip() for s in items if str(s).strip()]


def _strip_toml_comment(line):
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:idx]
    return line


def _parse_toml_scalar(raw):
    s = raw.strip()
    if s == "true":
        return True
    if s == "false":
        return False
    if re.fullmatch(r"[+-]?\d+", s):
        return int(s)
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        if s.startswith('"'):
            return bytes(s[1:-1], "utf-8").decode("unicode_escape")
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        items = []
        buf = []
        in_s = in_d = esc = False
        for ch in inner:
            if esc:
                buf.append(ch)
                esc = False
                continue
            if ch == "\\" and in_d:
                buf.append(ch)
                esc = True
                continue
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif ch == "," and not in_s and not in_d:
                part = "".join(buf).strip()
                if part:
                    items.append(_parse_toml_scalar(part))
                buf = []
                continue
            buf.append(ch)
        tail = "".join(buf).strip()
        if tail:
            items.append(_parse_toml_scalar(tail))
        return items
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        tbl = {}
        if not inner:
            return tbl
        pairs = []
        buf = []
        in_s = in_d = esc = False
        for ch in inner:
            if esc:
                buf.append(ch)
                esc = False
                continue
            if ch == "\\" and in_d:
                buf.append(ch)
                esc = True
                continue
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif ch == "," and not in_s and not in_d:
                part = "".join(buf).strip()
                if part:
                    pairs.append(part)
                buf = []
                continue
            buf.append(ch)
        tail = "".join(buf).strip()
        if tail:
            pairs.append(tail)
        for pair in pairs:
            if "=" not in pair:
                raise ValueError(f"invalid inline table entry: {pair!r}")
            k, v = pair.split("=", 1)
            tbl[k.strip().strip('"').strip("'")] = _parse_toml_scalar(v)
        return tbl
    raise ValueError(f"unsupported TOML value: {s!r}")


def _parse_toml_fallback(text):
    """Minimal TOML subset parser used only when stdlib tomllib/tomli is absent."""
    root = {}
    current = root
    lines = text.splitlines()
    idx = 0
    while idx < len(lines):
        cleaned = _strip_toml_comment(lines[idx]).strip()
        idx += 1
        if not cleaned:
            continue
        if cleaned.startswith("[") and cleaned.endswith("]"):
            header = cleaned[1:-1].strip()
            parts = [p.strip().strip('"').strip("'") for p in header.split(".")]
            target = root
            for part in parts:
                if not part:
                    raise ValueError(f"invalid TOML header {cleaned!r}")
                target = target.setdefault(part, {})
                if not isinstance(target, dict):
                    raise ValueError(f"conflicting TOML section {cleaned!r}")
            current = target
            continue
        if "=" not in cleaned:
            raise ValueError(f"expected key = value in policy.toml: {cleaned!r}")
        k, v = cleaned.split("=", 1)
        key = k.strip().strip('"').strip("'")
        val_raw = v.strip()
        while (val_raw.startswith("[") and not val_raw.endswith("]")) or (
            val_raw.startswith("{") and not val_raw.endswith("}")
        ):
            if idx >= len(lines):
                raise ValueError(f"unterminated TOML value for {key!r}")
            val_raw += " " + _strip_toml_comment(lines[idx]).strip()
            idx += 1
        current[key] = _parse_toml_scalar(val_raw)
    return root


def _policy_file_path(cwd):
    try:
        root = _vault_root(cwd)
    except Exception:
        root = None
    candidates = []
    if root is not None:
        candidates.append(Path(root) / ".ciphervault" / "policy.toml")
    if cwd:
        p = Path(cwd)
        if root is None or not _same_dir(p, root):
            candidates.append(p / ".ciphervault" / "policy.toml")
    for cand in candidates:
        try:
            if cand.is_file():
                return cand
        except OSError:
            continue
    return None


def _load_policy_toml(cwd):
    """Load `.ciphervault/policy.toml` if present. Returns (dict, error_or_None)."""
    path = _policy_file_path(cwd)
    if path is None:
        return {}, None
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return None, f"could not read .ciphervault/policy.toml: {exc}"
    try:
        if tomllib is not None:
            parsed = tomllib.loads(raw_bytes.decode("utf-8"))
        else:
            parsed = _parse_toml_fallback(raw_bytes.decode("utf-8"))
    except Exception as exc:
        return None, f"invalid .ciphervault/policy.toml: {exc}"
    if not isinstance(parsed, dict):
        return None, "invalid .ciphervault/policy.toml: root must be a table"
    return parsed, None


def _split_proxy_upstream_spec(spec):
    """Parse `VAR=https://host[:port][/path][@Header]` into (var_name, clean_url, scheme, parsed_url)."""
    if not isinstance(spec, str) or "=" not in spec:
        return None, "invalid proxy_upstream: expected VAR=https://host[@HeaderName]"
    var_name, rhs = spec.split("=", 1)
    var_name = var_name.strip()
    rhs = rhs.strip()
    if not var_name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", var_name):
        return None, f"invalid proxy_upstream variable name {var_name!r}"
    url_part = rhs
    if "@" in rhs:
        u, hdr = rhs.rsplit("@", 1)
        if "://" in u and hdr.strip() and "/" not in hdr:
            url_part = u.strip()
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c.isspace() for c in url_part) or "\\" in url_part:
        return None, f"invalid proxy_upstream URL {url_part!r}"
    try:
        parts = urllib.parse.urlsplit(url_part)
        port = parts.port
    except ValueError:
        return None, f"malformed proxy_upstream URL {url_part!r}"
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if (scheme not in ("http", "https") or not parts.netloc or not host
            or "@" in parts.netloc or "%" in parts.netloc or parts.query or parts.fragment):
        return None, f"invalid proxy_upstream URL {url_part!r}"
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None, f"invalid proxy_upstream hostname {host!r}"
    host_literal = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    netloc = f"{host_literal}:{port}" if port is not None else host_literal
    clean_url = f"{scheme}://{netloc}{parts.path.rstrip('/')}"
    return (var_name, clean_url, scheme, ascii_host, parts.port), None


def _policy_configured_upstreams(policy, profile_name=None):
    """Collect trusted `(VAR, clean_url)` pairs authored in `.ciphervault/policy.toml`."""
    allowed = set()

    def _add_table(raw_upstreams):
        if isinstance(raw_upstreams, dict):
            items = [f"{k}={v}" for k, v in raw_upstreams.items()]
        elif isinstance(raw_upstreams, (list, tuple)):
            items = [str(x).strip() for x in raw_upstreams if str(x).strip()]
        else:
            items = []
        for spec in items:
            parsed, err = _split_proxy_upstream_spec(spec)
            if not err and parsed:
                allowed.add((parsed[0], parsed[1]))

    _add_table(policy.get("upstreams"))
    vault_sec = policy.get("vault")
    if isinstance(vault_sec, dict):
        _add_table(vault_sec.get("upstreams"))
    profiles = policy.get("profiles")
    if isinstance(profiles, dict):
        if profile_name:
            prof = profiles.get(profile_name)
            if isinstance(prof, dict):
                _add_table(prof.get("upstreams"))
        else:
            for prof in profiles.values():
                if isinstance(prof, dict):
                    _add_table(prof.get("upstreams"))
    return allowed


def _is_unsafe_upstream_host(host, port):
    """Return True if host is loopback, private, link-local, metadata, or internal."""
    if (not host or host in _BLOCKED_OPERATOR_HOSTS
            or host.endswith((".localhost", ".local", ".internal"))):
        return True
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port or 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError:
            return False
        ips = []
        for _fam, _type, _proto, _canon, sockaddr in infos:
            try:
                ips.append(ipaddress.ip_address(str(sockaddr[0]).split("%")[0]))
            except ValueError:
                return True
    for raw_ip in ips:
        ip = _embedded_ipv4(raw_ip)
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified
                or ip in _CGNAT_NET or not ip.is_global):
            return True
    return False


def _validate_proxy_upstreams(specs, configured_upstreams):
    """Validate proxy_upstream entries against SSRF and known-provider hijacking."""
    for spec in specs:
        parsed, err = _split_proxy_upstream_spec(spec)
        if err:
            return err
        var_name, clean_url, scheme, host, port = parsed
        if (var_name, clean_url) in configured_upstreams:
            continue
        if var_name.upper() in _KNOWN_PROVIDER_KEYS:
            return (
                f"refusing proxy_upstream override for known provider {var_name!r}: "
                "configure custom provider upstreams in .ciphervault/policy.toml"
            )
        if scheme != "https":
            return f"refusing non-HTTPS proxy_upstream {clean_url!r}"
        if _is_unsafe_upstream_host(host, port):
            return (
                f"refusing proxy_upstream {clean_url!r}: loopback, private, link-local, "
                "or internal hosts are not allowed unless configured in .ciphervault/policy.toml"
            )
    return None


def _resolve_run_policy(params, cwd):
    """Merge `.ciphervault/policy.toml` profile defaults into `ciphervault_run` params
    and validate proxy_upstream entries. Returns (effective_params, error_or_None)."""
    raw = dict(params) if isinstance(params, dict) else {}
    policy, err = _load_policy_toml(cwd)
    if err:
        return None, err
    profile_name = str(raw.get("profile") or "").strip() or None
    configured_upstreams = _policy_configured_upstreams(policy, profile_name)
    caller_upstreams = _clean_proxy_upstreams(raw)

    if profile_name:
        profiles = policy.get("profiles") or {}
        prof = profiles.get(profile_name) if isinstance(profiles, dict) else None
        if not isinstance(prof, dict):
            return None, f"unknown policy profile {profile_name!r} in .ciphervault/policy.toml"

        allowed_cmds = prof.get("commands")
        cmd = raw.get("command") or []
        if isinstance(allowed_cmds, list) and allowed_cmds and cmd:
            prog_raw = str(cmd[0]).strip()
            prog_name = Path(prog_raw).name
            cmd_line = " ".join(str(x) for x in cmd)
            if not any(
                prog_raw == c or prog_name == c or cmd_line == c or cmd_line.startswith(c + " ")
                for c in (str(x).strip() for x in allowed_cmds if str(x).strip())
            ):
                return None, f"command {prog_raw!r} is not permitted by profile {profile_name!r}"

        if prof.get("allow_keys") is not None:
            prof_keys = [str(k).strip() for k in prof["allow_keys"] if str(k).strip()]
            if not prof_keys:
                return None, f"profile {profile_name!r} has empty allow_keys"
            if raw.get("allow_keys") is None:
                raw["allow_keys"] = prof_keys
            else:
                req_keys = [str(k).strip() for k in raw["allow_keys"] if str(k).strip()]
                if not req_keys or any(k not in prof_keys for k in req_keys):
                    return None, f"allow_keys exceeds profile {profile_name!r} allowlist"
                raw["allow_keys"] = req_keys

        if "no_net" in prof and prof["no_net"] is not None:
            prof_no_net = bool(prof["no_net"])
            if raw.get("no_net") is None:
                raw["no_net"] = prof_no_net
            elif prof_no_net and raw.get("no_net") is False:
                return None, f"profile {profile_name!r} enforces no_net=true"

        if "proxy" in prof and prof["proxy"] is not None:
            prof_proxy = bool(prof["proxy"])
            if raw.get("proxy") is None:
                raw["proxy"] = prof_proxy
            elif prof_proxy and raw.get("proxy") is False:
                return None, f"profile {profile_name!r} requires proxy=true"

        prof_upstreams = prof.get("upstreams")
        prof_specs = []
        if isinstance(prof_upstreams, dict):
            prof_specs = [f"{k}={v}" for k, v in prof_upstreams.items()]
        elif isinstance(prof_upstreams, (list, tuple)):
            prof_specs = [str(x).strip() for x in prof_upstreams if str(x).strip()]
        if prof_specs:
            combined = []
            for item in prof_specs + caller_upstreams:
                if item not in combined:
                    combined.append(item)
            raw["proxy_upstream"] = combined
            caller_upstreams = _clean_proxy_upstreams(raw)

        if raw.get("no_net") is True and (raw.get("proxy") or caller_upstreams):
            return None, f"profile {profile_name!r} combines incompatible no_net=true and proxy"
    else:
        vault_sec = policy.get("vault")
        if (isinstance(vault_sec, dict) and "default_no_net" in vault_sec
                and raw.get("no_net") is None and not raw.get("proxy") and not caller_upstreams):
            raw["no_net"] = bool(vault_sec["default_no_net"])

    upstream_err = _validate_proxy_upstreams(caller_upstreams, configured_upstreams)
    if upstream_err:
        return None, upstream_err
    return raw, None


def _effective_no_net(params):
    """Default to network isolation on Linux, macOS, and Windows where kernel
    `--no-net` is supported unprivileged. When `proxy` is enabled, loopback access
    is required so `no_net` defaults False unless explicitly set."""
    if isinstance(params, dict) and params.get("no_net") is not None:
        return bool(params["no_net"])
    if isinstance(params, dict) and (params.get("proxy") or _clean_proxy_upstreams(params)):
        return False
    return sys.platform.startswith("linux") or sys.platform in ("darwin", "win32")


_CLI_PROFILE_SUPPORT: dict[str, bool] = {}


def _cli_supports_run_profile() -> bool:
    """Return True if the active ciphervault binary accepts `run --profile`
    (or if no binary is resolved yet, so mocked unit tests see `--profile`)."""
    binary, _source = find_binary()
    if not binary:
        return True
    cached = _CLI_PROFILE_SUPPORT.get(binary)
    if cached is not None:
        return cached
    try:
        proc = subprocess.run(
            [binary, "run", "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            env=_minimal_env(),
        )
        supported = "--profile" in ((proc.stdout or "") + (proc.stderr or ""))
    except Exception:
        supported = False
    _CLI_PROFILE_SUPPORT[binary] = supported
    return supported


def _tool_run(params, **kwargs):
    params = params or {}
    cmd = params.get("command") or []
    if not cmd:
        return json.dumps({"success": False, "error": "command is required, e.g. ['npm','test']"})
    effective, policy_err = _resolve_run_policy(params, params.get("cwd"))
    if policy_err:
        return json.dumps({"success": False, "error": policy_err})
    args = ["run", "--json"]
    if effective.get("dry_run"):
        args.append("--dry-run")
    profile_name = str(effective.get("profile") or "").strip()
    if profile_name and _cli_supports_run_profile():
        args += ["--profile", profile_name]
    if effective.get("env_file"):
        args += ["--env-file", effective["env_file"]]
    if effective.get("project"):
        args += ["--project", effective["project"]]
    if effective.get("env"):
        args += ["--env", effective["env"]]
    allow_keys = effective.get("allow_keys")
    if allow_keys is not None:
        keys = [str(k).strip() for k in allow_keys if str(k).strip()]
        if not keys:
            return json.dumps({"success": False, "error": "allow_keys cannot be empty when provided"})
        args += ["--allow-keys", ",".join(keys)]
    if effective.get("proxy"):
        args.append("--proxy")
    for spec in _clean_proxy_upstreams(effective):
        args += ["--proxy-upstream", spec]
    if _effective_no_net(effective):
        args.append("--no-net")
    args.append("--")
    args += list(cmd)
    res = _run_cli_json(args, effective.get("cwd"), timeout=300)
    if effective.get("dry_run"):
        return json.dumps(res)
    res = _structured_run_failure(res)
    data = res.get("data")
    if not (isinstance(data, dict)
            and any(isinstance(data.get(k), str) for k in ("stdout", "stderr"))):
        # Nothing ran (no vault, bad flags, missing CLI): no output to receipt.
        return json.dumps(res)
    # ciphervault_* results skip transform_tool_result, so the run output
    # gets its receipt here: the exact string handed to the model, plus
    # the stdout a person reads (see ciphervault_audit check_text).
    raw = json.dumps(res)
    detail = {"program": str(cmd[0])[:64],
              "exit_code": data.get("exit_code"),
              "redactions": data.get("redactions"),
              "output_sha256": hashlib.sha256(raw.encode()).hexdigest(),
              "content_sha256": _content_sha256(data.get("stdout") or ""),
              "output_bytes": len(raw)}
    if effective.get("profile"):
        detail["profile"] = str(effective["profile"])[:64]
    if _audit("ciphervault_run", "scrubbed_result", detail=detail, cwd=effective.get("cwd")):
        return raw
    withheld = ("[CipherVault] run output withheld: the audit-log write failed, so "
                "there is no receipt for it. Exit code and counts are kept.")
    return json.dumps(dict(res, data=dict(data, stdout=withheld, stderr=""),
                           audit_receipt=False))


def _structured_run_failure(res):
    """`run --json` exits with the child's status after printing its
    report, which _run_cli turns into an error string. Keep a failing
    command's report structured (stdout/stderr/exit_code) instead."""
    if res.get("success") or "data" in res or not isinstance(res.get("error"), str):
        return res
    try:
        payload = json.loads(res["error"])
    except Exception:
        return res
    if isinstance(payload, dict) and "exit_code" in payload and "stdout" in payload:
        return {"success": False, "data": payload, "exit_code": res.get("exit_code"),
                "binary": res.get("binary")}
    return res


def _content_sha256(text):
    """Hash of the text a person reads, ignoring surrounding whitespace
    (terminals and copy/paste rarely keep the trailing newline)."""
    return hashlib.sha256(text.strip().encode()).hexdigest()


def _visible_text(result):
    """The part of a tool result a person actually reads: Hermes wraps
    terminal and file results in a JSON envelope (`output`, `content`)."""
    if result[:1] != "{":
        return result
    try:
        data = json.loads(result)
    except Exception:
        return result
    if isinstance(data, dict):
        for key in ("output", "content", "stdout"):
            if isinstance(data.get(key), str):
                return data[key]
    return result


def _tool_push(params, **kwargs):
    params = params or {}
    cwd = params.get("cwd")
    shred = params.get("shred_working_copy")
    if shred is None:
        policy, err = _load_policy_toml(cwd)
        if err:
            return json.dumps({"success": False, "error": err})
        shred = bool((policy.get("vault") or {}).get("sealed_mode", False))
    args = ["push", "-m", params.get("message", "Agent snapshot")]
    if params.get("local_only", True):
        args.append("--local")
    if shred:
        args.append("--shred")
    res = _run_cli(args, cwd, timeout=300)
    if res.get("success"):
        res["output"] = scrub(res["output"])
    return json.dumps(res)


_DOCTOR_SKIP_DIRS = frozenset({
    ".git", "node_modules", "target", ".venv", "venv", "__pycache__",
    "dist", "build", ".next", ".ciphervault", ".pytest_cache",
    ".mypy_cache", ".ruff_cache",
})
_DOCTOR_CODE_EXTS = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".go", ".yml", ".yaml",
})
_DOCTOR_MAX_FILES = 5000
_DOCTOR_MAX_FILE_BYTES = 1_048_576
_ENV_REF_PATTERNS = (
    re.compile(r"\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)\b"),
    re.compile(r"""\bprocess\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
    re.compile(r"\bimport\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)\b"),
    re.compile(r"""\bimport\.meta\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
    re.compile(r"""\bos\.(?:environ\.get|getenv)\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""\bos\.environ\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
    re.compile(r"""\b(?:std::)?env::(?:var|var_os)\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""\bos\.(?:Getenv|LookupEnv)\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"\$\{([A-Z][A-Z0-9_]{1,})(?:[:?-][^}]*)?\}"),
)
_DOCKERFILE_ENV_RE = re.compile(r"(?m)^\s*(?:ENV|ARG)\s+([A-Z][A-Z0-9_]{1,})(?:=|\s|$)")
_PLACEHOLDER_VAL_RE = re.compile(
    r"(?i)(?:^(?:changeme|todo|fixme|placeholder|replace[-_]?me|"
    r"your[-_].*[-_]?here|x{3,}|<[^>]+>|\*{3,}|demo[-_]?only)$|"
    r"your[-_]?(?:api[-_]?key|secret|token|password)|^sk-x{3,}$)"
)
_KNOWN_KEY_PREFIXES = {
    "ANTHROPIC_API_KEY": ("sk-ant-",),
    "OPENAI_API_KEY": ("sk-",),
    "STRIPE_SECRET_KEY": ("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
    "STRIPE_PUBLISHABLE_KEY": ("pk_live_", "pk_test_"),
    "GITHUB_TOKEN": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    "HF_TOKEN": ("hf_",),
    "HUGGINGFACE_TOKEN": ("hf_",),
    "OPENROUTER_API_KEY": ("sk-or-",),
}


def _scan_env_references(root_path):
    """Scan workspace code files for referenced environment variable names."""
    refs = set()
    files_seen = 0
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = sorted(d for d in dirnames if d not in _DOCTOR_SKIP_DIRS)
        for fname in sorted(filenames):
            if files_seen >= _DOCTOR_MAX_FILES:
                return refs
            fpath = Path(dirpath) / fname
            is_docker = fname == "Dockerfile" or fname.startswith("Dockerfile.")
            if not is_docker and fpath.suffix.lower() not in _DOCTOR_CODE_EXTS:
                continue
            try:
                if fpath.stat().st_size > _DOCTOR_MAX_FILE_BYTES:
                    continue
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_seen += 1
            for pat in _ENV_REF_PATTERNS:
                refs.update(pat.findall(content))
            if is_docker:
                refs.update(_DOCKERFILE_ENV_RE.findall(content))
    return refs


def _parse_example_keys(example_path):
    keys = set()
    if not example_path.is_file():
        return keys
    try:
        text = example_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return keys
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            keys.add(key)
    return keys


def _strip_inline_comment(val):
    for marker in (" #", "\t#"):
        pos = val.find(marker)
        if pos != -1:
            return val[:pos]
    return val


def _lint_dotenv_line(key, raw_rhs):
    """Return (parsed_value, list_of_issue_codes) computed strictly in RAM.
    Never returns or formats secret material."""
    issues = []
    raw_no_nl = raw_rhs.rstrip("\n")
    had_cr = raw_no_nl.endswith("\r")
    if had_cr:
        raw_no_nl = raw_no_nl[:-1]
    stripped = raw_no_nl.strip()

    if stripped.startswith('"') and stripped.endswith('"') and len(stripped) >= 2:
        inner = stripped[1:-1]
        if inner != inner.strip() or had_cr:
            issues.append("WHITESPACE_WRAPPED")
        val = inner
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            issues.append("UNSTRIPPED_QUOTES")
    elif stripped.startswith("'") and stripped.endswith("'") and len(stripped) >= 2:
        inner = stripped[1:-1]
        if inner != inner.strip() or had_cr:
            issues.append("WHITESPACE_WRAPPED")
        val = inner
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            issues.append("UNSTRIPPED_QUOTES")
    else:
        before_comment = _strip_inline_comment(raw_no_nl)
        if before_comment.startswith("#"):
            before_comment = ""
        if before_comment and before_comment != before_comment.strip(" \t"):
            issues.append("WHITESPACE_WRAPPED")
        elif had_cr and before_comment:
            issues.append("WHITESPACE_WRAPPED")
        val = before_comment.strip()
        if ((val.startswith('"') and not val.endswith('"'))
                or (val.endswith('"') and not val.startswith('"'))
                or (val.startswith("'") and not val.endswith("'"))
                or (val.endswith("'") and not val.startswith("'"))
                or val in ('"', "'")):
            issues.append("UNSTRIPPED_QUOTES")

    if not val.strip():
        issues.append("EMPTY_VALUE")
        return val, issues

    is_placeholder = bool(_PLACEHOLDER_VAL_RE.search(val.strip()))
    if is_placeholder:
        issues.append("PLACEHOLDER_VALUE")
        return val, issues

    if re.search(r"(?:_URL|_URI|_ENDPOINT|_DSN)$", key):
        try:
            parsed_url = urllib.parse.urlsplit(val.strip())
            scheme_ok = bool(parsed_url.scheme and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed_url.scheme))
            loc_ok = bool(parsed_url.netloc) or (
                parsed_url.scheme.lower() in ("sqlite", "file") and bool(parsed_url.path)
            )
            if not scheme_ok or not loc_ok or any(c.isspace() for c in val.strip()):
                issues.append("INVALID_URL")
        except Exception:
            issues.append("INVALID_URL")

    if key.endswith("_JSON"):
        try:
            json.loads(val)
        except Exception:
            issues.append("INVALID_JSON")

    expected_prefixes = _KNOWN_KEY_PREFIXES.get(key)
    if expected_prefixes and not any(val.startswith(pfx) for pfx in expected_prefixes):
        issues.append("PREFIX_MISMATCH")

    return val, issues


def _inspect_dotenv_file_in_memory(env_path):
    """Parse one .env file in RAM and return (keys_set, anomaly_list).
    Values never leave this function."""
    keys = set()
    anomalies = []
    seen_anomalies = set()
    try:
        text = env_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return keys, anomalies
    for raw_line in text.splitlines(keepends=True):
        stripped = raw_line.lstrip("\ufeff").strip()
        if not stripped or stripped.startswith("#"):
            continue
        body = raw_line.lstrip("\ufeff").lstrip()
        if body.startswith("export "):
            body = body[7:].lstrip()
        if "=" not in body:
            continue
        raw_key, raw_rhs = body.split("=", 1)
        key = raw_key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        keys.add(key)
        _val, issues = _lint_dotenv_line(key, raw_rhs)
        for issue in issues:
            pair = (key, issue)
            if pair not in seen_anomalies:
                seen_anomalies.add(pair)
                anomalies.append({"key": key, "issue": issue})
    return keys, anomalies


_ENV_DOCTOR_SUPPORT_CACHE = {}


def _cli_supports_env_doctor(cwd=None):
    """True when the resolved native CLI binary supports `ciphervault env-doctor --json`."""
    if _run_cli is not _ORIG_RUN_CLI or _run_cli_json is not _ORIG_RUN_CLI_JSON:
        return False
    binary, _src = find_binary()
    if not binary:
        return False
    cached = _ENV_DOCTOR_SUPPORT_CACHE.get(binary)
    if cached is not None:
        return cached
    probe = _ORIG_RUN_CLI(["env-doctor", "--help"], cwd, timeout=10)
    ok = bool(probe.get("success") and "--sync-env-example" in (probe.get("output") or ""))
    _ENV_DOCTOR_SUPPORT_CACHE[binary] = ok
    return ok


def _tool_env_doctor(params, **kwargs):
    params = params or {}
    cwd = params.get("cwd") or os.getcwd()
    root_path = Path(cwd)
    if not root_path.is_dir():
        return json.dumps({"success": False, "error": f"workspace directory does not exist: {cwd}"})
    resolved_root = root_path.resolve()
    vault_cwd = _vault_cwd(cwd)

    if _cli_supports_env_doctor(vault_cwd):
        cli_args = ["env-doctor", "--json"]
        if params.get("env_file"):
            rel = str(params["env_file"]).strip()
            cand = (resolved_root / rel).resolve()
            if not cand.is_relative_to(resolved_root):
                return json.dumps({"success": False, "error": "env_file must stay inside workspace cwd"})
            cli_args += ["--env-file", rel]
        if params.get("sync_env_example"):
            cli_args.append("--sync-env-example")
        res = _run_cli_json(cli_args, str(resolved_root), timeout=30)
        if res.get("success") and isinstance(res.get("data"), dict):
            return json.dumps(_attach_posture(res["data"], cwd))

    tracked_paths = []
    sealed = False
    status_res = _run_cli_json(["status", "--json"], vault_cwd, timeout=20)
    if status_res.get("success") and isinstance(status_res.get("data"), dict):
        sdata = status_res["data"]
        if sdata.get("vault"):
            tracked_paths = list(sdata.get("tracked_paths") or [])
            sealed = bool(sdata.get("working_tree_sealed"))

    candidate_files = []
    if params.get("env_file"):
        rel = str(params["env_file"]).strip()
        cand = (resolved_root / rel).resolve()
        if not cand.is_relative_to(resolved_root):
            return json.dumps({"success": False, "error": "env_file must stay inside workspace cwd"})
        candidate_files = [cand]
    elif tracked_paths:
        for rel in tracked_paths:
            name = Path(rel).name
            if (name == ".env" or name.startswith(".env.")) and not name.endswith(
                (".example", ".sample", ".template")
            ):
                cand = (resolved_root / rel).resolve()
                if cand.is_relative_to(resolved_root):
                    candidate_files.append(cand)
    else:
        for name in (".env", ".env.local", ".env.development", ".env.production", ".env.test"):
            cand = resolved_root / name
            if cand.is_file():
                candidate_files.append(cand)

    vault_keys_set = set()
    value_anomalies = []
    seen_anomalies = set()
    for env_path in candidate_files:
        if env_path.is_file():
            fkeys, fanomalies = _inspect_dotenv_file_in_memory(env_path)
            vault_keys_set.update(fkeys)
            for item in fanomalies:
                pair = (item["key"], item["issue"])
                if pair not in seen_anomalies:
                    seen_anomalies.add(pair)
                    value_anomalies.append(item)

    if sealed or (status_res.get("success") and status_res.get("data", {}).get("vault") and not vault_keys_set):
        dry_args = ["run", "--dry-run", "--json"]
        if params.get("env_file"):
            dry_args += ["--env-file", str(params["env_file"]).strip()]
        dry_args += ["--", "echo", "ok"]
        dry_res = _run_cli_json(dry_args, vault_cwd, timeout=30)
        if dry_res.get("success") and isinstance(dry_res.get("data"), dict):
            for entry in dry_res["data"].get("secrets") or []:
                key_name = entry.get("name") if isinstance(entry, dict) else str(entry)
                if key_name:
                    vault_keys_set.add(str(key_name))

    referenced_set = _scan_env_references(resolved_root)
    example_path = resolved_root / ".env.example"
    pre_example_keys = _parse_example_keys(example_path)

    vault_keys = sorted(vault_keys_set)
    referenced_in_code = sorted(referenced_set)
    missing_in_vault = sorted((referenced_set | pre_example_keys) - vault_keys_set)
    unreferenced_in_code = sorted(vault_keys_set - referenced_set)

    out = {
        "success": True,
        "sealed": sealed,
        "vault_keys": vault_keys,
        "referenced_in_code": referenced_in_code,
        "example_keys": sorted(pre_example_keys),
        "missing_in_vault": missing_in_vault,
        "unreferenced_in_code": unreferenced_in_code,
        "value_anomalies": value_anomalies,
    }

    if params.get("sync_env_example"):
        desired = sorted(vault_keys_set | referenced_set)
        to_add = [k for k in desired if k not in pre_example_keys]
        if to_add or not example_path.exists():
            existing_text = ""
            if example_path.is_file():
                existing_text = example_path.read_text(encoding="utf-8", errors="replace")
            prefix = ""
            if existing_text and not existing_text.endswith(("\n", "\r")):
                prefix = "\n"
            lines = "".join(f"{k}= # [required]\n" for k in to_add)
            example_path.write_text(existing_text + prefix + lines, encoding="utf-8")
        out["env_example_synced"] = True
        out["env_example_added"] = to_add
        out["example_keys"] = sorted(pre_example_keys | set(to_add))

    return json.dumps(_attach_posture(out, cwd))


_ENV_KEY_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")


def _validate_env_file(cwd, env_file_raw):
    """Resolve `cwd` and `env_file`, ensuring `env_file` is a safe relative path
    inside `cwd` and outside `.ciphervault`."""
    base_dir = Path(cwd or os.getcwd()).resolve()
    if not base_dir.is_dir():
        return None, None, f"workspace directory does not exist: {cwd}"
    env_file = str(env_file_raw or ".env").strip()
    if not env_file or "\x00" in env_file or env_file.startswith(("/", "\\")) or ".." in Path(env_file).parts:
        return None, None, "env_file must be a valid relative path inside workspace cwd"
    target_path = (base_dir / env_file).resolve()
    if (target_path == base_dir or not target_path.is_relative_to(base_dir)
            or ".ciphervault" in target_path.relative_to(base_dir).parts):
        return None, None, "env_file must be a valid path inside workspace cwd"
    return base_dir, target_path, None


def _upsert_env_vars(target_path: Path, pairs: list[tuple[str, str]]) -> None:
    """Update existing KEY=... lines or append new ones in `target_path`."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    if target_path.is_file():
        lines = target_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    for name, value in pairs:
        pattern = re.compile(rf"^(?:\ufeff)?(?:export\s+)?{re.escape(name)}\s*=")
        replaced = False
        new_lines = []
        for line in lines:
            if not replaced and pattern.match(line):
                new_lines.append(f"{name}={value}\n")
                replaced = True
            else:
                new_lines.append(line)
        if not replaced:
            if new_lines and not new_lines[-1].endswith(("\n", "\r")):
                new_lines[-1] = new_lines[-1] + "\n"
            new_lines.append(f"{name}={value}\n")
        lines = new_lines
    target_path.write_text("".join(lines), encoding="utf-8")


def _tool_secret_generate(params, **kwargs):
    params = params or {}
    name = str(params.get("name") or "").strip()
    if not _ENV_KEY_RE.fullmatch(name):
        return json.dumps({
            "success": False,
            "error": "invalid secret name: must match [A-Za-z_][A-Za-z0-9_]*",
        })
    fmt = str(params.get("format") or "base64url").strip().lower()
    if fmt not in ("base64url", "hex", "uuid", "alphanumeric"):
        return json.dumps({
            "success": False,
            "error": "invalid format: expected base64url, hex, uuid, or alphanumeric",
        })
    nbytes = params.get("bytes", 32)
    if isinstance(nbytes, bool) or not isinstance(nbytes, int) or not (16 <= nbytes <= 64):
        return json.dumps({
            "success": False,
            "error": "bytes must be an integer between 16 and 64",
        })

    cwd = params.get("cwd") or os.getcwd()
    env_file = str(params.get("env_file") or ".env").strip()
    if not env_file:
        return json.dumps({"success": False, "error": "env_file cannot be empty"})
    base_dir, target_path, path_err = _validate_env_file(cwd, env_file)
    if path_err:
        return json.dumps({"success": False, "error": path_err})

    seal_param = params.get("seal")
    if seal_param is None:
        policy, p_err = _load_policy_toml(cwd)
        seal = bool((policy.get("vault") or {}).get("sealed_mode", False)) if not p_err else False
    else:
        seal = bool(seal_param)

    if fmt == "base64url":
        value = secrets.token_urlsafe(nbytes)
    elif fmt == "hex":
        value = secrets.token_hex(nbytes)
    elif fmt == "uuid":
        raw_uuid = bytearray(secrets.token_bytes(16))
        raw_uuid[6] = (raw_uuid[6] & 0x0F) | 0x40
        raw_uuid[8] = (raw_uuid[8] & 0x3F) | 0x80
        value = str(uuid.UUID(bytes=bytes(raw_uuid)))
    else:
        alphabet = string.ascii_letters + string.digits
        value = "".join(secrets.choice(alphabet) for _ in range(nbytes))

    length_chars = len(value)
    sha256_prefix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]

    def _scrub_generated(msg):
        return scrub(str(msg).replace(value, "[REDACTED]"))

    try:
        _upsert_env_vars(target_path, [(name, value)])

        vault_cwd = _vault_cwd(cwd)
        try:
            track_arg = target_path.relative_to(Path(vault_cwd).resolve()).as_posix()
        except Exception:
            track_arg = target_path.relative_to(base_dir).as_posix()
        track_res = _run_cli(["track", track_arg], vault_cwd, timeout=60)
        if not track_res.get("success"):
            return json.dumps({
                "success": False,
                "error": _scrub_generated(track_res.get("error") or "ciphervault track failed"),
            })
        push_args = ["push", "--local", "-m", f"Generated secret {name}"]
        if seal:
            push_args.append("--shred")
        push_res = _run_cli(push_args, vault_cwd, timeout=120)
        if not push_res.get("success"):
            return json.dumps({
                "success": False,
                "error": _scrub_generated(push_res.get("error") or "ciphervault push failed"),
            })
        _audit(
            "ciphervault_secret_generate",
            "generated",
            path=env_file,
            detail={"name": name, "format": fmt, "sealed": seal},
            cwd=vault_cwd,
        )
        return json.dumps({
            "success": True,
            "name": name,
            "format": fmt,
            "length_chars": length_chars,
            "sha256_prefix": sha256_prefix,
            "env_file": env_file,
            "sealed": seal,
        })
    except Exception as exc:
        return json.dumps({"success": False, "error": _scrub_generated(exc)})
    finally:
        value = ""


def _tool_secret_prompt(params, **kwargs):
    params = params or {}
    raw_keys = params.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        return json.dumps({
            "success": False,
            "error": "keys must be a non-empty list of key names or {name, reason?, expected_prefix?} objects",
        })

    normalized_keys = []
    seen_names = set()
    for item in raw_keys:
        if isinstance(item, str):
            name = item.strip()
            reason = ""
            expected_prefix = ""
        elif isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            reason = str(item.get("reason") or "").strip()
            expected_prefix = str(item.get("expected_prefix") or "").strip()
        else:
            return json.dumps({
                "success": False,
                "error": "each item in keys must be a string or an object with a 'name' field",
            })
        if not _ENV_KEY_RE.fullmatch(name):
            return json.dumps({
                "success": False,
                "error": f"invalid secret name {name!r}: must match [A-Za-z_][A-Za-z0-9_]*",
            })
        if name in seen_names:
            continue
        seen_names.add(name)
        entry = {"name": name}
        if reason:
            entry["reason"] = reason[:200]
        if expected_prefix:
            entry["expected_prefix"] = expected_prefix[:32]
        normalized_keys.append(entry)

    cwd = params.get("cwd") or os.getcwd()
    env_file = str(params.get("env_file") or ".env").strip()
    base_dir, target_path, path_err = _validate_env_file(cwd, env_file)
    if path_err:
        return json.dumps({"success": False, "error": path_err})

    seal_param = params.get("seal")
    seal = True if seal_param is None else bool(seal_param)
    requested_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if os.environ.get("CIPHERVAULT_INTERACTIVE_PROMPT") == "1" and sys.stdin.isatty():
        entered: list[tuple[str, str]] = []

        def _scrub_entered(msg):
            out = str(msg)
            for _k, v in entered:
                if v:
                    out = out.replace(v, "[REDACTED]")
            return scrub(out)

        try:
            for item in normalized_keys:
                name = item["name"]
                hint_parts = []
                if item.get("reason"):
                    hint_parts.append(item["reason"])
                if item.get("expected_prefix"):
                    hint_parts.append(f"prefix: {item['expected_prefix']}")
                suffix = f" ({', '.join(hint_parts)})" if hint_parts else ""
                val = getpass.getpass(f"Enter {name}{suffix}: ")
                if not val or "\n" in val or "\r" in val:
                    return json.dumps({
                        "success": False,
                        "error": f"empty or invalid multiline value for {name}",
                    })
                prefix = item.get("expected_prefix") or ""
                if prefix and not val.startswith(prefix):
                    return json.dumps({
                        "success": False,
                        "error": f"value for {name} does not start with expected prefix {prefix!r}",
                    })
                entered.append((name, val))

            _upsert_env_vars(target_path, entered)
            vault_cwd = _vault_cwd(cwd)
            try:
                track_arg = target_path.relative_to(Path(vault_cwd).resolve()).as_posix()
            except Exception:
                track_arg = target_path.relative_to(base_dir).as_posix()
            track_res = _run_cli(["track", track_arg], vault_cwd, timeout=60)
            if not track_res.get("success"):
                return json.dumps({
                    "success": False,
                    "error": _scrub_entered(track_res.get("error") or "ciphervault track failed"),
                })
            push_args = ["push", "--local", "-m", "Configured secrets via interactive prompt"]
            if seal:
                push_args.append("--shred")
            push_res = _run_cli(push_args, vault_cwd, timeout=120)
            if not push_res.get("success"):
                return json.dumps({
                    "success": False,
                    "error": _scrub_entered(push_res.get("error") or "ciphervault push failed"),
                })
            configured_names = [k for k, _v in entered]
            _audit(
                "ciphervault_secret_prompt",
                "configured",
                path=env_file,
                detail={"keys": configured_names, "sealed": seal},
                cwd=vault_cwd,
            )
            return json.dumps({
                "success": True,
                "configured": configured_names,
                "env_file": env_file,
                "sealed": seal,
            })
        except Exception as exc:
            return json.dumps({"success": False, "error": _scrub_entered(exc)})
        finally:
            entered.clear()

    # Normal agent/desktop flow: queue metadata-only prompt (zero secrets!).
    vroot = _vault_root(cwd) or base_dir
    cv_dir = vroot / ".ciphervault"
    cv_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = cv_dir / "pending_secret_prompts.json"
    existing_keys = []
    if prompt_path.is_file():
        try:
            old = json.loads(prompt_path.read_text(encoding="utf-8", errors="replace") or "{}")
            if isinstance(old, dict) and isinstance(old.get("keys"), list):
                existing_keys = [k for k in old["keys"] if isinstance(k, dict) and k.get("name")]
        except Exception:
            existing_keys = []

    merged = {}
    order = []
    for k in existing_keys:
        n = str(k["name"])
        merged[n] = k
        order.append(n)
    for k in normalized_keys:
        n = k["name"]
        item_meta = {
            "name": n,
            "reason": k.get("reason", ""),
            "expected_prefix": k.get("expected_prefix", ""),
            "env_file": env_file,
            "seal": seal,
            "requested_at": requested_at,
        }
        if n not in merged:
            order.append(n)
        merged[n] = item_meta

    payload = {
        "keys": [merged[n] for n in order],
        "env_file": env_file,
        "seal": seal,
        "requested_at": requested_at,
    }
    prompt_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    pending_names = [k["name"] for k in normalized_keys]
    _audit(
        "ciphervault_secret_prompt",
        "prompt_queued",
        path=env_file,
        detail={"keys": pending_names, "sealed": seal},
        cwd=_vault_cwd(cwd),
    )
    return json.dumps({
        "success": True,
        "status": "prompt_queued",
        "pending_keys": pending_names,
        "env_file": env_file,
        "seal": seal,
        "message": "Secret input prompt queued in the CipherVault desktop pane. Enter the values there — never paste secrets into chat.",
    })


_KNOWN_PROXY_PROVIDERS = {
    "OPENAI_API_KEY": ("https://api.openai.com", ["OPENAI_BASE_URL", "OPENAI_API_BASE"]),
    "ANTHROPIC_API_KEY": ("https://api.anthropic.com", ["ANTHROPIC_BASE_URL"]),
    "GEMINI_API_KEY": ("https://generativelanguage.googleapis.com", ["GEMINI_BASE_URL", "GOOGLE_GEMINI_BASE_URL"]),
    "GOOGLE_API_KEY": ("https://generativelanguage.googleapis.com", ["GEMINI_BASE_URL", "GOOGLE_GEMINI_BASE_URL"]),
    "STRIPE_API_KEY": ("https://api.stripe.com", ["STRIPE_API_BASE"]),
    "STRIPE_SECRET_KEY": ("https://api.stripe.com", ["STRIPE_API_BASE"]),
    "GITHUB_TOKEN": ("https://api.github.com", []),
    "GH_TOKEN": ("https://api.github.com", []),
    "OPENROUTER_API_KEY": ("https://openrouter.ai/api", ["OPENROUTER_BASE_URL"]),
    "HF_TOKEN": ("https://huggingface.co", []),
    "HUGGINGFACE_TOKEN": ("https://huggingface.co", []),
}


def _tool_proxy_doctor(params, **kwargs):
    """Zero-knowledge dry-run proxy route diagnostic: reports which vault
    keys map to built-in provider routes vs policy.toml upstreams vs unmapped."""
    params = params or {}
    cwd = params.get("cwd")
    vault_cwd = _vault_cwd(cwd)
    dry_args = ["run", "--dry-run", "--json"]
    if params.get("env_file"):
        dry_args += ["--env-file", str(params["env_file"])]
    dry_args += ["--", "echo", "ok"]
    res = _run_cli_json(dry_args, vault_cwd, timeout=30)
    if not res.get("success"):
        return json.dumps(res)
    data = res.get("data") or {}
    secret_names = [
        str(item.get("name"))
        for item in (data.get("secrets") or [])
        if isinstance(item, dict) and item.get("name")
    ]
    policy, _policy_err = _load_policy_toml(vault_cwd)
    policy_upstreams = dict(_policy_configured_upstreams(policy, profile_name=params.get("profile")))
    mapped_providers = []
    mapped_policy = []
    unmapped = []
    for name in secret_names:
        if name in policy_upstreams:
            mapped_policy.append({"key": name, "upstream": policy_upstreams[name]})
        elif name in _KNOWN_PROXY_PROVIDERS:
            upstream, base_envs = _KNOWN_PROXY_PROVIDERS[name]
            mapped_providers.append({
                "key": name,
                "upstream": upstream,
                "injected_base_envs": base_envs,
            })
        else:
            unmapped.append(name)
    return json.dumps(_attach_posture({
        "success": True,
        "proxy_ready": bool(mapped_providers or mapped_policy),
        "mapped_providers": mapped_providers,
        "mapped_policy_upstreams": mapped_policy,
        "unmapped_keys": unmapped,
        "notes": [
            "Keys in mapped_providers/mapped_policy_upstreams can run with proxy=True without entering child RAM.",
            "Keys in unmapped_keys require no_net=True (offline) or an entry in .ciphervault/policy.toml [profiles.<name>.upstreams].",
        ],
    }, cwd))


def _tool_diff(params, **kwargs):
    params = params or {}
    cwd = params.get("cwd")
    args = ["diff", "--json"]
    file_filter = params.get("file")
    if file_filter is not None and str(file_filter).strip():
        fstr = str(file_filter).strip()
        if fstr.startswith("-"):
            return json.dumps({"success": False, "error": "invalid file filter"})
        args += ["--file", fstr]
    snap_a = params.get("snapshot_a")
    snap_b = params.get("snapshot_b")
    a_str = str(snap_a).strip() if snap_a is not None and str(snap_a).strip() else None
    b_str = str(snap_b).strip() if snap_b is not None and str(snap_b).strip() else None
    for tok in (a_str, b_str):
        if tok and tok.startswith("-"):
            return json.dumps({"success": False, "error": "snapshot reference cannot start with '-'"})
    if a_str and b_str:
        args += [a_str, b_str]
    elif a_str:
        args.append(a_str)
    elif b_str:
        args += ["head", b_str]
    # Security invariant: NEVER pass --reveal or -r from an agent tool.
    if "--reveal" in args or "-r" in args:  # pragma: no cover
        return json.dumps({"success": False, "error": "reveal is forbidden in ciphervault_diff"})
    return json.dumps(_run_cli_json(args, _vault_cwd(cwd), timeout=60))


def _tool_redact(params, **kwargs):
    params = params or {}
    cleaned, n, exact = cli_redact(params.get("text") or "", params.get("cwd"))
    if not exact:
        return json.dumps({
            "success": False, "exact_value_check": False,
            "error": "Exact-value redaction unavailable; text withheld, not safe to quote.",
            "next": "Run `hermes ciphervault doctor` to check the resolved CLI version and capabilities.",
        })
    return json.dumps({"success": True, "text": cleaned, "redactions": n,
                       "exact_value_check": exact})


def _tool_audit(params, **kwargs):
    params = params or {}
    cwd = params.get("cwd")
    limit = str(int(params.get("limit", 50)))
    show = _run_cli_json(["agent-log", "show", "--json", "--limit", limit], cwd)
    if not show.get("success"):
        return json.dumps(show)
    verify = _run_cli_json(["agent-log", "verify", "--json"], cwd)
    report = verify.get("data")
    verified = bool(verify.get("success") and isinstance(report, dict)
                    and report.get("ok") is True)
    out = {
        "success": verified,
        "entries": show.get("data", []),
        "verification": report if isinstance(report, dict) else verify,
        "binary": show.get("binary"),
    }
    if not verified:
        out["error"] = "Audit chain verification failed or was unavailable; no hash lookup is proof."
        return json.dumps(out)
    if params.get("check_text") is not None:
        # Exact text first (matches the stored tool-result hash), then the
        # whitespace-trimmed text (matches the stored visible-content hash).
        text = str(params["check_text"])
        digests = [hashlib.sha256(text.encode()).hexdigest()]
        if text.strip() != text:
            digests.append(_content_sha256(text))
        for digest in digests:
            check = _run_cli_json(
                ["agent-log", "check", "--json", "--output-sha256", digest], cwd)
            check_data = check.get("data")
            if not (check.get("success") and isinstance(check_data, dict)
                    and isinstance(check_data.get("found"), bool)):
                out.pop("check", None)
                out.update(success=False, check=check,
                           error="Audit output-hash lookup failed or returned an invalid response.")
                break
            out["check"] = check_data
            if check_data["found"]:
                break
    return json.dumps(out)


_DEFAULT_OPERATORS = (
    "https://op1.cipherv.online",
    "https://op2.cipherv.online",
    "https://op3.cipherv.online",
)
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_IPV4_TRANSLATED_NET = ipaddress.ip_network("::ffff:0:0:0/96")
_BLOCKED_OPERATOR_HOSTS = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
})


def _normalize_operator_url(url):
    """Canonical http(s) operator URL with no trailing slash, query,
    fragment, or userinfo; None if malformed or ambiguous."""
    if not isinstance(url, str):
        return None
    raw = url.strip()
    if not raw or any(ord(c) < 0x20 or ord(c) == 0x7F or c.isspace() for c in raw):
        return None
    try:
        parts = urllib.parse.urlsplit(raw)
        port = parts.port
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if (scheme not in ("http", "https") or not parts.netloc or not host
            or "\\" in raw or "@" in parts.netloc or "%" in parts.netloc
            or parts.query or parts.fragment):
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    host_literal = f"[{host}]" if ":" in host else host
    netloc = f"{host_literal}:{port}" if port is not None else host_literal
    path = parts.path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def _configured_operators(cwd):
    """Normalized operator URLs configured for the vault at `cwd`
    (CIPHERVAULT_OPERATORS env override, else .ciphervault/operators.json,
    else the default public fleet when a vault exists without an
    operators.json file). Fails closed (`()`) when no vault exists or
    operators.json cannot be parsed."""
    env_ops = os.environ.get("CIPHERVAULT_OPERATORS", "").strip()
    if env_ops:
        raw_list = [s for s in re.split(r"[\s,;]+", env_ops) if s]
    else:
        try:
            root = _vault_root(cwd)
        except Exception:
            return ()
        if root is None:
            return ()
        ops_path = Path(root) / ".ciphervault" / "operators.json"
        try:
            ops_path.lstat()
        except FileNotFoundError:
            raw_list = list(_DEFAULT_OPERATORS)
        except OSError:
            return ()
        else:
            try:
                loaded = json.loads(ops_path.read_text(encoding="utf-8"))
            except Exception:
                return ()
            if not isinstance(loaded, list) or not loaded:
                return ()
            raw_list = loaded
    out = []
    for item in raw_list:
        norm = _normalize_operator_url(item)
        if not norm:
            return ()
        if norm not in out:
            out.append(norm)
    return tuple(out)


def _embedded_ipv4(ip):
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _IPV4_TRANSLATED_NET:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def _is_public_operator_url(norm):
    """Unconditional SSRF floor: refuses loopback, private, link-local
    (169.254.0.0/16 incl. 169.254.169.254), CGNAT, reserved, multicast,
    unspecified, and internal hostnames even if allow_private_urls is set."""
    parts = urllib.parse.urlsplit(norm)
    host = (parts.hostname or "").lower().rstrip(".")
    if (not host or host in _BLOCKED_OPERATOR_HOSTS
            or host.endswith((".localhost", ".local", ".internal"))):
        return False
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(
                host, parts.port or (443 if parts.scheme == "https" else 80),
                socket.AF_UNSPEC, socket.SOCK_STREAM,
            )
        except OSError:
            return False
        ips = []
        for _fam, _type, _proto, _canon, sockaddr in infos:
            try:
                ips.append(ipaddress.ip_address(str(sockaddr[0]).split("%")[0]))
            except ValueError:
                return False
    if not ips:
        return False
    for raw_ip in ips:
        ip = _embedded_ipv4(raw_ip)
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified
                or ip in _CGNAT_NET or not ip.is_global):
            return False
    return True


def _is_safe_operator_url(url):
    """Validate an operator endpoint with Hermes's tools.url_safety.is_safe_url
    plus an unconditional public-IP check."""
    norm = _normalize_operator_url(url)
    if not norm:
        return False
    try:
        from tools.url_safety import is_safe_url
    except Exception:
        is_safe_url = None
    if is_safe_url is not None and not is_safe_url(norm):
        return False
    return _is_public_operator_url(norm)


def _validate_via_endpoints(via, cwd):
    """Accept `via` endpoints only when every URL passes
    tools.url_safety.is_safe_url / public-IP validation (never LAN,
    loopback, or cloud metadata) AND belongs to this vault's configured
    operator list."""
    raw_items = [via] if isinstance(via, str) else list(via) if isinstance(via, (list, tuple)) else []
    configured = set(_configured_operators(cwd))
    validated = []
    for raw in raw_items:
        norm = _normalize_operator_url(raw)
        if not norm:
            return None, "invalid operator URL in `via`: must be a clean http(s) origin without query, fragment, or credentials."
        if not _is_safe_operator_url(norm):
            return None, (
                f"refusing `via` endpoint {norm!r}: private, loopback, link-local, or cloud-metadata hosts are not allowed."
            )
        if norm not in configured:
            return None, (
                f"refusing `via` endpoint {norm!r}: not in this vault's configured operator list "
                "(.ciphervault/operators.json). Update operators.json or run `ciphervault recover --via` in your terminal."
            )
        if norm not in validated:
            validated.append(norm)
    return validated, None


def _tool_drill(params, **kwargs):
    params = params or {}
    kit = params.get("kit")
    shares = params.get("shares") or []
    if not kit and not shares:
        return json.dumps({
            "success": False,
            "error": "provide kit (path to kit file) or shares (list of share file paths). Paths only — never paste kit contents.",
        })
    cwd = params.get("cwd")
    via_raw = params.get("via")
    via = []
    if via_raw:
        via, err = _validate_via_endpoints(via_raw, cwd)
        if err:
            _audit("ciphervault_recovery_drill", "blocked",
                   detail={"reason": "rejected_via_endpoint"}, cwd=cwd)
            return json.dumps({"success": False, "error": err})
    # The restore target is ALWAYS a fresh temp dir created here, and
    # it is the only directory this tool ever deletes (reviewer rule:
    # never rmtree a model-chosen path).
    dest = tempfile.mkdtemp(prefix="cv-drill-")
    try:
        args = ["recover", "--to", dest]
        if kit:
            args += ["--kit", kit]
        if shares:
            args += ["--shares"] + list(shares)
        if via:
            # The kit keeps the operators from when it was printed; a vault
            # that moved fleets is recovered through its current operators.
            # Records stay authenticated by the kit's recovery key.
            args += ["--via"] + via
        res = _run_cli(args, cwd, timeout=300)
        if not res.get("success"):
            return json.dumps(res)
        # Hash-then-delete: prove the restore by manifest (names +
        # sizes + SHA-256) without the agent reading plaintext, and
        # leave no standing plaintext copy on disk.
        manifest = []
        root = Path(dest)
        for path in sorted(root.rglob("*")):
            if path.is_file():
                manifest.append({
                    "path": str(path.relative_to(root)).replace("\\", "/"),
                    "size": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                })
        return json.dumps({
            "success": True,
            "binary": res.get("binary"),
            "files_restored": len(manifest),
            "manifest": manifest,
            "drill_dir_deleted": True,
            "note": (
                "Plaintext was hashed, verified into this manifest, and "
                "the temp drill dir was deleted; it never entered this "
                "chat. Compare hashes against a later restore to re-verify."
            ),
        })
    finally:
        shutil.rmtree(dest, ignore_errors=True)


# ---------------------------------------------------------------- hooks

_SECRET_FILE_RE = re.compile(
    r"(?i)(^|[\s\\/\"'=])(\.env(?!(?:\.(?:example|sample|template))\b)(\.[\w.-]*)?|\.envrc|\.npmrc|\.pypirc|"
    r"[\w.-]+\.(pem|key|p12|pfx)|id_rsa|id_ed25519|"
    r"credentials\.json|secrets\.(json|ya?ml|toml)|"
    r"vault\.db|keystore\.(?:key|salt)|audit_hmac\.key|policy\.toml|"
    # Source/docs about kits (recovery_kit.rs, recovery_kit.md) are not kits.
    r"recovery_kit(?![\w-]*\.(?:rs|py|pyi|js|jsx|ts|tsx|go|java|kt|swift|c|cc|cpp|h|hpp|cs|rb|php|md|toml|ya?ml|lock)\b)[\w.-]*|"
    r"[\w.-]+\.kit|[\w.-]*share[\w.-]*\.txt)"
)
_PROTECTED_CONFIG_RE = re.compile(
    r"(?i)(^|[\s\\/\"'=])(?:\.?ciphervault[\\/])?(?:policy\.toml|operators\.json|vault\.db|keystore\.(?:key|salt)|audit_hmac\.key)(\b|$)"
)
_SHELL_CHAIN_RE = re.compile(r"[;&|`$<>]|\r|\n")
_SAFE_SECRET_PATH_CMD_RE = re.compile(
    r"(?i)^\s*(?:"
    r"(?:ciphervault|cv)(?:\.exe)?\s+(?:status|track|push|hook|audit|agent-log\s+(?:show|verify|check)|diff)\b|"
    r"git(?:\.exe)?\s+(?:status|check-ignore|rm\s+--cached|ls-files)\b"
    r")"
)
_CLI_FLAGS_RE = r"(?:\s+--?[\w-]+(?:=[^\s;&|]+)?)*"
_EXPORT_ENV_RE = re.compile(
    rf"(?i)(?:\b(?:ciphervault|cv)(?:\.exe)?[\"']?{_CLI_FLAGS_RE}\s+"
    rf"(?:(?:export-env|restore|pull|recover|init|rekey|prune|untrack)\b|"
    rf"secret{_CLI_FLAGS_RE}\s+get\b|"
    rf"agent-log{_CLI_FLAGS_RE}\s+(?:record|anchor)\b|"
    rf"diff\b[^\n;&|]*(?:--reveal|\s-r\b))|"
    r"/api/diff\b[^\n]*reveal|/api/snapshots/restore\b)"
)
_GIT_DANGER_RE = re.compile(r"(?i)\bgit\s+(commit|push|add)\b")
_INTERPRETER_BINARIES = frozenset({
    "python", "python3", "node", "bash", "sh",
    "pwsh", "powershell", "cmd", "ruby", "perl",
})
_INLINE_CODE_FLAGS = frozenset({"-c", "-e", "/c", "-command", "-enc", "-encodedcommand"})
_REDACT_CHUNK_CHARS = 262_144
_REDACT_SEAM_OVERLAP = 4_096
_MAX_RESULT_CHARS = int(os.environ.get("CIPHERVAULT_MAX_RESULT_CHARS", str(4 * 1024 * 1024)))


def _is_inline_interpreter_cmd(cmd):
    if not cmd or len(cmd) < 2:
        return False
    raw_prog = Path(str(cmd[0])).name.lower()
    for ext in (".exe", ".cmd", ".bat"):
        if raw_prog.endswith(ext):
            raw_prog = raw_prog[:-len(ext)]
            break
    is_interp = (
        raw_prog in _INTERPRETER_BINARIES
        or bool(re.match(r"^python\d*(?:\.\d+)*$", raw_prog))
    )
    if not is_interp:
        return False
    for arg in cmd[1:]:
        tok = str(arg).strip().lower()
        if tok == "--" or not tok.startswith(("-", "/")):
            break
        if tok == "-m":
            break
        if tok in _INLINE_CODE_FLAGS or tok.startswith(("-c=", "-e=", "/c:")):
            return True
    return False


def _compute_run_rule_key(cmd, profile_name, no_net, proxy_on, allow_keys):
    program = str((cmd or ["run"])[0])
    parts = ["ciphervault_run"]
    if profile_name:
        parts.append(f"profile={profile_name}")
    else:
        parts.append(program)
    if _is_inline_interpreter_cmd(cmd):
        cmd_digest = hashlib.sha256(
            json.dumps([str(x) for x in cmd]).encode("utf-8")
        ).hexdigest()[:12]
        parts.append(f"inline={cmd_digest}")
    clean_keys = (
        [str(k).strip() for k in allow_keys if str(k).strip()]
        if allow_keys is not None else None
    )
    if (not no_net) or proxy_on or (clean_keys is not None):
        net_mode = "proxy" if proxy_on else ("no_net" if no_net else "open")
        keys_part = ",".join(sorted(clean_keys)) if clean_keys else "ALL"
        parts.append(f"net={net_mode}")
        parts.append(f"keys={keys_part}")
    return ":".join(parts)


def _is_safe_terminal_secret_ref(text):
    if _EXPORT_ENV_RE.search(text):
        return False
    return (
        not _SHELL_CHAIN_RE.search(text)
        and bool(_SAFE_SECRET_PATH_CMD_RE.search(text))
    )


def _iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


def _scrub_full_text(text, cwd, timeout=15):
    """Scrub arbitrarily large text across all chunks + join seams.
    Returns (scrubbed_text, total_redactions, cli_ok, changed)."""
    if len(text) <= _REDACT_CHUNK_CHARS:
        cleaned, n, ok = _call_cli_redact(text, cwd, timeout=timeout)
        return cleaned, n, ok, (cleaned != text)

    parts = []
    seam_centers = []
    total_n = 0
    all_ok = True
    any_changed = False
    pos = 0
    while pos < len(text):
        chunk = text[pos:pos + _REDACT_CHUNK_CHARS]
        cleaned, n, ok = _call_cli_redact(chunk, cwd, timeout=timeout)
        if not ok:
            all_ok = False
        if cleaned != chunk:
            any_changed = True
        total_n += int(n)
        parts.append(cleaned)
        pos += _REDACT_CHUNK_CHARS
        if pos < len(text):
            seam_centers.append(sum(len(p) for p in parts))

    assembled = "".join(parts)
    for center in reversed(seam_centers):
        start = max(0, center - _REDACT_SEAM_OVERLAP)
        end = min(len(assembled), center + _REDACT_SEAM_OVERLAP)
        seam = assembled[start:end]
        cleaned_seam, n_seam, ok_seam = _call_cli_redact(seam, cwd, timeout=timeout)
        if not ok_seam:
            all_ok = False
        if cleaned_seam != seam:
            any_changed = True
            total_n += int(n_seam)
            assembled = assembled[:start] + cleaned_seam + assembled[end:]
    return assembled, total_n, all_ok, any_changed


def on_pre_tool_call(tool_name, args, **kwargs):
    """Leak guard. Blocks secret-file reads into chat, secret-shaped
    content handed to other tools, and git add/commit/push while the
    CipherVault hook check reports violations. Fails closed when a
    CipherVault workspace is present and redaction cannot run."""
    cwd = ((args or {}).get("cwd") or (args or {}).get("workdir") or os.getcwd()) if isinstance(args, dict) else os.getcwd()
    try:
        if tool_name == "ciphervault_run":
            # Running an arbitrary command with vault secrets in its
            # environment must go through Hermes's human-approval gate
            # (same gate as dangerous shell commands). Output scrubbing
            # alone cannot stop a command from exfiltrating the values
            # it was given. Every ciphervault_run call is gated.
            vault_cwd = _vault_cwd(cwd)
            effective, policy_err = _resolve_run_policy(args, cwd)
            if policy_err:
                _audit("ciphervault_run", "blocked",
                       detail={"reason": "policy_or_upstream_rejected"},
                       cwd=vault_cwd)
                return {"action": "block", "message": f"CipherVault guard: {policy_err}"}
            cmd = list(effective.get("command") or ["run"])
            allow_keys = effective.get("allow_keys")
            no_net = _effective_no_net(effective)
            proxy_on = bool(effective.get("proxy") or _clean_proxy_upstreams(effective))
            profile_name = str(effective.get("profile") or "").strip() or None
            detail = {
                "program": str(cmd[0]),
                "no_net": no_net,
                "proxy": proxy_on,
            }
            if profile_name:
                detail["profile"] = profile_name[:64]
            if allow_keys:
                detail["allow_keys"] = [str(k) for k in allow_keys][:20]
            _audit("ciphervault_run", "approval_requested",
                   detail=detail,
                   cwd=vault_cwd)
            # Cadence: checkpoint the chain head — this grant included —
            # to the fleet BEFORE the approved command can run, so a
            # run that goes badly cannot rewrite the grant away.
            _anchor_async(vault_cwd)
            # Scoped grant grain: bind rule_key to program/profile, inline
            # code hash, network isolation mode, and allow_keys.
            rule_key = _compute_run_rule_key(cmd, profile_name, no_net, proxy_on, allow_keys)
            scope_note = (
                f" (allow_keys: {', '.join(str(k) for k in allow_keys)})"
                if allow_keys else " (all vault secrets)"
            )
            net_note = (
                " [proxy: real keys stay in parent]" if proxy_on
                else (" [network: isolated (--no-net)]" if no_net else " [network: UNRESTRICTED]")
            )
            return {"action": "approve",
                    "message": (f"CipherVault: run a command with vault secrets{scope_note}{net_note} "
                                "injected in RAM? The command receives the values; "
                                "approve only if you trust it."),
                    "rule_key": rule_key}
        if not tool_name or tool_name.startswith("ciphervault_"):
            return None
        args = args or {}
        texts = list(_iter_strings(args))

        if tool_name in ("terminal", "execute_code", "browser_exec"):
            for text in texts:
                if _EXPORT_ENV_RE.search(text):
                    _audit(tool_name, "blocked", path=text[:300],
                           detail={"reason": "export_env_terminal"}, cwd=cwd)
                    return {"action": "block", "message": (
                        "CipherVault guard: plaintext secret export/restore/reveal/admin commands "
                        "cannot run via agent tools. Use ciphervault_run or run interactively."
                    )}

        if tool_name in ("write_file", "patch"):
            for key in ("path", "file_path", "file", "target_file"):
                target = args.get(key) if isinstance(args, dict) else None
                if isinstance(target, str) and (
                    _PROTECTED_CONFIG_RE.search(target) or _SECRET_FILE_RE.search(target)
                ):
                    _audit(tool_name, "blocked", path=target[:300],
                           detail={"reason": "protected_secret_or_policy_write"}, cwd=cwd)
                    return {"action": "block", "message": (
                        "CipherVault guard: modifying secret files or .ciphervault/policy.toml "
                        "directly is blocked. Use ciphervault_secret_generate or edit policy.toml manually."
                    )}

        if tool_name in ("terminal", "execute_code", "read_file", "browser_exec"):
            for text in texts:
                if _SECRET_FILE_RE.search(text):
                    if tool_name == "terminal" and _is_safe_terminal_secret_ref(text):
                        continue
                    _audit(tool_name, "blocked", path=text[:300],
                           detail={"reason": "secret_file_read"}, cwd=cwd)
                    return {"action": "block", "message": (
                        "CipherVault guard: accessing a secret/kit file from this tool could leak it. "
                        "Use ciphervault_run (RAM-only injection), ciphervault_redact (masked), or "
                        "ciphervault_status (names only). Paths are fine; contents are not."
                    )}

        joined = "\n".join(texts)
        if joined:
            # Check against every vault the call touches, not only the
            # cwd's (vaultless calls still get the CLI's shape pass).
            for root in _scrub_roots(args, cwd) or [cwd]:
                cleaned, n, exact, changed = _scrub_full_text(joined, root, timeout=10)
                if not exact and _vault_present(root) and tool_name in (
                    "terminal", "execute_code", "read_file", "write_file", "patch", "browser_exec"
                ):
                    _audit(tool_name, "blocked",
                           detail={"reason": "redact_unavailable_fail_closed"}, cwd=root)
                    return {"action": "block", "message": (
                        "CipherVault guard: exact-value redaction check failed/timed out inside "
                        "a vault workspace; failing closed. Verify `ciphervault` binary health."
                    )}
                if n > 0 or changed:
                    _audit(tool_name, "blocked",
                           detail={"reason": "secret_shaped_payload", "redactions": n}, cwd=root)
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
                        _audit(tool_name, "blocked",
                               detail={"reason": "git_sprawl",
                                       "violations": res["data"].get("violations_count", 0)},
                               cwd=cwd)
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
        if _vault_present(cwd):
            return {"action": "block", "message": (
                "CipherVault guard: internal error during security check inside a vault "
                "workspace; failing closed."
            )}
        return None


def _vault_root(cwd):
    """Nearest cwd/ancestor holding a vault store entry, else None.

    The store entry itself defines a vault: any `.ciphervault/vault.db`
    (even a directory or a corrupt file) stays guarded, while a bare
    `.ciphervault/` such as the installer's `~/.ciphervault/bin` does
    not. Inspection errors other than absence propagate to the caller.
    """
    p = Path(cwd or os.getcwd()).absolute()
    for parent in (p, *p.parents):
        try:
            (parent / ".ciphervault" / "vault.db").lstat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        return parent
    return None


def _vault_present(cwd):
    """An expected vault stays guarded even if its store is unreadable."""
    try:
        return _vault_root(cwd) is not None
    except Exception:
        # An inspection failure is not evidence of a vaultless workspace.
        return True


def _vault_cwd(cwd):
    """Run vault-scoped CLI calls at the workspace root: the CLI opens
    ./.ciphervault/vault.db relative to its cwd, so a subdirectory
    would otherwise look vaultless and lose its exact values/receipts."""
    try:
        root = _vault_root(cwd)
    except Exception:
        root = None
    return str(root) if root is not None else cwd


# Tool arguments name paths the cwd does not cover (`cat demo/notes.txt`
# from a parent directory, read_file on an absolute path). Tokens are
# split on shell punctuation; scans are bounded per call.
_ARG_TOKEN_RE = re.compile(r"[^\s\"'`;|&<>(){}\[\]=,]+")
_ARG_SCAN_CHARS = 16_384
_ARG_MAX_TOKENS = 256


def _same_dir(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _nearest_vault_lenient(path, cache):
    """_vault_root for argument paths: a level that cannot be inspected
    (glob, invalid name, permission wall) counts as "no store here" and
    the walk continues upward, so one odd token cannot hide the vault
    above it. `cache` maps walked directories to their nearest vault."""
    walked, found = [], None
    for parent in (path, *path.parents):
        key = str(parent)
        if key in cache:
            found = cache[key]
            break
        walked.append(key)
        try:
            (parent / ".ciphervault" / "vault.db").lstat()
        except (OSError, ValueError):
            continue
        found = key
        break
    for key in walked:
        cache[key] = found
    return found


def _arg_vault_roots(args, cwd):
    """Vault roots that path-like tokens in a call's arguments point into."""
    base = os.path.abspath(cwd or os.getcwd())
    cache, roots, tokens = {}, [], 0
    for text in _iter_strings(args or {}):
        for token in _ARG_TOKEN_RE.findall(text[:_ARG_SCAN_CHARS]):
            if tokens >= _ARG_MAX_TOKENS:
                return roots
            if "://" in token or token.startswith("-") or len(token) > 1024:
                continue
            tokens += 1
            try:
                path = Path(os.path.abspath(os.path.join(base, os.path.expanduser(token))))
                root = _nearest_vault_lenient(path, cache)
            except Exception:
                continue
            if root and not any(_same_dir(root, r) for r in roots):
                roots.append(root)
    return roots


def _scrub_roots(args, cwd):
    """Every vault whose exact values a call's input or output must be
    checked against: the cwd's vault (an uninspectable one stays
    guarded, see _vault_present) plus each vault a path argument points
    into. Empty means the call touches no vault."""
    roots = [_vault_cwd(cwd)] if _vault_present(cwd) else []
    for root in _arg_vault_roots(args, cwd):
        if not any(_same_dir(root, r) for r in roots):
            roots.append(root)
    return roots


def on_transform_tool_result(tool_name, args, result, **kwargs):
    """Scrub every non-CipherVault tool result before it enters model
    context. Fails CLOSED: if the exact-value scrub cannot run, or
    the audit receipt cannot be written, the result is withheld
    rather than passed on trust — a silent pass would make the
    audit log's absence meaningless."""
    try:
        if not isinstance(result, str) or not result:
            return None
        if tool_name and tool_name.startswith("ciphervault_"):
            return None
        cwd = (args or {}).get("cwd") or (args or {}).get("workdir") or os.getcwd()
        oversized = len(result) > _MAX_RESULT_CHARS
        sample = result[:_MAX_RESULT_CHARS] if oversized else result
        roots = _scrub_roots(args, cwd)
        if not roots:
            # No vault here (fresh install, gateway, unrelated
            # project): there are no vault values to protect, and
            # withholding every result Hermes-wide would punish
            # users who never opted into a vault. Pass through with
            # the local shape scrub; fail-closed applies only where
            # a vault is actually present (below).
            cleaned = scrub(sample)
            if cleaned != sample or oversized:
                return cleaned + ("\n…[truncated by CipherVault scrub]" if oversized else "")
            return None
        # Each vault the call touches scrubs its own exact values across all
        # 256 KiB chunks and 4 KiB join seams; any one failing withholds the result.
        cleaned, n = sample, 0
        for root in roots:
            cleaned, n_root, exact, _changed = _scrub_full_text(cleaned, root, timeout=15)
            n += n_root
            if not exact:
                _audit(tool_name, "scrub_unavailable",
                       detail={"withheld_bytes": len(result)}, cwd=root)
                return ("[CipherVault] tool result withheld: the exact-value scrub "
                        "could not run (CLI missing, incompatible, or timed out), so "
                        "this output was not shown. A shape-only pass could miss a "
                        "vault value entirely; failing loudly instead. Run "
                        "`hermes ciphervault doctor` to inspect the resolved CLI.")
        final = cleaned
        if oversized:
            # The window is never conditional: an untouched tail must
            # not pass just because the scrubbed head was clean.
            final = cleaned + "\n…[truncated by CipherVault scrub]"
        detail = {"redactions": n,
                  "output_sha256": hashlib.sha256(final.encode()).hexdigest(),
                  "content_sha256": _content_sha256(_visible_text(final)),
                  "output_bytes": len(final)}
        if len(roots) > 1:
            detail["vaults"] = len(roots)
        for root in roots:
            if not _audit(tool_name, "scrubbed_result", detail=detail, cwd=root):
                return ("[CipherVault] tool result withheld: the audit-log write "
                        "failed, so there is no receipt for this output. Withholding "
                        "it keeps 'no hash in the chain' unambiguous.")
        if final != result:
            return final
        return None
    except Exception:
        # Returning None means "release the original" to Hermes. An
        # unexpected scrub/receipt error must never take that path.
        return ("[CipherVault] tool result withheld: an unexpected scrub or "
                "audit error prevented safe release. Run `hermes ciphervault doctor`.")


_WRITE_TOOLS = {"write_file", "patch", "terminal", "execute_code", "browser_exec"}


def on_post_tool_call(tool_name, args=None, result=None, **kwargs):
    """Audit what executed: write/exec tools are recorded (tool +
    target path only) so a session can later prove what the agent
    read, wrote, and ran — and what it never saw."""
    try:
        if not tool_name or tool_name not in _WRITE_TOOLS:
            return None
        args = args or kwargs.get("params") or {}
        path = ""
        for key in ("path", "file_path", "file"):
            if isinstance(args, dict) and args.get(key):
                path = str(args[key])
                break
        cwd = (args.get("cwd") or args.get("workdir") or os.getcwd()) if isinstance(args, dict) else os.getcwd()
        # Receipt every vault the call touched, not only the cwd's.
        roots = _scrub_roots(args, cwd) if isinstance(args, dict) else []
        for root in roots or [cwd]:
            _audit(tool_name, "executed", path=path, cwd=root)
        return None
    except Exception:
        return None


_POSTURE_SEEN = set()


def _workspace_posture_summary(cwd):
    root = _vault_root(cwd)
    if root is None:
        return "vault=none"
    policy, _policy_err = _load_policy_toml(str(root))
    profiles = sorted((policy.get("profiles") or {}).keys())
    sealed_cfg = bool((policy.get("vault") or {}).get("sealed_mode", False))
    env_present = any((root / name).is_file() for name in (".env", ".env.local", ".env.production"))
    return (
        f"vault=present | working_env={'plaintext_on_disk' if env_present else 'sealed_or_absent'} "
        f"| sealed_mode={sealed_cfg} | profiles={profiles or ['default']}"
    )


def on_tool_request(tool_name, args, original_args, **kwargs):
    """Middleware: default the session cwd into ciphervault_* calls
    that omitted it, and attach a one-time ambient workspace posture
    summary per session/vault so the agent starts aware of seal & policy state."""
    try:
        if tool_name and tool_name.startswith("ciphervault_") and isinstance(args, dict):
            eff_cwd = args.get("cwd") or os.getcwd()
            vault_root = _vault_root(eff_cwd)
            posture_note = ""
            if vault_root is not None:
                root_key = os.path.normcase(os.path.abspath(str(vault_root)))
                if root_key not in _POSTURE_SEEN:
                    _POSTURE_SEEN.add(root_key)
                    posture_note = f"; posture: {_workspace_posture_summary(eff_cwd)}"
            if not args.get("cwd") or posture_note:
                updated = dict(args)
                if not updated.get("cwd"):
                    updated["cwd"] = eff_cwd
                return {
                    "args": updated,
                    "source": "ciphervault",
                    "reason": f"defaulted cwd to the session working directory{posture_note}",
                }
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
                    result.error = "ciphervault binary not found. " + _COMPATIBLE_CLI_HINT
                    result.error_kind = ErrorKind.BINARY_MISSING
                    return result
                argv = [binary, "export-env"]
                if cfg.get("env_file"):
                    argv += ["--env-file", str(cfg["env_file"])]
                if cfg.get("allow_working_copy"):
                    argv.append("--allow-working-copy")
                # Minimal allowlisted env, stdin closed, timeout.
                env = _minimal_env()
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
            return (_COMPATIBLE_CLI_HINT + " Then run `ciphervault init` in your "
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
        "doctor": "ciphervault_env_doctor", "diff": "ciphervault_diff",
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
        "Usage: /ciphervault <status|scan|push|drill|doctor|diff|version|setup>\n"
        "Tools: ciphervault_status, ciphervault_scan, ciphervault_run, "
        "ciphervault_push, ciphervault_recovery_drill, ciphervault_redact, "
        "ciphervault_env_doctor, ciphervault_secret_generate, ciphervault_diff."
    )


def _qs_run(binary, args, cwd):
    proc = subprocess.run(
        [binary, *args], cwd=cwd, capture_output=True, text=True, timeout=300,
        env=_minimal_env(),
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def quickstart(progress=print, keep=False):
    """Two-minute guided demo: throwaway vault, fake secrets, sealed
    snapshot, RAM-only run dry-run, audit verify — then cleanup."""
    binary, _src = find_binary()
    if not binary:
        result = bootstrap_binary(progress=progress)
        if not result.get("success"):
            return result
        binary = result["binary"]
    demo = Path(tempfile.mkdtemp(prefix="cv-quickstart-"))
    try:
        (demo / ".env").write_text(
            "DEMO_API_KEY=sk-demo-0000000000000000000000000000fake\n"
            "DEMO_DB_URL=postgres://demo:demo-password-fake@localhost:5432/demo\n",
            encoding="utf-8",
        )
        steps = [
            ("1/5  Create a throwaway vault (kit saved inside the demo dir)",
             ["init", "--save-kit", str(demo / "recovery-kit.txt")]),
            ("2/5  Track the fake .env (it is git-ignored automatically)",
             ["track", ".env"]),
            ("3/5  Seal an encrypted snapshot (local only)",
             ["push", "--local", "-m", "quickstart demo"]),
            ("4/5  RAM-only run, dry-run: names only, values never printed",
             ["run", "--dry-run", "--", "echo", "demo"]),
            ("5/5  Verify the tamper-evident audit chain",
             ["agent-log", "verify"]),
        ]
        for label, args in steps:
            progress(f"\n== {label}\n$ ciphervault {' '.join(args)}")
            rc, out = _qs_run(binary, args, str(demo))
            progress(out.strip()[-1200:] or "(no output)")
            if rc != 0:
                return {"success": False, "error": f"step failed ({args[0]}): rc={rc}",
                        "demo_dir": str(demo)}
        progress(
            "\nThat's the loop: sealed snapshots, RAM-only injection, and an\n"
            "audit chain that proves what an agent touched. Real vault next:\n"
            "  cd your-project && ciphervault init && ciphervault track .env"
        )
        return {"success": True, "demo_dir": str(demo) if keep else None}
    finally:
        if not keep:
            shutil.rmtree(demo, ignore_errors=True)


_STARTER_POLICY_TOML = """\
[vault]
sealed_mode = {sealed_mode}
default_no_net = true

[profiles.test]
commands = ["pytest", "python", "npm", "npx", "node", "cargo", "vitest"]
allow_keys = ["DATABASE_URL", "REDIS_URL", "TEST_*"]
no_net = true

[profiles.llm_eval]
commands = ["python", "node"]
allow_keys = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]
proxy = true
"""


def _upsert_hermes_secret_source(config_path: Path, vault_path: str) -> dict:
    """Safely enable `secrets.ciphervault` in `$HERMES_HOME/config.yaml`
    without touching or logging any secret values."""
    existing = ""
    if config_path.is_file():
        existing = config_path.read_text(encoding="utf-8", errors="replace")
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(existing) if existing.strip() else {}
        if not isinstance(data, dict):
            return {"updated": False, "error": f"{config_path} is not a YAML mapping"}
        secrets_cfg = data.setdefault("secrets", {})
        if not isinstance(secrets_cfg, dict):
            return {"updated": False, "error": "config.yaml `secrets` section is not a mapping"}
        secrets_cfg["ciphervault"] = {
            "enabled": True,
            "vault_path": str(vault_path),
            "allow_working_copy": False,
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return {"updated": True, "path": str(config_path), "vault_path": str(vault_path)}
    except ImportError:
        if "ciphervault:" in existing:
            return {"updated": False, "already_configured": True, "path": str(config_path)}
        snippet = (
            f"\nsecrets:\n"
            f"  ciphervault:\n"
            f"    enabled: true\n"
            f"    vault_path: {json.dumps(str(vault_path))}\n"
            f"    allow_working_copy: false\n"
        )
        if re.search(r"(?m)^secrets:\s*$", existing):
            updated = re.sub(
                r"(?m)^secrets:\s*$",
                "secrets:\n  ciphervault:\n    enabled: true\n"
                f"    vault_path: {json.dumps(str(vault_path))}\n"
                "    allow_working_copy: false",
                existing,
                count=1,
            )
        else:
            updated = existing + snippet
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(updated, encoding="utf-8")
        return {"updated": True, "path": str(config_path), "vault_path": str(vault_path)}


def setup_workspace(
    cwd=None,
    sealed=True,
    bootstrap=True,
    wire_hermes_config=False,
    force=False,
    dry_run=False,
    progress=print,
):
    """One-command setup wizard: verify/bootstrap binary, scaffold
    `.ciphervault/policy.toml` inside an initialized vault, and optionally
    wire `secrets.ciphervault` in `$HERMES_HOME/config.yaml`."""
    target_dir = Path(cwd or os.getcwd()).resolve()
    binary, source = find_binary()
    binary_info = {"binary": binary, "source": source, "bootstrapped": False}
    if not binary:
        if bootstrap and not dry_run:
            boot = bootstrap_binary(progress=progress)
            if not boot.get("success"):
                return {
                    "success": False,
                    "step": "bootstrap",
                    "error": boot.get("error", "binary bootstrap failed"),
                    "binary": binary_info,
                }
            binary = boot.get("binary")
            binary_info = {"binary": binary, "source": "bootstrapped", "bootstrapped": True}
        elif bootstrap and dry_run:
            binary_info["action"] = "would_bootstrap"
        else:
            return {
                "success": False,
                "step": "binary",
                "error": "ciphervault binary not found (run without --no-bootstrap or set CIPHERVAULT_BIN)",
                "binary": binary_info,
            }

    vault_root = _vault_root(str(target_dir))
    policy_info = {"written": False, "path": None}
    next_steps = []

    if vault_root is None:
        next_steps.append(
            f"Initialize a vault in your terminal: cd {target_dir} && ciphervault init && ciphervault track .env && ciphervault push --local --shred"
        )
    else:
        policy_path = Path(vault_root) / ".ciphervault" / "policy.toml"
        policy_info["path"] = str(policy_path)
        if policy_path.exists() and not force:
            policy_info["already_exists"] = True
        elif dry_run:
            policy_info["action"] = "would_write"
        else:
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            policy_path.write_text(
                _STARTER_POLICY_TOML.format(sealed_mode="true" if sealed else "false"),
                encoding="utf-8",
            )
            policy_info["written"] = True

    hermes_cfg_path = _hermes_home() / "config.yaml"
    hermes_info = {"path": str(hermes_cfg_path), "updated": False}
    if wire_hermes_config:
        vault_ref = str(vault_root or target_dir)
        if dry_run:
            hermes_info["action"] = "would_wire_secret_source"
            hermes_info["vault_path"] = vault_ref
        else:
            hermes_info = _upsert_hermes_secret_source(hermes_cfg_path, vault_ref)
            if hermes_info.get("error"):
                return {
                    "success": False,
                    "step": "wire_hermes",
                    "error": hermes_info["error"],
                    "binary": binary_info,
                    "policy": policy_info,
                    "hermes_secret_source": hermes_info,
                }
    else:
        next_steps.append(
            "Optional: re-run with `--wire-hermes` to configure Hermes's own `secrets.ciphervault` source."
        )

    return {
        "success": True,
        "dry_run": bool(dry_run),
        "cwd": str(target_dir),
        "vault_initialized": vault_root is not None,
        "vault_root": str(vault_root) if vault_root is not None else None,
        "binary": binary_info,
        "policy": policy_info,
        "hermes_secret_source": hermes_info,
        "next_steps": next_steps,
    }


def _cli_setup(parser):
    # Hermes hands us the `hermes ciphervault` subparser itself.
    sp = parser.add_subparsers(dest="ciphervault_cmd")
    sp.add_parser("bootstrap", help="Download + verify the pinned CipherVault binary")
    sp.add_parser("status", help="Binary resolution + vault status for the cwd")
    sp.add_parser("doctor", help="Check binary, vault, and wiring")
    qs = sp.add_parser("quickstart", help="Two-minute guided demo in a throwaway vault")
    qs.add_argument("--keep", action="store_true", help="Keep the demo directory")
    su = sp.add_parser("setup", help="Setup wizard: binary + .ciphervault/policy.toml + Hermes secret source")
    su.add_argument("--cwd", default=None, help="Target workspace directory (default: current directory)")
    su.add_argument("--no-bootstrap", action="store_true", help="Do not download binary if missing")
    su.add_argument("--unsealed", action="store_true", help="Set sealed_mode = false in starter policy.toml")
    su.add_argument("--wire-hermes", action="store_true", help="Enable secrets.ciphervault in $HERMES_HOME/config.yaml")
    su.add_argument("--force", action="store_true", help="Overwrite existing .ciphervault/policy.toml")
    su.add_argument("--dry-run", action="store_true", help="Show planned setup actions without writing files")


def _cli_handler(args):
    cmd = getattr(args, "ciphervault_cmd", None) or "status"
    if cmd == "bootstrap":
        result = bootstrap_binary()
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    if cmd == "setup":
        result = setup_workspace(
            cwd=getattr(args, "cwd", None),
            sealed=not bool(getattr(args, "unsealed", False)),
            bootstrap=not bool(getattr(args, "no_bootstrap", False)),
            wire_hermes_config=bool(getattr(args, "wire_hermes", False)),
            force=bool(getattr(args, "force", False)),
            dry_run=bool(getattr(args, "dry_run", False)),
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    if cmd == "quickstart":
        result = quickstart(keep=bool(getattr(args, "keep", False)))
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    if cmd == "doctor":
        result = binary_diagnostics(os.getcwd())
        status = _run_cli_json(["status", "--json"], os.getcwd())
        result["status"] = status
        result["success"] = bool(result["success"] and status.get("success"))
        print(json.dumps(result, indent=2))
        return 0 if result["success"] else 1
    binary, source = find_binary()
    print(f"binary: {binary or 'missing'} ({source})")
    result = _run_cli_json(["status", "--json"], os.getcwd())
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


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
      "profile": {"type": "string", "description": "Optional execution profile name defined in .ciphervault/policy.toml"},
      "env_file": {"type": "string"}, "project": {"type": "string"}, "env": {"type": "string"},
      "allow_keys": {"type": "array", "items": {"type": "string"}, "description": "Optional allowlist of variable names to inject (least-privilege scoping)"},
      "no_net": {"type": "boolean", "description": "Block child outbound/inbound network access (defaults true on Linux, macOS, and Windows)"},
      "proxy": {"type": "boolean", "default": False, "description": "Run loopback credential proxy in parent so real API keys never enter child env"},
      "proxy_upstream": {"type": "array", "items": {"type": "string"}, "description": "Optional VAR=https://host[@HeaderName] mappings for proxy mode (public HTTPS non-provider hosts unless pinned in .ciphervault/policy.toml)"},
      "dry_run": {"type": "boolean", "default": False, "description": "List variable names without executing"},
      "cwd": {"type": "string"}}),
    ("ciphervault_push", _tool_push,
     "Create an encrypted snapshot of tracked secret files (client-side sealed; operators store ciphertext only). Local by default; local_only=false replicates to configured operators.",
     {"message": {"type": "string", "default": "Agent snapshot"},
      "local_only": {"type": "boolean", "default": True},
      "shred_working_copy": {"type": "boolean", "description": "Zero-fill and remove tracked plaintext files from the working directory after sealing the snapshot (defaults to [vault].sealed_mode in policy.toml)"},
      "cwd": {"type": "string"}}),
    ("ciphervault_recovery_drill", _tool_drill,
     "Prove a recovery kit or guardian shares actually restore: restores into a fresh temp dir created by the tool, returns a SHA-256 manifest (names+sizes+hashes only), then deletes that temp dir. Takes FILE PATHS only — never accept kit/share contents.",
     {"kit": {"type": "string", "description": "Path to kit file on disk"},
      "shares": {"type": "array", "items": {"type": "string"}, "description": "Paths to guardian share files"},
      "via": {"type": "array", "items": {"type": "string"},
              "description": "Configured operator URLs to query instead of the endpoints printed in the kit (must belong to this vault's configured operator list and pass URL safety checks; private, loopback, link-local, and cloud-metadata hosts are refused)"},
      "cwd": {"type": "string"}}),
    ("ciphervault_redact", _tool_redact,
     "Redact secret material from text before using it anywhere: vault values matched exactly (inside the CLI), plus credential shapes. Returns masked text + redaction count.",
     {"text": {"type": "string"}, "cwd": {"type": "string"}}),
    ("ciphervault_audit", _tool_audit,
     "Show the tamper-evident agent audit log: what tools did around this vault's secrets (blocked reads, approval requests, scrubbed results, writes) plus chain verification. With check_text, proves whether that exact output passed the scrub (hash lookup). Paths/decisions/counts only.",
     {"limit": {"type": "integer", "default": 50},
      "check_text": {"type": "string", "description": "Output text to check against the scrub log (hashed locally)"},
      "cwd": {"type": "string"}}),
    ("ciphervault_env_doctor", _tool_env_doctor,
     "Zero-knowledge environment diagnostics: cross-reference env vars referenced in code and .env.example against vault keys and inspect .env* files in-memory for structural issues (empty, whitespace-wrapped, unstripped quotes, placeholders, invalid URLs/JSON, prefix mismatches). Never returns secret values.",
     {"env_file": {"type": "string", "description": "Optional specific .env file relative to cwd"},
      "sync_env_example": {"type": "boolean", "default": False, "description": "Safely create/update .env.example with KEY= # [required] placeholders"},
      "cwd": {"type": "string"}}),
    ("ciphervault_secret_generate", _tool_secret_generate,
     "Generate a cryptographically random secret inside the vault without exposing the value to chat or logs. Returns only name, format, length, and SHA-256 prefix.",
     {"name": {"type": "string", "description": "Environment variable name ([A-Za-z_][A-Za-z0-9_]*)"},
      "format": {"type": "string", "enum": ["base64url", "hex", "uuid", "alphanumeric"], "default": "base64url"},
      "bytes": {"type": "integer", "default": 32, "description": "Entropy length in bytes (16..64)"},
      "env_file": {"type": "string", "default": ".env"},
      "seal": {"type": "boolean", "description": "Shred the plaintext working copy after pushing the encrypted snapshot"},
      "cwd": {"type": "string"}}),
    ("ciphervault_diff", _tool_diff,
     "Compare key-level secret changes between snapshots or against the working tree (always masked; never reveals plaintext values).",
     {"snapshot_a": {"type": "string", "description": "Old snapshot ID or 'head'/'working'"},
      "snapshot_b": {"type": "string", "description": "New snapshot ID or 'head'/'working'"},
      "file": {"type": "string", "description": "Limit diff to a specific relative file path"},
      "cwd": {"type": "string"}}),
    ("ciphervault_proxy_doctor", _tool_proxy_doctor,
     "Dry-run proxy route diagnostic: report which vault keys map to built-in provider routes vs .ciphervault/policy.toml upstreams vs unmapped keys. Never exposes secret values.",
     {"env_file": {"type": "string"},
      "profile": {"type": "string", "description": "Optional profile name from .ciphervault/policy.toml"},
      "cwd": {"type": "string"}}),
    ("ciphervault_secret_prompt", _tool_secret_prompt,
     "Queue a secure secret input prompt in the CipherVault desktop pane (or interactive TTY) so the user can supply missing API keys or credentials without pasting secrets into chat.",
     {"keys": {"type": "array",
               "items": {"oneOf": [
                   {"type": "string"},
                   {"type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "reason": {"type": "string"},
                        "expected_prefix": {"type": "string"},
                    },
                    "required": ["name"]},
               ]},
               "description": "List of secret key names or {name, reason?, expected_prefix?} objects to request"},
      "env_file": {"type": "string", "default": ".env"},
      "seal": {"type": "boolean", "default": True, "description": "Shred the plaintext working copy after pushing the encrypted snapshot"},
      "cwd": {"type": "string"}}),
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
        required = (
            ["command"] if name == "ciphervault_run"
            else ["text"] if name == "ciphervault_redact"
            else ["name"] if name == "ciphervault_secret_generate"
            else ["keys"] if name == "ciphervault_secret_prompt"
            else []
        )
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
    ctx.register_hook("post_tool_call", on_post_tool_call)
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
