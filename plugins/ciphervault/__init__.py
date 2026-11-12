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
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

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


def _run_cli(args, cwd, timeout=120, input_text=None):
    binary, source = find_binary()
    if not binary:
        return {
            "success": False,
            "error": "ciphervault binary not found",
            "binary": "missing",
            "next": _COMPATIBLE_CLI_HINT,
        }
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
            env=_minimal_env(),
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
        args = ["agent-log", "record", "--tool", str(tool), "--decision", str(decision)]
        if path:
            args += ["--path", str(path)[:300]]
        if detail:
            args += ["--detail", json.dumps(detail)[:500]]
        res = _run_cli(args, _vault_cwd(cwd), timeout=10)
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
    res = _run_cli_json(["redact", "--json"], _vault_cwd(cwd), timeout=timeout,
                        input_text=text)
    if res.get("success"):
        data = res.get("data")
        if _complete_redact_response(data, require_vault=_vault_present(cwd)):
            return data["text"], data["redactions"], True
    return scrub(text), 0, False


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
    res = _run_cli_json(args, params.get("cwd"), timeout=300)
    if params.get("dry_run"):
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
    if _audit("ciphervault_run", "scrubbed_result", detail=detail, cwd=params.get("cwd")):
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
    args = ["push", "-m", params.get("message", "Agent snapshot")]
    if params.get("local_only", True):
        args.append("--local")
    res = _run_cli(args, params.get("cwd"), timeout=300)
    if res.get("success"):
        res["output"] = scrub(res["output"])
    return json.dumps(res)


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


def _tool_drill(params, **kwargs):
    params = params or {}
    kit = params.get("kit")
    shares = params.get("shares") or []
    if not kit and not shares:
        return json.dumps({
            "success": False,
            "error": "provide kit (path to kit file) or shares (list of share file paths). Paths only — never paste kit contents.",
        })
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
        via = params.get("via") or []
        if isinstance(via, str):
            via = [via]
        if via:
            # The kit keeps the operators from when it was printed; a vault
            # that moved fleets is recovered through its current operators.
            # Records stay authenticated by the kit's recovery key.
            args += ["--via"] + [str(endpoint) for endpoint in via]
        res = _run_cli(args, params.get("cwd"), timeout=300)
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
    r"(?i)(^|[\s\\/\"'=])(\.env(\.[\w.-]*)?|[\w.-]+\.(pem|key)|id_rsa|id_ed25519|"
    r"credentials\.json|secrets\.json|"
    # Source/docs about kits (recovery_kit.rs, recovery_kit.md) are not kits.
    r"recovery_kit(?![\w-]*\.(?:rs|py|pyi|js|jsx|ts|tsx|go|java|kt|swift|c|cc|cpp|h|hpp|cs|rb|php|md|toml|ya?ml|lock)\b)[\w.-]*|"
    r"[\w.-]+\.kit|[\w.-]*share[\w.-]*\.txt)"
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
        if tool_name == "ciphervault_run":
            # Running an arbitrary command with vault secrets in its
            # environment must go through Hermes's human-approval gate
            # (same gate as dangerous shell commands). Output scrubbing
            # alone cannot stop a command from exfiltrating the values
            # it was given. Every ciphervault_run call is gated.
            _audit("ciphervault_run", "approval_requested",
                   detail={"program": ((args or {}).get("command") or [""])[0]},
                   cwd=(args or {}).get("cwd") or os.getcwd())
            # Cadence: checkpoint the chain head — this grant included —
            # to the fleet BEFORE the approved command can run, so a
            # run that goes badly cannot rewrite the grant away.
            _anchor_async((args or {}).get("cwd") or os.getcwd())
            # Narrow grant grain: the rule key names the program, so a
            # session/always grant in Hermes's approval UI covers that
            # program only — never every command the model may run.
            program = str(((args or {}).get("command") or ["run"])[0])
            return {"action": "approve",
                    "message": ("CipherVault: run a command with vault secrets "
                                "injected in RAM? The command receives the values; "
                                "approve only if you trust it."),
                    "rule_key": f"ciphervault_run:{program}"}
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
                    _audit(tool_name, "blocked", path=text[:300],
                           detail={"reason": "secret_file_read"}, cwd=cwd)
                    return {"action": "block", "message": (
                        "CipherVault guard: reading a secret/kit file into the chat would leak it. "
                        "Use ciphervault_run (RAM-only injection), ciphervault_redact (masked), or "
                        "ciphervault_status (names only). Paths are fine; contents are not."
                    )}

        joined = "\n".join(texts)
        if joined:
            # Check against every vault the call touches, not only the
            # cwd's (vaultless calls still get the CLI's shape pass).
            for root in _scrub_roots(args, cwd) or [cwd]:
                cleaned, n, _exact = cli_redact(joined, root, timeout=10)
                if n > 0 or cleaned != joined:
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
        oversized = len(result) > 262_144
        sample = result[:262_144] if oversized else result
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
        # Each vault the call touches scrubs its own exact values; the
        # passes chain, and any one failing withholds the result.
        cleaned, n = sample, 0
        for root in roots:
            cleaned, n_root, exact = cli_redact(cleaned, root, timeout=10)
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


def _cli_setup(parser):
    # Hermes hands us the `hermes ciphervault` subparser itself.
    sp = parser.add_subparsers(dest="ciphervault_cmd")
    sp.add_parser("bootstrap", help="Download + verify the pinned CipherVault binary")
    sp.add_parser("status", help="Binary resolution + vault status for the cwd")
    sp.add_parser("doctor", help="Check binary, vault, and wiring")
    qs = sp.add_parser("quickstart", help="Two-minute guided demo in a throwaway vault")
    qs.add_argument("--keep", action="store_true", help="Keep the demo directory")


def _cli_handler(args):
    cmd = getattr(args, "ciphervault_cmd", None) or "status"
    if cmd == "bootstrap":
        result = bootstrap_binary()
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
      "env_file": {"type": "string"}, "project": {"type": "string"}, "env": {"type": "string"},
      "dry_run": {"type": "boolean", "default": False, "description": "List variable names without executing"},
      "cwd": {"type": "string"}}),
    ("ciphervault_push", _tool_push,
     "Create an encrypted snapshot of tracked secret files (client-side sealed; operators store ciphertext only). Local by default; local_only=false replicates to configured operators.",
     {"message": {"type": "string", "default": "Agent snapshot"},
      "local_only": {"type": "boolean", "default": True}, "cwd": {"type": "string"}}),
    ("ciphervault_recovery_drill", _tool_drill,
     "Prove a recovery kit or guardian shares actually restore: restores into a fresh temp dir created by the tool, returns a SHA-256 manifest (names+sizes+hashes only), then deletes that temp dir. Takes FILE PATHS only — never accept kit/share contents.",
     {"kit": {"type": "string", "description": "Path to kit file on disk"},
      "shares": {"type": "array", "items": {"type": "string"}, "description": "Paths to guardian share files"},
      "via": {"type": "array", "items": {"type": "string"},
              "description": "Current operator URLs to query instead of the endpoints printed in the kit (use when the vault moved fleets after the kit was made)"},
      "cwd": {"type": "string"}}),
    ("ciphervault_redact", _tool_redact,
     "Redact secret material from text before using it anywhere: vault values matched exactly (inside the CLI), plus credential shapes. Returns masked text + redaction count.",
     {"text": {"type": "string"}, "cwd": {"type": "string"}}),
    ("ciphervault_audit", _tool_audit,
     "Show the tamper-evident agent audit log: what tools did around this vault's secrets (blocked reads, approval requests, scrubbed results, writes) plus chain verification. With check_text, proves whether that exact output passed the scrub (hash lookup). Paths/decisions/counts only.",
     {"limit": {"type": "integer", "default": 50},
      "check_text": {"type": "string", "description": "Output text to check against the scrub log (hashed locally)"},
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
