"""Binary resolution, checksum-pinned bootstrap, local shape scrubbing, and CLI diagnostics."""

from __future__ import annotations

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

from . import _runtime

_self = sys.modules[__name__]

PLUGIN_DIR = _runtime.PLUGIN_DIR
RELEASE_VERSION = "1.0.37"
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
        "a9e23344b6da3b6c3731e7da17e7c58da7e1399c6b52039efe87c505cdd99dc4",
    ),
    "linux-amd64": (
        "ciphervault-linux-amd64",
        "fd9d2ffd3364eb9c54cc76907378eb51e92faf5275b9edb44810c4dfd90fca21",
    ),
    "macos-arm64": (
        "ciphervault-macos-arm64",
        "43dd46c0bd06573869a0cfa820f22ba5a93cf09c97e11340d5f9c680978d5c1a",
    ),
    "macos-amd64": (
        "ciphervault-macos-amd64",
        "59fa2600e442cb17a0fd44eca0b57ed1ca8c89e90a85b1b01d707b1153f19a38",
    ),
}
# Backward-compatible alias for the Windows pin.
RELEASE_BINARY_SHA256 = RELEASE_ASSETS["windows-amd64"][1]
# Whether the pinned release ships `redact --json`'s
# `exact_values_complete` attestation, which this plugin requires before
# releasing vault-scoped output. v1.0.35 does; bootstrap refuses any pin
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


def _hermes_home_resolver():
    """Hermes's own home resolver, which also handles profiles, or None
    outside Hermes (unit tests, the standalone dashboard process)."""
    try:
        from hermes_constants import get_hermes_home  # type: ignore
    except Exception:
        return None
    return get_hermes_home


def _hermes_home() -> Path:
    resolver = _runtime.resolve(_self, "_hermes_home_resolver")()
    if resolver is not None:
        try:
            home = resolver()
            if home:
                return Path(home)
        except Exception:
            pass
    return Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))


def _data_bin_dir() -> Path:
    return _hermes_home() / "plugins" / "ciphervault" / "bin"


def _read_configured_binary_path() -> str | None:
    """Read `binary_path` from the active Hermes plugin context, falling back
    to on-disk Hermes plugin config when invoked from a standalone dashboard process."""
    ctx = _runtime._ctx.get("ctx")
    if ctx is not None:
        try:
            configured = ctx.get_config("binary_path", "")
            if configured and str(configured).strip():
                return str(configured).strip()
        except Exception:
            pass
    home = _hermes_home()
    for cfg_json in (
        home / "plugins" / "ciphervault" / "config.json",
        home / "plugin_config" / "ciphervault.json",
    ):
        try:
            if cfg_json.is_file():
                data = json.loads(cfg_json.read_text(encoding="utf-8", errors="replace") or "{}")
                if isinstance(data, dict) and data.get("binary_path"):
                    return str(data["binary_path"]).strip()
        except Exception:
            pass
    cfg_yaml = home / "config.yaml"
    try:
        if cfg_yaml.is_file():
            raw = cfg_yaml.read_text(encoding="utf-8", errors="replace")
            if "binary_path" in raw and "ciphervault" in raw:
                try:
                    import yaml  # type: ignore

                    parsed = yaml.safe_load(raw)
                    if isinstance(parsed, dict):
                        for section in ("plugins", "plugin_config"):
                            entry = (parsed.get(section) or {}).get("ciphervault")
                            if isinstance(entry, dict) and entry.get("binary_path"):
                                return str(entry["binary_path"]).strip()
                except Exception:
                    pass
    except Exception:
        pass
    return None


def find_binary():
    """Resolve the ciphervault CLI: configured `binary_path`, `$CIPHERVAULT_BIN`,
    bootstrapped copy, repo checkout (dev), then PATH (`ciphervault` only —
    never an unrelated `cv` binary). Returns (path|None, source)."""
    configured = _read_configured_binary_path()
    for override in (configured, os.environ.get("CIPHERVAULT_BIN")):
        if override and Path(override).is_file():
            return str(override), "configured"
    exe = "ciphervault.exe" if os.name == "nt" else "ciphervault"
    bootstrapped = _runtime.resolve(_self, "_data_bin_dir")() / exe
    if bootstrapped.is_file():
        return str(bootstrapped), "bootstrapped"
    roots = [PLUGIN_DIR.parents[1]]
    if len(PLUGIN_DIR.parents) > 2:
        roots.append(PLUGIN_DIR.parents[2])
    for root in roots:
        for cand in (
            root / "dist" / "bin" / exe,
            root / "target" / "debug" / exe,
            root / "target" / "release" / exe,
        ):
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
    the connection drops mid-transfer. Integrity is NOT established here:
    the caller verifies the assembled bytes against the SHA-256 pinned in source."""
    attempts = int(_runtime.resolve(_self, "_DOWNLOAD_ATTEMPTS"))
    retry_delay = _runtime.resolve(_self, "_DOWNLOAD_RETRY_DELAY")
    data = bytearray()
    last_error = None
    for attempt in range(1, attempts + 1):
        headers = {"Range": f"bytes={len(data)}-"} if data else {}
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=300) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                if data and (status != 206 or _content_range_start(resp) != len(data)):
                    data.clear()  # server ignored or misanswered Range: start over
                    if status == 206:
                        raise OSError("server answered the resume with a different byte range")
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
            if attempt < attempts:
                reason = str(exc) or type(exc).__name__
                progress(
                    f"Download interrupted at {len(data)} bytes ({reason}); "
                    f"resuming (attempt {attempt + 1}/{attempts})…"
                )
                time.sleep(retry_delay * attempt)
    raise OSError(
        f"{str(last_error) or type(last_error).__name__} "
        f"(gave up after {attempts} attempts)"
    )


def _install_bootstrapped_binary(dest: Path, data: bytes) -> None:
    """Install verified bytes without truncating a binary that may be running.

    The bytes are staged beside the destination and renamed into place.
    Windows permits renaming a running executable but not overwriting it;
    when the direct replace is denied, move the live executable aside first
    (the running process keeps its image) and restore it if staging fails.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=dest.parent, prefix=f".{dest.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            tmp.chmod(0o755)
        try:
            os.replace(tmp, dest)
            return
        except PermissionError:
            if os.name != "nt" or not dest.exists():
                raise

        backup = dest.with_name(f"{dest.name}.pre-bootstrap.bak")
        if backup.exists():
            backup = dest.with_name(f"{dest.name}.pre-bootstrap-{os.getpid()}.bak")
        dest.rename(backup)
        try:
            tmp.rename(dest)
        except Exception:
            backup.rename(dest)
            raise
        try:
            backup.unlink()
        except OSError:
            pass
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def bootstrap_binary(progress=print):
    """Download the pinned upstream release binary and verify it
    against the release SHA256SUMS.txt before installing it into the
    plugin data dir. User-invoked setup action (CLI/slash command);
    never runs automatically at plugin load (catalog rule 3/17)."""
    if not _runtime.resolve(_self, "RELEASE_SUPPORTS_GUARD"):
        return {
            "success": False,
            "error": (
                f"The pinned CipherVault v{RELEASE_VERSION} release is incompatible with "
                "this plugin: it predates the complete exact-value redaction attestation. "
                "Nothing was downloaded or replaced."
            ),
            "next": _COMPATIBLE_CLI_HINT,
        }
    selected = _runtime.resolve(_self, "_release_asset")()
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
    dest_dir = _runtime.resolve(_self, "_data_bin_dir")()
    dest = dest_dir / dest_name
    try:
        _install_bootstrapped_binary(dest, data)
    except OSError as exc:
        return {"success": False, "error": f"install failed: {exc}"}
    try:
        alias = dest_dir / ("cv.exe" if os.name == "nt" else "cv")
        _install_bootstrapped_binary(alias, data)
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
    if "-----END" in text:
        text = _PEM_RE.sub("[REDACTED] PRIVATE KEY", text)
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _URL_RE.sub(r"\1[REDACTED]\2", text)
    text = _TOKEN_RE.sub("[REDACTED]", text)
    return _KV_RE.sub(r"\1[REDACTED]", text)


# ---------------------------------------------------------------- minimal env

_ENV_KEEP = (
    "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR",
    "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
    "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT",
)


def _minimal_env() -> dict[str, str]:
    """Environment for CLI subprocesses: an allow-list, so Hermes
    provider keys (OPENAI_API_KEY etc.) never reach the CLI or the
    children it spawns. CipherVault's own CIPHERVAULT_* config passes."""
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}
    env.update({k: v for k, v in os.environ.items() if k.startswith("CIPHERVAULT_")})
    env.setdefault("NO_COLOR", "1")
    return env


# ---------------------------------------------------------------- capabilities & diagnostics

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

_CLI_PROFILE_SUPPORT: dict[str, bool] = {}
_ENV_DOCTOR_SUPPORT_CACHE: dict[str, bool] = {}
_VAULT_SECRET_SUPPORT_CACHE: dict[str, bool] = {}


def _cli_supports_run_profile() -> bool:
    """Return True if the active ciphervault binary accepts `run --profile`
    (or if no binary is resolved yet, so mocked unit tests see `--profile`)."""
    binary, _source = _runtime.resolve(_self, "find_binary")()
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


def _cli_supports_env_doctor(cwd=None) -> bool:
    """True when the resolved native CLI binary supports `ciphervault env-doctor --json`."""
    from . import bridge

    if (
        _runtime.resolve(bridge, "_run_cli") is not bridge._ORIG_RUN_CLI
        or _runtime.resolve(bridge, "_run_cli_json") is not bridge._ORIG_RUN_CLI_JSON
    ):
        return False
    binary, _src = _runtime.resolve(_self, "find_binary")()
    if not binary:
        return False
    cached = _ENV_DOCTOR_SUPPORT_CACHE.get(binary)
    if cached is not None:
        return cached
    probe = bridge._ORIG_RUN_CLI(["env-doctor", "--help"], cwd, timeout=10)
    ok = bool(probe.get("success") and "--sync-env-example" in (probe.get("output") or ""))
    _ENV_DOCTOR_SUPPORT_CACHE[binary] = ok
    return ok


def _cli_supports_vault_secret(cwd=None) -> bool:
    """True when the resolved native CLI binary supports in-vault mutations
    (`ciphervault vault set|generate|unset` with `--overwrite`, `--seal`, `--json`)."""
    from . import bridge

    if (
        _runtime.resolve(bridge, "_run_cli") is not bridge._ORIG_RUN_CLI
        or _runtime.resolve(bridge, "_run_cli_json") is not bridge._ORIG_RUN_CLI_JSON
    ):
        return False
    binary, _src = _runtime.resolve(_self, "find_binary")()
    if not binary:
        return False
    cached = _VAULT_SECRET_SUPPORT_CACHE.get(binary)
    if cached is not None:
        return cached
    probe = bridge._ORIG_RUN_CLI(["vault", "generate", "--help"], cwd, timeout=10)
    out = probe.get("output") or ""
    ok = bool(
        probe.get("success")
        and "--overwrite" in out
        and "--seal" in out
        and "--json" in out
    )
    _VAULT_SECRET_SUPPORT_CACHE[binary] = ok
    return ok


def binary_diagnostics(cwd=None):
    """Read-only version/help probes of the binary actually resolved.

    A working `status --json` alone is insufficient: older CLIs lack
    the exact scrub, JSON run, and signed-audit commands. Version drift
    is reported separately; capabilities, not a version guess, gate
    compatibility. This never bootstraps or changes the active binary.
    """
    from . import bridge

    binary, source = _runtime.resolve(_self, "find_binary")()
    out = {
        "success": False,
        "binary": binary,
        "binary_source": source,
        "plugin_version": _runtime.PLUGIN_VERSION,
        "target_cli_version": RELEASE_VERSION,
        "installed_version": None,
        "version_matches_target": False,
        "capabilities": {},
        "missing_capabilities": [],
    }
    remediation = (
        _COMPATIBLE_CLI_HINT
        + " Vault outputs remain withheld until exact scrubbing and audit receipts work."
    )
    if not binary:
        out.update(error="ciphervault binary not found", next=remediation)
        return out
    run_cli_fn = _runtime.resolve(bridge, "_run_cli")
    run_cli_json_fn = _runtime.resolve(bridge, "_run_cli_json")
    version = run_cli_fn(["--version"], cwd, timeout=20)
    if version.get("success"):
        match = re.search(
            r"(?m)^ciphervault(?:\.exe)?\s+(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)\s*$",
            version.get("output", ""),
        )
        if match:
            out["installed_version"] = match.group(1)
    out["version_matches_target"] = out["installed_version"] == RELEASE_VERSION
    for command, flags in _CLI_CAPABILITIES:
        name = " ".join(command)
        probe = run_cli_fn([*command, "--help"], cwd, timeout=20)
        help_text = probe.get("output", "")
        missing = [
            flag
            for flag in flags
            if not re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])", help_text)
        ]
        supported = bool(probe.get("success") and not missing)
        capability = {"supported": supported, "missing_flags": missing}
        if not probe.get("success"):
            capability["error"] = probe.get("error", "help probe failed")
        out["capabilities"][name] = capability
        if not supported:
            out["missing_capabilities"].append(name)
    complete = False
    if out["capabilities"].get("redact", {}).get("supported"):
        with tempfile.TemporaryDirectory(prefix="cv-doctor-") as empty:
            probe = run_cli_json_fn(
                ["redact", "--json"], empty, timeout=10, input_text="cv doctor probe"
            )
        complete = bool(
            probe.get("success")
            and bridge._complete_redact_response(probe.get("data"))
        )
    out["capabilities"]["redact completeness"] = {
        "supported": complete,
        "missing_flags": [],
    }
    if not complete:
        out["missing_capabilities"].append("redact completeness")
    out["success"] = bool(out["installed_version"] and not out["missing_capabilities"])
    if not out["version_matches_target"]:
        out["warning"] = (
            f"Resolved CLI version {out['installed_version'] or 'unknown'} differs "
            f"from the plugin's pinned CLI target {RELEASE_VERSION}."
        )
    if not out["success"]:
        out.update(
            error="resolved CipherVault CLI is incompatible or could not be inspected",
            next=remediation,
        )
    return out
