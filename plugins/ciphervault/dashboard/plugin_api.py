"""CipherVault dashboard backend, mounted at /api/plugins/ciphervault/.

Serves workspace vault status to the desktop pane / dashboard tab via
`ctx.rest`. Values are never served: `ciphervault status --json`
reports tracked file paths, counts, and truncated identifiers only,
and every response here passes through the same allow-list.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

try:
    from fastapi import APIRouter, Body
except Exception:  # pragma: no cover - dashboard host always has fastapi
    APIRouter = None
    Body = None

router = APIRouter() if APIRouter is not None else None


def _find_binary():
    exe = "ciphervault.exe" if os.name == "nt" else "ciphervault"
    override = os.environ.get("CIPHERVAULT_BIN")
    if override and Path(override).is_file():
        return override
    home = Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))
    bootstrapped = home / "plugins" / "ciphervault" / "bin" / exe
    if bootstrapped.is_file():
        return str(bootstrapped)
    import shutil

    return shutil.which("ciphervault") or shutil.which("cv")


_ENV_KEEP = (
    "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR",
    "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
    "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT",
)


def _minimal_env() -> dict[str, str]:
    """Allow-listed subprocess environment so Hermes provider keys never
    reach the CLI subprocesses."""
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}
    env.update({k: v for k, v in os.environ.items() if k.startswith("CIPHERVAULT_")})
    env.setdefault("NO_COLOR", "1")
    return env


def _safe_cwd(cwd: str | None) -> str | None:
    """Validate workspace cwd against UNC/network coercion and require a
    real directory on disk."""
    if cwd is None or not str(cwd).strip():
        return os.getcwd()
    raw = str(cwd).strip()
    if raw.startswith("\\\\") or raw.startswith("//") or "\x00" in raw:
        return None
    try:
        resolved = Path(raw).resolve()
        if not resolved.is_dir():
            return None
        return str(resolved)
    except OSError:
        return None


def _status(cwd: str | None) -> dict:
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"binary": "error", "vault": False, "error": "invalid or non-directory cwd"}
    binary = _find_binary()
    if not binary:
        return {
            "binary": "missing",
            "vault": False,
            "next": "Run `hermes ciphervault bootstrap` (Windows) or set CIPHERVAULT_BIN.",
        }
    try:
        proc = subprocess.run(
            [binary, "status", "--json"],
            cwd=safe_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            env=_minimal_env(),
        )
    except Exception as exc:
        return {"binary": "error", "vault": False, "error": str(exc)[:200]}
    try:
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return {"binary": "error", "vault": False, "error": "non-JSON status output"}
    # Allow-list: never forward anything beyond status metadata.
    keep = (
        "vault", "cli_version", "tracked_paths", "tracked_files",
        "vault_id_short", "device_id_short", "active_head_short",
        "current_epoch", "pending_uploads",
        "working_tree_sealed", "working_tree_plaintext_files",
    )
    out = {k: data.get(k) for k in keep if k in data}
    out["binary"] = "ok"
    out["operators"] = len(data.get("operators") or [])
    if data.get("error"):
        out["error"] = str(data["error"])[:200]
    return out


def _seal(cwd: str | None) -> dict:
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"binary": "error", "vault": False, "error": "invalid or non-directory cwd"}
    binary = _find_binary()
    if not binary:
        return {
            "binary": "missing",
            "vault": False,
            "next": "Run `hermes ciphervault bootstrap` (Windows) or set CIPHERVAULT_BIN.",
        }
    try:
        proc = subprocess.run(
            [binary, "push", "--local", "--shred", "-m", "Sealed from Hermes desktop"],
            cwd=safe_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            env=_minimal_env(),
        )
    except Exception as exc:
        return {"binary": "error", "vault": False, "error": str(exc)[:200]}
    status_out = _status(safe_cwd)
    if proc.returncode != 0:
        err_msg = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
        status_out["error"] = err_msg[:200]
    return status_out


def _audit_trail(cwd: str | None, limit: int = 10) -> dict:
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"success": False, "error": "invalid or non-directory cwd", "entries": []}
    binary = _find_binary()
    if not binary:
        return {
            "success": False,
            "binary": "missing",
            "error": "ciphervault binary not found",
            "entries": [],
        }
    bounded_limit = max(1, min(100, int(limit)))
    env = _minimal_env()
    try:
        show_proc = subprocess.run(
            [binary, "agent-log", "show", "--json", "--limit", str(bounded_limit)],
            cwd=safe_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            env=env,
        )
        verify_proc = subprocess.run(
            [binary, "agent-log", "verify", "--json"],
            cwd=safe_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            env=env,
        )
    except Exception as exc:
        return {"success": False, "binary": "error", "error": str(exc)[:200], "entries": []}
    try:
        entries = json.loads(show_proc.stdout or "[]")
    except Exception:
        entries = []
    try:
        verification = json.loads(verify_proc.stdout or "{}")
    except Exception:
        verification = {}
    ok = bool(
        show_proc.returncode == 0
        and verify_proc.returncode == 0
        and isinstance(verification, dict)
        and verification.get("ok") is True
    )
    out = {
        "success": ok,
        "binary": "ok",
        "entries": entries if isinstance(entries, list) else [],
        "verification": verification if isinstance(verification, dict) else {},
    }
    if not ok:
        err = (verify_proc.stderr or show_proc.stderr or "").strip()
        if err:
            out["error"] = err[:200]
    return out


_ENV_KEY_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")


def _find_pending_prompts_file(safe_cwd: str) -> Path | None:
    p = Path(safe_cwd).resolve()
    for parent in (p, *p.parents):
        cand = parent / ".ciphervault" / "pending_secret_prompts.json"
        if cand.is_file():
            return cand
        if (parent / ".ciphervault" / "vault.db").exists():
            return cand
    return p / ".ciphervault" / "pending_secret_prompts.json"


def _pending_prompts(cwd: str | None) -> dict:
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"success": False, "error": "invalid or non-directory cwd", "keys": []}
    prompt_path = _find_pending_prompts_file(safe_cwd)
    if prompt_path is None or not prompt_path.is_file():
        return {"success": True, "keys": [], "env_file": ".env", "seal": True}
    try:
        raw = json.loads(prompt_path.read_text(encoding="utf-8", errors="replace") or "{}")
    except Exception:
        return {"success": True, "keys": [], "env_file": ".env", "seal": True}
    if not isinstance(raw, dict):
        return {"success": True, "keys": [], "env_file": ".env", "seal": True}
    items = []
    for item in raw.get("keys") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not _ENV_KEY_RE.fullmatch(name):
            continue
        entry = {
            "name": name,
            "reason": str(item.get("reason") or "")[:200],
            "expected_prefix": str(item.get("expected_prefix") or "")[:32],
        }
        if isinstance(item.get("env_file"), str) and item["env_file"].strip():
            entry["env_file"] = item["env_file"].strip()
        if "seal" in item:
            entry["seal"] = bool(item["seal"])
        if isinstance(item.get("requested_at"), str):
            entry["requested_at"] = item["requested_at"]
        items.append(entry)
    return {
        "success": True,
        "keys": items,
        "env_file": str(raw.get("env_file") or ".env"),
        "seal": bool(raw.get("seal", True)),
        "requested_at": raw.get("requested_at"),
    }


def _set_secret(
    cwd: str | None,
    key: object,
    value: object,
    env_file: object = ".env",
    seal: object = True,
) -> dict:
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"success": False, "error": "invalid or non-directory cwd"}
    if not isinstance(key, str) or "\n" in key or "\r" in key or not _ENV_KEY_RE.fullmatch(key):
        return {"success": False, "error": "invalid key: must match ^[A-Za-z_][A-Za-z0-9_]*$"}
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        return {"success": False, "error": "value must be a non-empty single-line string"}
    if not isinstance(env_file, str):
        return {"success": False, "error": "env_file must be a relative path string"}
    rel_env = env_file.strip()
    if (
        not rel_env
        or "\x00" in rel_env
        or rel_env.startswith(("/", "\\"))
        or ".." in Path(rel_env).parts
    ):
        return {"success": False, "error": "env_file must be a safe relative path inside workspace"}
    base_dir = Path(safe_cwd).resolve()
    target_path = (base_dir / rel_env).resolve()
    if (
        target_path == base_dir
        or not target_path.is_relative_to(base_dir)
        or ".ciphervault" in target_path.relative_to(base_dir).parts
    ):
        return {"success": False, "error": "env_file must resolve inside workspace"}

    binary = _find_binary()
    if not binary:
        return {"success": False, "binary": "missing", "error": "ciphervault binary not found"}

    def _scrub_val(msg: object) -> str:
        return str(msg).replace(value, "[REDACTED]")[:200]

    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if target_path.is_file():
            lines = target_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        pattern = re.compile(rf"^(?:\ufeff)?(?:export\s+)?{re.escape(key)}\s*=")
        replaced = False
        new_lines = []
        for line in lines:
            if not replaced and pattern.match(line):
                new_lines.append(f"{key}={value}\n")
                replaced = True
            else:
                new_lines.append(line)
        if not replaced:
            if new_lines and not new_lines[-1].endswith(("\n", "\r")):
                new_lines[-1] = new_lines[-1] + "\n"
            new_lines.append(f"{key}={value}\n")
        target_path.write_text("".join(new_lines), encoding="utf-8")

        env = _minimal_env()
        track_proc = subprocess.run(
            [binary, "track", rel_env],
            cwd=safe_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            env=env,
        )
        if track_proc.returncode != 0:
            err = (track_proc.stderr or track_proc.stdout or f"exit {track_proc.returncode}").strip()
            return {"success": False, "error": _scrub_val(err)}

        seal_flag = bool(seal)
        push_cmd = [binary, "push", "--local", "-m", f"Set {key} via desktop"]
        if seal_flag:
            push_cmd.append("--shred")
        push_proc = subprocess.run(
            push_cmd,
            cwd=safe_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            env=env,
        )
        if push_proc.returncode != 0:
            err = (push_proc.stderr or push_proc.stdout or f"exit {push_proc.returncode}").strip()
            return {"success": False, "error": _scrub_val(err)}
    except Exception as exc:
        return {"success": False, "error": _scrub_val(exc)}

    # Clear key from pending_secret_prompts.json if present
    prompt_path = _find_pending_prompts_file(safe_cwd)
    if prompt_path is not None and prompt_path.is_file():
        try:
            raw = json.loads(prompt_path.read_text(encoding="utf-8", errors="replace") or "{}")
            if isinstance(raw, dict) and isinstance(raw.get("keys"), list):
                raw["keys"] = [
                    item for item in raw["keys"]
                    if not (isinstance(item, dict) and item.get("name") == key)
                ]
                prompt_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
        except Exception:
            pass

    return {
        "success": True,
        "key": key,
        "env_file": rel_env,
        "sealed": bool(seal),
        "status": _status(safe_cwd),
    }


def _env_health(cwd: str | None) -> dict:
    """Zero-knowledge environment diagnostics for the desktop pane.
    Prefers `ciphervault env-doctor --json` so `.env` values are inspected
    and zeroized inside the Rust CLI rather than read in Python."""
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"success": False, "error": "invalid or non-directory cwd"}
    binary = _find_binary()
    if binary:
        try:
            proc = subprocess.run(
                [binary, "env-doctor", "--json"],
                cwd=safe_cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                env=_minimal_env(),
            )
            if proc.returncode == 0:
                payload = json.loads(proc.stdout or "{}")
                if isinstance(payload, dict) and payload.get("success"):
                    return payload
        except Exception:
            pass
    root = Path(safe_cwd)
    code_patterns = (
        re.compile(r"(?:import\.meta|process)\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
        re.compile(r"os\.environ(?:\.get)?\s*[\[(]\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"),
        re.compile(r"os\.getenv\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"),
        re.compile(r"std::env::var(?:_os)?\s*\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\""),
    )
    skip_dirs = {".git", ".ciphervault", "node_modules", "target", ".venv", "venv", "__pycache__", "dist"}
    code_exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".go", ".yml", ".yaml"}
    referenced = set()
    scanned_files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if scanned_files >= 400:
                break
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() not in code_exts and fname != "Dockerfile":
                continue
            scanned_files += 1
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")[:131072]
            except OSError:
                continue
            for pat in code_patterns:
                referenced.update(pat.findall(text))

    vault_keys = set()
    anomalies = []
    for env_name in (".env", ".env.local", ".env.development", ".env.production"):
        env_path = root / env_name
        if not env_path.is_file():
            continue
        try:
            lines = env_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            k = k.removeprefix("export ").strip()
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k):
                continue
            vault_keys.add(k)
            val_unquoted = v.strip()
            if not val_unquoted:
                anomalies.append({"key": k, "file": env_name, "issue": "EMPTY_VALUE"})
            elif val_unquoted.lower() in ("changeme", "your_api_key_here", "xxx", "todo"):
                anomalies.append({"key": k, "file": env_name, "issue": "PLACEHOLDER_VALUE"})

    example_keys = set()
    ex_path = root / ".env.example"
    if ex_path.is_file():
        try:
            for line in ex_path.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if s and not s.startswith("#") and "=" in s:
                    ek = s.split("=", 1)[0].removeprefix("export ").strip()
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", ek):
                        example_keys.add(ek)
        except OSError:
            pass

    if not vault_keys:
        binary = _find_binary()
        if binary:
            try:
                proc = subprocess.run(
                    [binary, "run", "--dry-run", "--json", "--", "echo", "ok"],
                    cwd=safe_cwd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    env=_minimal_env(),
                )
                if proc.returncode == 0:
                    dry = json.loads(proc.stdout or "{}")
                    for item in dry.get("secrets") or []:
                        if isinstance(item, dict) and item.get("name"):
                            vault_keys.add(str(item["name"]))
            except Exception:
                pass

    expected = referenced | example_keys
    return {
        "success": True,
        "vault_keys": sorted(vault_keys),
        "referenced_in_code": sorted(referenced),
        "example_keys": sorted(example_keys),
        "missing_in_vault": sorted(expected - vault_keys),
        "unreferenced_in_code": sorted(vault_keys - expected),
        "value_anomalies": anomalies,
    }


if router is not None:

    @router.get("/status")
    def status(cwd: str | None = None):
        return _status(cwd)

    @router.post("/seal")
    def seal(cwd: str | None = None):
        return _seal(cwd)

    @router.get("/audit")
    def audit(cwd: str | None = None, limit: int = 10):
        return _audit_trail(cwd, limit=limit)

    @router.get("/env-health")
    def env_health(cwd: str | None = None):
        return _env_health(cwd)

    @router.get("/pending-prompts")
    def pending_prompts(cwd: str | None = None):
        return _pending_prompts(cwd)

    @router.post("/set")
    def set_secret(payload: dict = Body(...), cwd: str | None = None):
        if not isinstance(payload, dict):
            return {"success": False, "error": "JSON object body required"}
        return _set_secret(
            cwd=cwd,
            key=payload.get("key"),
            value=payload.get("value"),
            env_file=payload.get("env_file", ".env"),
            seal=payload.get("seal", True),
        )

    @router.get("/health")
    def health():
        return {"ok": True, "binary": "ok" if _find_binary() else "missing"}
