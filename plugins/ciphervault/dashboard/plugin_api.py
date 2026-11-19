"""CipherVault dashboard backend, mounted at /api/plugins/ciphervault/.

Serves workspace vault status, env health, pending secret prompts, audit trail,
and sealed-vault-safe secret entry / generation to the desktop pane via `ctx.rest`.
Secret values are NEVER served or logged: mutations prefer the native Rust CLI
(`ciphervault vault set --stdin` / `ciphervault vault generate`) so plaintext
never touches Python disk I/O, and fail closed on sealed vaults with legacy CLIs.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    from fastapi import APIRouter, Body
except Exception:  # pragma: no cover - dashboard host always has fastapi
    APIRouter = None
    Body = None

router = APIRouter() if APIRouter is not None else None

_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_ORIG_SUBPROCESS_RUN = subprocess.run
_VAULT_SECRET_PROBE_CACHE: dict[str, bool] = {}


def _load_plugin_submodules():
    """Reuse the active CipherVault plugin package if already loaded in this
    process (so `ctx.get_config("binary_path")` is respected), else load it
    from the sibling plugin package directory."""
    binary_file = str((_PLUGIN_ROOT / "binary.py").resolve())
    pkg_prefix = None
    for mod_name, mod in list(sys.modules.items()):
        mfile = getattr(mod, "__file__", None)
        if mfile and mod_name.endswith(".binary"):
            try:
                if str(Path(mfile).resolve()) == binary_file:
                    pkg_prefix = mod_name.rsplit(".", 1)[0]
                    break
            except OSError:
                continue
    if pkg_prefix is None:
        pkg_prefix = "ciphervault_plugin"
        spec = importlib.util.spec_from_file_location(pkg_prefix, _PLUGIN_ROOT / "__init__.py")
        assert spec is not None and spec.loader is not None
        pkg_mod = importlib.util.module_from_spec(spec)
        sys.modules[pkg_prefix] = pkg_mod
        spec.loader.exec_module(pkg_mod)
    return (
        sys.modules[f"{pkg_prefix}.binary"],
        sys.modules[f"{pkg_prefix}.bridge"],
        sys.modules[f"{pkg_prefix}.policy"],
        sys.modules[f"{pkg_prefix}.tools"],
    )


_cv_binary, _cv_bridge, _cv_policy, _cv_tools = _load_plugin_submodules()

_ENV_KEEP = _cv_binary._ENV_KEEP
_minimal_env = _cv_binary._minimal_env
_ENV_KEY_RE = _cv_policy._ENV_KEY_RE


def _find_binary() -> str | None:
    """Resolve the ciphervault CLI via the shared plugin binary resolver
    (respects `binary_path` plugin config, `$CIPHERVAULT_BIN`, bootstrapped
    binary, repo checkout, and `PATH` `ciphervault` — never bare `cv`)."""
    bin_path, _source = _cv_binary.find_binary()
    return bin_path


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


def _cli_supports_vault_secret(binary: str, cwd: str) -> bool:
    """Return True if `binary` supports `ciphervault vault set|generate`."""
    use_cache = subprocess.run is _ORIG_SUBPROCESS_RUN
    if use_cache and binary in _VAULT_SECRET_PROBE_CACHE:
        return _VAULT_SECRET_PROBE_CACHE[binary]
    try:
        proc = subprocess.run(
            [binary, "vault", "generate", "--help"],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            env=_minimal_env(),
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        ok = bool(
            proc.returncode == 0
            and "--overwrite" in out
            and "--seal" in out
            and "--json" in out
        )
    except Exception:
        ok = False
    if use_cache:
        _VAULT_SECRET_PROBE_CACHE[binary] = ok
    return ok


def _check_legacy_sealed_guard(
    binary: str,
    safe_cwd: str,
    vault_cwd: str,
    target_path: Path,
    rel_env: str,
    native_cmd: str,
) -> str | None:
    """Before a legacy CLI fallback writes `.env` and runs `push`, verify the
    vault working tree is NOT sealed (failing closed on sealed or unreadable
    status so previously sealed keys are never overwritten)."""
    if _cv_bridge._vault_root(safe_cwd) is None:
        return None
    try:
        proc = subprocess.run(
            [binary, "status", "--json"],
            cwd=vault_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            env=_minimal_env(),
        )
        if proc.returncode != 0:
            return (
                f"Cannot verify vault seal state before mutating secrets with a legacy CLI; "
                f"failing closed to avoid wiping previously sealed keys. Upgrade CipherVault CLI "
                f"to support `{native_cmd}`."
            )
        sdata = json.loads(proc.stdout or "{}")
    except Exception:
        return (
            f"Cannot verify vault seal state before mutating secrets with a legacy CLI; "
            f"failing closed to avoid wiping previously sealed keys. Upgrade CipherVault CLI "
            f"to support `{native_cmd}`."
        )
    if not isinstance(sdata, dict):
        return (
            f"Invalid status response from legacy CLI; failing closed to protect sealed keys. "
            f"Upgrade CipherVault CLI to support `{native_cmd}`."
        )
    if not sdata.get("vault"):
        return None
    tracked_norm = {
        str(p).replace("\\", "/").lstrip("./") for p in (sdata.get("tracked_paths") or [])
    }
    target_norm = rel_env.replace("\\", "/").lstrip("./")
    if sdata.get("working_tree_sealed") is True or (
        target_norm in tracked_norm and not target_path.is_file()
    ):
        return (
            f"Working tree is sealed: a legacy CipherVault CLI cannot safely update a single "
            f"key without wiping previously sealed secrets. Upgrade CipherVault CLI to "
            f"support native `{native_cmd}`."
        )
    return None


def _status(cwd: str | None) -> dict:
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"binary": "error", "vault": False, "error": "invalid or non-directory cwd", "policy_profiles": []}
    profiles, policy_err = _cv_policy._policy_profiles_summary(safe_cwd)
    binary = _find_binary()
    if not binary:
        out = {
            "binary": "missing",
            "vault": False,
            "policy_profiles": profiles,
            "next": "Run `hermes ciphervault bootstrap` (Windows) or set CIPHERVAULT_BIN.",
        }
        if policy_err:
            out["policy_error"] = str(policy_err)[:200]
        return out
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
        out = {"binary": "error", "vault": False, "error": str(exc)[:200], "policy_profiles": profiles}
        if policy_err:
            out["policy_error"] = str(policy_err)[:200]
        return out
    try:
        data = json.loads(proc.stdout or "{}")
    except Exception:
        out = {"binary": "error", "vault": False, "error": "non-JSON status output", "policy_profiles": profiles}
        if policy_err:
            out["policy_error"] = str(policy_err)[:200]
        return out
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
    out["policy_profiles"] = profiles
    if policy_err:
        out["policy_error"] = str(policy_err)[:200]
    if data.get("error"):
        out["error"] = str(data["error"])[:200]
    return out


def _seal(cwd: str | None) -> dict:
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"binary": "error", "vault": False, "error": "invalid or non-directory cwd", "policy_profiles": []}
    binary = _find_binary()
    if not binary:
        return {
            "binary": "missing",
            "vault": False,
            "policy_profiles": [],
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
        return {"binary": "error", "vault": False, "error": str(exc)[:200], "policy_profiles": []}
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


def _find_pending_prompts_file(safe_cwd: str) -> Path | None:
    p = Path(safe_cwd).resolve()
    for parent in (p, *p.parents):
        cand = parent / ".ciphervault" / "pending_secret_prompts.json"
        if cand.is_file():
            return cand
        if (parent / ".ciphervault" / "vault.db").exists():
            return cand
    return p / ".ciphervault" / "pending_secret_prompts.json"


def _clear_pending_prompt(safe_cwd: str, key_name: str) -> None:
    prompt_path = _find_pending_prompts_file(safe_cwd)
    if prompt_path is None or not prompt_path.is_file():
        return
    try:
        raw = json.loads(prompt_path.read_text(encoding="utf-8", errors="replace") or "{}")
        if isinstance(raw, dict) and isinstance(raw.get("keys"), list):
            raw["keys"] = [
                item for item in raw["keys"]
                if not (isinstance(item, dict) and item.get("name") == key_name)
            ]
            prompt_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass


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


def _validate_rel_env(safe_cwd: str, env_file: object) -> tuple[Path | None, str | None, str | None]:
    if not isinstance(env_file, str):
        return None, None, "env_file must be a relative path string"
    rel_env = env_file.strip()
    if (
        not rel_env
        or "\x00" in rel_env
        or rel_env.startswith(("/", "\\"))
        or ".." in Path(rel_env).parts
    ):
        return None, None, "env_file must be a safe relative path inside workspace"
    base_dir = Path(safe_cwd).resolve()
    target_path = (base_dir / rel_env).resolve()
    if (
        target_path == base_dir
        or not target_path.is_relative_to(base_dir)
        or ".ciphervault" in target_path.relative_to(base_dir).parts
    ):
        return None, None, "env_file must resolve inside workspace"
    return target_path, rel_env, None


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
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value or "\x00" in value:
        return {"success": False, "error": "value must be a non-empty single-line string"}
    target_path, rel_env, path_err = _validate_rel_env(safe_cwd, env_file)
    if path_err or target_path is None or rel_env is None:
        return {"success": False, "error": path_err or "invalid env_file"}

    binary = _find_binary()
    if not binary:
        return {"success": False, "binary": "missing", "error": "ciphervault binary not found"}

    def _scrub_val(msg: object) -> str:
        return _cv_binary.scrub(str(msg).replace(value, "[REDACTED]"))[:200]

    vault_cwd = _cv_bridge._vault_cwd(safe_cwd) or safe_cwd
    try:
        cli_env_file = target_path.relative_to(Path(vault_cwd).resolve()).as_posix()
    except Exception:
        cli_env_file = rel_env

    seal_flag = True if seal is None else bool(seal)
    env = _minimal_env()

    # Prefer native `ciphervault vault set <KEY> --stdin` (zero plaintext written to disk in Python).
    if _cli_supports_vault_secret(binary, vault_cwd):
        cmd = [binary, "vault", "set", key, "--stdin", "--env-file", cli_env_file, "--json"]
        if seal_flag:
            cmd.append("--seal")
        try:
            proc = subprocess.run(
                cmd,
                cwd=vault_cwd,
                input=value,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                env=env,
            )
        except Exception as exc:
            return {"success": False, "error": _scrub_val(exc)}
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            return {"success": False, "error": _scrub_val(err)}
        try:
            data = json.loads(proc.stdout or "{}")
        except Exception:
            return {"success": False, "error": "non-JSON output from ciphervault vault set"}
        if not isinstance(data, dict) or data.get("success") is False:
            return {"success": False, "error": _scrub_val(data.get("error") if isinstance(data, dict) else "vault set failed")}
        _clear_pending_prompt(safe_cwd, key)
        return {
            "success": True,
            "key": str(data.get("name") or key),
            "env_file": str(data.get("env_file") or rel_env),
            "sealed": bool(data.get("sealed", seal_flag)),
            "snapshot_head": data.get("snapshot_head"),
            "status": _status(safe_cwd),
        }

    # Legacy CLI fallback: fail CLOSED if vault working tree is sealed!
    sealed_err = _check_legacy_sealed_guard(
        binary, safe_cwd, vault_cwd, target_path, cli_env_file, "ciphervault vault set"
    )
    if sealed_err:
        return {"success": False, "error": sealed_err}

    try:
        _cv_tools._upsert_env_vars(target_path, [(key, value)])
        track_proc = subprocess.run(
            [binary, "track", cli_env_file],
            cwd=vault_cwd,
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

        push_cmd = [binary, "push", "--local", "-m", f"Set {key} via desktop"]
        if seal_flag:
            push_cmd.append("--shred")
        push_proc = subprocess.run(
            push_cmd,
            cwd=vault_cwd,
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

    _clear_pending_prompt(safe_cwd, key)
    return {
        "success": True,
        "key": key,
        "env_file": rel_env,
        "sealed": seal_flag,
        "snapshot_head": None,
        "status": _status(safe_cwd),
    }


def _generate_secret(
    cwd: str | None,
    name: object,
    fmt: object = "base64url",
    nbytes: object = 32,
    env_file: object = ".env",
    seal: object = True,
    overwrite: object = False,
) -> dict:
    """Sealed-vault-safe one-click secret generator for the desktop pane.
    Prefers native `ciphervault vault generate`; fails closed on sealed vaults
    with legacy CLIs; never exposes secret values."""
    safe_cwd = _safe_cwd(cwd)
    if safe_cwd is None:
        return {"success": False, "error": "invalid or non-directory cwd"}
    if not isinstance(name, str) or "\n" in name or "\r" in name or not _ENV_KEY_RE.fullmatch(name.strip()):
        return {"success": False, "error": "invalid name: must match ^[A-Za-z_][A-Za-z0-9_]*$"}
    clean_name = name.strip()
    clean_fmt = str(fmt or "base64url").strip().lower()
    if clean_fmt not in ("base64url", "hex", "uuid", "alphanumeric"):
        return {"success": False, "error": "invalid format: expected base64url, hex, uuid, or alphanumeric"}
    if isinstance(nbytes, bool) or not isinstance(nbytes, int) or not (16 <= nbytes <= 64):
        return {"success": False, "error": "bytes must be an integer between 16 and 64"}
    target_path, rel_env, path_err = _validate_rel_env(safe_cwd, env_file if env_file is not None else ".env")
    if path_err or target_path is None or rel_env is None:
        return {"success": False, "error": path_err or "invalid env_file"}

    binary = _find_binary()
    if not binary:
        return {"success": False, "binary": "missing", "error": "ciphervault binary not found"}

    vault_cwd = _cv_bridge._vault_cwd(safe_cwd) or safe_cwd
    try:
        cli_env_file = target_path.relative_to(Path(vault_cwd).resolve()).as_posix()
    except Exception:
        cli_env_file = rel_env

    seal_flag = True if seal is None else bool(seal)
    overwrite_flag = bool(overwrite)
    env = _minimal_env()

    if _cli_supports_vault_secret(binary, vault_cwd):
        cmd = [
            binary, "vault", "generate", clean_name,
            "--format", clean_fmt,
            "--bytes", str(nbytes),
            "--env-file", cli_env_file,
            "--json",
        ]
        if seal_flag:
            cmd.append("--seal")
        if overwrite_flag:
            cmd.append("--overwrite")
        try:
            proc = subprocess.run(
                cmd,
                cwd=vault_cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                env=env,
            )
        except Exception as exc:
            return {"success": False, "error": _cv_binary.scrub(str(exc))[:200]}
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            return {"success": False, "error": _cv_binary.scrub(err)[:200]}
        try:
            data = json.loads(proc.stdout or "{}")
        except Exception:
            return {"success": False, "error": "non-JSON output from ciphervault vault generate"}
        if not isinstance(data, dict) or data.get("success") is False:
            return {
                "success": False,
                "error": _cv_binary.scrub(str(data.get("error") if isinstance(data, dict) else "vault generate failed"))[:200],
            }
        _clear_pending_prompt(safe_cwd, clean_name)
        return {
            "success": True,
            "name": str(data.get("name") or clean_name),
            "format": str(data.get("format") or clean_fmt),
            "length_chars": data.get("length_chars"),
            "sha256_prefix": data.get("sha256_prefix"),
            "env_file": str(data.get("env_file") or rel_env),
            "sealed": bool(data.get("sealed", seal_flag)),
            "snapshot_head": data.get("snapshot_head"),
            "status": _status(safe_cwd),
        }

    # Legacy CLI fallback: fail CLOSED if vault working tree is sealed!
    sealed_err = _check_legacy_sealed_guard(
        binary, safe_cwd, vault_cwd, target_path, cli_env_file, "ciphervault vault generate"
    )
    if sealed_err:
        return {"success": False, "error": sealed_err}

    if not overwrite_flag and _cv_tools._env_file_has_key(target_path, clean_name):
        return {
            "success": False,
            "error": f"Secret {clean_name!r} already exists in {rel_env}. Pass overwrite=true to replace it.",
        }

    value = _cv_tools._generate_random_secret_value(clean_fmt, nbytes)
    length_chars = len(value)
    sha256_prefix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]

    def _scrub_gen(msg: object) -> str:
        return _cv_binary.scrub(str(msg).replace(value, "[REDACTED]"))[:200]

    try:
        _cv_tools._upsert_env_vars(target_path, [(clean_name, value)])
        track_proc = subprocess.run(
            [binary, "track", cli_env_file],
            cwd=vault_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            env=env,
        )
        if track_proc.returncode != 0:
            err = (track_proc.stderr or track_proc.stdout or f"exit {track_proc.returncode}").strip()
            return {"success": False, "error": _scrub_gen(err)}

        push_cmd = [binary, "push", "--local", "-m", f"Generated {clean_name} via desktop"]
        if seal_flag:
            push_cmd.append("--shred")
        push_proc = subprocess.run(
            push_cmd,
            cwd=vault_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            env=env,
        )
        if push_proc.returncode != 0:
            err = (push_proc.stderr or push_proc.stdout or f"exit {push_proc.returncode}").strip()
            return {"success": False, "error": _scrub_gen(err)}
    except Exception as exc:
        return {"success": False, "error": _scrub_gen(exc)}
    finally:
        value = ""

    _clear_pending_prompt(safe_cwd, clean_name)
    return {
        "success": True,
        "name": clean_name,
        "format": clean_fmt,
        "length_chars": length_chars,
        "sha256_prefix": sha256_prefix,
        "env_file": rel_env,
        "sealed": seal_flag,
        "snapshot_head": None,
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
            if not _ENV_KEY_RE.fullmatch(k):
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
                    if _ENV_KEY_RE.fullmatch(ek):
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

    @router.post("/generate")
    def generate_secret(payload: dict = Body(...), cwd: str | None = None):
        if not isinstance(payload, dict):
            return {"success": False, "error": "JSON object body required"}
        return _generate_secret(
            cwd=cwd,
            name=payload.get("name") if payload.get("name") is not None else payload.get("key"),
            fmt=payload.get("format", "base64url"),
            nbytes=payload.get("bytes", 32),
            env_file=payload.get("env_file", ".env"),
            seal=payload.get("seal", True),
            overwrite=payload.get("overwrite", False),
        )

    @router.get("/health")
    def health():
        return {"ok": True, "binary": "ok" if _find_binary() else "missing"}
