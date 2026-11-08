"""CipherVault dashboard backend, mounted at /api/plugins/ciphervault/.

Serves workspace vault status to the desktop pane / dashboard tab via
`ctx.rest`. Values are never served: `ciphervault status --json`
reports tracked file paths, counts, and truncated identifiers only,
and every response here passes through the same allow-list.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

try:
    from fastapi import APIRouter
except Exception:  # pragma: no cover - dashboard host always has fastapi
    APIRouter = None

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


def _status(cwd: str | None) -> dict:
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
            cwd=cwd or os.getcwd(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
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
    )
    out = {k: data.get(k) for k in keep if k in data}
    out["binary"] = "ok"
    out["operators"] = len(data.get("operators") or [])
    if data.get("error"):
        out["error"] = str(data["error"])[:200]
    return out


if router is not None:

    @router.get("/status")
    def status(cwd: str | None = None):
        return _status(cwd)

    @router.get("/health")
    def health():
        return {"ok": True, "binary": "ok" if _find_binary() else "missing"}
