"""Shared runtime state and facade binding for the CipherVault Hermes plugin.

Keeping facade resolution in one tiny module lets `plugins/ciphervault/__init__.py`
act as a thin re-exporting facade while preserving full monkeypatch compatibility
when callers (or tests) patch attributes on the top-level plugin module.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

PLUGIN_DIR = Path(__file__).resolve().parent

_ctx: dict[str, Any] = {"ctx": None}
_SESSION_STATE: dict[str, str | None] = {"session_id": None, "platform": None}

_FACADE_DICT: dict[str, Any] | None = None
_ORIGINALS: dict[str, Any] = {}


def _read_plugin_version() -> str:
    """Read the plugin's own semver from plugin.yaml (distinct from CLI RELEASE_VERSION)."""
    manifest = PLUGIN_DIR / "plugin.yaml"
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
        match = re.search(r'(?m)^version:\s*["\']?([^"\'\s#]+)["\']?', text)
        if match:
            return match.group(1)
    except OSError:
        pass
    return "0.7.1"


PLUGIN_VERSION = _read_plugin_version()


def bind_facade(facade_dict: dict[str, Any], originals: dict[str, Any]) -> None:
    """Bind the top-level plugin module's `__dict__` so monkeypatches applied to
    the facade module transparently take effect inside submodules."""
    global _FACADE_DICT, _ORIGINALS
    _FACADE_DICT = facade_dict
    _ORIGINALS = dict(originals)


def resolve(submodule: Any, name: str) -> Any:
    """Return a monkeypatched override on the facade module if present, else
    `getattr(submodule, name)` (allowing direct submodule patches as well)."""
    mod_val = getattr(submodule, name)
    if _FACADE_DICT is not None and name in _FACADE_DICT:
        fac_val = _FACADE_DICT[name]
        if fac_val is not _ORIGINALS.get(name):
            return fac_val
    return mod_val
