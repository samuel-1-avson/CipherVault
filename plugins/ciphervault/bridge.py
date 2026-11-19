"""CLI subprocess bridge, persistent stdio redaction worker, vault discovery, and signed audit."""

from __future__ import annotations

import atexit
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
from pathlib import Path

from . import _runtime, binary

_self = sys.modules[__name__]


# ---------------------------------------------------------------- vault discovery

def _iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


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
        return _runtime.resolve(_self, "_vault_root")(cwd) is not None
    except Exception:
        return True


def _vault_cwd(cwd):
    """Run vault-scoped CLI calls at the workspace root: the CLI opens
    ./.ciphervault/vault.db relative to its cwd, so a subdirectory
    would otherwise look vaultless and lose its exact values/receipts."""
    try:
        root = _runtime.resolve(_self, "_vault_root")(cwd)
    except Exception:
        root = None
    return str(root) if root is not None else cwd


def _validate_env_file(cwd, env_file_raw):
    """Resolve `cwd` and `env_file`, ensuring `env_file` is a safe relative path
    inside `cwd` and outside `.ciphervault`."""
    base_dir = Path(cwd or os.getcwd()).resolve()
    if not base_dir.is_dir():
        return None, None, f"workspace directory does not exist: {cwd}"
    env_file = str(env_file_raw or ".env").strip()
    if (
        not env_file
        or "\x00" in env_file
        or env_file.startswith(("/", "\\"))
        or ".." in Path(env_file).parts
    ):
        return None, None, "env_file must be a valid relative path inside workspace cwd"
    target_path = (base_dir / env_file).resolve()
    if (
        target_path == base_dir
        or not target_path.is_relative_to(base_dir)
        or ".ciphervault" in target_path.relative_to(base_dir).parts
    ):
        return None, None, "env_file must be a valid path inside workspace cwd"
    return base_dir, target_path, None


def _secret_write_target(cwd, env_file_raw):
    """Where `ciphervault_secret_generate` and `ciphervault_secret_prompt` may write.

    Both tools take `cwd` and `env_file` from the model, so neither may write
    anywhere a vault does not already own: `cwd` must sit inside an existing
    vault, and `env_file` must resolve (after symlinks) inside that vault's
    root, outside `.ciphervault/`, and outside the Hermes home, whose files
    Hermes's own file tools refuse to write. Returns
    `(vault_root, base_dir, target_path, error)`.
    """
    base_dir, target_path, err = _validate_env_file(cwd, env_file_raw)
    if err:
        return None, None, None, err
    try:
        root = _runtime.resolve(_self, "_vault_root")(str(base_dir))
    except Exception:
        root = None
    if root is None:
        return None, None, None, (
            "no CipherVault vault at or above cwd: secret tools only write inside an "
            "existing vault (run `ciphervault init` there first)"
        )
    vault_root = Path(root).resolve()
    if (
        not target_path.is_relative_to(vault_root)
        or ".ciphervault" in target_path.relative_to(vault_root).parts
    ):
        return None, None, None, "env_file must resolve inside the vault root, outside .ciphervault/"
    try:
        hermes_home = _runtime.resolve(binary, "_hermes_home")().resolve()
    except Exception:
        hermes_home = None
    if hermes_home is not None and target_path.is_relative_to(hermes_home):
        return None, None, None, (
            "env_file resolves inside the Hermes home; CipherVault secret tools never write there"
        )
    return vault_root, base_dir, target_path, None


_ARG_TOKEN_RE = re.compile(r"[^\s\"'`;|&<>(){}\[\]=,]+")
_ARG_SCAN_CHARS = 16_384
_ARG_MAX_TOKENS = 256


def _same_dir(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _nearest_vault_lenient(path, cache):
    """_vault_root for argument paths: a level that cannot be inspected
    (glob, invalid name, permission wall) counts as "no store here" and
    the walk continues upward, so one odd token cannot hide the vault
    above it."""
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
    roots = (
        [_runtime.resolve(_self, "_vault_cwd")(cwd)]
        if _runtime.resolve(_self, "_vault_present")(cwd)
        else []
    )
    for root in _arg_vault_roots(args, cwd):
        if not any(_same_dir(root, r) for r in roots):
            roots.append(root)
    return roots


# ---------------------------------------------------------------- audit HMAC

_AUDIT_HMAC_KEY = secrets.token_bytes(32)


def _vault_audit_hmac_key_bytes(cwd=None):
    """Return the per-vault HMAC key from `<vault_root>/.ciphervault/audit_hmac.key`
    (creating it on first use so the Rust CLI enforces HMAC even if an attacker
    omits `CIPHERVAULT_AUDIT_HMAC_KEY` from its environment). Falls back to the
    in-memory key when no vault exists."""
    try:
        root = _runtime.resolve(_self, "_vault_root")(cwd)
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


# ---------------------------------------------------------------- CLI subprocess

def _run_cli(args, cwd, timeout=120, input_text=None, extra_env=None):
    bin_path, source = _runtime.resolve(binary, "find_binary")()
    if not bin_path:
        return {
            "success": False,
            "error": "ciphervault binary not found",
            "binary": "missing",
            "next": binary._COMPATIBLE_CLI_HINT,
        }
    env = binary._minimal_env()
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(
            [bin_path] + args,
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
    if re.search(r"(?m)^Error:", out) or re.search(r"(?m)^Error:", err):
        return {
            "success": False,
            "error": binary.scrub(out + ("\n" + err if err else "")),
            "binary": source,
            "exit_code": proc.returncode,
        }
    if proc.returncode != 0:
        return {
            "success": False,
            "error": binary.scrub(err or out or f"exit {proc.returncode}"),
            "binary": source,
            "exit_code": proc.returncode,
        }
    return {
        "success": True,
        "output": out,
        "stderr": binary.scrub(err),
        "exit_code": proc.returncode,
        "binary": source,
    }


def _run_cli_json(args, cwd, timeout=120, input_text=None):
    run_cli_fn = _runtime.resolve(_self, "_run_cli")
    if input_text is not None:
        res = run_cli_fn(args, cwd, timeout=timeout, input_text=input_text)
    else:
        res = run_cli_fn(args, cwd, timeout=timeout)
    if not res.get("success"):
        return res
    try:
        payload = json.loads(res["output"])
    except Exception:
        return {
            "success": False,
            "error": "ciphervault returned non-JSON output",
            "raw": binary.scrub(res["output"])[:2000],
            "binary": res.get("binary"),
        }
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

    def __init__(self, bin_path, cwd):
        self.binary = bin_path
        self.cwd = cwd
        env = binary._minimal_env()
        env["CIPHERVAULT_AUDIT_HMAC_KEY"] = _vault_audit_hmac_key_bytes(cwd).hex()
        self.proc = subprocess.Popen(
            [bin_path, "redact", "--stdio"],
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
        for b in _BRIDGE_POOL.values():
            b.close()
        _BRIDGE_POOL.clear()


atexit.register(_close_all_bridges)


def _bridge_request(cwd, payload, timeout=15):
    """Send one JSON request over a persistent `ciphervault redact --stdio`
    pipe. Returns None when unavailable or unsupported (e.g. legacy CLI or
    unit tests that monkeypatch `_run_cli` / `_run_cli_json`), so callers fall
    back cleanly."""
    if (
        _runtime.resolve(_self, "_run_cli") is not _ORIG_RUN_CLI
        or _runtime.resolve(_self, "_run_cli_json") is not _ORIG_RUN_CLI_JSON
    ):
        return None
    bin_path, _src = _runtime.resolve(binary, "find_binary")()
    if not bin_path:
        return None
    resolved_cwd = str(cwd or os.getcwd())
    key = (bin_path, resolved_cwd)
    with _BRIDGE_LOCK:
        if bin_path in _NO_STDIO_BINARIES:
            return None
        b = _BRIDGE_POOL.get(key)
        if b is not None and b.proc.poll() is not None:
            b.close()
            _BRIDGE_POOL.pop(key, None)
            b = None
        if b is None:
            if len(_BRIDGE_POOL) >= _MAX_BRIDGES:
                oldest_key = next(iter(_BRIDGE_POOL))
                _BRIDGE_POOL.pop(oldest_key).close()
            try:
                b = _StdioBridge(bin_path, resolved_cwd)
            except Exception:
                return None
            _BRIDGE_POOL[key] = b
    resp = b.request(payload, timeout=timeout)
    if resp is None:
        with _BRIDGE_LOCK:
            if _BRIDGE_POOL.get(key) is b:
                _BRIDGE_POOL.pop(key, None)
            b.close()
            if payload.get("op") != "ping":
                _NO_STDIO_BINARIES.add(bin_path)
    return resp


# ---------------------------------------------------------------- audit & redaction

def _audit(tool, decision, path="", detail=None, cwd=None):
    """Append one entry to the vault's tamper-evident agent audit
    chain via the CLI. Records paths/decisions/counts only, never
    contents. Returns True when the entry landed."""
    try:
        vault_cwd = _runtime.resolve(_self, "_vault_cwd")(cwd)
        session_id = _runtime._SESSION_STATE.get("session_id")
        if session_id:
            enriched = dict(detail) if isinstance(detail, dict) else {}
            if "session_id" not in enriched:
                enriched["session_id"] = session_id
            candidate = json.dumps(enriched)
            if len(candidate) <= 500:
                detail = enriched
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
        run_cli_fn = _runtime.resolve(_self, "_run_cli")
        if run_cli_fn is _ORIG_RUN_CLI:
            args += ["--hmac", hmac_tag]
            res = run_cli_fn(
                args,
                vault_cwd,
                timeout=10,
                extra_env={"CIPHERVAULT_AUDIT_HMAC_KEY": _vault_audit_hmac_key_bytes(vault_cwd).hex()},
            )
        else:
            res = run_cli_fn(args, vault_cwd, timeout=10)
        return bool(res and res.get("success"))
    except Exception:
        return False


def _anchor_async(cwd=None):
    """Fire-and-forget fleet anchor of the audit head. Runs detached
    so a slow/unreachable fleet can never delay or break the guarded call."""
    try:
        bin_path, _src = _runtime.resolve(binary, "find_binary")()
        if not bin_path:
            return
        kwargs = {
            "cwd": _runtime.resolve(_self, "_vault_cwd")(cwd) or os.getcwd(),
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
        subprocess.Popen([bin_path, "agent-log", "anchor"], **kwargs)
    except Exception:
        pass


def _complete_redact_response(data, require_vault=False):
    """A well-shaped response is not proof that all tracked files loaded."""
    return (
        isinstance(data, dict)
        and isinstance(data.get("text"), str)
        and type(data.get("redactions")) is int
        and data["redactions"] >= 0
        and type(data.get("exact_values_loaded")) is int
        and data["exact_values_loaded"] >= 0
        and data.get("exact_values_complete") is True
        and type(data.get("vault")) is bool
        and (not require_vault or data["vault"] is True)
    )


def cli_redact(text, cwd, timeout=15):
    """Exact+shape redaction via the CLI (vault values are matched
    inside the CLI process; they never enter this process). Returns
    (text, redactions, exact_ok)."""
    if not text:
        return text, 0, True
    vault_cwd = _runtime.resolve(_self, "_vault_cwd")(cwd)
    require_vault = _runtime.resolve(_self, "_vault_present")(cwd)
    resp = _bridge_request(vault_cwd, {"op": "redact", "text": text}, timeout=timeout)
    if resp and resp.get("ok") and _complete_redact_response(resp, require_vault=require_vault):
        return resp["text"], resp["redactions"], True
    run_cli_json_fn = _runtime.resolve(_self, "_run_cli_json")
    res = run_cli_json_fn(["redact", "--json"], vault_cwd, timeout=timeout, input_text=text)
    if res.get("success"):
        data = res.get("data")
        if _complete_redact_response(data, require_vault=require_vault):
            return data["text"], data["redactions"], True
    return binary.scrub(text), 0, False


_ORIG_CLI_REDACT = cli_redact


def _call_cli_redact(text, cwd, timeout=15):
    """Call exact+shape redaction via `cli_redact` (preserving 3-tuple return)."""
    if not text:
        return text, 0, True
    return _runtime.resolve(_self, "cli_redact")(text, cwd, timeout=timeout)
