"""Hermes lifecycle hooks and middleware: leak guards, redaction, posture, and session tracking."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import sys
from pathlib import Path

from . import _runtime, binary, bridge, policy

_self = sys.modules[__name__]

_SECRET_FILE_RE = re.compile(
    r"(?i)(^|[\s\\/\"'=])(\.env(?!(?:\.(?:example|sample|template))\b)(\.[\w.-]*)?|\.envrc|\.npmrc|\.pypirc|"
    r"[\w.-]+\.(pem|key|p12|pfx)|id_rsa|id_ed25519|"
    r"credentials\.json|secrets\.(json|ya?ml|toml)|"
    r"vault\.db|keystore\.(?:key|salt)|audit_hmac\.key|policy\.toml|"
    # Source/docs about kits (recovery_kit.rs, recovery_kit.md) are not kits.
    r"recovery_kit(?![\w-]*\.(?:rs|py|pyi|js|jsx|ts|tsx|go|java|kt|swift|c|cc|cpp|h|hpp|cs|rb|php|md|toml|ya?ml|lock)\b)[\w.-]*|"
    r"[\w.-]+\.kit|[\w.-]*share[\w.-]*\.txt)"
)
_SEARCH_SECRET_GLOB_RE = re.compile(
    r"(?i)(^|[\s\\/\"'=])("
    r"\*+\.env(?!(?:\.(?:example|sample|template))\b)(\.[\w.*-]*)?|"
    r"\*+\.(?:pem|key|p12|pfx|kit)\b|"
    r"\.ciphervault[\\/]\*"
    r")"
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
    rf"(?:(?:restore|pull|recover|init|rekey|prune|untrack|export-env)\b|"
    rf"secret{_CLI_FLAGS_RE}\s+get\b|"
    rf"agent-log{_CLI_FLAGS_RE}\s+(?:record|anchor)\b|"
    rf"diff\b[^\n;&|]*(?:--reveal|\s-r\b))|"
    r"/api/diff\b[^\n]*reveal|/api/snapshots/restore\b)"
)
_GIT_GLOBAL_OPT_RE = (
    r"(?:\s+(?:"
    r"(?:-C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path)\s+(?:\"[^\"]*\"|'[^']*'|[^\s;&|]+)"
    r"|--?[\w-]+(?:=(?:\"[^\"]*\"|'[^']*'|[^\s;&|]+))?"
    r"))*"
)
_GIT_DANGER_RE = re.compile(
    rf"(?i)\bgit(?:\.exe)?{_GIT_GLOBAL_OPT_RE}\s+(commit|push|add)\b"
)

_POSIX_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash"})
_JS_INTERPRETERS = frozenset({"node", "bun", "tsx", "ts-node", "deno"})
_PS_INTERPRETERS = frozenset({"pwsh", "powershell"})
_INTERPRETER_BINARIES = (
    frozenset({"python", "python3", "cmd", "ruby", "perl"})
    | _POSIX_SHELLS
    | _JS_INTERPRETERS
    | _PS_INTERPRETERS
)
_INLINE_CODE_FLAGS = frozenset({
    "-c", "-e", "--eval", "-p", "--print",
    "/c", "/k", "-command", "-enc", "-encodedcommand",
})
_INLINE_CODE_PREFIXES = (
    "-c=", "-e=", "--eval=", "-p=", "--print=",
    "/c:", "/k:", "-command=", "-enc=", "-encodedcommand=",
)
_REDACT_CHUNK_CHARS = 262_144
_REDACT_SEAM_OVERLAP = 4_096
_MAX_RESULT_CHARS = int(os.environ.get("CIPHERVAULT_MAX_RESULT_CHARS", str(4 * 1024 * 1024)))
_WRITE_TOOLS = {"write_file", "patch", "terminal", "execute_code", "browser_exec", "browser_cdp"}


def _is_browser_tool(tool_name: object) -> bool:
    return isinstance(tool_name, str) and (
        tool_name == "browser_cdp" or tool_name.startswith("browser_")
    )


def _strip_exe_name(token: object) -> str:
    raw = Path(str(token)).name.lower()
    for ext in (".exe", ".cmd", ".bat"):
        if raw.endswith(ext):
            raw = raw[:-len(ext)]
            break
    return raw


def _unwrap_launcher_cmd(cmd: list[str]) -> tuple[list[str], bool]:
    """Strip common wrapper launchers (`env`, `uv run`, `npx`, `command`, `exec`)
    so inline interpreter execution behind wrappers is still detected.
    Returns `(unwrapped_cmd, is_direct_inline)` where `is_direct_inline=True`
    catches wrappers that themselves execute inline shell strings (e.g. `npx -c`)."""
    cur = [str(x) for x in cmd if str(x)]
    for _ in range(6):
        if not cur:
            return cur, False
        prog = _strip_exe_name(cur[0])
        if prog == "env":
            idx = 1
            while idx < len(cur):
                tok = cur[idx].strip()
                if tok == "--":
                    idx += 1
                    break
                if tok in ("-S", "--split-string"):
                    if idx + 1 < len(cur):
                        try:
                            split_args = shlex.split(cur[idx + 1])
                        except ValueError:
                            split_args = cur[idx + 1].split()
                        cur = split_args + cur[idx + 2:]
                        break
                    return [], False
                if tok.startswith("--split-string="):
                    rhs = tok.split("=", 1)[1]
                    try:
                        split_args = shlex.split(rhs)
                    except ValueError:
                        split_args = rhs.split()
                    cur = split_args + cur[idx + 1:]
                    break
                if tok in ("-u", "--unset", "-C", "--chdir"):
                    idx += 2
                    continue
                if tok.startswith("-"):
                    idx += 1
                    continue
                if "=" in tok and not tok.startswith("="):
                    idx += 1
                    continue
                cur = cur[idx:]
                break
            else:
                return [], False
            continue
        if prog == "uv":
            idx = 1
            while idx < len(cur) and cur[idx].startswith("-"):
                tok = cur[idx].strip()
                if tok in ("--directory", "--project", "--config-file", "--cache-dir", "-C"):
                    idx += 2
                else:
                    idx += 1
            if idx < len(cur) and cur[idx].strip().lower() == "run":
                idx += 1
                while idx < len(cur):
                    tok = cur[idx].strip()
                    if tok == "--":
                        idx += 1
                        break
                    if tok in (
                        "--with", "--with-editable", "--with-requirements",
                        "--python", "-p", "--env-file", "--directory",
                        "--project", "--package", "--extra", "--group",
                        "--only-group", "--no-group", "--script",
                    ):
                        idx += 2
                        continue
                    if tok.startswith("-"):
                        idx += 1
                        continue
                    break
                cur = cur[idx:]
                continue
            return cur, False
        if prog == "npx":
            idx = 1
            while idx < len(cur):
                tok = cur[idx].strip().lower()
                if tok == "--":
                    idx += 1
                    break
                if tok in ("-c", "--call") or tok.startswith(("-c=", "--call=")):
                    return cur, True
                if tok in ("-p", "--package", "-w", "--workspace", "--cache", "--prefix"):
                    idx += 2
                    continue
                if tok.startswith("-"):
                    idx += 1
                    continue
                break
            cur = cur[idx:]
            continue
        if prog in ("command", "exec", "nohup"):
            idx = 1
            while idx < len(cur) and cur[idx].startswith("-"):
                tok = cur[idx].strip()
                if tok == "--":
                    idx += 1
                    break
                idx += 1
            cur = cur[idx:]
            continue
        break
    return cur, False


def _is_inline_interpreter_cmd(cmd):
    if not cmd or len(cmd) < 2:
        return False
    unwrapped, direct_inline = _unwrap_launcher_cmd(list(cmd))
    if direct_inline:
        return True
    if not unwrapped or len(unwrapped) < 2:
        return False
    raw_prog = _strip_exe_name(unwrapped[0])
    is_python = raw_prog in ("python", "python3") or bool(re.match(r"^python\d*(?:\.\d+)*$", raw_prog))
    is_interp = raw_prog in _INTERPRETER_BINARIES or is_python
    if not is_interp:
        return False

    # `deno eval "..."` executes inline code without a flag prefix.
    if raw_prog == "deno" and str(unwrapped[1]).strip().lower() == "eval":
        return True

    value_flags = set()
    if raw_prog in _POSIX_SHELLS:
        value_flags = {"-o", "+o"}
    elif is_python:
        value_flags = {"-w", "-x", "--check-hash-based-pycs"}
    elif raw_prog in _JS_INTERPRETERS:
        value_flags = {"-r", "--require", "--import", "--loader", "--input-type", "--conditions"}

    idx = 1
    while idx < len(unwrapped):
        tok = str(unwrapped[idx]).strip().lower()
        idx += 1
        if tok == "--":
            break
        if tok == "-m" and is_python:
            # Flags after `python -m <module>` belong to the module (e.g. pytest -c).
            break
        if not tok.startswith(("-", "/", "+")):
            break
        if tok in value_flags:
            idx += 1
            continue
        if tok in _INLINE_CODE_FLAGS or tok.startswith(_INLINE_CODE_PREFIXES):
            return True
        if raw_prog in _POSIX_SHELLS and tok.startswith("-") and not tok.startswith("--"):
            flags_body = tok[1:].split("=", 1)[0]
            if flags_body.isalpha() and "c" in flags_body:
                return True
        if raw_prog in _JS_INTERPRETERS and tok.startswith("-") and not tok.startswith("--"):
            flags_body = tok[1:].split("=", 1)[0]
            if flags_body.isalpha() and ("e" in flags_body or "p" in flags_body):
                return True
        if raw_prog in _PS_INTERPRETERS and tok.startswith("-") and len(tok) >= 2:
            flag_name = tok[1:].split("=", 1)[0].split(":", 1)[0]
            if (
                "command".startswith(flag_name) and len(flag_name) >= 1
            ) or (
                "encodedcommand".startswith(flag_name) and len(flag_name) >= 2
            ):
                return True
    return False


def _compute_run_rule_key(cmd, profile_name, no_net, proxy_on, allow_keys, require_explicit_approval=False):
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
        if allow_keys is not None
        else None
    )
    if (not no_net) or proxy_on or (clean_keys is not None):
        net_mode = "proxy" if proxy_on else ("no_net" if no_net else "open")
        keys_part = ",".join(sorted(clean_keys)) if clean_keys else "ALL"
        parts.append(f"net={net_mode}")
        parts.append(f"keys={keys_part}")
    if require_explicit_approval:
        parts.append(f"oneshot={secrets.token_hex(6)}")
    return ":".join(parts)


def _is_safe_terminal_secret_ref(text):
    if _EXPORT_ENV_RE.search(text):
        return False
    return (
        not _SHELL_CHAIN_RE.search(text)
        and bool(_SAFE_SECRET_PATH_CMD_RE.search(text))
    )


def _content_sha256(text):
    """Hash of the text a person reads, ignoring surrounding whitespace."""
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


def _scrub_full_text(text, cwd, timeout=15):
    """Scrub arbitrarily large text across all chunks + join seams.
    Returns (scrubbed_text, total_redactions, cli_ok, changed)."""
    chunk_chars = int(_runtime.resolve(_self, "_REDACT_CHUNK_CHARS"))
    seam_overlap = int(_runtime.resolve(_self, "_REDACT_SEAM_OVERLAP"))
    call_redact = _runtime.resolve(bridge, "_call_cli_redact")
    if len(text) <= chunk_chars:
        cleaned, n, ok = call_redact(text, cwd, timeout=timeout)
        return cleaned, n, ok, (cleaned != text)

    parts = []
    seam_centers = []
    total_n = 0
    all_ok = True
    any_changed = False
    pos = 0
    while pos < len(text):
        chunk = text[pos:pos + chunk_chars]
        cleaned, n, ok = call_redact(chunk, cwd, timeout=timeout)
        if not ok:
            all_ok = False
        if cleaned != chunk:
            any_changed = True
        total_n += int(n)
        parts.append(cleaned)
        pos += chunk_chars
        if pos < len(text):
            seam_centers.append(sum(len(p) for p in parts))

    assembled = "".join(parts)
    for center in reversed(seam_centers):
        start = max(0, center - seam_overlap)
        end = min(len(assembled), center + seam_overlap)
        seam = assembled[start:end]
        cleaned_seam, n_seam, ok_seam = call_redact(seam, cwd, timeout=timeout)
        if not ok_seam:
            all_ok = False
        if cleaned_seam != seam:
            any_changed = True
            total_n += int(n_seam)
            assembled = assembled[:start] + cleaned_seam + assembled[end:]
    return assembled, total_n, all_ok, any_changed


# ---------------------------------------------------------------- posture & session lifecycle

_POSTURE_SEEN: set[str] = set()
_LLM_POSTURE_CACHE: dict[str, str] = {}


def _pending_prompt_names(root: Path) -> list[str]:
    prompt_path = root / ".ciphervault" / "pending_secret_prompts.json"
    if not prompt_path.is_file():
        return []
    try:
        raw = json.loads(prompt_path.read_text(encoding="utf-8", errors="replace") or "{}")
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    names = []
    for item in raw.get("keys") or []:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if policy._ENV_KEY_RE.fullmatch(name):
                names.append(name)
    return names


def _workspace_posture_summary(cwd):
    root = _runtime.resolve(bridge, "_vault_root")(cwd)
    if root is None:
        return "vault=none"
    pol, policy_err = policy._load_policy_toml(str(root))
    pol = pol if isinstance(pol, dict) else {}
    profiles = sorted((pol.get("profiles") or {}).keys())
    sealed_cfg = bool((pol.get("vault") or {}).get("sealed_mode", False))
    env_present = any((root / name).is_file() for name in (".env", ".env.local", ".env.production"))
    pending = _pending_prompt_names(root)
    base = (
        f"vault=present | working_env={'plaintext_on_disk' if env_present else 'sealed_or_absent'} "
        f"| sealed_mode={sealed_cfg} | profiles={profiles or ['default']}"
    )
    if policy_err:
        base += " | policy=invalid"
    if pending:
        shown = pending[:8]
        suffix = f" (+{len(pending) - 8} more)" if len(pending) > 8 else ""
        base += f" | pending_prompts={shown}{suffix}"
    return base


def on_session_start(*args, **kwargs):
    """Hermes lifecycle hook: reset per-session posture caches and track session_id
    for tamper-evident audit detail enrichment."""
    try:
        _POSTURE_SEEN.clear()
        _LLM_POSTURE_CACHE.clear()
        meta = dict(kwargs)
        if args and isinstance(args[0], dict):
            for k, v in args[0].items():
                meta.setdefault(k, v)
        sid = meta.get("session_id")
        plat = meta.get("platform")
        _runtime._SESSION_STATE["session_id"] = str(sid).strip()[:64] if sid else None
        _runtime._SESSION_STATE["platform"] = str(plat).strip()[:32] if plat else None
    except Exception:
        pass
    return None


def pre_llm_call(*args, **kwargs):
    """Hermes lifecycle hook: inject a compact 1-line ambient CipherVault workspace
    posture note on turn 1 (and whenever seal state, policy profiles, or pending
    secret prompts change) so the model is vault-aware before calling any tool."""
    try:
        meta = dict(kwargs)
        if args and isinstance(args[0], dict):
            for k, v in args[0].items():
                meta.setdefault(k, v)
        sid = meta.get("session_id")
        if sid:
            sid_clean = str(sid).strip()[:64]
            if _runtime._SESSION_STATE.get("session_id") != sid_clean:
                _POSTURE_SEEN.clear()
                _LLM_POSTURE_CACHE.clear()
                _runtime._SESSION_STATE["session_id"] = sid_clean
        cwd = meta.get("cwd") or meta.get("workdir") or os.getcwd()
        root = _runtime.resolve(bridge, "_vault_root")(cwd)
        if root is None:
            return None
        root_key = os.path.normcase(os.path.abspath(str(root)))
        summary = _workspace_posture_summary(str(root))
        if _LLM_POSTURE_CACHE.get(root_key) == summary:
            return None
        _LLM_POSTURE_CACHE[root_key] = summary
        return {
            "context": (
                f"[CipherVault workspace posture] {summary}. "
                "Use ciphervault_run / ciphervault_env_doctor / ciphervault_secret_generate / "
                "ciphervault_secret_prompt; never read or paste plaintext secrets."
            )
        }
    except Exception:
        return None


# ---------------------------------------------------------------- tool hooks

_SECRET_WRITE_TOOLS = ("ciphervault_secret_generate", "ciphervault_secret_prompt")


def _requested_secret_names(raw_keys):
    """Valid key names from a `ciphervault_secret_prompt` `keys` argument."""
    names = []
    for item in raw_keys if isinstance(raw_keys, list) else []:
        name = item if isinstance(item, str) else (item.get("name") if isinstance(item, dict) else None)
        name = str(name or "").strip()
        if policy._ENV_KEY_RE.fullmatch(name) and name not in names:
            names.append(name)
    return names


def _secret_write_gate(tool_name, args, cwd, audit_fn):
    """Approval gate for the two tools that write secrets into an env file.

    The model chooses `cwd` and `env_file`, so the call is blocked unless the
    target lies inside an existing vault (see `bridge._secret_write_target`),
    and otherwise always goes to Hermes's approval prompt. An "always" grant
    is scoped to that vault and env file. Overwriting an existing key gets a
    one-shot rule key, so no earlier grant can approve it."""
    if not isinstance(args, dict):
        return {"action": "block", "message": "CipherVault guard: invalid tool arguments"}
    env_file = str(args.get("env_file") or ".env").strip()
    vault_root, _base, target, err = _runtime.resolve(bridge, "_secret_write_target")(cwd, env_file)
    if err:
        audit_fn(
            tool_name,
            "blocked",
            path=env_file[:128],
            detail={"reason": "secret_target_outside_vault"},
            cwd=cwd,
        )
        return {"action": "block", "message": f"CipherVault guard: {err}"}

    rel = target.relative_to(vault_root).as_posix()
    vault_cwd = str(vault_root)
    scope = hashlib.sha256(
        f"{os.path.normcase(vault_cwd)}\n{rel}".encode("utf-8")
    ).hexdigest()[:12]
    where = f"{rel!r} in the vault at {vault_cwd}"

    if tool_name == "ciphervault_secret_generate":
        key_name = str(args.get("name") or "").strip()[:64] or "?"
        overwrite = bool(args.get("overwrite"))
        audit_fn(
            tool_name,
            "approval_requested",
            path=rel,
            detail={"name": key_name, "overwrite": overwrite},
            cwd=vault_cwd,
        )
        if overwrite:
            return {
                "action": "approve",
                "message": (
                    f"CipherVault: overwrite the existing secret {key_name!r} in {where}? "
                    "Replacing an active key may invalidate existing credentials or sessions."
                ),
                "rule_key": f"ciphervault_secret_generate:overwrite:{key_name}:{scope}:oneshot={secrets.token_hex(6)}",
            }
        return {
            "action": "approve",
            "message": (
                f"CipherVault: generate a new random secret {key_name!r} into {where}? "
                "The value is never shown to the model, and an existing key is not replaced."
            ),
            "rule_key": f"ciphervault_secret_generate:{scope}",
        }

    names = _requested_secret_names(args.get("keys"))
    if not names:
        return {
            "action": "block",
            "message": "CipherVault guard: keys must list valid secret names ([A-Za-z_][A-Za-z0-9_]*)",
        }
    audit_fn(
        tool_name,
        "approval_requested",
        path=rel,
        detail={"keys": names[:20]},
        cwd=vault_cwd,
    )
    shown = ", ".join(names[:8]) + (f" (+{len(names) - 8} more)" if len(names) > 8 else "")
    return {
        "action": "approve",
        "message": (
            f"CipherVault: ask you to enter {shown} for {where}? "
            "You type the values yourself, outside the chat."
        ),
        "rule_key": f"ciphervault_secret_prompt:{scope}:keys={','.join(sorted(names))}",
    }


def on_pre_tool_call(tool_name, args, **kwargs):
    """Leak guard. Blocks secret-file reads/searches/writes, secret-shaped
    content handed to other tools, and git add/commit/push while violations
    exist or hook checks fail inside a vault. Gates ciphervault_run,
    ciphervault_secret_generate and ciphervault_secret_prompt behind Hermes
    approval, and blocks the two secret tools outside an existing vault."""
    cwd = (
        ((args or {}).get("cwd") or (args or {}).get("workdir") or os.getcwd())
        if isinstance(args, dict)
        else os.getcwd()
    )
    audit_fn = _runtime.resolve(bridge, "_audit")
    anchor_fn = _runtime.resolve(bridge, "_anchor_async")
    vault_cwd_fn = _runtime.resolve(bridge, "_vault_cwd")
    vault_present_fn = _runtime.resolve(bridge, "_vault_present")
    run_cli_json_fn = _runtime.resolve(bridge, "_run_cli_json")
    try:
        if tool_name == "ciphervault_run":
            vault_cwd = vault_cwd_fn(cwd)
            effective, policy_err = policy._resolve_run_policy(args, cwd)
            if policy_err:
                audit_fn(
                    "ciphervault_run",
                    "blocked",
                    detail={"reason": "policy_or_upstream_rejected"},
                    cwd=vault_cwd,
                )
                return {"action": "block", "message": f"CipherVault guard: {policy_err}"}
            cmd = list(effective.get("command") or ["run"])
            allow_keys = effective.get("allow_keys")
            no_net = policy._effective_no_net(effective)
            proxy_on = bool(effective.get("proxy") or policy._clean_proxy_upstreams(effective))
            profile_name = str(effective.get("profile") or "").strip() or None
            req_explicit = bool(effective.get("_require_explicit_approval"))
            detail = {
                "program": str(cmd[0]),
                "no_net": no_net,
                "proxy": proxy_on,
            }
            if profile_name:
                detail["profile"] = profile_name[:64]
            if allow_keys:
                detail["allow_keys"] = [str(k) for k in allow_keys][:20]
            audit_fn("ciphervault_run", "approval_requested", detail=detail, cwd=vault_cwd)
            anchor_fn(vault_cwd)
            rule_key = _compute_run_rule_key(
                cmd,
                profile_name,
                no_net,
                proxy_on,
                allow_keys,
                require_explicit_approval=req_explicit,
            )
            scope_note = (
                f" (allow_keys: {', '.join(str(k) for k in allow_keys)})"
                if allow_keys
                else " (all vault secrets)"
            )
            net_note = (
                " [proxy: real keys stay in parent]"
                if proxy_on
                else (" [network: isolated (--no-net)]" if no_net else " [network: UNRESTRICTED]")
            )
            explicit_note = " [explicit approval required]" if req_explicit else ""
            return {
                "action": "approve",
                "message": (
                    f"CipherVault: run a command with vault secrets{scope_note}{net_note}{explicit_note} "
                    "injected in RAM? The command receives the values; "
                    "approve only if you trust it."
                ),
                "rule_key": rule_key,
            }

        if tool_name in _SECRET_WRITE_TOOLS:
            try:
                return _secret_write_gate(tool_name, args, cwd, audit_fn)
            except Exception:
                # Unlike the outer handler, fail closed even outside a vault:
                # these tools write files wherever the arguments point.
                return {
                    "action": "block",
                    "message": "CipherVault guard: could not check where this secret tool would write; failing closed.",
                }

        if not tool_name or tool_name.startswith("ciphervault_"):
            return None
        args = args or {}
        texts = list(bridge._iter_strings(args))
        is_browser = _is_browser_tool(tool_name)

        if tool_name in ("terminal", "execute_code") or is_browser:
            for text in texts:
                if _EXPORT_ENV_RE.search(text):
                    audit_fn(
                        tool_name,
                        "blocked",
                        path=text[:300],
                        detail={"reason": "export_env_terminal"},
                        cwd=cwd,
                    )
                    return {
                        "action": "block",
                        "message": (
                            "CipherVault guard: plaintext secret export/restore/reveal/admin commands "
                            "cannot run via agent tools. Use ciphervault_run or run interactively."
                        ),
                    }

        if tool_name in ("write_file", "patch"):
            for key in ("path", "file_path", "file", "target_file"):
                target = args.get(key) if isinstance(args, dict) else None
                if isinstance(target, str) and (
                    _PROTECTED_CONFIG_RE.search(target) or _SECRET_FILE_RE.search(target)
                ):
                    audit_fn(
                        tool_name,
                        "blocked",
                        path=target[:300],
                        detail={"reason": "protected_secret_or_policy_write"},
                        cwd=cwd,
                    )
                    return {
                        "action": "block",
                        "message": (
                            "CipherVault guard: modifying secret files or .ciphervault/policy.toml "
                            "directly is blocked. Use ciphervault_secret_generate or edit policy.toml manually."
                        ),
                    }

        if tool_name in ("terminal", "execute_code", "read_file", "search_files") or is_browser:
            for text in texts:
                matched_secret = bool(_SECRET_FILE_RE.search(text)) or (
                    tool_name == "search_files" and bool(_SEARCH_SECRET_GLOB_RE.search(text))
                )
                if matched_secret:
                    if tool_name == "terminal" and _is_safe_terminal_secret_ref(text):
                        continue
                    audit_fn(
                        tool_name,
                        "blocked",
                        path=text[:300],
                        detail={"reason": "secret_file_read"},
                        cwd=cwd,
                    )
                    return {
                        "action": "block",
                        "message": (
                            "CipherVault guard: accessing a secret/kit file from this tool could leak it. "
                            "Use ciphervault_run (RAM-only injection), ciphervault_redact (masked), or "
                            "ciphervault_status (names only). Paths are fine; contents are not."
                        ),
                    }

        joined = "\n".join(texts)
        if joined:
            for root in bridge._scrub_roots(args, cwd) or [cwd]:
                _cleaned, n, exact, changed = _scrub_full_text(joined, root, timeout=10)
                if (
                    not exact
                    and vault_present_fn(root)
                    and (
                        tool_name in ("terminal", "execute_code", "read_file", "write_file", "patch", "search_files")
                        or is_browser
                    )
                ):
                    audit_fn(
                        tool_name,
                        "blocked",
                        detail={"reason": "redact_unavailable_fail_closed"},
                        cwd=root,
                    )
                    return {
                        "action": "block",
                        "message": (
                            "CipherVault guard: exact-value redaction check failed/timed out inside "
                            "a vault workspace; failing closed. Verify `ciphervault` binary health."
                        ),
                    }
                if n > 0 or changed:
                    audit_fn(
                        tool_name,
                        "blocked",
                        detail={"reason": "secret_shaped_payload", "redactions": n},
                        cwd=root,
                    )
                    return {
                        "action": "block",
                        "message": (
                            "CipherVault guard: this call contains secret material "
                            f"({n} exact/shape redaction(s)). Work with paths and names only, "
                            "seal values with ciphervault_push, run workloads via ciphervault_run."
                        ),
                    }

        if tool_name == "terminal":
            for text in texts:
                if _GIT_DANGER_RE.search(text):
                    vault_roots = bridge._scrub_roots(args, cwd)
                    targets = vault_roots if vault_roots else [cwd]
                    for root in targets:
                        res = run_cli_json_fn(["hook", "check", "--deep", "--json"], root, timeout=30)
                        data = res.get("data") if isinstance(res, dict) else None
                        if not (isinstance(res, dict) and res.get("success") and isinstance(data, dict)):
                            if vault_roots or vault_present_fn(root):
                                audit_fn(
                                    tool_name,
                                    "blocked",
                                    detail={"reason": "git_hook_check_failed"},
                                    cwd=root,
                                )
                                return {
                                    "action": "block",
                                    "message": (
                                        "CipherVault guard: secret sprawl check (`hook check`) failed or "
                                        "timed out inside a vault workspace; failing closed before "
                                        "git add/commit/push. Verify `ciphervault` binary health."
                                    ),
                                }
                            continue
                        if data.get("violations_count", 0) > 0:
                            audit_fn(
                                tool_name,
                                "blocked",
                                detail={
                                    "reason": "git_sprawl",
                                    "violations": data.get("violations_count", 0),
                                },
                                cwd=root,
                            )
                            paths = ", ".join(
                                v.get("path", "?") for v in data.get("violations", [])[:8]
                            )
                            return {
                                "action": "block",
                                "message": (
                                    "CipherVault guard: secret sprawl is staged/detected "
                                    f"({paths}). Unstage it, .gitignore it, or `ciphervault track` "
                                    "it, then retry. Details: ciphervault_scan."
                                ),
                            }
                    break
        return None
    except Exception:
        if vault_present_fn(cwd):
            return {
                "action": "block",
                "message": (
                    "CipherVault guard: internal error during security check inside a vault "
                    "workspace; failing closed."
                ),
            }
        return None


def on_transform_tool_result(tool_name, args, result, **kwargs):
    """Scrub every non-CipherVault tool result before it enters model context.
    Fails CLOSED inside a vault workspace."""
    audit_fn = _runtime.resolve(bridge, "_audit")
    try:
        if not isinstance(result, str) or not result:
            return None
        if tool_name and tool_name.startswith("ciphervault_"):
            return None
        cwd = (args or {}).get("cwd") or (args or {}).get("workdir") or os.getcwd()
        max_chars = int(_runtime.resolve(_self, "_MAX_RESULT_CHARS"))
        oversized = len(result) > max_chars
        sample = result[:max_chars] if oversized else result
        roots = bridge._scrub_roots(args, cwd)
        if not roots:
            cleaned = binary.scrub(sample)
            if cleaned != sample or oversized:
                return cleaned + ("\n…[truncated by CipherVault scrub]" if oversized else "")
            return None
        cleaned, n = sample, 0
        for root in roots:
            cleaned, n_root, exact, _changed = _scrub_full_text(cleaned, root, timeout=15)
            n += n_root
            if not exact:
                audit_fn(
                    tool_name,
                    "scrub_unavailable",
                    detail={"withheld_bytes": len(result)},
                    cwd=root,
                )
                return (
                    "[CipherVault] tool result withheld: the exact-value scrub "
                    "could not run (CLI missing, incompatible, or timed out), so "
                    "this output was not shown. A shape-only pass could miss a "
                    "vault value entirely; failing loudly instead. Run "
                    "`hermes ciphervault doctor` to inspect the resolved CLI."
                )
        final = cleaned
        if oversized:
            final = cleaned + "\n…[truncated by CipherVault scrub]"
        detail = {
            "redactions": n,
            "output_sha256": hashlib.sha256(final.encode()).hexdigest(),
            "content_sha256": _content_sha256(_visible_text(final)),
            "output_bytes": len(final),
        }
        if len(roots) > 1:
            detail["vaults"] = len(roots)
        for root in roots:
            if not audit_fn(tool_name, "scrubbed_result", detail=detail, cwd=root):
                return (
                    "[CipherVault] tool result withheld: the audit-log write "
                    "failed, so there is no receipt for this output. Withholding "
                    "it keeps 'no hash in the chain' unambiguous."
                )
        if final != result:
            return final
        return None
    except Exception:
        return (
            "[CipherVault] tool result withheld: an unexpected scrub or "
            "audit error prevented safe release. Run `hermes ciphervault doctor`."
        )


def on_post_tool_call(tool_name, args=None, result=None, **kwargs):
    """Audit what executed: write/exec/browser tools are recorded (tool + target path only)."""
    audit_fn = _runtime.resolve(bridge, "_audit")
    try:
        if not tool_name or (tool_name not in _WRITE_TOOLS and not _is_browser_tool(tool_name)):
            return None
        args = args or kwargs.get("params") or {}
        path = ""
        for key in ("path", "file_path", "file", "url"):
            if isinstance(args, dict) and args.get(key):
                path = str(args[key])
                break
        cwd = (
            (args.get("cwd") or args.get("workdir") or os.getcwd())
            if isinstance(args, dict)
            else os.getcwd()
        )
        roots = bridge._scrub_roots(args, cwd) if isinstance(args, dict) else []
        for root in roots or [cwd]:
            audit_fn(tool_name, "executed", path=path, cwd=root)
        return None
    except Exception:
        return None


def on_tool_request(tool_name, args, original_args, **kwargs):
    """Middleware: default the session cwd into ciphervault_* calls that omitted it,
    and attach a one-time ambient workspace posture summary per session/vault."""
    try:
        if tool_name and tool_name.startswith("ciphervault_") and isinstance(args, dict):
            eff_cwd = args.get("cwd") or os.getcwd()
            vault_root = _runtime.resolve(bridge, "_vault_root")(eff_cwd)
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
