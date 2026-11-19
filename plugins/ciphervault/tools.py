"""CipherVault agent tools (12 tools) and schema definitions."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import secrets
import shutil
import string
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path

from . import _runtime, binary, bridge, hooks, policy

_self = sys.modules[__name__]


def _attach_posture(payload: dict, cwd):
    """Attach `workspace_posture` directly to tool result JSON so the model
    reliably receives workspace posture even if middleware `reason` is not shown."""
    if not isinstance(payload, dict):
        return payload
    try:
        if _runtime.resolve(bridge, "_vault_root")(cwd) is not None:
            payload = dict(payload)
            payload["workspace_posture"] = hooks._workspace_posture_summary(cwd)
    except Exception:
        pass
    return payload


def _tool_status(params, **kwargs):
    cwd = (params or {}).get("cwd")
    res = _runtime.resolve(bridge, "_run_cli_json")(["status", "--json"], cwd)
    return json.dumps(_attach_posture(res, cwd))


def _tool_scan(params, **kwargs):
    params = params or {}
    args = ["hook", "check", "--json"]
    if params.get("deep", True):
        args.append("--deep")
    if params.get("fix"):
        args.append("--fix")
    return json.dumps(_runtime.resolve(bridge, "_run_cli_json")(args, params.get("cwd")))


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
        return {
            "success": False,
            "data": payload,
            "exit_code": res.get("exit_code"),
            "binary": res.get("binary"),
        }
    return res


def _tool_run(params, **kwargs):
    params = params or {}
    cmd = params.get("command") or []
    if not cmd:
        return json.dumps({"success": False, "error": "command is required, e.g. ['npm','test']"})
    effective, policy_err = policy._resolve_run_policy(params, params.get("cwd"))
    if policy_err:
        return json.dumps({"success": False, "error": policy_err})
    args = ["run", "--json"]
    if effective.get("dry_run"):
        args.append("--dry-run")
    profile_name = str(effective.get("profile") or "").strip()
    supports_profile = bool(
        profile_name and _runtime.resolve(binary, "_cli_supports_run_profile")()
    )
    if supports_profile:
        args += ["--profile", profile_name]
    if effective.get("env_file"):
        args += ["--env-file", effective["env_file"]]
    if effective.get("project"):
        args += ["--project", effective["project"]]
    if effective.get("env"):
        args += ["--env", effective["env"]]
    allow_keys = effective.get("allow_keys")
    caller_explicit_allow = bool(effective.get("_caller_allow_keys"))
    if allow_keys is not None and (not supports_profile or caller_explicit_allow):
        keys = [str(k).strip() for k in allow_keys if str(k).strip()]
        if not keys:
            return json.dumps({"success": False, "error": "allow_keys cannot be empty when provided"})
        args += ["--allow-keys", ",".join(keys)]
    if effective.get("proxy"):
        args.append("--proxy")
    # Only policy.toml profile upstreams can ever exist in `effective["proxy_upstream"]`.
    for spec in policy._clean_proxy_upstreams(effective):
        args += ["--proxy-upstream", spec]
    if policy._effective_no_net(effective):
        args.append("--no-net")
    args.append("--")
    args += list(cmd)
    res = _runtime.resolve(bridge, "_run_cli_json")(args, effective.get("cwd"), timeout=300)
    if effective.get("dry_run"):
        return json.dumps(res)
    res = _structured_run_failure(res)
    data = res.get("data")
    if not (
        isinstance(data, dict)
        and any(isinstance(data.get(k), str) for k in ("stdout", "stderr"))
    ):
        return json.dumps(res)
    raw = json.dumps(res)
    detail = {
        "program": str(cmd[0])[:64],
        "exit_code": data.get("exit_code"),
        "redactions": data.get("redactions"),
        "output_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "content_sha256": hooks._content_sha256(data.get("stdout") or ""),
        "output_bytes": len(raw),
    }
    if effective.get("profile"):
        detail["profile"] = str(effective["profile"])[:64]
    if _runtime.resolve(bridge, "_audit")(
        "ciphervault_run", "scrubbed_result", detail=detail, cwd=effective.get("cwd")
    ):
        return raw
    withheld = (
        "[CipherVault] run output withheld: the audit-log write failed, so "
        "there is no receipt for it. Exit code and counts are kept."
    )
    return json.dumps(
        dict(res, data=dict(data, stdout=withheld, stderr=""), audit_receipt=False)
    )


def _tool_push(params, **kwargs):
    params = params or {}
    cwd = params.get("cwd")
    shred = params.get("shred_working_copy")
    if shred is None:
        pol, err = policy._load_policy_toml(cwd)
        if err:
            return json.dumps({"success": False, "error": err})
        shred = bool((pol.get("vault") or {}).get("sealed_mode", False))
    args = ["push", "-m", params.get("message", "Agent snapshot")]
    if params.get("local_only", True):
        args.append("--local")
    if shred:
        args.append("--shred")
    res = _runtime.resolve(bridge, "_run_cli")(args, cwd, timeout=300)
    if res.get("success"):
        res["output"] = binary.scrub(res["output"])
    return json.dumps(res)


# ---------------------------------------------------------------- env doctor

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
_DOCKERFILE_ENV_RE = re.compile(r"(?m)^\s*(?:ARG|ENV)\s+([A-Z][A-Z0-9_]{1,})(?:=|\s|$)")
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
        if policy._ENV_KEY_RE.fullmatch(key):
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
        if (
            (val.startswith('"') and not val.endswith('"'))
            or (val.endswith('"') and not val.startswith('"'))
            or (val.startswith("'") and not val.endswith("'"))
            or (val.endswith("'") and not val.startswith("'"))
            or val in ('"', "'")
        ):
            issues.append("UNSTRIPPED_QUOTES")

    if not val.strip():
        issues.append("EMPTY_VALUE")
        return val, issues

    if _PLACEHOLDER_VAL_RE.search(val.strip()):
        issues.append("PLACEHOLDER_VALUE")
        return val, issues

    if re.search(r"(?:_URL|_URI|_ENDPOINT|_DSN)$", key):
        try:
            parsed_url = urllib.parse.urlsplit(val.strip())
            scheme_ok = bool(
                parsed_url.scheme and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed_url.scheme)
            )
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
    """Parse one .env file in RAM and return (keys_set, anomaly_list)."""
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
        if not policy._ENV_KEY_RE.fullmatch(key):
            continue
        keys.add(key)
        _val, issues = _lint_dotenv_line(key, raw_rhs)
        for issue in issues:
            pair = (key, issue)
            if pair not in seen_anomalies:
                seen_anomalies.add(pair)
                anomalies.append({"key": key, "issue": issue})
    return keys, anomalies


def _tool_env_doctor(params, **kwargs):
    params = params or {}
    cwd = params.get("cwd") or os.getcwd()
    root_path = Path(cwd)
    if not root_path.is_dir():
        return json.dumps({"success": False, "error": f"workspace directory does not exist: {cwd}"})
    resolved_root = root_path.resolve()
    vault_cwd = _runtime.resolve(bridge, "_vault_cwd")(cwd)
    run_cli_json_fn = _runtime.resolve(bridge, "_run_cli_json")

    if _runtime.resolve(binary, "_cli_supports_env_doctor")(vault_cwd):
        cli_args = ["env-doctor", "--json"]
        if params.get("env_file"):
            rel = str(params["env_file"]).strip()
            cand = (resolved_root / rel).resolve()
            if not cand.is_relative_to(resolved_root):
                return json.dumps({"success": False, "error": "env_file must stay inside workspace cwd"})
            cli_args += ["--env-file", rel]
        if params.get("sync_env_example"):
            cli_args.append("--sync-env-example")
        res = run_cli_json_fn(cli_args, str(resolved_root), timeout=30)
        if res.get("success") and isinstance(res.get("data"), dict):
            return json.dumps(_attach_posture(res["data"], cwd))

    tracked_paths = []
    sealed = False
    status_res = run_cli_json_fn(["status", "--json"], vault_cwd, timeout=20)
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

    if sealed or (
        status_res.get("success")
        and isinstance(status_res.get("data"), dict)
        and status_res["data"].get("vault")
        and not vault_keys_set
    ):
        dry_args = ["run", "--dry-run", "--json"]
        if params.get("env_file"):
            dry_args += ["--env-file", str(params["env_file"]).strip()]
        dry_args += ["--", "echo", "ok"]
        dry_res = run_cli_json_fn(dry_args, vault_cwd, timeout=30)
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


# ---------------------------------------------------------------- secret generation & prompt

# Path validation lives in `bridge` so the pre_tool_call gate and the tools
# share one definition; re-exported here for the facade.
_validate_env_file = bridge._validate_env_file


def _env_file_has_key(target_path: Path, name: str) -> bool:
    """Return True if `target_path` already defines `name=...` (never returns value)."""
    if not target_path.is_file():
        return False
    pattern = re.compile(rf"^(?:\ufeff)?(?:export\s+)?{re.escape(name)}\s*=")
    try:
        for line in target_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if pattern.match(line):
                return True
    except OSError:
        return False
    return False


def _upsert_env_vars(target_path: Path, pairs: list[tuple[str, str]], replace=()) -> None:
    """Append KEY=value lines to `target_path`, or replace an existing KEY line
    when KEY is in `replace` (the user approved replacing it). Any other
    existing KEY refuses the whole write before the file changes."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    if target_path.is_file():
        lines = target_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    allowed = set(replace)
    for name, _value in pairs:
        if name in allowed:
            continue
        pattern = re.compile(rf"^(?:\ufeff)?(?:export\s+)?{re.escape(name)}\s*=")
        if any(pattern.match(line) for line in lines):
            raise ValueError(
                f"{name} already exists in {target_path.name}; refusing to replace it without the user's confirmation"
            )
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


def _generate_random_secret_value(fmt: str, nbytes: int) -> str:
    if fmt == "base64url":
        return secrets.token_urlsafe(nbytes)
    if fmt == "hex":
        return secrets.token_hex(nbytes)
    if fmt == "uuid":
        raw_uuid = bytearray(secrets.token_bytes(16))
        raw_uuid[6] = (raw_uuid[6] & 0x0F) | 0x40
        raw_uuid[8] = (raw_uuid[8] & 0x3F) | 0x80
        return str(uuid.UUID(bytes=bytes(raw_uuid)))
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(nbytes))


def _check_legacy_sealed_guard(cwd, vault_cwd, target_path: Path, track_arg: str, native_cmd: str) -> str | None:
    """Before a legacy CLI fallback writes a working-tree `.env` file and runs `push`,
    verify the vault is NOT sealed — otherwise writing a 1-line `.env` and pushing
    would silently wipe all previously sealed keys from HEAD! Fails CLOSED."""
    if _runtime.resolve(bridge, "_vault_root")(cwd) is None:
        return None
    status_res = _runtime.resolve(bridge, "_run_cli_json")(["status", "--json"], vault_cwd, timeout=20)
    if not status_res.get("success") or not isinstance(status_res.get("data"), dict):
        return (
            f"Cannot verify vault seal state before mutating secrets with a legacy CLI; "
            f"failing closed to avoid wiping previously sealed keys. Upgrade CipherVault CLI "
            f"to support `{native_cmd}`."
        )
    sdata = status_res["data"]
    if not sdata.get("vault"):
        return None
    tracked_norm = {
        str(p).replace("\\", "/").lstrip("./") for p in (sdata.get("tracked_paths") or [])
    }
    target_norm = track_arg.replace("\\", "/").lstrip("./")
    if sdata.get("working_tree_sealed") is True or (
        target_norm in tracked_norm and not target_path.is_file()
    ):
        return (
            f"Working tree is sealed: a legacy CipherVault CLI cannot safely update a single "
            f"key without overwriting previously sealed secrets. Upgrade CipherVault CLI to "
            f"support native `{native_cmd}` (which merges in RAM without touching disk)."
        )
    return None


def _tool_secret_generate(params, **kwargs):
    params = params or {}
    name = str(params.get("name") or "").strip()
    if not policy._ENV_KEY_RE.fullmatch(name):
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
    vault_root, _base_dir, target_path, path_err = _runtime.resolve(bridge, "_secret_write_target")(
        cwd, env_file
    )
    if path_err:
        return json.dumps({"success": False, "error": path_err})

    overwrite = bool(params.get("overwrite", False))
    seal_param = params.get("seal")
    if seal_param is None:
        pol, p_err = policy._load_policy_toml(cwd)
        seal = bool((pol.get("vault") or {}).get("sealed_mode", False)) if (not p_err and isinstance(pol, dict)) else False
    else:
        seal = bool(seal_param)

    vault_cwd = str(vault_root)
    track_arg = target_path.relative_to(vault_root).as_posix()

    # Prefer native `ciphervault vault generate`: zero plaintext in Python or on disk.
    # Without --overwrite the CLI refuses an existing key, sealed or not.
    if _runtime.resolve(binary, "_cli_supports_vault_secret")(vault_cwd):
        cli_args = [
            "vault", "generate", name,
            "--format", fmt,
            "--bytes", str(nbytes),
            "--env-file", track_arg,
            "--json",
        ]
        if seal:
            cli_args.append("--seal")
        if overwrite:
            cli_args.append("--overwrite")
        res = _runtime.resolve(bridge, "_run_cli_json")(cli_args, vault_cwd, timeout=120)
        if not res.get("success") or not isinstance(res.get("data"), dict):
            err_out = {
                "success": False,
                "error": binary.scrub(res.get("error") or "ciphervault vault generate failed"),
            }
            if res.get("binary") == "missing":
                err_out["binary"] = "missing"
            return json.dumps(err_out)
        data = res["data"]
        if data.get("success") is False:
            return json.dumps({
                "success": False,
                "error": binary.scrub(str(data.get("error") or "ciphervault vault generate failed")),
            })
        eff_sealed = bool(data.get("sealed", seal))
        _runtime.resolve(bridge, "_audit")(
            "ciphervault_secret_generate",
            "generated",
            path=env_file,
            detail={"name": name, "format": fmt, "sealed": eff_sealed, "overwrite": overwrite},
            cwd=vault_cwd,
        )
        return json.dumps({
            "success": True,
            "name": str(data.get("name") or name),
            "format": str(data.get("format") or fmt),
            "length_chars": data.get("length_chars"),
            "sha256_prefix": data.get("sha256_prefix"),
            "env_file": str(data.get("env_file") or env_file),
            "sealed": eff_sealed,
            "snapshot_head": data.get("snapshot_head"),
        })

    # Legacy CLI fallback: fail CLOSED if the vault working tree is sealed!
    sealed_err = _check_legacy_sealed_guard(
        cwd, vault_cwd, target_path, track_arg, "ciphervault vault generate"
    )
    if sealed_err:
        return json.dumps({"success": False, "error": sealed_err})

    if not overwrite and _env_file_has_key(target_path, name):
        return json.dumps({
            "success": False,
            "error": (
                f"Secret {name!r} already exists in {env_file}. "
                "Pass overwrite=true (requires explicit approval) to replace it."
            ),
        })

    value = _generate_random_secret_value(fmt, nbytes)
    length_chars = len(value)
    sha256_prefix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]

    def _scrub_generated(msg):
        return binary.scrub(str(msg).replace(value, "[REDACTED]"))

    try:
        _upsert_env_vars(target_path, [(name, value)], replace={name} if overwrite else ())
        run_cli_fn = _runtime.resolve(bridge, "_run_cli")
        track_res = run_cli_fn(["track", track_arg], vault_cwd, timeout=60)
        if not track_res.get("success"):
            return json.dumps({
                "success": False,
                "error": _scrub_generated(track_res.get("error") or "ciphervault track failed"),
            })
        push_args = ["push", "--local", "-m", f"Generated secret {name}"]
        if seal:
            push_args.append("--shred")
        push_res = run_cli_fn(push_args, vault_cwd, timeout=120)
        if not push_res.get("success"):
            return json.dumps({
                "success": False,
                "error": _scrub_generated(push_res.get("error") or "ciphervault push failed"),
            })
        _runtime.resolve(bridge, "_audit")(
            "ciphervault_secret_generate",
            "generated",
            path=env_file,
            detail={"name": name, "format": fmt, "sealed": seal, "overwrite": overwrite},
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


def _existing_secret_names(vault_cwd, target_path: Path, track_arg: str, names) -> tuple[set, bool]:
    """Which of `names` the vault's `track_arg` env file already defines, and
    whether that answer is certain. Reads key names only, never values: from
    the plaintext file when present, else from the vault (a sealed file is not
    on disk). Uncertain answers make the caller ask before every key."""
    wanted = set(names)
    found = {n for n in wanted if _env_file_has_key(target_path, n)}
    run_cli_json_fn = _runtime.resolve(bridge, "_run_cli_json")
    status = run_cli_json_fn(["status", "--json"], vault_cwd, timeout=20)
    if status.get("success") and isinstance(status.get("data"), dict):
        tracked = {
            str(p).replace("\\", "/").lstrip("./")
            for p in (status["data"].get("tracked_paths") or [])
        }
        if track_arg.replace("\\", "/").lstrip("./") not in tracked and not target_path.exists():
            return found, True  # a new file: nothing in it to replace
    listing = run_cli_json_fn(
        ["run", "--dry-run", "--json", "--env-file", track_arg, "--", "echo", "ok"],
        vault_cwd,
        timeout=30,
    )
    if listing.get("success") and isinstance(listing.get("data"), dict):
        listed = {
            str(item.get("name"))
            for item in (listing["data"].get("secrets") or [])
            if isinstance(item, dict) and item.get("name")
        }
        return found | (listed & wanted), True
    return found, False


def _confirm_replace(name: str, env_file: str, certain: bool = True) -> bool:
    """Ask the user at the terminal before replacing an existing key. Only an
    explicit "y" or "yes" counts; anything else, or no answer, keeps it."""
    state = "already exists" if certain else "may already exist (could not check)"
    try:
        answer = input(f"{name} {state} in {env_file}. Replace it? [y/N]: ")
    except (EOFError, OSError):
        return False
    return answer.strip().lower() in ("y", "yes")


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
        if not policy._ENV_KEY_RE.fullmatch(name):
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
    vault_root, _base_dir, target_path, path_err = _runtime.resolve(bridge, "_secret_write_target")(
        cwd, env_file
    )
    if path_err:
        return json.dumps({"success": False, "error": path_err})

    seal_param = params.get("seal")
    seal = True if seal_param is None else bool(seal_param)
    requested_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if os.environ.get("CIPHERVAULT_INTERACTIVE_PROMPT") == "1" and sys.stdin.isatty():
        entered: list[tuple[str, str]] = []
        replace_ok: set[str] = set()
        skipped_existing: list[str] = []
        vault_cwd = str(vault_root)
        track_arg = target_path.relative_to(vault_root).as_posix()

        def _scrub_entered(msg):
            out = str(msg)
            for _k, v in entered:
                if v:
                    out = out.replace(v, "[REDACTED]")
            return binary.scrub(out)

        try:
            existing, certain = _existing_secret_names(
                vault_cwd, target_path, track_arg, [item["name"] for item in normalized_keys]
            )
            confirm_fn = _runtime.resolve(_self, "_confirm_replace")
            for item in normalized_keys:
                name = item["name"]
                if name in existing or not certain:
                    if not confirm_fn(name, env_file, certain=name in existing):
                        skipped_existing.append(name)
                        continue
                    replace_ok.add(name)
                hint_parts = []
                if item.get("reason"):
                    hint_parts.append(item["reason"])
                if item.get("expected_prefix"):
                    hint_parts.append(f"prefix: {item['expected_prefix']}")
                suffix = f" ({', '.join(hint_parts)})" if hint_parts else ""
                val = getpass.getpass(f"Enter {name}{suffix}: ")
                if not val or "\n" in val or "\r" in val or "\x00" in val:
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

            if not entered:
                return json.dumps({
                    "success": False,
                    "error": "nothing configured: the user kept every existing key",
                    "skipped_existing": skipped_existing,
                })
            extra = {"skipped_existing": skipped_existing} if skipped_existing else {}

            # Prefer native `ciphervault vault set <NAME> --stdin`: zero plaintext on disk.
            # `vault set` always replaces, so only keys that are new or that the user
            # confirmed above reach it.
            if _runtime.resolve(binary, "_cli_supports_vault_secret")(vault_cwd):
                run_cli_json_fn = _runtime.resolve(bridge, "_run_cli_json")
                last_head = None
                last_sealed = seal
                for name, val in entered:
                    cli_args = ["vault", "set", name, "--stdin", "--env-file", track_arg, "--json"]
                    if seal:
                        cli_args.append("--seal")
                    res = run_cli_json_fn(cli_args, vault_cwd, timeout=120, input_text=val)
                    if not res.get("success") or not isinstance(res.get("data"), dict):
                        return json.dumps({
                            "success": False,
                            "error": _scrub_entered(res.get("error") or f"ciphervault vault set failed for {name}"),
                        })
                    data = res["data"]
                    if data.get("success") is False:
                        return json.dumps({
                            "success": False,
                            "error": _scrub_entered(data.get("error") or f"ciphervault vault set failed for {name}"),
                        })
                    last_head = data.get("snapshot_head")
                    last_sealed = bool(data.get("sealed", seal))
                configured_names = [k for k, _v in entered]
                _runtime.resolve(bridge, "_audit")(
                    "ciphervault_secret_prompt",
                    "configured",
                    path=env_file,
                    detail={"keys": configured_names, "sealed": last_sealed},
                    cwd=vault_cwd,
                )
                return json.dumps({
                    "success": True,
                    "configured": configured_names,
                    "env_file": env_file,
                    "sealed": last_sealed,
                    "snapshot_head": last_head,
                    **extra,
                })

            # Legacy CLI fallback: fail CLOSED if vault working tree is sealed!
            sealed_err = _check_legacy_sealed_guard(
                cwd, vault_cwd, target_path, track_arg, "ciphervault vault set"
            )
            if sealed_err:
                return json.dumps({"success": False, "error": sealed_err})

            _upsert_env_vars(target_path, entered, replace=replace_ok)
            run_cli_fn = _runtime.resolve(bridge, "_run_cli")
            track_res = run_cli_fn(["track", track_arg], vault_cwd, timeout=60)
            if not track_res.get("success"):
                return json.dumps({
                    "success": False,
                    "error": _scrub_entered(track_res.get("error") or "ciphervault track failed"),
                })
            push_args = ["push", "--local", "-m", "Configured secrets via interactive prompt"]
            if seal:
                push_args.append("--shred")
            push_res = run_cli_fn(push_args, vault_cwd, timeout=120)
            if not push_res.get("success"):
                return json.dumps({
                    "success": False,
                    "error": _scrub_entered(push_res.get("error") or "ciphervault push failed"),
                })
            configured_names = [k for k, _v in entered]
            _runtime.resolve(bridge, "_audit")(
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
                **extra,
            })
        except Exception as exc:
            return json.dumps({"success": False, "error": _scrub_entered(exc)})
        finally:
            entered.clear()

    # Normal agent/desktop flow: queue metadata-only prompt (zero secrets!) in the
    # vault that owns `env_file`; the user enters the values in the desktop pane.
    prompt_path = vault_root / ".ciphervault" / "pending_secret_prompts.json"
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
    _runtime.resolve(bridge, "_audit")(
        "ciphervault_secret_prompt",
        "prompt_queued",
        path=env_file,
        detail={"keys": pending_names, "sealed": seal},
        cwd=_runtime.resolve(bridge, "_vault_cwd")(cwd),
    )
    return json.dumps({
        "success": True,
        "status": "prompt_queued",
        "pending_keys": pending_names,
        "env_file": env_file,
        "seal": seal,
        "message": (
            "Secret input prompt queued in the CipherVault desktop pane. "
            "Enter the values there — never paste secrets into chat."
        ),
    })


# ---------------------------------------------------------------- proxy doctor, diff, redact, audit, drill

def _tool_proxy_doctor(params, **kwargs):
    """Zero-knowledge dry-run proxy route diagnostic: reports which vault
    keys map to built-in provider routes vs policy.toml upstreams vs unmapped."""
    params = params or {}
    cwd = params.get("cwd")
    vault_cwd = _runtime.resolve(bridge, "_vault_cwd")(cwd)
    dry_args = ["run", "--dry-run", "--json"]
    if params.get("env_file"):
        dry_args += ["--env-file", str(params["env_file"])]
    dry_args += ["--", "echo", "ok"]
    res = _runtime.resolve(bridge, "_run_cli_json")(dry_args, vault_cwd, timeout=30)
    if not res.get("success"):
        return json.dumps(res)
    data = res.get("data") or {}
    secret_names = [
        str(item.get("name"))
        for item in (data.get("secrets") or [])
        if isinstance(item, dict) and item.get("name")
    ]
    pol, _policy_err = policy._load_policy_toml(vault_cwd)
    policy_upstreams = dict(policy._policy_configured_upstreams(pol, profile_name=params.get("profile")))
    mapped_providers = []
    mapped_policy = []
    unmapped = []
    for name in secret_names:
        if name in policy_upstreams:
            mapped_policy.append({"key": name, "upstream": policy_upstreams[name]})
        elif name in policy._KNOWN_PROXY_PROVIDERS:
            upstream, base_envs = policy._KNOWN_PROXY_PROVIDERS[name]
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
    if "--reveal" in args or "-r" in args:  # pragma: no cover
        return json.dumps({"success": False, "error": "reveal is forbidden in ciphervault_diff"})
    return json.dumps(
        _runtime.resolve(bridge, "_run_cli_json")(
            args, _runtime.resolve(bridge, "_vault_cwd")(cwd), timeout=60
        )
    )


def _tool_redact(params, **kwargs):
    params = params or {}
    cleaned, n, exact = _runtime.resolve(bridge, "cli_redact")(
        params.get("text") or "", params.get("cwd")
    )
    if not exact:
        return json.dumps({
            "success": False,
            "exact_value_check": False,
            "error": "Exact-value redaction unavailable; text withheld, not safe to quote.",
            "next": "Run `hermes ciphervault doctor` to check the resolved CLI version and capabilities.",
        })
    return json.dumps({
        "success": True,
        "text": cleaned,
        "redactions": n,
        "exact_value_check": exact,
    })


def _tool_audit(params, **kwargs):
    params = params or {}
    cwd = params.get("cwd")
    limit = str(int(params.get("limit", 50)))
    run_cli_json_fn = _runtime.resolve(bridge, "_run_cli_json")
    show = run_cli_json_fn(["agent-log", "show", "--json", "--limit", limit], cwd)
    if not show.get("success"):
        return json.dumps(show)
    verify = run_cli_json_fn(["agent-log", "verify", "--json"], cwd)
    report = verify.get("data")
    verified = bool(
        verify.get("success") and isinstance(report, dict) and report.get("ok") is True
    )
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
        text = str(params["check_text"])
        digests = [hashlib.sha256(text.encode()).hexdigest()]
        if text.strip() != text:
            digests.append(hooks._content_sha256(text))
        for digest in digests:
            check = run_cli_json_fn(
                ["agent-log", "check", "--json", "--output-sha256", digest], cwd
            )
            check_data = check.get("data")
            if not (
                check.get("success")
                and isinstance(check_data, dict)
                and isinstance(check_data.get("found"), bool)
            ):
                out.pop("check", None)
                out.update(
                    success=False,
                    check=check,
                    error="Audit output-hash lookup failed or returned an invalid response.",
                )
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
    cwd = params.get("cwd")
    via_raw = params.get("via")
    via = []
    if via_raw:
        via, err = policy._validate_via_endpoints(via_raw, cwd)
        if err:
            _runtime.resolve(bridge, "_audit")(
                "ciphervault_recovery_drill",
                "blocked",
                detail={"reason": "rejected_via_endpoint"},
                cwd=cwd,
            )
            return json.dumps({"success": False, "error": err})
    dest = tempfile.mkdtemp(prefix="cv-drill-")
    try:
        args = ["recover", "--to", dest]
        if kit:
            args += ["--kit", kit]
        if shares:
            args += ["--shares"] + list(shares)
        if via:
            args += ["--via"] + via
        res = _runtime.resolve(bridge, "_run_cli")(args, cwd, timeout=300)
        if not res.get("success"):
            return json.dumps(res)
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


# ---------------------------------------------------------------- tool schemas & redaction patterns

_TOOLS = [
    (
        "ciphervault_status",
        _tool_status,
        "Show CipherVault vault status for a workspace: tracked file PATHS (never contents), snapshot head, operator count, CLI version. Keys only.",
        {"cwd": {"type": "string", "description": "Workspace directory (default: session cwd)"}},
    ),
    (
        "ciphervault_scan",
        _tool_scan,
        "Scan workspace + staged git diffs for secret sprawl (masked: paths and violation kinds only, never values).",
        {
            "deep": {"type": "boolean", "default": True},
            "fix": {"type": "boolean", "default": False, "description": "Append findings to .gitignore automatically"},
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_run",
        _tool_run,
        "Run a command with vault secrets injected into its environment in RAM only (nothing written to disk). Output is exact-value + shape scrubbed before return. Custom proxy upstreams are configured in .ciphervault/policy.toml only. Never prints plaintext secrets.",
        {
            "command": {"type": "array", "items": {"type": "string"}, "description": "Command, e.g. ['npm','test']"},
            "profile": {"type": "string", "description": "Optional execution profile name defined in .ciphervault/policy.toml"},
            "env_file": {"type": "string"},
            "project": {"type": "string"},
            "env": {"type": "string"},
            "allow_keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional allowlist of variable names or * patterns (e.g. TEST_*) to inject (least-privilege scoping; narrows profile allow_keys)",
            },
            "no_net": {"type": "boolean", "description": "Block child outbound/inbound network access (defaults true on Linux, macOS, and Windows)"},
            "proxy": {
                "type": "boolean",
                "default": False,
                "description": "Run loopback credential proxy in parent so real API keys never enter child env (custom upstreams are configured in .ciphervault/policy.toml)",
            },
            "dry_run": {"type": "boolean", "default": False, "description": "List variable names without executing"},
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_push",
        _tool_push,
        "Create an encrypted snapshot of tracked secret files (client-side sealed; operators store ciphertext only). Local by default; local_only=false replicates to configured operators.",
        {
            "message": {"type": "string", "default": "Agent snapshot"},
            "local_only": {"type": "boolean", "default": True},
            "shred_working_copy": {
                "type": "boolean",
                "description": "Zero-fill and remove tracked plaintext files from the working directory after sealing the snapshot (defaults to [vault].sealed_mode in policy.toml)",
            },
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_recovery_drill",
        _tool_drill,
        "Prove a recovery kit or guardian shares actually restore: restores into a fresh temp dir created by the tool, returns a SHA-256 manifest (names+sizes+hashes only), then deletes that temp dir. Takes FILE PATHS only — never accept kit/share contents.",
        {
            "kit": {"type": "string", "description": "Path to kit file on disk"},
            "shares": {"type": "array", "items": {"type": "string"}, "description": "Paths to guardian share files"},
            "via": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Configured operator URLs to query instead of the endpoints printed in the kit (must belong to this vault's configured operator list and pass URL safety checks; private, loopback, link-local, and cloud-metadata hosts are refused)",
            },
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_redact",
        _tool_redact,
        "Redact secret material from text before using it anywhere: vault values matched exactly (inside the CLI), plus credential shapes. Returns masked text + redaction count.",
        {"text": {"type": "string"}, "cwd": {"type": "string"}},
    ),
    (
        "ciphervault_audit",
        _tool_audit,
        "Show the tamper-evident agent audit log: what tools did around this vault's secrets (blocked reads, approval requests, scrubbed results, writes) plus chain verification. With check_text, proves whether that exact output passed the scrub (hash lookup). Paths/decisions/counts only.",
        {
            "limit": {"type": "integer", "default": 50},
            "check_text": {"type": "string", "description": "Output text to check against the scrub log (hashed locally)"},
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_env_doctor",
        _tool_env_doctor,
        "Zero-knowledge environment diagnostics: cross-reference env vars referenced in code and .env.example against vault keys and inspect .env* files in-memory for structural issues (empty, whitespace-wrapped, unstripped quotes, placeholders, invalid URLs/JSON, prefix mismatches). Never returns secret values.",
        {
            "env_file": {"type": "string", "description": "Optional specific .env file relative to cwd"},
            "sync_env_example": {"type": "boolean", "default": False, "description": "Safely create/update .env.example with KEY= # [required] placeholders"},
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_secret_generate",
        _tool_secret_generate,
        "Generate a cryptographically random secret inside an existing vault without exposing the value to chat or logs. `cwd` must be inside a CipherVault vault and `env_file` inside that vault; every call asks the user for approval first. Preserves all other sealed keys via native `ciphervault vault generate`. Refuses to overwrite an existing key unless overwrite=true, which needs its own one-time user approval. Returns only name, format, length, and SHA-256 prefix.",
        {
            "name": {"type": "string", "description": "Environment variable name ([A-Za-z_][A-Za-z0-9_]*)"},
            "format": {"type": "string", "enum": ["base64url", "hex", "uuid", "alphanumeric"], "default": "base64url"},
            "bytes": {"type": "integer", "default": 32, "description": "Entropy length in bytes (16..64)"},
            "env_file": {"type": "string", "default": ".env"},
            "seal": {"type": "boolean", "description": "Keep/shred the plaintext working copy after sealing the encrypted snapshot"},
            "overwrite": {
                "type": "boolean",
                "default": False,
                "description": "Replace an existing key if already present (defaults to false; requires explicit user approval when true)",
            },
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_diff",
        _tool_diff,
        "Compare key-level secret changes between snapshots or against the working tree (always masked; never reveals plaintext values).",
        {
            "snapshot_a": {"type": "string", "description": "Old snapshot ID or 'head'/'working'"},
            "snapshot_b": {"type": "string", "description": "New snapshot ID or 'head'/'working'"},
            "file": {"type": "string", "description": "Limit diff to a specific relative file path"},
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_proxy_doctor",
        _tool_proxy_doctor,
        "Dry-run proxy route diagnostic: report which vault keys map to built-in provider routes vs .ciphervault/policy.toml upstreams vs unmapped keys. Never exposes secret values.",
        {
            "env_file": {"type": "string"},
            "profile": {"type": "string", "description": "Optional profile name from .ciphervault/policy.toml"},
            "cwd": {"type": "string"},
        },
    ),
    (
        "ciphervault_secret_prompt",
        _tool_secret_prompt,
        "Queue a secure secret input prompt in the CipherVault desktop pane (or interactive TTY) so the user can supply missing API keys or credentials without pasting secrets into chat. `cwd` must be inside a CipherVault vault and `env_file` inside that vault; every call asks the user for approval first, and the terminal prompt asks again before replacing a key that already exists.",
        {
            "keys": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "reason": {"type": "string"},
                                "expected_prefix": {"type": "string"},
                            },
                            "required": ["name"],
                        },
                    ]
                },
                "description": "List of secret key names or {name, reason?, expected_prefix?} objects to request",
            },
            "env_file": {"type": "string", "default": ".env"},
            "seal": {"type": "boolean", "default": True, "description": "Shred the plaintext working copy after pushing the encrypted snapshot"},
            "cwd": {"type": "string"},
        },
    ),
]

_REDACTION_PATTERNS = [
    r"cvst1\.[A-Za-z0-9._~=-]+",
    r"sk_live[\w-]{8,}",
    r"sk_test[\w-]{8,}",
    r"ghp_[\w]{20,}",
    r"AKIA[0-9A-Z]{16}",
]
