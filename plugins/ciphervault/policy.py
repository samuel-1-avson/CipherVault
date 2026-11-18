"""Workspace `.ciphervault/policy.toml` parsing, profile enforcement, glob allowlists, and URL safety."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
from pathlib import Path

from . import _runtime, bridge

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

_self = sys.modules[__name__]

_ENV_KEY_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")
_ALLOW_KEY_PATTERN_RE = re.compile(r"\A[A-Za-z0-9_*]+\Z")

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

_ALLOWED_ROOT_SECTIONS = frozenset({"vault", "profiles", "upstreams"})
_ALLOWED_VAULT_KEYS = frozenset({
    "sealed_mode",
    "default_no_net",
    "description",
    "sandbox_read_paths",
    "upstreams",
})
_ALLOWED_PROFILE_KEYS = frozenset({
    "description",
    "commands",
    "allow_keys",
    "require_keys",
    "no_net",
    "proxy",
    "require_explicit_approval",
    "sandbox_read_paths",
    "upstreams",
})


# ---------------------------------------------------------------- glob matching

def _glob_match(value: str, pattern: str) -> bool:
    """Match an environment key name against a `*`-glob pattern (e.g. `TEST_*`, `*_API_KEY`)."""
    if "*" not in pattern:
        return value == pattern
    regex = "^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$"
    return re.match(regex, value) is not None


def _pattern_subset_of(req_pat: str, prof_pat: str) -> bool:
    """Return True iff every key matched by `req_pat` is guaranteed to be matched by `prof_pat`."""
    if not req_pat or not prof_pat:
        return False
    if "*" not in req_pat:
        return _glob_match(req_pat, prof_pat)
    if req_pat == prof_pat or prof_pat == "*":
        return True
    if "*" not in prof_pat:
        # A wildcard pattern can never be a subset of a single exact key.
        return False
    p_parts = prof_pat.split("*")
    r_parts = req_pat.split("*")
    head, tail = p_parts[0], p_parts[-1]
    if not r_parts[0].startswith(head):
        return False
    if tail and not r_parts[-1].endswith(tail):
        return False
    mids = [p for p in p_parts[1:-1] if p]
    if not mids:
        return True
    # Check that each middle literal appears in order inside req_pat's literal segments
    # after removing the already-matched `head` prefix and `tail` suffix.
    rem_literals = list(r_parts)
    rem_literals[0] = rem_literals[0][len(head):]
    if tail:
        rem_literals[-1] = rem_literals[-1][:-len(tail)]
    seg_idx = 0
    pos_in_seg = 0
    for mid in mids:
        found = False
        while seg_idx < len(rem_literals):
            loc = rem_literals[seg_idx].find(mid, pos_in_seg)
            if loc != -1:
                pos_in_seg = loc + len(mid)
                found = True
                break
            seg_idx += 1
            pos_in_seg = 0
        if not found:
            return False
    return True


def _pattern_covered_by(req_pat: str, prof_patterns: list[str]) -> bool:
    """Return True iff `req_pat` is covered by (does not widen) `prof_patterns`."""
    return any(_pattern_subset_of(req_pat, pp) for pp in prof_patterns)


def _validate_allow_key_pattern(pat: str) -> bool:
    if not pat or not _ALLOW_KEY_PATTERN_RE.fullmatch(pat):
        return False
    if "*" not in pat:
        return bool(_ENV_KEY_RE.fullmatch(pat))
    return True


# ---------------------------------------------------------------- TOML loading

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
        root = _runtime.resolve(bridge, "_vault_root")(cwd)
    except Exception:
        root = None
    candidates = []
    if root is not None:
        candidates.append(Path(root) / ".ciphervault" / "policy.toml")
    if cwd:
        p = Path(cwd)
        if root is None or not bridge._same_dir(p, root):
            candidates.append(p / ".ciphervault" / "policy.toml")
    for cand in candidates:
        try:
            if cand.is_file():
                return cand
        except OSError:
            continue
    return None


def _validate_policy_schema(parsed: dict) -> str | None:
    """Fail closed on unknown top-level, [vault], or [profiles.<name>] keys."""
    for key in parsed:
        if key not in _ALLOWED_ROOT_SECTIONS:
            return f"invalid .ciphervault/policy.toml: unknown top-level section/key {key!r}"
    vault_sec = parsed.get("vault")
    if vault_sec is not None:
        if not isinstance(vault_sec, dict):
            return "invalid .ciphervault/policy.toml: [vault] must be a table"
        for k in vault_sec:
            if k not in _ALLOWED_VAULT_KEYS:
                return f"invalid .ciphervault/policy.toml: unknown [vault] key {k!r}"
    profiles = parsed.get("profiles")
    if profiles is not None:
        if not isinstance(profiles, dict):
            return "invalid .ciphervault/policy.toml: [profiles] must be a table"
        for pname, prof in profiles.items():
            if not isinstance(prof, dict):
                return f"invalid .ciphervault/policy.toml: [profiles.{pname}] must be a table"
            for k in prof:
                if k not in _ALLOWED_PROFILE_KEYS:
                    return f"invalid .ciphervault/policy.toml: unknown key {k!r} in [profiles.{pname}]"
    return None


def _load_policy_toml(cwd):
    """Load and validate `.ciphervault/policy.toml` if present. Returns (dict|None, error_or_None)."""
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
    schema_err = _validate_policy_schema(parsed)
    if schema_err:
        return None, schema_err
    return parsed, None


# ---------------------------------------------------------------- URL & upstream safety

def _split_proxy_upstream_spec(spec):
    """Parse `VAR=https://host[:port][/path][@Header]` into (var_name, clean_url, scheme, host, port)."""
    if not isinstance(spec, str) or "=" not in spec:
        return None, "invalid proxy_upstream: expected VAR=https://host[@HeaderName]"
    var_name, rhs = spec.split("=", 1)
    var_name = var_name.strip()
    rhs = rhs.strip()
    if not var_name or not _ENV_KEY_RE.fullmatch(var_name):
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
    if (
        scheme not in ("http", "https")
        or not parts.netloc
        or not host
        or "@" in parts.netloc
        or "%" in parts.netloc
        or parts.query
        or parts.fragment
    ):
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
    if not isinstance(policy, dict):
        return allowed

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


def _embedded_ipv4(ip):
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _IPV4_TRANSLATED_NET:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def _is_unsafe_upstream_host(host, port):
    """Return True if host is loopback, private, link-local, metadata, internal,
    or fails DNS resolution (fail closed on OSError/empty resolution)."""
    if (
        not host
        or host in _BLOCKED_OPERATOR_HOSTS
        or host.endswith((".localhost", ".local", ".internal"))
    ):
        return True
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port or 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError:
            return True
        ips = []
        for _fam, _type, _proto, _canon, sockaddr in infos:
            try:
                ips.append(ipaddress.ip_address(str(sockaddr[0]).split("%")[0]))
            except ValueError:
                return True
    if not ips:
        return True
    for raw_ip in ips:
        ip = _embedded_ipv4(raw_ip)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
            or ip in _CGNAT_NET
            or not ip.is_global
        ):
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
    if (
        scheme not in ("http", "https")
        or not parts.netloc
        or not host
        or "\\" in raw
        or "@" in parts.netloc
        or "%" in parts.netloc
        or parts.query
        or parts.fragment
    ):
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
    """Normalized operator URLs configured for the vault at `cwd`.
    Fails closed (`()`) when no vault exists or operators.json cannot be parsed."""
    env_ops = os.environ.get("CIPHERVAULT_OPERATORS", "").strip()
    if env_ops:
        raw_list = [s for s in re.split(r"[\s,;]+", env_ops) if s]
    else:
        try:
            root = _runtime.resolve(bridge, "_vault_root")(cwd)
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


def _is_public_operator_url(norm):
    """Unconditional SSRF floor: refuses loopback, private, link-local,
    CGNAT, reserved, multicast, unspecified, and internal hostnames."""
    parts = urllib.parse.urlsplit(norm)
    host = (parts.hostname or "").lower().rstrip(".")
    if (
        not host
        or host in _BLOCKED_OPERATOR_HOSTS
        or host.endswith((".localhost", ".local", ".internal"))
    ):
        return False
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(
                host,
                parts.port or (443 if parts.scheme == "https" else 80),
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
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
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
            or ip in _CGNAT_NET
            or not ip.is_global
        ):
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
    """Accept `via` endpoints only when every URL passes URL safety + public-IP
    checks AND belongs to this vault's configured operator list."""
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


# ---------------------------------------------------------------- run policy resolution

def _resolve_run_policy(params, cwd):
    """Merge `.ciphervault/policy.toml` profile defaults into `ciphervault_run` params.

    - Rejects any non-empty agent-supplied `proxy_upstream` (policy.toml-only, matching `ciphervault mcp`).
    - Supports `*` glob patterns (`TEST_*`, `*_API_KEY`) and optional/upper-bound `allow_keys`
      plus `require_keys`, matching `apps/cli/src/commands/run.rs`.
    Returns `(effective_params, error_or_None)`.
    """
    raw = dict(params) if isinstance(params, dict) else {}
    # Agent-supplied proxy_upstream is forbidden (policy.toml-only). Blank entries
    # like [""] are ignored cleanly; non-empty entries fail closed.
    agent_upstreams = _clean_proxy_upstreams(raw)
    raw.pop("proxy_upstream", None)
    if agent_upstreams:
        return None, (
            "refusing agent-supplied proxy_upstream: custom proxy upstreams must be "
            "configured by a human in .ciphervault/policy.toml [profiles.<name>.upstreams]"
        )

    policy, err = _load_policy_toml(cwd)
    if err:
        return None, err
    profile_name = str(raw.get("profile") or "").strip() or None
    configured_upstreams = _policy_configured_upstreams(policy, profile_name)
    caller_explicit_allow_keys = raw.get("allow_keys") is not None
    raw["_caller_allow_keys"] = caller_explicit_allow_keys
    raw["_require_explicit_approval"] = False

    if caller_explicit_allow_keys:
        if not isinstance(raw["allow_keys"], (list, tuple)):
            return None, "allow_keys must be a list of environment variable names or * patterns"
        req_keys = [str(k).strip() for k in raw["allow_keys"] if str(k).strip()]
        if not req_keys:
            return None, "allow_keys cannot be empty when provided"
        for k in req_keys:
            if not _validate_allow_key_pattern(k):
                return None, f"invalid allow_keys pattern {k!r}"
        raw["allow_keys"] = req_keys

    policy_upstreams: list[str] = []

    if profile_name:
        profiles = policy.get("profiles") or {}
        prof = profiles.get(profile_name) if isinstance(profiles, dict) else None
        if not isinstance(prof, dict):
            return None, f"unknown policy profile {profile_name!r} in .ciphervault/policy.toml"

        if prof.get("require_explicit_approval"):
            raw["_require_explicit_approval"] = True

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

        req_required_keys = []
        if prof.get("require_keys") is not None:
            if not isinstance(prof["require_keys"], list):
                return None, f"profile {profile_name!r} require_keys must be a list"
            for rk in prof["require_keys"]:
                rks = str(rk).strip()
                if not rks or not _ENV_KEY_RE.fullmatch(rks):
                    return None, f"profile {profile_name!r} has invalid require_keys entry {rk!r}"
                req_required_keys.append(rks)

        if prof.get("allow_keys") is not None:
            if not isinstance(prof["allow_keys"], list):
                return None, f"profile {profile_name!r} allow_keys must be a list"
            prof_keys = [str(k).strip() for k in prof["allow_keys"] if str(k).strip()]
            if not prof_keys:
                return None, f"profile {profile_name!r} has empty allow_keys"
            for pk in prof_keys:
                if not _validate_allow_key_pattern(pk):
                    return None, f"profile {profile_name!r} has invalid allow_keys pattern {pk!r}"
            for rk in req_required_keys:
                if not _pattern_covered_by(rk, prof_keys):
                    return None, (
                        f"profile {profile_name!r} require_keys entry {rk!r} "
                        "is not permitted by profile allow_keys"
                    )
            if not caller_explicit_allow_keys:
                raw["allow_keys"] = prof_keys
            else:
                req_keys = raw["allow_keys"]
                if not req_keys or any(not _pattern_covered_by(k, prof_keys) for k in req_keys):
                    return None, f"allow_keys exceeds profile {profile_name!r} allowlist"
                for rk in req_required_keys:
                    if not _pattern_covered_by(rk, req_keys):
                        return None, (
                            f"allow_keys excludes required key {rk!r} "
                            f"from profile {profile_name!r}"
                        )
        elif req_required_keys and caller_explicit_allow_keys:
            req_keys = raw["allow_keys"]
            for rk in req_required_keys:
                if not _pattern_covered_by(rk, req_keys):
                    return None, (
                        f"allow_keys excludes required key {rk!r} "
                        f"from profile {profile_name!r}"
                    )

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
            for spec in prof_specs:
                _parsed, spec_err = _split_proxy_upstream_spec(spec)
                if spec_err:
                    return None, f"profile {profile_name!r}: {spec_err}"
            raw["proxy_upstream"] = list(dict.fromkeys(prof_specs))
            policy_upstreams = _clean_proxy_upstreams(raw)

        if raw.get("no_net") is True and (raw.get("proxy") or policy_upstreams):
            return None, f"profile {profile_name!r} combines incompatible no_net=true and proxy"
    else:
        vault_sec = policy.get("vault")
        if (
            isinstance(vault_sec, dict)
            and "default_no_net" in vault_sec
            and raw.get("no_net") is None
            and not raw.get("proxy")
        ):
            raw["no_net"] = bool(vault_sec["default_no_net"])

    if policy_upstreams:
        upstream_err = _validate_proxy_upstreams(policy_upstreams, configured_upstreams)
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


def _policy_profiles_summary(cwd) -> tuple[list[dict], str | None]:
    """Return structured non-secret summaries of `[profiles.*]` from
    `.ciphervault/policy.toml` for the dashboard `/status` endpoint."""
    policy, err = _load_policy_toml(cwd)
    if err:
        return [], err
    profiles = policy.get("profiles") if isinstance(policy, dict) else None
    if not isinstance(profiles, dict):
        return [], None
    out = []
    for pname in sorted(profiles.keys()):
        prof = profiles.get(pname)
        if not isinstance(prof, dict):
            continue
        commands = [str(c).strip() for c in (prof.get("commands") or []) if str(c).strip()] if isinstance(prof.get("commands"), list) else []
        allow_keys = [str(k).strip() for k in (prof.get("allow_keys") or []) if str(k).strip()] if isinstance(prof.get("allow_keys"), list) else []
        require_keys = [str(k).strip() for k in (prof.get("require_keys") or []) if str(k).strip()] if isinstance(prof.get("require_keys"), list) else []
        raw_up = prof.get("upstreams")
        specs = []
        if isinstance(raw_up, dict):
            specs = [f"{k}={v}" for k, v in raw_up.items()]
        elif isinstance(raw_up, (list, tuple)):
            specs = [str(x).strip() for x in raw_up if str(x).strip()]
        clean_upstreams = []
        for spec in specs:
            parsed, s_err = _split_proxy_upstream_spec(spec)
            if not s_err and parsed:
                clean_upstreams.append(f"{parsed[0]}={parsed[1]}")
        out.append({
            "name": str(pname),
            "description": str(prof.get("description") or "")[:200],
            "commands": commands,
            "allow_keys": allow_keys,
            "allow_keys_count": len(allow_keys),
            "require_keys": require_keys,
            "no_net": bool(prof["no_net"]) if prof.get("no_net") is not None else None,
            "proxy": bool(prof.get("proxy", False)),
            "upstreams": sorted(set(clean_upstreams)),
        })
    return out, None
