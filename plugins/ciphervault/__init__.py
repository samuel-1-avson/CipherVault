"""CipherVault Hermes plugin — zero-knowledge secrets for AI agents.

Thin facade over focused submodules (`binary`, `bridge`, `policy`, `hooks`,
`tools`, `secret_source`, `setup`) so Hermes registration, external callers,
and test monkeypatches on the top-level plugin module all continue working.

Surfaces registered (see plugin.yaml):
  tools        ciphervault_status / scan / run / push / recovery_drill / redact /
               audit / env_doctor / secret_generate / diff / proxy_doctor /
               secret_prompt
  hooks        on_session_start        (reset posture cache, track session_id)
               pre_llm_call            (inject cached 1-line workspace posture)
               pre_tool_call           (leak guard: blocks secret reads/exfil)
               transform_tool_result   (scrubs every non-CipherVault result)
               post_tool_call          (audits write/exec/browser tool calls)
  middleware   tool_request            (defaults ciphervault_* cwd + posture)
  secret src   "ciphervault"           (Hermes env vars sourced from a vault)
  commands     /ciphervault (chat), `hermes ciphervault` (terminal)
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import types
import urllib.parse
import urllib.request
from pathlib import Path

# Support callers that load `__init__.py` via `importlib.util.spec_from_file_location`
# without first registering `__name__` in `sys.modules`.
if __name__ not in sys.modules:
    _pkg_stub = types.ModuleType(__name__)
    _pkg_stub.__file__ = __file__
    _pkg_stub.__path__ = [str(Path(__file__).resolve().parent)]
    _pkg_stub.__package__ = __name__
    _pkg_stub.__spec__ = __spec__
    sys.modules[__name__] = _pkg_stub

from . import _runtime, binary, bridge, hooks, policy, secret_source, setup, tools  # noqa: E402

# Re-export public and test symbols cleanly from submodules.
from ._runtime import PLUGIN_DIR, PLUGIN_VERSION, _SESSION_STATE, _ctx  # noqa: E402
from .binary import (  # noqa: E402
    RELEASE_ASSETS,
    RELEASE_BASE,
    RELEASE_BINARY_SHA256,
    RELEASE_SUPPORTS_GUARD,
    RELEASE_VERSION,
    _CLI_CAPABILITIES,
    _CLI_PROFILE_SUPPORT,
    _COMPATIBLE_CLI_HINT,
    _DOWNLOAD_ATTEMPTS,
    _DOWNLOAD_MAX_BYTES,
    _DOWNLOAD_RETRY_DELAY,
    _ENV_DOCTOR_SUPPORT_CACHE,
    _ENV_KEEP,
    _PLATFORM_LABELS,
    _VAULT_SECRET_SUPPORT_CACHE,
    _cli_supports_env_doctor,
    _cli_supports_run_profile,
    _cli_supports_vault_secret,
    _content_range_start,
    _data_bin_dir,
    _download_resumable,
    _hermes_home,
    _hermes_home_resolver,
    _install_bootstrapped_binary,
    _minimal_env,
    _read_configured_binary_path,
    _release_asset,
    binary_diagnostics,
    bootstrap_binary,
    find_binary,
    scrub,
)
from .bridge import (  # noqa: E402
    _AUDIT_HMAC_KEY,
    _BRIDGE_LOCK,
    _BRIDGE_POOL,
    _MAX_BRIDGES,
    _NO_STDIO_BINARIES,
    _ORIG_CLI_REDACT,
    _ORIG_RUN_CLI,
    _ORIG_RUN_CLI_JSON,
    _StdioBridge,
    _anchor_async,
    _arg_vault_roots,
    _audit,
    _audit_hmac_hex,
    _bridge_request,
    _call_cli_redact,
    _close_all_bridges,
    _complete_redact_response,
    _iter_strings,
    _nearest_vault_lenient,
    _run_cli,
    _run_cli_json,
    _same_dir,
    _scrub_roots,
    _secret_write_target,
    _vault_audit_hmac_key_bytes,
    _vault_cwd,
    _vault_present,
    _vault_root,
    cli_redact,
)
from .hooks import (  # noqa: E402
    _EXPORT_ENV_RE,
    _GIT_DANGER_RE,
    _INLINE_CODE_FLAGS,
    _INTERPRETER_BINARIES,
    _LLM_POSTURE_CACHE,
    _MAX_RESULT_CHARS,
    _POSTURE_SEEN,
    _PROTECTED_CONFIG_RE,
    _REDACT_CHUNK_CHARS,
    _REDACT_SEAM_OVERLAP,
    _SAFE_SECRET_PATH_CMD_RE,
    _SEARCH_SECRET_GLOB_RE,
    _SECRET_FILE_RE,
    _SECRET_WRITE_TOOLS,
    _SHELL_CHAIN_RE,
    _WRITE_TOOLS,
    _compute_run_rule_key,
    _content_sha256,
    _is_browser_tool,
    _is_inline_interpreter_cmd,
    _is_safe_terminal_secret_ref,
    _pending_prompt_names,
    _requested_secret_names,
    _scrub_full_text,
    _secret_write_gate,
    _unwrap_launcher_cmd,
    _visible_text,
    _workspace_posture_summary,
    on_post_tool_call,
    on_pre_tool_call,
    on_session_start,
    on_tool_request,
    on_transform_tool_result,
    pre_llm_call,
)
from .policy import (  # noqa: E402
    _BLOCKED_OPERATOR_HOSTS,
    _CGNAT_NET,
    _DEFAULT_OPERATORS,
    _ENV_KEY_RE,
    _IPV4_TRANSLATED_NET,
    _KNOWN_PROVIDER_KEYS,
    _KNOWN_PROXY_PROVIDERS,
    _clean_proxy_upstreams,
    _configured_operators,
    _effective_no_net,
    _embedded_ipv4,
    _glob_match,
    _is_public_operator_url,
    _is_safe_operator_url,
    _is_unsafe_upstream_host,
    _load_policy_toml,
    _normalize_operator_url,
    _parse_toml_fallback,
    _parse_toml_scalar,
    _pattern_covered_by,
    _pattern_subset_of,
    _policy_configured_upstreams,
    _policy_file_path,
    _policy_profiles_summary,
    _resolve_run_policy,
    _split_proxy_upstream_spec,
    _strip_toml_comment,
    _validate_policy_schema,
    _validate_proxy_upstreams,
    _validate_via_endpoints,
)
from .secret_source import _make_secret_source  # noqa: E402
from .setup import (  # noqa: E402
    _STARTER_POLICY_TOML,
    _cli_handler,
    _cli_setup,
    _hermes_secret_source_commands,
    _hermes_secret_source_plan,
    _qs_run,
    _shell_command,
    _slash_ciphervault,
    quickstart,
    setup_workspace,
)
from .tools import (  # noqa: E402
    _REDACTION_PATTERNS,
    _TOOLS,
    _attach_posture,
    _check_legacy_sealed_guard,
    _confirm_replace,
    _env_file_has_key,
    _existing_secret_names,
    _inspect_dotenv_file_in_memory,
    _lint_dotenv_line,
    _parse_example_keys,
    _scan_env_references,
    _structured_run_failure,
    _tool_audit,
    _tool_diff,
    _tool_drill,
    _tool_env_doctor,
    _tool_proxy_doctor,
    _tool_push,
    _tool_redact,
    _tool_run,
    _tool_scan,
    _tool_secret_generate,
    _tool_secret_prompt,
    _tool_status,
    _upsert_env_vars,
    _validate_env_file,
)


def register(ctx):
    _ctx["ctx"] = ctx
    for name, handler, description, props in _TOOLS:
        required = (
            ["command"] if name == "ciphervault_run"
            else ["text"] if name == "ciphervault_redact"
            else ["name"] if name == "ciphervault_secret_generate"
            else ["keys"] if name == "ciphervault_secret_prompt"
            else []
        )
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
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_middleware("tool_request", on_tool_request)
    for _registrar, fn in (
        ("register_redaction_patterns", lambda: ctx.register_redaction_patterns(_REDACTION_PATTERNS)),
        ("register_secret_source", lambda: ctx.register_secret_source(_make_secret_source())),
        (
            "register_command",
            lambda: ctx.register_command(
                "ciphervault",
                _slash_ciphervault,
                description="CipherVault: status/scan/run/push/drill/redact/doctor/diff/setup for zero-knowledge secrets",
                args_hint="<status|scan|run|push|drill|redact|doctor|diff|version|setup>",
            ),
        ),
        (
            "register_cli_command",
            lambda: ctx.register_cli_command(
                "ciphervault",
                "CipherVault zero-knowledge secrets (bootstrap/setup/status/doctor/quickstart)",
                _cli_setup,
                _cli_handler,
                description="Download/verify the CipherVault binary and inspect vault status from the terminal.",
            ),
        ),
    ):
        try:
            fn()
        except Exception:
            pass


# Bind facade namespace AFTER all re-exports so monkeypatching attributes on
# this top-level module propagates transparently into every submodule.
_runtime.bind_facade(globals(), dict(globals()))
