"""Tests for the CipherVault Hermes plugin.

Fast unit tests use a fake ctx and (mostly) a fake CLI on PATH; the
scrub/guard contracts are the security-critical parts, so they get the
most coverage. Set CV_TEST_BINARY to also run against a real CLI.
"""

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]

# Stub the Hermes secret-source ABC when running outside Hermes
# (unit tests); inside Hermes the real agent.* modules exist.
if "agent.secret_sources.base" not in sys.modules:
    try:
        import agent.secret_sources.base  # noqa: F401
    except Exception:
        import enum
        import types
        from dataclasses import dataclass, field as _field

        class _ErrorKind(enum.Enum):
            NOT_CONFIGURED = "NOT_CONFIGURED"
            BINARY_MISSING = "BINARY_MISSING"
            AUTH_FAILED = "AUTH_FAILED"
            REF_INVALID = "REF_INVALID"
            NETWORK = "NETWORK"
            EMPTY_VALUE = "EMPTY_VALUE"
            TIMEOUT = "TIMEOUT"
            INTERNAL = "INTERNAL"

        @dataclass
        class _FetchResult:
            secrets: dict = _field(default_factory=dict)
            error: object = None
            error_kind: object = None
            binary_path: object = None

        class _SecretSource:
            pass

        pkg = types.ModuleType("agent")
        sub = types.ModuleType("agent.secret_sources")
        base = types.ModuleType("agent.secret_sources.base")
        base.ErrorKind = _ErrorKind
        base.FetchResult = _FetchResult
        base.SecretSource = _SecretSource
        sys.modules.setdefault("agent", pkg)
        sys.modules.setdefault("agent.secret_sources", sub)
        sys.modules.setdefault("agent.secret_sources.base", base)

spec = importlib.util.spec_from_file_location("ciphervault_plugin", PLUGIN_DIR / "__init__.py")
cv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cv)


class FakeCtx:
    def __init__(self):
        self.tools = {}
        self.hooks = {}
        self.middleware = {}
        self.commands = {}
        self.cli_commands = {}
        self.patterns = None
        self.secret_source = None

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = (schema, handler)

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_middleware(self, kind, fn):
        self.middleware[kind] = fn

    def register_redaction_patterns(self, patterns):
        self.patterns = patterns
        return len(patterns)

    def register_secret_source(self, source):
        self.secret_source = source

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = handler

    def register_cli_command(self, name, help, setup_fn, handler_fn, description=""):
        self.cli_commands[name] = (setup_fn, handler_fn)

    def get_config(self, key, default=None):
        return default

    def dispatch_tool(self, name, args):
        return self.tools[name][1](args)


@pytest.fixture()
def ctx():
    c = FakeCtx()
    cv.register(c)
    return c


# ------------------------------------------------------------ manifest

def test_all_tools_registered(ctx):
    assert set(ctx.tools) == {
        "ciphervault_status", "ciphervault_scan", "ciphervault_run",
        "ciphervault_push", "ciphervault_recovery_drill", "ciphervault_redact",
        "ciphervault_audit", "ciphervault_env_doctor",
        "ciphervault_secret_generate", "ciphervault_diff",
        "ciphervault_proxy_doctor", "ciphervault_secret_prompt",
        "ciphervault_restore_preview",
    }


def test_manifest_and_registry_list_the_same_tools(ctx):
    manifest = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
    block = manifest.split("provides_tools:", 1)[1].split("provides_hooks:", 1)[0]
    listed = [line.strip()[2:] for line in block.splitlines() if line.strip().startswith("- ")]
    registered = [name for name, *_ in cv._TOOLS]
    assert sorted(listed) == sorted(registered) and len(set(listed)) == len(listed)
    assert len(listed) == 13
    readme = (PLUGIN_DIR / "README.md").read_text(encoding="utf-8")
    for name in listed:
        assert f"`{name}`" in readme, f"{name} missing from the plugin README"
    schema = ctx.tools["ciphervault_restore_preview"][0]
    assert schema["parameters"]["required"] == ["snapshot"]


def test_hooks_middleware_source_commands_registered(ctx):
    assert set(ctx.hooks) == {
        "on_session_start",
        "pre_llm_call",
        "pre_tool_call",
        "transform_tool_result",
        "post_tool_call",
    }
    assert set(ctx.middleware) == {"tool_request"}
    assert ctx.secret_source is not None
    assert ctx.secret_source.name == "ciphervault"
    assert "ciphervault" in ctx.commands
    assert "ciphervault" in ctx.cli_commands
    assert ctx.patterns and any("cvst1" in p for p in ctx.patterns)


# ------------------------------------------------------------ scrub

@pytest.mark.parametrize("raw", [
    "Bearer fake-test-token",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG",
    "DATABASE_URL=postgres://user:hunter2@db.internal/app",
    "token cvst1.eyJhbGciOiJIUzI1NiJ9.payload.sig here",
    "API_KEY=supersecretvalue123",
    "password: hunter2hunter2",
])
def test_scrub_redacts(raw):
    out = cv.scrub(raw)
    for leaked in ("fake-test-token", "wJalr", "hunter2", "supersecretvalue123", "eyJhbGciOiJIUzI1NiJ9"):
        assert leaked not in out


def test_scrub_passes_clean_text():
    assert cv.scrub("snapshot 9f2c head replicated") == "snapshot 9f2c head replicated"


def test_scrub_is_not_quadratic_on_long_tokens():
    import time
    for payload in ("a" * 256_000, "x" * 200_000 + "secret", "word " * 40_000,
                    "-----BEGIN FOO PRIVATE KEY-----" * 8_500):
        start = time.perf_counter()
        cv.scrub(payload)
        assert time.perf_counter() - start < 2.0


def test_drill_never_deletes_caller_chosen_dir(ctx, tmp_path, monkeypatch):
    precious = tmp_path / "precious"
    precious.mkdir()
    marker = precious / "keep.txt"
    marker.write_text("do not delete")

    def fake_run_cli(args, cwd, timeout=300):
        dest = Path(args[args.index("--to") + 1])
        (dest / "restored.txt").write_text("fake plaintext")
        return {"success": True, "binary": "test"}

    monkeypatch.setattr(cv, "_run_cli", fake_run_cli)
    out = json.loads(ctx.tools["ciphervault_recovery_drill"][1](
        {"kit": "kit.txt", "to": str(precious), "auto_delete": True}))
    assert out["success"] is True and out["drill_dir_deleted"] is True
    assert out["files_restored"] == 1
    assert marker.exists() and marker.read_text() == "do not delete"


@pytest.mark.parametrize("via, expected", [
    (["https://op1.cipherv.online/", "https://op2.cipherv.online"],
     ["https://op1.cipherv.online", "https://op2.cipherv.online"]),
    ("https://op1.cipherv.online", ["https://op1.cipherv.online"]),
])
def test_drill_queries_the_current_fleet_with_via(ctx, tmp_path, monkeypatch, via, expected):
    # A kit keeps the operators from when it was printed; a vault that
    # moved fleets must be drillable through its current configured
    # public operators.
    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "operators.json").write_text(
        json.dumps(["https://op1.cipherv.online", "https://op2.cipherv.online"]),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cv.socket, "getaddrinfo",
        lambda host, port, *a, **k: [(cv.socket.AF_INET, cv.socket.SOCK_STREAM, 6, "", ("136.65.43.84", 443))],
    )
    seen = []

    def fake_run_cli(args, cwd, timeout=300):
        seen.append(list(args))
        return {"success": True, "binary": "test"}

    monkeypatch.setattr(cv, "_run_cli", fake_run_cli)
    out = json.loads(ctx.tools["ciphervault_recovery_drill"][1](
        {"kit": "kit.txt", "via": via, "cwd": str(vault)}))
    assert out["success"] is True, out
    args = seen[0]
    start = args.index("--via") + 1
    assert args[start:start + len(expected)] == expected


def test_drill_refuses_unconfigured_via_endpoint(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "operators.json").write_text(
        json.dumps(["https://op1.cipherv.online"]), encoding="utf-8",
    )
    monkeypatch.setattr(
        cv.socket, "getaddrinfo",
        lambda host, port, *a, **k: [(cv.socket.AF_INET, cv.socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    calls = _capture_audit(monkeypatch)
    out = json.loads(ctx.tools["ciphervault_recovery_drill"][1](
        {"kit": "kit.txt", "via": ["https://attacker.example.com"], "cwd": str(vault)}))
    assert out["success"] is False
    assert "configured operator" in out["error"]
    assert not [c for c in calls if c[:1] == ["recover"]]
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "blocked" in rec[0]


@pytest.mark.parametrize("bad_url, resolved_ip", [
    ("http://169.254.169.254", "169.254.169.254"),
    ("http://169.254.169.254/latest/meta-data", "169.254.169.254"),
    ("http://[::ffff:169.254.169.254]", "::ffff:169.254.169.254"),
    ("http://metadata.google.internal", "169.254.169.254"),
    ("http://127.0.0.1:8202", "127.0.0.1"),
    ("http://localhost:8202", "127.0.0.1"),
    ("http://[::1]:8202", "::1"),
    ("http://10.0.0.1:8202", "10.0.0.1"),
    ("http://172.16.5.4:8202", "172.16.5.4"),
    ("http://192.168.1.10:8202", "192.168.1.10"),
    ("http://100.64.0.1:8202", "100.64.0.1"),
    ("https://rebind.example.com", "169.254.169.254"),
    ("https://lan.example.com", "192.168.1.50"),
])
def test_drill_refuses_private_loopback_and_metadata_via_even_if_configured(
        ctx, tmp_path, monkeypatch, bad_url, resolved_ip):
    # Even if an internal/metadata address appears in operators.json, the
    # agent tool must refuse to send the vault's recovery locator to it.
    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "operators.json").write_text(
        json.dumps([bad_url]), encoding="utf-8",
    )
    monkeypatch.setattr(
        cv.socket, "getaddrinfo",
        lambda host, port, *a, **k: [(cv.socket.AF_INET, cv.socket.SOCK_STREAM, 6, "", (resolved_ip, 80))],
    )
    calls = _capture_audit(monkeypatch)
    out = json.loads(ctx.tools["ciphervault_recovery_drill"][1](
        {"kit": "kit.txt", "via": [bad_url], "cwd": str(vault)}))
    assert out["success"] is False, (bad_url, out)
    assert not [c for c in calls if c[:1] == ["recover"]]


def test_drill_consults_hermes_url_safety_is_safe_url(ctx, tmp_path, monkeypatch):
    import types
    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "operators.json").write_text(
        json.dumps(["https://op1.cipherv.online"]), encoding="utf-8",
    )
    monkeypatch.setattr(
        cv.socket, "getaddrinfo",
        lambda host, port, *a, **k: [(cv.socket.AF_INET, cv.socket.SOCK_STREAM, 6, "", ("136.65.43.84", 443))],
    )
    checked = []
    fake_mod = types.ModuleType("tools.url_safety")
    fake_mod.is_safe_url = lambda url: (checked.append(url), False)[1]
    monkeypatch.setitem(sys.modules, "tools", types.ModuleType("tools"))
    monkeypatch.setitem(sys.modules, "tools.url_safety", fake_mod)
    calls = _capture_audit(monkeypatch)
    out = json.loads(ctx.tools["ciphervault_recovery_drill"][1](
        {"kit": "kit.txt", "via": ["https://op1.cipherv.online"], "cwd": str(vault)}))
    assert out["success"] is False
    assert checked == ["https://op1.cipherv.online"]
    assert not [c for c in calls if c[:1] == ["recover"]]


def test_drill_fails_closed_when_operators_json_is_corrupt_or_vault_absent(
        ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(
        cv.socket, "getaddrinfo",
        lambda host, port, *a, **k: [(cv.socket.AF_INET, cv.socket.SOCK_STREAM, 6, "", ("136.65.43.84", 443))],
    )
    calls = _capture_audit(monkeypatch)
    # 1. No vault in tmp_path -> no configured operators.
    out = json.loads(ctx.tools["ciphervault_recovery_drill"][1](
        {"kit": "kit.txt", "via": ["https://op1.cipherv.online"], "cwd": str(tmp_path)}))
    assert out["success"] is False
    # 2. Vault exists, but operators.json is corrupt -> fail closed, do not fall back.
    vault = _marker_vault(tmp_path / "v")
    (vault / ".ciphervault" / "operators.json").write_text("{not-json", encoding="utf-8")
    out2 = json.loads(ctx.tools["ciphervault_recovery_drill"][1](
        {"kit": "kit.txt", "via": ["https://op1.cipherv.online"], "cwd": str(vault)}))
    assert out2["success"] is False
    assert not [c for c in calls if c[:1] == ["recover"]]


def test_drill_without_via_keeps_the_kit_endpoints(ctx, monkeypatch):
    seen = []
    monkeypatch.setattr(cv, "_run_cli",
                        lambda args, cwd, timeout=300: seen.append(list(args)) or {"success": True})
    ctx.tools["ciphervault_recovery_drill"][1]({"kit": "kit.txt"})
    assert "--via" not in seen[0]


def test_minimal_env_excludes_provider_keys(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-leak")
    monkeypatch.setenv("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", "own-config")
    env = cv._minimal_env()
    assert "OPENAI_API_KEY" not in env
    assert env.get("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") == "own-config"


# ------------------------------------------------------------ audit log

def _capture_audit(monkeypatch):
    calls = []
    monkeypatch.setattr(cv, "_run_cli", lambda args, cwd, timeout=120, input_text=None:
                        (calls.append(args), {"success": True, "output": "{}", "binary": "test"})[1])
    return calls


def test_guard_block_is_audit_logged(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    calls = _capture_audit(monkeypatch)
    out = cv.on_pre_tool_call("terminal", {"command": "cat .env"})
    assert out and out["action"] == "block"
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "--decision" in rec[0] and "blocked" in rec[0]


def test_run_approval_is_audit_logged(ctx, monkeypatch):
    calls = _capture_audit(monkeypatch)
    out = cv.on_pre_tool_call("ciphervault_run", {"command": ["echo", "hi"]})
    assert out and out["action"] == "approve"
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "approval_requested" in rec[0]


def test_scrubbed_result_is_audit_logged(ctx, monkeypatch):
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (cv.scrub(text), 2, True))
    calls = _capture_audit(monkeypatch)
    out = cv.on_transform_tool_result("terminal", {}, "leak: Bearer fake-test-token")
    assert out is not None
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "scrubbed_result" in rec[0]
    import hashlib as _hl
    detail = json.loads(rec[0][rec[0].index("--detail") + 1])
    assert detail["output_sha256"] == _hl.sha256(out.encode()).hexdigest()
    assert detail["redactions"] == 2


def test_transform_passes_through_without_vault(monkeypatch, tmp_path):
    # No binary (fresh install, pre-bootstrap): results must come
    # back — locally shape-scrubbed — never withheld Hermes-wide.
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    out = cv.on_transform_tool_result(
        "terminal", {"cwd": str(tmp_path)}, "token: Bearer fake-test-token")
    assert out is not None and "withheld" not in out and "REDACTED" in out
    out = cv.on_transform_tool_result(
        "terminal", {"cwd": str(tmp_path)}, "perfectly plain output")
    assert out is None


def test_transform_passes_through_in_vaultless_project(monkeypatch, tmp_path):
    # Binary present but no .ciphervault/vault.db in the cwd tree.
    monkeypatch.setattr(cv, "find_binary", lambda: ("/bin/ciphervault", "test"))
    out = cv.on_transform_tool_result(
        "terminal", {"cwd": str(tmp_path)}, "perfectly plain output")
    assert out is None


def test_transform_missing_binary_still_withholds_in_existing_vault(monkeypatch, tmp_path):
    store = tmp_path / ".ciphervault"
    store.mkdir()
    (store / "vault.db").touch()  # discovery marker only; not a real vault or credential
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    fake_value = "obviously-fake-shape-blind-value"
    out = cv.on_transform_tool_result("terminal", {"cwd": str(tmp_path)}, fake_value)
    assert out is not None and "withheld" in out
    assert fake_value not in out
    assert "doctor" in out


@pytest.mark.parametrize("store_state", ["directory", "file"])
def test_transform_expected_vault_never_downgrades_to_vaultless(monkeypatch, tmp_path, store_state):
    vault = tmp_path / ".ciphervault"
    vault.mkdir()
    if store_state == "directory":
        (vault / "vault.db").mkdir()
    else:
        (vault / "vault.db").write_bytes(b"invalid fixture store")
    child = tmp_path / "nested"
    child.mkdir()
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    fake_value = "obviously-fake-shape-blind-value"
    assert cv._vault_present(str(child)) is True
    out = cv.on_transform_tool_result("terminal", {"cwd": str(child)}, fake_value)
    assert out and "withheld" in out
    assert fake_value not in out


def test_cli_install_dir_without_store_is_not_a_vault(monkeypatch, tmp_path):
    # The installer keeps binaries in ~/.ciphervault/bin. That layout
    # holds no vault store and must not guard every directory below it.
    (tmp_path / ".ciphervault" / "bin").mkdir(parents=True)
    child = tmp_path / "project"
    child.mkdir()
    assert cv._vault_root(str(child)) is None
    assert cv._vault_present(str(child)) is False
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    assert cv.on_transform_tool_result("terminal", {"cwd": str(child)}, "plain output") is None


def test_subdirectory_routes_redact_and_audit_to_vault_root(monkeypatch, tmp_path):
    # The CLI opens ./.ciphervault/vault.db relative to its cwd, so a
    # command run in a subdirectory must be scrubbed and receipted at
    # the workspace root, not reported as vaultless.
    (tmp_path / ".ciphervault").mkdir()
    (tmp_path / ".ciphervault" / "vault.db").write_bytes(b"discovery marker only")
    child = tmp_path / "apps" / "web"
    child.mkdir(parents=True)
    seen = []

    def run_json(args, cwd, **kwargs):
        seen.append(("json", args[0], cwd))
        return {"success": True, "data": {
            "text": "[REDACTED] tail", "redactions": 1, "exact_values_loaded": 1,
            "exact_values_complete": True, "vault": True}}

    def run(args, cwd, **kwargs):
        seen.append(("run", args[0], cwd))
        return {"success": True, "output": ""}

    monkeypatch.setattr(cv, "_run_cli_json", run_json)
    monkeypatch.setattr(cv, "_run_cli", run)
    out = cv.on_transform_tool_result("terminal", {"workdir": str(child)}, "fake-value tail")
    assert out == "[REDACTED] tail"
    assert seen and all(cwd == str(tmp_path) for _kind, _cmd, cwd in seen), seen
    assert ("json", "redact", str(tmp_path)) in seen
    assert ("run", "agent-log", str(tmp_path)) in seen


def test_transform_unexpected_scrub_error_is_fail_closed(monkeypatch):
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)

    def fail(*args, **kwargs):
        raise RuntimeError("fake backend failure")

    monkeypatch.setattr(cv, "cli_redact", fail)
    out = cv.on_transform_tool_result("terminal", {}, "obviously-fake-shape-blind-value")
    assert out is not None and "withheld" in out
    assert "obviously-fake-shape-blind-value" not in out


def test_transform_fails_closed_without_exact_scrub(monkeypatch):
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, False))
    _capture_audit(monkeypatch)
    out = cv.on_transform_tool_result("terminal", {}, "postgres://u:p@h/db")
    assert out is not None and "withheld" in out and "postgres" not in out


def test_transform_logs_clean_results_too(monkeypatch):
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    calls = _capture_audit(monkeypatch)
    out = cv.on_transform_tool_result("terminal", {}, "all clean output")
    assert out is None  # unchanged: original passes through
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "scrubbed_result" in rec[0]
    import hashlib as _hl
    detail = json.loads(rec[0][rec[0].index("--detail") + 1])
    assert detail["redactions"] == 0
    assert detail["output_sha256"] == _hl.sha256(b"all clean output").hexdigest()


def test_transform_truncates_oversized_when_head_is_clean(monkeypatch):
    monkeypatch.setattr(cv, "_MAX_RESULT_CHARS", 262_144)
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)
    out = cv.on_transform_tool_result("terminal", {}, "A" * 300_000)
    assert out is not None and len(out) < 300_000 and "truncated" in out


def test_transform_scrubs_multi_chunk_output_without_256k_clipping(monkeypatch):
    canary = "tail_exact_secret_987654"
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(
        cv,
        "cli_redact",
        lambda text, cwd, timeout=10: (
            text.replace(canary, "[REDACTED:EXACT]"),
            text.count(canary),
            True,
        ),
    )
    _capture_audit(monkeypatch)
    half = len(canary) // 2
    payload = (
        ("A" * (cv._REDACT_CHUNK_CHARS - half))
        + canary
        + ("B" * 300_000)
        + canary
        + ("C" * 50)
    )
    out = cv.on_transform_tool_result("terminal", {}, payload)
    assert out is not None
    assert canary not in out
    assert out.count("[REDACTED:EXACT]") == 2
    assert "truncated" not in out


def test_transform_withholds_when_audit_write_fails(monkeypatch):
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    monkeypatch.setattr(cv, "_audit", lambda *a, **k: False)
    out = cv.on_transform_tool_result("terminal", {}, "some output")
    assert out is not None and "withheld" in out and "audit" in out


def _marker_vault(root):
    # Discovery marker only; not a real vault or credential store.
    (root / ".ciphervault").mkdir(parents=True)
    (root / ".ciphervault" / "vault.db").write_bytes(b"discovery marker only")
    return root


def _recording_cli(monkeypatch, redacted_text="[REDACTED] tail"):
    seen = []

    def run_json(args, cwd, **kwargs):
        seen.append(("json", args[0], cwd))
        return {"success": True, "data": {
            "text": redacted_text, "redactions": 1, "exact_values_loaded": 1,
            "exact_values_complete": True, "vault": True}}

    def run(args, cwd, **kwargs):
        seen.append(("run", args[0], cwd))
        return {"success": True, "output": ""}

    monkeypatch.setattr(cv, "_run_cli_json", run_json)
    monkeypatch.setattr(cv, "_run_cli", run)
    return seen


@pytest.mark.parametrize("tool, make_args", [
    ("terminal", lambda base, demo: {"command": "cat demo/notes.txt", "workdir": str(base)}),
    ("terminal", lambda base, demo: {"command": f"cat {demo / 'notes.txt'}", "workdir": str(base)}),
    ("terminal", lambda base, demo: {"command": "cd demo && cat notes.txt", "workdir": str(base)}),
    ("read_file", lambda base, demo: {"path": str(demo / "sub" / "notes.txt")}),
])
def test_transform_exact_scrubs_with_the_vault_a_path_argument_names(
        monkeypatch, tmp_path, tool, make_args):
    # Tour finding: the workdir sat outside the vault while the command
    # read a file inside it, and the exact-value pass never ran.
    base = tmp_path / "outside"
    base.mkdir()
    demo = _marker_vault(base / "demo")
    seen = _recording_cli(monkeypatch)
    out = cv.on_transform_tool_result(tool, make_args(base, demo), "fake-value tail")
    assert out == "[REDACTED] tail"
    assert ("json", "redact", str(demo)) in seen, seen
    assert ("run", "agent-log", str(demo)) in seen, seen


def test_transform_withholds_when_a_path_points_into_a_vault_it_cannot_scrub(monkeypatch, tmp_path):
    base = tmp_path / "outside"
    base.mkdir()
    _marker_vault(base / "demo")
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    fake_value = "obviously-fake-shape-blind-value"
    out = cv.on_transform_tool_result(
        "terminal", {"command": "cat demo/notes.txt", "workdir": str(base)}, fake_value)
    assert out and "withheld" in out and fake_value not in out


def test_transform_path_tokens_outside_any_vault_stay_vaultless(monkeypatch, tmp_path):
    (tmp_path / "plain" / "dir").mkdir(parents=True)
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    args = {"command": "ls plain/dir ../elsewhere https://example.invalid/a/b *.txt",
            "workdir": str(tmp_path)}
    assert cv.on_transform_tool_result("terminal", args, "plain output") is None


def test_transform_scrubs_against_every_vault_a_call_touches(monkeypatch, tmp_path):
    home = _marker_vault(tmp_path / "home")
    other = _marker_vault(tmp_path / "other")
    seen = _recording_cli(monkeypatch)
    args = {"command": f"diff notes.txt {other / 'notes.txt'}", "workdir": str(home)}
    out = cv.on_transform_tool_result("terminal", args, "fake-value tail")
    assert out == "[REDACTED] tail"
    redacts = [cwd for kind, cmd, cwd in seen if (kind, cmd) == ("json", "redact")]
    assert redacts == [str(home), str(other)]
    receipts = [cwd for kind, cmd, cwd in seen if (kind, cmd) == ("run", "agent-log")]
    assert receipts == [str(home), str(other)]


def test_guard_checks_arguments_against_the_vault_a_path_names(monkeypatch, tmp_path):
    base = tmp_path / "outside"
    base.mkdir()
    demo = _marker_vault(base / "demo")
    seen = []
    monkeypatch.setattr(cv, "cli_redact",
                        lambda text, cwd, timeout=10: (seen.append(cwd), (text, 0, True))[1])
    out = cv.on_pre_tool_call(
        "terminal", {"command": "echo hello > demo/out.txt", "workdir": str(base)})
    assert out is None
    assert str(demo) in seen, seen


def test_post_tool_call_receipts_writes_into_a_vault_named_by_path(monkeypatch, tmp_path):
    base = tmp_path / "outside"
    base.mkdir()
    demo = _marker_vault(base / "demo")
    seen = _recording_cli(monkeypatch)
    cv.on_post_tool_call("write_file", {"path": str(demo / "notes.txt"), "content": "x"})
    assert ("run", "agent-log", str(demo)) in seen, seen


def test_scrubbed_result_receipt_hashes_the_visible_output(monkeypatch):
    # A person checks the text they saw (the terminal `output` field),
    # not the JSON envelope Hermes wraps around it.
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    calls = _capture_audit(monkeypatch)
    envelope = json.dumps({"output": "hello visible\n", "exit_code": 0, "error": None})
    assert cv.on_transform_tool_result("terminal", {}, envelope) is None
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    detail = json.loads(rec[0][rec[0].index("--detail") + 1])
    assert detail["output_sha256"] == hashlib.sha256(envelope.encode()).hexdigest()
    assert detail["content_sha256"] == hashlib.sha256(b"hello visible").hexdigest()


def test_audit_check_text_matches_visible_output_with_trailing_newline(ctx, monkeypatch):
    wanted = hashlib.sha256(b"hello visible").hexdigest()
    looked_up = []

    def run_json(args, cwd):
        if args[1] == "show":
            return {"success": True, "data": []}
        if args[1] == "verify":
            return {"success": True, "data": {"ok": True}}
        digest = args[args.index("--output-sha256") + 1]
        looked_up.append(digest)
        return {"success": True, "data": {"found": digest == wanted}}

    monkeypatch.setattr(cv, "_run_cli_json", run_json)
    out = json.loads(ctx.tools["ciphervault_audit"][1]({"check_text": "hello visible\n"}))
    assert out["success"] is True and out["check"]["found"] is True
    assert looked_up == [hashlib.sha256(b"hello visible\n").hexdigest(), wanted]


def _fake_run_result(stdout="build ok\n"):
    return {"success": True, "binary": "test", "data": {
        "exit_code": 0, "stdout": stdout, "stderr": "", "redactions": 1}}


def test_run_output_is_receipted(ctx, monkeypatch):
    calls = _capture_audit(monkeypatch)
    monkeypatch.setattr(cv, "_run_cli_json", lambda args, cwd, timeout=120: _fake_run_result())
    raw = ctx.tools["ciphervault_run"][1]({"command": ["make", "build"]})
    assert json.loads(raw)["data"]["stdout"] == "build ok\n"
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "ciphervault_run" in rec[0] and "scrubbed_result" in rec[0]
    detail = json.loads(rec[0][rec[0].index("--detail") + 1])
    assert detail["output_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert detail["content_sha256"] == hashlib.sha256(b"build ok").hexdigest()
    assert detail["redactions"] == 1 and detail["program"] == "make"


def test_run_dry_run_writes_no_output_receipt(ctx, monkeypatch):
    calls = _capture_audit(monkeypatch)
    monkeypatch.setattr(cv, "_run_cli_json",
                        lambda args, cwd, timeout=120: {"success": True, "data": {"secrets": []}})
    ctx.tools["ciphervault_run"][1]({"command": ["make"], "dry_run": True})
    assert not [c for c in calls if c[:2] == ["agent-log", "record"]]


def test_run_output_is_withheld_when_its_receipt_fails(ctx, monkeypatch):
    monkeypatch.setattr(cv, "_run_cli_json",
                        lambda args, cwd, timeout=120: _fake_run_result("build ok\n"))
    monkeypatch.setattr(cv, "_audit", lambda *a, **k: False)
    out = json.loads(ctx.tools["ciphervault_run"][1]({"command": ["make"]}))
    assert "build ok" not in json.dumps(out)
    assert out["data"]["exit_code"] == 0
    assert "withheld" in out["data"]["stdout"] and out["audit_receipt"] is False


def test_failed_run_keeps_its_structured_report_and_receipt(ctx, monkeypatch):
    # `run --json` exits with the child's status after printing its
    # report; a failing test suite must stay readable as stdout/stderr.
    report = {"status": "failed", "exit_code": 3, "stdout": "2 tests failed\n",
              "stderr": "", "redactions": 0}
    monkeypatch.setattr(cv, "_run_cli_json", lambda args, cwd, timeout=120: {
        "success": False, "error": json.dumps(report, indent=2), "exit_code": 3,
        "binary": "test"})
    calls = _capture_audit(monkeypatch)
    out = json.loads(ctx.tools["ciphervault_run"][1]({"command": ["make", "test"]}))
    assert out["success"] is False
    assert out["data"]["stdout"] == "2 tests failed\n" and out["data"]["exit_code"] == 3
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "scrubbed_result" in rec[0]


def test_run_that_never_started_is_not_withheld(ctx, monkeypatch):
    monkeypatch.setattr(cv, "_run_cli_json", lambda args, cwd, timeout=120: {
        "success": False, "error": "No vault in this directory", "exit_code": 1})
    monkeypatch.setattr(cv, "_audit", lambda *a, **k: False)
    out = json.loads(ctx.tools["ciphervault_run"][1]({"command": ["make"]}))
    assert out["error"] == "No vault in this directory"


def test_release_asset_selection(monkeypatch):
    monkeypatch.setattr(cv.sys, "platform", "win32")
    asset, sha, dest = cv._release_asset()
    assert asset == "ciphervault.exe" and dest == "ciphervault.exe"
    assert sha == cv.RELEASE_ASSETS["windows-amd64"][1]
    monkeypatch.setattr(cv.sys, "platform", "linux")
    monkeypatch.setattr(cv.platform, "machine", lambda: "x86_64")
    asset, sha, dest = cv._release_asset()
    assert asset == "ciphervault-linux-amd64" and dest == "ciphervault"
    assert sha == cv.RELEASE_ASSETS["linux-amd64"][1]
    monkeypatch.setattr(cv.sys, "platform", "darwin")
    for machine, key in (("arm64", "macos-arm64"), ("x86_64", "macos-amd64")):
        monkeypatch.setattr(cv.platform, "machine", lambda m=machine: m)
        selected = cv._release_asset()
        if key in cv.RELEASE_ASSETS:
            assert selected == (cv.RELEASE_ASSETS[key][0], cv.RELEASE_ASSETS[key][1], "ciphervault")
        else:
            # A platform without a pinned asset for this release is
            # "not published", never a KeyError at bootstrap time.
            assert selected is None


def test_pinned_release_is_guard_compatible_and_hash_pinned():
    # The pinned release ships redact --json's exact_values_complete
    # attestation (first shipped in v1.0.35). Assert the shape and floor
    # rather than one exact version so automated re-pin PRs (which only
    # rewrite binary.py) stay green without editing this test each cycle.
    version = tuple(int(part) for part in cv.RELEASE_VERSION.split("."))
    assert len(version) == 3 and version >= (1, 0, 35)
    assert cv.RELEASE_SUPPORTS_GUARD is True
    assert cv.RELEASE_BASE.endswith(f"/v{cv.RELEASE_VERSION}")
    for name, (asset, sha) in cv.RELEASE_ASSETS.items():
        assert asset and len(sha) == 64 and int(sha, 16) >= 0, name
    assert "windows-amd64" in cv.RELEASE_ASSETS


def test_every_supported_platform_has_a_pinned_release_asset():
    # The pinned release publishes Windows x64, Linux x64, and macOS arm64/Intel CLIs.
    assert set(cv.RELEASE_ASSETS) == {"windows-amd64", "linux-amd64", "macos-arm64", "macos-amd64"}
    assert cv.RELEASE_ASSETS["macos-arm64"][0] == "ciphervault-macos-arm64"
    assert cv.RELEASE_ASSETS["macos-amd64"][0] == "ciphervault-macos-amd64"
    assert len({sha for _asset, sha in cv.RELEASE_ASSETS.values()}) == 4


def test_bootstrap_names_published_platforms_when_none_fits(monkeypatch, tmp_path):
    monkeypatch.setattr(cv, "_data_bin_dir", lambda: tmp_path / "bin")
    monkeypatch.setattr(cv, "_release_asset", lambda: None)

    def unexpected_download(*args, **kwargs):
        raise AssertionError("no download without a pinned asset")

    monkeypatch.setattr(cv.urllib.request, "urlopen", unexpected_download)
    out = cv.bootstrap_binary(progress=lambda *args: None)
    assert out["success"] is False
    assert "No prebuilt" in out["error"] and "Build from source" in out["error"]
    assert "Windows x64" in out["error"]
    assert ("macOS" in out["error"]) == any(k.startswith("macos") for k in cv.RELEASE_ASSETS)
    assert not (tmp_path / "bin").exists()


class _FakeDownload:
    """Minimal urlopen() response: streams `body`, optionally dropping the
    connection after `drop_after` bytes the way http.client does."""

    def __init__(self, body, status=200, drop_after=None, content_range=None, silent_drop=False):
        self._body, self.status, self._drop = body, status, drop_after
        self._pos, self._silent = 0, silent_drop
        self.headers = {"Content-Length": str(len(body))}
        if content_range:
            self.headers["Content-Range"] = content_range

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getcode(self):
        return self.status

    def read(self, amt=-1):
        import http.client
        end = len(self._body) if amt is None or amt < 0 else self._pos + amt
        if self._drop is not None and end > self._drop:
            if self._pos >= self._drop:
                if self._silent:
                    # CPython's HTTPResponse.read(amt) returns b"" when the
                    # peer closes early, even with Content-Length unmet.
                    return b""
                raise http.client.IncompleteRead(b"", len(self._body) - self._pos)
            end = self._drop
        chunk = self._body[self._pos:end]
        self._pos += len(chunk)
        return chunk


def _bootstrap_fixture(monkeypatch, tmp_path, payload, asset_responses):
    """Wire bootstrap_binary() to a fake release whose asset requests are
    answered, in order, by `asset_responses(range_header)`."""
    import hashlib as _hashlib
    digest = _hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(cv, "RELEASE_SUPPORTS_GUARD", True)
    monkeypatch.setattr(cv, "_release_asset", lambda: ("fixture-asset", digest, "fixture-cli"))
    monkeypatch.setattr(cv, "_data_bin_dir", lambda: tmp_path / "bin")
    monkeypatch.setattr(cv, "_DOWNLOAD_RETRY_DELAY", 0)
    ranges = []

    def fake_urlopen(request, timeout=None):
        url = request if isinstance(request, str) else request.full_url
        if url.endswith("/SHA256SUMS.txt"):
            return _FakeDownload((digest + " *fixture-asset").encode() + bytes([13, 10]))
        header = None if isinstance(request, str) else request.get_header("Range")
        ranges.append(header)
        return asset_responses(header)

    monkeypatch.setattr(cv.urllib.request, "urlopen", fake_urlopen)
    return ranges


def test_bootstrap_resumes_an_interrupted_download(monkeypatch, tmp_path):
    payload = bytes(range(256)) * 400  # ~100 KiB fixture, not a real binary
    cut = 70_001

    def respond(range_header):
        if range_header is None:
            return _FakeDownload(payload, drop_after=cut)
        assert range_header == f"bytes={cut}-"
        return _FakeDownload(payload[cut:], status=206,
                             content_range=f"bytes {cut}-{len(payload) - 1}/{len(payload)}")

    ranges = _bootstrap_fixture(monkeypatch, tmp_path, payload, respond)
    out = cv.bootstrap_binary(progress=lambda *a: None)
    assert out["success"] is True, out
    assert ranges == [None, f"bytes={cut}-"]
    assert (tmp_path / "bin" / "fixture-cli").read_bytes() == payload


def test_bootstrap_resumes_after_a_silent_early_close(monkeypatch, tmp_path):
    # Real failure mode: the stream just ends short of Content-Length.
    payload = bytes(range(256)) * 400
    cut = 3_203

    def respond(range_header):
        if range_header is None:
            return _FakeDownload(payload, drop_after=cut, silent_drop=True)
        assert range_header == f"bytes={cut}-"
        return _FakeDownload(payload[cut:], status=206,
                             content_range=f"bytes {cut}-{len(payload) - 1}/{len(payload)}")

    ranges = _bootstrap_fixture(monkeypatch, tmp_path, payload, respond)
    out = cv.bootstrap_binary(progress=lambda *a: None)
    assert out["success"] is True, out
    assert ranges == [None, f"bytes={cut}-"]
    assert (tmp_path / "bin" / "fixture-cli").read_bytes() == payload


def test_bootstrap_restarts_when_the_server_ignores_range(monkeypatch, tmp_path):
    payload = b"fixture-binary-bytes" * 5000
    calls = iter([_FakeDownload(payload, drop_after=1234), _FakeDownload(payload, status=200)])
    _bootstrap_fixture(monkeypatch, tmp_path, payload, lambda header: next(calls))
    out = cv.bootstrap_binary(progress=lambda *a: None)
    assert out["success"] is True, out
    assert (tmp_path / "bin" / "fixture-cli").read_bytes() == payload


def test_bootstrap_gives_up_without_installing(monkeypatch, tmp_path):
    payload = b"fixture-binary-bytes" * 5000
    ranges = _bootstrap_fixture(monkeypatch, tmp_path, payload,
                                lambda header: _FakeDownload(payload, drop_after=0))
    out = cv.bootstrap_binary(progress=lambda *a: None)
    assert out["success"] is False
    assert "download failed" in out["error"] and str(cv._DOWNLOAD_ATTEMPTS) in out["error"]
    assert len(ranges) == cv._DOWNLOAD_ATTEMPTS
    assert not (tmp_path / "bin").exists()


def test_bootstrap_resume_cannot_bypass_the_pinned_hash(monkeypatch, tmp_path):
    payload = b"fixture-binary-bytes" * 5000
    cut = 4000

    def respond(range_header):
        if range_header is None:
            return _FakeDownload(payload, drop_after=cut)
        tampered = b"X" * (len(payload) - cut)
        return _FakeDownload(tampered, status=206,
                             content_range=f"bytes {cut}-{len(payload) - 1}/{len(payload)}")

    _bootstrap_fixture(monkeypatch, tmp_path, payload, respond)
    out = cv.bootstrap_binary(progress=lambda *a: None)
    assert out["success"] is False and "SHA-256 mismatch" in out["error"]
    assert not (tmp_path / "bin").exists()


def test_install_bootstrapped_binary_replaces_existing_atomically(tmp_path):
    dest = tmp_path / "bin" / "fixture-cli"
    dest.parent.mkdir()
    dest.write_bytes(b"old-binary")

    cv._install_bootstrapped_binary(dest, b"new-binary")

    assert dest.read_bytes() == b"new-binary"
    assert not list(dest.parent.glob("*.tmp"))


def test_install_bootstrapped_binary_moves_locked_windows_exe_aside(monkeypatch, tmp_path):
    dest = tmp_path / "bin" / "ciphervault.exe"
    dest.parent.mkdir()
    dest.write_bytes(b"running-binary")
    real_replace = cv.os.replace
    calls = {"count": 0}

    def locked_replace(src, dst):
        calls["count"] += 1
        if calls["count"] == 1:
            raise PermissionError("executable is running")
        return real_replace(src, dst)

    monkeypatch.setattr(cv.os, "name", "nt")
    monkeypatch.setattr(cv.os, "replace", locked_replace)
    cv._install_bootstrapped_binary(dest, b"new-binary")

    assert dest.read_bytes() == b"new-binary"
    assert not list(dest.parent.glob("*.tmp"))


def test_bootstrap_install_failure_is_structured(monkeypatch, tmp_path):
    payload = b"fixture-binary-bytes"
    _bootstrap_fixture(
        monkeypatch,
        tmp_path,
        payload,
        lambda header: _FakeDownload(payload),
    )
    (tmp_path / "bin").write_bytes(b"not a directory")

    out = cv.bootstrap_binary(progress=lambda *a: None)

    assert out["success"] is False
    assert "install failed" in out["error"]


@pytest.mark.parametrize("existing_binary", [False, True])
def test_bootstrap_refuses_incompatible_pin_without_shadowing(monkeypatch, tmp_path, existing_binary):
    dest_dir = tmp_path / "bin"
    dest = dest_dir / ("ciphervault.exe" if os.name == "nt" else "ciphervault")
    if existing_binary:
        dest_dir.mkdir()
        dest.write_bytes(b"working-source-fixture")
    monkeypatch.setattr(cv, "_data_bin_dir", lambda: dest_dir)
    network_calls = []

    def unexpected_download(*args, **kwargs):
        network_calls.append(args)
        raise AssertionError("an incompatible pinned CLI must not be downloaded")

    monkeypatch.setattr(cv.urllib.request, "urlopen", unexpected_download)
    # Keep the fail-closed path covered while the shipped pin is compatible.
    monkeypatch.setattr(cv, "RELEASE_SUPPORTS_GUARD", False)
    out = cv.bootstrap_binary(progress=lambda *args: None)
    assert out["success"] is False
    assert not network_calls
    assert cv.RELEASE_VERSION in out["error"] and "incompatible" in out["error"]
    assert "source" in out["next"] and "CIPHERVAULT_BIN" in out["next"]
    assert "bootstrap" not in out["next"]
    if existing_binary:
        assert dest.read_bytes() == b"working-source-fixture"
    else:
        assert not dest_dir.exists()


def test_quickstart_walks_the_demo(monkeypatch, tmp_path):
    monkeypatch.setattr(cv, "find_binary", lambda: ("/bin/ciphervault", "test"))
    calls = []

    def fake_run(binary, args, cwd):
        calls.append((args, cwd))
        return 0, "ok"

    monkeypatch.setattr(cv, "_qs_run", fake_run)
    monkeypatch.setattr(cv.tempfile, "mkdtemp", lambda prefix: str(tmp_path / "demo"))
    (tmp_path / "demo").mkdir(exist_ok=True)
    result = cv.quickstart(progress=lambda *a: None, keep=True)
    assert result["success"] is True
    seq = [c[0][0] for c in calls]
    assert seq[:4] == ["init", "track", "push", "run"]
    assert (tmp_path / "demo" / ".env").is_file()
    assert "DEMO_API_KEY" in (tmp_path / "demo" / ".env").read_text()


def test_post_tool_call_logs_writes(ctx, monkeypatch):
    calls = _capture_audit(monkeypatch)
    cv.on_post_tool_call("write_file", {"path": "src/app.py"}, "ok")
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "executed" in rec[0]
    calls.clear()
    cv.on_post_tool_call("read_file", {"path": "README.md"}, "ok")
    assert not [c for c in calls if c[:2] == ["agent-log", "record"]]


def test_run_approval_triggers_anchor(monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)
    anchored = []
    monkeypatch.setattr(cv, "_anchor_async", lambda cwd=None: anchored.append(cwd))
    out = cv.on_pre_tool_call("ciphervault_run", {"command": ["npm", "test"], "cwd": "/proj"})
    assert out and out["action"] == "approve"
    assert anchored == ["/proj"]


def test_block_does_not_trigger_anchor(monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)
    anchored = []
    monkeypatch.setattr(cv, "_anchor_async", lambda cwd=None: anchored.append(cwd))
    out = cv.on_pre_tool_call("terminal", {"command": "cat .env"})
    assert out and out["action"] == "block"
    assert anchored == []


def test_anchor_async_spawns_detached_cli(monkeypatch):
    spawned = {}

    class FakePopen:
        def __init__(self, argv, **kwargs):
            spawned["argv"] = argv
            spawned["kwargs"] = kwargs

    monkeypatch.setattr(cv, "find_binary", lambda: ("/bin/ciphervault", "test"))
    monkeypatch.setattr(cv.subprocess, "Popen", FakePopen)
    cv._anchor_async("/proj")
    assert spawned["argv"] == ["/bin/ciphervault", "agent-log", "anchor"]
    assert spawned["kwargs"].get("cwd") == "/proj"


# ------------------------------------------------------------ guard

def test_guard_blocks_terminal_cat_env(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    out = cv.on_pre_tool_call("terminal", {"command": "cat .env"})
    assert out and out["action"] == "block"


def test_guard_blocks_read_file_on_key(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    out = cv.on_pre_tool_call("read_file", {"path": "/proj/id_ed25519"})
    assert out and out["action"] == "block"


def test_guard_blocks_secret_shaped_payload(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (cv.scrub(text), 1, True))
    out = cv.on_pre_tool_call("write_file", {"path": "notes.txt", "content": "API_KEY=supersecretvalue123"})
    assert out and out["action"] == "block"


def test_guard_allows_clean_terminal(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    assert cv.on_pre_tool_call("terminal", {"command": "git status"}) is None


@pytest.mark.parametrize("path", [
    "apps/cli/src/commands/recovery_kit.rs",
    "docs/recovery_kit.md",
    "tests/recovery_kit_test.py",
])
def test_guard_allows_source_files_named_like_kits(ctx, monkeypatch, path):
    # Source and docs about kits are not kits; blocking them makes the
    # CipherVault codebase itself uneditable through Hermes.
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    assert cv.on_pre_tool_call("read_file", {"path": path}) is None
    assert cv.on_pre_tool_call("terminal", {"command": "head -n 5 " + path}) is None


@pytest.mark.parametrize("path", [
    "C:/Users/me/CipherVault-Recovery/recovery_kit.txt",
    ".ciphervault/recovery_kit_backup.txt",
    "backup/recovery_kit",
])
def test_guard_still_blocks_kit_files(ctx, monkeypatch, path):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    out = cv.on_pre_tool_call("read_file", {"path": path})
    assert out and out["action"] == "block"


def test_guard_gates_ciphervault_run_with_approval(ctx):
    out = cv.on_pre_tool_call("ciphervault_run", {"command": ["echo", "hi"]})
    assert out and out["action"] == "approve" and out.get("rule_key") == "ciphervault_run:echo"
    out = cv.on_pre_tool_call("ciphervault_run", {"command": ["echo", "hi"], "dry_run": True})
    assert out and out["action"] == "approve"


def test_guard_never_blocks_other_ciphervault_tools(ctx):
    assert cv.on_pre_tool_call("ciphervault_status", {}) is None
    assert cv.on_pre_tool_call("ciphervault_redact", {"text": "API_KEY=x"}) is None


def test_transform_scrubs_other_results(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (cv.scrub(text), 1, True))
    out = cv.on_transform_tool_result("terminal", {}, "leak: Bearer fake-test-token")
    assert out is not None and "fake-test-token" not in out


def test_transform_leaves_clean_and_own_results(ctx, monkeypatch):
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)
    assert cv.on_transform_tool_result("terminal", {}, "all good") is None
    assert cv.on_transform_tool_result("ciphervault_run", {}, "Bearer fake-test-token") is None


def test_middleware_defaults_cwd(ctx):
    out = cv.on_tool_request("ciphervault_status", {}, {})
    assert out and out["args"]["cwd"]
    assert cv.on_tool_request("ciphervault_status", {"cwd": "/x"}, {}) is None
    assert cv.on_tool_request("terminal", {}, {}) is None


# ------------------------------------------------------------ tools

def test_drill_requires_paths(ctx):
    out = json.loads(ctx.tools["ciphervault_recovery_drill"][1]({}))
    assert out["success"] is False


def test_run_requires_command(ctx):
    out = json.loads(ctx.tools["ciphervault_run"][1]({}))
    assert out["success"] is False


def test_missing_binary_is_structured(ctx, monkeypatch):
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    out = json.loads(ctx.tools["ciphervault_status"][1]({}))
    assert out["success"] is False and out["binary"] == "missing" and "next" in out


def test_redact_tool_withholds_shape_only_fallback(ctx, monkeypatch):
    fake_value = "obviously-fake-shape-blind-value"
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd: (text, 0, False))
    out = json.loads(ctx.tools["ciphervault_redact"][1]({"text": fake_value}))
    assert out["success"] is False
    assert out["exact_value_check"] is False
    assert fake_value not in json.dumps(out)
    assert "doctor" in out["next"]


@pytest.mark.parametrize("payload", [
    {}, [], {"text": None, "redactions": 0},
    {"text": "fake text", "redactions": "not-a-count"},
    {"text": "fake text", "redactions": -1},
])
def test_redact_invalid_backend_response_is_not_exact(monkeypatch, payload):
    monkeypatch.setattr(cv, "_run_cli_json", lambda *a, **k: {"success": True, "data": payload})
    _cleaned, _count, exact = cv.cli_redact("obviously-fake-value", None)
    assert exact is False


@pytest.mark.parametrize("completion", [None, False, "true", 1])
def test_guarded_redact_requires_explicit_complete_loading(monkeypatch, completion):
    fake_value = "obviously-fake-shape-blind-fixture"
    payload = {"text": fake_value, "redactions": 0,
               "exact_values_loaded": 0, "vault": True}
    if completion is not None:
        payload["exact_values_complete"] = completion
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "_run_cli_json", lambda *a, **k: {"success": True, "data": payload})
    decisions = []
    monkeypatch.setattr(cv, "_audit", lambda tool, decision, **k: decisions.append(decision) or True)

    assert cv.cli_redact(fake_value, None)[2] is False
    redacted = json.loads(cv._tool_redact({"text": fake_value}))
    assert redacted["success"] is False
    assert fake_value not in json.dumps(redacted)
    transformed = cv.on_transform_tool_result("terminal", {}, fake_value)
    assert transformed and "withheld" in transformed
    assert fake_value not in transformed
    assert "scrubbed_result" not in decisions


def test_guarded_redact_rejects_complete_but_vaultless_response(monkeypatch):
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    payload = {"text": "fake output", "redactions": 0,
               "exact_values_loaded": 0, "exact_values_complete": True, "vault": False}
    monkeypatch.setattr(cv, "_run_cli_json", lambda *a, **k: {"success": True, "data": payload})
    assert cv.cli_redact("fake output", None)[2] is False


def test_redact_accepts_explicit_complete_empty_vault(monkeypatch):
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    payload = {"text": "fake output", "redactions": 0,
               "exact_values_loaded": 0, "exact_values_complete": True, "vault": True}
    monkeypatch.setattr(cv, "_run_cli_json", lambda *a, **k: {"success": True, "data": payload})
    assert cv.cli_redact("fake output", None) == ("fake output", 0, True)


@pytest.mark.parametrize("verification", [
    {"success": False, "error": "fake verification command failed", "exit_code": 1},
    {"success": True, "data": {"ok": False, "entries": 0, "first_bad_id": 1}},
    {"success": True, "data": {}},
    {"success": True, "data": []},
])
def test_audit_never_claims_success_without_verified_chain(ctx, monkeypatch, verification):
    calls = []

    def run_json(args, cwd):
        calls.append(args[1])
        if args[1] == "show":
            return {"success": True, "data": [{"id": 1, "decision": "scrubbed_result"}]}
        if args[1] == "verify":
            return verification
        return {"success": True, "data": {"found": True}}

    monkeypatch.setattr(cv, "_run_cli_json", run_json)
    out = json.loads(ctx.tools["ciphervault_audit"][1]({"check_text": "fake output"}))
    assert out["success"] is False
    assert out["error"]
    assert "verification" in out
    assert "check" not in calls  # never present a hash hit from an unverified chain as proof


@pytest.mark.parametrize("check", [
    {"success": False, "error": "fake lookup failed", "exit_code": 1},
    {"success": True, "data": {}},
    {"success": True, "data": []},
])
def test_audit_lookup_failure_is_not_success(ctx, monkeypatch, check):
    def run_json(args, cwd):
        if args[1] == "show":
            return {"success": True, "data": []}
        if args[1] == "verify":
            return {"success": True, "data": {"ok": True}}
        return check

    monkeypatch.setattr(cv, "_run_cli_json", run_json)
    out = json.loads(ctx.tools["ciphervault_audit"][1]({"check_text": "fake output"}))
    assert out["success"] is False
    assert out["error"]


def test_secret_source_fetch_missing_binary(ctx, monkeypatch):
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    result = ctx.secret_source.fetch({"enabled": True}, Path("."))
    assert result.error and not result.secrets


# ------------------------------------------------------------ fake CLI

FAKE_CLI = r"""
import json, os, sys
args = sys.argv[1:]
if args[:1] == ["--version"]:
    if os.environ.get("CIPHERVAULT_TEST_INCOMPLETE"):
        print("ciphervault 1.0.32"); raise SystemExit(0)
    print("ciphervault 1.0.28" if os.environ.get("CIPHERVAULT_TEST_LEGACY") else "ciphervault 1.0.31")
    raise SystemExit(0)
if args[-1:] == ["--help"]:
    command = " ".join(args[:-1])
    help_flags = {
        "status": "--json", "hook check": "--json --deep --fix",
        "run": "--json --dry-run --env-file --project --env",
        "push": "--local", "recover": "--to --kit --shares",
        "redact": "--json", "export-env": "--env-file --allow-working-copy",
        "agent-log record": "--tool --decision --path --detail",
        "agent-log show": "--json --limit", "agent-log verify": "--json",
        "agent-log check": "--json --output-sha256", "agent-log anchor": "--json",
    }
    if os.environ.get("CIPHERVAULT_TEST_LEGACY"):
        help_flags.pop("redact", None)
        help_flags = {k: v for k, v in help_flags.items() if not k.startswith("agent-log")}
        help_flags["run"] = "--dry-run --env-file --project --env"
    if command in help_flags:
        print("Usage: ciphervault " + command + " [OPTIONS]\nOptions: " + help_flags[command])
        raise SystemExit(0)
    print("error: unrecognized subcommand", file=sys.stderr); raise SystemExit(2)
if args[:2] == ["status", "--json"]:
    print(json.dumps({"vault": True, "cli_version": "1.0.31", "tracked_paths": [".env"],
                      "vault_id_short": "abcd1234", "active_head_short": "beef5678",
                      "tracked_files": 1, "operators": []})); raise SystemExit(0)
if args[:2] == ["redact", "--json"]:
    text = sys.stdin.buffer.read().decode("utf-8")
    payload = {"text": text.replace("test_value_123456", "[REDACTED:API_KEY]"),
               "redactions": text.count("test_value_123456"),
               "exact_values_loaded": 1, "exact_values_complete": True, "vault": True}
    if os.environ.get("CIPHERVAULT_TEST_INCOMPLETE"):
        payload.pop("exact_values_complete")
    print(json.dumps(payload)); raise SystemExit(0)
if args[:2] == ["run", "--json"]:
    print(json.dumps({"status": "success", "exit_code": 0, "stdout": "KEY=[REDACTED:API_KEY]",
                      "stderr": "", "redactions": 1, "secrets_injected_count": 1})); raise SystemExit(0)
if args[:2] == ["agent-log", "show"]:
    print(json.dumps([{"id": 1, "tool": "terminal", "decision": "blocked", "path": ".env",
                       "entry_hash": "ab12", "prev_hash": "GENESIS"}])); raise SystemExit(0)
if args[:2] == ["agent-log", "verify"]:
    print(json.dumps({"ok": True, "entries": 1, "head_hash": "ab12", "first_bad_id": None})); raise SystemExit(0)
if args[:2] == ["agent-log", "check"]:
    print(json.dumps({"found": True, "entry_id": 1, "tool": "terminal", "decision": "scrubbed_result"})); raise SystemExit(0)
if args[:1] == ["failure-with-json"]:
    print(json.dumps({"status": "failed", "exit_code": 7, "stdout": "fake progress"}))
    print("child exited 7", file=sys.stderr); raise SystemExit(7)
print("unexpected args", args, file=sys.stderr); raise SystemExit(2)
"""


@pytest.fixture()
def fake_cli(tmp_path, monkeypatch):
    exe = tmp_path / ("ciphervault.exe" if os.name == "nt" else "ciphervault")
    # A .py script with a .exe name won't run on Windows; use a .bat shim there.
    if os.name == "nt":
        script = tmp_path / "fake_cli.py"
        script.write_text(FAKE_CLI)
        exe = tmp_path / "ciphervault.bat"
        exe.write_text(f'@echo off\n"{sys.executable}" "{script}" %*\n')
    else:
        # Run a script file: a `python3 - <<EOF` launcher would consume
        # stdin for the program text, hiding the redaction payload.
        script = tmp_path / "fake_cli.py"
        script.write_text(FAKE_CLI)
        exe.write_text(f"#!/bin/sh\nexec \"{sys.executable}\" \"{script}\" \"$@\"\n")
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(cv, "find_binary", lambda: (str(exe), "test"))
    return exe


def test_status_against_fake_cli(ctx, fake_cli):
    out = json.loads(ctx.tools["ciphervault_status"][1]({}))
    assert out["success"] is True
    assert out["data"]["tracked_paths"] == [".env"]


def test_redact_tool_against_fake_cli(ctx, fake_cli):
    out = json.loads(ctx.tools["ciphervault_redact"][1]({"text": "x test_value_123456 y"}))
    assert out["redactions"] == 1 and "test_value_123456" not in out["text"]


@pytest.mark.parametrize("text", [
    "plain" + chr(10) + "text" + chr(10),
    "plain" + chr(13) + chr(10) + "text" + chr(13) + chr(10),
    "mixed" + chr(10) + "text" + chr(13) + chr(10) + "end",
    "unicode snowman " + chr(0x2603) + chr(10) + "next line" + chr(13) + chr(10),
])
def test_redact_preserves_input_bytes_and_line_endings(fake_cli, text):
    cleaned, count, exact = cv.cli_redact(text, None)
    assert cleaned.encode("utf-8") == text.encode("utf-8")
    assert count == 0 and exact is True


@pytest.mark.parametrize("text", [
    "plain" + chr(10) + "text" + chr(10),
    "plain" + chr(13) + chr(10) + "text" + chr(13) + chr(10),
    "mixed" + chr(10) + "text" + chr(13) + chr(10) + "end",
    "unicode snowman " + chr(0x2603) + chr(10) + "next line" + chr(13) + chr(10),
])
def test_real_cli_preserves_input_bytes_and_line_endings(monkeypatch, tmp_path, text):
    binary = os.environ.get("CV_TEST_BINARY")
    if not binary:
        pytest.skip("set CV_TEST_BINARY for real CLI byte-preservation checks")
    assert Path(binary).is_file()
    monkeypatch.setattr(cv, "find_binary", lambda: (binary, "integration test"))
    cleaned, count, exact = cv.cli_redact(text, str(tmp_path))
    assert exact is True, "real CLI must provide compatible exact redaction"
    assert cleaned.encode("utf-8") == text.encode("utf-8")
    assert count == 0


def test_guard_clean_multistring_args_are_not_false_secret(fake_cli, tmp_path):
    args = {"command": "pwd", "workdir": str(tmp_path)}
    assert cv.on_pre_tool_call("terminal", args) is None


def test_run_against_fake_cli(ctx, fake_cli):
    out = json.loads(ctx.tools["ciphervault_run"][1]({"command": ["echo", "hi"]}))
    assert out["success"] is True and out["data"]["redactions"] == 1


def test_audit_tool_against_fake_cli(ctx, fake_cli):
    out = json.loads(ctx.tools["ciphervault_audit"][1]({}))
    assert out["success"] is True
    assert out["verification"]["ok"] is True
    assert out["entries"][0]["decision"] == "blocked"


def test_audit_tool_check_text_against_fake_cli(ctx, fake_cli):
    out = json.loads(ctx.tools["ciphervault_audit"][1]({"check_text": "anything"}))
    assert out["success"] is True
    assert out["check"]["found"] is True


def test_cli_nonzero_exit_is_failure_even_with_json_stdout(fake_cli, tmp_path):
    out = cv._run_cli_json(["failure-with-json"], str(tmp_path))
    assert out["success"] is False
    assert out["exit_code"] == 7
    assert "child exited 7" in out["error"]


def test_doctor_rejects_legacy_cli_despite_working_status(fake_cli, tmp_path, monkeypatch, capsys):
    import argparse

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CIPHERVAULT_TEST_LEGACY", "1")
    rc = cv._cli_handler(argparse.Namespace(ciphervault_cmd="doctor"))
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert out["installed_version"] == "1.0.28"
    assert out["target_cli_version"] == cv.RELEASE_VERSION
    assert out["binary"] == str(fake_cli)
    assert out["binary_source"] == "test"
    assert "redact" in out["missing_capabilities"]
    assert "run" in out["missing_capabilities"]
    assert "agent-log verify" in out["missing_capabilities"]
    assert "source" in out["next"] and "CIPHERVAULT_BIN" in out["next"]
    assert "bootstrap" not in out["next"]


def test_doctor_rejects_old_official_cli_with_all_flags(fake_cli, tmp_path, monkeypatch, capsys):
    import argparse

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CIPHERVAULT_TEST_INCOMPLETE", "1")
    rc = cv._cli_handler(argparse.Namespace(ciphervault_cmd="doctor"))
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert out["installed_version"] == "1.0.32"
    # The real v1.0.32 has every flag but no completeness attestation;
    # it is older than the pin, and rejected for completeness, not version.
    assert out["version_matches_target"] is False
    assert all(out["capabilities"][" ".join(command)]["supported"]
               for command, _flags in cv._CLI_CAPABILITIES)
    assert "redact completeness" in out["missing_capabilities"]
    assert "source" in out["next"] and "bootstrap" not in out["next"]


def test_doctor_accepts_capable_cli_but_reports_version_drift(fake_cli, tmp_path, monkeypatch, capsys):
    import argparse

    monkeypatch.chdir(tmp_path)
    rc = cv._cli_handler(argparse.Namespace(ciphervault_cmd="doctor"))
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is True
    assert out["installed_version"] == "1.0.31"
    assert out["version_matches_target"] is False
    assert out["missing_capabilities"] == []
    assert "warning" in out


# ------------------------------------------------------------ phase 1 hardening

def test_scrub_full_text_past_256k_and_across_chunk_boundary(ctx, tmp_path, monkeypatch):
    canary = "super_exact_canary_999"
    monkeypatch.setattr(
        cv,
        "cli_redact",
        lambda text, cwd, timeout=10: (
            text.replace(canary, "[REDACTED:EXACT]"),
            text.count(canary),
            True,
        ),
    )
    # Case 1: clean prefix > 256 KiB, canary at byte ~280,000
    payload_tail = ("a" * 280_000) + canary + ("b" * 100)
    out_tail, _, ok_tail, _ = cv._scrub_full_text(payload_tail, str(tmp_path))
    assert ok_tail is True
    assert out_tail is not None
    assert canary not in out_tail
    assert "[REDACTED:EXACT]" in out_tail

    # Case 2: canary straddles the 262,144-byte chunk boundary
    half = len(canary) // 2
    payload_seam = ("x" * (cv._REDACT_CHUNK_CHARS - half)) + canary + ("y" * 50)
    out_seam, _, ok_seam, _ = cv._scrub_full_text(payload_seam, str(tmp_path))
    assert ok_seam is True
    assert out_seam is not None
    assert canary not in out_seam
    assert "[REDACTED:EXACT]" in out_seam


@pytest.mark.parametrize("cmd", [
    "python -c \"print(open('.env').read())\"",
    "node -e \"console.log(require('fs').readFileSync('.env','utf8'))\"",
    "base64 .env",
    "sed -n '1,20p' .env",
    "jq . secrets.json",
    "ciphervault export-env",
    "ciphervault track .env && cat .env",
])
def test_guard_blocks_shell_secret_bypasses(ctx, monkeypatch, cmd):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    out = cv.on_pre_tool_call("terminal", {"command": cmd})
    assert out and out["action"] == "block"


@pytest.mark.parametrize("cmd", [
    "ciphervault track .env",
    "cv status",
    "git check-ignore .env",
])
def test_guard_allows_safe_vault_and_git_commands(ctx, monkeypatch, cmd):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    assert cv.on_pre_tool_call("terminal", {"command": cmd}) is None


def test_hooks_fail_closed_inside_vault_when_cli_unavailable(ctx, tmp_path, monkeypatch):
    (tmp_path / ".ciphervault").mkdir()
    (tmp_path / ".ciphervault" / "vault.db").touch()
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))

    pre = cv.on_pre_tool_call("terminal", {"command": "echo hi", "cwd": str(tmp_path)})
    assert pre and pre["action"] == "block"

    res = cv.on_transform_tool_result("terminal", {"cwd": str(tmp_path)}, "raw stdout")
    assert res is not None and "withheld" in res


def test_hooks_fail_open_outside_vault_when_cli_missing(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    monkeypatch.delenv("CIPHERVAULT_VAULT_DB", raising=False)

    assert cv.on_pre_tool_call("terminal", {"command": "echo hi", "cwd": str(tmp_path)}) is None
    assert cv.on_transform_tool_result("terminal", {"cwd": str(tmp_path)}, "clean stdout") is None


# ------------------------------------------------------------ phase 2

def test_stdio_bridge_reuses_single_process(ctx, tmp_path, monkeypatch):
    cv._close_all_bridges()
    cv._NO_STDIO_BINARIES.clear()
    spawn_count_file = tmp_path / "spawns.txt"
    bridge_script = tmp_path / "bridge_cli.py"
    bridge_script.write_text(
        "import json, sys\n"
        f"open({str(spawn_count_file)!r}, 'a').write('1\\n')\n"
        "if sys.argv[1:3] == ['redact', '--stdio']:\n"
        "    for line in sys.stdin:\n"
        "        req = json.loads(line)\n"
        "        if req.get('op') == 'redact':\n"
        "            txt = req.get('text', '')\n"
        "            out = txt.replace('bridge_canary_88', '[REDACTED:CANARY]')\n"
        "            print(json.dumps({'ok': True, 'text': out, 'redactions': txt.count('bridge_canary_88'), 'exact_values_loaded': 1, 'exact_values_complete': True, 'vault': True}), flush=True)\n"
        "        elif req.get('op') == 'audit':\n"
        "            print(json.dumps({'ok': True}), flush=True)\n"
        "    raise SystemExit(0)\n"
    )
    if os.name == "nt":
        exe = tmp_path / "ciphervault_stdio.bat"
        exe.write_text(f'@echo off\n"{sys.executable}" "{bridge_script}" %*\n')
    else:
        exe = tmp_path / "ciphervault_stdio"
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{bridge_script}" "$@"\n')
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)

    monkeypatch.setattr(cv, "find_binary", lambda: (str(exe), "test-stdio"))
    try:
        for i in range(3):
            out, n, ok = cv._call_cli_redact(f"call {i} bridge_canary_88", str(tmp_path))
            assert ok is True and n == 1 and "bridge_canary_88" not in out
        assert len(spawn_count_file.read_text().splitlines()) == 1
    finally:
        cv._close_all_bridges()


def test_stdio_bridge_falls_back_on_legacy_cli(ctx, fake_cli, tmp_path):
    cv._close_all_bridges()
    cv._NO_STDIO_BINARIES.clear()
    try:
        out, n, ok = cv._call_cli_redact("x test_value_123456 y", str(tmp_path))
        assert ok is True and n == 1 and "test_value_123456" not in out
        assert str(fake_cli) in cv._NO_STDIO_BINARIES
    finally:
        cv._close_all_bridges()
        cv._NO_STDIO_BINARIES.clear()


def test_run_allow_keys_forwarded_and_validated(ctx, monkeypatch):
    seen = {}

    def fake_run_json(args, cwd, timeout=300):
        seen["args"] = args
        return {"success": True, "data": {"status": "success"}}

    monkeypatch.setattr(cv, "_run_cli_json", fake_run_json)
    out = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest"],
        "allow_keys": ["PORT", "DB_HOST"],
    }))
    assert out["success"] is True
    assert "--allow-keys" in seen["args"]
    idx = seen["args"].index("--allow-keys")
    assert seen["args"][idx + 1] == "PORT,DB_HOST"

    bad = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest"],
        "allow_keys": ["  "],
    }))
    assert bad["success"] is False

    appr = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["pytest"],
        "allow_keys": ["PORT"],
    })
    assert appr and appr["action"] == "approve" and "PORT" in appr["message"]


def test_run_no_net_defaults_and_forwarding(ctx, monkeypatch):
    seen = {}

    def fake_run_json(args, cwd, timeout=300):
        seen["args"] = args
        return {"success": True, "data": {"status": "success"}}

    monkeypatch.setattr(cv, "_run_cli_json", fake_run_json)

    # Explicit True forwards --no-net on any OS and surfaces in approval prompt
    out = json.loads(ctx.tools["ciphervault_run"][1]({"command": ["pytest"], "no_net": True}))
    assert out["success"] is True and "--no-net" in seen["args"]
    appr_iso = cv.on_pre_tool_call("ciphervault_run", {"command": ["pytest"], "no_net": True})
    assert appr_iso and "isolated (--no-net)" in appr_iso["message"]

    # Explicit False omits --no-net and warns UNRESTRICTED in approval prompt
    seen.clear()
    out2 = json.loads(ctx.tools["ciphervault_run"][1]({"command": ["pytest"], "no_net": False}))
    assert out2["success"] is True and "--no-net" not in seen["args"]
    appr_open = cv.on_pre_tool_call("ciphervault_run", {"command": ["pytest"], "no_net": False})
    assert appr_open and "UNRESTRICTED" in appr_open["message"]

    # Platform defaults: Linux, macOS, and Windows all default True
    monkeypatch.setattr(cv.sys, "platform", "linux")
    assert cv._effective_no_net({}) is True
    monkeypatch.setattr(cv.sys, "platform", "darwin")
    assert cv._effective_no_net({}) is True
    monkeypatch.setattr(cv.sys, "platform", "win32")
    assert cv._effective_no_net({}) is True


def test_run_proxy_forwarding_and_no_net_interaction(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[profiles.api]\n'
        'proxy = true\n'
        'upstreams = { MY_VAR = "https://api.example.com" }\n',
        encoding="utf-8",
    )
    seen = {}

    def fake_run_json(args, cwd, timeout=300):
        seen["args"] = args
        return {"success": True, "data": {"status": "success"}}

    monkeypatch.setattr(cv, "_run_cli_json", fake_run_json)
    monkeypatch.setattr(cv.sys, "platform", "linux")

    # Policy-configured proxy upstream is forwarded and disables --no-net.
    out = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest"],
        "profile": "api",
        "cwd": str(vault),
    }))
    assert out["success"] is True
    assert "--proxy" in seen["args"]
    assert "--proxy-upstream" in seen["args"]
    assert "MY_VAR=https://api.example.com" in seen["args"]
    # proxy implies loopback access on Linux/macOS unless no_net explicitly passed
    assert "--no-net" not in seen["args"]

    # Agent-supplied proxy_upstream is rejected (policy.toml-only, matching ciphervault mcp).
    rejected = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest"],
        "proxy": True,
        "proxy_upstream": ["MY_VAR=https://api.example.com"],
        "cwd": str(vault),
    }))
    assert rejected["success"] is False
    assert "policy.toml" in rejected["error"]

    appr = cv.on_pre_tool_call("ciphervault_run", {"command": ["pytest"], "proxy": True})
    assert appr and "proxy: real keys stay in parent" in appr["message"]


def test_push_shred_working_copy_and_blocked_cli_dumps(ctx, monkeypatch):
    seen = {}

    def fake_run(args, cwd, timeout=300):
        seen["args"] = args
        return {"success": True, "output": "ok"}

    monkeypatch.setattr(cv, "_run_cli", fake_run)
    out = json.loads(ctx.tools["ciphervault_push"][1]({
        "message": "seal test",
        "shred_working_copy": True,
    }))
    assert out["success"] is True
    assert "--local" in seen["args"]
    assert "--shred" in seen["args"]

    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    for cmd in [
        "cv diff --reveal",
        "ciphervault diff -r",
        "ciphervault restore",
        "cv pull --force",
        "ciphervault recover --kit kit.txt",
        "ciphervault secret get DB_PASS",
    ]:
        blk = cv.on_pre_tool_call("terminal", {"command": cmd})
        assert blk and blk["action"] == "block", f"expected {cmd} to be blocked"

    blk_db = cv.on_pre_tool_call("read_file", {"path": ".ciphervault/vault.db"})
    assert blk_db and blk_db["action"] == "block"
    assert cv.on_pre_tool_call("terminal", {"command": "ciphervault diff"}) is None


# ------------------------------------------------------------ security audit fixes & P1 tools


@pytest.mark.parametrize("blank_upstreams", [[""], ["   ", "\t"], [""]])
def test_blank_proxy_upstream_never_disables_no_net_or_spoofs_proxy_banner(
        ctx, monkeypatch, blank_upstreams):
    seen = {}

    def fake_run_json(args, cwd, timeout=300):
        seen["args"] = args
        return {"success": True, "data": {"status": "success"}}

    monkeypatch.setattr(cv, "_run_cli_json", fake_run_json)
    monkeypatch.setattr(cv.sys, "platform", "linux")

    assert cv._clean_proxy_upstreams({"proxy_upstream": blank_upstreams}) == []
    assert cv._effective_no_net({"proxy": False, "proxy_upstream": blank_upstreams}) is True

    appr = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["python", "app.py"],
        "proxy": False,
        "proxy_upstream": blank_upstreams,
    })
    assert appr and appr["action"] == "approve"
    assert "proxy: real keys stay in parent" not in appr["message"]
    assert "isolated (--no-net)" in appr["message"]

    out = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["python", "app.py"],
        "proxy": False,
        "proxy_upstream": blank_upstreams,
    }))
    assert out["success"] is True
    assert "--no-net" in seen["args"]
    assert "--proxy-upstream" not in seen["args"]


@pytest.mark.parametrize("bad_spec", [
    "MY_VAR=http://127.0.0.1:19999",
    "MY_VAR=https://127.0.0.1:19999",
    "MY_VAR=http://localhost:8080",
    "MY_VAR=https://169.254.169.254/latest/meta-data",
    "MY_VAR=https://10.0.0.5",
    "MY_VAR=https://192.168.1.50",
    "MY_VAR=https://[::1]:8443",
    "MY_VAR=http://api.example.com",
    "OPENAI_API_KEY=https://attacker.example.com",
    "ANTHROPIC_API_KEY=https://attacker.example.com",
    "STRIPE_SECRET_KEY=https://attacker.example.com",
    "GITHUB_TOKEN=https://attacker.example.com",
    "GEMINI_API_KEY=https://attacker.example.com",
    "HF_TOKEN=https://attacker.example.com",
])
def test_proxy_upstream_blocks_ssrf_and_known_provider_override(ctx, tmp_path, monkeypatch, bad_spec):
    calls = _capture_audit(monkeypatch)
    monkeypatch.setattr(cv, "_run_cli_json", lambda *a, **k: pytest.fail("CLI must not run for blocked upstream"))

    blk = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["python", "app.py"],
        "proxy": True,
        "proxy_upstream": [bad_spec],
        "cwd": str(tmp_path),
    })
    assert blk and blk["action"] == "block"
    assert any(c[:2] == ["agent-log", "record"] and "blocked" in c for c in calls)

    res = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["python", "app.py"],
        "proxy": True,
        "proxy_upstream": [bad_spec],
        "cwd": str(tmp_path),
    }))
    assert res["success"] is False


def test_rule_key_scoping_prevents_session_grant_escalation(ctx, monkeypatch):
    _capture_audit(monkeypatch)
    monkeypatch.setattr(cv.sys, "platform", "linux")

    r_pytest = cv.on_pre_tool_call("ciphervault_run", {"command": ["python", "-m", "pytest"]})
    r_inline1 = cv.on_pre_tool_call("ciphervault_run", {"command": ["python", "-c", "print(1)"]})
    r_inline2 = cv.on_pre_tool_call("ciphervault_run", {"command": ["python", "-c", "import os; print(os.environ)"]})
    assert r_pytest["rule_key"] == "ciphervault_run:python"
    assert r_inline1["rule_key"].startswith("ciphervault_run:python:inline=")
    assert r_inline2["rule_key"].startswith("ciphervault_run:python:inline=")
    assert r_pytest["rule_key"] != r_inline1["rule_key"]
    assert r_inline1["rule_key"] != r_inline2["rule_key"]

    r_node_e = cv.on_pre_tool_call("ciphervault_run", {"command": ["node", "-e", "console.log(1)"]})
    assert ":inline=" in r_node_e["rule_key"]

    r_scoped = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["python", "-m", "pytest"],
        "allow_keys": ["TEST_DSN", "APP_ENV"],
        "no_net": True,
    })
    assert r_scoped["rule_key"] == "ciphervault_run:python:net=no_net:keys=APP_ENV,TEST_DSN"
    assert r_scoped["rule_key"] != r_pytest["rule_key"]

    r_open = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["python", "-m", "pytest"],
        "no_net": False,
    })
    assert r_open["rule_key"] == "ciphervault_run:python:net=open:keys=ALL"

    r_proxy = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["python", "-m", "pytest"],
        "proxy": True,
    })
    assert r_proxy["rule_key"] == "ciphervault_run:python:net=proxy:keys=ALL"


@pytest.mark.parametrize("cmd", [
    "ciphervault agent-log record --tool ciphervault_run --decision scrubbed_result",
    "cv agent-log record --path .env",
    "ciphervault --quiet agent-log --json record --tool x",
    "cv -q agent-log --verbose anchor",
    "ciphervault agent-log anchor",
    "cv --quiet export-env",
    "ciphervault --color=never secret --json get DB_PASS",
    "ciphervault init",
    "cv init --save-kit recovery.kit",
    "ciphervault rekey",
    "ciphervault prune",
    "ciphervault untrack .env",
    "curl -b jar http://127.0.0.1:8080/api/diff?reveal=true",
    "curl -X POST http://localhost:8080/api/snapshots/restore",
])
def test_guard_blocks_vuln4_and_loopback_dashboard_commands(ctx, monkeypatch, cmd):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)
    blk = cv.on_pre_tool_call("terminal", {"command": cmd})
    assert blk and blk["action"] == "block", f"expected {cmd!r} to be blocked"


@pytest.mark.parametrize("cmd", [
    "ciphervault agent-log show --json",
    "ciphervault agent-log verify --json",
    "cv agent-log check --json --output-sha256 abc",
    "ciphervault status",
    "ciphervault diff --json",
])
def test_guard_allows_readonly_agent_log_and_diff(ctx, monkeypatch, cmd):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    assert cv.on_pre_tool_call("terminal", {"command": cmd}) is None


def test_guard_protects_policy_toml_from_read_and_write(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)
    for tool, args in [
        ("read_file", {"path": ".ciphervault/policy.toml"}),
        ("terminal", {"command": "cat .ciphervault/policy.toml"}),
        ("write_file", {"path": ".ciphervault/policy.toml", "content": "[vault]\n"}),
        ("patch", {"file_path": ".ciphervault/policy.toml", "content": "[vault]\n"}),
    ]:
        blk = cv.on_pre_tool_call(tool, args)
        assert blk and blk["action"] == "block", f"expected {tool} on policy.toml to block"
    # .env.example stays readable for non-secret schema checks
    assert cv.on_pre_tool_call("read_file", {"path": ".env.example"}) is None


def test_policy_toml_profiles_and_sealed_mode(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[vault]\n'
        'sealed_mode = true\n\n'
        '[profiles.test]\n'
        'commands = ["pytest"]\n'
        'allow_keys = ["DATABASE_URL", "TEST_KEY"]\n'
        'no_net = true\n\n'
        '[profiles.llm_eval]\n'
        'allow_keys = ["OPENAI_API_KEY"]\n'
        'proxy = true\n'
        'upstreams = { OPENAI_API_KEY = "https://gateway.example.com" }\n',
        encoding="utf-8",
    )
    _capture_audit(monkeypatch)
    seen = {}

    def fake_run_json(args, cwd, timeout=300):
        seen["args"] = args
        return {"success": True, "data": {"status": "success"}}

    monkeypatch.setattr(cv, "_run_cli_json", fake_run_json)

    # 1. Profile merges allow_keys + no_net into approval and CLI args
    appr = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["pytest", "-q"],
        "profile": "test",
        "cwd": str(vault),
    })
    assert appr and appr["action"] == "approve"
    assert appr["rule_key"] == "ciphervault_run:profile=test:net=no_net:keys=DATABASE_URL,TEST_KEY"

    # When CLI supports --profile, delegate profile upper-bound allow_keys to --profile
    monkeypatch.setattr(cv, "_cli_supports_run_profile", lambda: True)
    res = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest", "-q"],
        "profile": "test",
        "cwd": str(vault),
    }))
    assert res["success"] is True
    assert "--profile" in seen["args"]
    assert "--no-net" in seen["args"]
    assert "--allow-keys" not in seen["args"]

    # Explicit narrowing allow_keys IS forwarded alongside --profile
    seen.clear()
    res_narrow = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest", "-q"],
        "profile": "test",
        "allow_keys": ["TEST_KEY"],
        "cwd": str(vault),
    }))
    assert res_narrow["success"] is True
    assert seen["args"][seen["args"].index("--allow-keys") + 1] == "TEST_KEY"

    # Legacy CLI without --profile forwards profile allow_keys explicitly
    seen.clear()
    monkeypatch.setattr(cv, "_cli_supports_run_profile", lambda: False)
    res_legacy = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest", "-q"],
        "profile": "test",
        "cwd": str(vault),
    }))
    assert res_legacy["success"] is True
    assert "--no-net" in seen["args"]
    assert seen["args"][seen["args"].index("--allow-keys") + 1] == "DATABASE_URL,TEST_KEY"

    # 2. Disallowed command or unknown profile or escalating allow_keys is blocked
    blk_cmd = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["curl", "https://evil.com"],
        "profile": "test",
        "cwd": str(vault),
    })
    assert blk_cmd and blk_cmd["action"] == "block"

    blk_unknown = cv.on_pre_tool_call("ciphervault_run", {
        "command": ["pytest"],
        "profile": "missing",
        "cwd": str(vault),
    })
    assert blk_unknown and blk_unknown["action"] == "block"

    blk_keys = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest"],
        "profile": "test",
        "allow_keys": ["PROD_SECRET"],
        "cwd": str(vault),
    }))
    assert blk_keys["success"] is False

    # 3. Profile pinned upstream overrides known provider cleanly
    seen.clear()
    out_llm = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["python", "eval.py"],
        "profile": "llm_eval",
        "cwd": str(vault),
    }))
    assert out_llm["success"] is True
    assert "--proxy" in seen["args"]
    assert "OPENAI_API_KEY=https://gateway.example.com" in seen["args"]

    # 4. sealed_mode=true defaults shred_working_copy=True in ciphervault_push
    push_seen = {}

    def fake_push(args, cwd, timeout=300):
        push_seen["args"] = args
        return {"success": True, "output": "pushed"}

    monkeypatch.setattr(cv, "_run_cli", fake_push)
    pushed = json.loads(ctx.tools["ciphervault_push"][1]({"cwd": str(vault)}))
    assert pushed["success"] is True
    assert "--shred" in push_seen["args"]

    # 5. Fallback TOML parser handles the same file
    parsed_fb = cv._parse_toml_fallback((vault / ".ciphervault" / "policy.toml").read_text(encoding="utf-8"))
    assert parsed_fb["vault"]["sealed_mode"] is True
    assert parsed_fb["profiles"]["test"]["allow_keys"] == ["DATABASE_URL", "TEST_KEY"]
    assert parsed_fb["profiles"]["llm_eval"]["upstreams"]["OPENAI_API_KEY"] == "https://gateway.example.com"


def test_env_doctor_detects_drift_anomalies_and_sealed_fallback(ctx, tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        'import os\n'
        'db = os.environ["DATABASE_URL"]\n'
        'tok = os.getenv("MISSING_TOKEN")\n'
        'key = os.environ.get("OPENAI_API_KEY")\n',
        encoding="utf-8",
    )
    (tmp_path / "web.ts").write_text(
        'const a = process.env.NEXT_PUBLIC_URL;\n'
        'const b = import.meta.env.VITE_API;\n',
        encoding="utf-8",
    )
    (tmp_path / "main.rs").write_text('let _ = std::env::var("RUST_SECRET");\n', encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("environment:\n  - COMPOSE_VAR=${COMPOSE_VAR}\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("DATABASE_URL=\nEXAMPLE_ONLY=\n", encoding="utf-8")
    secret_sentinel = "super-secret-value-never-in-output"
    (tmp_path / ".env").write_text(
        "DATABASE_URL=not a valid url\n"
        "OPENAI_API_KEY=wrong_prefix_secret\n"
        "EMPTY_ONE=\n"
        "SPACE_ONE= padded \n"
        "QUOTED_ONE=\"'nested'\"\n"
        "PLACEHOLDER_ONE=changeme\n"
        "BAD_JSON={not-json\n"
        f"UNUSED_KEY={secret_sentinel}\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(cv, "_run_cli_json", lambda args, cwd, timeout=20: {"success": False, "error": "no vault"})
    raw = ctx.tools["ciphervault_env_doctor"][1]({"cwd": str(tmp_path), "sync_env_example": True})
    assert secret_sentinel not in raw
    assert "wrong_prefix_secret" not in raw
    assert "not a valid url" not in raw

    out = json.loads(raw)
    assert out["success"] is True
    assert set(out["referenced_in_code"]) >= {
        "DATABASE_URL", "MISSING_TOKEN", "OPENAI_API_KEY",
        "NEXT_PUBLIC_URL", "VITE_API", "RUST_SECRET", "COMPOSE_VAR",
    }
    assert set(out["missing_in_vault"]) >= {
        "MISSING_TOKEN", "NEXT_PUBLIC_URL", "VITE_API", "RUST_SECRET", "COMPOSE_VAR", "EXAMPLE_ONLY",
    }
    assert "UNUSED_KEY" in out["unreferenced_in_code"]

    anomalies = {(a["key"], a["issue"]) for a in out["value_anomalies"]}
    assert ("DATABASE_URL", "INVALID_URL") in anomalies
    assert ("OPENAI_API_KEY", "PREFIX_MISMATCH") in anomalies
    assert ("EMPTY_ONE", "EMPTY_VALUE") in anomalies
    assert ("SPACE_ONE", "WHITESPACE_WRAPPED") in anomalies
    assert ("QUOTED_ONE", "UNSTRIPPED_QUOTES") in anomalies
    assert ("PLACEHOLDER_ONE", "PLACEHOLDER_VALUE") in anomalies
    assert ("BAD_JSON", "INVALID_JSON") in anomalies

    example_text = (tmp_path / ".env.example").read_text(encoding="utf-8")
    assert "MISSING_TOKEN= # [required]" in example_text
    assert secret_sentinel not in example_text

    # Sealed mode fallback: no .env on disk, uses `run --dry-run --json -- echo ok`
    (tmp_path / ".env").unlink()

    def sealed_cli_json(args, cwd, timeout=30):
        if args[:2] == ["status", "--json"]:
            return {"success": True, "data": {
                "vault": True, "tracked_paths": [".env"], "working_tree_sealed": True,
            }}
        if args[:3] == ["run", "--dry-run", "--json"]:
            return {"success": True, "data": {
                "status": "dry_run",
                "secrets": [{"name": "DATABASE_URL"}, {"name": "OPENAI_API_KEY"}],
            }}
        return {"success": False}

    monkeypatch.setattr(cv, "_run_cli_json", sealed_cli_json)
    sealed_out = json.loads(ctx.tools["ciphervault_env_doctor"][1]({"cwd": str(tmp_path)}))
    assert sealed_out["success"] is True
    assert sealed_out["sealed"] is True
    assert sealed_out["vault_keys"] == ["DATABASE_URL", "OPENAI_API_KEY"]
    assert "DATABASE_URL" not in sealed_out["missing_in_vault"]


@pytest.mark.parametrize("fmt", ["base64url", "hex", "uuid", "alphanumeric"])
def test_secret_generate_writes_env_and_never_exposes_secret(ctx, tmp_path, monkeypatch, fmt):
    _marker_vault(tmp_path)
    cli_calls = []

    def fake_run(args, cwd, timeout=120, input_text=None):
        cli_calls.append(list(args))
        if args[:2] == ["status", "--json"]:
            return {
                "success": True,
                "output": json.dumps({"vault": True, "working_tree_sealed": False, "tracked_paths": []}),
                "binary": "test",
            }
        return {"success": True, "output": "ok", "binary": "test"}

    monkeypatch.setattr(cv, "_run_cli", fake_run)
    monkeypatch.setattr(cv, "_cli_supports_vault_secret", lambda cwd=None: False)
    raw = ctx.tools["ciphervault_secret_generate"][1]({
        "name": "NEXTAUTH_SECRET",
        "format": fmt,
        "bytes": 32,
        "env_file": ".env",
        "seal": True,
        "cwd": str(tmp_path),
    })
    out = json.loads(raw)
    assert out["success"] is True
    assert out["name"] == "NEXTAUTH_SECRET"
    assert out["format"] == fmt
    assert out["sealed"] is True
    assert len(out["sha256_prefix"]) == 8

    written = (tmp_path / ".env").read_text(encoding="utf-8")
    gen_val = written.strip().split("=", 1)[1]
    assert len(gen_val) == out["length_chars"]
    assert hashlib.sha256(gen_val.encode("utf-8")).hexdigest()[:8] == out["sha256_prefix"]
    assert gen_val not in raw

    assert ["track", ".env"] in cli_calls
    push_calls = [c for c in cli_calls if c[:1] == ["push"]]
    assert push_calls and "--local" in push_calls[0] and "--shred" in push_calls[0]
    audit_calls = [c for c in cli_calls if c[:2] == ["agent-log", "record"]]
    assert audit_calls and "ciphervault_secret_generate" in audit_calls[0]


def test_secret_generate_validates_inputs(ctx, tmp_path):
    vault = str(_marker_vault(tmp_path / "proj"))
    for bad in [
        {"name": "123BAD", "cwd": vault},
        {"name": "GOOD_NAME", "format": "plain", "cwd": vault},
        {"name": "GOOD_NAME", "bytes": 8, "cwd": vault},
        {"name": "GOOD_NAME", "bytes": True, "cwd": vault},
        {"name": "GOOD_NAME", "env_file": "../escape.env", "cwd": vault},
        {"name": "GOOD_NAME", "env_file": ".ciphervault/vault.db", "cwd": vault},
        {"name": "GOOD_NAME", "cwd": str(tmp_path)},  # no vault at or above cwd
    ]:
        res = json.loads(ctx.tools["ciphervault_secret_generate"][1](bad))
        assert res["success"] is False


def test_diff_tool_never_passes_reveal(ctx, tmp_path, monkeypatch):
    seen = []

    def fake_run_json(args, cwd, timeout=60):
        seen.append(list(args))
        return {"success": True, "data": {"old_source": "head:abcd", "new_source": "working tree", "files": []}}

    monkeypatch.setattr(cv, "_run_cli_json", fake_run_json)
    out = json.loads(ctx.tools["ciphervault_diff"][1]({
        "snapshot_a": "head",
        "snapshot_b": "working",
        "file": ".env",
        "cwd": str(tmp_path),
    }))
    assert out["success"] is True
    assert seen[0] == ["diff", "--json", "--file", ".env", "head", "working"]
    assert "--reveal" not in seen[0] and "-r" not in seen[0]

    bad = json.loads(ctx.tools["ciphervault_diff"][1]({"snapshot_a": "--reveal", "cwd": str(tmp_path)}))
    assert bad["success"] is False


def test_dashboard_plugin_api_hardening_and_endpoints(tmp_path, monkeypatch):
    import importlib.util as _ilu
    api_spec = _ilu.spec_from_file_location("cv_plugin_api", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    api = _ilu.module_from_spec(api_spec)
    api_spec.loader.exec_module(api)

    # UNC and non-directory paths rejected before subprocess invocation
    assert api._safe_cwd(r"\\attacker.example\share") is None
    assert api._safe_cwd("//attacker.example/share") is None
    assert api._safe_cwd(str(tmp_path / "missing-dir")) is None
    assert api._safe_cwd(str(tmp_path)) == str(tmp_path.resolve())

    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-must-not-pass")
    monkeypatch.setenv("CIPHERVAULT_CUSTOM", "keep-me")
    min_env = api._minimal_env()
    assert "OPENAI_API_KEY" not in min_env
    assert min_env.get("CIPHERVAULT_CUSTOM") == "keep-me"

    monkeypatch.setattr(api, "_find_binary", lambda: "/bin/ciphervault")
    calls = []

    class FakeProc:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode

    def fake_subprocess_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[1] == "status":
            return FakeProc(json.dumps({
                "vault": True,
                "cli_version": "1.0.34",
                "tracked_paths": [".env"],
                "tracked_files": 1,
                "working_tree_sealed": True,
                "working_tree_plaintext_files": 0,
                "operators": ["https://op1.cipherv.online"],
                "unexpected_secret_field": "should-be-stripped",
            }))
        if argv[1] == "push":
            return FakeProc("sealed ok")
        if argv[1:3] == ["agent-log", "show"]:
            return FakeProc(json.dumps([{"id": 1, "tool": "terminal", "decision": "blocked"}]))
        if argv[1:3] == ["agent-log", "verify"]:
            return FakeProc(json.dumps({"ok": True, "entries": 1}))
        return FakeProc("{}")

    monkeypatch.setattr(api.subprocess, "run", fake_subprocess_run)

    unc_status = api._status(r"\\attacker.example\share")
    assert unc_status["binary"] == "error" and unc_status["vault"] is False
    assert calls == []

    st = api._status(str(tmp_path))
    assert st["working_tree_sealed"] is True
    assert st["working_tree_plaintext_files"] == 0
    assert "unexpected_secret_field" not in st
    assert "OPENAI_API_KEY" not in calls[-1][1]["env"]

    sealed = api._seal(str(tmp_path))
    assert sealed["working_tree_sealed"] is True
    push_cmd = [argv for argv, _kw in calls if argv[1] == "push"][0]
    assert push_cmd == ["/bin/ciphervault", "push", "--local", "--shred", "-m", "Sealed from Hermes desktop"]

    audit = api._audit_trail(str(tmp_path), limit=10)
    assert audit["success"] is True
    assert audit["verification"]["ok"] is True
    assert audit["entries"][0]["decision"] == "blocked"

    if api.router is not None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(api.router)
        client = TestClient(app)
        assert client.post("/seal", params={"cwd": str(tmp_path)}).json()["working_tree_sealed"] is True
        assert client.get("/audit", params={"cwd": str(tmp_path)}).json()["success"] is True

    desktop_js = (PLUGIN_DIR / "desktop" / "plugin.js").read_text(encoding="utf-8")
    assert "sealed (0B on disk)" in desktop_js
    assert "plaintext on disk" in desktop_js
    assert "Seal & shred .env" in desktop_js
    assert "/seal?cwd=" in desktop_js
    assert "/set?cwd=" in desktop_js
    assert "/pending-prompts?cwd=" in desktop_js
    assert "Save to Vault" in desktop_js


def test_secret_prompt_queued_and_interactive(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)

    # Rejects invalid key names
    bad = json.loads(ctx.tools["ciphervault_secret_prompt"][1]({
        "keys": ["INVALID-KEY"],
        "cwd": str(vault),
    }))
    assert bad["success"] is False

    # Queued desktop prompt mode
    res = json.loads(ctx.tools["ciphervault_secret_prompt"][1]({
        "keys": [
            {"name": "OPENAI_API_KEY", "reason": "Needed for LLM calls", "expected_prefix": "sk-"},
            "STRIPE_SECRET_KEY",
        ],
        "env_file": ".env",
        "seal": True,
        "cwd": str(vault),
    }))
    assert res["success"] is True
    assert res["status"] == "prompt_queued"
    assert res["pending_keys"] == ["OPENAI_API_KEY", "STRIPE_SECRET_KEY"]
    assert res["env_file"] == ".env"
    assert res["seal"] is True

    prompt_file = vault / ".ciphervault" / "pending_secret_prompts.json"
    assert prompt_file.is_file()
    stored = json.loads(prompt_file.read_text(encoding="utf-8"))
    assert [k["name"] for k in stored["keys"]] == ["OPENAI_API_KEY", "STRIPE_SECRET_KEY"]
    assert stored["keys"][0]["expected_prefix"] == "sk-"
    assert "requested_at" in stored

    # Interactive TTY mode with mocked getpass (legacy unsealed CLI fallback)
    monkeypatch.setenv("CIPHERVAULT_INTERACTIVE_PROMPT", "1")
    monkeypatch.setattr(cv.sys.stdin, "isatty", lambda: True)
    cli_calls = []

    def fake_run_cli(args, cwd, timeout=300, input_text=None):
        cli_calls.append((args, cwd, input_text))
        if args[:2] == ["status", "--json"]:
            return {
                "success": True,
                "output": json.dumps({
                    "vault": True,
                    "working_tree_sealed": False,
                    "tracked_paths": [],
                }),
            }
        return {"success": True, "output": "ok"}

    monkeypatch.setattr(cv, "_run_cli", fake_run_cli)

    # Prefix mismatch must fail without leaking entered secret
    monkeypatch.setattr(cv.getpass, "getpass", lambda _p: "wrong_prefix_secret_xyz")
    mismatch = json.loads(ctx.tools["ciphervault_secret_prompt"][1]({
        "keys": [{"name": "OPENAI_API_KEY", "expected_prefix": "sk-"}],
        "cwd": str(vault),
    }))
    assert mismatch["success"] is False
    assert "wrong_prefix_secret_xyz" not in json.dumps(mismatch)

    # Valid interactive entry on unsealed legacy CLI writes .env, runs track + push --local --shred
    secret_val = "sk-test-interactive-secret-999"
    monkeypatch.setattr(cv.getpass, "getpass", lambda _p: secret_val)
    ok = json.loads(ctx.tools["ciphervault_secret_prompt"][1]({
        "keys": [{"name": "OPENAI_API_KEY", "expected_prefix": "sk-"}],
        "env_file": ".env",
        "seal": True,
        "cwd": str(vault),
    }))
    assert ok["success"] is True
    assert ok["configured"] == ["OPENAI_API_KEY"]
    assert ok["sealed"] is True
    assert secret_val not in json.dumps(ok)
    assert f"OPENAI_API_KEY={secret_val}" in (vault / ".env").read_text(encoding="utf-8")
    assert ["track", ".env"] in [c[0] for c in cli_calls]
    push_calls = [c[0] for c in cli_calls if c[0][:3] == ["push", "--local", "-m"]]
    assert push_calls and "--shred" in push_calls[0]


def test_run_passes_profile_flag_when_supported(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[profiles.ci]\ncommands = ["pytest"]\nallow_keys = ["APP_ENV"]\nno_net = true\n',
        encoding="utf-8",
    )
    seen_args = []

    def fake_run_cli_json(args, cwd, timeout=300):
        seen_args.append(list(args))
        return {"success": True, "data": {"exit_code": 0, "stdout": "ok", "stderr": "", "redactions": 0}}

    monkeypatch.setattr(cv, "_run_cli_json", fake_run_cli_json)
    monkeypatch.setattr(cv, "_cli_supports_run_profile", lambda: True)

    res = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest"],
        "profile": "ci",
        "cwd": str(vault),
    }))
    assert res["success"] is True
    assert "--profile" in seen_args[0]
    assert seen_args[0][seen_args[0].index("--profile") + 1] == "ci"

    # When CLI does not support --profile, omit --profile while still enforcing policy.toml
    seen_args.clear()
    monkeypatch.setattr(cv, "_cli_supports_run_profile", lambda: False)
    res2 = json.loads(ctx.tools["ciphervault_run"][1]({
        "command": ["pytest"],
        "profile": "ci",
        "cwd": str(vault),
    }))
    assert res2["success"] is True
    assert "--profile" not in seen_args[0]
    assert "--allow-keys" in seen_args[0]


def test_dashboard_plugin_api_set_and_pending_prompts(tmp_path, monkeypatch):
    import importlib.util as _ilu
    api_spec = _ilu.spec_from_file_location("cv_plugin_api_set", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    api = _ilu.module_from_spec(api_spec)
    api_spec.loader.exec_module(api)

    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "pending_secret_prompts.json").write_text(
        json.dumps({
            "keys": [
                {"name": "OPENAI_API_KEY", "reason": "LLM key", "expected_prefix": "sk-"},
                {"name": "OTHER_KEY", "reason": "Other", "expected_prefix": ""},
            ],
            "env_file": ".env",
            "seal": True,
        }),
        encoding="utf-8",
    )

    monkeypatch.setattr(api, "_find_binary", lambda: "/bin/ciphervault")
    calls = []

    class FakeProc:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode

    def fake_subprocess_run(argv, **kwargs):
        calls.append((argv, kwargs.get("input")))
        if argv[1:4] == ["vault", "generate", "--help"]:
            return FakeProc("Usage: ciphervault vault generate --overwrite --seal --json")
        if argv[1:3] == ["vault", "set"]:
            return FakeProc(json.dumps({
                "success": True,
                "name": argv[3],
                "env_file": ".env",
                "sealed": True,
                "snapshot_head": "deadbeef" * 8,
            }))
        if argv[1] == "status":
            return FakeProc(json.dumps({"vault": True, "working_tree_sealed": True, "tracked_paths": [".env"]}))
        return FakeProc("ok")

    monkeypatch.setattr(api.subprocess, "run", fake_subprocess_run)

    # Validation checks
    assert api._set_secret(str(vault), "BAD-KEY", "val")["success"] is False
    assert api._set_secret(str(vault), "GOOD_KEY\n", "val")["success"] is False
    assert api._set_secret(str(vault), "GOOD_KEY", "")["success"] is False
    assert api._set_secret(str(vault), "GOOD_KEY", 123)["success"] is False
    assert api._set_secret(str(vault), "GOOD_KEY", "val", env_file="../escape.env")["success"] is False
    assert api._set_secret(str(vault), "GOOD_KEY", "val", env_file="/etc/passwd")["success"] is False
    assert api._set_secret(str(vault), "GOOD_KEY", "val", env_file=r"\abs.env")["success"] is False

    secret_val = "sk-desktop-secret-value-12345"
    if api.router is not None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(api.router)
        client = TestClient(app)

        pending_before = client.get("/pending-prompts", params={"cwd": str(vault)}).json()
        assert pending_before["success"] is True
        assert [k["name"] for k in pending_before["keys"]] == ["OPENAI_API_KEY", "OTHER_KEY"]

        resp = client.post(
            "/set",
            params={"cwd": str(vault)},
            json={"key": "OPENAI_API_KEY", "value": secret_val, "env_file": ".env", "seal": True},
        )
        body = resp.json()
        assert body["success"] is True
        assert body["key"] == "OPENAI_API_KEY"
        assert body["sealed"] is True
        assert body["snapshot_head"] == "deadbeef" * 8
        assert secret_val not in resp.text

        # Native `vault set --stdin` never writes plaintext `.env` from Python!
        assert not (vault / ".env").exists()
        set_calls = [(argv, inp) for argv, inp in calls if argv[1:3] == ["vault", "set"]]
        assert len(set_calls) == 1
        assert set_calls[0][0] == [
            "/bin/ciphervault", "vault", "set", "OPENAI_API_KEY",
            "--stdin", "--env-file", ".env", "--json", "--seal",
        ]
        assert set_calls[0][1] == secret_val

        pending_after = client.get("/pending-prompts", params={"cwd": str(vault)}).json()
        assert [k["name"] for k in pending_after["keys"]] == ["OTHER_KEY"]


def test_setup_workspace_scaffolds_policy_and_wires_hermes_config(tmp_path, monkeypatch):
    vault = tmp_path / "proj"
    (vault / ".ciphervault").mkdir(parents=True)
    (vault / ".ciphervault" / "vault.db").write_bytes(b"")
    hermes_home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(cv, "find_binary", lambda: ("/bin/ciphervault", "configured"))

    dry = cv.setup_workspace(cwd=str(vault), wire_hermes_config=True, dry_run=True)
    assert dry["success"] is True
    assert dry["dry_run"] is True
    assert dry["policy"]["action"] == "would_write"
    assert dry["hermes_secret_source"]["action"] == "run_these_commands"
    assert not (vault / ".ciphervault" / "policy.toml").exists()
    assert not (hermes_home / "config.yaml").exists()

    # --wire-hermes never edits Hermes's config.yaml: it hands back the
    # `hermes config set` commands, and the user's file stays byte-for-byte.
    hermes_home.mkdir()
    original_cfg = "# my settings\nmodel: hermes-4  # keep this comment\nsecrets:\n  other: {}\n"
    (hermes_home / "config.yaml").write_text(original_cfg, encoding="utf-8")
    res = cv.setup_workspace(cwd=str(vault), sealed=True, wire_hermes_config=True)
    assert res["success"] is True
    assert res["vault_initialized"] is True
    assert res["policy"]["written"] is True
    wiring = res["hermes_secret_source"]
    assert wiring["updated"] is False
    assert wiring["action"] == "run_these_commands"
    assert wiring["vault_path"] == str(vault.resolve())
    assert wiring["commands"] == [cv._shell_command(argv) for argv in [
        ["hermes", "config", "set", "secrets.ciphervault.enabled", "true"],
        ["hermes", "config", "set", "secrets.ciphervault.vault_path", str(vault.resolve())],
        ["hermes", "config", "set", "secrets.ciphervault.allow_working_copy", "false"],
    ]]
    assert all(cmd in res["next_steps"] for cmd in wiring["commands"])
    assert (hermes_home / "config.yaml").read_text(encoding="utf-8") == original_cfg

    policy_text = (vault / ".ciphervault" / "policy.toml").read_text(encoding="utf-8")
    assert "sealed_mode = true" in policy_text
    assert "[profiles.test]" in policy_text
    assert "[profiles.llm_eval]" in policy_text

    # Re-running without force preserves existing policy.toml.
    (vault / ".ciphervault" / "policy.toml").write_text("# custom\n", encoding="utf-8")
    res2 = cv.setup_workspace(cwd=str(vault), wire_hermes_config=False)
    assert res2["success"] is True
    assert res2["policy"]["already_exists"] is True
    assert (vault / ".ciphervault" / "policy.toml").read_text(encoding="utf-8") == "# custom\n"

    # Re-running with force overwrites policy.toml.
    res3 = cv.setup_workspace(cwd=str(vault), sealed=False, force=True)
    assert res3["policy"]["written"] is True
    assert "sealed_mode = false" in (vault / ".ciphervault" / "policy.toml").read_text(encoding="utf-8")


def test_cli_setup_subcommand_parses_and_runs_dry_run(tmp_path, monkeypatch, capsys):
    import argparse

    vault = tmp_path / "proj"
    vault.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    monkeypatch.setattr(cv, "find_binary", lambda: ("/bin/ciphervault", "configured"))

    parser = argparse.ArgumentParser()
    cv._cli_setup(parser)
    args = parser.parse_args(["setup", "--cwd", str(vault), "--dry-run", "--wire-hermes"])
    rc = cv._cli_handler(args)
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is True
    assert out["vault_initialized"] is False
    assert out["hermes_secret_source"]["action"] == "run_these_commands"
    assert not (tmp_path / "hh" / "config.yaml").exists()


def test_proxy_doctor_reports_providers_policy_and_unmapped_without_values(tmp_path, monkeypatch):
    vault = tmp_path / "proj"
    (vault / ".ciphervault").mkdir(parents=True)
    (vault / ".ciphervault" / "vault.db").write_bytes(b"")
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[profiles.eval]\n[profiles.eval.upstreams]\nCUSTOM_KEY = "https://gw.example.com"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cv,
        "_run_cli_json",
        lambda args, cwd, timeout=30: {
            "success": True,
            "data": {
                "secrets": [
                    {"name": "OPENAI_API_KEY"},
                    {"name": "CUSTOM_KEY"},
                    {"name": "DATABASE_URL"},
                ]
            },
        },
    )
    out = json.loads(cv._tool_proxy_doctor({"cwd": str(vault), "profile": "eval"}))
    assert out["success"] is True
    assert out["proxy_ready"] is True
    assert [p["key"] for p in out["mapped_providers"]] == ["OPENAI_API_KEY"]
    assert out["mapped_policy_upstreams"] == [{"key": "CUSTOM_KEY", "upstream": "https://gw.example.com"}]
    assert out["unmapped_keys"] == ["DATABASE_URL"]


def test_on_tool_request_emits_ambient_posture_once_per_workspace(tmp_path, monkeypatch):
    vault = tmp_path / "proj"
    (vault / ".ciphervault").mkdir(parents=True)
    (vault / ".ciphervault" / "vault.db").write_bytes(b"")
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[vault]\nsealed_mode = true\n[profiles.test]\nno_net = true\n',
        encoding="utf-8",
    )
    cv._POSTURE_SEEN.clear()
    first = cv.on_tool_request("ciphervault_status", {"cwd": str(vault)}, {"cwd": str(vault)})
    assert first is not None
    assert "posture:" in first["reason"]
    assert "sealed_mode=True" in first["reason"]
    assert "['test']" in first["reason"]

    second = cv.on_tool_request("ciphervault_status", {"cwd": str(vault)}, {"cwd": str(vault)})
    assert second is None


def test_audit_hmac_hex_not_leaked_in_minimal_env():
    assert "CIPHERVAULT_AUDIT_HMAC_KEY" not in cv._minimal_env()
    tag1 = cv._audit_hmac_hex("terminal", "blocked", ".env", '{"reason":"x"}')
    tag2 = cv._audit_hmac_hex("terminal", "blocked", ".env", '{"reason":"x"}')
    assert len(tag1) == 64
    assert tag1 == tag2


def test_dashboard_plugin_api_env_health_endpoint(tmp_path, monkeypatch):
    import importlib.util
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    spec = importlib.util.spec_from_file_location(
        "cv_plugin_api_health",
        Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py",
    )
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("import os\na = os.getenv('NEEDED_KEY')\nb = os.getenv('HAVE_KEY')\n", encoding="utf-8")
    (proj / ".env").write_text("HAVE_KEY=real_val\nEMPTY_KEY=\n", encoding="utf-8")
    monkeypatch.setattr(api, "_find_binary", lambda: None)

    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)
    res = client.get("/env-health", params={"cwd": str(proj)}).json()
    assert res["success"] is True
    assert "real_val" not in json.dumps(res)
    assert res["missing_in_vault"] == ["NEEDED_KEY"]
    assert {"key": "EMPTY_KEY", "file": ".env", "issue": "EMPTY_VALUE"} in res["value_anomalies"]


def test_workspace_posture_included_in_tool_result_json(tmp_path, monkeypatch):
    vault = tmp_path / "proj"
    (vault / ".ciphervault").mkdir(parents=True)
    (vault / ".ciphervault" / "vault.db").write_bytes(b"")
    (vault / ".ciphervault" / "policy.toml").write_text(
        "[vault]\nsealed_mode = true\n[profiles.unit]\nno_net = true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cv,
        "_run_cli_json",
        lambda args, cwd, timeout=120: {"success": True, "data": {"vault": True}},
    )
    status_out = json.loads(cv._tool_status({"cwd": str(vault)}))
    assert "workspace_posture" in status_out
    assert "sealed_mode=True" in status_out["workspace_posture"]
    assert "['unit']" in status_out["workspace_posture"]


@pytest.fixture
def real_vault(tmp_path, monkeypatch):
    import subprocess

    binary = os.environ.get("CV_TEST_BINARY")
    if not binary or not Path(binary).is_file():
        pytest.skip("set CV_TEST_BINARY for real CLI vault integration checks")
    monkeypatch.setattr(cv, "find_binary", lambda: (binary, "integration test"))
    vault = tmp_path / "real_vault"
    vault.mkdir()
    subprocess.run([binary, "init"], cwd=str(vault), check=True, capture_output=True, env=cv._minimal_env())
    yield binary, vault
    cv._close_all_bridges()


def test_per_vault_audit_hmac_key_enforced_without_env_var_and_protected(real_vault):
    import subprocess
    binary, vault = real_vault
    key_bytes = cv._vault_audit_hmac_key_bytes(str(vault))
    assert len(key_bytes) == 32
    key_file = vault / ".ciphervault" / "audit_hmac.key"
    assert key_file.is_file()

    # Guard blocks reading or writing .ciphervault/audit_hmac.key
    r_block = cv.on_pre_tool_call("read_file", {"path": str(key_file), "cwd": str(vault)})
    w_block = cv.on_pre_tool_call("write_file", {"path": str(key_file), "content": "x", "cwd": str(vault)})
    assert r_block and r_block["action"] == "block"
    assert w_block and w_block["action"] == "block"

    # Even with CIPHERVAULT_AUDIT_HMAC_KEY absent from env, direct `agent-log record`
    # without --hmac is rejected by the Rust CLI because .ciphervault/audit_hmac.key exists!
    env = cv._minimal_env()
    env.pop("CIPHERVAULT_AUDIT_HMAC_KEY", None)
    unauth = subprocess.run(
        [binary, "agent-log", "record", "--tool", "forged", "--decision", "scrubbed_result"],
        cwd=str(vault),
        capture_output=True,
        text=True,
        env=env,
    )
    assert unauth.returncode != 0
    assert "missing --hmac" in (unauth.stderr + unauth.stdout)

    # Meanwhile the plugin's own _audit() succeeds using the key.
    assert cv._audit("ciphervault_status", "ok", cwd=str(vault)) is True


def test_real_cli_env_doctor_works_on_sealed_shredded_vault(real_vault):
    import subprocess
    binary, vault = real_vault
    (vault / "app.py").write_text(
        "import os\nx = os.getenv('OPENAI_API_KEY')\ny = os.getenv('MISSING_FROM_VAULT')\n",
        encoding="utf-8",
    )
    (vault / ".env").write_text(
        "OPENAI_API_KEY=wrong_prefix_secret_value_999\nEMPTY_ONE=\n",
        encoding="utf-8",
    )
    subprocess.run([binary, "track", ".env"], cwd=str(vault), check=True, env=cv._minimal_env())
    subprocess.run(
        [binary, "push", "--local", "--shred", "-m", "seal for env-doctor"],
        cwd=str(vault),
        check=True,
        env=cv._minimal_env(),
    )
    assert not (vault / ".env").exists()

    cv._ENV_DOCTOR_SUPPORT_CACHE.clear()
    raw = cv._tool_env_doctor({"cwd": str(vault)})
    assert "wrong_prefix_secret_value_999" not in raw
    out = json.loads(raw)
    assert out["success"] is True
    assert out["sealed"] is True
    assert "OPENAI_API_KEY" in out["vault_keys"]
    assert "MISSING_FROM_VAULT" in out["missing_in_vault"]
    issues = {(a["key"], a["issue"]) for a in out["value_anomalies"]}
    assert ("OPENAI_API_KEY", "PREFIX_MISMATCH") in issues
    assert ("EMPTY_ONE", "EMPTY_VALUE") in issues
    assert "workspace_posture" in out


# ------------------------------------------------------------ v0.7.1 hardening, sealed-vault fix & lifecycle hooks


def test_plugin_yaml_declares_version_and_lifecycle_hooks():
    yaml_text = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
    assert 'version: "0.8.0"' in yaml_text
    for hook in ("on_session_start", "pre_llm_call", "pre_tool_call", "transform_tool_result", "post_tool_call"):
        assert f"- {hook}" in yaml_text
    assert cv.PLUGIN_VERSION == "0.8.0"
    manifest = json.loads((PLUGIN_DIR / "dashboard" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == cv.PLUGIN_VERSION


def test_dashboard_manifest_version_matches_plugin_version():
    # The dashboard manifest drifted to 0.4.0 while the plugin moved to
    # 0.7.x; pin them together so the next bump cannot drift again.
    manifest = json.loads(
        (PLUGIN_DIR / "dashboard" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["version"] == cv.PLUGIN_VERSION


def test_secret_generate_prefers_native_vault_generate_without_writing_disk(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    seen = []

    def fake_run_json(args, cwd, timeout=120, input_text=None):
        seen.append((list(args), cwd))
        return {
            "success": True,
            "data": {
                "success": True,
                "name": "APP_SECRET",
                "format": "hex",
                "length_chars": 64,
                "sha256_prefix": "a1b2c3d4",
                "env_file": ".env",
                "sealed": True,
                "snapshot_head": "cafebabe" * 8,
            },
        }

    audit_calls = _capture_audit(monkeypatch)
    monkeypatch.setattr(cv, "_cli_supports_vault_secret", lambda cwd=None: True)
    monkeypatch.setattr(cv, "_run_cli_json", fake_run_json)

    raw = ctx.tools["ciphervault_secret_generate"][1]({
        "name": "APP_SECRET",
        "format": "hex",
        "bytes": 32,
        "env_file": ".env",
        "seal": True,
        "cwd": str(vault),
    })
    out = json.loads(raw)
    assert out["success"] is True
    assert out["name"] == "APP_SECRET"
    assert out["length_chars"] == 64
    assert out["sha256_prefix"] == "a1b2c3d4"
    assert out["sealed"] is True
    assert out["snapshot_head"] == "cafebabe" * 8
    assert not (vault / ".env").exists(), "native vault generate must never write plaintext .env in Python"
    assert seen[0][0] == [
        "vault", "generate", "APP_SECRET",
        "--format", "hex", "--bytes", "32", "--env-file", ".env", "--json", "--seal",
    ]
    assert "--overwrite" not in seen[0][0]
    assert any(c[:2] == ["agent-log", "record"] and "ciphervault_secret_generate" in c for c in audit_calls)

    # Explicit overwrite=True forwards --overwrite
    seen.clear()
    out2 = json.loads(ctx.tools["ciphervault_secret_generate"][1]({
        "name": "APP_SECRET",
        "overwrite": True,
        "seal": False,
        "cwd": str(vault),
    }))
    assert out2["success"] is True
    assert "--overwrite" in seen[0][0]
    assert "--seal" not in seen[0][0]


def test_secret_generate_legacy_fallback_fails_closed_on_sealed_vault_and_refuses_overwrite(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    monkeypatch.setattr(cv, "_cli_supports_vault_secret", lambda cwd=None: False)

    # 1. Sealed vault with legacy CLI MUST fail closed without writing .env or calling push
    cli_calls = []

    def fake_sealed_cli(args, cwd, timeout=120, input_text=None):
        cli_calls.append(list(args))
        if args[:2] == ["status", "--json"]:
            return {
                "success": True,
                "output": json.dumps({
                    "vault": True,
                    "working_tree_sealed": True,
                    "tracked_paths": [".env"],
                }),
            }
        raise AssertionError(f"legacy fallback must not run {args} on a sealed vault")

    monkeypatch.setattr(cv, "_run_cli", fake_sealed_cli)
    res_sealed = json.loads(ctx.tools["ciphervault_secret_generate"][1]({
        "name": "NEW_KEY",
        "cwd": str(vault),
    }))
    assert res_sealed["success"] is False
    assert "sealed" in res_sealed["error"].lower()
    assert "vault generate" in res_sealed["error"]
    assert not (vault / ".env").exists()
    assert cli_calls == [["status", "--json"]]

    # 2. Status failure inside a vault MUST also fail closed
    monkeypatch.setattr(cv, "_run_cli", lambda args, cwd, timeout=120, input_text=None: {"success": False, "error": "boom"})
    res_err = json.loads(ctx.tools["ciphervault_secret_generate"][1]({
        "name": "NEW_KEY",
        "cwd": str(vault),
    }))
    assert res_err["success"] is False
    assert not (vault / ".env").exists()

    # 3. Unsealed vault with existing key refuses overwrite by default, allows with overwrite=True
    (vault / ".env").write_text("EXISTING_KEY=original-value\n", encoding="utf-8")
    unsealed_calls = []

    def fake_unsealed_cli(args, cwd, timeout=120, input_text=None):
        unsealed_calls.append(list(args))
        if args[:2] == ["status", "--json"]:
            return {
                "success": True,
                "output": json.dumps({
                    "vault": True,
                    "working_tree_sealed": False,
                    "tracked_paths": [".env"],
                }),
            }
        return {"success": True, "output": "ok"}

    monkeypatch.setattr(cv, "_run_cli", fake_unsealed_cli)
    dup = json.loads(ctx.tools["ciphervault_secret_generate"][1]({
        "name": "EXISTING_KEY",
        "cwd": str(vault),
    }))
    assert dup["success"] is False
    assert "overwrite" in dup["error"].lower()
    assert (vault / ".env").read_text(encoding="utf-8") == "EXISTING_KEY=original-value\n"

    rot = json.loads(ctx.tools["ciphervault_secret_generate"][1]({
        "name": "EXISTING_KEY",
        "overwrite": True,
        "cwd": str(vault),
    }))
    assert rot["success"] is True
    assert "original-value" not in (vault / ".env").read_text(encoding="utf-8")


def test_secret_generate_always_requires_pre_tool_call_approval(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "proj")
    calls = _capture_audit(monkeypatch)

    # Every generate call goes to Hermes approval, scoped to the vault and env file.
    new = cv.on_pre_tool_call("ciphervault_secret_generate", {"name": "NEW_KEY", "cwd": str(vault)})
    assert new and new["action"] == "approve"
    assert "NEW_KEY" in new["message"] and str(vault.resolve()) in new["message"]
    assert "overwrite" not in new["rule_key"]
    again = cv.on_pre_tool_call(
        "ciphervault_secret_generate", {"name": "OTHER_KEY", "overwrite": False, "cwd": str(vault)}
    )
    assert again["rule_key"] == new["rule_key"]
    other_file = cv.on_pre_tool_call(
        "ciphervault_secret_generate", {"name": "NEW_KEY", "env_file": ".env.local", "cwd": str(vault)}
    )
    assert other_file["rule_key"] != new["rule_key"]

    # Overwriting is one-shot: no "always" grant can cover the next one.
    appr = cv.on_pre_tool_call(
        "ciphervault_secret_generate", {"name": "EXISTING_KEY", "overwrite": True, "cwd": str(vault)}
    )
    assert appr and appr["action"] == "approve"
    assert "EXISTING_KEY" in appr["message"] and "overwrite" in appr["message"]
    assert "overwrite" in appr["rule_key"]
    appr2 = cv.on_pre_tool_call(
        "ciphervault_secret_generate", {"name": "EXISTING_KEY", "overwrite": True, "cwd": str(vault)}
    )
    assert appr2["rule_key"] != appr["rule_key"]
    assert any(c[:2] == ["agent-log", "record"] and "approval_requested" in c for c in calls)


def test_secret_prompt_requires_pre_tool_call_approval(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "proj")
    _capture_audit(monkeypatch)
    appr = cv.on_pre_tool_call(
        "ciphervault_secret_prompt",
        {"keys": [{"name": "OPENAI_API_KEY", "reason": "LLM"}, "STRIPE_KEY"], "cwd": str(vault)},
    )
    assert appr and appr["action"] == "approve"
    assert "OPENAI_API_KEY" in appr["message"] and "STRIPE_KEY" in appr["message"]
    assert appr["rule_key"].startswith("ciphervault_secret_prompt:")
    assert "OPENAI_API_KEY,STRIPE_KEY" in appr["rule_key"]
    bad = cv.on_pre_tool_call("ciphervault_secret_prompt", {"keys": ["not-a-name"], "cwd": str(vault)})
    assert bad["action"] == "block"
    assert cv.on_pre_tool_call("ciphervault_secret_prompt", "not a dict")["action"] == "block"

    # An internal error while checking the target fails closed, vault or not.
    def boom(cwd, env_file):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(cv, "_secret_write_target", boom)
    for cwd in (str(vault), str(tmp_path)):
        for tool in ("ciphervault_secret_prompt", "ciphervault_secret_generate"):
            out = cv.on_pre_tool_call(tool, {"keys": ["K"], "name": "K", "cwd": cwd})
            assert out and out["action"] == "block"


@pytest.mark.parametrize("tool, args", [
    ("ciphervault_secret_generate", {"name": "OPENROUTER_API_KEY", "overwrite": True}),
    ("ciphervault_secret_prompt", {"keys": ["OPENROUTER_API_KEY"]}),
])
def test_secret_tools_are_blocked_outside_a_vault(ctx, tmp_path, monkeypatch, tool, args):
    # The review's example: a model-chosen cwd at the Hermes home (no vault)
    # must not let either tool rewrite a NAME= line in $HERMES_HOME/.env.
    hermes_home = tmp_path / "hermes-home"
    hermes_home.mkdir()
    (hermes_home / ".env").write_text("OPENROUTER_API_KEY=keep-me\n", encoding="utf-8")
    monkeypatch.setattr(cv, "_hermes_home_resolver", lambda: None)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    _capture_audit(monkeypatch)
    call = dict(args, cwd=str(hermes_home), env_file=".env")

    gate = cv.on_pre_tool_call(tool, call)
    assert gate and gate["action"] == "block"
    assert "vault" in gate["message"]
    res = json.loads(ctx.tools[tool][1](call))
    assert res["success"] is False
    assert (hermes_home / ".env").read_text(encoding="utf-8") == "OPENROUTER_API_KEY=keep-me\n"


@pytest.mark.parametrize("tool, args", [
    ("ciphervault_secret_generate", {"name": "OPENROUTER_API_KEY"}),
    ("ciphervault_secret_prompt", {"keys": ["OPENROUTER_API_KEY"]}),
])
def test_secret_tools_never_write_into_the_hermes_home(ctx, tmp_path, monkeypatch, tool, args):
    # Even a vault that contains the Hermes home (say, one at the user's home
    # directory) cannot be used to write the Hermes home's files.
    vault = _marker_vault(tmp_path / "home")
    hermes_home = vault / ".hermes"
    hermes_home.mkdir()
    (hermes_home / ".env").write_text("OPENROUTER_API_KEY=keep-me\n", encoding="utf-8")
    monkeypatch.setattr(cv, "_hermes_home_resolver", lambda: None)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    _capture_audit(monkeypatch)
    for call in (
        dict(args, cwd=str(vault), env_file=".hermes/.env"),
        dict(args, cwd=str(hermes_home), env_file=".env"),
    ):
        gate = cv.on_pre_tool_call(tool, call)
        assert gate and gate["action"] == "block"
        assert "Hermes home" in gate["message"]
        res = json.loads(ctx.tools[tool][1](call))
        assert res["success"] is False
    assert (hermes_home / ".env").read_text(encoding="utf-8") == "OPENROUTER_API_KEY=keep-me\n"


def test_secret_target_must_stay_inside_the_vault_after_symlinks(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "proj")
    outside = tmp_path / "outside.env"
    outside.write_text("KEY=keep-me\n", encoding="utf-8")
    try:
        (vault / "linked.env").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available to this user")
    root, _base, target, err = cv._secret_write_target(str(vault), "linked.env")
    assert err and root is None and target is None


def test_hermes_home_prefers_hermes_resolver(tmp_path, monkeypatch):
    profile_home = tmp_path / "profiles" / "work"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "plain"))
    monkeypatch.setattr(cv, "_hermes_home_resolver", lambda: (lambda: str(profile_home)))
    assert cv._hermes_home() == profile_home
    # A failing resolver, or none (outside Hermes), falls back to $HERMES_HOME.
    monkeypatch.setattr(cv, "_hermes_home_resolver", lambda: (lambda: 1 / 0))
    assert cv._hermes_home() == tmp_path / "plain"
    monkeypatch.setattr(cv, "_hermes_home_resolver", lambda: None)
    assert cv._hermes_home() == tmp_path / "plain"


def test_upsert_env_vars_never_replaces_without_approval(tmp_path):
    env = tmp_path / ".env"
    env.write_text("export KEEP=1\nOTHER=2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        cv._upsert_env_vars(env, [("NEW", "x"), ("KEEP", "replaced")])
    assert env.read_text(encoding="utf-8") == "export KEEP=1\nOTHER=2\n"
    cv._upsert_env_vars(env, [("NEW", "x")])
    cv._upsert_env_vars(env, [("KEEP", "replaced")], replace={"KEEP"})
    assert env.read_text(encoding="utf-8") == "KEEP=replaced\nOTHER=2\nNEW=x\n"


def test_secret_prompt_tty_asks_before_replacing_an_existing_key(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "proj")
    (vault / ".env").write_text("OPENAI_API_KEY=sk-old-value\n", encoding="utf-8")
    monkeypatch.setenv("CIPHERVAULT_INTERACTIVE_PROMPT", "1")
    monkeypatch.setattr(cv.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cv.getpass, "getpass", lambda _p: "sk-new-value-123")
    monkeypatch.setattr(cv, "_cli_supports_vault_secret", lambda cwd=None: False)
    cli_calls = []

    def fake_run_cli(args, cwd, timeout=300, input_text=None):
        cli_calls.append(list(args))
        if args[:2] == ["status", "--json"]:
            return {"success": True, "output": json.dumps({
                "vault": True, "working_tree_sealed": False, "tracked_paths": [".env"],
            })}
        if args[:3] == ["run", "--dry-run", "--json"]:
            return {"success": True, "output": json.dumps({"secrets": [{"name": "OPENAI_API_KEY"}]})}
        return {"success": True, "output": "ok"}

    monkeypatch.setattr(cv, "_run_cli", fake_run_cli)
    asked = []

    def decline(name, env_file, certain=True):
        asked.append((name, env_file, certain))
        return False

    monkeypatch.setattr(cv, "_confirm_replace", decline)
    call = {"keys": ["OPENAI_API_KEY", "NEW_KEY"], "env_file": ".env", "seal": False, "cwd": str(vault)}
    res = json.loads(ctx.tools["ciphervault_secret_prompt"][1](call))
    assert asked == [("OPENAI_API_KEY", ".env", True)]  # only the existing key is asked about
    assert res["success"] is True
    assert res["configured"] == ["NEW_KEY"]
    assert res["skipped_existing"] == ["OPENAI_API_KEY"]
    text = (vault / ".env").read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=sk-old-value" in text and "NEW_KEY=sk-new-value-123" in text

    # With a yes, the existing key is replaced.
    monkeypatch.setattr(cv, "_confirm_replace", lambda name, env_file, certain=True: True)
    res2 = json.loads(ctx.tools["ciphervault_secret_prompt"][1](dict(call, keys=["OPENAI_API_KEY"])))
    assert res2["success"] is True and res2["configured"] == ["OPENAI_API_KEY"]
    assert "OPENAI_API_KEY=sk-new-value-123" in (vault / ".env").read_text(encoding="utf-8")

    # When existence cannot be checked, every key is asked about; declining all writes nothing.
    monkeypatch.setattr(cv, "_run_cli", lambda args, cwd, timeout=300, input_text=None: {"success": False, "error": "boom"})
    asked.clear()
    monkeypatch.setattr(cv, "_confirm_replace", decline)
    before = (vault / ".env").read_text(encoding="utf-8")
    res3 = json.loads(ctx.tools["ciphervault_secret_prompt"][1](dict(call, keys=["BRAND_NEW"])))
    assert asked == [("BRAND_NEW", ".env", False)]
    assert res3["success"] is False and res3["skipped_existing"] == ["BRAND_NEW"]
    assert (vault / ".env").read_text(encoding="utf-8") == before


def test_confirm_replace_needs_an_explicit_yes(monkeypatch):
    for answer, expected in (("y", True), ("YES", True), ("", False), ("n", False), ("sure", False)):
        monkeypatch.setattr("builtins.input", lambda _p, a=answer: a)
        assert cv._confirm_replace("KEY", ".env") is expected

    def eof(_p):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert cv._confirm_replace("KEY", ".env") is False


def test_secret_prompt_tty_native_vault_set_and_sealed_legacy_fail_closed(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    monkeypatch.setenv("CIPHERVAULT_INTERACTIVE_PROMPT", "1")
    monkeypatch.setattr(cv.sys.stdin, "isatty", lambda: True)
    secret_val = "sk-native-tty-secret-999"
    monkeypatch.setattr(cv.getpass, "getpass", lambda _p: secret_val)

    # 1. Native `ciphervault vault set <NAME> --stdin`: zero plaintext written to disk
    seen_native = []

    def fake_native_json(args, cwd, timeout=120, input_text=None):
        seen_native.append((list(args), cwd, input_text))
        return {
            "success": True,
            "data": {
                "success": True,
                "name": "OPENAI_API_KEY",
                "env_file": ".env",
                "sealed": True,
                "snapshot_head": "abcd1234" * 8,
            },
        }

    _capture_audit(monkeypatch)
    monkeypatch.setattr(cv, "_cli_supports_vault_secret", lambda cwd=None: True)
    monkeypatch.setattr(cv, "_run_cli_json", fake_native_json)

    res = json.loads(ctx.tools["ciphervault_secret_prompt"][1]({
        "keys": [{"name": "OPENAI_API_KEY", "expected_prefix": "sk-"}],
        "env_file": ".env",
        "seal": True,
        "cwd": str(vault),
    }))
    assert res["success"] is True
    assert res["configured"] == ["OPENAI_API_KEY"]
    assert res["snapshot_head"] == "abcd1234" * 8
    assert secret_val not in json.dumps(res)
    assert not (vault / ".env").exists()
    set_calls = [c for c in seen_native if c[0][:2] == ["vault", "set"]]
    assert len(set_calls) == 1
    assert set_calls[0][0] == ["vault", "set", "OPENAI_API_KEY", "--stdin", "--env-file", ".env", "--json", "--seal"]
    assert set_calls[0][2] == secret_val
    # Only the vault set call carries the secret.
    assert all(c[2] is None for c in seen_native if c[0][:2] != ["vault", "set"])

    # 2. Legacy CLI fallback on sealed vault MUST fail closed without writing .env or leaking secret
    monkeypatch.setattr(cv, "_cli_supports_vault_secret", lambda cwd=None: False)
    monkeypatch.setattr(
        cv,
        "_run_cli_json",
        lambda args, cwd, timeout=20, input_text=None: {
            "success": True,
            "data": {"vault": True, "working_tree_sealed": True, "tracked_paths": [".env"]},
        },
    )
    res_sealed = json.loads(ctx.tools["ciphervault_secret_prompt"][1]({
        "keys": [{"name": "OPENAI_API_KEY", "expected_prefix": "sk-"}],
        "env_file": ".env",
        "seal": True,
        "cwd": str(vault),
    }))
    assert res_sealed["success"] is False
    assert "sealed" in res_sealed["error"].lower()
    assert secret_val not in json.dumps(res_sealed)
    assert not (vault / ".env").exists()


def test_proxy_upstream_removed_from_schema_and_dns_error_fails_closed(ctx, tmp_path, monkeypatch):
    run_props = ctx.tools["ciphervault_run"][0]["parameters"]["properties"]
    assert "proxy_upstream" not in run_props

    gen_props = ctx.tools["ciphervault_secret_generate"][0]["parameters"]["properties"]
    assert "overwrite" in gen_props and gen_props["overwrite"]["default"] is False

    # _is_unsafe_upstream_host MUST fail CLOSED on DNS OSError and empty resolution
    def raise_dns(*a, **k):
        raise OSError("NXDOMAIN")

    monkeypatch.setattr(cv.socket, "getaddrinfo", raise_dns)
    assert cv._is_unsafe_upstream_host("unresolvable.example.com", 443) is True

    monkeypatch.setattr(cv.socket, "getaddrinfo", lambda *a, **k: [])
    assert cv._is_unsafe_upstream_host("empty-dns.example.com", 443) is True

    monkeypatch.setattr(
        cv.socket,
        "getaddrinfo",
        lambda *a, **k: [(cv.socket.AF_INET, cv.socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    assert cv._is_unsafe_upstream_host("api.example.com", 443) is False


@pytest.mark.parametrize("tool, args", [
    ("search_files", {"path": ".env", "pattern": "KEY"}),
    ("search_files", {"glob": "*.env", "pattern": "API"}),
    ("search_files", {"glob": "**/*.pem", "pattern": "PRIVATE"}),
    ("search_files", {"glob": ".ciphervault/*", "pattern": "allow_keys"}),
    ("search_files", {"path": ".ciphervault/policy.toml", "pattern": "upstreams"}),
    ("browser_cdp", {"url": "file:///proj/.env"}),
    ("browser_navigate", {"url": "file:///proj/secrets.json"}),
    ("browser_eval", {"script": "fetch('http://127.0.0.1:8080/api/diff?reveal=true')"}),
    ("browser_read", {"path": "/proj/id_ed25519"}),
])
def test_guard_blocks_search_files_and_browser_tools_on_secrets(ctx, monkeypatch, tool, args):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)
    blk = cv.on_pre_tool_call(tool, args)
    assert blk and blk["action"] == "block", f"expected {tool}({args}) to block"


def test_guard_search_files_allows_clean_and_fails_closed_in_vault(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    assert cv.on_pre_tool_call("search_files", {"path": "src/", "pattern": "API_KEY", "cwd": str(vault)}) is None

    # Fail closed inside vault when exact redaction fails
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, False))
    _capture_audit(monkeypatch)
    blk_s = cv.on_pre_tool_call("search_files", {"path": "src/", "pattern": "foo", "cwd": str(vault)})
    blk_b = cv.on_pre_tool_call("browser_cdp", {"action": "snapshot", "cwd": str(vault)})
    assert blk_s and blk_s["action"] == "block"
    assert blk_b and blk_b["action"] == "block"

    # post_tool_call audits browser_* tools too
    audit_calls = _capture_audit(monkeypatch)
    cv.on_post_tool_call("browser_cdp", {"url": "https://example.com", "cwd": str(vault)}, "ok")
    assert any(c[:2] == ["agent-log", "record"] and "browser_cdp" in c for c in audit_calls)


@pytest.mark.parametrize("cmd", [
    ["bash", "-lc", "echo $SECRET"],
    ["sh", "-xc", "env"],
    ["zsh", "-euoc", "printenv"],
    ["node", "--eval", "console.log(process.env)"],
    ["node", "-p", "process.env.API_KEY"],
    ["node", "--print", "process.env.API_KEY"],
    ["node", "--input-type", "module", "-e", "console.log(1)"],
    ["env", "FOO=1", "python", "-c", "import os; print(os.environ)"],
    ["env", "-S", "bash -lc 'env'"],
    ["uv", "run", "python", "-c", "print(1)"],
    ["uv", "run", "--with", "pytest", "python3", "-c", "print(1)"],
    ["npx", "node", "--eval", "console.log(1)"],
    ["npx", "-c", "printenv"],
    ["pwsh", "-Enc", "QQ=="],
])
def test_inline_interpreter_hardening_catches_shells_node_and_wrappers(cmd):
    assert cv._is_inline_interpreter_cmd(cmd) is True, f"expected inline detection for {cmd!r}"
    key = cv._compute_run_rule_key(cmd, None, True, False, None)
    assert ":inline=" in key


@pytest.mark.parametrize("cmd", [
    ["python", "-m", "pytest", "-c", "pytest.ini"],
    ["uv", "run", "pytest", "-q"],
    ["npx", "vitest", "run"],
    ["node", "scripts/check.js", "-e", "prod"],
    ["bash", "scripts/test.sh"],
])
def test_inline_interpreter_hardening_allows_non_inline_commands(cmd):
    assert cv._is_inline_interpreter_cmd(cmd) is False, f"unexpected inline detection for {cmd!r}"


@pytest.mark.parametrize("git_cmd", [
    "git -C repo push",
    "git --no-pager commit -m hi",
    "git -c user.name=bot add .",
    "git --git-dir=.git --work-tree=. push origin main",
    'git.exe -C "sub dir" commit -m test',
])
def test_git_danger_flags_and_fail_closed_hook_check_in_vault(ctx, tmp_path, monkeypatch, git_cmd):
    vault = _marker_vault(tmp_path)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)

    # 1. Fail CLOSED when `hook check` fails or times out inside a vault
    monkeypatch.setattr(
        cv,
        "_run_cli_json",
        lambda args, cwd, timeout=30: {"success": False, "error": "timed out"},
    )
    blk_fail = cv.on_pre_tool_call("terminal", {"command": git_cmd, "cwd": str(vault)})
    assert blk_fail and blk_fail["action"] == "block"
    assert "failing closed" in blk_fail["message"]

    # 2. Blocks when violations exist
    monkeypatch.setattr(
        cv,
        "_run_cli_json",
        lambda args, cwd, timeout=30: {
            "success": True,
            "data": {"violations_count": 1, "violations": [{"path": ".env"}]},
        },
    )
    blk_sprawl = cv.on_pre_tool_call("terminal", {"command": git_cmd, "cwd": str(vault)})
    assert blk_sprawl and blk_sprawl["action"] == "block"
    assert ".env" in blk_sprawl["message"]

    # 3. Passes when hook check succeeds with 0 violations
    monkeypatch.setattr(
        cv,
        "_run_cli_json",
        lambda args, cwd, timeout=30: {"success": True, "data": {"violations_count": 0, "violations": []}},
    )
    assert cv.on_pre_tool_call("terminal", {"command": git_cmd, "cwd": str(vault)}) is None


def test_policy_toml_wildcards_require_keys_explicit_approval_and_starter(ctx, tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path)
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[vault]\n'
        'sealed_mode = true\n'
        'description = "Project vault"\n'
        'sandbox_read_paths = [".venv"]\n\n'
        '[profiles.test]\n'
        'description = "Test profile"\n'
        'commands = ["pytest"]\n'
        'allow_keys = ["DATABASE_URL", "TEST_*", "*_TOKEN"]\n'
        'require_keys = ["DATABASE_URL"]\n'
        'no_net = true\n'
        'require_explicit_approval = true\n'
        'sandbox_read_paths = [".venv", "node_modules"]\n',
        encoding="utf-8",
    )
    _capture_audit(monkeypatch)

    # Wildcard narrowing: concrete match and narrower glob match are allowed
    eff1, err1 = cv._resolve_run_policy(
        {"command": ["pytest"], "profile": "test", "allow_keys": ["DATABASE_URL", "TEST_API_KEY"]},
        str(vault),
    )
    assert err1 is None and eff1["allow_keys"] == ["DATABASE_URL", "TEST_API_KEY"]

    eff2, err2 = cv._resolve_run_policy(
        {"command": ["pytest"], "profile": "test", "allow_keys": ["DATABASE_URL", "TEST_DB_*"]},
        str(vault),
    )
    assert err2 is None and eff2["allow_keys"] == ["DATABASE_URL", "TEST_DB_*"]

    # Dropping a required key fails
    _eff3, err3 = cv._resolve_run_policy(
        {"command": ["pytest"], "profile": "test", "allow_keys": ["TEST_API_KEY"]},
        str(vault),
    )
    assert err3 and "required key" in err3

    # Widening beyond profile allow_keys fails
    for wider in (["DATABASE_URL", "PROD_SECRET"], ["DATABASE_URL", "*"], ["DATABASE_URL", "PROD_*"]):
        _eff_w, err_w = cv._resolve_run_policy(
            {"command": ["pytest"], "profile": "test", "allow_keys": wider},
            str(vault),
        )
        assert err_w and "exceeds" in err_w

    # require_explicit_approval=true produces unique one-shot rule keys
    a1 = cv.on_pre_tool_call("ciphervault_run", {"command": ["pytest"], "profile": "test", "cwd": str(vault)})
    a2 = cv.on_pre_tool_call("ciphervault_run", {"command": ["pytest"], "profile": "test", "cwd": str(vault)})
    assert a1["action"] == "approve" and a2["action"] == "approve"
    assert ":oneshot=" in a1["rule_key"]
    assert a1["rule_key"] != a2["rule_key"]

    # Unknown key in policy.toml fails closed
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[profiles.test]\nunknown_setting = true\n',
        encoding="utf-8",
    )
    _pol, perr = cv._load_policy_toml(str(vault))
    assert perr and "unknown key" in perr

    # Starter policy.toml validates cleanly
    (vault / ".ciphervault" / "policy.toml").write_text(
        cv._STARTER_POLICY_TOML.format(sealed_mode="true"),
        encoding="utf-8",
    )
    pol_ok, perr_ok = cv._load_policy_toml(str(vault))
    assert perr_ok is None
    assert "TEST_*" in pol_ok["profiles"]["test"]["allow_keys"]


def test_slash_ciphervault_version_and_argument_parsing(ctx, monkeypatch):
    dispatched = []
    monkeypatch.setattr(ctx, "dispatch_tool", lambda name, params: dispatched.append((name, params)) or "ok")
    monkeypatch.setattr(cv, "find_binary", lambda: ("/bin/ciphervault", "configured"))

    ver = cv._slash_ciphervault("version")
    assert f"plugin v{cv.PLUGIN_VERSION}" in ver
    assert f"v{cv.RELEASE_VERSION}" in ver
    assert cv.PLUGIN_VERSION != cv.RELEASE_VERSION

    # run with flags + command
    assert cv._slash_ciphervault("run --profile test --dry-run --allow-keys A,B -- pytest -q") == "ok"
    assert dispatched[-1] == (
        "ciphervault_run",
        {"profile": "test", "dry_run": True, "allow_keys": ["A", "B"], "command": ["pytest", "-q"]},
    )
    assert "Usage:" in cv._slash_ciphervault("run")

    # redact preserves text payload
    assert cv._slash_ciphervault("redact Bearer token-abc-123") == "ok"
    assert dispatched[-1] == ("ciphervault_redact", {"text": "Bearer token-abc-123"})
    assert "Usage:" in cv._slash_ciphervault("redact")

    # drill supports positional kit path, --shares, and --via
    assert cv._slash_ciphervault("drill /tmp/recovery.kit --via https://op1.cipherv.online") == "ok"
    assert dispatched[-1] == (
        "ciphervault_recovery_drill",
        {"kit": "/tmp/recovery.kit", "via": ["https://op1.cipherv.online"]},
    )
    assert cv._slash_ciphervault("drill --shares s1.txt s2.txt") == "ok"
    assert dispatched[-1] == ("ciphervault_recovery_drill", {"shares": ["s1.txt", "s2.txt"]})
    assert "Usage:" in cv._slash_ciphervault("drill")


def test_session_start_and_pre_llm_call_ambient_posture_and_audit_session_id(ctx, tmp_path, monkeypatch):
    non_vault = tmp_path / "plain"
    non_vault.mkdir()
    vault = _marker_vault(tmp_path / "proj")
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[vault]\nsealed_mode = true\n[profiles.test]\nno_net = true\n',
        encoding="utf-8",
    )

    try:
        cv.on_session_start(session_id="sess-turn1-xyz", platform="desktop")
        # Non-vault cwd returns None
        assert cv.pre_llm_call(cwd=str(non_vault), session_id="sess-turn1-xyz") is None

        # Turn 1 inside a vault injects 1-line workspace posture
        first = cv.pre_llm_call(cwd=str(vault), session_id="sess-turn1-xyz")
        assert isinstance(first, dict) and "context" in first
        assert "vault=present" in first["context"]
        assert "sealed_mode=True" in first["context"]
        assert "['test']" in first["context"]

        # Turn 2 with unchanged workspace state returns None (cached)
        assert cv.pre_llm_call(cwd=str(vault), session_id="sess-turn1-xyz") is None

        # State change (pending prompt queued) invalidates cache and re-injects posture
        (vault / ".ciphervault" / "pending_secret_prompts.json").write_text(
            json.dumps({"keys": [{"name": "OPENAI_API_KEY"}]}),
            encoding="utf-8",
        )
        changed = cv.pre_llm_call(cwd=str(vault), session_id="sess-turn1-xyz")
        assert changed and "OPENAI_API_KEY" in changed["context"]
        assert cv.pre_llm_call(cwd=str(vault), session_id="sess-turn1-xyz") is None

        # New session resets posture cache and updates audit session_id
        cv.on_session_start(session_id="sess-new-456", platform="cli")
        again = cv.pre_llm_call(cwd=str(vault), session_id="sess-new-456")
        assert again and "vault=present" in again["context"]

        calls = _capture_audit(monkeypatch)
        assert cv._audit("ciphervault_status", "ok", detail={"k": 1}, cwd=str(vault)) is True
        rec = [c for c in calls if c[:2] == ["agent-log", "record"]][-1]
        detail = json.loads(rec[rec.index("--detail") + 1])
        assert detail["session_id"] == "sess-new-456"
    finally:
        cv.on_session_start()


def test_dashboard_explorer_validates_requests_and_limits_chain_projection(tmp_path, monkeypatch):
    import importlib.util
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location("cv_plugin_explorer", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    cid = "ab" * 32
    paths = []

    def public(path):
        paths.append(path)
        if path == "/api/explorer/overview":
            return {"operators": {"total": 2, "reachable": 1}, "anchors": {"count": 0}}
        if path == "/api/operators":
            return [{"operator_id": "op1", "private_field": "ignored"}]
        if path == "/api/explorer/object/" + cid:
            return {"cid": cid, "quorum": {"required": 3}, "replicas": [{"status": "present", "object_bytes": "ignored"}]}
        raise OSError("fixture outage")

    monkeypatch.setattr(api, "_read_public_explorer", public)
    assert api._public_explorer_object("../bad")["state"] == "invalid"
    assert not paths
    assert api._public_explorer_object("0x" + cid.upper())["replicas"] == [{"status": "present"}]
    view = api._public_explorer_overview()
    assert view["state"] == "ready"
    assert view["operators"] == [{"operator_id": "op1"}]
    assert view["anchors_available"] is False

    commands = []
    monkeypatch.setattr(api, "_find_binary", lambda: "fixture-cli")

    def cli(args, **_kwargs):
        commands.append(args)
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "state": "ready", "solo": True, "blocks": [],
            "detail": {"block": {"height": 5, "salt": "ignored"}, "salt": "ignored", "commitments": [cid]},
        }))

    monkeypatch.setattr(api.subprocess, "run", cli)
    assert api._local_chain_explorer(str(tmp_path), "--help")["state"] == "invalid"
    assert not commands
    chain = api._local_chain_explorer(str(tmp_path), "#5")
    assert chain["detail"]["block"] == {"height": 5}
    assert chain["detail"]["commitments"] == [cid]
    assert "salt" not in chain["detail"]
    assert commands == [["fixture-cli", "chain-explorer", "--query", "#5"]]


def test_dashboard_plugin_api_shares_binary_resolver_status_profiles_and_generate(tmp_path, monkeypatch):
    import importlib.util as _ilu
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    api_spec = _ilu.spec_from_file_location("cv_plugin_api_v071", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    api = _ilu.module_from_spec(api_spec)
    api_spec.loader.exec_module(api)

    # Deduplication: shares _minimal_env directly with plugin package
    assert api._minimal_env is cv._minimal_env

    # Binary resolution respects ctx `binary_path` config and NEVER falls back to bare `cv`
    fake_bin = tmp_path / "custom-ciphervault"
    fake_bin.write_bytes(b"#!/bin/sh\n")

    class CfgCtx(FakeCtx):
        def get_config(self, key, default=None):
            return str(fake_bin) if key == "binary_path" else default

    prev_ctx = cv._ctx["ctx"]
    try:
        cv._ctx["ctx"] = CfgCtx()
        assert api._find_binary() == str(fake_bin)
        cv._ctx["ctx"] = None
        monkeypatch.delenv("CIPHERVAULT_BIN", raising=False)
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "empty-hermes"))
        which_queries = []
        monkeypatch.setattr(cv.shutil, "which", lambda name: (which_queries.append(name), None)[1])
        # Point repo checkout check away by testing find_binary does not query "cv"
        api._find_binary()
        assert "cv" not in which_queries
    finally:
        cv._ctx["ctx"] = prev_ctx

    # GET /status includes policy_profiles matching desktop contract
    vault = _marker_vault(tmp_path / "vault")
    (vault / ".ciphervault" / "policy.toml").write_text(
        '[vault]\nsealed_mode = true\n\n'
        '[profiles.test]\n'
        'description = "Offline unit tests"\n'
        'commands = ["pytest", "python"]\n'
        'allow_keys = ["DATABASE_URL", "TEST_*"]\n'
        'require_keys = ["DATABASE_URL"]\n'
        'no_net = true\n\n'
        '[profiles.llm_eval]\n'
        'description = "Proxy eval"\n'
        'allow_keys = ["OPENAI_API_KEY"]\n'
        'proxy = true\n'
        'upstreams = { OPENAI_API_KEY = "https://gw.example.com" }\n',
        encoding="utf-8",
    )
    (vault / ".ciphervault" / "pending_secret_prompts.json").write_text(
        json.dumps({"keys": [{"name": "SESSION_SECRET"}], "env_file": ".env", "seal": True}),
        encoding="utf-8",
    )

    monkeypatch.setattr(api, "_find_binary", lambda: "/bin/ciphervault")

    class FakeProc:
        def __init__(self, stdout, returncode=0, stderr=""):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    native_calls = []

    def fake_native_run(argv, **kwargs):
        native_calls.append(argv)
        if argv[1:4] == ["vault", "generate", "--help"]:
            return FakeProc("Usage: ciphervault vault generate --overwrite --seal --json")
        if argv[1:3] == ["vault", "generate"]:
            return FakeProc(json.dumps({
                "success": True,
                "name": argv[3],
                "format": "base64url",
                "length_chars": 43,
                "sha256_prefix": "1234abcd",
                "env_file": ".env",
                "sealed": True,
                "snapshot_head": "feedface" * 8,
            }))
        if argv[1] == "status":
            return FakeProc(json.dumps({
                "vault": True,
                "cli_version": "1.0.36",
                "tracked_paths": [".env"],
                "tracked_files": 1,
                "working_tree_sealed": True,
                "working_tree_plaintext_files": 0,
                "operators": [],
            }))
        return FakeProc("{}")

    monkeypatch.setattr(api.subprocess, "run", fake_native_run)
    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)

    st = client.get("/status", params={"cwd": str(vault)}).json()
    assert st["vault"] is True
    assert len(st["policy_profiles"]) == 2
    by_name = {p["name"]: p for p in st["policy_profiles"]}
    assert by_name["test"] == {
        "name": "test",
        "description": "Offline unit tests",
        "commands": ["pytest", "python"],
        "allow_keys": ["DATABASE_URL", "TEST_*"],
        "allow_keys_count": 2,
        "require_keys": ["DATABASE_URL"],
        "no_net": True,
        "proxy": False,
        "upstreams": [],
    }
    assert by_name["llm_eval"]["proxy"] is True
    assert by_name["llm_eval"]["upstreams"] == ["OPENAI_API_KEY=https://gw.example.com"]

    # POST /generate uses native `vault generate`, clears pending prompt, never touches disk
    gen = client.post(
        "/generate",
        params={"cwd": str(vault)},
        json={"name": "SESSION_SECRET", "format": "base64url", "bytes": 32, "env_file": ".env", "seal": True},
    ).json()
    assert gen["success"] is True
    assert gen["name"] == "SESSION_SECRET"
    assert gen["length_chars"] == 43
    assert gen["sha256_prefix"] == "1234abcd"
    assert gen["sealed"] is True
    assert gen["snapshot_head"] == "feedface" * 8
    assert isinstance(gen["status"], dict) and gen["status"]["vault"] is True
    assert not (vault / ".env").exists()
    gen_cmd = [c for c in native_calls if c[1:3] == ["vault", "generate"] and "--help" not in c][0]
    assert gen_cmd == [
        "/bin/ciphervault", "vault", "generate", "SESSION_SECRET",
        "--format", "base64url", "--bytes", "32", "--env-file", ".env", "--json", "--seal",
    ]
    assert client.get("/pending-prompts", params={"cwd": str(vault)}).json()["keys"] == []

    # Legacy CLI on a SEALED vault MUST fail closed for BOTH POST /set and POST /generate
    def fake_legacy_sealed(argv, **kwargs):
        if argv[1:4] == ["vault", "generate", "--help"]:
            return FakeProc("", returncode=2, stderr="unrecognized subcommand")
        if argv[1] == "status":
            return FakeProc(json.dumps({
                "vault": True,
                "working_tree_sealed": True,
                "tracked_paths": [".env"],
            }))
        raise AssertionError(f"legacy sealed vault must not run {argv}")

    monkeypatch.setattr(api.subprocess, "run", fake_legacy_sealed)
    set_blk = client.post(
        "/set",
        params={"cwd": str(vault)},
        json={"key": "OPENAI_API_KEY", "value": "sk-never-write", "env_file": ".env", "seal": True},
    ).json()
    assert set_blk["success"] is False and "sealed" in set_blk["error"].lower()
    assert "sk-never-write" not in json.dumps(set_blk)
    assert not (vault / ".env").exists()

    gen_blk = client.post(
        "/generate",
        params={"cwd": str(vault)},
        json={"name": "ANOTHER_SECRET", "env_file": ".env", "seal": True},
    ).json()
    assert gen_blk["success"] is False and "sealed" in gen_blk["error"].lower()
    assert not (vault / ".env").exists()

    # Invalid POST /generate inputs rejected cleanly
    assert client.post("/generate", params={"cwd": str(vault)}, json={"name": "123BAD"}).json()["success"] is False
    assert client.post("/generate", params={"cwd": str(vault)}, json={"name": "OK_KEY", "bytes": 8}).json()["success"] is False
    assert client.post("/generate", params={"cwd": str(vault)}, json={"name": "OK_KEY", "env_file": "../x"}).json()["success"] is False

    # Invalid policy.toml surfaces policy_error with empty policy_profiles
    (vault / ".ciphervault" / "policy.toml").write_text("[bad_section]\nx = 1\n", encoding="utf-8")
    st_bad_pol = client.get("/status", params={"cwd": str(vault)}).json()
    assert st_bad_pol["policy_profiles"] == []
    assert "policy_error" in st_bad_pol


