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
        "ciphervault_audit",
    }


def test_hooks_middleware_source_commands_registered(ctx):
    assert set(ctx.hooks) == {"pre_tool_call", "transform_tool_result", "post_tool_call"}
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
    (["https://op1.example.test", "https://op2.example.test"],
     ["https://op1.example.test", "https://op2.example.test"]),
    ("https://op1.example.test", ["https://op1.example.test"]),
])
def test_drill_queries_the_current_fleet_with_via(ctx, monkeypatch, via, expected):
    # A kit keeps the operators from when it was printed; a vault that
    # moved fleets must be drillable through its current operators.
    seen = []

    def fake_run_cli(args, cwd, timeout=300):
        seen.append(list(args))
        return {"success": True, "binary": "test"}

    monkeypatch.setattr(cv, "_run_cli", fake_run_cli)
    out = json.loads(ctx.tools["ciphervault_recovery_drill"][1]({"kit": "kit.txt", "via": via}))
    assert out["success"] is True
    args = seen[0]
    start = args.index("--via") + 1
    assert args[start:start + len(expected)] == expected


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
    monkeypatch.setattr(cv, "_vault_present", lambda cwd: True)
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0, True))
    _capture_audit(monkeypatch)
    out = cv.on_transform_tool_result("terminal", {}, "A" * 300_000)
    assert out is not None and len(out) < 300_000 and "truncated" in out


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
    # v1.0.33 ships redact --json's exact_values_complete attestation.
    assert cv.RELEASE_VERSION == "1.0.33"
    assert cv.RELEASE_SUPPORTS_GUARD is True
    assert cv.RELEASE_BASE.endswith("/v1.0.33")
    for name, (asset, sha) in cv.RELEASE_ASSETS.items():
        assert asset and len(sha) == 64 and int(sha, 16) >= 0, name
    assert "windows-amd64" in cv.RELEASE_ASSETS


def test_every_supported_platform_has_a_pinned_v1033_asset():
    # v1.0.33 publishes Windows x64, Linux x64, and macOS arm64/Intel CLIs.
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
