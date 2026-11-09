"""Tests for the CipherVault Hermes plugin.

Fast unit tests use a fake ctx and (mostly) a fake CLI on PATH; the
scrub/guard contracts are the security-critical parts, so they get the
most coverage. Set CV_TEST_BINARY to also run against a real CLI.
"""

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
    "Bearer abcdefghijklmnop",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG",
    "DATABASE_URL=postgres://user:hunter2@db.internal/app",
    "token cvst1.eyJhbGciOiJIUzI1NiJ9.payload.sig here",
    "API_KEY=supersecretvalue123",
    "password: hunter2hunter2",
])
def test_scrub_redacts(raw):
    out = cv.scrub(raw)
    for leaked in ("abcdefghijklmnop", "wJalr", "hunter2", "supersecretvalue123", "eyJhbGciOiJIUzI1NiJ9"):
        assert leaked not in out


def test_scrub_passes_clean_text():
    assert cv.scrub("snapshot 9f2c head replicated") == "snapshot 9f2c head replicated"


def test_scrub_is_not_quadratic_on_long_tokens():
    import time
    for payload in ("a" * 256_000, "x" * 200_000 + "secret", "word " * 40_000):
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
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0))
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
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (cv.scrub(text), 2))
    calls = _capture_audit(monkeypatch)
    out = cv.on_transform_tool_result("terminal", {}, "leak: Bearer abcdefghijklmnop")
    assert out is not None
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "scrubbed_result" in rec[0]
    import hashlib as _hl
    detail = json.loads(rec[0][rec[0].index("--detail") + 1])
    assert detail["output_sha256"] == _hl.sha256(out.encode()).hexdigest()
    assert detail["redactions"] == 2


def test_post_tool_call_logs_writes(ctx, monkeypatch):
    calls = _capture_audit(monkeypatch)
    cv.on_post_tool_call("write_file", {"path": "src/app.py"}, "ok")
    rec = [c for c in calls if c[:2] == ["agent-log", "record"]]
    assert rec and "executed" in rec[0]
    calls.clear()
    cv.on_post_tool_call("read_file", {"path": "README.md"}, "ok")
    assert not [c for c in calls if c[:2] == ["agent-log", "record"]]


# ------------------------------------------------------------ guard

def test_guard_blocks_terminal_cat_env(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0))
    out = cv.on_pre_tool_call("terminal", {"command": "cat .env"})
    assert out and out["action"] == "block"


def test_guard_blocks_read_file_on_key(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0))
    out = cv.on_pre_tool_call("read_file", {"path": "/proj/id_ed25519"})
    assert out and out["action"] == "block"


def test_guard_blocks_secret_shaped_payload(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (cv.scrub(text), 1))
    out = cv.on_pre_tool_call("write_file", {"path": "notes.txt", "content": "API_KEY=supersecretvalue123"})
    assert out and out["action"] == "block"


def test_guard_allows_clean_terminal(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0))
    assert cv.on_pre_tool_call("terminal", {"command": "git status"}) is None


def test_guard_gates_ciphervault_run_with_approval(ctx):
    out = cv.on_pre_tool_call("ciphervault_run", {"command": ["echo", "hi"]})
    assert out and out["action"] == "approve" and out.get("rule_key") == "ciphervault_run:echo"
    out = cv.on_pre_tool_call("ciphervault_run", {"command": ["echo", "hi"], "dry_run": True})
    assert out and out["action"] == "approve"


def test_guard_never_blocks_other_ciphervault_tools(ctx):
    assert cv.on_pre_tool_call("ciphervault_status", {}) is None
    assert cv.on_pre_tool_call("ciphervault_redact", {"text": "API_KEY=x"}) is None


def test_transform_scrubs_other_results(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (cv.scrub(text), 1))
    out = cv.on_transform_tool_result("terminal", {}, "leak: Bearer abcdefghijklmnop")
    assert out is not None and "abcdefghijklmnop" not in out


def test_transform_leaves_clean_and_own_results(ctx, monkeypatch):
    monkeypatch.setattr(cv, "cli_redact", lambda text, cwd, timeout=10: (text, 0))
    assert cv.on_transform_tool_result("terminal", {}, "all good") is None
    assert cv.on_transform_tool_result("ciphervault_run", {}, "Bearer abcdefghijklmnop") is None


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


def test_secret_source_fetch_missing_binary(ctx, monkeypatch):
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    result = ctx.secret_source.fetch({"enabled": True}, Path("."))
    assert result.error and not result.secrets


# ------------------------------------------------------------ fake CLI

FAKE_CLI = r"""
import json, sys
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("ciphervault 1.0.31"); raise SystemExit(0)
if args[:2] == ["status", "--json"]:
    print(json.dumps({"vault": True, "cli_version": "1.0.31", "tracked_paths": [".env"],
                      "vault_id_short": "abcd1234", "active_head_short": "beef5678",
                      "tracked_files": 1, "operators": []})); raise SystemExit(0)
if args[:2] == ["redact", "--json"]:
    text = sys.stdin.read()
    print(json.dumps({"text": text.replace("test_value_123456", "[REDACTED:API_KEY]"),
                      "redactions": text.count("test_value_123456"),
                      "exact_values_loaded": 1, "vault": True})); raise SystemExit(0)
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
        exe.write_text("#!/bin/sh\nexec python3 - \"$@\" <<'EOF'\n" + FAKE_CLI + "\nEOF\n")
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
