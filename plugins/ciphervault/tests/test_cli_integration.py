"""Opt-in real CLI roundtrips in disposable fake-data vaults.

Set CV_TEST_BINARY to a native executable path. No active Hermes install
is modified, no remote fleet is contacted, and init output is discarded.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from test_plugin import cv


@pytest.fixture()
def real_cli(monkeypatch):
    configured = os.environ.get("CV_TEST_BINARY")
    if not configured:
        pytest.skip("set CV_TEST_BINARY to exercise a real compatible CLI")
    binary = Path(configured).resolve()
    assert binary.is_file(), "CV_TEST_BINARY must point to an existing executable"
    monkeypatch.setattr(cv, "find_binary", lambda: (str(binary), "integration test"))
    return str(binary)


def test_real_binary_diagnostics_require_wrapped_capabilities(real_cli, tmp_path):
    report = cv.binary_diagnostics(str(tmp_path))
    assert report["installed_version"], "resolved CLI must report its actual version"
    assert report["success"], (
        "incompatible CLI: " + str(report["installed_version"])
        + "; missing capabilities: " + ", ".join(report["missing_capabilities"])
    )


@pytest.fixture()
def real_vault(real_cli, tmp_path, monkeypatch):
    monkeypatch.setattr(cv.tempfile, "tempdir", str(tmp_path))
    root = Path(tempfile.mkdtemp(prefix="fixture-vault-", dir=tmp_path))
    try:
        kit = root / "recovery-kit.txt"
        # init prints a real recovery kit: discard both streams.
        proc = subprocess.run(
            [real_cli, "init", "--save-kit", str(kit), "--operators", "http://127.0.0.1:1"],
            cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=30, env=cv._minimal_env(),
        )
        assert proc.returncode == 0, "fixture initialization failed (output withheld)"
        fake_value = "obviously-fake-integration-fixture-value"
        (root / ".env").write_text("DEMO_VALUE=" + fake_value + chr(10), encoding="utf-8")
        tracked = cv._run_cli(["track", ".env"], str(root))
        assert tracked["success"], "fixture tracking failed"
        yield root, kit, fake_value
    finally:
        # Remove the generated kit, store, and fake plaintext immediately.
        shutil.rmtree(root)


def test_real_handlers_scrub_receipt_run_and_failed_recovery_cleanup(real_vault, monkeypatch):
    root, kit, fake_value = real_vault
    cwd = str(root)
    status = json.loads(cv._tool_status({"cwd": cwd}))
    assert status["success"] and status["data"]["vault"] is True
    assert ".env" in status["data"]["tracked_paths"]

    redacted = json.loads(cv._tool_redact({"cwd": cwd, "text": "fixture: " + fake_value}))
    assert redacted["success"] and redacted["exact_value_check"] is True
    assert fake_value not in redacted["text"]
    assert redacted["redactions"] > 0

    pushed = json.loads(cv._tool_push({"cwd": cwd, "local_only": True, "message": "fixture"}))
    assert pushed["success"], "local fake-data snapshot failed"
    ran = json.loads(cv._tool_run({"cwd": cwd, "command": [
        sys.executable, "-c", "import os; print(os.environ['DEMO_VALUE'])",
    ]}))
    assert ran["success"], "fake-data command failed"
    assert fake_value not in ran["data"]["stdout"]
    assert ran["data"]["redactions"] > 0

    failed_run = json.loads(cv._tool_run({"cwd": cwd, "command": [
        sys.executable, "-c", "print('fake child progress'); raise SystemExit(7)",
    ]}))
    assert failed_run["success"] is False, "nonzero child exit must not become tool success"

    original = "fixture: " + fake_value + chr(10) + "LF" + chr(13) + chr(10) + "CRLF"
    transformed = cv.on_transform_tool_result("terminal", {"cwd": cwd}, original)
    assert transformed and "withheld" not in transformed
    assert fake_value not in transformed
    assert chr(10) + "LF" + chr(13) + chr(10) + "CRLF" in transformed
    audit = json.loads(cv._tool_audit({"cwd": cwd, "check_text": transformed}))
    assert audit["success"] and audit["verification"]["ok"] is True
    assert audit["check"]["found"] is True
    absent = json.loads(cv._tool_audit({"cwd": cwd, "check_text": "never emitted fixture output"}))
    assert absent["success"] and absent["check"]["found"] is False

    # A local snapshot has no operator recovery records. It must fail
    # honestly while deleting the tool-owned plaintext staging directory.
    created = []
    original_mkdtemp = cv.tempfile.mkdtemp

    def record_drill_dir(*args, **kwargs):
        path = original_mkdtemp(*args, **kwargs)
        created.append(Path(path))
        return path

    monkeypatch.setattr(cv.tempfile, "mkdtemp", record_drill_dir)
    drilled = json.loads(cv._tool_drill({"cwd": cwd, "kit": str(kit)}))
    assert drilled["success"] is False
    assert len(created) == 1
    assert not created[0].exists(), "failed recovery must remove its staging directory"


def test_real_audit_rejects_tampered_entry(real_vault):
    root, _kit, _fake_value = real_vault
    cwd = str(root)
    assert cv._audit("fixture", "executed", cwd=cwd)
    before = json.loads(cv._tool_audit({"cwd": cwd}))
    assert before["success"] and before["verification"]["ok"] is True
    db = sqlite3.connect(root / ".ciphervault" / "vault.db")
    try:
        # Forge metadata only, in this disposable fixture's log.
        db.execute("UPDATE agent_audit SET decision = ? WHERE id = ?", ("forged-fixture", 1))
        db.commit()
    finally:
        db.close()
    after = json.loads(cv._tool_audit({"cwd": cwd, "check_text": "fake output"}))
    assert after["success"] is False
    assert "check" not in after, "a tampered chain cannot prove an output hash"


def _assert_incomplete_redact_withholds(real_cli, root, fake_value, monkeypatch):
    cwd = str(root)
    for flags in (["--json"], []):
        proc = subprocess.run(
            [real_cli, "redact", *flags], cwd=root, input=fake_value.encode("utf-8"),
            capture_output=True, timeout=30, env=cv._minimal_env(),
        )
        assert proc.returncode != 0, "incomplete loading must fail, not return success"
        assert not bool(proc.stdout), "failed redaction must not release any stdout"
        assert fake_value.encode("utf-8") not in proc.stderr

    redacted = json.loads(cv._tool_redact({"cwd": cwd, "text": fake_value}))
    assert redacted["success"] is False
    assert fake_value not in json.dumps(redacted)

    decisions = []
    original_audit = cv._audit

    def record_decision(tool, decision, **kwargs):
        decisions.append(decision)
        return original_audit(tool, decision, **kwargs)

    monkeypatch.setattr(cv, "_audit", record_decision)
    transformed = cv.on_transform_tool_result("terminal", {"cwd": cwd}, fake_value)
    assert transformed and "withheld" in transformed
    assert fake_value not in transformed
    assert "scrubbed_result" not in decisions, "incomplete scrub must never get a receipt"


@pytest.mark.parametrize("fault", [
    "deleted_tracked_file", "tracked_path_is_directory", "corrupt_store",
    "store_open_failure", "tracked_list_failure",
])
def test_real_redact_loading_failure_never_releases_output(real_cli, real_vault, monkeypatch, fault):
    root, _kit, fake_value = real_vault
    db = root / ".ciphervault" / "vault.db"
    if fault == "deleted_tracked_file":
        (root / ".env").unlink()
    elif fault == "tracked_path_is_directory":
        (root / ".env").unlink()
        (root / ".env").mkdir()
    elif fault == "corrupt_store":
        db.write_bytes(b"not a SQLite database: disposable fixture")
    elif fault == "store_open_failure":
        db.unlink()
        db.mkdir()
    elif fault == "tracked_list_failure":
        # Keep a valid store, but inject a typed row-decode error in the
        # tracked-file listing. This is deterministic on Windows and Unix.
        connection = sqlite3.connect(db)
        try:
            connection.execute("UPDATE tracked_files SET file_id = 1")
            connection.commit()
        finally:
            connection.close()
    _assert_incomplete_redact_withholds(real_cli, root, fake_value, monkeypatch)


def test_real_redact_unreadable_tracked_file_never_releases_output(real_cli, real_vault, monkeypatch):
    root, _kit, fake_value = real_vault
    path = root / ".env"
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        create_file.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        # A no-sharing handle makes the *real* read fail, unlike chmod
        # which does not remove read permission on Windows.
        handle = create_file(str(path), 0x80000000, 0, None, 3, 0x80, None)
        assert handle not in (None, wintypes.HANDLE(-1).value), "fixture lock failed"
        try:
            _assert_incomplete_redact_withholds(real_cli, root, fake_value, monkeypatch)
        finally:
            kernel32.CloseHandle(handle)
    else:
        if os.geteuid() == 0:
            pytest.skip("root bypasses file read permissions; directory-read failure is tested separately")
        mode = path.stat().st_mode
        path.chmod(0)
        try:
            _assert_incomplete_redact_withholds(real_cli, root, fake_value, monkeypatch)
        finally:
            path.chmod(mode)


def test_real_redact_reports_complete_loaded_vault(real_vault):
    root, _kit, fake_value = real_vault
    response = cv._run_cli_json(["redact", "--json"], str(root), input_text=fake_value)
    assert response["success"] is True
    data = response["data"]
    assert data["vault"] is True
    assert data.get("exact_values_complete") is True
    assert data["exact_values_loaded"] > 0
    assert fake_value not in data["text"]


def test_real_redact_reports_complete_without_vault(real_cli, tmp_path):
    response = cv._run_cli_json(["redact", "--json"], str(tmp_path), input_text="plain fixture output")
    assert response["success"] is True
    data = response["data"]
    assert data["vault"] is False
    assert data.get("exact_values_complete") is True
    assert data["exact_values_loaded"] == 0
    assert data["text"] == "plain fixture output"


def test_real_redact_treats_install_dir_layout_as_vaultless(real_cli, tmp_path):
    # ~/.ciphervault/bin (installer layout) has no store: not a vault.
    (tmp_path / ".ciphervault" / "bin").mkdir(parents=True)
    response = cv._run_cli_json(["redact", "--json"], str(tmp_path), input_text="plain fixture output")
    assert response["success"] is True
    assert response["data"]["vault"] is False
    assert response["data"].get("exact_values_complete") is True


def test_real_subdirectory_output_is_scrubbed_and_receipted_at_root(real_vault):
    root, _kit, fake_value = real_vault
    child = root / "apps" / "web"
    child.mkdir(parents=True)
    transformed = cv.on_transform_tool_result("terminal", {"workdir": str(child)},
                                              "fixture: " + fake_value)
    assert transformed and "withheld" not in transformed
    assert fake_value not in transformed
    audit = json.loads(cv._tool_audit({"cwd": str(root), "check_text": transformed}))
    assert audit["success"] and audit["check"]["found"] is True


def test_real_sealed_vault_generate_preserves_existing_keys(real_vault):
    root, _kit, fake_value = real_vault
    cwd = str(root)
    cv._VAULT_SECRET_SUPPORT_CACHE.clear()
    if not cv._cli_supports_vault_secret(cwd):
        pytest.skip("resolved CLI does not ship native `ciphervault vault generate` yet")

    pushed = json.loads(cv._tool_push({
        "cwd": cwd,
        "local_only": True,
        "shred_working_copy": True,
        "message": "seal before generate",
    }))
    assert pushed["success"] is True
    assert not (root / ".env").exists(), "working tree must be sealed before generate"

    gen1 = json.loads(cv._tool_secret_generate({
        "cwd": cwd,
        "name": "GENERATED_TOKEN",
        "format": "base64url",
        "bytes": 32,
        "seal": True,
    }))
    assert gen1["success"] is True, gen1
    assert gen1["sealed"] is True
    assert len(gen1["sha256_prefix"]) == 8
    assert not (root / ".env").exists(), "native vault generate must keep working tree sealed"

    # Both the original sealed DEMO_VALUE and the newly generated GENERATED_TOKEN must exist.
    dry = json.loads(cv._tool_run({"cwd": cwd, "dry_run": True, "command": ["echo", "ok"]}))
    assert dry["success"] is True, dry
    names = {item["name"] for item in dry["data"].get("secrets") or [] if isinstance(item, dict)}
    assert {"DEMO_VALUE", "GENERATED_TOKEN"} <= names, names
    assert fake_value not in json.dumps(dry)

    # Default overwrite=False refuses to clobber an existing key.
    dup = json.loads(cv._tool_secret_generate({
        "cwd": cwd,
        "name": "GENERATED_TOKEN",
        "seal": True,
    }))
    assert dup["success"] is False

    # Explicit overwrite=True requires approval in pre_tool_call and rotates the key.
    appr = cv.on_pre_tool_call("ciphervault_secret_generate", {
        "cwd": cwd,
        "name": "GENERATED_TOKEN",
        "overwrite": True,
    })
    assert appr and appr["action"] == "approve"
    gen2 = json.loads(cv._tool_secret_generate({
        "cwd": cwd,
        "name": "GENERATED_TOKEN",
        "overwrite": True,
        "seal": True,
    }))
    assert gen2["success"] is True, gen2
    assert gen2["sha256_prefix"] != gen1["sha256_prefix"]


def test_real_wildcard_profile_run_injects_optional_matching_keys(real_vault):
    root, _kit, fake_value = real_vault
    cwd = str(root)
    cv._CLI_PROFILE_SUPPORT.clear()
    if not cv._cli_supports_run_profile():
        pytest.skip("resolved CLI does not support `run --profile`")

    pushed = json.loads(cv._tool_push({"cwd": cwd, "local_only": True, "message": "profile fixture"}))
    assert pushed["success"] is True

    python_name = Path(sys.executable).name
    (root / ".ciphervault" / "policy.toml").write_text(
        "[vault]\n"
        "sealed_mode = false\n\n"
        "[profiles.wildtest]\n"
        'description = "Wildcard + optional keys test"\n'
        f"commands = [{json.dumps(python_name)}, {json.dumps(sys.executable)}]\n"
        'allow_keys = ["DEMO_*", "OPTIONAL_ABSENT_KEY"]\n'
        "no_net = true\n",
        encoding="utf-8",
    )
    ran = json.loads(cv._tool_run({
        "cwd": cwd,
        "profile": "wildtest",
        "command": [
            sys.executable,
            "-c",
            "import os; print('HAS_DEMO=' + str('DEMO_VALUE' in os.environ), 'VAL=' + os.environ['DEMO_VALUE'])",
        ],
    }))
    assert ran["success"] is True, ran
    assert "HAS_DEMO=True" in ran["data"]["stdout"]
    assert fake_value not in ran["data"]["stdout"]

