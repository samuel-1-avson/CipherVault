"""Snapshot history (`ciphervault_status` history_limit) and the read-only
`ciphervault_restore_preview` tool, against a scripted CLI.

The real-CLI versions of these checks live in test_cli_integration.py
(opt-in through CV_TEST_BINARY).
"""

import json

import pytest

from test_plugin import cv

ID_A = "a" * 64
ID_B = "b" * 64
LOGICAL_A = "1" * 64
LOGICAL_B = "2" * 64
SECRET = "obviously-fake-history-fixture-value"


def _marker_vault(root):
    # Discovery marker only; not a real vault or credential store.
    (root / ".ciphervault").mkdir(parents=True)
    (root / ".ciphervault" / "vault.db").write_bytes(b"discovery marker only")
    return root


def _history_payload(rows, total=None):
    return {
        "vault": True,
        "cli_version": "test",
        "order": "newest_first",
        "total": len(rows) if total is None else total,
        "returned": len(rows),
        "limit": 20,
        "truncated": False,
        "active_head_id": rows[0].get("snapshot_id") if rows and isinstance(rows[0], dict) else None,
        "unreadable_records": 0,
        "snapshots": rows,
    }


def _row(sid, logical, at, head=False, **extra):
    row = {
        "snapshot_id": sid,
        "logical_id": logical,
        "recorded_at_utc": at,
        "epoch": 1,
        "device_counter": 2,
        "parent_snapshot_ids": [],
        "is_active_head": head,
    }
    row.update(extra)
    return row


def _preview_payload(**overrides):
    payload = {
        "success": True,
        "dry_run": True,
        "snapshot_id": ID_A,
        "logical_id": LOGICAL_A,
        "is_active_head": False,
        "recorded_at_utc": 1_800_000_000,
        "epoch": 1,
        "destination": "workspace",
        "mode": "merge",
        "verification": {
            "status": "passed",
            "checks": list(cv.tools._PREVIEW_CHECKS),
            "checked_at_utc": 1_800_000_100,
        },
        "files": [
            {"path": ".env", "action": "replace", "bytes": 31},
            {"path": "config/app.env", "action": "create", "bytes": 12},
            {"path": "config/keep.pem", "action": "unchanged", "bytes": 64},
        ],
        "counts": {"create": 1, "replace": 1, "unchanged": 1, "total": 3},
        "uncommitted_changes": [".env"],
        "restore_requires_force": True,
        "interrupted_restore_pending": False,
    }
    payload.update(overrides)
    return payload


class ScriptedCli:
    """Records every CLI call; answers status, history and restore."""

    def __init__(self, monkeypatch, *, history=None, preview=None, preview_exit=0,
                 history_supported=True, preview_supported=True, status=None,
                 watcher=None, watcher_supported=True):
        self.calls = []
        self.history = history
        self.preview = preview
        self.preview_exit = preview_exit
        self.watcher = watcher
        self.status = status or {"vault": True, "tracked_paths": [".env"], "active_head_hex": ID_A}
        monkeypatch.setattr(cv, "_run_cli_json", self.run_json)
        monkeypatch.setattr(cv, "_run_cli", self.run)
        monkeypatch.setattr(cv, "find_binary", lambda: ("/fake/ciphervault", "test"))
        monkeypatch.setattr(cv, "_cli_supports_history_json", lambda cwd=None: history_supported)
        monkeypatch.setattr(cv, "_cli_supports_restore_preview", lambda cwd=None: preview_supported)
        monkeypatch.setattr(cv, "_cli_supports_watcher_health", lambda cwd=None: watcher_supported)

    def run_json(self, args, cwd, **kwargs):
        self.calls.append(list(args))
        if args[:2] == ["status", "--json"]:
            data = dict(self.status)
            if "--watcher" in args and self.watcher is not None:
                data["watcher_health"] = json.loads(json.dumps(self.watcher))
            return {"success": True, "data": data, "binary": "test"}
        if args[:2] == ["history", "--json"]:
            return {"success": True, "data": self.history, "binary": "test"}
        return {"success": False, "error": "unexpected call"}

    def run(self, args, cwd, timeout=120, keep_stdout_on_error=False, **kwargs):
        self.calls.append(list(args))
        if args[:1] == ["restore"]:
            out = json.dumps(self.preview)
            if self.preview_exit == 0:
                return {"success": True, "output": out, "stderr": "", "exit_code": 0, "binary": "test"}
            res = {"success": False, "error": "warning: noise on stderr", "exit_code": self.preview_exit,
                   "binary": "test"}
            if keep_stdout_on_error:
                res["stdout"] = out
            return res
        return {"success": False, "error": "unexpected call"}


def _status(params):
    return json.loads(cv._tool_status(params))


def _preview(params):
    return json.loads(cv._tool_restore_preview(params))


# ------------------------------------------------------------ status history

def test_status_without_history_limit_is_the_ordinary_response(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, history=_history_payload([]))
    out = _status({"cwd": str(vault)})
    assert out["success"] is True and out["data"]["tracked_paths"] == [".env"]
    assert "history" not in out
    assert cli.calls == [["status", "--json"]]


def test_status_history_is_bounded_newest_first_and_metadata_only(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    rows = [
        _row(ID_B, LOGICAL_B, 1_800_000_200, head=True, message=f"token={SECRET}",
             manifest={"files": [".env"]}),
        _row(ID_A, LOGICAL_A, 1_800_000_100),
        _row("c" * 64, "3" * 64, 0),
    ]
    cli = ScriptedCli(monkeypatch, history=_history_payload(rows, total=9))
    out = _status({"cwd": str(vault), "history_limit": 2})
    assert ["history", "--json", "--limit", "2"] in cli.calls
    history = out["history"]
    assert history["success"] is True
    assert [s["snapshot_id"] for s in history["snapshots"]] == [ID_B, ID_A]
    assert history["returned"] == 2 and history["total"] == 9 and history["truncated"] is True
    assert history["snapshots"][0]["is_active_head"] is True
    assert history["snapshots"][0]["recorded_at"] == "2027-01-15T08:03:20Z"
    assert set(history["snapshots"][0]) == {
        "snapshot_id", "logical_id", "recorded_at_utc", "recorded_at", "epoch", "is_active_head",
    }
    assert SECRET not in json.dumps(out)
    assert out["data"]["tracked_paths"] == [".env"], "ordinary status fields stay intact"


def test_status_history_empty_vault_says_so(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    ScriptedCli(monkeypatch, history=_history_payload([]))
    history = _status({"cwd": str(vault), "history_limit": 5})["history"]
    assert history["success"] is True and history["total"] == 0 and history["snapshots"] == []
    assert "ciphervault_push" in history["note"]


def test_status_history_without_vault_skips_the_cli(tmp_path, monkeypatch):
    cli = ScriptedCli(monkeypatch, status={"vault": False, "tracked_paths": []})
    history = _status({"cwd": str(tmp_path), "history_limit": 5})["history"]
    assert history["success"] is True and history["vault"] is False and history["snapshots"] == []
    assert not any(call[:1] == ["history"] for call in cli.calls)


def test_status_history_records_without_timestamps_stay_listed(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    ScriptedCli(monkeypatch, history=_history_payload([_row(ID_A, LOGICAL_A, 0)]))
    snap = _status({"cwd": str(vault), "history_limit": 1})["history"]["snapshots"][0]
    assert snap["recorded_at_utc"] is None and snap["recorded_at"] is None


@pytest.mark.parametrize("bad", [0, -1, 51, 10_000, True, 2.5, "ten", [3]])
def test_status_history_limit_is_validated_before_any_cli_call(tmp_path, monkeypatch, bad):
    cli = ScriptedCli(monkeypatch, history=_history_payload([]))
    out = _status({"cwd": str(tmp_path), "history_limit": bad})
    assert out["success"] is False and out["error_code"] == "invalid_argument"
    assert cli.calls == []


def test_status_history_unsupported_cli_keeps_plain_status(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, history_supported=False)
    out = _status({"cwd": str(vault), "history_limit": 3})
    assert out["success"] is True and out["data"]["vault"] is True
    assert out["history"]["success"] is False
    assert out["history"]["error_code"] == "cli_unsupported"
    assert "--json --limit" in out["history"]["error"]
    assert not any(call[:1] == ["history"] for call in cli.calls)


@pytest.mark.parametrize("rows", [
    [_row("not-hex", LOGICAL_A, 1)],
    [_row(ID_A.upper(), LOGICAL_A, 1)],
    ["just a string"],
])
def test_status_history_rejects_malformed_cli_rows(tmp_path, monkeypatch, rows):
    vault = _marker_vault(tmp_path / "v")
    ScriptedCli(monkeypatch, history=_history_payload(rows))
    history = _status({"cwd": str(vault), "history_limit": 3})["history"]
    assert history["success"] is False and history["error_code"] == "invalid_cli_response"


# ------------------------------------------------------------ restore preview

@pytest.mark.parametrize("ref", [
    None, "", "   ", "abc", "-" + "a" * 63, "a" * 63, "a" * 65, "g" * 64, "HEAD~1",
    "../" + "a" * 61, "--force", "a" * 64 + " --to /tmp", 42, ["a" * 64],
])
def test_preview_rejects_malformed_references_without_running_the_cli(tmp_path, monkeypatch, ref):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, preview=_preview_payload())
    out = _preview({"cwd": str(vault), "snapshot": ref})
    assert out["success"] is False and out["error_code"] == "invalid_snapshot_reference"
    assert out["read_only"] is True
    assert cli.calls == []


def test_preview_passes_validated_ids_directly(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, preview=_preview_payload())
    out = _preview({"cwd": str(vault / "sub"), "snapshot": "  " + ID_A.upper() + " "})
    assert out["success"] is True
    assert cli.calls == [["restore", "--dry-run", "--json", "--snapshot", ID_A]]

    cli.calls.clear()
    cli.preview = _preview_payload(is_active_head=True)
    assert _preview({"cwd": str(vault), "snapshot": "HEAD"})["success"] is True
    assert cli.calls == [["restore", "--dry-run", "--json"]]


def test_preview_reports_actions_counts_and_leaves_restore_to_the_user(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    (vault / ".env").write_text("CURRENT=1\n", encoding="utf-8")
    before = sorted((p.relative_to(vault).as_posix(), p.read_bytes()) for p in vault.rglob("*") if p.is_file())
    payload = _preview_payload()
    payload["files"][0]["plaintext"] = SECRET  # an extra field must never pass through
    payload["counts"] = {"create": 99, "replace": 0, "unchanged": 0, "total": 99}
    ScriptedCli(monkeypatch, preview=payload)
    out = _preview({"cwd": str(vault), "snapshot": ID_A})
    assert out["success"] is True and out["read_only"] is True
    assert out["snapshot_id"] == ID_A and out["logical_id"] == LOGICAL_A
    assert {f["path"]: f["action"] for f in out["files"]} == {
        ".env": "replace", "config/app.env": "create", "config/keep.pem": "unchanged",
    }
    assert out["counts"] == {"create": 1, "replace": 1, "unchanged": 1, "total": 3}
    assert out["verification"]["status"] == "passed"
    assert out["verification"]["checked_at"] == "2027-01-15T08:01:40Z"
    assert out["restore_requires_force"] is True and out["uncommitted_changes"] == [".env"]
    assert f"ciphervault restore --snapshot {ID_A} --force" in out["next"]
    assert SECRET not in json.dumps(out)
    after = sorted((p.relative_to(vault).as_posix(), p.read_bytes()) for p in vault.rglob("*") if p.is_file())
    assert after == before, "the preview tool must not write anything"


@pytest.mark.parametrize("path", [
    "../outside.env", "/etc/passwd", "\\\\server\\share\\x", "C:/Windows/x.env", "C:x.env",
    "a/../../b.env", "./.env", "a//b.env", ".env:stream", "", "a\x00b", "a\nb",
])
def test_preview_rejects_paths_that_could_leave_the_workspace(tmp_path, monkeypatch, path):
    vault = _marker_vault(tmp_path / "v")
    payload = _preview_payload()
    payload["files"].append({"path": path, "action": "create", "bytes": 1})
    ScriptedCli(monkeypatch, preview=payload)
    out = _preview({"cwd": str(vault), "snapshot": ID_A})
    assert out["success"] is False and out["error_code"] == "invalid_cli_response"
    assert "files" not in out


@pytest.mark.parametrize("override", [
    {"snapshot_id": ID_B, "logical_id": LOGICAL_B},          # different snapshot
    {"destination": "directory"},                             # not the workspace
    {"dry_run": False},
    {"verification": {"status": "passed", "checks": ["manifest"]}},
    {"verification": {"status": "failed", "checks": list(cv.tools._PREVIEW_CHECKS)}},
    {"files": [{"path": ".env", "action": "delete", "bytes": 1}]},
    {"files": "not a list"},
])
def test_preview_rejects_inconsistent_cli_reports(tmp_path, monkeypatch, override):
    vault = _marker_vault(tmp_path / "v")
    ScriptedCli(monkeypatch, preview=_preview_payload(**override))
    out = _preview({"cwd": str(vault), "snapshot": ID_A})
    assert out["success"] is False and out["error_code"] == "invalid_cli_response"


@pytest.mark.parametrize("code,check", [
    ("snapshot_not_found", None),
    ("verification_failed", "chunks_present"),
    ("verification_failed", "record_signature"),
    ("unsafe_destination", None),
    ("hardware_token_required", None),
])
def test_preview_refusals_are_structured(tmp_path, monkeypatch, code, check):
    vault = _marker_vault(tmp_path / "v")
    refusal = {"success": False, "dry_run": True, "error_code": code, "failed_check": check,
               "error": f"refused; api_key={SECRET}", "snapshot_ref": ID_A}
    ScriptedCli(monkeypatch, preview=refusal, preview_exit=3)
    out = _preview({"cwd": str(vault), "snapshot": ID_A})
    assert out["success"] is False and out["read_only"] is True
    assert out["error_code"] == code and out["failed_check"] == check
    assert out["snapshot_ref"] == ID_A and out["next"]
    assert SECRET not in json.dumps(out), "refusal text is shape-scrubbed"


def test_preview_unsupported_cli_is_a_clear_error(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, preview=_preview_payload(), preview_supported=False)
    out = _preview({"cwd": str(vault), "snapshot": ID_A})
    assert out["success"] is False and out["error_code"] == "cli_unsupported"
    assert "--dry-run --json" in out["error"] and "v1.0.38" in out["error"]
    assert cli.calls == []


def test_preview_needs_a_vault_and_a_binary(tmp_path, monkeypatch):
    cli = ScriptedCli(monkeypatch, preview=_preview_payload())
    out = _preview({"cwd": str(tmp_path), "snapshot": ID_A})
    assert out["success"] is False and out["error_code"] == "no_vault"
    vault = _marker_vault(tmp_path / "v")
    monkeypatch.setattr(cv, "find_binary", lambda: (None, "missing"))
    out = _preview({"cwd": str(vault), "snapshot": ID_A})
    assert out["success"] is False and out["error_code"] == "binary_missing"
    assert cli.calls == []


def test_preview_non_json_failure_stays_an_error(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, preview=None, preview_exit=1)
    cli.preview = None
    monkeypatch.setattr(cv, "_run_cli", lambda args, cwd, **kw: {
        "success": False, "error": "Error: something broke", "stdout": "", "exit_code": 1})
    out = _preview({"cwd": str(vault), "snapshot": ID_A})
    assert out["success"] is False and out["error_code"] == "preview_failed"


# ------------------------------------------------------------ watcher health

NOW = 1_800_000_000


def _watcher_payload(**overrides):
    payload = {
        "checked_at_utc": NOW,
        "live_check_performed": False,
        "watcher": {
            "state": "running", "evidence": "heartbeat", "reason": "Watcher heartbeat 4s ago (pid 77).",
            "heartbeat_at_utc": NOW - 4, "heartbeat_age_secs": 4, "stale_after_secs": 120,
            "started_at_utc": NOW - 600, "stopped_at_utc": None, "pid": 77,
            "sync_enabled": True, "operator_count": 3,
        },
        "last_change_detected_at_utc": NOW - 30,
        "last_capture": {"at_utc": NOW - 29, "snapshot_id": ID_B, "logical_id": LOGICAL_B,
                         "source": "watcher_status"},
        "last_error": None,
        "sync": {"pending": 1, "failed": 1, "oldest_pending_at_utc": NOW - 29,
                 "last_error": f"upload failed: token={SECRET}",
                 "last_watcher_attempt": {"at_utc": NOW - 28, "outcome": "failed", "snapshot_id": ID_B,
                                          "error": "operator unreachable", "source": "watcher_status"}},
        "remote_verification": {
            "evidence": "recorded", "live_check_performed": False,
            "verified_snapshot": {"snapshot_id": ID_A, "logical_id": LOGICAL_A, "recorded_at_utc": NOW - 3600},
            "checked_at_utc": NOW - 3500,
            "head": {"snapshot_id": ID_B, "logical_id": LOGICAL_B, "recorded_at_utc": NOW - 29},
            "head_verified": False, "newer_unverified_snapshots": 1,
            "scanned_snapshots": 2, "total_snapshots": 2,
        },
    }
    payload.update(overrides)
    return payload


def test_status_without_watcher_health_never_asks_for_it(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, watcher=_watcher_payload())
    out = _status({"cwd": str(vault)})
    assert "watcher_health" not in out and "watcher_health" not in out["data"]
    assert cli.calls == [["status", "--json"]]


def test_watcher_health_older_verified_backup_then_newer_local_capture(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, watcher=_watcher_payload())
    out = _status({"cwd": str(vault), "watcher_health": True})
    assert cli.calls == [["status", "--json", "--watcher"]]
    assert "watcher_health" not in out["data"], "the section moves out of the plain status"
    health = out["watcher_health"]
    assert health["success"] is True and health["live_check_performed"] is False
    assert health["watcher"]["state"] == "running"
    assert health["last_capture"]["snapshot_id"] == ID_B
    remote = health["remote_verification"]
    assert remote["verified_snapshot"]["snapshot_id"] == ID_A
    assert remote["head"]["snapshot_id"] == ID_B and remote["head_verified"] is False
    assert remote["evidence"] == "recorded" and remote["live_check_performed"] is False
    summary = " ".join(health["summary"])
    assert "Watcher running" in summary
    assert f"Last capture: snapshot {ID_B[:12]}" in summary
    assert f"Remote backup verified for snapshot {ID_A[:12]}" in summary
    assert "not a live check" in summary
    assert f"current head {ID_B[:12]} has no recorded remote verification" in summary
    assert "1 pending, 1 failed" in summary
    assert SECRET not in json.dumps(out), "operator error text is shape-scrubbed"


def test_watcher_health_stale_and_missing_evidence_is_unknown(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    stale = _watcher_payload(
        watcher={"state": "unknown", "evidence": "stale_heartbeat",
                 "reason": "Watcher state unknown: last heartbeat 3600s ago, older than 120s.",
                 "heartbeat_at_utc": NOW - 3600, "heartbeat_age_secs": 3600, "pid": 77},
        last_change_detected_at_utc=NOW - 10,
        last_capture={"at_utc": NOW - 3700, "snapshot_id": ID_A, "logical_id": LOGICAL_A,
                      "source": "watcher_status"},
    )
    ScriptedCli(monkeypatch, watcher=stale)
    health = _status({"cwd": str(vault), "watcher_health": True})["watcher_health"]
    assert health["watcher"]["state"] == "unknown" and health["watcher"]["evidence"] == "stale_heartbeat"
    summary = " ".join(health["summary"])
    assert "Watcher running" not in summary
    assert "last heartbeat 3600s ago" in summary
    assert "is newer than the last capture, so it is not in a snapshot yet" in summary


@pytest.mark.parametrize("raw,code", [
    (None, "watcher_health_unavailable"),
    ({"error": f"database is locked; password={SECRET}"}, "watcher_health_unavailable"),
    ("garbage", "watcher_health_unavailable"),
])
def test_watcher_health_unavailable_data_is_a_typed_error(tmp_path, monkeypatch, raw, code):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, watcher=raw)
    cli.watcher = raw
    out = _status({"cwd": str(vault), "watcher_health": True})
    assert out["success"] is True and out["data"]["vault"] is True
    assert out["watcher_health"]["success"] is False
    assert out["watcher_health"]["error_code"] == code
    assert SECRET not in json.dumps(out)


def test_watcher_health_untyped_fields_never_pass_through(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    odd = _watcher_payload()
    odd["watcher"]["state"] = "definitely-running"
    odd["watcher"]["evidence"] = "trust me"
    odd["last_capture"]["snapshot_id"] = "not-an-id"
    odd["last_capture"]["plaintext"] = SECRET
    odd["remote_verification"]["live_check_performed"] = "yes"
    ScriptedCli(monkeypatch, watcher=odd)
    health = _status({"cwd": str(vault), "watcher_health": True})["watcher_health"]
    assert health["watcher"]["state"] == "unknown" and health["watcher"]["evidence"] == "unknown"
    assert health["last_capture"]["snapshot_id"] is None
    assert "plaintext" not in health["last_capture"]
    assert health["remote_verification"]["live_check_performed"] is False
    assert SECRET not in json.dumps(health)


def test_watcher_health_unsupported_cli_keeps_plain_status(tmp_path, monkeypatch):
    vault = _marker_vault(tmp_path / "v")
    cli = ScriptedCli(monkeypatch, watcher=_watcher_payload(), watcher_supported=False)
    out = _status({"cwd": str(vault), "watcher_health": True, "history_limit": 2,
                   })
    assert cli.calls[0] == ["status", "--json"], "an old CLI never gets --watcher"
    assert out["success"] is True and out["data"]["vault"] is True
    assert out["watcher_health"]["error_code"] == "cli_unsupported"
    assert "--watcher" in out["watcher_health"]["error"]


@pytest.mark.parametrize("bad", ["yes", 1, 0, "true", [True]])
def test_watcher_health_flag_must_be_boolean(tmp_path, monkeypatch, bad):
    cli = ScriptedCli(monkeypatch, watcher=_watcher_payload())
    out = _status({"cwd": str(tmp_path), "watcher_health": bad})
    assert out["success"] is False and out["error_code"] == "invalid_argument"
    assert cli.calls == []


def test_watcher_health_without_vault_says_so(tmp_path, monkeypatch):
    ScriptedCli(monkeypatch, status={"vault": False, "tracked_paths": []})
    out = _status({"cwd": str(tmp_path), "watcher_health": True})
    assert out["watcher_health"]["success"] is True and out["watcher_health"]["vault"] is False


# ------------------------------------------------------------ capability probes

def test_optional_capabilities_follow_help_text_and_do_not_gate_doctor(tmp_path, monkeypatch):
    exe = tmp_path / "ciphervault"
    exe.write_bytes(b"fake")
    monkeypatch.setattr(cv, "find_binary", lambda: (str(exe), "test"))
    helps = {
        "history": "Usage: ciphervault history [OPTIONS]\n  --json\n  --limit <LIMIT>",
        "restore": "Usage: ciphervault restore [OPTIONS]\n  --dry-run\n  --force",
    }
    seen = []

    def run(args, cwd, **kwargs):
        seen.append(args)
        if args[-1:] == ["--help"] and args[0] in helps:
            return {"success": True, "output": helps[args[0]]}
        return {"success": False, "error": "nope"}

    monkeypatch.setattr(cv, "_run_cli", run)
    cv._CLI_FEATURE_CACHE.clear()
    assert cv._cli_supports_history_json(str(tmp_path)) is True
    assert cv._cli_supports_restore_preview(str(tmp_path)) is False, "--json missing from restore help"
    probes = len(seen)
    cv._cli_supports_history_json(str(tmp_path))
    assert len(seen) == probes, "the probe result is cached per binary"
    exe.write_bytes(b"upgraded fake binary")  # size changes: cache entry no longer applies
    helps["restore"] += "\n  --json"
    assert cv._cli_supports_restore_preview(str(tmp_path)) is True
    cv._CLI_FEATURE_CACHE.clear()
