"""Unit and integration tests for the CipherVault MCP delegating shim."""

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_DIR = REPO_ROOT / "services" / "mcp"
sys.path.insert(0, str(MCP_DIR))

from ciphervault_mcp_server import (
    CipherVaultMcpServer,
    LEGACY_TOOL_ALIASES,
    _augment_tools_list,
    _minimal_env,
    find_ciphervault_binary,
    translate_legacy_tool_call,
)


def _has_live_binary() -> bool:
    bin_path = find_ciphervault_binary()
    p = Path(bin_path)
    if p.is_file() and os.access(p, os.X_OK):
        return True
    return shutil.which(bin_path) is not None


class TestCipherVaultMcpShimUnit(unittest.TestCase):
    """Pure unit tests (run cleanly even in Python-only CI without a Rust build)."""

    def setUp(self):
        self.server = CipherVaultMcpServer(binary_path="/fake/ciphervault")

    def tearDown(self):
        self.server.close()

    def test_minimal_env_filters_provider_keys_and_keeps_allowlist(self):
        fake_env = {
            "PATH": "/usr/bin",
            "HOME": "/home/tester",
            "USERPROFILE": "C:\\Users\\tester",
            "SYSTEMROOT": "C:\\Windows",
            "WINDIR": "C:\\Windows",
            "TEMP": "/tmp",
            "TMP": "/tmp",
            "TMPDIR": "/tmp",
            "LANG": "en_US.UTF-8",
            "LC_ALL": "C.UTF-8",
            "APPDATA": "C:\\AppData",
            "LOCALAPPDATA": "C:\\LocalAppData",
            "COMSPEC": "cmd.exe",
            "PATHEXT": ".EXE",
            "CIPHERVAULT_PROFILE": "ci",
            "OPENAI_API_KEY": "sk-parent-should-not-leak",
            "ANTHROPIC_API_KEY": "sk-ant-parent-should-not-leak",
            "AWS_SECRET_ACCESS_KEY": "aws-parent-should-not-leak",
            "NO_COLOR": "0",
        }
        with patch.dict(os.environ, fake_env, clear=True):
            env = _minimal_env()
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertNotIn("ANTHROPIC_API_KEY", env)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertEqual(env["CIPHERVAULT_PROFILE"], "ci")
            self.assertEqual(env["NO_COLOR"], "1")
            for k in (
                "PATH",
                "HOME",
                "USERPROFILE",
                "SYSTEMROOT",
                "WINDIR",
                "TEMP",
                "TMP",
                "TMPDIR",
                "LANG",
                "LC_ALL",
                "APPDATA",
                "LOCALAPPDATA",
                "COMSPEC",
                "PATHEXT",
            ):
                self.assertEqual(env[k], fake_env[k])

    def test_native_mcp_spawn_passes_minimal_env_and_mcp_subcommand(self):
        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.stdin = io.StringIO()
        fake_proc.stdout = iter(['{"jsonrpc":"2.0","id":1,"result":{}}\n'])

        with patch.dict(
            os.environ,
            {
                "PATH": os.environ.get("PATH", "/usr/bin"),
                "OPENAI_API_KEY": "sk-secret-parent",
                "CIPHERVAULT_CLI_MODE": "strict",
            },
            clear=True,
        ):
            with patch("ciphervault_mcp_server.subprocess.Popen", return_value=fake_proc) as mock_popen:
                resp = self.server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "ping"})
                self.assertEqual(resp, {"jsonrpc": "2.0", "id": 1, "result": {}})
                mock_popen.assert_called_once()
                argv = mock_popen.call_args.args[0]
                self.assertEqual(argv, ["/fake/ciphervault", "mcp"])
                passed_env = mock_popen.call_args.kwargs["env"]
                self.assertNotIn("OPENAI_API_KEY", passed_env)
                self.assertEqual(passed_env["CIPHERVAULT_CLI_MODE"], "strict")
                self.assertEqual(passed_env["NO_COLOR"], "1")

    def test_notifications_produce_no_response(self):
        with patch.object(self.server, "_forward_to_native", return_value=None) as mock_fwd:
            resp = self.server.handle_request(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
            self.assertIsNone(resp)
            mock_fwd.assert_called_once()

    def test_augment_tools_list_derives_legacy_aliases_without_proxy_upstream(self):
        native_tools = [
            {
                "name": "ciphervault_run",
                "description": "native run",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "array"},
                        "allow_keys": {"type": "array"},
                        "no_net": {"type": "boolean"},
                        "proxy": {"type": "boolean"},
                        "env": {"type": "string"},
                    },
                },
            },
            {
                "name": "ciphervault_scan",
                "description": "native scan",
                "inputSchema": {"type": "object", "properties": {"deep": {"type": "boolean"}}},
            },
            {
                "name": "ciphervault_status",
                "description": "native status",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ciphervault_push",
                "description": "native push",
                "inputSchema": {
                    "type": "object",
                    "properties": {"shred_working_copy": {"type": "boolean"}},
                },
            },
        ]
        augmented = _augment_tools_list(native_tools)
        by_name = {t["name"]: t for t in augmented}
        for alias in LEGACY_TOOL_ALIASES:
            self.assertIn(alias, by_name)
        run_props = by_name["ciphervault_run_in_memory"]["inputSchema"]["properties"]
        self.assertIn("allow_keys", run_props)
        self.assertIn("no_net", run_props)
        self.assertIn("proxy", run_props)
        self.assertIn("environment", run_props)
        self.assertNotIn("proxy_upstream", run_props)
        snap_props = by_name["ciphervault_create_snapshot"]["inputSchema"]["properties"]
        self.assertIn("shred_working_copy", snap_props)

    def test_legacy_run_in_memory_translation_and_validation(self):
        name, args, err = translate_legacy_tool_call(
            "ciphervault_run_in_memory",
            {
                "command": ["pytest", "-q"],
                "environment": "staging",
                "allow_keys": [" DATABASE_URL ", "REDIS_URL"],
                "proxy_upstream": ["OPENAI_API_KEY=http://127.0.0.1:9999"],
            },
        )
        self.assertIsNone(err)
        self.assertEqual(name, "ciphervault_run")
        self.assertEqual(args["command"], ["pytest", "-q"])
        self.assertEqual(args["env"], "staging")
        self.assertEqual(args["allow_keys"], ["DATABASE_URL", "REDIS_URL"])
        self.assertNotIn("proxy_upstream", args)

        # proxy=True without no_net forwards proxy=True cleanly
        name, args, err = translate_legacy_tool_call(
            "ciphervault_run_in_memory",
            {"command": ["python", "app.py"], "proxy": True},
        )
        self.assertIsNone(err)
        self.assertEqual(name, "ciphervault_run")
        self.assertTrue(args["proxy"])
        self.assertNotIn("no_net", args)

        # proxy=True + no_net=True fails closed with -32602 without calling native binary
        with patch.object(self.server, "_forward_to_native") as mock_fwd:
            resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 14,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_run_in_memory",
                        "arguments": {
                            "command": ["python", "app.py"],
                            "proxy": True,
                            "no_net": True,
                        },
                    },
                }
            )
            self.assertEqual(resp["error"]["code"], -32602)
            mock_fwd.assert_not_called()

        # Empty allow_keys fails closed with -32602 without calling native binary
        with patch.object(self.server, "_forward_to_native") as mock_fwd:
            resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 16,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_run_in_memory",
                        "arguments": {"command": ["pytest"], "allow_keys": ["   "]},
                    },
                }
            )
            self.assertEqual(resp["error"]["code"], -32602)
            mock_fwd.assert_not_called()

        # UNC cwd fails closed
        with patch.object(self.server, "_forward_to_native") as mock_fwd:
            resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 17,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_list_secrets",
                        "arguments": {"cwd": "\\\\attacker.example\\share"},
                    },
                }
            )
            self.assertEqual(resp["error"]["code"], -32602)
            mock_fwd.assert_not_called()

    def test_legacy_create_snapshot_delegates_to_ciphervault_push(self):
        fake_resp = {
            "jsonrpc": "2.0",
            "id": 18,
            "result": {"content": [{"type": "text", "text": "{}"}], "isError": False},
        }
        with patch.object(self.server, "_forward_to_native", return_value=fake_resp) as mock_fwd:
            self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 18,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_create_snapshot",
                        "arguments": {"message": "snapshot 1"},
                    },
                }
            )
            forwarded = mock_fwd.call_args.args[0]
            self.assertEqual(forwarded["params"]["name"], "ciphervault_push")
            self.assertEqual(forwarded["params"]["arguments"]["message"], "snapshot 1")
            self.assertIs(forwarded["params"]["arguments"]["local_only"], True)
            self.assertIs(forwarded["params"]["arguments"]["shred_working_copy"], False)

            mock_fwd.reset_mock()
            self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 19,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_create_snapshot",
                        "arguments": {
                            "message": "sealed snapshot",
                            "shred_working_copy": True,
                        },
                    },
                }
            )
            forwarded = mock_fwd.call_args.args[0]
            self.assertEqual(forwarded["params"]["name"], "ciphervault_push")
            self.assertIs(forwarded["params"]["arguments"]["shred_working_copy"], True)


@unittest.skipUnless(_has_live_binary(), "native ciphervault binary not built")
class TestCipherVaultMcpLiveBinary(unittest.TestCase):
    """End-to-end tests exercising the shim talking to the real `ciphervault mcp` binary."""

    def setUp(self):
        self.server = CipherVaultMcpServer()

    def tearDown(self):
        self.server.close()

    def test_initialize_handshake_live(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "test-agent", "version": "1.0"},
            },
        }
        resp = self.server.handle_request(req)
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], 1)
        self.assertIn("capabilities", resp["result"])
        self.assertEqual(resp["result"]["serverInfo"]["name"], "ciphervault")

    def test_tools_list_live_includes_all_native_tools_and_legacy_aliases(self):
        resp = self.server.handle_request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        self.assertEqual(resp["id"], 2)
        tools = resp["result"]["tools"]
        by_name = {t["name"]: t for t in tools}

        for expected_native in (
            "ciphervault_status",
            "ciphervault_scan",
            "ciphervault_redact",
            "ciphervault_run",
            "ciphervault_push",
            "ciphervault_diff",
            "ciphervault_audit",
            "ciphervault_env_doctor",
            "ciphervault_proxy_doctor",
            "ciphervault_recovery_drill",
            "ciphervault_secret_generate",
        ):
            self.assertIn(expected_native, by_name)

        for expected_legacy in LEGACY_TOOL_ALIASES:
            self.assertIn(expected_legacy, by_name)

        for run_name in ("ciphervault_run", "ciphervault_run_in_memory"):
            run_props = by_name[run_name]["inputSchema"]["properties"]
            self.assertIn("allow_keys", run_props)
            self.assertIn("no_net", run_props)
            self.assertIn("proxy", run_props)
            self.assertNotIn("proxy_upstream", run_props)

    def test_tool_dispatch_scan_secrets_live(self):
        resp = self.server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "ciphervault_scan_secrets",
                    "arguments": {"deep": True, "fix": False},
                },
            }
        )
        self.assertEqual(resp["id"], 3)
        self.assertIn("result", resp)
        content = resp["result"]["content"]
        self.assertEqual(content[0]["type"], "text")
        parsed = json.loads(content[0]["text"])
        self.assertIn("status", parsed)

    def test_tool_dispatch_redact_live_emits_completeness(self):
        synthetic = "sk_" + "live_" + "11223344556677889900aabb"
        resp = self.server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {
                    "name": "ciphervault_redact",
                    "arguments": {"text": f"Authorization: Bearer {synthetic}"},
                },
            }
        )
        self.assertEqual(resp["result"]["isError"], False)
        parsed = json.loads(resp["result"]["content"][0]["text"])
        self.assertIs(parsed["exact_values_complete"], True)
        self.assertNotIn(synthetic, parsed["text"])
        self.assertIn("[REDACTED", parsed["text"])

    def test_tool_dispatch_env_doctor_live(self):
        with tempfile.TemporaryDirectory(prefix="cv-mcp-envdoc-") as td:
            root = Path(td)
            (root / "app.py").write_text(
                'import os\nx = os.getenv("MISSING_KEY")\n', encoding="utf-8"
            )
            resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 31,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_env_doctor",
                        "arguments": {"cwd": td},
                    },
                }
            )
            self.assertEqual(resp["result"]["isError"], False)
            parsed = json.loads(resp["result"]["content"][0]["text"])
            self.assertTrue(parsed["success"])
            self.assertIn("MISSING_KEY", parsed["referenced_in_code"])
            self.assertIn("MISSING_KEY", parsed["missing_in_vault"])

    def test_tool_dispatch_recovery_drill_blocks_metadata_via_live(self):
        resp = self.server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 32,
                "method": "tools/call",
                "params": {
                    "name": "ciphervault_recovery_drill",
                    "arguments": {
                        "kit": "dummy.kit",
                        "via": ["http://169.254.169.254"],
                    },
                },
            }
        )
        self.assertEqual(resp["result"]["isError"], True)
        parsed = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("private, loopback, link-local", parsed["error"])

    def test_unknown_method_and_unknown_tool_live(self):
        bad_method = self.server.handle_request(
            {"jsonrpc": "2.0", "id": 4, "method": "unknown/method", "params": {}}
        )
        self.assertEqual(bad_method["id"], 4)
        self.assertEqual(bad_method["error"]["code"], -32601)

        bad_tool = self.server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "non_existent_tool", "arguments": {}},
            }
        )
        self.assertEqual(bad_tool["id"], 5)
        self.assertTrue(bad_tool["result"]["isError"])

    def test_live_vault_run_audit_receipt_and_proxy_doctor(self):
        binary = find_ciphervault_binary()
        secret_val = "live_mcp_canary_" + "secret_778899"
        with tempfile.TemporaryDirectory(prefix="cv-mcp-live-") as td:
            root = Path(td)
            (root / ".env").write_text(
                f"DEMO_SECRET={secret_val}\n"
                "OPENAI_API_KEY=sk-proj-synthetic1234567890abcd\n"
                "RESEND_API_KEY=re_synthetic1234567890abcd\n"
                "INTERNAL_TOKEN=internal_tok_1234567890\n",
                encoding="utf-8",
            )
            env = _minimal_env()
            for argv in (
                [binary, "init"],
                [binary, "track", ".env"],
                [binary, "push", "--local", "-m", "init"],
            ):
                proc = subprocess.run(
                    argv, cwd=td, capture_output=True, text=True, timeout=60, env=env
                )
                self.assertEqual(proc.returncode, 0, f"{argv} failed: {proc.stderr}")

            (root / ".ciphervault" / "policy.toml").write_text(
                "[vault]\n"
                "sealed_mode = false\n"
                "[profiles.svc.upstreams]\n"
                'INTERNAL_TOKEN = "https://internal.example.com"\n',
                encoding="utf-8",
            )

            # 1. proxy_doctor classifies built-in providers, policy upstreams, and unmapped keys
            pd_resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 40,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_proxy_doctor",
                        "arguments": {"cwd": td},
                    },
                }
            )
            self.assertEqual(pd_resp["result"]["isError"], False)
            pd_data = json.loads(pd_resp["result"]["content"][0]["text"])
            self.assertTrue(pd_data["proxy_ready"])
            mapped_keys = [p["key"] for p in pd_data["mapped_providers"]]
            self.assertIn("OPENAI_API_KEY", mapped_keys)
            self.assertIn("RESEND_API_KEY", mapped_keys)
            policy_keys = [p["key"] for p in pd_data["mapped_policy_upstreams"]]
            self.assertIn("INTERNAL_TOKEN", policy_keys)
            self.assertIn("DEMO_SECRET", pd_data["unmapped_keys"])

            # 2. ciphervault_run_in_memory scrubs echoed secret and writes a verified audit receipt
            run_cmd = (
                ["cmd", "/c", "echo LEAK=%DEMO_SECRET%"]
                if sys.platform == "win32"
                else ["sh", "-c", 'printf "LEAK=%s\\n" "$DEMO_SECRET"']
            )
            run_resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 41,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_run_in_memory",
                        "arguments": {
                            "command": run_cmd,
                            "allow_keys": ["DEMO_SECRET"],
                            "cwd": td,
                        },
                    },
                }
            )
            self.assertEqual(run_resp["result"]["isError"], False, run_resp)
            run_text = run_resp["result"]["content"][0]["text"]
            self.assertNotIn(secret_val, run_text)
            run_data = json.loads(run_text)
            self.assertIn("[REDACTED:DEMO_SECRET]", run_data["stdout"])

            # 3. ciphervault_audit verifies the scrubbed_result receipt in the local vault store
            audit_resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 42,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_audit",
                        "arguments": {"limit": 10, "cwd": td},
                    },
                }
            )
            self.assertEqual(audit_resp["result"]["isError"], False)
            audit_data = json.loads(audit_resp["result"]["content"][0]["text"])
            self.assertTrue(audit_data["ok"])
            self.assertGreaterEqual(audit_data["entries_total"], 1)
            entry = audit_data["entries"][0]
            self.assertEqual(entry["tool"], "ciphervault_run")
            self.assertEqual(entry["decision"], "scrubbed_result")
            detail = json.loads(entry["detail_json"])
            self.assertEqual(detail["exit_code"], 0)
            self.assertGreaterEqual(detail["redactions"], 1)
            self.assertIn("output_sha256", detail)
            self.assertIn("content_sha256", detail)


if __name__ == "__main__":
    unittest.main()
