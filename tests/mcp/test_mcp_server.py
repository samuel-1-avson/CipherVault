"""Unit tests for CipherVault Model Context Protocol (MCP) Server."""

import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_DIR = REPO_ROOT / "services" / "mcp"
sys.path.insert(0, str(MCP_DIR))

from ciphervault_mcp_server import CipherVaultMcpServer, _minimal_env


class TestCipherVaultMcpServer(unittest.TestCase):
    def setUp(self):
        self.server = CipherVaultMcpServer()

    def test_initialize_handshake(self):
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
        self.assertEqual(resp["result"]["serverInfo"]["name"], "ciphervault-mcp-server")

    def test_tools_list(self):
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        resp = self.server.handle_request(req)
        self.assertEqual(resp["id"], 2)
        tools = resp["result"]["tools"]
        by_name = {t["name"]: t for t in tools}

        self.assertIn("ciphervault_run_in_memory", by_name)
        self.assertIn("ciphervault_scan_secrets", by_name)
        self.assertIn("ciphervault_list_secrets", by_name)
        self.assertIn("ciphervault_create_snapshot", by_name)

        run_props = by_name["ciphervault_run_in_memory"]["inputSchema"]["properties"]
        self.assertIn("allow_keys", run_props)
        self.assertIn("no_net", run_props)
        self.assertIn("proxy", run_props)
        self.assertNotIn("proxy_upstream", run_props)

        snap_props = by_name["ciphervault_create_snapshot"]["inputSchema"]["properties"]
        self.assertIn("shred_working_copy", snap_props)

    def test_tool_dispatch_scan_secrets(self):
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "ciphervault_scan_secrets",
                "arguments": {"deep": True, "fix": False},
            },
        }
        resp = self.server.handle_request(req)
        self.assertEqual(resp["id"], 3)
        self.assertIn("result", resp)
        content = resp["result"]["content"]
        self.assertEqual(content[0]["type"], "text")
        # Text should be valid JSON payload
        parsed = json.loads(content[0]["text"])
        self.assertIn("status", parsed)

    def test_unknown_method(self):
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "unknown/method",
            "params": {},
        }
        resp = self.server.handle_request(req)
        self.assertEqual(resp["id"], 4)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_unknown_tool(self):
        req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "non_existent_tool",
                "arguments": {},
            },
        }
        resp = self.server.handle_request(req)
        self.assertEqual(resp["id"], 5)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32602)

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
                "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR",
                "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
                "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT",
            ):
                self.assertEqual(env[k], fake_env[k])

    def test_run_cli_passes_minimal_env(self):
        fake_proc = MagicMock(stdout='{"ok": true}', stderr="", returncode=0)
        with patch.dict(
            os.environ,
            {
                "PATH": os.environ.get("PATH", "/usr/bin"),
                "OPENAI_API_KEY": "sk-secret-parent",
                "CIPHERVAULT_CLI_MODE": "strict",
            },
            clear=True,
        ):
            with patch("ciphervault_mcp_server.subprocess.run", return_value=fake_proc) as mock_run:
                self.server.run_cli([self.server.binary_path, "status", "--json"], {})
                mock_run.assert_called_once()
                passed_env = mock_run.call_args.kwargs["env"]
                self.assertNotIn("OPENAI_API_KEY", passed_env)
                self.assertEqual(passed_env["CIPHERVAULT_CLI_MODE"], "strict")
                self.assertEqual(passed_env["NO_COLOR"], "1")

    def test_run_in_memory_defaults_to_no_net_across_platforms(self):
        fake_proc = MagicMock(stdout='{"exit_code": 0, "stdout": "ok"}', stderr="", returncode=0)
        for plat in ("linux", "darwin", "win32"):
            with self.subTest(platform=plat):
                with patch("ciphervault_mcp_server.sys.platform", plat), patch(
                    "ciphervault_mcp_server.subprocess.run", return_value=fake_proc
                ) as mock_run:
                    resp = self.server.handle_request(
                        {
                            "jsonrpc": "2.0",
                            "id": 10,
                            "method": "tools/call",
                            "params": {
                                "name": "ciphervault_run_in_memory",
                                "arguments": {"command": ["python", "-V"]},
                            },
                        }
                    )
                    self.assertIn("result", resp)
                    cli_args = mock_run.call_args.args[0]
                    self.assertIn("--no-net", cli_args)
                    self.assertNotIn("--proxy", cli_args)

    def test_run_in_memory_no_net_false_and_proxy_options(self):
        fake_proc = MagicMock(stdout='{"exit_code": 0, "stdout": "ok"}', stderr="", returncode=0)
        with patch("ciphervault_mcp_server.subprocess.run", return_value=fake_proc) as mock_run:
            # Explicit no_net=False omits --no-net
            self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_run_in_memory",
                        "arguments": {"command": ["pytest"], "no_net": False},
                    },
                }
            )
            cli_args = mock_run.call_args.args[0]
            self.assertNotIn("--no-net", cli_args)

            # proxy=True adds --proxy and omits --no-net by default
            mock_run.reset_mock()
            self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 12,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_run_in_memory",
                        "arguments": {"command": ["python", "app.py"], "proxy": True},
                    },
                }
            )
            cli_args = mock_run.call_args.args[0]
            self.assertIn("--proxy", cli_args)
            self.assertNotIn("--no-net", cli_args)

            # Untrusted proxy_upstream cannot disable --no-net or pass --proxy-upstream
            mock_run.reset_mock()
            self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_run_in_memory",
                        "arguments": {
                            "command": ["python", "app.py"],
                            "proxy_upstream": ["OPENAI_API_KEY=http://127.0.0.1:9999"],
                        },
                    },
                }
            )
            cli_args = mock_run.call_args.args[0]
            self.assertNotIn("--proxy-upstream", cli_args)
            self.assertIn("--no-net", cli_args)

            # proxy=True combined with explicit no_net=True fails closed
            mock_run.reset_mock()
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
            self.assertIn("error", resp)
            self.assertEqual(resp["error"]["code"], -32602)
            mock_run.assert_not_called()

    def test_run_in_memory_allow_keys(self):
        fake_proc = MagicMock(stdout='{"exit_code": 0, "stdout": "ok"}', stderr="", returncode=0)
        with patch("ciphervault_mcp_server.subprocess.run", return_value=fake_proc) as mock_run:
            resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 15,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_run_in_memory",
                        "arguments": {
                            "command": ["pytest", "-q"],
                            "allow_keys": [" DATABASE_URL ", "REDIS_URL"],
                        },
                    },
                }
            )
            self.assertIn("result", resp)
            cli_args = mock_run.call_args.args[0]
            idx = cli_args.index("--allow-keys")
            self.assertEqual(cli_args[idx + 1], "DATABASE_URL,REDIS_URL")
            self.assertIn("--no-net", cli_args)

            # Empty allow_keys is rejected without invoking CLI
            mock_run.reset_mock()
            bad_resp = self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 16,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_run_in_memory",
                        "arguments": {
                            "command": ["pytest"],
                            "allow_keys": ["   "],
                        },
                    },
                }
            )
            self.assertIn("error", bad_resp)
            self.assertEqual(bad_resp["error"]["code"], -32602)
            mock_run.assert_not_called()

    def test_create_snapshot_shred_working_copy(self):
        fake_proc = MagicMock(stdout="Snapshot created", stderr="", returncode=0)
        with patch("ciphervault_mcp_server.subprocess.run", return_value=fake_proc) as mock_run:
            # Default: no --shred
            self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 17,
                    "method": "tools/call",
                    "params": {
                        "name": "ciphervault_create_snapshot",
                        "arguments": {"message": "snapshot 1"},
                    },
                }
            )
            cli_args = mock_run.call_args.args[0]
            self.assertIn("push", cli_args)
            self.assertIn("--local", cli_args)
            self.assertNotIn("--shred", cli_args)

            # With shred_working_copy=True: passes --shred
            mock_run.reset_mock()
            self.server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 18,
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
            cli_args = mock_run.call_args.args[0]
            self.assertIn("--shred", cli_args)


if __name__ == "__main__":
    unittest.main()
