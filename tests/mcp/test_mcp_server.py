"""Unit tests for CipherVault Model Context Protocol (MCP) Server."""

import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_DIR = REPO_ROOT / "services" / "mcp"
sys.path.insert(0, str(MCP_DIR))

from ciphervault_mcp_server import CipherVaultMcpServer


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
        names = [t["name"] for t in tools]

        self.assertIn("ciphervault_run_in_memory", names)
        self.assertIn("ciphervault_scan_secrets", names)
        self.assertIn("ciphervault_list_secrets", names)
        self.assertIn("ciphervault_create_snapshot", names)

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


if __name__ == "__main__":
    unittest.main()
