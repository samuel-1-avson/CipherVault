"""Unit tests for CipherVault backup alert dispatcher."""

import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "recovery" / "backup_alert.py"
SPEC = importlib.util.spec_from_file_location("backup_alert", SCRIPT)
alert = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(alert)


class TestBackupAlert(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_sanitize_message(self):
        raw = "failed to backup token cvst1.abcdef123456.secret and key age14v9uzph70chnqw9v975dpeh9gamthcle88qp56jkmzxemlx39pas9essuh"
        sanitized = alert.sanitize_message(raw)
        self.assertNotIn("cvst1.abcdef", sanitized)
        self.assertIn("cvst1.[REDACTED]", sanitized)
        self.assertNotIn("age14v9uzph", sanitized)
        self.assertIn("age1[REDACTED]", sanitized)

    def test_read_log_tail(self):
        log_file = self.tmp_dir / "test.log"
        with open(log_file, "w", encoding="utf-8") as f:
            for i in range(50):
                f.write(f"Line {i}: normal operation\n")
            f.write("Line 50: cvst1.leakedtoken\n")

        tail = alert.read_log_tail(log_file)
        self.assertIn("Line 49", tail)
        self.assertIn("Line 50", tail)
        self.assertNotIn("cvst1.leakedtoken", tail)
        self.assertIn("cvst1.[REDACTED]", tail)

    @patch("urllib.request.urlopen")
    def test_dispatch_healthcheck(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        # Test success
        ok, msg = alert.dispatch_healthcheck("https://hc-ping.com/abc-123", "success")
        self.assertTrue(ok)
        mock_urlopen.assert_called_with(mock_urlopen.call_args[0][0], timeout=15)
        self.assertEqual(mock_urlopen.call_args[0][0].full_url, "https://hc-ping.com/abc-123")

        # Test failure
        ok, msg = alert.dispatch_healthcheck("https://hc-ping.com/abc-123", "failure", "error tail")
        self.assertTrue(ok)
        self.assertEqual(mock_urlopen.call_args[0][0].full_url, "https://hc-ping.com/abc-123/fail")
        self.assertEqual(mock_urlopen.call_args[0][0].data, b"error tail")

        # Test start
        ok, msg = alert.dispatch_healthcheck("https://hc-ping.com/abc-123", "start")
        self.assertTrue(ok)
        self.assertEqual(mock_urlopen.call_args[0][0].full_url, "https://hc-ping.com/abc-123/start")

    @patch("urllib.request.urlopen")
    def test_dispatch_webhook_slack_format(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        event_data = {
            "service": "ciphervault-account-custody",
            "status": "failure",
            "host": "cv-web-ui",
            "message": "Backup upload failed",
            "log_tail": "Error 403 denied",
        }
        ok, msg = alert.dispatch_webhook("https://hooks.slack.com/services/T00/B00/X00", event_data)
        self.assertTrue(ok)

        # Check payload format
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertIn("🚨", payload["text"])
        self.assertIn("cv-web-ui", payload["text"])
        self.assertEqual(payload["attachments"][0]["color"], "#e02424")

    @patch("urllib.request.urlopen")
    def test_dispatch_pagerduty(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 202
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        event_data = {
            "service": "ciphervault-account-custody",
            "status": "failure",
            "host": "cv-web-ui",
            "message": "Upload failed",
        }
        ok, msg = alert.dispatch_pagerduty("routing-key-123", event_data)
        self.assertTrue(ok)

        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["routing_key"], "routing-key-123")
        self.assertEqual(payload["event_action"], "trigger")
        self.assertEqual(payload["payload"]["severity"], "critical")

    def test_load_config_env_precedence(self):
        cfg_file = self.tmp_dir / "alert.json"
        with open(cfg_file, "w") as f:
            json.dump({"webhook_url": "https://old.url"}, f)

        # Environment variable overrides file
        with patch.dict(os.environ, {"CIPHERVAULT_ALERT_WEBHOOK_URL": "https://new.url"}):
            loaded = alert.load_config(str(cfg_file))
            self.assertEqual(loaded.get("webhook_url"), "https://new.url")

    def test_run_alert_dry_run(self):
        # Dry-run should succeed without any network calls
        cfg = {"healthcheck_url": "https://hc-ping.com/abc"}
        cfg_file = self.tmp_dir / "alert.json"
        with open(cfg_file, "w") as f:
            json.dump(cfg, f)

        res = alert.run_alert(
            status="success",
            message="Backup completed",
            config_path=str(cfg_file),
            dry_run=True,
        )
        self.assertTrue(res)


if __name__ == "__main__":
    unittest.main()
