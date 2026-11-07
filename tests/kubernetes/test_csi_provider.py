"""Unit tests for CipherVault Kubernetes CSI Ephemeral Secret Provider."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

# Add provider directory to Python path
REPO_ROOT = Path(__file__).resolve().parents[2]
PROVIDER_DIR = REPO_ROOT / "deploy" / "kubernetes" / "csi" / "provider"
sys.path.insert(0, str(PROVIDER_DIR))

from ciphervault_csi_provider import CipherVaultCSIProvider, CSIDriverError


class TestCipherVaultCSIProvider(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="cv_csi_test_")
        self.target_path = Path(self.temp_dir.name) / "mount"
        self.provider = CipherVaultCSIProvider(zero_disk=False)  # disable Linux root mount requirement in unit test

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_publish_and_unpublish_lifecycle(self):
        secrets = {
            ".env": "DATABASE_URL=postgres://user:pass@db:5432/app\nPORT=8080\n",
            "keys/api_token.txt": "cvst1.eyJhbGciOiJFZDI1NTE5In0.k8s_secret_payload_token",
            "configs/service.json": json.dumps({"service": "order-api", "enabled": True}),
        }

        # 1. Publish Volume
        meta = self.provider.publish_volume(
            target_path=self.target_path,
            volume_id="vol-test-12345",
            project="ecommerce-core",
            environment="production",
            secrets_payload=secrets,
            pod_uid="pod-uuid-9999",
        )

        self.assertEqual(meta["status"], "published")
        self.assertEqual(meta["files_count"], 3)
        self.assertTrue(self.target_path.exists())

        # Verify files materialized correctly
        env_file = self.target_path / ".env"
        self.assertTrue(env_file.exists())
        self.assertEqual(env_file.read_text(encoding="utf-8"), secrets[".env"])

        key_file = self.target_path / "keys" / "api_token.txt"
        self.assertTrue(key_file.exists())
        self.assertEqual(key_file.read_text(encoding="utf-8"), secrets["keys/api_token.txt"])

        # Verify permissions: file must be read-only (0400 on POSIX)
        if sys.platform != "win32":
            file_mode = stat.S_IMODE(env_file.stat().st_mode)
            self.assertEqual(file_mode, stat.S_IRUSR)

        # 2. Unpublish Volume
        unpub_meta = self.provider.unpublish_volume(
            target_path=self.target_path,
            volume_id="vol-test-12345",
        )

        self.assertEqual(unpub_meta["status"], "unmounted")
        self.assertEqual(unpub_meta["volume_id"], "vol-test-12345")
        self.assertTrue(unpub_meta["scrubbed_files_count"] >= 3)
        self.assertFalse(self.target_path.exists())

    def test_path_traversal_rejection(self):
        bad_secrets = {
            "../../escape.txt": "sensitive_data",
        }
        with self.assertRaises(CSIDriverError):
            self.provider.publish_volume(
                target_path=self.target_path,
                volume_id="vol-bad-path",
                project="proj",
                environment="prod",
                secrets_payload=bad_secrets,
            )

    def test_idempotent_unpublish(self):
        nonexistent = self.target_path / "does_not_exist"
        res = self.provider.unpublish_volume(nonexistent, "vol-none")
        self.assertEqual(res["status"], "unmounted")
        self.assertFalse(res["existed"])

    def test_cli_execution(self):
        provider_script = PROVIDER_DIR / "ciphervault_csi_provider.py"
        secrets_arg = json.dumps({"app.env": "SECRET=test1234"})

        # CLI Publish
        pub_proc = subprocess.run(
            [
                sys.executable,
                str(provider_script),
                "publish",
                "--target-path",
                str(self.target_path),
                "--volume-id",
                "vol-cli-test",
                "--project",
                "test-project",
                "--env",
                "test-env",
                "--secrets-json",
                secrets_arg,
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(pub_proc.returncode, 0, f"CLI publish failed: {pub_proc.stderr}")
        self.assertTrue((self.target_path / "app.env").exists())

        # CLI Unpublish
        unpub_proc = subprocess.run(
            [
                sys.executable,
                str(provider_script),
                "unpublish",
                "--target-path",
                str(self.target_path),
                "--volume-id",
                "vol-cli-test",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(unpub_proc.returncode, 0, f"CLI unpublish failed: {unpub_proc.stderr}")
        self.assertFalse(self.target_path.exists())


if __name__ == "__main__":
    unittest.main()
