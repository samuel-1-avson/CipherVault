"""Unit tests for Path A Multi-Cloud Recovery Custody Orchestrator."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts" / "recovery"
sys.path.insert(0, str(SCRIPTS_DIR))

from multicloud_custody import (
    MultiCloudCustodyManager,
    split_secret_2_of_2,
    reconstruct_secret_2_of_2,
)


class TestMultiCloudCustody(unittest.TestCase):
    def setUp(self):
        self.mgr = MultiCloudCustodyManager()

    def test_shamir_2_of_2_pure_math(self):
        original = os.urandom(32)
        (x1, s1), (x2, s2) = split_secret_2_of_2(original)
        self.assertEqual(x1, 1)
        self.assertEqual(x2, 2)
        self.assertEqual(len(s1), 32)
        self.assertEqual(len(s2), 32)

        # Neither share matches original
        self.assertNotEqual(s1, original)
        self.assertNotEqual(s2, original)

        # Reconstruct
        recovered = reconstruct_secret_2_of_2((x1, s1), (x2, s2))
        self.assertEqual(recovered, original)

        # Order of shares does not matter
        recovered_reversed = reconstruct_secret_2_of_2((x2, s2), (x1, s1))
        self.assertEqual(recovered_reversed, original)

    def test_dual_cloud_custody_split_and_reconstruct(self):
        master_secret = b"EMERGENCY_RECOVERY_KEY_32BYTES!!"
        res = self.mgr.generate_custody_split(
            master_secret=master_secret,
            custodian_a_id="arn:aws:iam::111122223333:user/custodian-alice",
            custodian_b_id="custodian-bob@gcp-security-org.iam.gserviceaccount.com",
            aws_bucket="ciphervault-custody-immutable-us-east-1",
            gcp_bucket="ciphervault-custody-locked-europe-west3",
        )

        env_a = res["aws_envelope"]
        env_b = res["gcp_envelope"]

        self.assertEqual(env_a["cloud_provider"], "AWS")
        self.assertEqual(env_b["cloud_provider"], "GCP")
        self.assertEqual(env_a["immutability_mode"], "S3_OBJECT_LOCK_COMPLIANCE")
        self.assertEqual(env_b["immutability_mode"], "GCS_LOCKED_RETENTION_POLICY")

        # Successful reconstruction
        recovered = self.mgr.verify_and_reconstruct(env_a, env_b)
        self.assertEqual(recovered, master_secret)

    def test_collusion_and_same_custodian_rejection(self):
        master = b"TEST_KEY_FOR_REJECTION_00000000"
        with self.assertRaises(ValueError):
            self.mgr.generate_custody_split(
                master_secret=master,
                custodian_a_id="shared-admin@corp.com",
                custodian_b_id="shared-admin@corp.com",
                aws_bucket="b1",
                gcp_bucket="b2",
            )

    def test_fingerprint_mismatch_rejection(self):
        res1 = self.mgr.generate_custody_split(
            master_secret=b"KEY_ONE_111111111111111111111111",
            custodian_a_id="custodian-a@aws",
            custodian_b_id="custodian-b@gcp",
            aws_bucket="b1",
            gcp_bucket="b2",
        )
        res2 = self.mgr.generate_custody_split(
            master_secret=b"KEY_TWO_222222222222222222222222",
            custodian_a_id="custodian-c@aws",
            custodian_b_id="custodian-d@gcp",
            aws_bucket="b3",
            gcp_bucket="b4",
        )

        # Cross-pairing shares from different keys must fail
        with self.assertRaises(ValueError):
            self.mgr.verify_and_reconstruct(res1["aws_envelope"], res2["gcp_envelope"])

    def test_cli_split_and_reconstruct(self):
        secret_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        with tempfile.TemporaryDirectory(prefix="cv_mc_cli_") as tmp:
            tmp_path = Path(tmp)
            script = SCRIPTS_DIR / "multicloud_custody.py"

            # 1. CLI Split
            split_cmd = [
                sys.executable,
                str(script),
                "split",
                "--secret-hex",
                secret_hex,
                "--custodian-aws",
                "arn:aws:iam::123:user/alice",
                "--custodian-gcp",
                "bob@gcp.org",
                "--aws-bucket",
                "aws-vault-bucket",
                "--gcp-bucket",
                "gcp-vault-bucket",
                "--out-dir",
                str(tmp_path),
            ]
            res_split = subprocess.run(split_cmd, capture_output=True, text=True)
            self.assertEqual(res_split.returncode, 0, f"Split failed: {res_split.stderr}")

            self.assertTrue((tmp_path / "envelope-aws.json").exists())
            self.assertTrue((tmp_path / "envelope-gcp.json").exists())

            # 2. CLI Reconstruct
            recon_cmd = [
                sys.executable,
                str(script),
                "reconstruct",
                "--env-aws",
                str(tmp_path / "envelope-aws.json"),
                "--env-gcp",
                str(tmp_path / "envelope-gcp.json"),
            ]
            res_recon = subprocess.run(recon_cmd, capture_output=True, text=True)
            self.assertEqual(res_recon.returncode, 0, f"Reconstruct failed: {res_recon.stderr}")

            output_json = json.loads(res_recon.stdout)
            self.assertEqual(output_json["status"], "reconstructed")
            self.assertEqual(output_json["secret_hex"], secret_hex)


if __name__ == "__main__":
    unittest.main()
