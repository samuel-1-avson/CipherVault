"""Synthetic local fixtures; no cloud credentials or network calls are used."""

import contextlib
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "recovery" / "account_custody.py"
SPEC = importlib.util.spec_from_file_location("account_custody", SCRIPT)
custody = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(custody)
sys.modules["account_custody"] = custody


def companion(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPT.with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


receiver = companion("receive_custody")
provisioning = companion("plan_provisioning")


class CustodyFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cv-custody-fixture-")
        self.root = Path(self.temporary.name).resolve()
        # Most tests exercise policy, not the platform ACL API. The separate
        # permission test uses the real Windows DACL implementation.
        self.acl_patch = patch.object(custody, "windows_acl")
        self.acl_patch.start()
        self.now = int(time.time())
        self.source = custody.private_dir(self.root / "source")
        self.work = custody.private_dir(self.root / "work")
        with contextlib.closing(sqlite3.connect(self.source / "accounts.sqlite3")) as db:
            db.execute("CREATE TABLE fixture(value TEXT)")
            db.execute("INSERT INTO fixture VALUES('synthetic account metadata')")
            db.commit()
        for name in ("account", "gcloud", "kek", "totp", "age", "age-identity"):
            self.write(name, "synthetic fixture only")
        self.attestation = {
            "governance_id": "independent-backup-team", "bucket": "gs://separate-custodian-bucket",
            "project_number": "999999999999", "production_admins_cannot_delete": True,
            "review_reference": "fixture-review", "expires_at_utc": self.now + 86400,
        }
        self.key_receipt = {
            "governance_id": "offline-key-team", "historical_kek_versions": ["legacy", "v2"],
            "totp_key_retained": True, "scope_signing_key_rotation_ready": True,
            "archive_decryption_key_retained": True, "restore_reference": "fixture-restore",
            "expires_at_utc": self.now + 86400,
        }
        self.write("attestation.json", self.attestation)
        self.write("keys.json", self.key_receipt)
        self.cfg = {
            "schema_version": 1, "production_project_number": "108687509435",
            "production_governance_id": "production-admins", "production_principals": ["group:prod@example.test"],
            "account_binary": str(self.root / "account"), "gcloud_binary": str(self.root / "gcloud"),
            "data_dir": str(self.source), "work_dir": str(self.work), "kek_file": str(self.root / "kek"),
            "totp_key_file": str(self.root / "totp"), "max_backup_age_seconds": 90000,
            "max_artifact_bytes": 1073741824, "timeout_seconds": 60,
            "destination": {"bucket": "gs://separate-custodian-bucket", "prefix": "accounts",
                            "project_number": "999999999999", "governance_id": "independent-backup-team",
                            "min_retention_days": 30, "attestation_file": str(self.root / "attestation.json")},
            "key_custody": {"governance_id": "offline-key-team", "receipt_file": str(self.root / "keys.json")},
            "archive_encryption": None,
        }
        self.bucket = {
            "name": "separate-custodian-bucket", "projectNumber": "999999999999",
            "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "enforced"},
            "versioning": {"enabled": True}, "retentionPolicy": {"isLocked": True, "retentionPeriod": "2592000"},
        }
        self.policy = {"bindings": [{"role": "roles/storage.objectCreator", "members": ["serviceAccount:backup@example.test"]}]}
        self.objects = {}
        self.calls = []
        self.tamper = False

    def tearDown(self):
        self.acl_patch.stop()
        self.temporary.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value) if isinstance(value, dict) else value, encoding="utf-8")
        custody.private(path, True)
        return path

    def config(self):
        return custody.load_config(self.write("config.json", self.cfg), self.now)

    def backup(self, output):
        custody.private_dir(output)
        shutil.copyfile(self.source / "accounts.sqlite3", output / "accounts.sqlite3")
        custody.private(output / "accounts.sqlite3", True)
        receipt = {"format_version": 1, "created_at_utc": self.now, "database_sha256": custody.digest(output / "accounts.sqlite3"),
                   "database_bytes": (output / "accounts.sqlite3").stat().st_size, "table_rows": {"accounts": 1},
                   "audit_chains_checked": 0}
        custody.json_write(output / "backup-receipt.json", receipt)
        return receipt

    def native(self, cfg, arguments, stage, account=False):
        self.calls.append((stage, arguments, account))
        if stage == "bucket preflight":
            return json.dumps(self.bucket).encode()
        if stage == "bucket IAM preflight":
            return json.dumps(self.policy).encode()
        if stage == "account backup":
            self.assertTrue(account)
            self.assertEqual(arguments[arguments.index("--data-dir") + 1], str(self.source))
            self.backup(Path(arguments[arguments.index("--output-dir") + 1]))
        elif stage == "isolated rehearsal":
            self.assertTrue(account)
            bundle = Path(arguments[arguments.index("--backup-dir") + 1])
            output = custody.private_dir(Path(arguments[arguments.index("--output-dir") + 1]))
            self.assertNotEqual(output, self.source)
            receipt = custody.validate_bundle(bundle)
            report = {"status": "verified_isolated_restore", "backup_sha256": receipt["database_sha256"],
                      "table_rows": receipt["table_rows"], "production_modified": False, "keys_included": False,
                      "secret_versions_decrypted": 0, "totp_seeds_decrypted": 1}
            custody.json_write(output / "rehearsal-report.json", report)
        elif stage in ("immutable upload", "custody evidence upload"):
            self.assertIn("--if-generation-match=0", arguments)
            self.assertNotIn(arguments[4], self.objects)
            self.objects[arguments[4]] = Path(arguments[3]).read_bytes()
        elif stage == "copy verification download":
            self.assertIn("--do-not-decompress", arguments)
            Path(arguments[4]).write_bytes(self.objects[arguments[3]] + (b"tampered" if self.tamper else b""))
        elif stage == "archive encryption":
            # This fixture checks CLI wiring and copy verification, not age
            # cryptography. Real age/identity interoperability is a rollout gate.
            destination = Path(arguments[arguments.index("--output") + 1])
            destination.write_bytes(b"fixture-encrypted:" + Path(arguments[-1]).read_bytes())
        elif stage == "archive decryption rehearsal":
            destination = Path(arguments[arguments.index("--output") + 1])
            destination.write_bytes(Path(arguments[-1]).read_bytes().removeprefix(b"fixture-encrypted:"))
        else:
            self.fail("unexpected native stage: " + stage)
        return b""

    def test_default_preflight_never_executes_cloud_or_account(self):
        cfg_path = self.write("config.json", self.cfg)
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SCRIPT), "--config", str(cfg_path)]), patch.object(custody, "command") as native:
            with contextlib.redirect_stdout(output):
                self.assertEqual(custody.main(), 0)
            native.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["status"], "preflight_only")
        self.assertEqual(list(self.work.iterdir()), [])

    def test_same_project_and_same_admin_or_key_governance_fail(self):
        mutations = (
            ("destination", "project_number", "108687509435"),
            ("destination", "governance_id", "production-admins"),
            ("key_custody", "governance_id", "production-admins"),
            ("key_custody", "governance_id", "independent-backup-team"),
        )
        original = copy.deepcopy(self.cfg)
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                self.cfg = copy.deepcopy(original)
                self.cfg[section][field] = value
                with self.assertRaises(custody.CustodyError):
                    self.config()

    def test_expired_or_missing_historical_key_receipt_fails(self):
        self.key_receipt["historical_kek_versions"] = []
        self.write("keys.json", self.key_receipt)
        with self.assertRaisesRegex(custody.CustodyError, "historical KEK"):
            self.config()
        self.key_receipt["historical_kek_versions"] = ["legacy"]
        self.key_receipt["expires_at_utc"] = self.now
        self.write("keys.json", self.key_receipt)
        with self.assertRaisesRegex(custody.CustodyError, "expired"):
            self.config()

    def test_live_policy_requires_real_project_privacy_versioning_and_locked_retention(self):
        cfg = self.config()
        mutations = [("projectNumber", "108687509435"), ("versioning", {"enabled": False}),
                     ("retentionPolicy", {"isLocked": False, "retentionPeriod": "2592000"}),
                     ("retentionPolicy", {"isLocked": True, "retentionPeriod": "86400"}),
                     ("iamConfiguration", {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "inherited"})]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.bucket)
                changed[field] = value
                with self.assertRaises(custody.CustodyError):
                    custody.validate_bucket(cfg, changed, self.policy)
        for principal in ("allUsers", "allAuthenticatedUsers", "group:prod@example.test"):
            with self.subTest(principal=principal):
                policy = {"bindings": [{"members": [principal]}]}
                with self.assertRaises(custody.CustodyError):
                    custody.validate_bucket(cfg, self.bucket, policy)

    def test_success_copies_only_database_receipt_and_preserves_keys(self):
        cfg = self.config()
        before = {name: custody.digest(self.root / name) for name in ("kek", "totp", "keys.json")}
        source_before = custody.digest(self.source / "accounts.sqlite3")
        with patch.object(custody, "command", side_effect=self.native):
            report = custody.apply(cfg)
        self.assertEqual(report["status"], "verified_backup_copy_and_isolated_restore")
        self.assertFalse(report["keys_included"])
        self.assertFalse(report["account_metadata_client_encrypted"])
        self.assertEqual(before, {name: custody.digest(self.root / name) for name in before})
        self.assertEqual(source_before, custody.digest(self.source / "accounts.sqlite3"))
        self.assertEqual([stage for stage, _, _ in self.calls].count("isolated rehearsal"), 2)
        archive = next((self.work / report["run_id"]).glob("account-backup.tar.gz"))
        with tarfile.open(archive) as tar:
            self.assertEqual(set(tar.getnames()), {"accounts.sqlite3", "backup-receipt.json"})
        self.assertTrue(custody.status(cfg, self.now + 1)["healthy"])
        self.assertFalse(custody.status(cfg, self.now + 90001)["healthy"])
        self.assertEqual(custody.status(cfg, self.now + 90001)["status"], "stale")

    def test_download_tamper_retains_failure_and_never_runs_remote_drill(self):
        cfg = self.config()
        self.tamper = True
        with patch.object(custody, "command", side_effect=self.native):
            with self.assertRaisesRegex(custody.CustodyError, "checksum"):
                custody.apply(cfg)
        reports = list(self.work.glob("*/custody-run.json"))
        self.assertEqual(len(reports), 1)
        self.assertEqual(custody.json_load(reports[0])["status"], "failed")
        self.assertEqual([stage for stage, _, _ in self.calls].count("isolated rehearsal"), 1)
        self.assertEqual(custody.status(cfg)["status"], "failed")

    def test_insufficient_work_capacity_fails_before_backup_and_preserves_history(self):
        cfg = self.config()
        with patch.object(custody, "command", side_effect=self.native), patch.object(shutil, "disk_usage") as disk:
            disk.return_value.free = 0
            with self.assertRaisesRegex(custody.CustodyError, "free space"):
                custody.apply(cfg)
        self.assertNotIn("account backup", [stage for stage, _, _ in self.calls])
        self.assertEqual(custody.status(cfg)["status"], "failed")

    def test_configuration_change_invalidates_old_success(self):
        cfg = self.config()
        with patch.object(custody, "command", side_effect=self.native):
            custody.apply(cfg)
        cfg["destination"]["prefix"] = "new-destination-prefix"
        self.assertEqual(custody.status(cfg)["status"], "configuration_changed")

    def test_custodian_receipt_change_invalidates_old_success(self):
        cfg = self.config()
        with patch.object(custody, "command", side_effect=self.native):
            custody.apply(cfg)
        self.key_receipt["historical_kek_versions"].append("v3")
        self.write("keys.json", self.key_receipt)
        self.assertEqual(custody.status(cfg)["status"], "custody_attestation_changed")

    def test_missing_running_or_failed_evidence_is_unhealthy(self):
        cfg = self.config()
        self.assertEqual(custody.status(cfg)["status"], "never_completed")
        run = custody.private_dir(self.work / "fixture-interrupted")
        custody.json_write(run / "custody-run.json", {"started_at_utc": self.now, "configuration_sha256": custody.config_digest(cfg),
                                                     "status": "running"})
        self.assertFalse(custody.status(cfg)["healthy"])
        self.assertEqual(custody.status(cfg)["status"], "running")

    def test_archive_rejects_extra_keys_and_path_traversal(self):
        for name in ("kek", "../escaped.sqlite3"):
            with self.subTest(name=name):
                archive = self.root / "malicious.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    info = tarfile.TarInfo(name)
                    info.size = 4
                    tar.addfile(info, io.BytesIO(b"fake"))
                with self.assertRaisesRegex(custody.CustodyError, "unexpected entries"):
                    custody.unpack_bundle(archive, self.root / ("unpack-" + str(len(name))), 65536)
        self.assertFalse((self.root.parent / "escaped.sqlite3").exists())

    def test_archive_rejects_link_even_with_expected_names(self):
        archive = self.root / "links.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            link = tarfile.TarInfo("accounts.sqlite3")
            link.type = tarfile.SYMTYPE
            link.linkname = str(self.root / "kek")
            tar.addfile(link)
            receipt = tarfile.TarInfo("backup-receipt.json")
            receipt.size = 2
            tar.addfile(receipt, io.BytesIO(b"{}"))
        with self.assertRaisesRegex(custody.CustodyError, "link"):
            custody.unpack_bundle(archive, self.root / "unpacked-link", 65536)

    def test_unexpected_backup_entry_and_database_corruption_fail(self):
        bundle = self.root / "backup-fixture"
        self.backup(bundle)
        (bundle / "private-key").write_text("synthetic", encoding="utf-8")
        with self.assertRaisesRegex(custody.CustodyError, "unexpected files"):
            custody.validate_bundle(bundle)
        (bundle / "private-key").unlink()
        with (bundle / "accounts.sqlite3").open("ab") as handle:
            handle.write(b"corrupted")
        with self.assertRaisesRegex(custody.CustodyError, "receipt"):
            custody.validate_bundle(bundle)

    def test_overlapping_runs_cannot_proceed(self):
        with custody.run_lock(self.work):
            with self.assertRaisesRegex(custody.CustodyError, "active"):
                with custody.run_lock(self.work):
                    self.fail("second lock must fail")

    def test_optional_age_wires_encryption_and_download_decryption_without_archiving_identity(self):
        self.cfg["archive_encryption"] = {"age_binary": str(self.root / "age"), "recipient": "age1" + "q" * 58,
                                           "identity_file": str(self.root / "age-identity")}
        cfg = self.config()
        with patch.object(custody, "command", side_effect=self.native):
            result = custody.apply(cfg)
        self.assertTrue(result["account_metadata_client_encrypted"])
        self.assertTrue(result["destination_object"].endswith(".tar.gz.age"))
        self.assertEqual([stage for stage, _, _ in self.calls].count("archive encryption"), 1)
        self.assertEqual([stage for stage, _, _ in self.calls].count("archive decryption rehearsal"), 1)
        self.assertNotIn("synthetic fixture only", json.dumps(result))

    def configure_age(self, identity=True):
        self.cfg["archive_encryption"] = {"age_binary": str(self.root / "age"), "recipient": "age1" + "q" * 58,
                                           "identity_file": str(self.root / "age-identity") if identity else None}

    def test_upload_only_requires_encryption_and_never_reads_objects_or_age_identity(self):
        cfg = self.config()
        with self.assertRaisesRegex(custody.CustodyError, "requires age"):
            custody.apply(cfg, upload_only=True)
        self.configure_age(identity=False)
        cfg = self.config()
        with patch.object(custody, "command", side_effect=self.native):
            report = custody.apply(cfg, upload_only=True)
        self.assertEqual(report["status"], "uploaded_pending_independent_verification")
        self.assertFalse(report["copy_verified"])
        stages = [stage for stage, _, _ in self.calls]
        self.assertNotIn("copy verification download", stages)
        self.assertNotIn("archive decryption rehearsal", stages)
        self.assertEqual(stages.count("isolated rehearsal"), 1)
        self.assertTrue(custody.status(cfg, upload_stage=True)["healthy"])
        self.assertFalse(custody.status(cfg)["healthy"])

    def receiver_native(self, cfg, arguments, stage, account=False):
        if stage == "custody evidence listing":
            return "\n".join(uri for uri in self.objects if uri.endswith("custody-run.json")).encode()
        if stage == "custody object preflight":
            return json.dumps({"size": str(len(self.objects[arguments[4]]))}).encode()
        if stage == "custodian download":
            self.calls.append((stage, arguments, account))
            Path(arguments[4]).write_bytes(self.objects[arguments[3]])
            return b""
        if stage == "custodian archive decryption":
            self.calls.append((stage, arguments, account))
            Path(arguments[arguments.index("--output") + 1]).write_bytes(
                Path(arguments[-1]).read_bytes().removeprefix(b"fixture-encrypted:"))
            return b""
        return self.native(cfg, arguments, stage, account)

    def receiver_config(self):
        self.configure_age()
        self.cfg["data_dir"] = None
        self.cfg["work_dir"] = str(custody.private_dir(self.root / "receiver-work"))
        return custody.load_config(self.write("receiver-config.json", self.cfg), self.now, receiver=True)

    def test_independent_receiver_has_no_prod_path_or_cloud_write(self):
        self.configure_age(identity=False)
        producer_cfg = self.config()
        with patch.object(custody, "command", side_effect=self.native):
            producer = custody.apply(producer_cfg, upload_only=True)
        cfg = self.receiver_config()
        self.calls.clear()
        with patch.object(custody, "command", side_effect=self.receiver_native):
            verified = receiver.verify(cfg, latest=True)
        self.assertEqual(verified["status"], "verified_received_archive_and_isolated_restore")
        self.assertEqual(verified["archive_sha256"], producer["archive_sha256"])
        self.assertFalse(verified["production_modified"])
        self.assertFalse(verified["independent_custody_certified"])
        self.assertNotIn("account backup", [stage for stage, _, _ in self.calls])
        self.assertNotIn("immutable upload", [stage for stage, _, _ in self.calls])
        self.assertNotIn("custody evidence upload", [stage for stage, _, _ in self.calls])
        self.assertTrue(custody.status(cfg)["healthy"])

    def test_receiver_rejects_production_mount_and_unconfigured_objects(self):
        self.configure_age()
        with self.assertRaisesRegex(custody.CustodyError, "production data"):
            custody.load_config(self.write("receiver-invalid.json", self.cfg), self.now, receiver=True)
        cfg = self.receiver_config()
        for value in ("gs://outside/secret.age", cfg["destination"]["bucket"] + "/accounts/../escape.age"):
            with self.subTest(uri=value), self.assertRaises(custody.CustodyError):
                receiver.object_uri(cfg, value, "account-backup.tar.gz.age")

    def test_receiver_checksum_failure_never_decrypts_or_rehearses(self):
        self.configure_age(identity=False)
        with patch.object(custody, "command", side_effect=self.native):
            producer = custody.apply(self.config(), upload_only=True)
        cfg = self.receiver_config()
        self.calls.clear()
        with patch.object(custody, "command", side_effect=self.receiver_native):
            with self.assertRaisesRegex(custody.CustodyError, "checksum"):
                receiver.verify(cfg, producer["destination_object"], "0" * 64)
        self.assertNotIn("custodian archive decryption", [stage for stage, _, _ in self.calls])
        self.assertNotIn("isolated rehearsal", [stage for stage, _, _ in self.calls])
        self.assertEqual(custody.status(cfg)["status"], "failed")

    def provisioning_config(self):
        return {"schema_version": 1, "production_project_id": "gen-lang-client-0022105784",
                "production_project_number": "108687509435", "production_admin_principals": ["user:prod-admin@example.test"],
                "recovery_project_id": "cv-recovery-108687509435", "recovery_bucket_name": "cv-account-recovery-108687509435",
                "bucket_location": "EU", "retention_days": 30, "billing_account": "ABCDEF-123456-ABCDEF",
                "organization_id": None, "folder_id": None, "provisioner_account": "backup-admin@example.test",
                "custody_admin_principals": ["user:backup-admin@example.test"], "restore_principals": ["group:restore@example.test"],
                "offline_key_custodian_principals": ["group:offline-keys@example.test"],
                "production_uploader_principal": "serviceAccount:cv-web-runtime@gen-lang-client-0022105784.iam.gserviceaccount.com",
                "age_public_recipient": "age1" + "q" * 58, "governance_review_reference": "fixture-governance-review",
                "independence_reviewed": True, "review_expires_at_utc": self.now + 86400}

    def test_provisioning_plan_never_executes_and_grants_no_object_read_to_production(self):
        with patch.object(subprocess, "run") as native:
            plan = provisioning.plan(self.provisioning_config(), self.now)
            native.assert_not_called()
        self.assertFalse(plan["cloud_mutated"])
        self.assertEqual(plan["retention_days"], 30)
        self.assertEqual(plan["bucket_location"], "EU")
        self.assertEqual(plan["archive_encryption"], "age_x25519")
        grants = [step["argv"] for step in plan["commands"] if "--member=" + self.provisioning_config()["production_uploader_principal"] in step["argv"]]
        self.assertEqual(len(grants), 2)
        self.assertTrue(any("--role=roles/storage.objectCreator" in command for command in grants))
        self.assertFalse(any("--role=roles/storage.objectViewer" in command or "--role=roles/owner" in command for command in grants))
        self.assertEqual([step["phase"] for step in plan["commands"]].count("irreversible_retention_lock"), 1)
        self.assertTrue(all(not step["execute_automatically"] for step in plan["commands"]))

    def test_provisioning_requires_distinct_real_owner_identity_and_current_review(self):
        original = self.provisioning_config()
        mutations = [("production_admin_principals", ["user:backup-admin@example.test"]),
                     ("offline_key_custodian_principals", ["group:restore@example.test"]),
                     ("provisioner_account", "invented-placeholder"), ("independence_reviewed", False),
                     ("review_expires_at_utc", self.now), ("recovery_project_id", original["production_project_id"])]
        for field, value in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed[field] = value
                with self.assertRaises(custody.CustodyError):
                    provisioning.plan(changed, self.now)
        example = custody.json_load(SCRIPT.with_name("provisioning.example.json"))
        with self.assertRaises(custody.CustodyError):
            provisioning.plan(example, self.now)

    def test_sensitive_native_output_is_suppressed_and_account_env_is_stripped(self):
        cfg = self.config()
        with patch.dict(os.environ, {"CIPHERVAULT_ACCOUNT_LOCAL_KEK": "PRIVATE_KEY"}), patch.object(subprocess, "Popen", wraps=subprocess.Popen) as native:
            with self.assertRaises(custody.CustodyError) as caught:
                custody.command(cfg, [sys.executable, "-c", "import sys;sys.stdout.write('PRIVATE_VALUE');sys.stderr.write('PRIVATE_KEY');sys.exit(1)"], "fixture command", account=True)
            self.assertNotIn("PRIVATE", str(caught.exception))
            self.assertNotIn("CIPHERVAULT_ACCOUNT_LOCAL_KEK", native.call_args.kwargs["env"])

    def test_native_output_is_capped_during_capture(self):
        cfg = self.config()
        started = time.monotonic()
        with self.assertRaisesRegex(custody.CustodyError, "output exceeds limit"):
            custody.command(cfg, [sys.executable, "-u", "-c", "import sys,time;sys.stdout.buffer.write(b'x'*2097152);time.sleep(20)"], "listing")
        self.assertLess(time.monotonic() - started, 5)

    def test_native_timeout_is_bounded(self):
        cfg = self.config()
        cfg["timeout_seconds"] = 1
        started = time.monotonic()
        with self.assertRaisesRegex(custody.CustodyError, "timed out"):
            custody.command(cfg, [sys.executable, "-c", "import time;time.sleep(20)"], "listing")
        self.assertLess(time.monotonic() - started, 5)

    def test_archive_rejects_third_header_without_enumerating_history(self):
        archive = self.root / "many-entries.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for name in ["accounts.sqlite3", "backup-receipt.json", *[f"extra-{i}" for i in range(4096)]]:
                tar.addfile(tarfile.TarInfo(name))
        with gzip.open(archive, "rb") as stream:
            with patch.object(stream, "read", wraps=stream.read) as reads, patch.object(custody.gzip, "open", return_value=stream):
                with self.assertRaisesRegex(custody.CustodyError, "unexpected entries"):
                    custody.unpack_bundle(archive, self.root / "many-output", 65536)
                self.assertEqual(sum(call.args[0] for call in reads.call_args_list), 1536)

    def test_archive_rejects_oversized_and_extended_headers_before_body_read(self):
        for kind in (tarfile.REGTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("accounts.sqlite3")
                info.type, info.size = kind, 2 * 1024 * 1024
                archive = self.root / (kind.decode("ascii") + "-oversized.tar.gz")
                with gzip.open(archive, "wb") as output:
                    output.write(info.tobuf(format=tarfile.USTAR_FORMAT) + bytes(info.size))
                with gzip.open(archive, "rb") as stream:
                    with patch.object(stream, "read", wraps=stream.read) as reads, patch.object(custody.gzip, "open", return_value=stream):
                        with self.assertRaisesRegex(custody.CustodyError, "excessive entry"):
                            custody.unpack_bundle(archive, self.root / (kind.decode("ascii") + "-output"), 65536)
                        self.assertEqual(sum(call.args[0] for call in reads.call_args_list), 512)

    def test_archive_expanded_bytes_are_aggregate_and_padding_is_bounded(self):
        archive = self.root / "aggregate.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for name in ("accounts.sqlite3", "backup-receipt.json"):
                info = tarfile.TarInfo(name)
                info.size = 4
                tar.addfile(info, io.BytesIO(b"test"))
        with self.assertRaisesRegex(custody.CustodyError, "excessive entry"):
            custody.unpack_bundle(archive, self.root / "aggregate-output", 6)
        with gzip.open(archive, "rb") as stream:
            content = stream.read()
        with gzip.open(archive, "wb") as stream:
            stream.write(content + bytes(1024 * 1024))
        with self.assertRaisesRegex(custody.CustodyError, "trailing data"):
            custody.unpack_bundle(archive, self.root / "padding-output", 65536)

    def test_json_duplicates_and_unknown_config_fields_fail(self):
        duplicate = self.write("duplicate.json", '{"field":1,"field":2}')
        with self.assertRaisesRegex(custody.CustodyError, "duplicate"):
            custody.json_load(duplicate)
        self.cfg["raw_key"] = "never-allowed"
        with self.assertRaisesRegex(custody.CustodyError, "unknown"):
            self.config()


class NativePermissionCheck(unittest.TestCase):
    def test_private_output_has_real_platform_permissions(self):
        with tempfile.TemporaryDirectory(prefix="cv-custody-permission-") as temporary:
            root = Path(temporary).resolve()
            output = custody.private_dir(root / "protected")
            custody.json_write(output / "report.json", {"synthetic": True})
            custody.private(output)
            custody.private(output / "report.json")


class RealAccountCliCheck(unittest.TestCase):
    def test_real_offline_backup_and_downloaded_rehearsal_without_http(self):
        binary = os.environ.get("CIPHERVAULT_ACCOUNT_TEST_BINARY")
        if not binary:
            candidate = SCRIPT.parents[2] / "target" / "debug" / ("ciphervault-account.exe" if os.name == "nt" else "ciphervault-account")
            if candidate.is_file():
                binary = str(candidate)
        if not binary:
            self.skipTest("set CIPHERVAULT_ACCOUNT_TEST_BINARY to an existing compiled account binary")
        binary = str(Path(binary).resolve())
        with tempfile.TemporaryDirectory(prefix="cv-custody-real-account-") as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            env = {key: value for key, value in os.environ.items() if not key.upper().startswith("CIPHERVAULT_")}
            env.update(CIPHERVAULT_ACCOUNT_DATA_DIR=str(source), CIPHERVAULT_ACCOUNT_BIND="invalid-fixture-bind")
            initialized = subprocess.run([binary], env=env, capture_output=True, timeout=30, check=False)
            self.assertNotEqual(initialized.returncode, 0, "invalid bind must never start an HTTP server")
            self.assertTrue((source / "accounts.sqlite3").is_file())
            cfg = {"account_binary": binary, "timeout_seconds": 30, "kek_file": None, "totp_key_file": None}
            backup = root / "backup"
            custody.command(cfg, [binary, "backup", "--data-dir", str(source), "--output-dir", str(backup)], "real backup", account=True)
            original = custody.digest(source / "accounts.sqlite3")
            archive = root / "backup.tar.gz"
            custody.archive_bundle(backup, archive)
            receipt = custody.validate_bundle(backup)
            downloaded = root / "downloaded-backup"
            custody.unpack_bundle(archive, downloaded, receipt["database_bytes"] + 65536)
            report = custody.rehearse(cfg, downloaded, root / "rehearsal")
            self.assertFalse(report["production_modified"])
            self.assertFalse(report["keys_included"])
            self.assertEqual(custody.digest(source / "accounts.sqlite3"), original)


if __name__ == "__main__":
    unittest.main()
