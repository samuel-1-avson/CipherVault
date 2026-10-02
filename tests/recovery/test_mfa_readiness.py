"""Synthetic fixtures for the offline MFA readiness report; no live data used."""

import hashlib
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "recovery" / "mfa_readiness.py"
SPEC = importlib.util.spec_from_file_location("mfa_readiness", SCRIPT)
readiness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readiness)


SCHEMA = """
CREATE TABLE accounts(account_id TEXT PRIMARY KEY, display_name TEXT,
    account_public_key_hex TEXT, created_at_utc INTEGER);
CREATE TABLE account_mfa_policy(account_id TEXT PRIMARY KEY,
    required INTEGER NOT NULL, updated_at_utc INTEGER NOT NULL);
CREATE TABLE totp_credentials(account_id TEXT PRIMARY KEY,
    secret_ciphertext_b64 TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
    created_at_utc INTEGER NOT NULL, last_used_step INTEGER,
    last_used_at_utc INTEGER, revoked_at_utc INTEGER);
CREATE TABLE webauthn_credentials(account_id TEXT NOT NULL,
    credential_id_hex TEXT NOT NULL, device_id_hex TEXT, algorithm INTEGER NOT NULL,
    public_key_hex TEXT NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0,
    created_at_utc INTEGER NOT NULL, last_used_at_utc INTEGER,
    revoked_at_utc INTEGER, PRIMARY KEY (account_id, credential_id_hex));
CREATE TABLE recovery_codes(account_id TEXT NOT NULL,
    code_hash_hex TEXT PRIMARY KEY, created_at_utc INTEGER NOT NULL,
    used_at_utc INTEGER);
CREATE TABLE sessions(token_hash_hex TEXT PRIMARY KEY, account_id TEXT NOT NULL,
    device_id_hex TEXT, credential_id_hex TEXT, session_kind TEXT NOT NULL,
    issued_at_utc INTEGER NOT NULL, expires_at_utc INTEGER NOT NULL,
    revoked_at_utc INTEGER);
"""


class ReadinessFixtures(unittest.TestCase):
    NOW = 1790000000

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cv-mfa-readiness-")
        self.db_path = Path(self.temporary.name) / "offline-copy.sqlite3"
        db = sqlite3.connect(self.db_path)
        db.executescript(SCHEMA)
        # enforced_ready: required + active TOTP + unused codes + live session.
        db.execute("INSERT INTO accounts VALUES('a-enforced','Enforced','pk',1)")
        db.execute("INSERT INTO account_mfa_policy VALUES('a-enforced',1,2)")
        db.execute(
            "INSERT INTO totp_credentials VALUES('a-enforced','SYNTHETIC-SEED-CIPHERTEXT',"
            "1,3,NULL,NULL,NULL)"
        )
        db.execute(
            "INSERT INTO recovery_codes VALUES('a-enforced','SYNTHETIC-CODE-HASH',4,NULL)"
        )
        db.execute(
            "INSERT INTO sessions VALUES('tok1','a-enforced',NULL,NULL,'device',"
            f"{self.NOW - 10},{self.NOW + 3600},NULL)"
        )
        # enforced_no_factor: required but revoked factor (lockout signal).
        db.execute("INSERT INTO accounts VALUES('a-locked','Locked','pk',1)")
        db.execute("INSERT INTO account_mfa_policy VALUES('a-locked',1,2)")
        db.execute(
            "INSERT INTO totp_credentials VALUES('a-locked','old',1,3,NULL,NULL,5)"
        )
        # ready_to_enable: no policy row yet, WebAuthn factor + unused codes.
        db.execute("INSERT INTO accounts VALUES('a-ready','Ready','pk',1)")
        db.execute(
            "INSERT INTO webauthn_credentials VALUES('a-ready','cred1',NULL,-7,'pk',0,"
            "3,NULL,NULL)"
        )
        db.execute(
            "INSERT INTO recovery_codes VALUES('a-ready','h1',4,NULL)"
        )
        # blocked_no_factor: nothing enrolled.
        db.execute("INSERT INTO accounts VALUES('a-bare','Bare','pk',1)")
        # blocked_no_recovery_codes: factor present, only used codes.
        db.execute("INSERT INTO accounts VALUES('a-nocodes','NoCodes','pk',1)")
        db.execute(
            "INSERT INTO totp_credentials VALUES('a-nocodes','seed',1,3,NULL,NULL,NULL)"
        )
        db.execute("INSERT INTO recovery_codes VALUES('a-nocodes','h2',4,5)")
        # Expired and revoked sessions must not count as active.
        db.execute(
            "INSERT INTO sessions VALUES('tok-old','a-ready',NULL,NULL,'device',1,"
            f"{self.NOW - 5},NULL)"
        )
        db.execute(
            "INSERT INTO sessions VALUES('tok-rev','a-ready',NULL,NULL,'device',"
            f"{self.NOW - 10},{self.NOW + 3600},{self.NOW})"
        )
        db.commit()
        db.close()

    def tearDown(self):
        self.temporary.cleanup()

    def verdicts(self):
        report = readiness.readiness_report(str(self.db_path), now=self.NOW)
        return report, {a["account_id"]: a for a in report["accounts"]}

    def test_verdicts_cover_rollout_states(self):
        report, by_id = self.verdicts()
        self.assertEqual(report["account_count"], 5)
        self.assertEqual(by_id["a-enforced"]["verdict"], "enforced_ready")
        self.assertEqual(by_id["a-locked"]["verdict"], "enforced_no_factor")
        self.assertEqual(by_id["a-ready"]["verdict"], "ready_to_enable")
        self.assertEqual(by_id["a-bare"]["verdict"], "blocked_no_factor")
        self.assertEqual(by_id["a-nocodes"]["verdict"], "blocked_no_recovery_codes")
        self.assertFalse(report["all_enforced_ready"])
        self.assertEqual(
            report["summary"],
            {
                "enforced_ready": 1,
                "enforced_no_factor": 1,
                "ready_to_enable": 1,
                "blocked_no_factor": 1,
                "blocked_no_recovery_codes": 1,
            },
        )

    def test_counts_exclude_revoked_used_and_expired(self):
        _, by_id = self.verdicts()
        self.assertEqual(by_id["a-enforced"]["totp_active"], 1)
        self.assertEqual(by_id["a-locked"]["totp_active"], 0)
        self.assertEqual(by_id["a-ready"]["webauthn_active"], 1)
        self.assertEqual(by_id["a-ready"]["active_sessions"], 0)
        self.assertEqual(by_id["a-nocodes"]["unused_recovery_codes"], 0)

    def test_default_policy_is_not_required(self):
        _, by_id = self.verdicts()
        self.assertFalse(by_id["a-ready"]["mfa_required"])
        self.assertFalse(by_id["a-bare"]["mfa_required"])

    def test_output_contains_no_secret_material(self):
        report, _ = self.verdicts()
        dumped = json.dumps(report)
        self.assertNotIn("SYNTHETIC-SEED-CIPHERTEXT", dumped)
        self.assertNotIn("SYNTHETIC-CODE-HASH", dumped)
        self.assertNotIn("tok1", dumped)

    def test_source_copy_is_unmodified(self):
        before = hashlib.sha256(self.db_path.read_bytes()).hexdigest()
        readiness.readiness_report(str(self.db_path), now=self.NOW)
        after = hashlib.sha256(self.db_path.read_bytes()).hexdigest()
        self.assertEqual(before, after)

    def test_check_gate_passes_only_when_all_enforced(self):
        with patch("sys.stdout", new_callable=StringIO), patch(
            "sys.stderr", new_callable=StringIO
        ):
            self.assertEqual(readiness.main([str(self.db_path), "--check"]), 1)
        solo = Path(self.temporary.name) / "solo.sqlite3"
        db = sqlite3.connect(solo)
        db.executescript(SCHEMA)
        db.execute("INSERT INTO accounts VALUES('only','Only','pk',1)")
        db.execute("INSERT INTO account_mfa_policy VALUES('only',1,2)")
        db.execute(
            "INSERT INTO totp_credentials VALUES('only','seed',1,3,NULL,NULL,NULL)"
        )
        db.commit()
        db.close()
        with patch("sys.stdout", new_callable=StringIO):
            self.assertEqual(readiness.main([str(solo), "--check"]), 0)

    def test_missing_tables_fail_closed(self):
        other = Path(self.temporary.name) / "other.sqlite3"
        db = sqlite3.connect(other)
        db.execute("CREATE TABLE fixture(value TEXT)")
        db.commit()
        db.close()
        with patch("sys.stdout", new_callable=StringIO), patch(
            "sys.stderr", new_callable=StringIO
        ):
            self.assertEqual(readiness.main([str(other)]), 2)

    def test_missing_file_fails_closed(self):
        with patch("sys.stdout", new_callable=StringIO), patch(
            "sys.stderr", new_callable=StringIO
        ):
            self.assertEqual(
                readiness.main([str(Path(self.temporary.name) / "absent.sqlite3")]), 2
            )


if __name__ == "__main__":
    unittest.main()
