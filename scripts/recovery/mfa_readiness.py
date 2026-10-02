"""Offline MFA rollout-readiness report for account database copies.

Reads an OFFLINE copy (stopped snapshot or extracted backup database) in
read-only mode and reports per-account MFA state. Never point this at the live
production database file. Output contains only counts and booleans plus
account identifiers; no secret material, seeds, or code hashes are printed.
"""

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path


REQUIRED_TABLES = (
    "accounts",
    "account_mfa_policy",
    "totp_credentials",
    "webauthn_credentials",
    "recovery_codes",
    "sessions",
)


def open_offline(path):
    real = Path(path).resolve()
    if not real.is_file():
        raise ValueError(f"database copy not found: {path}")
    db = sqlite3.connect(f"file:{real}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


def readiness_report(db_path, now=None):
    """Return a JSON-serializable readiness report for the offline copy."""
    now = int(time.time()) if now is None else now
    db = open_offline(db_path)
    try:
        present = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        missing = [t for t in REQUIRED_TABLES if t not in present]
        if missing:
            raise ValueError(
                "not an account database copy; missing tables: "
                + ", ".join(sorted(missing))
            )
        accounts = []
        for row in db.execute(
            "SELECT account_id, display_name FROM accounts ORDER BY account_id"
        ):
            account_id = row["account_id"]
            required = db.execute(
                "SELECT required FROM account_mfa_policy WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            required = bool(required[0]) if required else False
            totp_active = db.execute(
                """SELECT COUNT(*) FROM totp_credentials
                   WHERE account_id = ? AND enabled = 1
                   AND revoked_at_utc IS NULL""",
                (account_id,),
            ).fetchone()[0]
            webauthn_active = db.execute(
                """SELECT COUNT(*) FROM webauthn_credentials
                   WHERE account_id = ? AND revoked_at_utc IS NULL""",
                (account_id,),
            ).fetchone()[0]
            unused_codes = db.execute(
                """SELECT COUNT(*) FROM recovery_codes
                   WHERE account_id = ? AND used_at_utc IS NULL""",
                (account_id,),
            ).fetchone()[0]
            active_sessions = db.execute(
                """SELECT COUNT(*) FROM sessions
                   WHERE account_id = ? AND revoked_at_utc IS NULL
                   AND expires_at_utc > ?""",
                (account_id, now),
            ).fetchone()[0]
            factors = totp_active + webauthn_active
            if required and factors > 0:
                verdict = "enforced_ready"
            elif required:
                verdict = "enforced_no_factor"
            elif factors == 0:
                verdict = "blocked_no_factor"
            elif unused_codes == 0:
                verdict = "blocked_no_recovery_codes"
            else:
                verdict = "ready_to_enable"
            accounts.append(
                {
                    "account_id": account_id,
                    "display_name": row["display_name"],
                    "mfa_required": required,
                    "totp_active": totp_active,
                    "webauthn_active": webauthn_active,
                    "unused_recovery_codes": unused_codes,
                    "active_sessions": active_sessions,
                    "verdict": verdict,
                }
            )
    finally:
        db.close()
    summary = {}
    for entry in accounts:
        summary[entry["verdict"]] = summary.get(entry["verdict"], 0) + 1
    return {
        "source": str(Path(db_path).resolve()),
        "generated_at_utc": now,
        "account_count": len(accounts),
        "summary": summary,
        "all_enforced_ready": bool(accounts)
        and all(a["verdict"] == "enforced_ready" for a in accounts),
        "accounts": accounts,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Report MFA rollout readiness from an offline account DB copy."
    )
    parser.add_argument("database", help="path to the offline database copy")
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 unless every account is enforced with an active factor",
    )
    args = parser.parse_args(argv)
    try:
        report = readiness_report(args.database)
    except (ValueError, sqlite3.Error) as error:
        print(f"mfa_readiness: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.check and not report["all_enforced_ready"]:
        print(
            "mfa_readiness: rollout gate not satisfied "
            f"(summary={json.dumps(report['summary'], sort_keys=True)})",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
