#!/usr/bin/env python3
"""Custodian-side archive download/decryption/isolated rehearsal; no upload.

Use a separately controlled host/configuration. Default is local preflight;
--verify-latest or an explicit object+checksum performs read-only cloud work
and writes only new private local evidence. No production data path is accepted.
"""

import argparse
import json
from pathlib import Path
import re
import sys
import time
import uuid

import account_custody as custody


def object_uri(cfg, value, basename):
    prefix = cfg["destination"]["bucket"] + "/" + cfg["destination"]["prefix"] + "/"
    custody.require(isinstance(value, str) and value.startswith(prefix), "object is outside configured custody destination")
    remainder = value[len(prefix):]
    custody.require(re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}/" + re.escape(basename), remainder),
                    "custody object path is invalid")
    return value


def download(cfg, uri, output, ceiling):
    metadata = custody.cloud_json(cfg, ["storage", "objects", "describe", uri, "--raw"], "custody object preflight")
    try:
        size = int(metadata.get("size", -1))
    except (TypeError, ValueError):
        raise custody.CustodyError("custody object size is invalid") from None
    custody.require(0 < size <= ceiling, "custody object exceeds size ceiling")
    with output.open("xb"):
        custody.private(output, True)
    custody.command(cfg, [cfg["gcloud_binary"], "storage", "cp", uri, str(output), "--do-not-decompress", "--quiet"],
                    "custodian download")
    custody.private(custody.checked_path(str(output)), True)
    custody.require(output.stat().st_size == size, "custody download size does not match")


def newest_receipt(cfg):
    pattern = cfg["destination"]["bucket"] + "/" + cfg["destination"]["prefix"] + "/*/custody-run.json"
    raw = custody.command(cfg, [cfg["gcloud_binary"], "storage", "ls", pattern, "--quiet"], "custody evidence listing")
    custody.require(len(raw) <= 1024 * 1024, "custody evidence listing exceeds limit")
    try:
        entries = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
    except UnicodeError:
        raise custody.CustodyError("custody evidence listing is invalid") from None
    custody.require(bool(entries), "no custody upload evidence is available")
    for entry in entries:
        object_uri(cfg, entry, "custody-run.json")
    return sorted(entries)[-1]


def verify(cfg, uri=None, expected=None, latest=False):
    encryption = cfg["archive_encryption"]
    custody.require(encryption is not None and encryption["identity_file"] is not None,
                    "receiver requires a custodian age identity")
    root = custody.checked_path(cfg["work_dir"], True)
    with custody.run_lock(root):
        started = int(time.time())
        run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started)) + "-" + uuid.uuid4().hex
        run = custody.private_dir(root / run_id)
        report = {"schema_version": 1, "run_id": run_id, "started_at_utc": started, "status": "running",
                  "configuration_sha256": custody.config_digest(cfg), "keys_included": False,
                  "production_modified": False, "independent_custody_certified": False,
                  "verification_host_role": "configured_custodian"}
        custody.json_write(run / "custody-run.json", report)
        try:
            report.update(custody.destination_preflight(cfg))
            if latest:
                evidence_uri = newest_receipt(cfg)
                evidence_path = run / "producer-evidence.json"
                download(cfg, evidence_uri, evidence_path, 65536)
                evidence = custody.json_load(evidence_path)
                custody.require(evidence.get("status") == "uploaded_pending_independent_verification" and
                                evidence.get("archive_encryption") == "age_x25519" and evidence.get("keys_included") is False,
                                "producer evidence does not describe an encrypted pending custody copy")
                uri, expected = evidence.get("destination_object"), evidence.get("archive_sha256")
                custody.require(isinstance(uri, str) and uri.rsplit("/", 1)[0] == evidence_uri.rsplit("/", 1)[0],
                                "producer evidence points outside its own run")
            uri = object_uri(cfg, uri, "account-backup.tar.gz.age")
            custody.require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected),
                            "expected archive SHA-256 is required")
            custody.require_work_capacity(cfg, cfg["max_artifact_bytes"])
            encrypted = run / "received.tar.gz.age"
            download(cfg, uri, encrypted, cfg["max_artifact_bytes"])
            custody.require(custody.digest(encrypted) == expected, "custody archive checksum does not match")
            decrypted = run / "decrypted.tar.gz"
            custody.command(cfg, [encryption["age_binary"], "--decrypt", "--identity", encryption["identity_file"],
                                  "--output", str(decrypted), str(encrypted)], "custodian archive decryption")
            custody.private(custody.checked_path(str(decrypted)), True)
            custody.require(decrypted.stat().st_size <= cfg["max_artifact_bytes"], "decrypted archive exceeds size ceiling")
            bundle = run / "received-backup"
            receipt = custody.unpack_bundle(decrypted, bundle, cfg["max_artifact_bytes"])
            drill = custody.rehearse(cfg, bundle, run / "isolated-rehearsal")
            report.update(status="verified_received_archive_and_isolated_restore", destination_object=uri,
                          archive_sha256=expected, database_sha256=receipt["database_sha256"],
                          backup_created_at_utc=receipt["created_at_utc"], completed_at_utc=int(time.time()),
                          archive_encryption="age_x25519", account_metadata_client_encrypted=True, copy_verified=True,
                          secret_versions_decrypted=drill["secret_versions_decrypted"], totp_seeds_decrypted=drill["totp_seeds_decrypted"],
                          destination_attestation_sha256=custody.digest(Path(cfg["destination"]["attestation_file"])),
                          key_custody_receipt_sha256=custody.digest(Path(cfg["key_custody"]["receipt_file"])))
            custody.json_write(run / "custody-run.json", report)
            return report
        except Exception as error:
            report.update(status="failed", completed_at_utc=int(time.time()),
                          error=str(error) if isinstance(error, custody.CustodyError) else "custody receiver failed; details suppressed")
            custody.json_write(run / "custody-run.json", report)
            raise custody.CustodyError(report["error"]) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--verify-latest", action="store_true")
    action.add_argument("--object", help="specific archive URI; requires --expected-sha256")
    action.add_argument("--status", action="store_true")
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    try:
        custody.require(bool(args.object) == bool(args.expected_sha256),
                        "an explicit object and its expected checksum must be supplied together")
        cfg = custody.load_config(args.config, receiver=True)
        if args.verify_latest or args.object:
            result = verify(cfg, args.object, args.expected_sha256, args.verify_latest)
        elif args.status:
            result = custody.status(cfg)
        else:
            result = {"status": "receiver_preflight_only", "cloud_mutated": False, "independent_custody_certified": False}
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("healthy", True) else 1
    except Exception as error:
        message = str(error) if isinstance(error, custody.CustodyError) else "custody receiver preflight failed; details suppressed"
        print(json.dumps({"status": "failed", "error": message}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
