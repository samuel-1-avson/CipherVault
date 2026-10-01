#!/usr/bin/env python3
"""Private, fail-closed account backup/copy/rehearsal runner (stdlib only).

The default command is an offline configuration preflight. --online only reads
destination policy. --apply is the explicit backup/upload/rehearsal operation.
No keys are archived, no history is removed, and no cloud policy is changed.
"""

import argparse
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid


class CustodyError(Exception):
    """Only fixed, non-sensitive descriptions may be returned to operators."""


def require(condition, message):
    if not condition:
        raise CustodyError(message)


def checked_path(value, directory=False):
    require(isinstance(value, str) and os.path.isabs(value), "paths must be absolute")
    path = Path(os.path.abspath(value))
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                    "paths cannot contain symlinks or reparse points")
        require(path.is_dir() if directory else path.is_file(), "required path has wrong type")
    except OSError:
        raise CustodyError("required path is unavailable") from None
    return path


def windows_acl(path, protect=False):
    # Touch only the DACL; setting a whole security descriptor through Set-Acl
    # can unnecessarily require SeSecurityPrivilege on Windows directories.
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(wintypes.DWORD)]
    advapi.GetSecurityDescriptorDacl.argtypes = [pointer, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(pointer), ctypes.POINTER(wintypes.BOOL)]
    advapi.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, pointer, pointer, pointer, pointer]
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer)]
    advapi.GetSecurityDescriptorControl.argtypes = [pointer, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    advapi.GetAclInformation.argtypes = [pointer, pointer, wintypes.DWORD, wintypes.DWORD]
    advapi.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [pointer]

    def sid_text(sid):
        text = wintypes.LPWSTR()
        require(advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)), "Windows SID lookup failed")
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, pointer))

    token = wintypes.HANDLE()
    require(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)), "Windows token lookup failed")
    try:
        length = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        buffer = ctypes.create_string_buffer(length.value)
        require(advapi.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)), "Windows token lookup failed")
        user = sid_text(ctypes.cast(buffer, ctypes.POINTER(pointer)).contents)
    finally:
        kernel.CloseHandle(token)
    allowed = {user, "S-1-5-18", "S-1-5-32-544"}
    if protect:
        flags = "OICI" if path.is_dir() else ""
        sddl = "D:P" + "".join("(A;" + flags + ";FA;;;" + sid + ")" for sid in sorted(allowed))
        descriptor = pointer()
        require(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None),
                "private Windows DACL creation failed")
        try:
            present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), pointer()
            require(advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)),
                    "private Windows DACL creation failed")
            require(advapi.SetNamedSecurityInfoW(str(path), 1, 4 | 0x80000000, None, None, dacl, None) == 0,
                    "private Windows DACL protection failed")
        finally:
            kernel.LocalFree(descriptor)
    owner, dacl, descriptor = pointer(), pointer(), pointer()
    require(advapi.GetNamedSecurityInfoW(str(path), 1, 1 | 4, ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                        ctypes.byref(descriptor)) == 0, "private Windows DACL lookup failed")
    try:
        control, revision = wintypes.WORD(), wintypes.DWORD()
        require(advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)) and
                control.value & 0x1000 and sid_text(owner) in allowed and dacl.value,
                "private Windows owner or DACL verification failed")
        class AclSize(ctypes.Structure):
            _fields_ = [("count", wintypes.DWORD), ("used", wintypes.DWORD), ("free", wintypes.DWORD)]
        info = AclSize()
        require(advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2), "Windows ACL enumeration failed")
        for index in range(info.count):
            ace = pointer()
            require(advapi.GetAce(dacl, index, ctypes.byref(ace)), "Windows ACL enumeration failed")
            kind = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte)).contents.value
            if kind == 1:  # A denial cannot expand access.
                continue
            require(kind == 0 and sid_text(pointer(ace.value + 8)) in allowed,
                    "private Windows DACL grants access to an unapproved principal")
    finally:
        kernel.LocalFree(descriptor)


def private(path, protect=False):
    if os.name == "nt":
        windows_acl(path, protect)
    else:
        if protect:
            path.chmod(0o700 if path.is_dir() else 0o600)
        info = path.stat()
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "private paths must be owner-only")


def private_dir(path):
    path.mkdir(mode=0o700)
    private(path, True)
    return path


def json_load(path):
    checked_path(str(path))
    require(path.stat().st_size <= 65536, "JSON document exceeds 64 KiB")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, "JSON contains duplicate fields")
                result[key] = value
            return result
        result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise CustodyError("JSON document is malformed") from None
    require(isinstance(result, dict), "JSON document must be an object")
    return result


def json_write(path, value):
    # A sibling file and atomic replacement publish the report only after fsync.
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("x", encoding="utf-8") as handle:
        private(temporary, True)
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def digest(path):
    checked_path(str(path))
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def positive_int(value, minimum, maximum, message):
    require(type(value) is int and minimum <= value <= maximum, message)
    return value


def label(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,191}", value),
            "custody labels must be non-empty identifiers")
    return value


def load_config(path, now=None, receiver=False):
    path = checked_path(str(path))
    private(path)
    cfg = json_load(path)
    require(set(cfg) == {"schema_version", "production_project_number", "production_governance_id",
                        "production_principals", "account_binary", "gcloud_binary", "data_dir", "work_dir",
                        "kek_file", "totp_key_file", "max_backup_age_seconds", "max_artifact_bytes", "timeout_seconds",
                        "destination", "key_custody", "archive_encryption"}, "configuration fields are incomplete or unknown")
    require(cfg["schema_version"] == 1, "unsupported configuration version")
    production = label(cfg["production_governance_id"])
    require(isinstance(cfg["production_project_number"], str) and
            re.fullmatch(r"[1-9][0-9]{5,20}", cfg["production_project_number"]), "production project number is required")
    principals = cfg["production_principals"]
    require(isinstance(principals, list) and len(principals) > 0 and all(isinstance(p, str) and
            re.fullmatch(r"(?:user|group|serviceAccount|domain|principal|principalSet):\S+", p) for p in principals),
            "production admin principals must be explicitly listed")
    for key in ("account_binary", "gcloud_binary"):
        checked_path(cfg[key])
    source = None
    if not receiver:
        source = checked_path(cfg["data_dir"], True)
        checked_path(str(source / "accounts.sqlite3"))
    else:
        require(cfg["data_dir"] is None, "custodian receiver must not configure a production data directory")
    work = checked_path(cfg["work_dir"], True)
    private(work)
    require(source is None or (source != work and source not in work.parents and work not in source.parents),
            "work directory must be separate from production data")
    for key in ("kek_file", "totp_key_file"):
        if cfg[key] is not None:
            private(checked_path(cfg[key]))
    positive_int(cfg["max_backup_age_seconds"], 60, 604800, "backup freshness threshold is invalid")
    positive_int(cfg["max_artifact_bytes"], 65536, 1024 ** 4, "artifact size ceiling is invalid")
    positive_int(cfg["timeout_seconds"], 30, 7200, "command timeout is invalid")
    dest = cfg["destination"]
    require(isinstance(dest, dict) and set(dest) == {"bucket", "prefix", "project_number", "governance_id",
            "min_retention_days", "attestation_file"}, "destination fields are incomplete or unknown")
    require(isinstance(dest["bucket"], str) and re.fullmatch(r"gs://[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", dest["bucket"]),
            "destination must be an explicit GCS bucket without an object path")
    require(isinstance(dest["project_number"], str) and re.fullmatch(r"[1-9][0-9]{5,20}", dest["project_number"]) and
            dest["project_number"] != cfg["production_project_number"], "same-project custody is not independent")
    require(label(dest["governance_id"]) != production, "backup governance must differ from production governance")
    require(isinstance(dest["prefix"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_/-]{0,127}", dest["prefix"]) and
            "//" not in dest["prefix"] and not dest["prefix"].endswith("/"), "object prefix is invalid")
    positive_int(dest["min_retention_days"], 7, 3650, "retention policy is invalid")
    keys = cfg["key_custody"]
    require(isinstance(keys, dict) and set(keys) == {"governance_id", "receipt_file"}, "key custody fields are invalid")
    require(label(keys["governance_id"]) not in (production, dest["governance_id"]),
            "key custody must differ from production and backup governance")
    encryption = cfg["archive_encryption"]
    if encryption is not None:
        require(isinstance(encryption, dict) and set(encryption) == {"age_binary", "recipient", "identity_file"},
                "archive encryption fields are invalid")
        checked_path(encryption["age_binary"])
        if encryption["identity_file"] is not None:
            private(checked_path(encryption["identity_file"]))
        require(not receiver or encryption["identity_file"] is not None,
                "custodian receiver requires a separate age identity file")
        require(isinstance(encryption["recipient"], str) and re.fullmatch(r"age1[a-z0-9]{58,80}", encryption["recipient"]),
                "age X25519 public recipient is invalid")
    now = int(time.time()) if now is None else now
    private(checked_path(dest["attestation_file"]))
    attestation = json_load(Path(dest["attestation_file"]))
    require(set(attestation) == {"governance_id", "bucket", "project_number", "production_admins_cannot_delete",
                               "review_reference", "expires_at_utc"}, "destination attestation fields are invalid")
    require(attestation["governance_id"] == dest["governance_id"] and attestation["bucket"] == dest["bucket"] and
            attestation["project_number"] == dest["project_number"] and attestation["production_admins_cannot_delete"] is True,
            "destination governance attestation does not match")
    label(attestation["review_reference"])
    require(type(attestation["expires_at_utc"]) is int and now < attestation["expires_at_utc"] <= now + 366 * 86400,
            "destination governance attestation is expired or unbounded")
    private(checked_path(keys["receipt_file"]))
    receipt = json_load(Path(keys["receipt_file"]))
    require(set(receipt) == {"governance_id", "historical_kek_versions", "totp_key_retained", "scope_signing_key_rotation_ready",
                           "archive_decryption_key_retained", "restore_reference", "expires_at_utc"},
            "key custody receipt fields are invalid")
    require(receipt["governance_id"] == keys["governance_id"] and receipt["scope_signing_key_rotation_ready"] is True,
            "key custody receipt does not match or rotation is unavailable")
    versions = receipt["historical_kek_versions"]
    require(isinstance(versions, list) and len(versions) <= 32 and all(isinstance(v, str) for v in versions) and
            len(set(versions)) == len(versions),
            "historical key version inventory is invalid")
    for version in versions:
        require(re.fullmatch(r"[A-Za-z0-9._-]{1,64}", version), "historical KEK version label is invalid")
    require(cfg["kek_file"] is None or len(versions) > 0, "historical KEK custody inventory is missing")
    require(cfg["totp_key_file"] is None or receipt["totp_key_retained"] is True, "TOTP key custody receipt is missing")
    require(encryption is None or receipt["archive_decryption_key_retained"] is True,
            "archive decryption-key custody receipt is missing")
    label(receipt["restore_reference"])
    require(type(receipt["expires_at_utc"]) is int and now < receipt["expires_at_utc"] <= now + 366 * 86400,
            "key custody receipt is expired or unbounded")
    return cfg


def config_digest(cfg):
    return hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def command(cfg, arguments, stage, account=False):
    env = os.environ.copy()
    if account:
        env = {key: value for key, value in env.items() if not key.upper().startswith("CIPHERVAULT_")}
    try:
        process = subprocess.Popen(arguments, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        raise CustodyError(stage + " command unavailable or timed out") from None
    output = bytearray()
    exceeded = threading.Event()
    read_failed = threading.Event()

    def capture():
        try:
            while True:
                block = process.stdout.read1(65536)
                if not block:
                    break
                if len(block) > 1024 * 1024 - len(output):
                    exceeded.set()
                    process.kill()
                    break
                output.extend(block)
        except (OSError, ValueError):
            read_failed.set()

    reader = threading.Thread(target=capture, daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=cfg["timeout_seconds"])
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        reader.join(timeout=1)
        raise CustodyError(stage + " command unavailable or timed out") from None
    reader.join(timeout=1)
    if not reader.is_alive():
        process.stdout.close()
    require(not exceeded.is_set(), stage + " command output exceeds limit; native output suppressed")
    require(not reader.is_alive() and not read_failed.is_set(), stage + " command output unavailable; native output suppressed")
    require(code == 0, stage + " command failed; native output suppressed")
    return bytes(output)


def cloud_json(cfg, args, stage):
    raw = command(cfg, [cfg["gcloud_binary"], *args, "--format=json", "--quiet"], stage)
    require(len(raw) <= 1024 * 1024, "cloud metadata exceeds limit")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise CustodyError(stage + " returned invalid metadata") from None
    require(isinstance(result, dict), stage + " returned invalid metadata")
    return result


def validate_bucket(cfg, bucket, policy):
    dest = cfg["destination"]
    require(bucket.get("name") == dest["bucket"][5:] and str(bucket.get("projectNumber")) == dest["project_number"],
            "destination bucket or owning project does not match")
    iam = bucket.get("iamConfiguration", {})
    require(iam.get("uniformBucketLevelAccess", {}).get("enabled") is True and iam.get("publicAccessPrevention") == "enforced",
            "destination must enforce uniform access and public-access prevention")
    require(bucket.get("versioning", {}).get("enabled") is True, "destination object versioning is required")
    retention = bucket.get("retentionPolicy", {})
    try:
        period = int(retention.get("retentionPeriod", 0))
    except (TypeError, ValueError):
        raise CustodyError("destination retention metadata is invalid") from None
    require(retention.get("isLocked") is True and period >= dest["min_retention_days"] * 86400,
            "destination requires an already locked retention policy meeting the minimum")
    bindings = policy.get("bindings")
    require(isinstance(bindings, list) and bindings, "destination IAM policy cannot be verified")
    prohibited = set(cfg["production_principals"]) | {"allUsers", "allAuthenticatedUsers"}
    for binding in bindings:
        require(isinstance(binding, dict) and isinstance(binding.get("members"), list), "destination IAM binding is malformed")
        require(not prohibited.intersection(binding["members"]), "destination directly grants access to a prohibited principal")
    # This is deliberately not an IAM/organization/transitive-group proof.
    return {"bucket_policy_verified": True, "governance_independence": "requires_custodian_review",
            "retention_seconds": period}


def destination_preflight(cfg):
    bucket = cfg["destination"]["bucket"]
    metadata = cloud_json(cfg, ["storage", "buckets", "describe", bucket, "--raw"], "bucket preflight")
    policy = cloud_json(cfg, ["storage", "buckets", "get-iam-policy", bucket], "bucket IAM preflight")
    return validate_bucket(cfg, metadata, policy)


def require_work_capacity(cfg, database_bytes=None):
    if database_bytes is None:
        source = Path(cfg["data_dir"]) / "accounts.sqlite3"
        database_bytes = checked_path(str(source)).stat().st_size
        wal = source.with_name(source.name + "-wal")
        if wal.exists():
            database_bytes += checked_path(str(wal)).stat().st_size
    # All artifacts are retained: allow for both drills, archives, downloaded
    # copies, age output, SQLite work, and growth. This is a guard, not a quota.
    minimum = database_bytes * 10 + 64 * 1024 * 1024
    require(shutil.disk_usage(cfg["work_dir"]).free >= minimum,
            "work directory has insufficient free space for retained rehearsal artifacts")


def validate_bundle(bundle):
    require({item.name for item in bundle.iterdir()} == {"accounts.sqlite3", "backup-receipt.json"},
            "backup bundle contains unexpected files")
    receipt = json_load(bundle / "backup-receipt.json")
    database = checked_path(str(bundle / "accounts.sqlite3"))
    require(receipt.get("format_version") == 1 and receipt.get("database_sha256") == digest(database) and
            receipt.get("database_bytes") == database.stat().st_size, "backup receipt does not match the database")
    return receipt


def archive_bundle(bundle, archive):
    validate_bundle(bundle)
    with archive.open("xb") as handle:
        private(archive, True)
        with tarfile.open(fileobj=handle, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for name in ("accounts.sqlite3", "backup-receipt.json"):
                tar.add(bundle / name, arcname=name, recursive=False)
        handle.flush()
        os.fsync(handle.fileno())


def unpack_bundle(archive, output, max_bytes):
    private_dir(output)
    names = {"accounts.sqlite3", "backup-receipt.json"}
    seen = set()
    expanded = 0
    # Parse fixed USTAR headers directly. tarfile's PAX/GNU processing and
    # getmembers() can allocate or decompress unbounded metadata before yielding.
    with gzip.open(archive, "rb") as source:
        while True:
            header = source.read(512)
            require(len(header) == 512, "downloaded archive is truncated")
            if header == bytes(512):
                require(seen == names, "downloaded archive contains unexpected entries")
                # The writer pads to a 10 KiB record. Reject huge padding,
                # concatenated archives and hidden entries without reading EOF.
                tail = source.read(10241)
                require(len(tail) <= 10240 and len(tail) >= 512 and not any(tail),
                        "downloaded archive has excessive or invalid trailing data")
                break
            require(len(seen) < 2, "downloaded archive contains unexpected entries")
            try:
                item = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            except (tarfile.HeaderError, UnicodeError):
                raise CustodyError("downloaded archive header is invalid") from None
            require(item.name in names and item.name not in seen, "downloaded archive contains unexpected entries")
            require(item.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not item.linkname and
                    0 <= item.size <= max_bytes - expanded,
                    "downloaded archive contains a link or excessive entry")
            seen.add(item.name)
            expanded += item.size
            with (output / item.name).open("xb") as target:
                private(output / item.name, True)
                remaining = item.size
                while remaining:
                    block = source.read(min(remaining, 1024 * 1024))
                    require(bool(block), "downloaded archive is truncated")
                    target.write(block)
                    remaining -= len(block)
                target.flush()
                os.fsync(target.fileno())
            padding = (-item.size) % 512
            pad = source.read(padding)
            require(len(pad) == padding and not any(pad), "downloaded archive padding is invalid")
    return validate_bundle(output)


def rehearse(cfg, bundle, output):
    args = [cfg["account_binary"], "restore-rehearsal", "--backup-dir", str(bundle), "--output-dir", str(output)]
    for key, flag in (("kek_file", "--kek-file"), ("totp_key_file", "--totp-key-file")):
        if cfg[key] is not None:
            args.extend([flag, cfg[key]])
    command(cfg, args, "isolated rehearsal", account=True)
    report = json_load(output / "rehearsal-report.json")
    receipt = validate_bundle(bundle)
    require(report.get("status") == "verified_isolated_restore" and report.get("production_modified") is False and
            report.get("keys_included") is False and report.get("backup_sha256") == receipt["database_sha256"] and
            report.get("table_rows") == receipt.get("table_rows"), "isolated rehearsal report is invalid")
    return report


@contextlib.contextmanager
def run_lock(root):
    path = root / ".custody.lock"
    if path.exists():
        checked_path(str(path))
        private(path)
    with path.open("a+b") as handle:
        private(path, True)
        if path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise CustodyError("another custody run is active") from None
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def apply(cfg, upload_only=False):
    encryption = cfg["archive_encryption"]
    require(not upload_only or encryption is not None, "upload-only custody requires age archive encryption")
    require(upload_only or encryption is None or encryption["identity_file"] is not None,
            "combined copy verification requires an age identity; use upload-only on production")
    root = checked_path(cfg["work_dir"], True)
    with run_lock(root):
        started = int(time.time())
        run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started)) + "-" + uuid.uuid4().hex
        run = private_dir(root / run_id)
        report = {"schema_version": 1, "run_id": run_id, "started_at_utc": started,
                  "configuration_sha256": config_digest(cfg),
                  "status": "running", "keys_included": False, "production_modified": False,
                  "independent_custody_certified": False}
        json_write(run / "custody-run.json", report)
        try:
            report.update(destination_preflight(cfg))
            require_work_capacity(cfg)
            bundle = run / "backup"
            command(cfg, [cfg["account_binary"], "backup", "--data-dir", cfg["data_dir"], "--output-dir", str(bundle)],
                    "account backup", account=True)
            receipt = validate_bundle(bundle)
            require(receipt["database_bytes"] <= cfg["max_artifact_bytes"], "backup database exceeds artifact ceiling")
            require_work_capacity(cfg, receipt["database_bytes"])
            rehearse(cfg, bundle, run / "local-rehearsal")
            archive = run / "account-backup.tar.gz"
            archive_bundle(bundle, archive)
            transfer = archive
            if encryption is not None:
                transfer = run / "account-backup.tar.gz.age"
                command(cfg, [encryption["age_binary"], "--encrypt", "--recipient", encryption["recipient"],
                              "--output", str(transfer), str(archive)], "archive encryption")
                private(checked_path(str(transfer)), True)
            expected = digest(transfer)
            require(transfer.stat().st_size <= cfg["max_artifact_bytes"], "backup archive exceeds artifact ceiling")
            dest = cfg["destination"]
            uri = dest["bucket"] + "/" + dest["prefix"] + "/" + run_id + "/" + transfer.name
            command(cfg, [cfg["gcloud_binary"], "storage", "cp", str(transfer), uri,
                          "--if-generation-match=0", "--quiet"], "immutable upload")
            if upload_only:
                report.update(status="uploaded_pending_independent_verification", archive_sha256=expected,
                              database_sha256=receipt["database_sha256"], backup_created_at_utc=receipt["created_at_utc"],
                              archive_bytes=transfer.stat().st_size, destination_object=uri,
                              archive_encryption="age_x25519", account_metadata_client_encrypted=True,
                              copy_verified=False, completed_at_utc=int(time.time()),
                              destination_attestation_sha256=digest(Path(dest["attestation_file"])),
                              key_custody_receipt_sha256=digest(Path(cfg["key_custody"]["receipt_file"])))
                require(0 <= report["completed_at_utc"] - report["backup_created_at_utc"] <= cfg["max_backup_age_seconds"],
                        "completed backup exceeds freshness threshold")
                json_write(run / "custody-run.json", report)
                command(cfg, [cfg["gcloud_binary"], "storage", "cp", str(run / "custody-run.json"),
                              uri.rsplit("/", 1)[0] + "/custody-run.json", "--if-generation-match=0", "--quiet"],
                        "custody evidence upload")
                return report
            downloaded = run / ("downloaded.tar.gz.age" if encryption is not None else "downloaded.tar.gz")
            # The empty private file gives Windows an owner-only DACL before
            # cloud tooling opens it; GCS download is bounded by source size.
            with downloaded.open("xb"):
                private(downloaded, True)
            command(cfg, [cfg["gcloud_binary"], "storage", "cp", uri, str(downloaded),
                          "--do-not-decompress", "--quiet"], "copy verification download")
            private(checked_path(str(downloaded)), True)
            require(downloaded.stat().st_size == transfer.stat().st_size and digest(downloaded) == expected,
                    "downloaded archive checksum does not match")
            if encryption is not None:
                decrypted = run / "decrypted-download.tar.gz"
                command(cfg, [encryption["age_binary"], "--decrypt", "--identity", encryption["identity_file"],
                              "--output", str(decrypted), str(downloaded)], "archive decryption rehearsal")
                private(checked_path(str(decrypted)), True)
                require(digest(decrypted) == digest(archive), "decrypted archive checksum does not match")
                downloaded = decrypted
            copied = run / "downloaded-backup"
            unpack_bundle(downloaded, copied, max(65536, receipt["database_bytes"]))
            drill = rehearse(cfg, copied, run / "downloaded-rehearsal")
            report.update(status="verified_backup_copy_and_isolated_restore", archive_sha256=expected,
                          database_sha256=receipt["database_sha256"], backup_created_at_utc=receipt["created_at_utc"],
                          archive_bytes=transfer.stat().st_size, destination_object=uri,
                          archive_encryption="age_x25519" if encryption is not None else "gcs_at_rest_only",
                          account_metadata_client_encrypted=encryption is not None,
                          secret_versions_decrypted=drill["secret_versions_decrypted"],
                          totp_seeds_decrypted=drill["totp_seeds_decrypted"],
                          destination_attestation_sha256=digest(Path(dest["attestation_file"])),
                          key_custody_receipt_sha256=digest(Path(cfg["key_custody"]["receipt_file"])))
            report["completed_at_utc"] = int(time.time())
            require(0 <= report["completed_at_utc"] - report["backup_created_at_utc"] <= cfg["max_backup_age_seconds"],
                    "completed backup exceeds freshness threshold")
            json_write(run / "custody-run.json", report)
            command(cfg, [cfg["gcloud_binary"], "storage", "cp", str(run / "custody-run.json"),
                          uri.rsplit("/", 1)[0] + "/custody-run.json", "--if-generation-match=0", "--quiet"],
                    "custody evidence upload")
            return report
        except Exception as error:
            report.update(status="failed", completed_at_utc=int(time.time()),
                          error=str(error) if isinstance(error, CustodyError) else "custody operation failed; details suppressed")
            json_write(run / "custody-run.json", report)
            raise CustodyError(report["error"]) from None


def status(cfg, now=None, upload_stage=False):
    now = int(time.time()) if now is None else now
    records = []
    for path in Path(cfg["work_dir"]).glob("*/custody-run.json"):
        try:
            report = json_load(path)
            require(type(report.get("started_at_utc")) is int, "run timestamp is invalid")
            records.append(report)
        except CustodyError:
            return {"status": "invalid_history", "healthy": False}
    if not records:
        return {"status": "never_completed", "healthy": False}
    records.sort(key=lambda item: item["started_at_utc"], reverse=True)
    latest = records[0]
    if latest.get("configuration_sha256") != config_digest(cfg):
        return {"status": "configuration_changed", "healthy": False}
    success_states = {"uploaded_pending_independent_verification"} if upload_stage else {
        "verified_backup_copy_and_isolated_restore", "verified_received_archive_and_isolated_restore"}
    if latest.get("status") in success_states and (
        latest.get("destination_attestation_sha256") != digest(Path(cfg["destination"]["attestation_file"])) or
        latest.get("key_custody_receipt_sha256") != digest(Path(cfg["key_custody"]["receipt_file"]))
    ):
        return {"status": "custody_attestation_changed", "healthy": False}
    valid = [item for item in records if item.get("status") in success_states]
    backup_at = valid[0].get("backup_created_at_utc") if valid else None
    age = now - backup_at if type(backup_at) is int else None
    fresh = age is not None and 0 <= age <= cfg["max_backup_age_seconds"]
    healthy = latest.get("status") in success_states and fresh
    return {"status": "healthy" if healthy else "stale" if latest.get("status") in success_states
            else latest.get("status", "invalid_history"), "healthy": healthy, "backup_age_seconds": age,
            "latest_run_id": latest.get("run_id"), "independent_custody_certified": False,
            "monitored_stage": "production_upload_only" if upload_stage else "copy_and_restore"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true")
    action.add_argument("--upload-only", action="store_true", help="encrypt/upload without object-read permission")
    action.add_argument("--status", action="store_true")
    action.add_argument("--upload-status", action="store_true", help="monitor upload stage; does not assert custody verification")
    action.add_argument("--online", action="store_true", help="preflight destination with read-only cloud calls")
    args = parser.parse_args()
    try:
        cfg = load_config(args.config)
        if args.apply or args.upload_only:
            result = apply(cfg, args.upload_only)
        elif args.status or args.upload_status:
            result = status(cfg, upload_stage=args.upload_status)
        else:
            result = {"status": "preflight_only", "configuration_valid": True, "cloud_mutated": False,
                      "keys_read": False, "independent_custody_certified": False}
            if args.online:
                result.update(destination_preflight(cfg))
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("healthy", True) else 1
    except Exception as error:
        message = str(error) if isinstance(error, CustodyError) else "custody preflight failed; details suppressed"
        print(json.dumps({"status": "failed", "error": message}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
