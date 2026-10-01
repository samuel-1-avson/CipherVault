#!/usr/bin/env python3
"""Build/verify an allowlisted local source review ZIP; never upload evidence.

Hashes establish integrity, not publisher authenticity or security certification.
Only tracked source files and explicitly listed review documents are eligible.
Run a secret scan and inspect the manifest before transferring any source pack.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import zipfile

FORMAT_VERSION = 1
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PACK_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 4000
MANIFEST = "MANIFEST.json"
ROOT_FILES = {
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain",
    "README.md", "SECURITY.md", "LICENSE", "LICENSE-MIT", "LICENSE-APACHE",
    "foundry.toml", "install.sh", "install.ps1",
}
REVIEW_DOCUMENTS = {
    "docs/SECURITY_AUDIT_READINESS.md",
    "docs/CURRENT_SECURITY_GUARANTEES.md",
    "docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md",
    "docs/ACCOUNT_BACKUP_AND_RECOVERY.md",
    "docs/DEPENDENCY_AUDIT.md",
    "docs/PLATFORM_SUPPORT.md",
    "docs/CAPACITY_VALIDATION.md",
    "docs/ENFORCED_MFA.md",
    "docs/INDEPENDENT_RECOVERY_CUSTODY.md",
    "report/CAPACITY_VALIDATION_2026-10-01.md",
    "report/RECOVERY_CUSTODY_2026-10-01.md",
    "report/PROJECT_AUDIT_2026-09-30.md",
    "report/AUDIT_REMEDIATION_2026-09-30.md",
    "report/DEPLOYMENT_2026-09-30.md",
    "report/PROJECT_REASSESSMENT_2026-10-01.md",
    "report/SECURITY_REVIEW_READINESS_2026-10-01.md",
    "report/ASSURANCE_IMPLEMENTATION_2026-10-01.md",
    "report/capacity-final-2026-10-01.json",
    "report/capacity-fresh-mfa-2026-10-01.json",
    "report/capacity-http-admission-2026-10-01.json",
    "report/capacity-legacy-baseline-2026-10-01.json",
    "scripts/security/build_review_pack.py",
    "scripts/security/test_review_pack.py",
}
CUSTODY_EXAMPLES = {
    "scripts/recovery/custody.example.json",
    "scripts/recovery/custodian.example.json",
    "scripts/recovery/provisioning.example.json",
    "scripts/recovery/destination-attestation.example.json",
    "scripts/recovery/key-custody-receipt.example.json",
    "scripts/recovery/ciphervault-account-custody.service.example",
    "scripts/recovery/ciphervault-account-custody.timer.example",
    "scripts/recovery/ciphervault-account-custody-status.service.example",
    "scripts/recovery/ciphervault-account-custody-status.timer.example",
    "scripts/recovery/ciphervault-custodian-verify.service.example",
    "scripts/recovery/ciphervault-custodian-verify.timer.example",
    "scripts/recovery/ciphervault-custodian-status.service.example",
    "scripts/recovery/ciphervault-custodian-status.timer.example",
}
PREPARED_FILES = REVIEW_DOCUMENTS | CUSTODY_EXAMPLES | {
    # New files for this scoped development cycle. This finite list preserves
    # an internal review snapshot before staging without walking runtime dirs.
    "services/account/src/mfa.rs",
    ".github/workflows/capacity-validation.yml",
    "scripts/capacity-validation.cjs",
    "tests/capacity_harness.cjs",
    "scripts/recovery/account_custody.py",
    "scripts/recovery/plan_provisioning.py",
    "scripts/recovery/receive_custody.py",
    "tests/recovery/test_account_custody.py",
}
SOURCE_EXTENSIONS = {".rs", ".toml", ".md", ".js", ".cjs", ".mjs", ".css", ".html"}
SCRIPT_EXTENSIONS = {".sh", ".ps1", ".py", ".cjs", ".mjs"}
FORBIDDEN_PARTS = {
    ".git", ".agents", ".ciphervault", "secrets", "target", ".cargo-targets",
    "node_modules", "operator-data", "data", "backups", "recovery-archives",
    "review-evidence", "__pycache__",
}


def safe_name(name):
    if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
        return False
    path = PurePosixPath(name)
    return (not path.is_absolute() and ":" not in name
            and name == path.as_posix()
            and not any(part in {".", ".."} for part in path.parts)
            and not any(part.lower() in FORBIDDEN_PARTS for part in path.parts))


def allowed(name):
    if not safe_name(name):
        return False
    if name in ROOT_FILES or name in REVIEW_DOCUMENTS or name in CUSTODY_EXAMPLES:
        return True
    path = PurePosixPath(name)
    if path.parts[0] in {"crates", "services", "apps"}:
        return path.suffix.lower() in SOURCE_EXTENSIONS
    if path.parts[0] == "scripts":
        return path.suffix.lower() in SCRIPT_EXTENSIONS
    if path.parts[0] == "tests":
        return path.suffix.lower() in SCRIPT_EXTENSIONS | {".rs", ".toml", ".md"}
    if path.parts[:2] == (".github", "workflows"):
        return path.suffix.lower() in {".yml", ".yaml"}
    if path.parts[:2] == (".github", "scripts") or path.parts[:2] == ("dist", "scripts"):
        return path.suffix.lower() in SCRIPT_EXTENSIONS
    if path.parts[0] == "contracts":
        return path.suffix.lower() in {".sol", ".toml", ".md"}
    if path.parts[0] == "deploy":
        return (path.suffix.lower() in {".sh", ".ps1", ".conf", ".yml", ".yaml", ".md"}
                or path.name.startswith("Dockerfile") or path.name.startswith("Caddyfile"))
    return False


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def read_worktree_file(repo, name):
    path = repo.joinpath(*PurePosixPath(name).parts)
    for candidate in [path, *path.parents]:
        if candidate == repo:
            break
        info = candidate.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError(f"linked/reparse path excluded: {name}")
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"not a bounded regular source file: {name}")
    with path.open("rb") as source:
        data = source.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"source grew past limit: {name}")
    return data


def collect(repo, ref=None):
    repo = repo.resolve()
    commit = git(repo, "rev-parse", "--verify", "--end-of-options",
                 f"{ref or 'HEAD'}^{{commit}}").decode().strip()
    tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    files = {}
    if ref is not None:
        entries = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
        for entry in filter(None, entries):
            metadata, raw_name = entry.split(b"\t", 1)
            name = raw_name.decode("utf-8")
            if not allowed(name):
                continue
            mode, kind, _ = metadata.split()
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                raise ValueError(f"nonregular tracked source excluded: {name}")
            files[name] = git(repo, "cat-file", "blob", f"{commit}:{name}")
        state = {"mode": "immutable_commit", "commit": commit, "tree": tree}
    else:
        names = {name.decode("utf-8") for name in
                 git(repo, "ls-files", "-z").split(b"\0") if name}
        # Newly prepared handoff documents may be captured before commit. This
        # is deliberately a finite list, never an untracked workspace walk.
        names.update(name for name in PREPARED_FILES if (repo / name).is_file())
        for name in sorted(names):
            if allowed(name):
                files[name] = read_worktree_file(repo, name)
        state = {
            "mode": "worktree_snapshot_not_a_frozen_release", "commit": commit, "tree": tree,
            "tracked_changes_present": bool(git(repo, "status", "--porcelain", "--untracked-files=no")),
            "includes_untracked_prepared_files": bool(PREPARED_FILES.intersection(names)
                - {name.decode("utf-8") for name in git(repo, "ls-files", "-z").split(b"\0") if name}),
        }
    if not files or len(files) > MAX_ENTRIES:
        raise ValueError("empty pack or file-count limit exceeded")
    if any(len(data) > MAX_FILE_BYTES for data in files.values()) or sum(map(len, files.values())) > MAX_PACK_BYTES:
        raise ValueError("source file/aggregate size limit exceeded")
    return files, state


def write_pack(repo, output, ref=None):
    files, state = collect(repo, ref)
    manifest = {
        "format_version": FORMAT_VERSION, "purpose": "internal_source_security_review",
        "source_state": state,
        "integrity_is_not_authenticity": True,
        "runtime_files_included": False,
        "secret_scan_required_before_transfer": True,
        "excluded": sorted(FORBIDDEN_PARTS) + ["ambient logs", "environment/key/database/archive files", "git remotes"],
        "files": [{"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in sorted(files.items())],
    }
    with Path(output).open("xb") as destination:
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            contents = {**files, MANIFEST: (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()}
            for name, data in sorted(contents.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, data)
    verify_pack(output)
    return manifest


def verify_pack(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or len(names) > MAX_ENTRIES + 1:
            raise ValueError("duplicate entries or file-count limit exceeded")
        if MANIFEST not in names or any(name != MANIFEST and not allowed(name) for name in names):
            raise ValueError("missing manifest or non-allowlisted archive entry")
        if sum(entry.file_size for entry in entries) > MAX_PACK_BYTES + MAX_FILE_BYTES:
            raise ValueError("aggregate size limit exceeded")
        for entry in entries:
            mode = entry.external_attr >> 16
            if (entry.file_size > MAX_FILE_BYTES or entry.is_dir()
                    or (stat.S_IFMT(mode) and not stat.S_ISREG(mode))):
                raise ValueError("oversized or nonregular archive entry")
        manifest = json.loads(archive.read(MANIFEST))
        if manifest.get("format_version") != FORMAT_VERSION or not isinstance(manifest.get("files"), list):
            raise ValueError("unsupported manifest")
        listed = [entry["path"] for entry in manifest["files"]]
        if len(listed) != len(set(listed)) or set(listed) != set(names) - {MANIFEST}:
            raise ValueError("manifest/archive membership mismatch")
        for entry in manifest["files"]:
            data = archive.read(entry["path"])
            if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError(f"hash/length mismatch: {entry['path']}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ref", help="immutable Git commit/ref to export")
    mode.add_argument("--worktree", action="store_true", help="explicit uncommitted source snapshot")
    mode.add_argument("--verify", type=Path, help="verify existing ZIP without extracting")
    parser.add_argument("--output", type=Path, help="new ZIP path; existing files are never overwritten")
    args = parser.parse_args()
    if args.verify:
        if args.output:
            parser.error("--output is invalid with --verify")
        manifest = verify_pack(args.verify)
        path = args.verify
    else:
        if not args.output:
            parser.error("--output is required when building")
        manifest = write_pack(Path(__file__).resolve().parents[2], args.output, args.ref)
        path = args.output
    print(json.dumps({"path": str(path.resolve()), "files": len(manifest["files"]),
                      "source_state": manifest["source_state"],
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}, indent=2))


if __name__ == "__main__":
    main()
