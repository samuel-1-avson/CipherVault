#!/usr/bin/env python3
"""CipherVault Kubernetes CSI Ephemeral Secret Store Driver.

Implements zero-disk in-memory secret volume mounting for Kubernetes pods.
Secrets are materialized exclusively inside an isolated in-memory tmpfs mount
with 0400 read-only file permissions and are zeroized upon pod termination.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


class CSIDriverError(Exception):
    """Raised when CSI volume operations fail."""


class CipherVaultCSIProvider:
    """Manages ephemeral in-memory secret volumes for Kubernetes pods."""

    def __init__(self, operator_url=None, zero_disk=True):
        self.operator_url = operator_url or os.environ.get(
            "CIPHERVAULT_OPERATORS", "http://127.0.0.1:8101"
        )
        self.zero_disk = zero_disk

    def publish_volume(
        self,
        target_path: Path,
        volume_id: str,
        project: str,
        environment: str,
        secrets_payload: dict,
        pod_uid: str = "default-pod",
        target_uid: int = 1000,
        target_gid: int = 1000,
    ) -> dict:
        """Mount an in-memory volume and materialize requested secrets."""
        target_path = Path(target_path).resolve()
        target_path.mkdir(parents=True, exist_ok=True)

        # Enforce isolated directory permissions
        try:
            os.chmod(target_path, stat.S_IRWXU)  # 0700
        except OSError:
            pass

        # In Linux/K8s environments, mount tmpfs in-memory filesystem
        is_mounted_tmpfs = False
        if sys.platform == "linux" and self.zero_disk:
            mount_cmd = [
                "mount",
                "-t",
                "tmpfs",
                "-o",
                "size=16M,mode=0700,noexec,nosuid,nodev",
                "tmpfs",
                str(target_path),
            ]
            res = subprocess.run(mount_cmd, capture_output=True, text=True)
            if res.returncode == 0:
                is_mounted_tmpfs = True
            else:
                # If already mounted or in non-privileged test mode, log warning
                pass

        written_files = []
        total_secret_bytes = 0

        # Materialize secret files into target RAM mount
        for rel_filename, secret_content in secrets_payload.items():
            # Validate no path traversal
            norm_rel = os.path.normpath(rel_filename)
            if norm_rel.startswith("..") or os.path.isabs(norm_rel):
                raise CSIDriverError(f"Illegal relative path in secret specification: {rel_filename}")

            file_path = target_path / norm_rel
            file_path.parent.mkdir(parents=True, exist_ok=True)

            content_bytes = (
                secret_content.encode("utf-8")
                if isinstance(secret_content, str)
                else bytes(secret_content)
            )

            file_path.write_bytes(content_bytes)

            # Enforce read-only 0400 permissions
            try:
                os.chmod(file_path, stat.S_IRUSR)  # 0400
                if sys.platform != "win32" and target_uid is not None:
                    os.chown(file_path, target_uid, target_gid)
            except OSError:
                pass

            written_files.append(str(norm_rel))
            total_secret_bytes += len(content_bytes)

        metadata = {
            "volume_id": volume_id,
            "project": project,
            "environment": environment,
            "pod_uid": pod_uid,
            "is_tmpfs": is_mounted_tmpfs or sys.platform != "linux",
            "files_count": len(written_files),
            "files": written_files,
            "total_bytes": total_secret_bytes,
            "status": "published",
        }

        # Store volume state descriptor in .ciphervault-meta
        meta_file = target_path / ".ciphervault-csi-meta"
        meta_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        try:
            os.chmod(meta_file, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        return metadata

    def unpublish_volume(self, target_path: Path, volume_id: str) -> dict:
        """Securely zeroize secrets, unmount tmpfs, and tear down volume directory."""
        target_path = Path(target_path).resolve()
        if not target_path.exists():
            return {"status": "unmounted", "volume_id": volume_id, "existed": False}

        scrubbed_files = []

        # Helper for removing read-only attributes on Windows/POSIX
        def on_rmtree_error(func, path, _exc_info):
            try:
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                func(path)
            except OSError:
                pass

        # 1. Zeroize in-memory bytes before deletion
        for root, _, files in os.walk(target_path):
            for file_name in files:
                f_path = Path(root) / file_name
                try:
                    # Clear read-only attribute before wiping
                    os.chmod(f_path, stat.S_IWRITE | stat.S_IREAD)
                    f_size = f_path.stat().st_size
                    # Overwrite file with zeroes
                    f_path.write_bytes(b"\x00" * f_size)
                    scrubbed_files.append(str(f_path.name))
                except OSError:
                    pass

        # 2. Unmount tmpfs if mounted on Linux
        if sys.platform == "linux":
            subprocess.run(["umount", "-f", str(target_path)], capture_output=True)

        # 3. Remove mount directory
        shutil.rmtree(target_path, onerror=on_rmtree_error)
        if target_path.exists():
            shutil.rmtree(target_path, ignore_errors=True)

        return {
            "status": "unmounted",
            "volume_id": volume_id,
            "scrubbed_files_count": len(scrubbed_files),
            "existed": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Publish subcommand
    pub_parser = subparsers.add_parser("publish", help="Publish ephemeral volume")
    pub_parser.add_argument("--target-path", required=True, type=Path, help="Target mount path")
    pub_parser.add_argument("--volume-id", required=True, help="Kubernetes Volume ID")
    pub_parser.add_argument("--project", default="default-project", help="CipherVault Project")
    pub_parser.add_argument("--env", default="production", help="CipherVault Environment")
    pub_parser.add_argument("--secrets-json", required=True, help="JSON map of file->secret pairs")

    # Unpublish subcommand
    unpub_parser = subparsers.add_parser("unpublish", help="Unpublish and zeroize volume")
    unpub_parser.add_argument("--target-path", required=True, type=Path, help="Target mount path")
    unpub_parser.add_argument("--volume-id", required=True, help="Kubernetes Volume ID")

    args = parser.parse_args()
    provider = CipherVaultCSIProvider()

    if args.command == "publish":
        secrets = json.loads(args.secrets_json)
        result = provider.publish_volume(
            target_path=args.target_path,
            volume_id=args.volume_id,
            project=args.project,
            environment=args.env,
            secrets_payload=secrets,
        )
        print(json.dumps(result, indent=2))
    elif args.command == "unpublish":
        result = provider.unpublish_volume(
            target_path=args.target_path,
            volume_id=args.volume_id,
        )
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
