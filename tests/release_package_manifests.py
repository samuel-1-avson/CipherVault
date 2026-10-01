import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dist.scripts.fill_package_manager_manifests import update_manifests


class PackageManifestUpdateTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        dist = root / "package-managers"
        manifests = dist / "winget/manifests/c/CipherVault/CipherVault"
        old = manifests / "1.0.26"
        old.mkdir(parents=True)

        (dist / "homebrew/Formula").mkdir(parents=True)
        (dist / "homebrew/Formula/ciphervault.rb").write_text(
            '\n'.join(
                [
                    '  version "1.0.26"',
                    f'      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-aarch64-apple-darwin.tar.gz"',
                    '      sha256 "' + '1' * 64 + '"',
                    f'      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-x86_64-apple-darwin.tar.gz"',
                    '      sha256 "' + '2' * 64 + '"',
                    f'      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-aarch64-unknown-linux-gnu.tar.gz"',
                    '      sha256 "' + '3' * 64 + '"',
                    f'      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-x86_64-unknown-linux-gnu.tar.gz"',
                    '      sha256 "' + '4' * 64 + '"',
                ]
            ),
            encoding="utf-8",
        )
        (dist / "scoop").mkdir(parents=True)
        (dist / "scoop/ciphervault.json").write_text(
            '\n'.join(
                [
                    '    "version": "1.0.26",',
                    f'            "url": "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-x86_64-pc-windows-msvc.zip",',
                    '            "hash": "' + '5' * 64 + '",',
                ]
            ),
            encoding="utf-8",
        )
        for filename in (
            "CipherVault.CipherVault.yaml",
            "CipherVault.CipherVault.installer.yaml",
            "CipherVault.CipherVault.locale.en-US.yaml",
        ):
            (old / filename).write_text(
                f"PackageVersion: 1.0.26\n"
                "InstallerUrl: https://github.com/samuel-1-avson/CipherVault/releases/download/"
                "v1.0.26/ciphervault-v1.0.26-x86_64-pc-windows-msvc.zip\n"
                f"InstallerSha256: {'6' * 64}\n",
                encoding="utf-8",
            )

        sums = root / "SHA256SUMS.txt"
        assets = (
            "aarch64-apple-darwin.tar.gz",
            "x86_64-apple-darwin.tar.gz",
            "aarch64-unknown-linux-gnu.tar.gz",
            "x86_64-unknown-linux-gnu.tar.gz",
            "x86_64-pc-windows-msvc.zip",
        )
        sums.write_text(
            ''.join(
                f"{hashlib.sha256(asset.encode()).hexdigest()}  ciphervault-v1.0.28-{asset}\n"
                for asset in assets
            ),
            encoding="utf-8",
        )
        return dist, sums

    def test_updates_versions_urls_and_hashes_and_seeds_missing_winget_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dist, sums = self.fixture(Path(directory))
            update_manifests(dist, sums, "v1.0.28")

            brew = (dist / "homebrew/Formula/ciphervault.rb").read_text(encoding="utf-8")
            scoop = (dist / "scoop/ciphervault.json").read_text(encoding="utf-8")
            installer = (
                dist
                / "winget/manifests/c/CipherVault/CipherVault/1.0.28/CipherVault.CipherVault.installer.yaml"
            ).read_text(encoding="utf-8")

            self.assertIn('version "1.0.28"', brew)
            self.assertEqual(brew.count("releases/download/v1.0.28/"), 4)
            self.assertNotIn("v1.0.26", brew)
            for target in (
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
                "aarch64-unknown-linux-gnu",
                "x86_64-unknown-linux-gnu",
            ):
                digest = hashlib.sha256(f"{target}.tar.gz".encode()).hexdigest()
                self.assertIn(f'sha256 "{digest}"', brew)
            self.assertIn('"version": "1.0.28"', scoop)
            self.assertIn("ciphervault-v1.0.28-x86_64-pc-windows-msvc.zip", scoop)
            self.assertNotIn("v1.0.26", scoop)
            windows_digest = hashlib.sha256(b"x86_64-pc-windows-msvc.zip").hexdigest()
            self.assertIn(f'"hash": "{windows_digest}"', scoop)
            self.assertIn("PackageVersion: 1.0.28", installer)
            self.assertIn("v1.0.28/ciphervault-v1.0.28-x86_64-pc-windows-msvc.zip", installer)
            self.assertIn("InstallerSha256: " + windows_digest, installer)

            paths = [
                dist / "homebrew/Formula/ciphervault.rb",
                dist / "scoop/ciphervault.json",
                *(
                    dist / "winget/manifests/c/CipherVault/CipherVault/1.0.28" / filename
                    for filename in (
                        "CipherVault.CipherVault.yaml",
                        "CipherVault.CipherVault.installer.yaml",
                        "CipherVault.CipherVault.locale.en-US.yaml",
                    )
                ),
            ]
            expected = [path.read_bytes() for path in paths]
            update_manifests(dist, sums, "v1.0.28")
            self.assertEqual([path.read_bytes() for path in paths], expected)

    def test_fails_closed_on_missing_target_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dist, sums = self.fixture(Path(directory))
            lines = sums.read_text(encoding="utf-8").splitlines()
            sums.write_text('\n'.join(lines[:-1]) + '\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing checksum"):
                update_manifests(dist, sums, "v1.0.28")


if __name__ == "__main__":
    unittest.main()
