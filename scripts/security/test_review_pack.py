"""Adversarial isolation/integrity tests for the source evidence builder."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

import build_review_pack as pack


class ReviewPackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cv-review-pack-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.file("Cargo.toml", "[workspace]\nmembers = []\n")
        self.file("crates/crypto/src/lib.rs", "// synthetic source\n")
        for name in [".ciphervault/vault.db", ".agents/probe.rs", "crates/crypto/keys.key",
                     "deploy/docker/.env.example", "scripts/recovery-archives/guardian.py",
                     "docs/review-evidence/session.log", "credentials.json"]:
            self.file(name, "DO-NOT-EXPORT-RUNTIME-FIXTURE")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "-m", "synthetic source fixture")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def file(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def archive(self, name="pack.zip", ref=None):
        output = self.root / name
        pack.write_pack(self.repo, output, ref)
        return output

    def rewrite(self, original, modify):
        output = self.root / "changed.zip"
        with zipfile.ZipFile(original) as source, zipfile.ZipFile(output, "w") as dest:
            contents = {entry.filename: source.read(entry) for entry in source.infolist()}
            modify(contents)
            for name, content in contents.items():
                dest.writestr(name, content)
        return output

    def test_allowlist_excludes_even_tracked_runtime_material(self):
        output = self.archive()
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(set(archive.namelist()),
                             {"Cargo.toml", "crates/crypto/src/lib.rs", pack.MANIFEST})
            self.assertNotIn(b"DO-NOT-EXPORT", b"".join(archive.read(n) for n in archive.namelist()))
        self.assertEqual(len(pack.verify_pack(output)["files"]), 2)

    def test_frozen_ref_ignores_worktree_changes_and_untracked_source(self):
        self.file("crates/crypto/src/lib.rs", "// uncommitted change\n")
        self.file("crates/crypto/src/untracked.rs", "// excluded untracked\n")
        output = self.archive(ref="HEAD")
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read("crates/crypto/src/lib.rs"), b"// synthetic source\n")
            self.assertNotIn("crates/crypto/src/untracked.rs", archive.namelist())
        self.assertEqual(pack.verify_pack(output)["source_state"]["mode"], "immutable_commit")

    def test_same_snapshot_is_deterministic_and_does_not_overwrite(self):
        first, second = self.archive("first.zip"), self.archive("second.zip")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with self.assertRaises(FileExistsError):
            pack.write_pack(self.repo, first)

    def test_modified_source_is_rejected(self):
        changed = self.rewrite(self.archive(), lambda files: files.update({"Cargo.toml": b"changed"}))
        with self.assertRaisesRegex(ValueError, "hash/length"):
            pack.verify_pack(changed)

    def test_extra_missing_and_traversal_entries_are_rejected(self):
        original = self.archive()
        for mutation in [lambda f: f.update({"../outside.rs": b"bad"}),
                         lambda f: f.update({"crates/crypto/src/extra.rs": b"extra"}),
                         lambda f: f.pop("Cargo.toml")]:
            with self.subTest(mutation=mutation):
                changed = self.rewrite(original, mutation)
                with self.assertRaises(ValueError):
                    pack.verify_pack(changed)

    def test_duplicate_entries_and_manifest_paths_are_rejected(self):
        original = self.archive()
        duplicate = self.root / "duplicate.zip"
        with zipfile.ZipFile(original) as source, zipfile.ZipFile(duplicate, "w") as dest:
            for name in source.namelist():
                dest.writestr(name, source.read(name))
            with self.assertWarns(UserWarning):
                dest.writestr("Cargo.toml", source.read("Cargo.toml"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pack.verify_pack(duplicate)

        def repeat_manifest(files):
            manifest = json.loads(files[pack.MANIFEST])
            manifest["files"].append(manifest["files"][0])
            files[pack.MANIFEST] = json.dumps(manifest).encode()

        changed = self.rewrite(original, repeat_manifest)
        with self.assertRaisesRegex(ValueError, "membership"):
            pack.verify_pack(changed)

    def test_symlinked_source_is_rejected_without_reading_target(self):
        path = self.repo / "crates/crypto/src/lib.rs"
        path.unlink()
        outside = self.root / "private.txt"
        outside.write_text("DO-NOT-EXPORT", encoding="utf-8")
        try:
            path.symlink_to(outside)
        except OSError:
            self.skipTest("symlink creation not enabled on this host")
        with self.assertRaisesRegex(ValueError, "linked/reparse"):
            self.archive()

    @unittest.skipUnless(os.name == "nt", "Windows junction-specific test")
    def test_windows_junction_parent_is_rejected(self):
        path = self.repo / "crates/crypto/src"
        (path / "lib.rs").unlink()
        path.rmdir()
        outside = self.root / "private-source"
        outside.mkdir()
        (outside / "lib.rs").write_text("DO-NOT-EXPORT", encoding="utf-8")
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        f"New-Item -ItemType Junction -Path {quote(path)} -Target {quote(outside)} | Out-Null"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.assertRaisesRegex(ValueError, "linked/reparse"):
            self.archive()


if __name__ == "__main__":
    unittest.main()
