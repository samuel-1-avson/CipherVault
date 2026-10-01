#!/usr/bin/env python3
"""Synchronize package-manager versions, URLs, and hashes from release checksums.

The caller must authenticate SHA256SUMS.txt before invoking this script.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Callable


PACKAGE_ID = "CipherVault.CipherVault"
WINGET_FILES = (
    f"{PACKAGE_ID}.yaml",
    f"{PACKAGE_ID}.installer.yaml",
    f"{PACKAGE_ID}.locale.en-US.yaml",
)
HOMEBREW_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
)
WINDOWS_TARGET = "x86_64-pc-windows-msvc"
REPO_RELEASE_URL = "https://github.com/samuel-1-avson/CipherVault/releases/download/"


def exact_substitution(
    text: str,
    pattern: re.Pattern[str],
    replacement: str | Callable[[re.Match[str]], str],
    label: str,
) -> str:
    updated, count = pattern.subn(replacement, text)
    if count != 1:
        raise ValueError(f"{label}: expected one match, found {count}")
    return updated


def read_checksums(path: Path, tag: str) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        digest, filename = parts
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"non-hex SHA-256 digest for {filename}")
        if filename in checksums:
            raise ValueError(f"duplicate SHA256SUMS entry for {filename}")
        checksums[filename] = digest

    def require(name: str) -> str:
        filename = f"ciphervault-{tag}-{name}"
        if filename not in checksums:
            raise ValueError(f"missing checksum for {filename}")
        return checksums[filename]

    required = [f"{target}.tar.gz" for target in HOMEBREW_TARGETS]
    required.append(f"{WINDOWS_TARGET}.zip")
    for name in required:
        require(name)
    return checksums


def semver_key(version: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError(f"unsupported package version {version!r}; expected MAJOR.MINOR.PATCH")
    return tuple(map(int, match.groups()))


def seed_winget_manifests(manifests_root: Path, version: str) -> Path:
    destination = manifests_root / version
    if not destination.exists():
        candidates = [
            path
            for path in manifests_root.iterdir()
            if path.is_dir() and re.fullmatch(r"\d+\.\d+\.\d+", path.name)
        ]
        if not candidates:
            raise ValueError(f"no prior Winget manifest set exists under {manifests_root}")
        source = max(candidates, key=lambda path: semver_key(path.name))
        source_files = [source / filename for filename in WINGET_FILES]
        for source_file in source_files:
            if not source_file.is_file():
                raise ValueError(f"incomplete source Winget manifest set: missing {source_file}")
        destination.mkdir(parents=True)
        for filename, source_file in zip(WINGET_FILES, source_files):
            text = source_file.read_bytes().decode("utf-8")
            text = text.replace(source.name, version).replace(f"v{source.name}", f"v{version}")
            (destination / filename).write_bytes(text.encode("utf-8"))
    for filename in WINGET_FILES:
        if not (destination / filename).is_file():
            raise ValueError(f"incomplete Winget manifest set: missing {destination / filename}")
    return destination


def write_preserving_newlines(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def update_homebrew(path: Path, version: str, tag: str, checksums: dict[str, str]) -> None:
    text = path.read_bytes().decode("utf-8")
    text = exact_substitution(
        text,
        re.compile(r'(?m)^([ \t]*)version "[^"]+"(\r?)$'),
        lambda match: f'{match.group(1)}version "{version}"{match.group(2)}',
        str(path),
    )
    for target in HOMEBREW_TARGETS:
        digest = checksums[f"ciphervault-{tag}-{target}.tar.gz"]
        pattern = re.compile(
            rf'(?m)^([ \t]*)url "({re.escape(REPO_RELEASE_URL)})[^/"\r\n]+/'
            rf'ciphervault-v\d+\.\d+\.\d+-{re.escape(target)}\.tar\.gz"(\r?\n)'
            rf'\1sha256 "[0-9a-f]{{64}}"(\r?)$'
        )

        def replace(match: re.Match[str]) -> str:
            indent, base_url, newline, trailing_cr = match.groups()
            filename = f"ciphervault-{tag}-{target}.tar.gz"
            return (
                f'{indent}url "{base_url}{tag}/{filename}"{newline}'
                f'{indent}sha256 "{checksums[filename]}"{trailing_cr}'
            )

        text = exact_substitution(text, pattern, replace, f"{path} ({target})")
    write_preserving_newlines(path, text)


def update_scoop(path: Path, version: str, tag: str, checksums: dict[str, str]) -> None:
    text = path.read_bytes().decode("utf-8")
    text = exact_substitution(
        text,
        re.compile(r'(?m)^([ \t]*)"version": "[^"]+",(\r?)$'),
        lambda match: f'{match.group(1)}"version": "{version}",{match.group(2)}',
        str(path),
    )
    filename = f"ciphervault-{tag}-{WINDOWS_TARGET}.zip"
    pattern = re.compile(
        rf'(?m)^([ \t]*)"url": "{re.escape(REPO_RELEASE_URL)}[^/"\r\n]+/'
        rf'ciphervault-v\d+\.\d+\.\d+-{re.escape(WINDOWS_TARGET)}\.zip",(\r?\n)'
        rf'\1"hash": "[0-9a-f]{{64}}",(\r?)$'
    )

    def replace(match: re.Match[str]) -> str:
        indent, newline, trailing_cr = match.groups()
        return (
            f'{indent}"url": "{REPO_RELEASE_URL}{tag}/{filename}",{newline}'
            f'{indent}"hash": "{checksums[filename]}",{trailing_cr}'
        )

    text = exact_substitution(text, pattern, replace, str(path))
    write_preserving_newlines(path, text)


def update_winget(manifests_root: Path, version: str, checksums: dict[str, str], tag: str) -> None:
    destination = seed_winget_manifests(manifests_root, version)
    for filename in WINGET_FILES:
        path = destination / filename
        text = path.read_bytes().decode("utf-8")
        if not re.search(rf"(?m)^PackageVersion: {re.escape(version)}\r?$", text):
            raise ValueError(f"Winget manifest has the wrong PackageVersion: {path}")

    installer = destination / f"{PACKAGE_ID}.installer.yaml"
    text = installer.read_bytes().decode("utf-8")
    expected_url = f"{REPO_RELEASE_URL}{tag}/ciphervault-{tag}-{WINDOWS_TARGET}.zip"
    if text.count(f"InstallerUrl: {expected_url}") != 1:
        raise ValueError(f"Winget installer manifest has the wrong InstallerUrl: {installer}")
    text = exact_substitution(
        text,
        re.compile(r"(?m)^([ \t]*InstallerSha256: )[0-9a-f]{64}(\r?)$"),
        lambda match: (
            f"{match.group(1)}{checksums[f'ciphervault-{tag}-{WINDOWS_TARGET}.zip']}"
            f"{match.group(2)}"
        ),
        str(installer),
    )
    write_preserving_newlines(installer, text)


def update_manifests(dist: Path, sums_path: Path, tag: str) -> None:
    if not re.fullmatch(r"v?\d+\.\d+\.\d+", tag):
        raise ValueError(f"unsupported release tag {tag!r}")
    version = tag[1:] if tag.startswith("v") else tag
    tag = f"v{version}"
    checksums = read_checksums(sums_path, tag)

    update_homebrew(dist / "homebrew/Formula/ciphervault.rb", version, tag, checksums)
    update_scoop(dist / "scoop/ciphervault.json", version, tag, checksums)
    winget = dist / "winget/manifests/c/CipherVault/CipherVault"
    update_winget(winget, version, checksums, tag)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="dist/package-managers directory")
    parser.add_argument("sums", type=Path, help="authenticated SHA256SUMS.txt")
    parser.add_argument("tag", help="release tag, for example v1.0.28")
    args = parser.parse_args()
    update_manifests(args.dist, args.sums, args.tag)
    print(f"Updated Homebrew, Scoop, and Winget manifests for {args.tag}")


if __name__ == "__main__":
    main()
