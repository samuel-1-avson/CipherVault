# CipherVault Package Manager Manifests & Distribution

This directory contains package manager manifests and installation configurations for **CipherVault** across macOS, Linux, and Windows.

---

## 1. Scoop (Windows)

Install with [Scoop](https://scoop.sh):

```powershell
# Option A: Install from local repository / direct manifest
scoop install dist/package-managers/scoop/ciphervault.json

# Option B: Install via custom tap/bucket
scoop bucket add ciphervault https://github.com/samuel-1-avson/CipherVault
scoop install ciphervault
```

The manifest automatically places `ciphervault.exe`, `ciphervault-operator.exe`, `ciphervault-agent.exe`, and `ciphervault-maintenance.exe` in your Scoop shims directory.

---

## 2. Homebrew (macOS & Linux)

Install with [Homebrew](https://brew.sh):

```bash
# Option A: Direct install from URL
brew install --formula dist/package-managers/homebrew/Formula/ciphervault.rb

# Option B: Install via tap
brew tap samuel-1-avson/ciphervault https://github.com/samuel-1-avson/CipherVault
brew install ciphervault
```

Supports:
- macOS Apple Silicon (`aarch64-apple-darwin`)
- macOS Intel (`x86_64-apple-darwin`)
- Linux x86_64 (`x86_64-unknown-linux-gnu`)
- Linux ARM64 (`aarch64-unknown-linux-gnu`)

---

## 3. Winget (Windows Package Manager)

Install via [Windows Package Manager (`winget`)](https://learn.microsoft.com/en-us/windows/package-manager/winget/):

```powershell
# Local testing:
winget install --manifest dist/package-managers/winget/manifests/c/CipherVault/CipherVault/1.0.17/

# Upstream publication:
wingetcreate submit dist/package-managers/winget/manifests/c/CipherVault/CipherVault/1.0.17/
```

---

## 4. One-Liner Installers

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex
```

### Linux & macOS (Bash)
```bash
curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash
```
---

## 5. Roles: developer vs node runner

Every package installs the full binary set (guided `ciphervault node
setup` needs the CLI next to the operator daemon). Pick your path after
installing:

- **Developers** (day-to-day secrets): `ciphervault init`,
  `ciphervault --help` (command groups), or bare `ciphervault` (guided TUI).
- **Node runners** (contribute storage): `ciphervault node setup`.
- Smaller footprint? The one-liners accept
  `CIPHERVAULT_ROLE=developer|node|full`, and each release ships
  `ciphervault-dev-*` and `ciphervault-node-*` bundles beside the full archive.

Full two-track walkthrough: [docs/SETUP_GUIDE.md](../../docs/SETUP_GUIDE.md).

---

## 6. Updating package manifests for a new release

The release workflow verifies the signed `SHA256SUMS.txt`, then updates the version, release URLs, and hashes in the Homebrew, Scoop, and Winget manifests. If the versioned Winget directory is missing, it seeds the three files from the newest existing manifest before updating them. The workflow opens a pull request for review.

If that job ever fails, first authenticate the checksum file and signature using `dist/scripts/install.sh`, then run the manifest updater against the authenticated checksums:

```sh
tag=v1.0.28
verify_dir="$(mktemp -d)"
trap 'rm -rf "$verify_dir"' EXIT
CIPHERVAULT_INSTALLER_VERIFY_ONLY=1 \
  CIPHERVAULT_VERIFY_SUMS="$PWD/SHA256SUMS.txt" \
  CIPHERVAULT_VERIFY_SIGNATURE="$PWD/SHA256SUMS.txt.sig" \
  CIPHERVAULT_VERIFY_TAG="$tag" \
  CIPHERVAULT_VERIFY_SCRATCH="$verify_dir" \
  bash dist/scripts/install.sh
python3 dist/scripts/fill_package_manager_manifests.py dist/package-managers SHA256SUMS.txt "$tag"
git diff -- dist/package-managers
```
