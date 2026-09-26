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
winget install --manifest dist/package-managers/winget/manifests/c/CipherVault/CipherVault/1.0.16/

# Upstream publication:
wingetcreate submit dist/package-managers/winget/manifests/c/CipherVault/CipherVault/1.0.16/
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

## 6. Refreshing the winget hash for a new release

The release workflow fills `InstallerSha256` (plus the scoop/brew hashes) automatically from the published `SHA256SUMS.txt` and commits the result to `main`.
If that job ever fails, fill manually from `SHA256SUMS.txt`:

```powershell
$tag = 'v1.0.16'
$zip = "ciphervault-$tag-x86_64-pc-windows-msvc.zip"
(Get-Content SHA256SUMS.txt | Select-String $zip).ToString().Split()[0]
```
