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
winget install --manifest dist/package-managers/winget/manifests/c/CipherVault/CipherVault/0.1.0-beta.2/

# Upstream publication:
wingetcreate submit dist/package-managers/winget/manifests/c/CipherVault/CipherVault/0.1.0-beta.2/
```

---

## 4. One-Liner Installers

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/master/dist/scripts/install.ps1 | iex
```

### Linux & macOS (Bash)
```bash
curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/master/dist/scripts/install.sh | bash
```
