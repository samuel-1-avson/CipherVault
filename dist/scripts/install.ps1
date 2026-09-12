# CipherVault — Automated Windows Installer
# Usage: irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/master/dist/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "samuel-1-avson/CipherVault"
$Tag = "v0.1.0-beta.2"
$Target = "x86_64-pc-windows-msvc"
$PkgName = "ciphervault-$Tag-$Target.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/$PkgName"

$InstallDir = Join-Path $HOME ".ciphervault"
$BinDir = Join-Path $InstallDir "bin"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Installing CipherVault $Tag (Windows x64)" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan

# Create target directories
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$TempZip = Join-Path ([System.IO.Path]::GetTempPath()) $PkgName

# Check if local release zip exists (e.g. running from repo), otherwise download
$LocalBin = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\ciphervault.exe"
if (Test-Path $LocalBin) {
    Write-Host "Local binaries found in workspace. Copying..." -ForegroundColor Yellow
    Copy-Item (Join-Path (Split-Path -Parent $PSScriptRoot) "bin\*.exe") -Destination $BinDir -Force
} else {
    Write-Host "Downloading $DownloadUrl..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
        Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
        Remove-Item $TempZip -Force
    } catch {
        Write-Host "GitHub release asset not yet uploaded. Compiling locally..." -ForegroundColor Yellow
        cargo build --release -p ciphervault-cli -p ciphervault-operator -p ciphervault-agent -p ciphervault-maintenance
        Copy-Item "target\release\*.exe" -Destination $BinDir -Force
    }
}

# Add to User PATH if not present
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$BinDir*") {
    Write-Host "Adding $BinDir to User PATH..." -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$BinDir", [EnvironmentVariableTarget]::User)
    $env:Path = "$env:Path;$BinDir"
}

Write-Host "`n✓ CipherVault successfully installed to $BinDir!" -ForegroundColor Green
Write-Host "`nQuickstart:" -ForegroundColor Yellow
Write-Host "  ciphervault init                    # Initialize vault in current repository"
Write-Host "  ciphervault track .env              # Track confidential files"
Write-Host "  ciphervault push -m 'Initial'       # Encrypt and replicate snapshot"
Write-Host "  ciphervault ui                      # Launch local web dashboard"
Write-Host ""
