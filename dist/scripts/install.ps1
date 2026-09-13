# CipherVault — Automated Windows Installer
# Usage: irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "samuel-1-avson/CipherVault"
$Tag = "v1.0.0"
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

# Check if local release binaries exist (e.g. running locally from repo), otherwise download
$LocalBin = $null
if ($PSScriptRoot) {
    $LocalBin = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\ciphervault.exe"
}
if ($LocalBin -and (Test-Path $LocalBin)) {
    Write-Host "Local binaries found in workspace. Copying..." -ForegroundColor Yellow
    Copy-Item (Join-Path (Split-Path -Parent $PSScriptRoot) "bin\*.exe") -Destination $BinDir -Force
} else {
    $RawBinaryUrl = "https://raw.githubusercontent.com/$Repo/main/dist/bin/ciphervault.exe"
    $TargetExe = Join-Path $BinDir "ciphervault.exe"

    Write-Host "Downloading CipherVault..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
        Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
        Remove-Item $TempZip -Force
    } catch {
        Write-Host "Release archive not yet published on GitHub Releases. Fetching standalone binary..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $RawBinaryUrl -OutFile $TargetExe -UseBasicParsing
            Write-Host "Downloaded standalone binary from repository." -ForegroundColor Green
        } catch {
            if (Get-Command cargo -ErrorAction SilentlyContinue) {
                Write-Host "Compiling locally via cargo..." -ForegroundColor Yellow
                cargo build --release -p ciphervault-cli -p ciphervault-operator -p ciphervault-agent -p ciphervault-maintenance
                Copy-Item "target\release\*.exe" -Destination $BinDir -Force
            } else {
                throw "Could not download CipherVault executable. Please check internet connection or visit https://github.com/$Repo"
            }
        }
    }
}

# Add to User PATH if not present
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$BinDir*") {
    Write-Host "Adding $BinDir to User PATH..." -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$BinDir", [EnvironmentVariableTarget]::User)
    $env:Path = "$env:Path;$BinDir"
}

Write-Host ""
Write-Host "[+] CipherVault successfully installed to $BinDir!" -ForegroundColor Green
Write-Host ""
Write-Host "Quickstart:" -ForegroundColor Yellow
Write-Host "  ciphervault init                    # Initialize vault in current repository"
Write-Host "  ciphervault track .env              # Track confidential files"
Write-Host "  ciphervault push -m 'Initial'       # Encrypt and replicate snapshot"
Write-Host "  ciphervault ui                      # Launch local web dashboard"
Write-Host ""

