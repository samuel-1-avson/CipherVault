# CipherVault — Automated Windows Installer
# Usage: irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "samuel-1-avson/CipherVault"
$Tag = "v1.0.0"
$Target = "x86_64-pc-windows-msvc"
$PkgName = "ciphervault-$Tag-$Target.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/$PkgName"
$RawBinaryUrl = "https://raw.githubusercontent.com/$Repo/main/dist/bin/ciphervault.exe"

$InstallDir = Join-Path $HOME ".ciphervault"
$BinDir = Join-Path $InstallDir "bin"
$TargetExe = Join-Path $BinDir "ciphervault.exe"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Installing CipherVault $Tag (Windows x64)" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan

# Ensure installation directory exists
if (-not (Test-Path -Path $BinDir)) {
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
}

$TempZip = Join-Path ([System.IO.Path]::GetTempPath()) $PkgName

# Check if a local binary is in the current working directory or dist/bin
$LocalCandidate = "dist\bin\ciphervault.exe"
if (Test-Path -Path $LocalCandidate -PathType Leaf) {
    Write-Host "Found local release binary in workspace. Copying..." -ForegroundColor Yellow
    Copy-Item -Path "dist\bin\*.exe" -Destination $BinDir -Force
} else {
    Write-Host "Downloading CipherVault from GitHub ($Repo)..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
        Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
        Remove-Item -Path $TempZip -Force
    } catch {
        Write-Host "Release archive not yet attached to tag. Downloading standalone binary from repository..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $RawBinaryUrl -OutFile $TargetExe -UseBasicParsing
            Write-Host "Downloaded standalone binary from repository." -ForegroundColor Green
        } catch {
            if (Get-Command cargo -ErrorAction SilentlyContinue) {
                Write-Host "Building locally via cargo..." -ForegroundColor Yellow
                cargo build --release -p ciphervault-cli
                Copy-Item -Path "target\release\ciphervault.exe" -Destination $BinDir -Force
            } else {
                throw "Could not download CipherVault. Please check your internet connection or visit https://github.com/$Repo"
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


