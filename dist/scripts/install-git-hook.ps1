# CipherVault — Install Git Pre-Commit Secret Leak Prevention Hook
# Usage: powershell -ExecutionPolicy Bypass -File dist/scripts/install-git-hook.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$BinDir = Join-Path (Split-Path -Parent $ScriptDir) "bin"

$CliBin = Join-Path $BinDir "ciphervault.exe"
if (-not (Test-Path $CliBin)) {
    Write-Error "ciphervault.exe not found in $BinDir. Run 'cargo build --release' first."
}

Write-Host "Installing CipherVault pre-commit hook into current Git repository..." -ForegroundColor Cyan
& $CliBin hook install

Write-Host "Verifying hook check..." -ForegroundColor Green
& $CliBin hook check
