# CipherVault — Launch Local 3-Operator Storage Cluster & Dashboard
# Usage: powershell -ExecutionPolicy Bypass -File dist/scripts/run-local-cluster.ps1 [-WithUi] [-Stop]

param (
    [switch]$WithUi,
    [switch]$Stop
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$BinDir = Join-Path (Split-Path -Parent $ScriptDir) "bin"

if ($Stop) {
    Write-Host "Stopping all local CipherVault operators and UI processes..." -ForegroundColor Yellow
    Get-Process -Name "ciphervault-operator", "ciphervault" -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "All local processes stopped." -ForegroundColor Green
    exit 0
}

$OpBin = Join-Path $BinDir "ciphervault-operator.exe"
if (-not (Test-Path $OpBin)) {
    Write-Error "ciphervault-operator.exe not found in $BinDir. Run 'cargo build --release' first."
}

$CliBin = Join-Path $BinDir "ciphervault.exe"

$DataDir = Join-Path (Split-Path -Parent $ScriptDir) "data"
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "op-8201") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "op-8202") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "op-8203") | Out-Null

Write-Host "Starting Operator 1 on port 8201..." -ForegroundColor Cyan
$p1 = Start-Process -FilePath $OpBin -ArgumentList "--port 8201 --data-dir `"$DataDir\op-8201`" --operator-id op_8201" -PassThru

Write-Host "Starting Operator 2 on port 8202..." -ForegroundColor Cyan
$p2 = Start-Process -FilePath $OpBin -ArgumentList "--port 8202 --data-dir `"$DataDir\op-8202`" --operator-id op_8202" -PassThru

Write-Host "Starting Operator 3 on port 8203..." -ForegroundColor Cyan
$p3 = Start-Process -FilePath $OpBin -ArgumentList "--port 8203 --data-dir `"$DataDir\op-8203`" --operator-id op_8203" -PassThru

$pids = @($p1.Id, $p2.Id, $p3.Id)

if ($WithUi -and (Test-Path $CliBin)) {
    Write-Host "Starting Web Dashboard on port 8080..." -ForegroundColor Magenta
    $pUi = Start-Process -FilePath $CliBin -ArgumentList "ui --port 8080 --no-browser" -PassThru
    $pids += $pUi.Id
    Write-Host "Web Dashboard PID: $($pUi.Id) (http://127.0.0.1:8080)" -ForegroundColor Magenta
}

Write-Host "`nAll services spawned successfully!" -ForegroundColor Green
Write-Host "Operator 1 PID: $($p1.Id) (http://127.0.0.1:8201)"
Write-Host "Operator 2 PID: $($p2.Id) (http://127.0.0.1:8202)"
Write-Host "Operator 3 PID: $($p3.Id) (http://127.0.0.1:8203)"
if ($WithUi) {
    Write-Host "Dashboard:      http://127.0.0.1:8080"
}
Write-Host "`nTo stop all processes: powershell -File dist/scripts/run-local-cluster.ps1 -Stop" -ForegroundColor Yellow
