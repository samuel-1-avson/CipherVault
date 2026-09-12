# CipherVault — Launch Local 3-Operator Storage Cluster
# Usage: powershell -ExecutionPolicy Bypass -File dist/scripts/run-local-cluster.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$BinDir = Join-Path (Split-Path -Parent $ScriptDir) "bin"

$OpBin = Join-Path $BinDir "ciphervault-operator.exe"
if (-not (Test-Path $OpBin)) {
    Write-Error "ciphervault-operator.exe not found in $BinDir. Run 'cargo build --release' first."
}

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

Write-Host "`nAll 3 operators spawned successfully!" -ForegroundColor Green
Write-Host "Operator 1 PID: $($p1.Id) (http://127.0.0.1:8201)"
Write-Host "Operator 2 PID: $($p2.Id) (http://127.0.0.1:8202)"
Write-Host "Operator 3 PID: $($p3.Id) (http://127.0.0.1:8203)"
Write-Host "`nTo stop all operators: Stop-Process -Id $($p1.Id),$($p2.Id),$($p3.Id)" -ForegroundColor Yellow
