<#
.SYNOPSIS
    Installs CipherVault background daemons as managed Windows Services.

.DESCRIPTION
    Registers CipherVaultAgent and CipherVaultMaintenance as persistent Windows Services
    with automatic recovery and restart actions. Requires Administrator privileges.

.PARAMETER BinDir
    Directory containing ciphervault-agent.exe and ciphervault-maintenance.exe.
    Defaults to the repo's dist\bin directory.

.EXAMPLE
    .\deploy\windows\install-services.ps1
#>

[CmdletBinding()]
param(
    [string]$BinDir = "$PSScriptRoot\..\..\dist\bin"
)

$ErrorActionPreference = "Stop"

# Check Administrator Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to register Windows Services. Please relaunch PowerShell as Administrator."
    exit 1
}

$ResolvedBinDir = (Resolve-Path $BinDir).Path
$AgentExe = Join-Path $ResolvedBinDir "ciphervault-agent.exe"
$MaintExe = Join-Path $ResolvedBinDir "ciphervault-maintenance.exe"

if (-not (Test-Path $AgentExe)) {
    Write-Error "Could not find ciphervault-agent.exe at $AgentExe"
    exit 1
}
if (-not (Test-Path $MaintExe)) {
    Write-Error "Could not find ciphervault-maintenance.exe at $MaintExe"
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CipherVault Windows Service Installer                   " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Binary Directory: $ResolvedBinDir"

# 1. Register CipherVaultAgent Service
$agentServiceName = "CipherVaultAgent"
$existingAgent = Get-Service -Name $agentServiceName -ErrorAction SilentlyContinue

if ($existingAgent) {
    Write-Host "Service '$agentServiceName' already exists. Stopping and updating..." -ForegroundColor Yellow
    Stop-Service -Name $agentServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $agentServiceName | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "Registering '$agentServiceName'..." -ForegroundColor Cyan
$agentBinPath = "`"$AgentExe`""
sc.exe create $agentServiceName binPath= $agentBinPath start= auto DisplayName= "CipherVault Watcher Agent" | Out-Null
sc.exe description $agentServiceName "CipherVault Continuous File Watcher and Zero-Knowledge Snapshot Engine." | Out-Null
sc.exe failure $agentServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null

Write-Host "  ✓ Registered '$agentServiceName' (Automatic Startup with Auto-Recovery)" -ForegroundColor Green

# 2. Register CipherVaultMaintenance Service
$maintServiceName = "CipherVaultMaintenance"
$existingMaint = Get-Service -Name $maintServiceName -ErrorAction SilentlyContinue

if ($existingMaint) {
    Write-Host "Service '$maintServiceName' already exists. Stopping and updating..." -ForegroundColor Yellow
    Stop-Service -Name $maintServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $maintServiceName | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "Registering '$maintServiceName'..." -ForegroundColor Cyan
$maintBinPath = "`"$MaintExe`" --operators http://127.0.0.1:8201 http://127.0.0.1:8202 http://127.0.0.1:8203 --interval-secs 30"
sc.exe create $maintServiceName binPath= $maintBinPath start= auto DisplayName= "CipherVault Self-Repair Maintenance Engine" | Out-Null
sc.exe description $maintServiceName "CipherVault Distributed Replica Maintenance, Closure Audit, and Self-Repair Engine." | Out-Null
sc.exe failure $maintServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

Write-Host "  ✓ Registered '$maintServiceName' (Automatic Startup with Auto-Recovery)" -ForegroundColor Green

Write-Host "`nInstallation complete! You can manage services via 'services.msc' or PowerShell:" -ForegroundColor Green
Write-Host "  Start-Service -Name CipherVaultAgent" -ForegroundColor White
Write-Host "  Start-Service -Name CipherVaultMaintenance" -ForegroundColor White
