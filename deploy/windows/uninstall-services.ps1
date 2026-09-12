<#
.SYNOPSIS
    Uninstalls CipherVault Windows Services.

.DESCRIPTION
    Stops and unregisters CipherVaultAgent and CipherVaultMaintenance services.
    Requires Administrator privileges.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to unregister Windows Services. Please relaunch PowerShell as Administrator."
    exit 1
}

$services = @("CipherVaultAgent", "CipherVaultMaintenance")

foreach ($svc in $services) {
    $existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Stopping and deleting '$svc'..." -ForegroundColor Yellow
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        sc.exe delete $svc | Out-Null
        Write-Host "  ✓ Deleted '$svc'" -ForegroundColor Green
    } else {
        Write-Host "Service '$svc' is not installed." -ForegroundColor Gray
    }
}

Write-Host "`nAll CipherVault Windows Services have been uninstalled." -ForegroundColor Green
