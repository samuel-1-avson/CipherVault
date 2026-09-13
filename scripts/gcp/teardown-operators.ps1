# ==============================================================================
# CipherVault — Google Cloud Platform (GCP) VPS Operator Cluster Decommissioner
# ==============================================================================
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/gcp/teardown-operators.ps1
# ==============================================================================

[CmdletBinding()]
param(
    [string]$Project = "",
    [string[]]$Zones = @("us-central1-a", "us-central1-b", "us-central1-c"),
    [string]$Prefix = "cv-operator",
    [switch]$DeleteFirewall
)

$ErrorActionPreference = "Stop"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  CipherVault GCP VPS Storage Operator Teardown" -ForegroundColor Red
Write-Host "=======================================================" -ForegroundColor Cyan

# 1. Resolve Active Project
if (-not $Project) {
    $Project = (gcloud config get-value project 2>&1).Trim()
}
Write-Host "Active GCP Project: " -NoNewline
Write-Host $Project -ForegroundColor Yellow

# 2. Delete Compute Instances
for ($i = 0; $i -lt $Zones.Count; $i++) {
    $nodeNum = $i + 1
    $vmName = "$Prefix-$nodeNum"
    $zone = $Zones[$i]

    Write-Host "Checking $vmName in $zone..." -NoNewline
    $checkArgs = @("compute", "instances", "list", "--project=$Project", "--filter=name=$vmName AND zone:$zone", '--format=value(name)')
    $exists = & gcloud @checkArgs 2>&1
    if ($exists) {
        Write-Host " Deleting..." -ForegroundColor Yellow
        $delArgs = @("compute", "instances", "delete", $vmName, "--project=$Project", "--zone=$zone", "--quiet")
        & gcloud @delArgs | Out-Null
        Write-Host "  [OK] Deleted $vmName!" -ForegroundColor Green
    } else {
        Write-Host " [NOT FOUND]" -ForegroundColor DarkGray
    }
}

# 3. Optional Firewall Deletion
if ($DeleteFirewall) {
    $FirewallRule = "ciphervault-allow-ingress"
    Write-Host ""
    Write-Host "Deleting firewall rule $FirewallRule..." -ForegroundColor Yellow
    $fwDelArgs = @("compute", "firewall-rules", "delete", $FirewallRule, "--project=$Project", "--quiet")
    & gcloud @fwDelArgs 2>&1 | Out-Null
    Write-Host "  [OK] Deleted $FirewallRule!" -ForegroundColor Green
}

Write-Host ""
Write-Host "Teardown complete! All specified CipherVault GCP VPS resources removed." -ForegroundColor Green
