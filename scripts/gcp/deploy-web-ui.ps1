<#
.SYNOPSIS
    Deploys the CipherVault Web Dashboard to a dedicated, Free-Tier-eligible GCP Compute Engine VM with automated Let's Encrypt TLS.

.DESCRIPTION
    Provisions 'cv-web-ui' in us-central1-a on an e2-micro instance, opens ports 80 and 443,
    and returns the public IP address with exact GoDaddy DNS setup instructions.

.PARAMETER DomainName
    The full domain or subdomain to serve (e.g. vault.yourdomain.com).

.PARAMETER AcmeEmail
    Email address for Let's Encrypt expiry and security notices.

.PARAMETER Zone
    GCP zone to deploy into (default: us-central1-a).

.EXAMPLE
    .\scripts\gcp\deploy-web-ui.ps1 -DomainName "vault.mysecurityapp.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Full subdomain or domain (e.g. vault.yourdomain.com)")]
    [string]$DomainName,

    [Parameter(Mandatory = $false)]
    [string]$AcmeEmail = "admin@example.com",

    [Parameter(Mandatory = $false)]
    [string]$Zone = "us-central1-a",

    [Parameter(Mandatory = $false)]
    [string]$MachineType = "e2-micro",

    [Parameter(Mandatory = $false)]
    [int]$BootDiskSizeGb = 20
)

$ErrorActionPreference = "Stop"

# Helper to find gcloud command
$GcloudCmd = "gcloud"
if (Get-Command "gcloud.cmd" -ErrorAction SilentlyContinue) {
    $GcloudCmd = "gcloud.cmd"
} elseif (Test-Path "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd") {
    $GcloudCmd = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  CipherVault Web Dashboard GCP Provisioner            " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Target Domain:  $DomainName" -ForegroundColor Yellow
Write-Host "Machine Type:   $MachineType (GCP Always-Free eligible)" -ForegroundColor Yellow
Write-Host "Zone:           $Zone" -ForegroundColor Yellow

# 1. Verify Active Project
$Project = & $GcloudCmd config get-value project 2>$null
if (-not $Project) {
    Write-Error "No active GCP project found. Run 'gcloud init' or 'gcloud config set project <PROJECT_ID>'."
}
Write-Host "GCP Project:    $Project" -ForegroundColor Green

# 2. Configure Firewall Rule for Ingress (Ports 80 & 443)
Write-Host "`n[1/4] Ensuring Firewall Rule for HTTP/HTTPS Ingress..." -ForegroundColor Cyan
$FwExists = & $GcloudCmd compute firewall-rules list --filter="name=allow-ciphervault-web-ui" --format="value(name)" 2>$null
if (-not $FwExists) {
    & $GcloudCmd compute firewall-rules create allow-ciphervault-web-ui `
        --allow=tcp:80,tcp:443 `
        --target-tags=ciphervault-web-ui `
        --description="Allow public HTTP and HTTPS ingress for CipherVault Web Dashboard" `
        --quiet
    Write-Host "✓ Firewall rule 'allow-ciphervault-web-ui' created." -ForegroundColor Green
} else {
    Write-Host "✓ Firewall rule 'allow-ciphervault-web-ui' already exists." -ForegroundColor Green
}

# 3. Create or Update Compute Engine Instance
$InstanceName = "cv-web-ui"
Write-Host "`n[2/4] Checking Compute Engine instance '$InstanceName'..." -ForegroundColor Cyan
$InstExists = & $GcloudCmd compute instances list --filter="name=$InstanceName AND zone:($Zone)" --format="value(name)" 2>$null

$StartupScriptPath = Join-Path $PSScriptRoot "..\..\deploy\gcp\startup-web.sh"

if (-not $InstExists) {
    Write-Host "Provisioning new VM '$InstanceName' ($MachineType in $Zone)..." -ForegroundColor Cyan
    & $GcloudCmd compute instances create $InstanceName `
        --zone=$Zone `
        --machine-type=$MachineType `
        --image-family=ubuntu-2404-lts-amd64 `
        --image-project=ubuntu-os-cloud `
        --boot-disk-size="${BootDiskSizeGb}GB" `
        --boot-disk-type="pd-balanced" `
        --tags="ciphervault-web-ui,http-server,https-server" `
        --metadata-from-file="startup-script=$StartupScriptPath" `
        --metadata="web-domain=$DomainName,acme-email=$AcmeEmail" `
        --quiet
    Write-Host "✓ Instance '$InstanceName' created." -ForegroundColor Green
} else {
    Write-Host "Updating metadata for existing instance '$InstanceName'..." -ForegroundColor Cyan
    & $GcloudCmd compute instances add-metadata $InstanceName `
        --zone=$Zone `
        --metadata="web-domain=$DomainName,acme-email=$AcmeEmail" `
        --metadata-from-file="startup-script=$StartupScriptPath" `
        --quiet
    Write-Host "✓ Metadata updated." -ForegroundColor Green
}

# 4. Retrieve Public IP Address
Write-Host "`n[3/4] Retrieving Public IP address..." -ForegroundColor Cyan
Start-Sleep -Seconds 3
$ExternalIp = & $GcloudCmd compute instances describe $InstanceName `
    --zone=$Zone `
    --format="value(networkInterfaces[0].accessConfigs[0].natIP)"

if (-not $ExternalIp) {
    Write-Error "Failed to retrieve external IP for $InstanceName."
}

Write-Host "✓ Public IP: $ExternalIp" -ForegroundColor Green

# 5. Output GoDaddy DNS Instructions
Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host "           GODADDY DNS CONFIGURATION GUIDE              " -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green

# Parse host part for subdomain
$HostPart = $DomainName
if ($DomainName -match '^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_.-]+)$') {
    $HostPart = $Matches[1]
}

Write-Host "Log in to your GoDaddy Account -> Domain Portfolio -> Manage DNS for your domain:`n"
Write-Host "  1. Click 'Add New Record'" -ForegroundColor White
Write-Host "  2. Set the following fields:" -ForegroundColor White
Write-Host "     ------------------------------------------------" -ForegroundColor DarkGray
Write-Host "     Type:  A" -ForegroundColor Yellow
Write-Host "     Name:  $HostPart" -ForegroundColor Yellow
Write-Host "     Value: $ExternalIp" -ForegroundColor Yellow
Write-Host "     TTL:   1/2 Hour (or 600 seconds)" -ForegroundColor Yellow
Write-Host "     ------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  3. Click 'Save'.`n" -ForegroundColor White

Write-Host "Once DNS propagates (usually 1-3 minutes):" -ForegroundColor Cyan
Write-Host "  • Caddy will automatically issue a Let's Encrypt TLS certificate." -ForegroundColor White
Write-Host "  • Your CipherVault Web Dashboard will be live at:" -ForegroundColor White
Write-Host "    https://$DomainName" -ForegroundColor Green
Write-Host "=======================================================`n" -ForegroundColor Green
