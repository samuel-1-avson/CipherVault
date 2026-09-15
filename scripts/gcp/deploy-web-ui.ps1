[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [Parameter(Mandatory = $false)]
    [string]$AcmeEmail = "admin@example.com",

    [Parameter(Mandatory = $false)]
    [string]$Zone = "us-east1-b",

    [Parameter(Mandatory = $false)]
    [string]$MachineType = "e2-micro",

    [Parameter(Mandatory = $false)]
    [int]$BootDiskSizeGb = 20,

    [Parameter(Mandatory = $false)]
    [string]$WebAuthnRpId = "",

    [Parameter(Mandatory = $false)]
    [string]$WebAuthnOrigin = "",

    [Parameter(Mandatory = $false)]
    [string]$AccountAllowedOrigins = ""
)

$ErrorActionPreference = "Stop"

$GcloudCmd = "gcloud"
if (Get-Command "gcloud.cmd" -ErrorAction SilentlyContinue) {
    $GcloudCmd = "gcloud.cmd"
} elseif (Test-Path "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd") {
    $GcloudCmd = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  CipherVault Web Dashboard GCP Provisioner            " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ("Target Domain:  " + $DomainName) -ForegroundColor Yellow
Write-Host ("Machine Type:   " + $MachineType + " (GCP Always-Free eligible)") -ForegroundColor Yellow
Write-Host ("Zone:           " + $Zone) -ForegroundColor Yellow

# 1. Verify Active Project
$Project = & $GcloudCmd config get-value project 2>$null
if (-not $Project) {
    Write-Error "No active GCP project found. Run 'gcloud init' or 'gcloud config set project <PROJECT_ID>'."
}
Write-Host ("GCP Project:    " + $Project) -ForegroundColor Green

# 2. Configure Firewall Rule for Ingress (Ports 80 & 443)
Write-Host ""
Write-Host "[1/4] Ensuring Firewall Rule for HTTP/HTTPS Ingress..." -ForegroundColor Cyan
$FwExists = & $GcloudCmd compute firewall-rules list --filter="name=allow-ciphervault-web-ui" --format="value(name)" 2>$null
if (-not $FwExists) {
    & $GcloudCmd compute firewall-rules create allow-ciphervault-web-ui `
        --allow=tcp:80,tcp:443 `
        --target-tags=ciphervault-web-ui `
        --description="Allow public HTTP and HTTPS ingress for CipherVault Web Dashboard" `
        --quiet
    Write-Host "Firewall rule 'allow-ciphervault-web-ui' created." -ForegroundColor Green
} else {
    Write-Host "Firewall rule 'allow-ciphervault-web-ui' already exists." -ForegroundColor Green
}

# 3. Create or Update Compute Engine Instance
$InstanceName = "cv-web-ui"
Write-Host ""
Write-Host ("[2/4] Checking Compute Engine instance " + $InstanceName + "...") -ForegroundColor Cyan
$InstExists = & $GcloudCmd compute instances list --filter="name=$InstanceName AND zone:($Zone)" --format="value(name)" 2>$null

$StartupScriptPath = Join-Path $PSScriptRoot "..\..\deploy\gcp\startup-web.sh"

if (-not $WebAuthnRpId) { $WebAuthnRpId = $DomainName }
if (-not $WebAuthnOrigin) { $WebAuthnOrigin = "https://$DomainName" }
if (-not $AccountAllowedOrigins) { $AccountAllowedOrigins = $WebAuthnOrigin }

$DiskArg = "$BootDiskSizeGb" + "GB"
$MetaFileArg = "startup-script=" + $StartupScriptPath
$MetaArg = "web-domain=$DomainName,acme-email=$AcmeEmail,webauthn-rp-id=$WebAuthnRpId,webauthn-origin=$WebAuthnOrigin,account-allowed-origins=$AccountAllowedOrigins"

if (-not $InstExists) {
    Write-Host ("Provisioning new VM " + $InstanceName + " (" + $MachineType + " in " + $Zone + ")...") -ForegroundColor Cyan
    & $GcloudCmd compute instances create $InstanceName `
        --zone=$Zone `
        --machine-type=$MachineType `
        --image-family=ubuntu-2404-lts-amd64 `
        --image-project=ubuntu-os-cloud `
        --boot-disk-size=$DiskArg `
        --boot-disk-type="pd-balanced" `
        --tags="ciphervault-web-ui,http-server,https-server" `
        --metadata-from-file=$MetaFileArg `
        --metadata=$MetaArg `
        --quiet
    Write-Host ("Instance " + $InstanceName + " created successfully.") -ForegroundColor Green
} else {
    Write-Host ("Updating metadata for existing instance " + $InstanceName + "...") -ForegroundColor Cyan
    & $GcloudCmd compute instances add-metadata $InstanceName `
        --zone=$Zone `
        --metadata=$MetaArg `
        --metadata-from-file=$MetaFileArg `
        --quiet
    Write-Host "Metadata updated." -ForegroundColor Green
}

# 4. Retrieve Public IP Address
Write-Host ""
Write-Host "[3/4] Retrieving Public IP address..." -ForegroundColor Cyan
Start-Sleep -Seconds 3
$ExternalIp = & $GcloudCmd compute instances describe $InstanceName `
    --zone=$Zone `
    --format="value(networkInterfaces[0].accessConfigs[0].natIP)"

if (-not $ExternalIp) {
    Write-Error ("Failed to retrieve external IP for " + $InstanceName)
}

Write-Host ("Public IP: " + $ExternalIp) -ForegroundColor Green

# 5. Output GoDaddy DNS Instructions
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "           GODADDY DNS CONFIGURATION GUIDE              " -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green

$HostPart = "vault"
if ($DomainName.Contains(".")) {
    $HostPart = $DomainName.Split(".")[0]
}

Write-Host "In GoDaddy DNS Manager for your domain, add this record:"
Write-Host ""
Write-Host "  Type:  A" -ForegroundColor Yellow
Write-Host ("  Name:  " + $HostPart) -ForegroundColor Yellow
Write-Host ("  Value: " + $ExternalIp) -ForegroundColor Yellow
Write-Host "  TTL:   1/2 Hour (or 600 seconds)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Once DNS propagates (typically 1-3 minutes):" -ForegroundColor Cyan
Write-Host "  - Caddy automatically provisions a Let's Encrypt TLS certificate." -ForegroundColor White
Write-Host ("  - Your dashboard will be live at: https://" + $DomainName) -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""
