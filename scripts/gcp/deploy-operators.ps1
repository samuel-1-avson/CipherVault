# ==============================================================================
# CipherVault — Google Cloud Platform (GCP) VPS Operator Cluster Provisioner
# ==============================================================================
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/gcp/deploy-operators.ps1
# ==============================================================================

[CmdletBinding()]
param(
    [string]$Project = "",
    [string]$MachineType = "e2-micro",
    [string]$DiskSize = "20GB",
    [string[]]$Zones = @("us-central1-a", "us-central1-b", "us-east1-b"),
    [string]$Prefix = "cv-operator"
)

$ErrorActionPreference = "Continue"
if (Test-Path Variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  CipherVault GCP VPS Storage Operator Provisioner" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan

# 1. Check gcloud CLI (with PATH auto-discovery)
Write-Host "Checking Google Cloud SDK..." -NoNewline
$gcloudCmd = Get-Command gcloud -ErrorAction SilentlyContinue
if (-not $gcloudCmd) {
    $defaultGcloudDir = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin"
    if (Test-Path "$defaultGcloudDir\gcloud.cmd") {
        $env:PATH = "$defaultGcloudDir;$env:PATH"
        $gcloudCmd = Get-Command gcloud -ErrorAction SilentlyContinue
    }
}

if ($gcloudCmd) {
    Write-Host " [FOUND]" -ForegroundColor Green
} else {
    Write-Host " [FAILED]" -ForegroundColor Red
    Write-Error "gcloud CLI is not installed or not in PATH. Please install Google Cloud SDK."
}

# 2. Resolve Active Project
if (-not $Project) {
    $Project = (gcloud config get-value project 2>$null)
    if ($Project) { $Project = $Project.Trim() }
}
if (-not $Project -or $Project -match "none") {
    Write-Error "No GCP project configured. Run 'gcloud config set project <PROJECT_ID>' first."
}
Write-Host "Active GCP Project: " -NoNewline
Write-Host $Project -ForegroundColor Yellow

# 3. Locate Startup Script
$StartupScript = (Resolve-Path (Join-Path $PSScriptRoot "..\..\deploy\gcp\startup.sh")).Path

if (-not (Test-Path $StartupScript)) {
    Write-Error "Cannot find startup script at $StartupScript"
}

# 4. Create Cloud Firewall Ingress Rule (tcp:80, tcp:443)
$FirewallRule = "ciphervault-allow-ingress"
Write-Host ""
Write-Host "Checking Cloud Firewall Rule '$FirewallRule'..." -NoNewline
$fwList = & gcloud compute firewall-rules list --project=$Project "--filter=name=$FirewallRule" '--format=value(name)' 2>$null

if (-not $fwList) {
    Write-Host " Creating rule..." -ForegroundColor Yellow
    $fwArgs = @(
        "compute", "firewall-rules", "create", $FirewallRule,
        "--project=$Project",
        "--direction=INGRESS",
        "--priority=1000",
        "--network=default",
        "--action=ALLOW",
        "--rules=tcp:80,tcp:443",
        "--source-ranges=0.0.0.0/0",
        "--target-tags=ciphervault-operator"
    )
    & gcloud @fwArgs | Out-Null
    Write-Host "Firewall rule created successfully! (Ports 80 & 443 open for tag 'ciphervault-operator')" -ForegroundColor Green
} else {
    Write-Host " [ALREADY EXISTS]" -ForegroundColor Green
}

# 5. Provision 3 Compute Engine VPS Instances
Write-Host ""
Write-Host "Provisioning 3-node Storage Operator Quorum across distinct GCP zones..." -ForegroundColor Cyan

$Endpoints = @()
$Instances = @()

for ($i = 0; $i -lt $Zones.Count; $i++) {
    $nodeNum = $i + 1
    $vmName = "$Prefix-$nodeNum"
    $zone = $Zones[$i]

    Write-Host ""
    Write-Host "[$nodeNum/3] Deploying $vmName in zone $zone ($MachineType, $DiskSize)..." -ForegroundColor Yellow

    # Check if instance already exists
    $listArgs = @("compute", "instances", "list", "--project=$Project", "--filter=name=$vmName AND zone:$zone", '--format=value(name)')
    $existing = & gcloud @listArgs 2>$null
    if ($existing) {
        Write-Host "  Instance $vmName already exists in $zone. Reusing." -ForegroundColor DarkGray
    } else {
        $createArgs = @(
            "compute", "instances", "create", $vmName,
            "--project=$Project",
            "--zone=$zone",
            "--machine-type=$MachineType",
            "--network-interface=network-tier=PREMIUM,subnet=default",
            "--metadata-from-file=startup-script=$StartupScript",
            "--tags=ciphervault-operator,http-server,https-server",
            "--boot-disk-size=$DiskSize",
            "--boot-disk-type=pd-balanced",
            "--image-family=ubuntu-2404-lts-amd64",
            "--image-project=ubuntu-os-cloud"
        )
        $createOut = (& gcloud @createArgs 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [FAILED] Could not launch $vmName in ${zone}:" -ForegroundColor Red
            Write-Host $createOut -ForegroundColor Red
            return
        }
        Write-Host "  [OK] Instance $vmName launched!" -ForegroundColor Green
    }

    # Fetch External IP
    $ipArgs = @("compute", "instances", "describe", $vmName, "--project=$Project", "--zone=$zone", '--format=value(networkInterfaces[0].accessConfigs[0].natIP)')
    $externalIp = (& gcloud @ipArgs 2>$null)
    if ($externalIp) { $externalIp = $externalIp.Trim() }
    
    $Instances += [PSCustomObject]@{
        Node        = $nodeNum
        Name        = $vmName
        Zone        = $zone
        MachineType = $MachineType
        ExternalIP  = $externalIp
        HTTPS_URL   = "https://$externalIp"
    }

    $Endpoints += "https://$externalIp"
}

# 6. Display Summary Matrix
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  GCP STORAGE OPERATOR CLUSTER PROVISIONED" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan

$Instances | Format-Table -AutoSize

Write-Host "NOTE: Startup script is bootstrapping Docker and Caddy on VMs." -ForegroundColor DarkGray
Write-Host "Initial container build takes ~2-3 minutes after VM launch." -ForegroundColor DarkGray
Write-Host "=======================================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "Ready-to-use CipherVault Client Initialization Command:" -ForegroundColor Green
$joinedEndpoints = $Endpoints -join ' '
Write-Host "ciphervault init --operators $joinedEndpoints" -ForegroundColor Yellow
Write-Host ""

if ($Instances.Count -gt 0) {
    Write-Host "To monitor startup logs on any instance:" -ForegroundColor Cyan
    $firstVm = $Instances[0].Name
    $firstZone = $Instances[0].Zone
    $logCmd = "gcloud compute ssh $firstVm --zone=$firstZone"
    Write-Host "SSH into node: $logCmd" -ForegroundColor DarkGray
}
