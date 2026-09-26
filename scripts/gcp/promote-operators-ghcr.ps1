# ==============================================================================
# CipherVault -- GHCR-Pull Rolling Operator Promotion
# ==============================================================================
# Rolls the storage-operator fleet (cv-operator-1/2/3) to a released version
# by pulling the signed GHCR image instead of rebuilding from source on
# each VM (~90 min x 3). One node at a time, health-gated, with automatic
# rollback to the previous image when a node fails to come back.
#
# Usage:
#   # Dry run: resolve + verify signature + print the plan (default, changes nothing)
#   powershell -ExecutionPolicy Bypass -File scripts/gcp/promote-operators-ghcr.ps1 -Version 1.0.16
#
#   # Live rolling promote:
#   powershell -ExecutionPolicy Bypass -File scripts/gcp/promote-operators-ghcr.ps1 -Version 1.0.16 -Apply
#
# Trust model: the version tag is resolved to an immutable digest with
# `cosign triangulate`, the digest is verified against the release-workflow
# OIDC identity, and nodes pull exactly that digest. The tag is never
# trusted after resolution.
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$OperatorImage = "ghcr.io/samuel-1-avson/ciphervault-operator",

    [string]$OperatorImageDigest = "",

    [string[]]$Nodes = @(
        "cv-operator-1:us-central1-a:https://op1.cipherv.online",
        "cv-operator-2:us-central1-b:https://op2.cipherv.online",
        "cv-operator-3:us-east1-b:https://op3.cipherv.online"
    ),

    [string]$LocalTag = "ciphervault-operator:gcp",

    [string]$ComposeFile = "/opt/ciphervault/docker-compose.yml",

    [string]$Service = "operator",

    [string]$CosignCertificateIdentityRegex = "https://github.com/samuel-1-avson/CipherVault/.github/workflows/release.yml@refs/tags/.*",

    [string]$CosignOidcIssuer = "https://token.actions.githubusercontent.com",

    [int]$HealthTimeoutSec = 180,

    [switch]$Apply
)

$ErrorActionPreference = "Stop"

function Invoke-Gcloud {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & gcloud @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "gcloud $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

# Windows PowerShell 5.1 turns redirected native stderr into a terminating
# error under $ErrorActionPreference = "Stop", even when it is redirected to
# $null. Capture native text output through this helper so the exit code
# drives control flow instead of an ambient stderr line.
function Invoke-NativeText {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    $previousEAP = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & $Command @Arguments 2>$null
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEAP
    }
    return @{ Output = $output; ExitCode = $exitCode }
}

function Get-SshOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][string]$Zone,
        [Parameter(Mandatory = $true)][string]$RemoteCommand
    )
    $previousEAP = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & gcloud compute ssh $Node --zone=$Zone --command=$RemoteCommand 2>$null
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEAP
    }
    if ($exitCode -ne 0) {
        throw "ssh to $Node failed with exit code $exitCode"
    }
    return ($output | Out-String)
}

function Test-NodeHealth {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$Node
    )
    try {
        $body = Invoke-RestMethod "$Endpoint/healthz" -TimeoutSec 20
        if ($body.status -eq "ready" -and $body.storage_ready -eq $true) {
            return $true
        }
        Write-Warning "$Node healthz not ready: $($body | ConvertTo-Json -Compress)"
        return $false
    } catch {
        Write-Warning "$Node healthz unreachable: $($_.Exception.Message)"
        return $false
    }
}

function Wait-NodeHealth {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$Node,
        [int]$TimeoutSec = 180
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-NodeHealth -Endpoint $Endpoint -Node $Node) {
            return $true
        }
        Start-Sleep -Seconds 10
    }
    return $false
}

# --- Preflight: local tools ----------------------------------------------

foreach ($tool in @("gcloud", "cosign")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required tool '$tool' is not on PATH."
    }
}

# --- Resolve + verify the target digest (runs in dry-run too) -------------

if ([string]::IsNullOrWhiteSpace($OperatorImageDigest)) {
    Write-Host "Resolving $OperatorImage`:$Version to a digest..." -ForegroundColor Cyan
    $tri = Invoke-NativeText cosign triangulate "$OperatorImage`:$Version"
    if ($tri.ExitCode -ne 0) {
        throw "cosign triangulate failed for $OperatorImage`:$Version"
    }
    $digestRef = ($tri.Output | Out-String).Trim()
    if ($digestRef -match '@(sha256:[0-9a-f]{64})$') {
        $OperatorImageDigest = $Matches[1]
    } elseif ($digestRef -match ':sha256-([0-9a-f]{64})\.sig$') {
        # Newer cosign prints the signature location; the digest rides along.
        $OperatorImageDigest = "sha256:$($Matches[1])"
    } else {
        throw "Unexpected triangulate output: $digestRef"
    }
}
$pin = "$OperatorImage@$OperatorImageDigest"
Write-Host "Target: $pin" -ForegroundColor Green

Write-Host "Verifying keyless signature..." -ForegroundColor Cyan
$verify = Invoke-NativeText cosign verify $pin `
    --certificate-identity-regexp $CosignCertificateIdentityRegex `
    --certificate-oidc-issuer $CosignOidcIssuer
if ($verify.ExitCode -ne 0) {
    throw "cosign verify FAILED for $pin -- refusing to promote."
}
Write-Host "Signature OK (release-workflow OIDC identity)." -ForegroundColor Green

if (-not $Apply) {
    Write-Host ""
    Write-Host "DRY RUN -- no fleet changes made. Plan:" -ForegroundColor Yellow
    foreach ($entry in $Nodes) {
        $parts = $entry.Split(":")
        Write-Host "  - $($parts[0]) ($($parts[1])) pull $pin, retag $LocalTag, recreate $Service, assert version $Version"
    }
    Write-Host "Re-run with -Apply to execute the rolling promote."
    return
}

# --- Rolling promote ------------------------------------------------------

foreach ($entry in $Nodes) {
    $parts = $entry.Split(":")
    $node = $parts[0]
    $zone = $parts[1]
    $endpoint = ($parts[2..($parts.Length - 1)] -join ":")
    Write-Host ""
    Write-Host "=== $node ($zone) ===" -ForegroundColor Cyan

    Write-Host "Pre-health check..."
    if (-not (Test-NodeHealth -Endpoint $endpoint -Node $node)) {
        throw "$node is not healthy BEFORE the promote -- aborting the roll."
    }

    Write-Host "Snapshotting current image for rollback..."
    Get-SshOutput -Node $node -Zone $zone -RemoteCommand "sudo docker tag $LocalTag ${LocalTag}-prev" | Out-Null

    Write-Host "Pulling $pin ..."
    Get-SshOutput -Node $node -Zone $zone -RemoteCommand "sudo docker pull $pin" | Out-Null
    Get-SshOutput -Node $node -Zone $zone -RemoteCommand "sudo docker tag $pin $LocalTag" | Out-Null

    Write-Host "Recreating $Service..."
    Get-SshOutput -Node $node -Zone $zone -RemoteCommand "sudo docker compose -f $ComposeFile up -d $Service" | Out-Null

    Write-Host "Waiting for health (up to $HealthTimeoutSec s)..."
    $healthy = Wait-NodeHealth -Endpoint $endpoint -Node $node -TimeoutSec $HealthTimeoutSec
    $reported = ""
    if ($healthy) {
        $reported = Get-SshOutput -Node $node -Zone $zone -RemoteCommand "sudo docker exec ciphervault-operator ciphervault-operator --version"
        $reported = $reported.Trim()
        if (-not ($reported -like "*$Version*")) {
            Write-Warning "$node reports '$reported', expected version $Version"
            $healthy = $false
        }
    }

    if (-not $healthy) {
        Write-Warning "$node FAILED to come back healthy -- rolling back to the previous image."
        Get-SshOutput -Node $node -Zone $zone -RemoteCommand "sudo docker tag ${LocalTag}-prev $LocalTag && sudo docker compose -f $ComposeFile up -d $Service" | Out-Null
        if (-not (Wait-NodeHealth -Endpoint $endpoint -Node $node -TimeoutSec $HealthTimeoutSec)) {
            throw "$node rollback did not restore health -- STOP, investigate $node before continuing."
        }
        throw "$node rolled back to its previous image and is healthy. Aborting the roll -- investigate before retrying."
    }

    Write-Host "$node on $reported -- healthy." -ForegroundColor Green
}

Write-Host ""
Write-Host "Fleet promote to $Version complete." -ForegroundColor Green
