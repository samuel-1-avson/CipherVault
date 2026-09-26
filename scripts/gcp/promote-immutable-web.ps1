[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DashboardImage,

    [Parameter(Mandatory = $true)]
    [string]$AccountImage,

    [Parameter(Mandatory = $true)]
    [string]$RollbackDashboardImage,

    [Parameter(Mandatory = $true)]
    [string]$RollbackAccountImage,

    [Parameter(Mandatory = $true)]
    [string]$OperatorEndpoints,

    [Parameter(Mandatory = $true)]
    [string]$RuntimeServiceAccount,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedBuildVersion,

    [string]$ProjectId = "",
    [string]$InstanceName = "cv-web-ui",
    [string]$Zone = "us-east1-b",
    [string]$DomainName = "vault.cipherv.online",
    [string]$AcmeEmail = "admin@example.com",
    [string]$AccountTotpSecret = "ciphervault-account-totp-key",
    [string]$HealthCheckIp = "",

    [string]$FinalityConfirmations = "",

    [string]$OperatorRegions = "",
    [string]$CosignCertificateIdentityRegex = "https://github.com/samuel-1-avson/CipherVault/.github/workflows/release.yml@refs/tags/.*",
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
    $lines = @($output)
    $text = ""
    if ($lines.Count -gt 0 -and $null -ne $lines[0]) {
        $text = ([string]$lines[0]).Trim()
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Text = $text }
}

function Assert-DigestImage {
    param([string]$Name, [string]$Image)
    if ($Image -notmatch '^ghcr\.io/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$') {
        throw "$Name must be a lowercase GHCR image pinned by sha256 digest."
    }
}

function Assert-MetadataValue {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Contains("`r") -or $Value.Contains("`n") -or $Value.Contains(',')) {
        throw "$Name must be non-empty and cannot contain a comma or newline."
    }
}

function Verify-ImageSignature {
    param([string]$Image)
    # Routed through Invoke-NativeText: cosign prints its success banner
    # to stderr, which is terminating under $ErrorActionPreference = "Stop"
    # even when piped to $null. The exit code drives control flow.
    $result = Invoke-NativeText cosign verify `
        --certificate-identity-regexp $CosignCertificateIdentityRegex `
        --certificate-oidc-issuer https://token.actions.githubusercontent.com `
        $Image
    if ($result.ExitCode -ne 0) {
        throw "Cosign verification failed for $Image"
    }
}

function Invoke-PromotionGet {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$DomainName,
        [string]$HealthCheckIp = ""
    )
    # Mirrors the health-check transport: curl with an explicit resolve when
    # the operator pins the check IP, Invoke-WebRequest otherwise. Both fail
    # on non-2xx (curl via --fail, Invoke-WebRequest by throwing).
    if ($HealthCheckIp) {
        # Same stderr discipline as Invoke-NativeText: curl diagnostics
        # must not terminate under $ErrorActionPreference = "Stop"; the
        # exit code drives control flow and the throw below reports it.
        $previousEAP = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $body = @(& curl.exe --fail --silent --show-error --max-time 10 --resolve "$DomainName`:443`:$HealthCheckIp" $Url 2>$null)
            $curlExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousEAP
        }
        if ($curlExit -ne 0) { throw "GET $Url failed with exit code $curlExit" }
        return ($body -join "`n")
    }
    return (Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 10).Content
}

function Confirm-LiveDeployment {
    param(
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][string]$ExpectedBuildVersion,
        [string]$HealthCheckIp = "",
        [string]$Scheme = "https"
    )
    # The /api/vault health check only proves a web server answers. These
    # probes prove the NEW build serves the NEW routes, and the version
    # assertion proves it is the expected build. Any failure throws into
    # the caller's rollback path. Retries absorb post-startup transients so
    # a flake cannot roll back a good deploy.
    $probes = @(
        "$Scheme`://$DomainName/api/context",
        "$Scheme`://$DomainName/api/operators",
        "$Scheme`://$DomainName/api/explorer/overview"
    )
    $contextBody = ""
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $contextBody = Invoke-PromotionGet -Url $probes[0] -DomainName $DomainName -HealthCheckIp $HealthCheckIp
            Invoke-PromotionGet -Url $probes[1] -DomainName $DomainName -HealthCheckIp $HealthCheckIp | Out-Null
            Invoke-PromotionGet -Url $probes[2] -DomainName $DomainName -HealthCheckIp $HealthCheckIp | Out-Null
            break
        } catch {
            if ($attempt -eq 3) { throw }
            Start-Sleep -Seconds 10
        }
    }
    $deployedVersion = ($contextBody | ConvertFrom-Json).build_version
    if ([string]::IsNullOrWhiteSpace($deployedVersion)) {
        throw "Live /api/context has no build_version; the deployment predates promotion verification."
    }
    if ($deployedVersion -ne $ExpectedBuildVersion) {
        throw "Live build_version is '$deployedVersion', expected '$ExpectedBuildVersion'."
    }
    Write-Host "Live deployment verified: build_version $deployedVersion, explorer routes responding." -ForegroundColor Green
}

function Get-StagedCaddyImage {
    param([Parameter(Mandatory = $true)][string]$ComposePath)
    $refs = @(Select-String -LiteralPath $ComposePath -Pattern '^\s*image:\s*(caddy:\S+)' -AllMatches |
        ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    if ($refs.Count -ne 1) {
        throw "Expected exactly one Caddy image pin in $ComposePath; found $($refs.Count)."
    }
    return $refs[0]
}

function Invoke-RemoteCaddyValidate {
    param(
        [Parameter(Mandatory = $true)][string]$InstanceName,
        [Parameter(Mandatory = $true)][string]$ProjectId,
        [Parameter(Mandatory = $true)][string]$Zone,
        [Parameter(Mandatory = $true)][string]$RemoteCaddyfile,
        [Parameter(Mandatory = $true)][string]$CaddyImage
    )
    # VM-side gate: the candidate Caddyfile is adapted by the exact image
    # pin the staged compose deploys. A broken edge config aborts the
    # promotion BEFORE the VM stops, so the 1.0.7 outage class (bad
    # directive crash-looping Caddy) cannot recur.
    Write-Host "Validating the candidate Caddyfile against $CaddyImage..." -ForegroundColor Cyan
    Invoke-Gcloud compute ssh $InstanceName --project $ProjectId --zone $Zone --command "set -eu; sudo docker pull '$CaddyImage' >/dev/null; sudo docker run --rm -v '${RemoteCaddyfile}:/etc/caddy/Caddyfile:ro' '$CaddyImage' caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile"
}

foreach ($command in @("gcloud", "cosign")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command must be installed and authenticated before promotion."
    }
}

if (-not $ProjectId) {
    $projectDetect = Invoke-NativeText gcloud config get-value project
    if ($projectDetect.ExitCode -eq 0) {
        $ProjectId = $projectDetect.Text
    }
}
foreach ($item in @(
    @{ Name = "CIPHERVAULT_DASHBOARD_IMAGE"; Value = $DashboardImage },
    @{ Name = "CIPHERVAULT_ACCOUNT_IMAGE"; Value = $AccountImage },
    @{ Name = "ROLLBACK_DASHBOARD_IMAGE"; Value = $RollbackDashboardImage },
    @{ Name = "ROLLBACK_ACCOUNT_IMAGE"; Value = $RollbackAccountImage }
)) {
    Assert-DigestImage $item.Name $item.Value
}
foreach ($item in @(
    @{ Name = "ProjectId"; Value = $ProjectId },
    @{ Name = "OperatorEndpoints"; Value = $OperatorEndpoints },
    @{ Name = "RuntimeServiceAccount"; Value = $RuntimeServiceAccount },
    @{ Name = "DomainName"; Value = $DomainName },
    @{ Name = "AccountTotpSecret"; Value = $AccountTotpSecret }
)) {
    Assert-MetadataValue $item.Name $item.Value
}
if ($AccountTotpSecret -notmatch '^[A-Za-z0-9_-]+$') {
    throw "AccountTotpSecret contains unsupported characters."
}
if ($RuntimeServiceAccount -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\.iam\.gserviceaccount\.com$') {
    throw "RuntimeServiceAccount must be a Google service-account address."
}
if ([string]::IsNullOrWhiteSpace($ExpectedBuildVersion) -or $ExpectedBuildVersion -match '[\s,]') {
    throw "ExpectedBuildVersion must be a non-empty version without whitespace or commas."
}

Write-Host "Verifying signed image attestations..." -ForegroundColor Cyan
foreach ($image in @($DashboardImage, $AccountImage, $RollbackDashboardImage, $RollbackAccountImage) | Select-Object -Unique) {
    Verify-ImageSignature $image
}

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$compose = Join-Path $root "deploy\gcp\docker-compose.web.yml"
$caddy = Join-Path $root "deploy\gcp\Caddyfile.web.gcp"
$startup = Join-Path $root "deploy\gcp\startup-web.sh"
foreach ($path in @($compose, $caddy, $startup)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required deployment file is missing: $path"
    }
}

if ($FinalityConfirmations.Trim() -ne "" -and $FinalityConfirmations.Trim() -notmatch '^[1-9][0-9]*$') {
    throw "FinalityConfirmations must be a positive integer"
}
if ($OperatorRegions.Contains(',')) {
    throw "OperatorRegions must use spaces (not commas) between endpoints: commas corrupt the instance metadata join"
}

$caddyImage = Get-StagedCaddyImage -ComposePath $compose

$stageId = $DashboardImage.Substring($DashboardImage.Length - 12)
$remoteStage = "/tmp/ciphervault-release-$stageId"

Write-Host "Checking that the target VM can pull the candidate images..." -ForegroundColor Cyan
Invoke-Gcloud compute ssh $InstanceName --project $ProjectId --zone $Zone --command "set -eu; sudo docker pull '$DashboardImage' >/dev/null; sudo docker pull '$AccountImage' >/dev/null"

if (-not $Apply) {
    $preflightCaddy = "/tmp/ciphervault-caddy-preflight-$stageId"
    Invoke-Gcloud compute scp $caddy "${InstanceName}:$preflightCaddy" --project $ProjectId --zone $Zone
    try {
        Invoke-RemoteCaddyValidate -InstanceName $InstanceName -ProjectId $ProjectId -Zone $Zone -RemoteCaddyfile $preflightCaddy -CaddyImage $caddyImage
    } finally {
        Invoke-Gcloud compute ssh $InstanceName --project $ProjectId --zone $Zone --command "rm -f '$preflightCaddy'"
    }
    Write-Host "Preflight succeeded. Re-run with -Apply to stage the release and perform the controlled VM restart." -ForegroundColor Yellow
    return
}

$promotionStarted = $false
try {
    Write-Host "Staging reviewed deployment configuration on the VM..." -ForegroundColor Cyan
    Invoke-Gcloud compute ssh $InstanceName --project $ProjectId --zone $Zone --command "set -eu; rm -rf '$remoteStage'; mkdir -p '$remoteStage'"
    Invoke-Gcloud compute scp $compose "${InstanceName}:$remoteStage/docker-compose.yml" --project $ProjectId --zone $Zone
    Invoke-Gcloud compute scp $caddy "${InstanceName}:$remoteStage/Caddyfile" --project $ProjectId --zone $Zone
    Invoke-Gcloud compute ssh $InstanceName --project $ProjectId --zone $Zone --command "set -eu; sudo install -d -m 0755 /opt/ciphervault-ui/release/last-good; for f in docker-compose.yml Caddyfile; do if [ -f /opt/ciphervault-ui/release/`$f ]; then sudo install -m 0644 /opt/ciphervault-ui/release/`$f /opt/ciphervault-ui/release/last-good/`$f; fi; done; sudo install -m 0644 '$remoteStage/docker-compose.yml' /opt/ciphervault-ui/release/docker-compose.yml; sudo install -m 0644 '$remoteStage/Caddyfile' /opt/ciphervault-ui/release/Caddyfile; rm -rf '$remoteStage'"

    # Mandatory gate on exactly what was staged: a broken edge config
    # aborts here, before the VM stops, leaving the live deployment untouched.
    Invoke-RemoteCaddyValidate -InstanceName $InstanceName -ProjectId $ProjectId -Zone $Zone -RemoteCaddyfile "/opt/ciphervault-ui/release/Caddyfile" -CaddyImage $caddyImage


    $metadata = @(
        "ciphervault-dashboard-image=$DashboardImage",
        "ciphervault-account-image=$AccountImage",
        "operator-endpoints=$OperatorEndpoints",
        "web-domain=$DomainName",
        "acme-email=$AcmeEmail",
        "webauthn-rp-id=$DomainName",
        "webauthn-origin=https://$DomainName",
        "account-allowed-origins=https://$DomainName",
        "account-totp-secret=$AccountTotpSecret",
        "project-id=$ProjectId"
    )
    if ($FinalityConfirmations.Trim() -ne "") { $metadata += "finality-confirmations=$($FinalityConfirmations.Trim())" }
    if ($OperatorRegions.Trim() -ne "") { $metadata += "operator-regions=$($OperatorRegions.Trim())" }
    $metadata = $metadata -join ','

    Write-Host "Switching the VM to the least-privilege runtime identity and cloud-platform scope..." -ForegroundColor Cyan
    Invoke-Gcloud compute instances stop $InstanceName --project $ProjectId --zone $Zone --quiet
    $promotionStarted = $true
    Invoke-Gcloud compute instances set-service-account $InstanceName --project $ProjectId --zone $Zone `
        --service-account $RuntimeServiceAccount --scopes cloud-platform --quiet
    Invoke-Gcloud compute instances add-metadata $InstanceName --project $ProjectId --zone $Zone `
        --metadata $metadata --metadata-from-file "startup-script=$startup" --quiet
    Invoke-Gcloud compute instances start $InstanceName --project $ProjectId --zone $Zone --quiet
    $running = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $statusResult = Invoke-NativeText gcloud compute instances describe $InstanceName --project $ProjectId --zone $Zone --format="value(status)"
        if ($statusResult.ExitCode -ne 0) {
            throw "Could not read the VM status after starting it."
        }
        $status = $statusResult.Text
        if ($status -eq "RUNNING") {
            $running = $true
            break
        }
        Start-Sleep -Seconds 10
    }
    if (-not $running) {
        throw "The VM did not reach RUNNING state within five minutes."
    }
    $remoteHealthCommand = "set -eu; systemctl is-active --quiet ciphervault-ui.service; sudo docker compose -f /opt/ciphervault-ui/docker-compose.yml ps --status running"
    $remoteReady = $false
    for ($attempt = 1; $attempt -le 36; $attempt++) {
        # Native stderr stays suppressed inside Invoke-NativeText (see above)
        # so an unreachable SSH attempt retries instead of aborting the poll.
        $sshExit = (Invoke-NativeText gcloud compute ssh $InstanceName --project $ProjectId --zone $Zone --command $remoteHealthCommand).ExitCode
        if ($sshExit -eq 0) {
            $remoteReady = $true
            break
        }
        Start-Sleep -Seconds 10
    }
    if (-not $remoteReady) {
        throw "The VM did not become SSH- and service-ready within six minutes."
    }

    $healthUrl = "https://$DomainName/api/vault"
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        try {
            if ($HealthCheckIp) {
                & curl.exe --fail --silent --show-error --max-time 10 --resolve "$DomainName`:443`:$HealthCheckIp" $healthUrl | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "curl health check failed with exit code $LASTEXITCODE" }
            } else {
                Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec 10 | Out-Null
            }
            Write-Host "Production health endpoint is responding." -ForegroundColor Green
            break
        } catch {
            if ($attempt -eq 12) { throw }
            Start-Sleep -Seconds 10
        }
    }
    Confirm-LiveDeployment -DomainName $DomainName -HealthCheckIp $HealthCheckIp -ExpectedBuildVersion $ExpectedBuildVersion
    Write-Host "Promotion completed. Run scripts/gcp/verify-immutable-deployment.sh for independent post-deploy verification." -ForegroundColor Green
} catch {
    if ($promotionStarted) {
        Write-Warning "Promotion failed after the VM stop. Restoring the last-good staged configuration and the supplied signed rollback images."
        try {
            # The boot-time startup script reinstalls the active config from
            # release/, so restoring the snapshot here makes the reset boot
            # the last-good config: rollback restores config AND images.
            Invoke-Gcloud compute ssh $InstanceName --project $ProjectId --zone $Zone --command "set -eu; if [ -f /opt/ciphervault-ui/release/last-good/docker-compose.yml ] && [ -f /opt/ciphervault-ui/release/last-good/Caddyfile ]; then sudo install -m 0644 /opt/ciphervault-ui/release/last-good/docker-compose.yml /opt/ciphervault-ui/release/docker-compose.yml; sudo install -m 0644 /opt/ciphervault-ui/release/last-good/Caddyfile /opt/ciphervault-ui/release/Caddyfile; echo last-good configuration restored; else echo no last-good snapshot, keeping staged configuration; fi"
        } catch {
            Write-Warning "Could not restore the last-good staged configuration: $($_.Exception.Message)"
        }
        $rollbackMetadata = @(
            "ciphervault-dashboard-image=$RollbackDashboardImage",
            "ciphervault-account-image=$RollbackAccountImage"
        ) -join ','
        try {
            Invoke-Gcloud compute instances add-metadata $InstanceName --project $ProjectId --zone $Zone --metadata $rollbackMetadata --quiet
            Invoke-Gcloud compute instances reset $InstanceName --project $ProjectId --zone $Zone --quiet
        } catch {
            Write-Error "Automatic rollback could not be completed: $($_.Exception.Message)"
        }
    }
    throw
}
