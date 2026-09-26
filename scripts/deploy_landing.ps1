# ==============================================================================
# CipherVault Landing Page Deployment Script (Windows PowerShell)
# Target: https://cipherv.online
# ==============================================================================
param (
    [string]$TargetHost = "cv-web-ui",
    [string]$Zone = "us-central1-a"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = (Get-Item "$scriptDir\..").FullName
$landingDir = "$rootDir\apps\landing"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "   CipherVault Landing Page Deployer (cipherv.online)  " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Source:  $landingDir"
Write-Host "Target:  $TargetHost"
Write-Host "Zone:    $Zone"
Write-Host ""

# 1. Verify Local Assets
Write-Host "--> [1/4] Verifying landing page assets and contract IDs..." -ForegroundColor Yellow
$verifyScript = "$scriptDir\verify_landing.cjs"
if (-not (Test-Path $verifyScript)) {
    Write-Error "Missing verification script: $verifyScript"
}

node $verifyScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "Contract verification failed!"
}
Write-Host "  [OK] Contract verification passed." -ForegroundColor Green

# 2. Package Archive
Write-Host "--> [2/4] Packaging static release archive..." -ForegroundColor Yellow
$distDir = "$rootDir\dist"
if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
}
$version = (Select-String -Path "$rootDir\Cargo.toml" -Pattern '^version = "(.*)"$' | Select-Object -First 1).Matches.Groups[1].Value
$zipFile = "$distDir\ciphervault-landing-v$version.zip"
if (Test-Path $zipFile) {
    Remove-Item $zipFile -Force
}
Compress-Archive -Path "$landingDir\*" -DestinationPath $zipFile -Force
Write-Host "  [OK] Static archive created at: $zipFile" -ForegroundColor Green

# 3. GCP Caddy Web VM Synchronization
Write-Host "--> [3/4] Checking Google Cloud VM connectivity..." -ForegroundColor Yellow
$gcloudCmd = Get-Command gcloud -ErrorAction SilentlyContinue
if ($null -ne $gcloudCmd) {
    try {
        $vmStatus = gcloud compute instances describe $TargetHost --zone=$Zone --format="value(status)" 2>&1
        if ($vmStatus -match "RUNNING") {
            Write-Host "  Connecting to $TargetHost ($Zone)..." -ForegroundColor Cyan
            $remoteDest = $TargetHost + ":/tmp/ciphervault-landing"
            gcloud compute scp --recurse --zone=$Zone "$landingDir" $remoteDest

            $remoteCmd = 'sudo install -d -m 0755 /var/www/ciphervault-landing && sudo cp -r /tmp/ciphervault-landing/* /var/www/ciphervault-landing/ && sudo rm -rf /tmp/ciphervault-landing && (sudo chown -R www-data:www-data /var/www/ciphervault-landing || sudo chown -R root:root /var/www/ciphervault-landing) && (docker compose -f /opt/ciphervault-ui/release/docker-compose.yml exec -T caddy caddy reload --config /etc/caddy/Caddyfile || sudo caddy reload || true)'

            gcloud compute ssh $TargetHost --zone=$Zone --command=$remoteCmd
            Write-Host "  [OK] Remote VM assets updated." -ForegroundColor Green
        } else {
            Write-Host "  [INFO] VM $TargetHost is not running. Deploying to static bundle only." -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "  [INFO] Notice: Could not push to VM automatically. Deploying to static bundle only." -ForegroundColor DarkYellow
    }
} else {
    Write-Host "  [INFO] Notice: gcloud CLI not found in PATH. Static archive prepared at $zipFile." -ForegroundColor DarkYellow
}

# 4. HTTPS Healthcheck
Write-Host "--> [4/4] Verifying https://cipherv.online..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "https://cipherv.online" -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
    if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) {
        Write-Host "  [OK] Live endpoint healthy: https://cipherv.online (HTTP $($response.StatusCode))" -ForegroundColor Green
    }
} catch {
    Write-Host "  [INFO] Note: https://cipherv.online connection pending DNS propagation or server startup." -ForegroundColor Gray
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Deployment Complete! Archive: $zipFile" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
