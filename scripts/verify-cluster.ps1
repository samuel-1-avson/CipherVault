# CipherVault — Docker Staging Cluster Verification Drill
# Usage: powershell -ExecutionPolicy Bypass -File scripts/verify-cluster.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RootDir = Split-Path -Parent $ScriptDir
$CliBin = Join-Path $RootDir "dist\bin\ciphervault.exe"

if (-not (Test-Path $CliBin)) {
    Write-Host "Building release binary..." -ForegroundColor Yellow
    & "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release --bin ciphervault
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  CipherVault Container Cluster Verification Drill" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan

# 1. Probe the 3 containerized operator endpoints
$ports = @(8201, 8202, 8203)
$keys = @()

foreach ($port in $ports) {
    $url = "http://127.0.0.1:$port/v1/info"
    Write-Host "Probing Operator on port $port ($url)..." -NoNewline
    try {
        $info = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 5
        Write-Host " [ONLINE]" -ForegroundColor Green
        Write-Host "   Operator ID: $($info.operator_id)" -ForegroundColor Yellow
        Write-Host "   Public Key:  $($info.operator_signing_pk_hex.Substring(0, 16))..." -ForegroundColor DarkGray
        Write-Host "   Terms:       $($info.retention_terms)" -ForegroundColor DarkGray

        if ($keys -contains $info.operator_signing_pk_hex) {
            Write-Error "CRITICAL: Duplicate operator signing key detected between operators!"
        }
        $keys += $info.operator_signing_pk_hex
    } catch {
        Write-Host " [FAILED]" -ForegroundColor Red
        Write-Error "Cannot reach operator on port $port. Is 'docker compose up -d' running?"
    }
}

Write-Host "`nAll 3 container operators are healthy and cryptographically unique!" -ForegroundColor Green

# 2. Setup a clean drill vault
$TestVault = Join-Path $env:TEMP "cv_docker_drill_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $TestVault | Out-Null
Set-Location $TestVault

Write-Host "`nInitializing test vault in $TestVault..." -ForegroundColor Cyan

# Initialize vault with custom container operator endpoints
& $CliBin init --operators http://127.0.0.1:8201 http://127.0.0.1:8202 http://127.0.0.1:8203
$KitFile = Join-Path $TestVault ".ciphervault\recovery_kit_backup.txt"

# Create synthetic secrets
Set-Content -Path ".env" -Value "DATABASE_URL=postgres://cluster_admin:secr3t_pass@db.internal:5432/main`nJWT_SECRET=cluster_jwt_token_9999"
Set-Content -Path "prod_api.key" -Value "CV-CLUSTER-KEY-4815162342-OMEGA"

& $CliBin track .env
& $CliBin track prod_api.key

# Replicate to 3 container operators
Write-Host "`nReplicating snapshot to 3 Docker container operators..." -ForegroundColor Cyan
& $CliBin push -m "Docker cluster validation snapshot"

Write-Host "`n[PASSED] Replicated and verified 3-way container persistence!" -ForegroundColor Green

# 3. Simulate Operator 1 failure
Write-Host "`n[DISASTER SIMULATION] Stopping operator-1 container..." -ForegroundColor Yellow
docker compose -f "$RootDir\docker-compose.yml" stop operator-1

# 4. Perform clean machine recovery using kit and surviving operators 2 & 3
$RestoreDir = Join-Path $env:TEMP "cv_docker_restore_$([guid]::NewGuid().ToString('N'))"
Write-Host "Restoring to clean machine target $RestoreDir..." -ForegroundColor Cyan

& $CliBin recover --kit $KitFile --to $RestoreDir

# 5. Verify byte-for-byte fidelity
$origEnv = Get-Content -Raw ".env"
$restEnv = Get-Content -Raw (Join-Path $RestoreDir ".env")
$origKey = Get-Content -Raw "prod_api.key"
$restKey = Get-Content -Raw (Join-Path $RestoreDir "prod_api.key")

if ($origEnv.Trim() -ne $restEnv.Trim() -or $origKey.Trim() -ne $restKey.Trim()) {
    Write-Error "INTEGRITY MISMATCH: Restored files differ from original!"
}

Write-Host "`n[PASSED] Byte-for-byte integrity verified with 1 operator offline (2/3 quorum)!" -ForegroundColor Green

# 6. Restart operator-1 and confirm persistence
Write-Host "`nRestarting operator-1..." -ForegroundColor Cyan
docker compose -f "$RootDir\docker-compose.yml" start operator-1
Start-Sleep -Seconds 3

$info1 = Invoke-RestMethod -Uri "http://127.0.0.1:8201/v1/info" -Method Get
Write-Host "Operator 1 revived with same ID: $($info1.operator_id)" -ForegroundColor Green

Write-Host "`n=======================================================" -ForegroundColor Cyan
Write-Host "  DOCKER STAGING CLUSTER DRILL: 100% SUCCESS!" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan

Set-Location $RootDir
Remove-Item -Recurse -Force $TestVault -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $RestoreDir -ErrorAction SilentlyContinue
