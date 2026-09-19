<#
.SYNOPSIS
    CipherVault Live Multi-Node Federation & Chaos Engineering Drill
.DESCRIPTION
    Automates an end-to-end operational validation drill using compiled release binaries:
    - Spawns 3 independent storage operators on localhost
    - Ingests confidential secrets with FastCDC chunking and Proof-of-Storage readback
    - Anchors state commitment to Arbitrum L2 automated relayer
    - Splits master recovery secret into 2-of-3 Shamir threshold guardian sheets
    - Injects chaos: terminates Operator 1 to induce quorum degradation
    - Spawns replacement Operator 4 and triggers automated repair
    - Destroys developer client storage (clean-machine simulation)
    - Reconstructs secrets from 2 guardian paper shares with 100% byte-for-byte SHA-256 fidelity
#>

[CmdletBinding()]
param(
    [string]$BinDir = "",
    [int]$BasePort = 8201
)

$ErrorActionPreference = "Stop"

if (-not $BinDir) {
    if ($PSScriptRoot) {
        $BinDir = Join-Path (Split-Path -Parent $PSScriptRoot) "dist\bin"
    } else {
        $BinDir = Join-Path (Get-Location).Path "dist\bin"
    }
}
$BinDir = [System.IO.Path]::GetFullPath($BinDir)

function Write-Step {
    param([string]$Message)
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Yellow -NoNewline
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "  [..] $Message" -ForegroundColor DarkGray
}

$CliBin = Join-Path $BinDir "ciphervault.exe"
$OpBin = Join-Path $BinDir "ciphervault-operator.exe"

if (-not (Test-Path $CliBin)) {
    throw "CLI binary not found at $CliBin. Run 'cargo build --workspace --release' first."
}
if (-not (Test-Path $OpBin)) {
    throw "Operator binary not found at $OpBin. Run 'cargo build --workspace --release' first."
}

$TestDir = Join-Path $env:TEMP "ciphervault_chaos_ps_$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $TestDir -Force | Out-Null

$Processes = @()

try {
    Write-Step "1. Spawning 3-Node Storage Operator Federation"
    $OpUrls = @()
    for ($i = 1; $i -le 3; $i++) {
        $Port = $BasePort + ($i - 1)
        $OpDir = Join-Path $TestDir "operator_$i"
        New-Item -ItemType Directory -Path $OpDir -Force | Out-Null
        $LogOut = Join-Path $TestDir "operator_${i}_out.log"
        $LogErr = Join-Path $TestDir "operator_${i}_err.log"

        $Proc = Start-Process -FilePath $OpBin -ArgumentList "--port", "$Port", "--data-dir", "$OpDir", "--operator-id", "operator-$i" -WorkingDirectory $OpDir -RedirectStandardOutput $LogOut -RedirectStandardError $LogErr -PassThru -NoNewWindow
        $Processes += $Proc
        $Url = "http://127.0.0.1:$Port"
        $OpUrls += $Url
        Write-Info "Started Operator $i on $Url (PID: $($Proc.Id))"
    }

    Start-Sleep -Milliseconds 1200

    Write-Step "2. Initializing Client Vault with Zero-Disk Paper Recovery"
    $ClientDir = Join-Path $TestDir "client_workstation"
    New-Item -ItemType Directory -Path $ClientDir -Force | Out-Null
    $PaperKit = Join-Path $TestDir "emergency_recovery_kit.txt"

    Push-Location $ClientDir
    & $CliBin init --operators $OpUrls[0] $OpUrls[1] $OpUrls[2] --save-kit $PaperKit
    if ($LASTEXITCODE -ne 0) { throw "ciphervault init failed" }
    Write-Success "Client initialized with 3 operators. Recovery kit saved offline."

    Write-Step "3. Generating and Tracking Confidential Secrets"
    $EnvFile = Join-Path $ClientDir ".env"
    "APP_ENV=production`nCLUSTER_ENDPOINT=https://cluster.internal:8443/vault`nSYNTHETIC_TEST_TOKEN=synthetic_hex_token_9918239012" | Set-Content -Path $EnvFile -NoNewline
    $KeyFile = Join-Path $ClientDir "jwt_private.key"
    "MOCK_KEY_HEADER_V1`nMHcCAQEEIAp0aGlzX2lzX3N5bnRoZXRpY19jaGFvc19kcmlsbF9kYXRhX21hdGVyaWFs`nMOCK_KEY_FOOTER_V1" | Set-Content -Path $KeyFile -NoNewline

    $OriginalEnvHash = (Get-FileHash -Path $EnvFile -Algorithm SHA256).Hash
    $OriginalKeyHash = (Get-FileHash -Path $KeyFile -Algorithm SHA256).Hash

    & $CliBin track .env jwt_private.key
    if ($LASTEXITCODE -ne 0) { throw "ciphervault track failed" }
    Write-Success "Tracked .env ($OriginalEnvHash) and jwt_private.key ($OriginalKeyHash)"

    Write-Step "4. Pushing Snapshot with FastCDC & Proof-of-Storage Readback"
    & $CliBin push --message "Chaos Drill Pre-Failure Snapshot"
    if ($LASTEXITCODE -ne 0) { throw "ciphervault push failed" }
    Write-Success "Snapshot pushed and readback verified across all 3 nodes via PoS."

    Write-Step "5. Anchoring State Commitment to Arbitrum L2 Relayer"
    & $CliBin anchor --auto-relay --relayer-url $OpUrls[0]
    if ($LASTEXITCODE -ne 0) { throw "ciphervault anchor failed" }
    Write-Success "EIP-712 checkpoint confirmed and sequencer receipt persisted."

    Write-Step "6. Exporting 2-of-3 Shamir Threshold Guardian Sheets"
    $GuardianDir = Join-Path $TestDir "guardian_sheets"
    & $CliBin recovery split --threshold 2 --shares 3 --kit $PaperKit --out-dir $GuardianDir
    if ($LASTEXITCODE -ne 0) { throw "ciphervault recovery split failed" }
    $Share1 = Join-Path $GuardianDir "guardian_share_1_of_3.txt"
    $Share2 = Join-Path $GuardianDir "guardian_share_2_of_3.txt"
    $Share3 = Join-Path $GuardianDir "guardian_share_3_of_3.txt"
    Write-Success "Generated 3 ASCII guardian sheets. Threshold: 2 guardians."

    Write-Step "7. CHAOS INJECTION: Abruptly Killing Operator 1 & Wiping Disk"
    $Op1Proc = $Processes[0]
    Stop-Process -Id $Op1Proc.Id -Force
    Write-Info "Killed Operator 1 (PID: $($Op1Proc.Id))"
    Remove-Item -Path (Join-Path $TestDir "operator_1") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Success "Operator 1 disk destroyed. Testing quorum degradation..."

    & $CliBin audit
    if ($LASTEXITCODE -eq 0) {
        throw "Audit should report degraded health when Op1 is offline, but returned success!"
    }
    Write-Success "Audit correctly detected degraded replica health as expected."

    Write-Step "8. Autonomous Self-Repair with Replacement Operator 4"
    $Op4Port = $BasePort + 3
    $Op4Dir = Join-Path $TestDir "operator_4"
    New-Item -ItemType Directory -Path $Op4Dir -Force | Out-Null
    $LogOut4 = Join-Path $TestDir "operator_4_out.log"
    $LogErr4 = Join-Path $TestDir "operator_4_err.log"
    $Proc4 = Start-Process -FilePath $OpBin -ArgumentList "--port", "$Op4Port", "--data-dir", "$Op4Dir", "--operator-id", "operator-4" -WorkingDirectory $Op4Dir -RedirectStandardOutput $LogOut4 -RedirectStandardError $LogErr4 -PassThru -NoNewWindow
    $Processes += $Proc4
    $Url4 = "http://127.0.0.1:$Op4Port"
    Start-Sleep -Milliseconds 1000

    Write-Info "Replacement Node 4 running on $Url4. Triggering repair..."
    & $CliBin repair --operators $Url4 $OpUrls[1] $OpUrls[2]
    if ($LASTEXITCODE -ne 0) { throw "ciphervault repair failed" }
    Write-Success "Autonomous repair complete. Checking healed quorum..."

    & $CliBin audit --operators $Url4 $OpUrls[1] $OpUrls[2]
    if ($LASTEXITCODE -ne 0) { throw "ciphervault audit failed" }
    Write-Success "Federation 100% Healthy across 3/3 operators!"

    Write-Step "9. Catastrophic Client Loss & Clean-Machine Disaster Recovery"
    Pop-Location
    Set-Location $TestDir
    [System.IO.Directory]::SetCurrentDirectory($TestDir)
    Start-Sleep -Milliseconds 500
    Remove-Item -Path $ClientDir -Recurse -Force
    Remove-Item -Path $PaperKit -Force
    Write-Info "Original client workstation and single recovery kit deleted."

    $VirginDir = Join-Path $TestDir "virgin_laptop"
    New-Item -ItemType Directory -Path $VirginDir -Force | Out-Null

    Write-Info "Recovering using ONLY Guardian Share 1 and Guardian Share 3 (Share 2 omitted)..."
    & $CliBin recover --shares $Share1 $Share3 --to $VirginDir
    if ($LASTEXITCODE -ne 0) { throw "ciphervault recover failed" }
    Write-Success "Clean-machine reconstruction completed successfully."

    Write-Step "10. Cryptographic Bit-for-Bit Integrity Verification"
    $RestoredEnv = Join-Path $VirginDir ".env"
    $RestoredKey = Join-Path $VirginDir "jwt_private.key"

    $RestoredEnvHash = (Get-FileHash -Path $RestoredEnv -Algorithm SHA256).Hash
    $RestoredKeyHash = (Get-FileHash -Path $RestoredKey -Algorithm SHA256).Hash

    Write-Host "  Original .env Hash:  $OriginalEnvHash" -ForegroundColor DarkGray
    Write-Host "  Restored .env Hash:  $RestoredEnvHash" -ForegroundColor Green
    Write-Host "  Original Key Hash:   $OriginalKeyHash" -ForegroundColor DarkGray
    Write-Host "  Restored Key Hash:   $RestoredKeyHash" -ForegroundColor Green

    if ($RestoredEnvHash -ne $OriginalEnvHash) { throw ".env hash mismatch!" }
    if ($RestoredKeyHash -ne $OriginalKeyHash) { throw "jwt_private.key hash mismatch!" }

    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host "  ALL CHAOS DRILL PHASES PASSED WITH ZERO BITFLIPS!   " -ForegroundColor Green -BackgroundColor Black
    Write-Host "=======================================================`n" -ForegroundColor Green

} finally {
    Set-Location $env:TEMP
    Write-Info "Cleaning up background operator processes..."
    foreach ($p in $Processes) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 300
    Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Info "Cleaned up test environment."
}
