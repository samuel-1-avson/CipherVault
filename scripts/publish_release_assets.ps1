# ==============================================================================
# CipherVault v1.0.0 GitHub Release Publisher
# ==============================================================================
param(
    [string]$Repo = "samuel-1-avson/CipherVault",
    [string]$Tag = "v1.0.0",
    [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"

if (-not $Token) {
    try {
        $cred = "protocol=https`nhost=github.com" | git credential fill 2>$null
        $tokenLine = ($cred -split "`n") | Where-Object { $_ -match "^password=(.*)$" }
        if ($tokenLine) {
            $Token = ($tokenLine -replace "^password=", "").Trim()
        }
    } catch {}
}

if (-not $Token) {
    throw "GITHUB_TOKEN environment variable or parameter is required to publish release assets."
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Publishing GitHub Release Assets for $Repo ($Tag)" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan

$Headers = @{
    "Authorization" = "token $Token"
    "Accept"        = "application/vnd.github+json"
    "User-Agent"    = "CipherVault-Release-Publisher"
}

# 1. Fetch or Create Release
$ReleaseUrl = "https://api.github.com/repos/$Repo/releases/tags/$Tag"
$Release = $null

try {
    Write-Host "Checking if release $Tag already exists..." -ForegroundColor Cyan
    $Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers $Headers -Method Get
    Write-Host "Found existing release: $($Release.name) (ID: $($Release.id))" -ForegroundColor Green
} catch {
    Write-Host "Release $Tag does not exist. Creating new release..." -ForegroundColor Yellow
    $CreateReleaseUrl = "https://api.github.com/repos/$Repo/releases"
    $Body = @{
        tag_name         = $Tag
        target_commitish = "main"
        name             = "CipherVault v1.0.0 - Production General Availability & Visual Explorer Hardening"
        body             = "CipherVault v1.0.0 - Production General Availability and Visual Explorer Hardening. Visit https://vault.cipherv.online for live explorer."
        draft            = $false
        prerelease       = $false
    } | ConvertTo-Json

    $Release = Invoke-RestMethod -Uri $CreateReleaseUrl -Headers $Headers -Method Post -Body $Body
    Write-Host "Created new release ID: $($Release.id)" -ForegroundColor Green
}

$ReleaseId = $Release.id

# 2. Stage Assets in a Clean Directory
$StagingDir = Join-Path $PSScriptRoot "..\dist\release_staging"
if (-not (Test-Path -Path $StagingDir)) {
    New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null
}

$ExistingStaged = Get-ChildItem -Path $StagingDir -File -Filter "*.gz"
if ($ExistingStaged.Count -eq 0) {
    Write-Host "Fetching build artifacts from GitHub Actions..." -ForegroundColor Cyan
$RunsUrl = "https://api.github.com/repos/$Repo/actions/runs?per_page=5"
$Runs = Invoke-RestMethod -Uri $RunsUrl -Headers $Headers -Method Get
$LatestRun = $Runs.workflow_runs | Where-Object { $_.name -eq "Release Matrix & Cross-Platform Artifacts" } | Select-Object -First 1

if ($LatestRun) {
    Write-Host "Querying artifacts from run ID: $($LatestRun.id)..." -ForegroundColor Cyan
    $ArtifactsUrl = "https://api.github.com/repos/$Repo/actions/runs/$($LatestRun.id)/artifacts"
    $Artifacts = Invoke-RestMethod -Uri $ArtifactsUrl -Headers $Headers -Method Get

    foreach ($art in $Artifacts.artifacts) {
        Write-Host "Downloading artifact: $($art.name)..." -ForegroundColor Cyan
        $ArtZip = Join-Path $StagingDir "$($art.name).zip"
        $ArtExtractDir = Join-Path $StagingDir "$($art.name)_extracted"
        
        # Download artifact zip
        curl.exe -sSL -H "Authorization: token $Token" $art.archive_download_url -o $ArtZip
        
        # Extract to find inner release archive (.zip or .tar.gz)
        Expand-Archive -Path $ArtZip -DestinationPath $ArtExtractDir -Force
        Get-ChildItem -Path $ArtExtractDir -Recurse | Where-Object { $_.Extension -in @(".zip", ".gz", ".exe") } | ForEach-Object {
            Move-Item -Path $_.FullName -Destination $StagingDir -Force
        }
        Remove-Item -Path $ArtZip -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $ArtExtractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
}

# Ensure local Windows executable and archive are present
$LocalExe = Join-Path $PSScriptRoot "..\dist\bin\ciphervault.exe"
if (Test-Path -Path $LocalExe) {
    Copy-Item -Path $LocalExe -Destination (Join-Path $StagingDir "ciphervault.exe") -Force
}

# If Windows zip wasn't in actions artifacts, build it locally
$WinZipName = "ciphervault-$Tag-x86_64-pc-windows-msvc.zip"
$WinZipPath = Join-Path $StagingDir $WinZipName
if (-not (Test-Path -Path $WinZipPath)) {
    Write-Host "Packaging Windows release zip locally..." -ForegroundColor Cyan
    $WinPkgDir = Join-Path $StagingDir "ciphervault-$Tag-x86_64-pc-windows-msvc"
    $WinBinDir = Join-Path $WinPkgDir "bin"
    New-Item -ItemType Directory -Force -Path $WinBinDir | Out-Null
    Copy-Item -Path $LocalExe -Destination (Join-Path $WinBinDir "ciphervault.exe") -Force
    Copy-Item -Path (Join-Path $PSScriptRoot "..\README.md") -Destination $WinPkgDir -Force
    Compress-Archive -Path "$WinPkgDir\*" -DestinationPath $WinZipPath -Force
    Remove-Item -Path $WinPkgDir -Recurse -Force
}

# 3. Generate SHA256SUMS.txt
Write-Host "Generating SHA256SUMS.txt for all release assets..." -ForegroundColor Cyan
$ChecksumFile = Join-Path $StagingDir "SHA256SUMS.txt"
if (Test-Path -Path $ChecksumFile) { Remove-Item -Path $ChecksumFile -Force }

$StagedFiles = Get-ChildItem -Path $StagingDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" }
$ChecksumLines = @()
foreach ($file in $StagedFiles) {
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
    $ChecksumLines += "$hash  $($file.Name)"
    Write-Host "  $($file.Name): $hash" -ForegroundColor DarkGray
}
$ChecksumLines | Out-File -FilePath $ChecksumFile -Encoding utf8 -Force

# 4. Upload Assets to GitHub Release
Write-Host "Uploading release assets to GitHub Release $Tag..." -ForegroundColor Cyan

# Check existing release assets
$ExistingAssets = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/$ReleaseId/assets" -Headers $Headers -Method Get
$ExistingMap = @{}
foreach ($ea in $ExistingAssets) {
    $ExistingMap[$ea.name] = $ea.id
}

$AllUploadFiles = Get-ChildItem -Path $StagingDir -File
foreach ($uf in $AllUploadFiles) {
    $Filename = $uf.Name
    if ($ExistingMap.ContainsKey($Filename)) {
        Write-Host "Asset $Filename already exists on release. Deleting old asset ID: $($ExistingMap[$Filename])..." -ForegroundColor Yellow
        $DeleteUrl = "https://api.github.com/repos/$Repo/releases/assets/$($ExistingMap[$Filename])"
        Invoke-RestMethod -Uri $DeleteUrl -Headers $Headers -Method Delete
    }

    Write-Host "Uploading $Filename ($([math]::Round($uf.Length / 1MB, 2)) MB)..." -ForegroundColor Cyan
    $UploadUrl = "https://uploads.github.com/repos/$Repo/releases/$ReleaseId/assets?name=$Filename"
    
    $UploadHeaders = @{
        "Authorization" = "token $Token"
        "Content-Type"  = "application/octet-stream"
    }

    Invoke-RestMethod -Uri $UploadUrl -Method Post -Headers $UploadHeaders -InFile $uf.FullName | Out-Null
    Write-Host "  [+] Uploaded $Filename successfully!" -ForegroundColor Green
}

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "  Release $Tag successfully published with all assets!" -ForegroundColor Green
Write-Host "  URL: $($Release.html_url)" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
