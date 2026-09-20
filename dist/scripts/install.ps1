# CipherVault - verified Windows installer/updater
# Usage: irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex
# Optional env knobs: CIPHERVAULT_VERSION=v1.0.7-beta.7 (pin, skips the
# API call), CIPHERVAULT_INSTALL_DIR=D:\tools\cv-bin (override bindir).

$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$Repo = "samuel-1-avson/CipherVault"
$Target = "x86_64-pc-windows-msvc"
$Headers = @{ "Accept" = "application/vnd.github+json"; "User-Agent" = "CipherVault-Installer" }
$InstallDir = $env:CIPHERVAULT_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $HOME ".ciphervault" }
$BinDir = Join-Path $InstallDir "bin"
$Binaries = @("ciphervault.exe", "ciphervault-operator.exe", "ciphervault-agent.exe", "ciphervault-maintenance.exe")

$Tag = $env:CIPHERVAULT_VERSION
$DownloadUrl = $null
if ([string]::IsNullOrWhiteSpace($Tag)) {
    $release = Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Tag = [string]$release.tag_name
    if ([string]::IsNullOrWhiteSpace($Tag)) { throw "GitHub did not return a latest CipherVault release." }
    $PkgName = "ciphervault-$Tag-$Target.zip"
    $asset = @($release.assets) | Where-Object { $_.name -eq $PkgName } | Select-Object -First 1
    if ($null -eq $asset) { throw "The latest release $Tag has no Windows x64 archive ($PkgName)." }
    $DownloadUrl = [string]$asset.browser_download_url
} else {
    $Tag = $Tag.Trim()
    $PkgName = "ciphervault-$Tag-$Target.zip"
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/$PkgName"
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Installing CipherVault $Tag (Windows x64)" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ciphervault-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
try {
    $archive = Join-Path $tempRoot $PkgName
    Invoke-WebRequest -Headers $Headers -Uri $DownloadUrl -OutFile $archive -UseBasicParsing
    $sumsUrl = "https://github.com/$Repo/releases/download/$Tag/SHA256SUMS.txt"
    $sumsResponse = Invoke-WebRequest -Headers $Headers -Uri $sumsUrl -UseBasicParsing
    $sums = if ($sumsResponse.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($sumsResponse.Content) } else { [string]$sumsResponse.Content }
    # Same rule as the in-app updater: first whitespace field is the hex
    # digest, second (minus an optional '*' binary marker) is the name.
    $expected = $null
    foreach ($line in ($sums -split "`r?`n")) {
        $fields = ($line -split '\s+') | Where-Object { $_ -ne '' }
        if ($fields.Count -ge 2 -and $fields[1].TrimStart('*') -eq $PkgName) { $expected = $fields[0]; break }
    }
    if ([string]::IsNullOrWhiteSpace($expected)) { throw "Release checksum does not list $PkgName." }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -ne $expected.ToLowerInvariant()) { throw "Release checksum mismatch for $PkgName." }

    $extract = Join-Path $tempRoot "extract"
    Expand-Archive -LiteralPath $archive -DestinationPath $extract -Force
    foreach ($name in $Binaries) {
        $binary = Get-ChildItem -LiteralPath $extract -Filter $name -Recurse -File | Select-Object -First 1
        if ($null -eq $binary) { throw "The verified release archive does not contain $name." }
        Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $BinDir $name) -Force
    }

    # Double-clicking a console executable is expected to close when it exits.
    # This wrapper gives PowerShell and Command Prompt users a stable entry point.
    $wrapper = Join-Path $BinDir "ciphervault.cmd"
    Set-Content -LiteralPath $wrapper -Value "@echo off`r`n`"%~dp0ciphervault.exe`" %*`r`n" -Encoding ASCII
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$BinDir*") {
    $NewUserPath = if ([string]::IsNullOrWhiteSpace($UserPath)) { $BinDir } else { "$($UserPath.TrimEnd(';'));$BinDir" }
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, [EnvironmentVariableTarget]::User)
    $env:Path = "$env:Path;$BinDir"
}

Write-Host "[+] CipherVault $Tag installed to $BinDir" -ForegroundColor Green
Write-Host "Run 'ciphervault --help' from a NEW terminal. To update later, run 'ciphervault update' or rerun this installer." -ForegroundColor Yellow
