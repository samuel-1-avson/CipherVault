# CipherVault - verified Windows installer/updater
# Usage: irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$Repo = "samuel-1-avson/CipherVault"
$Target = "x86_64-pc-windows-msvc"
$Headers = @{ "Accept" = "application/vnd.github+json"; "User-Agent" = "CipherVault-Installer" }
$InstallDir = Join-Path $HOME ".ciphervault"
$BinDir = Join-Path $InstallDir "bin"
$TargetExe = Join-Path $BinDir "ciphervault.exe"

$release = Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/repos/$Repo/releases/latest"
$Tag = [string]$release.tag_name
if ([string]::IsNullOrWhiteSpace($Tag)) { throw "GitHub did not return a latest CipherVault release." }
$PkgName = "ciphervault-$Tag-$Target.zip"
$asset = @($release.assets) | Where-Object { $_.name -eq $PkgName } | Select-Object -First 1
if ($null -eq $asset) { throw "The latest release $Tag has no Windows x64 archive ($PkgName)." }

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Installing CipherVault $Tag (Windows x64)" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ciphervault-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
try {
    $archive = Join-Path $tempRoot $PkgName
    Invoke-WebRequest -Headers $Headers -Uri ([string]$asset.browser_download_url) -OutFile $archive -UseBasicParsing
    $sumsUrl = "https://github.com/$Repo/releases/download/$Tag/SHA256SUMS.txt"
    $sums = (Invoke-WebRequest -Headers $Headers -Uri $sumsUrl -UseBasicParsing).Content
    $expectedLine = $sums -split "`r?`n" | Where-Object { $_ -match "s*?$([regex]::Escape($PkgName))$" } | Select-Object -First 1
    $expected = ($expectedLine -split "s+" | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($expected)) { throw "Release checksum does not list $PkgName." }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -ne $expected.ToLowerInvariant()) { throw "Release checksum mismatch for $PkgName." }

    $extract = Join-Path $tempRoot "extract"
    Expand-Archive -LiteralPath $archive -DestinationPath $extract -Force
    $binary = Get-ChildItem -LiteralPath $extract -Filter "ciphervault.exe" -Recurse -File | Select-Object -First 1
    if ($null -eq $binary) { throw "The verified release archive does not contain ciphervault.exe." }
    Copy-Item -LiteralPath $binary.FullName -Destination $TargetExe -Force

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
Write-Host "Run 'ciphervault --help' from a terminal. To update later, run 'ciphervault update' or rerun this installer." -ForegroundColor Yellow

