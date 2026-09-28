# CipherVault - verified Windows installer/updater
# Usage: irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex
# Optional env knobs: CIPHERVAULT_VERSION=v1.0.22 (pin, skips the
# API call), CIPHERVAULT_INSTALL_DIR=D:\tools\cv-bin (override bindir),
# CIPHERVAULT_ROLE=developer|node|full (default full; developer = CLI+agent,
# node = CLI+operator+maintenance for guided `ciphervault node setup`),
# CIPHERVAULT_INSTALL_NO_STOP=1 (never stop running CipherVault processes;
# the install fails with instructions instead of replacing locked binaries).

$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$Repo = "samuel-1-avson/CipherVault"
$Target = "x86_64-pc-windows-msvc"
$Headers = @{ "Accept" = "application/vnd.github+json"; "User-Agent" = "CipherVault-Installer" }
$GithubToken = $env:CIPHERVAULT_GITHUB_TOKEN
if ([string]::IsNullOrWhiteSpace($GithubToken)) { $GithubToken = $env:GH_TOKEN }
if ([string]::IsNullOrWhiteSpace($GithubToken)) { $GithubToken = $env:GITHUB_TOKEN }
if (-not [string]::IsNullOrWhiteSpace($GithubToken)) { $Headers["Authorization"] = "Bearer $($GithubToken.Trim())" }
$PrivateHint = "If the repo is private, set CIPHERVAULT_GITHUB_TOKEN (a token with Contents: read) and re-run."

# Windows locks a running .exe, so replacing the bindir while a TUI, agent,
# or node daemon runs from it fails in Copy-Item. These helpers only ever
# touch ciphervault* processes executing from the install bindir itself -
# exactly the binaries this installer is about to replace.
function Get-InstallDirProcesses {
    param([string]$BinDir)
    $found = @()
    foreach ($proc in (Get-Process -Name "ciphervault*" -ErrorAction SilentlyContinue)) {
        if ($proc.Id -eq $PID) { continue }
        $procPath = $null
        try { $procPath = $proc.Path } catch { continue }
        if ([string]::IsNullOrWhiteSpace($procPath)) { continue }
        $procDir = $null
        try { $procDir = [System.IO.Path]::GetDirectoryName($procPath) } catch { continue }
        if ($procDir -eq $BinDir) { $found += $proc }
    }
    return $found
}

function Stop-InstallDirProcesses {
    param([string]$BinDir)
    $stopped = @()
    foreach ($proc in (Get-InstallDirProcesses -BinDir $BinDir)) {
        $label = "$($proc.ProcessName) (PID $($proc.Id))"
        Write-Host "Stopping running $label from the install directory..." -ForegroundColor Yellow
        try { $null = $proc.CloseMainWindow() } catch {}
        try {
            if (-not $proc.WaitForExit(5000)) {
                $proc.Kill()
                $null = $proc.WaitForExit(10000)
            }
        } catch {}
        $stopped += $label
    }
    return $stopped
}

function Install-BinaryWithLockHandling {
    param([string]$Source, [string]$Destination, [string]$BinDir)
    $stopped = @()
    $stopAttempted = $false
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            Copy-Item -LiteralPath $Source -Destination $Destination -Force
            return $stopped
        } catch {
            $locked = $_.Exception -is [System.IO.IOException]
            if (-not $locked) { throw }
            if ($env:CIPHERVAULT_INSTALL_NO_STOP -eq "1") { throw (New-LockedError $Destination $BinDir) }
            if (-not $stopAttempted) {
                $stopAttempted = $true
                $justStopped = Stop-InstallDirProcesses -BinDir $BinDir
                if ($justStopped) { $stopped += @($justStopped) }
            }
            if ($attempt -eq 6) { throw (New-LockedError $Destination $BinDir) }
            Start-Sleep -Milliseconds 1000
        }
    }
    return $stopped
}

function New-LockedError {
    param([string]$Destination, [string]$BinDir)
    $holders = @(Get-InstallDirProcesses -BinDir $BinDir | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" })
    $holderText = if ($holders.Count -gt 0) {
        "Still holding it: $($holders -join ', ')."
    } else {
        "No CipherVault process is holding it now - a transient antivirus/file-manager lock is likely."
    }
    return "Cannot replace '$Destination': the file is locked. $holderText Close any CipherVault windows (TUI, agent, operator, maintenance) and re-run the installer."
}
$InstallDir = $env:CIPHERVAULT_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $HOME ".ciphervault" }
$BinDir = Join-Path $InstallDir "bin"
$Role = $env:CIPHERVAULT_ROLE
if ([string]::IsNullOrWhiteSpace($Role)) { $Role = "full" }
$Role = $Role.Trim().ToLowerInvariant()
$Binaries = switch ($Role) {
    "developer" { @("ciphervault.exe", "ciphervault-agent.exe") }
    "node" { @("ciphervault.exe", "ciphervault-operator.exe", "ciphervault-maintenance.exe") }
    "full" { @("ciphervault.exe", "ciphervault-operator.exe", "ciphervault-agent.exe", "ciphervault-maintenance.exe") }
    default { throw "Unknown CIPHERVAULT_ROLE '$Role'. Use developer, node, or full." }
}

$Tag = $env:CIPHERVAULT_VERSION
if ([string]::IsNullOrWhiteSpace($Tag)) {
    try {
        $release = Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/repos/$Repo/releases/latest"
    } catch {
        throw "Could not read the release feed: $($_.Exception.Message). $PrivateHint"
    }
    $Tag = [string]$release.tag_name
    if ([string]::IsNullOrWhiteSpace($Tag)) { throw "GitHub did not return a latest CipherVault release." }
} else {
    $Tag = $Tag.Trim()
    try {
        $release = Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/repos/$Repo/releases/tags/$Tag"
    } catch {
        throw "Could not read release $Tag : $($_.Exception.Message). $PrivateHint"
    }
}
$PkgName = "ciphervault-$Tag-$Target.zip"
$SumsName = "SHA256SUMS.txt"
# Assets download through the API asset endpoint (Accept: octet-stream):
# the browser-download redirector does not honor tokens on private repos.
$DlHeaders = $Headers.Clone()
$DlHeaders["Accept"] = "application/octet-stream"
$pkgAsset = @($release.assets) | Where-Object { $_.name -eq $PkgName } | Select-Object -First 1
if ($null -eq $pkgAsset) { throw "Release $Tag has no Windows x64 archive ($PkgName)." }
$sumsAsset = @($release.assets) | Where-Object { $_.name -eq $SumsName } | Select-Object -First 1
if ($null -eq $sumsAsset) { throw "Release $Tag has no $SumsName." }
$ArchiveUrl = "https://api.github.com/repos/$Repo/releases/assets/$($pkgAsset.id)"
$SumsUrl = "https://api.github.com/repos/$Repo/releases/assets/$($sumsAsset.id)"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Installing CipherVault $Tag (Windows x64)" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ciphervault-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
try {
    $archive = Join-Path $tempRoot $PkgName
    try {
        Invoke-WebRequest -Headers $DlHeaders -Uri $ArchiveUrl -OutFile $archive -UseBasicParsing
    } catch {
        throw "Could not download ${PkgName}: $($_.Exception.Message). $PrivateHint"
    }
    try {
        $sumsResponse = Invoke-WebRequest -Headers $DlHeaders -Uri $SumsUrl -UseBasicParsing
    } catch {
        throw "Could not download SHA256SUMS.txt: $($_.Exception.Message). $PrivateHint"
    }
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
    $stoppedProcesses = @()
    foreach ($name in $Binaries) {
        $binary = Get-ChildItem -LiteralPath $extract -Filter $name -Recurse -File | Select-Object -First 1
        if ($null -eq $binary) { throw "The verified release archive does not contain $name." }
        $justStopped = Install-BinaryWithLockHandling -Source $binary.FullName -Destination (Join-Path $BinDir $name) -BinDir $BinDir
        if ($justStopped) { $stoppedProcesses += @($justStopped) }
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

Write-Host "[+] CipherVault $Tag ($Role) installed to $BinDir" -ForegroundColor Green
if ($stoppedProcesses.Count -gt 0) {
    Write-Host "Stopped for replacement: $($stoppedProcesses -join ', '). Restart anything you need (operator daemon, file-watcher agent, TUI)." -ForegroundColor Yellow
}
if ($Role -eq "node") {
    Write-Host "Next (from a NEW terminal): 'ciphervault node setup' for guided node onboarding." -ForegroundColor Yellow
} else {
    Write-Host "Next (from a NEW terminal): 'ciphervault init' (new vault), 'ciphervault --help' (command groups), or bare 'ciphervault' (guided TUI)." -ForegroundColor Yellow
}
Write-Host "To update later, run 'ciphervault update' or rerun this installer." -ForegroundColor Yellow
