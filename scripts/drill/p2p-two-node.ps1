# Two-node P2P mesh drill: boots two operators with an explicit
# bootstrap edge, probes the seed from the joiner via --p2p-probe-peer,
# and asserts the probe RPC succeeds. Localhost only, no fleet needed.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts/drill/p2p-two-node.ps1
#   [-OperatorBin <path>] [-PortA 18631] [-PortB 18632]
param(
    [string]$OperatorBin = "ciphervault-operator",
    [int]$PortA = 18631,
    [int]$PortB = 18632,
    [int]$TcpA = 19301,
    [int]$QuicA = 19302,
    [int]$TcpB = 19311,
    [int]$QuicB = 19312
)

$ErrorActionPreference = "Stop"

function New-ServiceToken {
    $b = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return (($b | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Wait-Healthy([string]$BaseUrl, [int]$TimeoutSecs = 30) {
    $deadline = (Get-Date).AddSeconds($TimeoutSecs)
    while ((Get-Date) -lt $deadline) {
        try {
            $body = Invoke-WebRequest "$BaseUrl/healthz" -UseBasicParsing -TimeoutSec 3
            if ($body.Content -match '"status"\s*:\s*"ready"') { return }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    throw "node at $BaseUrl never became ready"
}

function Wait-LogMatch([string]$LogFile, [string]$Pattern, [int]$TimeoutSecs = 90) {
    $deadline = (Get-Date).AddSeconds($TimeoutSecs)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $LogFile) {
            $hit = Select-String -Path $LogFile -Pattern $Pattern -SimpleMatch | Select-Object -First 1
            if ($null -ne $hit) { return $hit.Line }
        }
        Start-Sleep -Seconds 2
    }
    throw "timed out waiting for [$Pattern] in $LogFile"
}

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("cv-p2p-drill-" + [guid]::NewGuid().ToString("N"))
$dirA = Join-Path $root "a"
$dirB = Join-Path $root "b"
New-Item -ItemType Directory -Force -Path $dirA, $dirB | Out-Null
$procA = $null
$procB = $null
try {
    Write-Host "--- seed node (A) on HTTP $PortA / P2P $TcpA ---"
    $env:CIPHERVAULT_OPERATOR_SERVICE_TOKEN = New-ServiceToken
    $procA = Start-Process $OperatorBin -ArgumentList @(
        "--port", $PortA, "--data-dir", $dirA, "--operator-id", "drill-a",
        "--enable-p2p", "--p2p-tcp-port", $TcpA, "--p2p-quic-port", $QuicA
    ) -RedirectStandardOutput (Join-Path $dirA "out.log") -WindowStyle Hidden -PassThru
    Wait-Healthy "http://127.0.0.1:$PortA"
    $peerLine = Select-String -Path (Join-Path $dirA "out.log") -Pattern "P2P Peer ID:" | Select-Object -First 1
    if ($null -eq $peerLine) { throw "seed log has no P2P Peer ID line" }
    $peerA = ($peerLine.Line -split "P2P Peer ID:")[1].Trim()
    Write-Host "seed peer id: $peerA"
    $bootstrapA = "/ip4/127.0.0.1/tcp/$TcpA/p2p/$peerA"

    Write-Host "--- joiner node (B), bootstrapped to A ---"
    $env:CIPHERVAULT_OPERATOR_SERVICE_TOKEN = New-ServiceToken
    $procB = Start-Process $OperatorBin -ArgumentList @(
        "--port", $PortB, "--data-dir", $dirB, "--operator-id", "drill-b",
        "--enable-p2p", "--p2p-tcp-port", $TcpB, "--p2p-quic-port", $QuicB,
        "--p2p-bootstrap", $bootstrapA, "--p2p-probe-peer", $peerA
    ) -RedirectStandardOutput (Join-Path $dirB "out.log") -WindowStyle Hidden -PassThru
    Wait-Healthy "http://127.0.0.1:$PortB"

    $probe = Wait-LogMatch (Join-Path $dirB "out.log") "P2P probe ${peerA}: OK"
    Write-Host "MESH OK: $probe"
    Write-Host "PASS: two-node P2P drill" -ForegroundColor Green
} finally {
    foreach ($p in @($procA, $procB)) {
        if ($null -ne $p) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {}
        }
    }
    Start-Sleep 1
    if (Test-Path $root) { Remove-Item -Recurse -Force $root }
}
