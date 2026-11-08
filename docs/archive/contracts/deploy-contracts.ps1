<#
.SYNOPSIS
    Deploys CipherVaultRegistry.sol to Arbitrum One or Arbitrum Sepolia.

.DESCRIPTION
    Automates smart contract deployment using Foundry (forge) with automated
    Arbiscan contract source code verification.

.PARAMETER Network
    Target network: 'arbitrum_sepolia' (Chain ID 421614) or 'arbitrum_one' (Chain ID 42161).

.PARAMETER Verify
    Flag to verify contract on Arbiscan using $env:ARBISCAN_API_KEY.

.EXAMPLE
    .\scripts\deploy-contracts.ps1 -Network arbitrum_sepolia -Verify
#>

[CmdletBinding()]
param(
    [ValidateSet("arbitrum_sepolia", "arbitrum_one")]
    [string]$Network = "arbitrum_sepolia",

    [switch]$Verify
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CipherVault Smart Contract Deployer                     " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target Network: $Network" -ForegroundColor Yellow

$RpcMap = @{
    "arbitrum_sepolia" = @{
        "Rpc" = if ($env:ARBITRUM_SEPOLIA_RPC) { $env:ARBITRUM_SEPOLIA_RPC } else { "https://sepolia-rollup.arbitrum.io/rpc" }
        "ChainId" = 421614
        "Explorer" = "https://sepolia.arbiscan.io"
        "VerifierUrl" = "https://api-sepolia.arbiscan.io/api"
    }
    "arbitrum_one" = @{
        "Rpc" = if ($env:ARBITRUM_ONE_RPC) { $env:ARBITRUM_ONE_RPC } else { "https://arb1.arbitrum.io/rpc" }
        "ChainId" = 42161
        "Explorer" = "https://arbiscan.io"
        "VerifierUrl" = "https://api.arbiscan.io/api"
    }
}

$NetConfig = $RpcMap[$Network]
$RpcUrl = $NetConfig.Rpc
Write-Host "RPC Endpoint:   $RpcUrl"
Write-Host "Chain ID:       $($NetConfig.ChainId)"

# Check Private Key
if (-not $env:PRIVATE_KEY) {
    Write-Warning "No PRIVATE_KEY environment variable detected."
    $keyInput = Read-Host -Prompt "Enter deployer private key (0x...)" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($keyInput)
    $PlainKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    $env:PRIVATE_KEY = $PlainKey
}

if (-not $env:PRIVATE_KEY) {
    Write-Error "Deployment aborted: PRIVATE_KEY is required to sign transactions."
    exit 1
}

# Check Foundry installation
$forgeCmd = Get-Command forge -ErrorAction SilentlyContinue
if (-not $forgeCmd) {
    Write-Warning "Foundry ('forge') is not detected in PATH."
    Write-Host "`nTo install Foundry on Windows:" -ForegroundColor Yellow
    Write-Host "  powershell -c ""irm https://foundry.paradigm.xyz | iex"""
    Write-Host "  foundryup"
    Write-Host "`nAlternative 1: Deploy with Node.js script: node scripts/deploy-registry.cjs --network $Network" -ForegroundColor Green
    Write-Host "Alternative 2: Deploy using cast or standard web3 wallet to contracts/CipherVaultRegistry.sol"
    exit 1
}

Write-Host "`nCompiling contracts with Foundry..." -ForegroundColor Cyan
forge build

$deployArgs = @(
    "script",
    "contracts/script/DeployRegistry.s.sol:DeployRegistry",
    "--rpc-url", $RpcUrl,
    "--broadcast"
)

if ($Verify) {
    if (-not $env:ARBISCAN_API_KEY) {
        Write-Warning "ARBISCAN_API_KEY is not set. Contract will be deployed without automated verification."
    } else {
        $deployArgs += @("--verify", "--verifier-url", $NetConfig.VerifierUrl, "--etherscan-api-key", $env:ARBISCAN_API_KEY)
    }
}

Write-Host "`nBroadcasting deployment transaction to $Network..." -ForegroundColor Green
& forge @deployArgs

Write-Host "`nDeployment complete! Review your transaction on $($NetConfig.Explorer)" -ForegroundColor Green
Write-Host "Set the deployed contract in your environment:" -ForegroundColor Cyan
Write-Host '  $env:CIPHERVAULT_REGISTRY_CONTRACT = "0x<DEPLOYED_ADDRESS>"' -ForegroundColor White
