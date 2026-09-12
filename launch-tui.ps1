Set-Location $PSScriptRoot
if (Test-Path "dist\bin\ciphervault.exe") {
    & "dist\bin\ciphervault.exe" tui
} else {
    cargo run -p ciphervault-cli -- tui
}
