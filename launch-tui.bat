@echo off
title CipherVault TUI Dashboard
cd /d "%~dp0"
if exist "dist\bin\ciphervault.exe" (
    dist\bin\ciphervault.exe tui
) else (
    cargo run -p ciphervault-cli -- tui
)
pause
