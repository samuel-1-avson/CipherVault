@echo off
title CipherVault Autonomous File Watcher
cd /d "%~dp0"
echo ================================================================================
echo   Launching CipherVault Autonomous File Watcher Daemon
echo   Debounce: 2 seconds ^| Remote Sync: Enabled (3/3 Operators)
echo ================================================================================
echo.

if exist "%USERPROFILE%\.cargo\bin\ciphervault.exe" (
    "%USERPROFILE%\.cargo\bin\ciphervault.exe" watch --debounce 2 --sync
) else if exist ".\dist\bin\ciphervault.exe" (
    ".\dist\bin\ciphervault.exe" watch --debounce 2 --sync
) else (
    cargo run -p ciphervault-cli -- watch --debounce 2 --sync
)

pause
