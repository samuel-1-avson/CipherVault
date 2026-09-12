@echo off
title Start CipherVault Operators
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File scripts\start-operators.ps1
pause
