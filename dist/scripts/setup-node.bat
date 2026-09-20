@echo off
title CipherVault Node Setup
rem Double-click friendly node onboarding: answers three questions, then
rem starts your storage node. Uses the CLI bundled next to this script,
rem so no PATH setup is needed. Advanced users run `ciphervault node setup`.
"%~dp0..\bin\ciphervault.exe" node setup
pause
