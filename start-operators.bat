@echo off
title Start CipherVault Operators
cd /d "%~dp0"
echo Starting CipherVault 3-node Operator Quorum...
wt -w 0 nt -d "%~dp0." powershell -NoExit -Command "Write-Host 'Operator 1 (Port 8101)' -ForegroundColor Green; .\dist\bin\ciphervault-operator.exe -p 8101 -d ./operator-data-1 -o operator-1"
wt -w 0 nt -d "%~dp0." powershell -NoExit -Command "Write-Host 'Operator 2 (Port 8102)' -ForegroundColor Green; .\dist\bin\ciphervault-operator.exe -p 8102 -d ./operator-data-2 -o operator-2"
wt -w 0 nt -d "%~dp0." powershell -NoExit -Command "Write-Host 'Operator 3 (Port 8103)' -ForegroundColor Green; .\dist\bin\ciphervault-operator.exe -p 8103 -d ./operator-data-3 -o operator-3"
echo All 3 operators spawned in Windows Terminal tabs!
