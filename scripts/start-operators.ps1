$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir
Write-Host "Starting CipherVault 3-Node Operator Quorum..." -ForegroundColor Cyan
Start-Process "wt.exe" -ArgumentList "-w 0 nt -d `"$RootDir`" powershell -NoExit -Command `"Write-Host 'Operator 1 (Port 8101)' -ForegroundColor Green; .\dist\bin\ciphervault-operator.exe -p 8101 -d ./operator-data-1 -o operator-1`""
Start-Process "wt.exe" -ArgumentList "-w 0 nt -d `"$RootDir`" powershell -NoExit -Command `"Write-Host 'Operator 2 (Port 8102)' -ForegroundColor Green; .\dist\bin\ciphervault-operator.exe -p 8102 -d ./operator-data-2 -o operator-2`""
Start-Process "wt.exe" -ArgumentList "-w 0 nt -d `"$RootDir`" powershell -NoExit -Command `"Write-Host 'Operator 3 (Port 8103)' -ForegroundColor Green; .\dist\bin\ciphervault-operator.exe -p 8103 -d ./operator-data-3 -o operator-3`""
Write-Host "All 3 operators spawned in Windows Terminal tabs!" -ForegroundColor Green
