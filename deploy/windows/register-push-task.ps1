# ==============================================================================
# CipherVault Periodic Snapshot Push Task Registration (push backstop)
# ==============================================================================
param(
    [ValidateSet("Register", "Unregister", "Status")]
    [string]$Action = "Register",
    [int]$IntervalMinutes = 15
)

$TaskName = "CipherVault-Periodic-Push"
$ExePath = Join-Path $HOME ".ciphervault\bin\ciphervault.exe"

switch ($Action) {
    "Register" {
        if (-not (Test-Path -Path $ExePath)) {
            $ExePath = (Get-Command ciphervault.exe -ErrorAction SilentlyContinue).Source
        }
        if (-not $ExePath) {
            throw "ciphervault.exe not found in ~/.ciphervault/bin or PATH. Please install CipherVault first."
        }

        Write-Host "Registering Windows Scheduled Task: $TaskName..." -ForegroundColor Cyan
        # Runs in the vault home: adjust -WorkingDirectory to the vault to replicate.
        $TaskAction = New-ScheduledTaskAction -Execute $ExePath -Argument "push" -WorkingDirectory $HOME
        $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration ([TimeSpan]::MaxValue)
        $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Description "CipherVault Automated Periodic Snapshot Push (forgot-to-push backstop)" -Force | Out-Null
        Write-Host "[+] Scheduled task '$TaskName' registered successfully (runs every $IntervalMinutes minute(s))!" -ForegroundColor Green
    }
    "Unregister" {
        Write-Host "Unregistering task $TaskName..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Scheduled task '$TaskName' unregistered." -ForegroundColor Green
    }
    "Status" {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-Host "Task '$TaskName' is $($task.State)" -ForegroundColor Green
            Get-ScheduledTaskInfo -TaskName $TaskName | Format-List LastRunTime, NextRunTime, LastTaskResult
        } else {
            Write-Host "Task '$TaskName' is not registered." -ForegroundColor Yellow
        }
    }
}
