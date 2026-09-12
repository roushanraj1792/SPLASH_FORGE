# ==============================================================================
# SentinelX Local Auto-Start Configuration Script
# Configures Windows Task Scheduler to start SentinelX on localhost:8501 at logon
# ==============================================================================
[CmdletBinding()]
param (
    [switch]$StartNow
)

$ErrorActionPreference = "Stop"

$taskName = "SentinelX_AutoStart"
$projectDir = $PSScriptRoot
if (-not $projectDir) {
    $projectDir = "C:\Users\krak7\OneDrive\Desktop\SentinelX"
}

$pythonExe = Join-Path $projectDir "venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "[ERROR] Python interpreter not found at: $pythonExe" -ForegroundColor Red
    exit 1
}

$appPy = Join-Path $projectDir "app.py"
if (-not (Test-Path $appPy)) {
    Write-Host "[ERROR] app.py not found at: $appPy" -ForegroundColor Red
    exit 1
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   SENTINELX SOC PLATFORM -- LOCAL AUTO-START CONFIGURATION    " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Project Directory : $projectDir" -ForegroundColor Gray
Write-Host " Python Executable : $pythonExe" -ForegroundColor Gray
Write-Host " Task Name         : $taskName" -ForegroundColor Gray
Write-Host " Target Address    : http://127.0.0.1:8501 (LOCAL ONLY)" -ForegroundColor Gray
Write-Host " Trigger           : Windows User Logon ($env:USERDOMAIN\$env:USERNAME)" -ForegroundColor Gray
Write-Host ""

# Connect to Windows Task Scheduler via COM
$service = New-Object -ComObject("Schedule.Service")
$service.Connect()
$rootFolder = $service.GetFolder("\")

# Create task definition
$taskDef = $service.NewTask(0)
$taskDef.RegistrationInfo.Description = "SentinelX Autonomous SOC Platform - Local Background Auto-Start (Port 8501)"
$taskDef.RegistrationInfo.Author = "SentinelX"

# 1. Trigger: User Logon
$trigger = $taskDef.Triggers.Create(9) # TASK_TRIGGER_LOGON = 9
$trigger.UserId = "$env:USERDOMAIN\$env:USERNAME"
$trigger.Enabled = $true

# 2. Action: Run Streamlit bound strictly to 127.0.0.1 (Local Only)
$action = $taskDef.Actions.Create(0) # TASK_ACTION_EXEC = 0
$action.Path = $pythonExe
$action.Arguments = "-m streamlit run app.py --server.port 8501 --server.headless true --server.address 127.0.0.1"
$action.WorkingDirectory = $projectDir

# 3. Settings: Background execution, automatic restart, unlimited execution time
$settings = $taskDef.Settings
$settings.AllowDemandStart = $true
$settings.AllowHardTerminate = $true
$settings.DisallowStartIfOnBatteries = $false
$settings.StopIfGoingOnBatteries = $false
$settings.ExecutionTimeLimit = "PT0S" # Unlimited duration
$settings.Hidden = $true
$settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW
$settings.RestartCount = 3 # Auto-restart up to 3 times on unexpected termination
$settings.RestartInterval = "PT1M" # Wait 1 minute before restart
$settings.StartWhenAvailable = $true
$settings.Priority = 7 # Normal background priority

# 4. Register the task (TASK_CREATE_OR_UPDATE = 6, TASK_LOGON_INTERACTIVE_TOKEN = 3)
try {
    $registeredTask = $rootFolder.RegisterTaskDefinition(
        $taskName,
        $taskDef,
        6, # TASK_CREATE_OR_UPDATE
        "$env:USERDOMAIN\$env:USERNAME",
        $null,
        3  # TASK_LOGON_INTERACTIVE_TOKEN
    )
    Write-Host "[SUCCESS] Windows Scheduled Task '$taskName' registered successfully." -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to register task definition: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 5. Optionally start immediately or verify health
if ($StartNow) {
    Write-Host "`nStarting SentinelX in background via Task Scheduler..." -ForegroundColor Yellow
    $registeredTask.Run($null) | Out-Null
    
    Write-Host "Waiting for SentinelX to initialize on http://127.0.0.1:8501..." -ForegroundColor Yellow
    $healthy = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $res = Invoke-WebRequest -Uri "http://127.0.0.1:8501/_stcore/health" -UseBasicParsing -TimeoutSec 2
            if ($res.StatusCode -eq 200) {
                $healthy = $true
                break
            }
        } catch {}
    }
    
    if ($healthy) {
        Write-Host "[SUCCESS] SentinelX is active and healthy on http://127.0.0.1:8501" -ForegroundColor Green
    } else {
        Write-Host "[WARNING] Task started, but health endpoint did not respond within 15 seconds." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Auto-start is configured. SentinelX will launch automatically" -ForegroundColor White
Write-Host " whenever you log into Windows." -ForegroundColor White
Write-Host ""
Write-Host " To manually start the task now : .\setup_autostart.ps1 -StartNow" -ForegroundColor Gray
Write-Host " To remove the auto-start task  : .\remove_autostart.ps1" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
