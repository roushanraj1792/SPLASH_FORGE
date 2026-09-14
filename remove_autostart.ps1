# ==============================================================================
# SentinelX Local Auto-Start Removal Script
# Disables, stops, and removes the SentinelX Windows Task Scheduler task
# ==============================================================================
[CmdletBinding()]
param (
    [switch]$StopRunning
)

$ErrorActionPreference = "Continue"
$taskName = "SentinelX_AutoStart"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   SPLASH FORGE SOC PLATFORM -- REMOVE LOCAL AUTO-START        " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Connect to Windows Task Scheduler via COM
$service = New-Object -ComObject("Schedule.Service")
$service.Connect()
$rootFolder = $service.GetFolder("\")

# Check if task exists
$task = $null
try {
    $task = $rootFolder.GetTask($taskName)
} catch {}

if ($task) {
    try {
        if ($task.State -eq 4) { # 4 = TASK_STATE_RUNNING
            Write-Host "Stopping running task '$taskName'..." -ForegroundColor Yellow
            $task.Stop(0)
        }
        $rootFolder.DeleteTask($taskName, 0)
        Write-Host "[SUCCESS] Scheduled Task '$taskName' removed successfully." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to delete task '$taskName': $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[INFO] Scheduled Task '$taskName' not found (already removed)." -ForegroundColor Gray
}

# Stop any lingering process on port 8501 if requested
if ($StopRunning -or $true) {
    $conns = Get-NetTCPConnection -LocalPort 8501 -State Listen -ErrorAction SilentlyContinue
    if ($conns) {
        foreach ($c in $conns) {
            Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
            Write-Host "[OK] Stopped process $($c.OwningProcess) listening on port 8501." -ForegroundColor Green
        }
    }
}

Write-Host "`nSPLASH FORGE auto-start removal complete." -ForegroundColor Green
