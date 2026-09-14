# SPLASH FORGE Clean Shutdown Script
Write-Host "Stopping SPLASH FORGE services..." -ForegroundColor Cyan

# Stop cloudflared
try {
    $service = New-Object -ComObject("Schedule.Service")
    $service.Connect()
    $rf = $service.GetFolder("\")
    $t = $rf.GetTask("SentinelX_PublicTunnel")
    if ($t) {
        if ($t.State -eq 4) { $t.Stop(0) }
        $rf.DeleteTask("SentinelX_PublicTunnel", 0)
    }
} catch {}

$cfProcesses = Get-Process -Name "cloudflared" -ErrorAction SilentlyContinue
if ($cfProcesses) {
    $cfProcesses | Stop-Process -Force
    Write-Host "[OK] Cloudflare tunnel stopped." -ForegroundColor Green
} else {
    Write-Host "[INFO] No cloudflared process found." -ForegroundColor Gray
}

# Stop streamlit processes listening on 8501
$conns = Get-NetTCPConnection -LocalPort 8501 -State Listen -ErrorAction SilentlyContinue
if ($conns) {
    foreach ($c in $conns) {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Stopped process $($c.OwningProcess) listening on port 8501." -ForegroundColor Green
    }
} else {
    Write-Host "[INFO] No process listening on port 8501." -ForegroundColor Gray
}

# Cleanup tunnel url file
$urlFile = Join-Path $PSScriptRoot "tunnel_url.txt"
if (Test-Path $urlFile) { Remove-Item $urlFile -Force }

Write-Host "SPLASH FORGE shutdown complete." -ForegroundColor Green
