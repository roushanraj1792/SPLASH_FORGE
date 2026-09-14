Write-Host "SPLASH FORGE validation starting..." -ForegroundColor Cyan

$python = ".\venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "Python virtual environment missing." -ForegroundColor Red
    exit 1
}

Write-Host "`n[1] Python compilation" -ForegroundColor Cyan
& $python -m compileall -q app.py database detection services simulator tests

if ($LASTEXITCODE -eq 0) {
    Write-Host "[PASS] Python compilation" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Python compilation" -ForegroundColor Red
}

Write-Host "`n[2] Complete pytest suite" -ForegroundColor Cyan
& $python -m pytest -q

if ($LASTEXITCODE -eq 0) {
    Write-Host "[PASS] Pytest suite" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Pytest suite" -ForegroundColor Red
}

Write-Host "`n[3] Port Scan and Privilege Escalation" -ForegroundColor Cyan

& $python -c "from datetime import datetime,timezone,timedelta; from detection.port_scan import detect_port_scan; from detection.privilege_escalation import detect_privilege_escalation; now=datetime.now(timezone.utc); ports=[21,22,23,25,53,80,110,135,443,445]; e=[{'id':i+1,'timestamp':(now+timedelta(seconds=i*5)).isoformat(),'source_ip':'10.99.99.10','event_type':'NETWORK_CONNECTION','port':p} for i,p in enumerate(ports)]; a=detect_port_scan(e); print('[PASS] Port Scan' if a else '[FAIL] Port Scan'); e2=[{'id':i+1,'timestamp':(now+timedelta(minutes=i)).isoformat(),'source_ip':'10.99.99.20','event_type':'PRIVILEGE_CHANGE','status':'SUCCESS'} for i in range(3)]; a2=detect_privilege_escalation(e2); print('[PASS] Privilege Escalation' if a2 else '[FAIL] Privilege Escalation')"

Write-Host "`n[4] Streamlit health check" -ForegroundColor Cyan

$port = 8511
$process = Start-Process `
    -FilePath $python `
    -ArgumentList "-m streamlit run app.py --server.headless true --server.port $port" `
    -WorkingDirectory (Get-Location) `
    -PassThru `
    -WindowStyle Hidden

$healthy = $false

for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500

    try {
        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$port" `
            -UseBasicParsing `
            -TimeoutSec 2

        if ($response.StatusCode -eq 200) {
            $healthy = $true
            break
        }
    } catch {}
}

if ($healthy) {
    Write-Host "[PASS] Streamlit HTTP 200" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Streamlit health check" -ForegroundColor Red
}

if ($process -and -not $process.HasExited) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "SPLASH FORGE validation completed." -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
