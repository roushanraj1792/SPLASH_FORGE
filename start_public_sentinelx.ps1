# SentinelX Public Access Launcher
# Boots SentinelX on port 8501 and creates a public HTTPS tunnel via Cloudflare
$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   SENTINELX SOC PLATFORM -- PUBLIC SECURE TUNNEL LAUNCHER      " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

$python = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "[ERROR] Python virtual environment missing at $python" -ForegroundColor Red
    exit 1
}

# 1. Start Streamlit if not running on port 8501
$streamlitConn = Get-NetTCPConnection -LocalPort 8501 -State Listen -ErrorAction SilentlyContinue
if (-not $streamlitConn) {
    Write-Host "`n[1/3] Starting SentinelX Streamlit server on port 8501..." -ForegroundColor Yellow
    Start-Process `
        -FilePath $python `
        -ArgumentList "-m streamlit run app.py --server.port 8501 --server.headless true" `
        -WorkingDirectory $PSScriptRoot `
        -WindowStyle Hidden
} else {
    Write-Host "`n[1/3] SentinelX Streamlit server is already running on port 8501." -ForegroundColor Green
}

# Wait for Streamlit HTTP 200
Write-Host "`n[2/3] Verifying Streamlit local health..." -ForegroundColor Yellow
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

if (-not $healthy) {
    Write-Host "[ERROR] Streamlit did not respond on http://127.0.0.1:8501" -ForegroundColor Red
    exit 1
}
Write-Host "      SentinelX local server is Healthy (HTTP 200 OK)" -ForegroundColor Green

# 2. Check cloudflared binary
$cloudflared = Join-Path $PSScriptRoot "cloudflared.exe"
if (-not (Test-Path $cloudflared)) {
    Write-Host "`n[INFO] Downloading cloudflared.exe..." -ForegroundColor Yellow
    curl.exe -L --output $cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe
}

# 3. Check if cloudflared is already running
$cfRunning = Get-Process -Name "cloudflared" -ErrorAction SilentlyContinue
if (-not $cfRunning) {
    Write-Host "`n[3/3] Establishing Cloudflare Secure Public Tunnel..." -ForegroundColor Yellow
    $tunnelLog = Join-Path $PSScriptRoot "tunnel.log"
    if (Test-Path $tunnelLog) { Remove-Item $tunnelLog -Force }

    Start-Process `
        -FilePath $cloudflared `
        -ArgumentList "tunnel --url http://127.0.0.1:8501" `
        -WorkingDirectory $PSScriptRoot `
        -RedirectStandardError $tunnelLog `
        -WindowStyle Hidden

    $tunnelUrl = $null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-Path $tunnelLog) {
            $content = Get-Content $tunnelLog -Raw -ErrorAction SilentlyContinue
            if ($content -match "(https://[a-zA-Z0-9-]+\.trycloudflare\.com)") {
                $tunnelUrl = $matches[1]
                break
            }
        }
    }
} else {
    Write-Host "`n[3/3] Cloudflare Tunnel is already running." -ForegroundColor Green
    if (Test-Path (Join-Path $PSScriptRoot "tunnel_url.txt")) {
        $tunnelUrl = (Get-Content (Join-Path $PSScriptRoot "tunnel_url.txt") -Raw).Trim()
    }
}

if ($tunnelUrl) {
    Set-Content -Path (Join-Path $PSScriptRoot "tunnel_url.txt") -Value $tunnelUrl -Force
    Write-Host "`n================================================================" -ForegroundColor Green
    Write-Host "   SENTINELX SOC PLATFORM -- SECURE PUBLIC ACCESS READY         " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " PUBLIC HTTPS URL : " -NoNewline; Write-Host $tunnelUrl -ForegroundColor Cyan
    Write-Host " LOCAL ACCESS     : " -NoNewline; Write-Host "http://localhost:8501" -ForegroundColor Gray
    Write-Host " STATUS           : " -NoNewline; Write-Host "LIVE & OPERATIONAL (Cross-network ready)" -ForegroundColor Green
    Write-Host ""
    Write-Host " DEMO LOGIN CREDENTIALS:" -ForegroundColor Yellow
    Write-Host "   Admin   : admin   / SentinelX@Admin2026   (Role: ADMIN - Full Control)"
    Write-Host "   Analyst : analyst / SentinelX@Analyst2026 (Role: ANALYST - Investigations)"
    Write-Host ""
    Write-Host " Share the PUBLIC HTTPS URL above with your teammates and judges!" -ForegroundColor Cyan
    Write-Host " To stop SentinelX and the tunnel, run: .\stop_sentinelx.ps1" -ForegroundColor Gray
    Write-Host "================================================================" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Could not extract public tunnel URL. Check tunnel.log." -ForegroundColor Red
}
