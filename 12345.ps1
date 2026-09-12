# SentinelX Telegram Alert Test Shortcut

$ErrorActionPreference = "Stop"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   SENTINELX - TELEGRAM ALERT TEST           " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

$python = Join-Path $PSScriptRoot "venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "[ERROR] Python virtual environment not found." -ForegroundColor Red
    exit 1
}

Write-Host "[1/2] Sending safe Telegram test alert..." -ForegroundColor Yellow

try {
    & $python -c "from services.telegram_alert import send_telegram_message; send_telegram_message('SentinelX SAFE TEST ALERT - Telegram integration is working. This is only a test, not a real security incident.')"

    if ($LASTEXITCODE -ne 0) {
        throw "Telegram service returned exit code $LASTEXITCODE"
    }

    Write-Host "[2/2] Telegram test completed successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "SUCCESS: Check your Telegram." -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "[ERROR] Telegram test failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
