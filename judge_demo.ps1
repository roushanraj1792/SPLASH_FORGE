[CmdletBinding()]
param(
    [string]$ApiUrl = "http://127.0.0.1:8502"
)

$ErrorActionPreference = "Stop"

$envFile = Join-Path $PSScriptRoot ".env"
if (-not $env:SENTINELX_INGEST_TOKEN -and (Test-Path $envFile)) {
    $line = Get-Content $envFile | Where-Object { $_ -match '^SENTINELX_INGEST_TOKEN=' } | Select-Object -First 1
    if ($line) {
        $env:SENTINELX_INGEST_TOKEN = $line -replace '^SENTINELX_INGEST_TOKEN=',''
    }
}

$token = $env:SENTINELX_INGEST_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "SENTINELX_INGEST_TOKEN is not configured."
}

function Send-SentinelEvent {
    param([hashtable]$Event)

    $json = $Event | ConvertTo-Json -Compress
    $headers = @{ Authorization = "Bearer $token" }

    Invoke-RestMethod `
        -Uri "$ApiUrl/events" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $json
}

Write-Host "============================================================"
Write-Host " SENTINELX - AUTHORIZED JUDGE DEMO SIMULATION"
Write-Host "============================================================"
Write-Host ""

Write-Host "[1/5] API health"
Invoke-RestMethod -Uri "$ApiUrl/health" -Method Get | Format-List
Write-Host ""

Write-Host "[2/5] Brute-force simulation: 5 failed logins"
1..5 | ForEach-Object {
    Send-SentinelEvent @{
        event_type = "LOGIN"
        source_ip = "10.0.0.50"
        username = "windows_demo"
        status = "FAILED"
        message = "Authorized SentinelX demo failed login attempt $_"
    }
    Start-Sleep -Seconds 1
}
Write-Host ""

Write-Host "[3/5] Port-scan simulation: 10 unique ports"
$ports = @(21,22,23,25,53,80,110,135,443,445)
foreach ($port in $ports) {
    Send-SentinelEvent @{
        event_type = "NETWORK_CONNECTION"
        source_ip = "10.0.0.50"
        username = "windows_demo"
        status = "FAILED"
        message = "Authorized SentinelX demo connection attempt to port $port"
        port = $port
    }
    Start-Sleep -Seconds 5
}
Write-Host ""

Write-Host "[4/5] Privilege + PowerShell simulation"
1..3 | ForEach-Object {
    Send-SentinelEvent @{
        event_type = "PRIVILEGE_CHANGE"
        source_ip = "10.0.0.50"
        username = "windows_demo"
        status = "SUCCESS"
        message = "Authorized SentinelX demo privilege escalation event $_"
    }
    Start-Sleep -Seconds 1
}

Send-SentinelEvent @{
    event_type = "POWERSHELL"
    source_ip = "10.0.0.50"
    username = "windows_demo"
    status = "SUCCESS"
    message = "Authorized SentinelX demo PowerShell ExecutionPolicy Bypass"
}
Start-Sleep -Seconds 1
Send-SentinelEvent @{
    event_type = "POWERSHELL"
    source_ip = "10.0.0.50"
    username = "windows_demo"
    status = "SUCCESS"
    message = "Authorized SentinelX demo PowerShell EncodedCommand"
}
Write-Host ""

Write-Host "[5/5] Simulation complete."
Write-Host ""
Write-Host "Open SentinelX and show:"
Write-Host "  Events -> Alerts -> Incident -> Evidence/Timeline"
Write-Host "  Investigation -> Recommended Response -> Containment -> Verification"
Write-Host ""
Write-Host "No external host was scanned or attacked."
