$ErrorActionPreference = "Continue"

$root = "C:\Users\krak7\OneDrive\Desktop\SentinelX"
$python = Join-Path $root "venv\Scripts\python.exe"
$envFile = Join-Path $root ".env"

# Load SentinelX ingest token from .env without printing it
if (Test-Path $envFile) {
    $tokenLine = Get-Content $envFile -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^SENTINELX_INGEST_TOKEN=' } |
        Select-Object -First 1

    if ($tokenLine) {
        $env:SENTINELX_INGEST_TOKEN =
            $tokenLine -replace '^SENTINELX_INGEST_TOKEN=',''
    }
}

# Start API 8502 if it is not already running
$api = Get-NetTCPConnection -LocalPort 8502 -State Listen -ErrorAction SilentlyContinue

if (-not $api) {
    Start-Process `
        -FilePath $python `
        -ArgumentList "api.py" `
        -WorkingDirectory $root `
        -WindowStyle Hidden
}

# Start Streamlit 8501 if it is not already running
$streamlit = Get-NetTCPConnection -LocalPort 8501 -State Listen -ErrorAction SilentlyContinue

if (-not $streamlit) {
    Start-Process `
        -FilePath $python `
        -ArgumentList "-m streamlit run app.py --server.port 8501 --server.headless true --server.address 127.0.0.1" `
        -WorkingDirectory $root `
        -WindowStyle Hidden
}
