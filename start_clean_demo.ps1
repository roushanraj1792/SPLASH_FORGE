$ErrorActionPreference = "Stop"

Write-Host "============================================================"
Write-Host " SPLASH FORGE - CLEAN LIVE DEMO START"
Write-Host "============================================================"
Write-Host ""

python -c "from pathlib import Path; import sqlite3; p=Path('database/sentinelx.db'); c=sqlite3.connect(p); c.execute('PRAGMA foreign_keys=OFF'); tables=[r[0] for r in c.execute('SELECT name FROM sqlite_master WHERE type=? AND name NOT LIKE ?',('table','sqlite_%')) if r[0] != 'users']; [c.execute('DELETE FROM [' + t.replace(']', ']]') + ']') for t in tables]; c.commit(); c.close(); print('Database cleaned successfully. Users preserved.')"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Database cleanup FAILED."
    exit 1
}

Write-Host ""
Write-Host "Starting SPLASH FORGE..."
Write-Host ""

& ".\start_public_sentinelx.ps1"
