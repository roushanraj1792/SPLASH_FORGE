$ErrorActionPreference = "Continue"

Set-Location $PSScriptRoot

while ($true) {

    Clear-Host

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "                SPLASH FORGE CONTROL PANEL" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Clean + Start SPLASH FORGE" -ForegroundColor Green
    Write-Host "  [2] Clean Demo Database" -ForegroundColor Yellow
    Write-Host "  [3] Stop SPLASH FORGE" -ForegroundColor Red
    Write-Host "  [0] Exit" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "Enter choice"

    switch ($choice) {

        "1" {
            Write-Host ""
            Write-Host "Starting CLEAN SPLASH FORGE demo..." -ForegroundColor Green
            Write-Host ""
            & ".\start_clean_demo.ps1"
            Write-Host ""
            Read-Host "Press Enter to return to menu"
        }

        "2" {
            Write-Host ""
            Write-Host "Cleaning demo database..." -ForegroundColor Yellow
            Write-Host ""

            python -c "from pathlib import Path; import sqlite3; p=Path('database/sentinelx.db'); c=sqlite3.connect(p); c.execute('PRAGMA foreign_keys=OFF'); tables=[r[0] for r in c.execute('SELECT name FROM sqlite_master WHERE type=? AND name NOT LIKE ?',('table','sqlite_%')) if r[0] != 'users']; [c.execute('DELETE FROM [' + t.replace(']', ']]') + ']') for t in tables]; c.commit(); c.close(); print('Database cleaned successfully. Users preserved.')"

            Write-Host ""
            Read-Host "Press Enter to return to menu"
        }

        "3" {
            Write-Host ""
            Write-Host "Stopping SPLASH FORGE..." -ForegroundColor Red
            Write-Host ""
            & ".\stop_sentinelx.ps1"
            Write-Host ""
            Read-Host "Press Enter to return to menu"
        }

        "0" {
            Write-Host ""
            Write-Host "Exiting SPLASH FORGE Control Panel..." -ForegroundColor Gray
            break
        }

        default {
            Write-Host ""
            Write-Host "Invalid choice. Please select 1, 2, 3 or 0." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}
