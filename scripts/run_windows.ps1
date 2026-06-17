# Run from the project folder in Windows PowerShell:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\scripts\run_windows.ps1

$ErrorActionPreference = "Stop"

$pythonCmd = Get-Command py -ErrorAction SilentlyContinue
if ($pythonCmd) {
    $pythonExe = "py"
} else {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd) {
        $pythonExe = "python"
    } else {
        Write-Host "Python was not found. Install Python 3.11+ and tick 'Add Python to PATH', then reopen PowerShell."
        exit 1
    }
}

if (!(Test-Path ".venv")) {
    & $pythonExe -m venv .venv
}

. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

if (!(Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example. Edit BOT_TOKEN, ADMIN_IDS, ADMIN_PANEL_PASSWORD, and ADMIN_SESSION_SECRET, then run this script again."
    notepad .env
    exit 0
}

Write-Host "Starting bot + admin website in one process. Do not run a second bot instance."
Write-Host "Local admin panel: http://127.0.0.1:8080/admin"
python bot.py
