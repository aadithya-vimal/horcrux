$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "              HORCRUX                   " -ForegroundColor Magenta
Write-Host "        Installation Wizard             " -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Python 3.11+ is required." -ForegroundColor Red
    Write-Host "    Install Python from https://www.python.org/downloads/"
    exit 1
}

$python = (Get-Command python).Source

Write-Host "[+] Python found: $python" -ForegroundColor Green

if (-not (Test-Path ".\.venv")) {
    Write-Host "[+] Creating virtual environment..." -ForegroundColor Cyan
    & $python -m venv .venv
}

$venvPython = Join-Path $PWD ".venv\Scripts\python.exe"

Write-Host "[+] Upgrading pip..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip

Write-Host "[+] Installing Horcrux dependencies..." -ForegroundColor Cyan
& $venvPython -m pip install -r requirements.txt

Write-Host "[+] Installing Horcrux..." -ForegroundColor Cyan
& $venvPython -m pip install -e .

Write-Host ""
Write-Host "[+] HORCRUX installation complete." -ForegroundColor Green
Write-Host ""
Write-Host "Run:" -ForegroundColor White
Write-Host "    .\.venv\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "    horcrux" -ForegroundColor Yellow
Write-Host ""
Write-Host "Check your environment with:" -ForegroundColor White
Write-Host "    horcrux doctor" -ForegroundColor Yellow
Write-Host ""
