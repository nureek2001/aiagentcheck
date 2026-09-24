$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path '.venv/Scripts/python.exe')) { python -m venv .venv }
& .venv/Scripts/python.exe -m pip install -r requirements.lock -e '.[dev]'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not (Test-Path '.env')) { Copy-Item '.env.example' '.env' }
Write-Host 'Installed. Add your DeepSeek key to .env, then run scripts/scan.ps1.'
