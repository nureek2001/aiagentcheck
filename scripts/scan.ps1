param(
    [string]$Repo = '',
    [string]$Ref = 'main'
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not $Repo) {
    $Repo = Join-Path $PWD 'targets/KMG-Digital-Hackathon'
    if (-not (Test-Path $Repo)) {
        git clone https://github.com/AlmasNUR/KMG-Digital-Hackathon.git $Repo
        if ($LASTEXITCODE -ne 0) { exit 2 }
        git -C $Repo checkout $Ref
        if ($LASTEXITCODE -ne 0) { exit 2 }
    }
}
$runDirectory = Join-Path $PWD ('reports/run-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
& .venv/Scripts/python.exe -m kmg_agent scan --repo $Repo --output $runDirectory --env-file .env
$scanCode = $LASTEXITCODE
Write-Host "Artifacts: $runDirectory"
exit $scanCode
