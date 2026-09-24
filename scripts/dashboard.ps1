param(
    [string]$GitHubRepo = '',
    [int]$Port = 8765
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
$cliArgs = @('-m', 'kmg_agent', 'dashboard', '--reports', 'reports', '--repo',
             'targets/KMG-Digital-Hackathon', '--port', "$Port")
if ($GitHubRepo) { $cliArgs += @('--github-repo', $GitHubRepo) }
& $python @cliArgs
exit $LASTEXITCODE
