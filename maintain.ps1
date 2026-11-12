param(
    [ValidateSet('doctor','setup','rebuild','pack','capture')][string]$Action = 'doctor',
    [string]$Profile = 'muyu-os4.0.3.0',
    [string]$Artifact,
    [string]$Python,
    [string]$Adb = 'D:\platform-tools\adb.exe'
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$settingsPath = Join-Path $PSScriptRoot '.local/settings.json'
$venvPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not $Python -and (Test-Path -LiteralPath $settingsPath)) {
    $Python = (Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json).python
}
if ($Action -eq 'setup') {
    if (-not $Python) {
        $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if ($pythonCommand -and $pythonCommand.Source -notmatch 'Microsoft\\WindowsApps\\python.exe$') { $Python = $pythonCommand.Source }
    }
    if (-not $Python) { throw 'Install Python 3.12 or specify -Python with the full interpreter path.' }
    $priorTemp = $env:TEMP
    $priorTmp = $env:TMP
    try {
        $projectTemp = Join-Path $PSScriptRoot '.local/tmp'
        New-Item -ItemType Directory -Path $projectTemp -Force | Out-Null
        $env:TEMP = $projectTemp
        $env:TMP = $projectTemp
        & $Python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the project Python environment.' }
        & $venvPython -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    } finally {
        $env:TEMP = $priorTemp
        $env:TMP = $priorTmp
    }
    New-Item -ItemType Directory -Path .local -Force | Out-Null
    @{ python = $Python } | ConvertTo-Json | Set-Content -LiteralPath $settingsPath -Encoding utf8
    $Action = 'doctor'
}
if (-not (Test-Path -LiteralPath $venvPython)) { throw 'Run .\maintain.ps1 setup -Python <python.exe> once before using this entry point.' }
$arguments = @('tools/maintain.py','--profile',$Profile,$Action)
if ($Action -eq 'pack') {
    if (-not $Artifact) { throw 'Specify -Artifact with the downloaded build artifact directory.' }
    $arguments += @('--artifact',$Artifact)
}
if ($Action -eq 'capture') { $arguments += @('--adb',$Adb) }
& $venvPython @arguments
if ($LASTEXITCODE -ne 0) { throw 'The operation stopped. See the error above; no device partitions were written.' }
