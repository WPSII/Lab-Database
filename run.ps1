# run.ps1 - Minimal launcher for Windows PowerShell (5.1+)
# - Creates venv if missing
# - Installs deps from requirements (quiet)
# - Only prints pip logs on failure (and saves them to pip_install_error.log)
# - Launches app.py

param(
    [string]$VenvDir = "venv",
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 5000,
    # Optional override path to requirements
    [string]$Requirements = "",
    # Set this if you want to see full pip logs
    [switch]$ShowPip
)

$ErrorActionPreference = "Stop"
$here = Get-Location
$logFile = Join-Path $here "pip_install_error.log"
$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"

function Ensure-Venv {
    $venvPyPath = Join-Path $VenvDir "Scripts/python.exe"
    if (-not (Test-Path -Path $venvPyPath)) {
        Write-Host "venv: creating..."
        try { py -3 -m venv $VenvDir } catch { python -m venv $VenvDir }
        Write-Host "venv: created" -ForegroundColor Green
    } else {
        Write-Host "venv: ok" -ForegroundColor Green
    }
}

function Resolve-RequirementsPath {
    param([string]$Override)
    if ($Override -and (Test-Path -Path $Override)) { return $Override }
    foreach ($c in @("requirements.txt","requirements/requirements.txt","requirements-lock.txt")) {
        if (Test-Path -Path $c) { return $c }
    }
    return $null
}

function Upgrade-Pip-Quiet {
    param([string]$venvPy)
    # keep this silent unless debug requested
    if ($ShowPip) {
        & $venvPy -m pip install --upgrade pip
    } else {
        & $venvPy -m pip install --upgrade pip --quiet *> $null
    }
}

function Install-Requirements-Quiet {
    param(
        [string]$venvPy,
        [string]$reqFile
    )

    if (-not $reqFile -or -not (Test-Path -Path $reqFile)) {
        Write-Host "deps: skipped (no requirements file)"
        return
    }

    $count = (Get-Content $reqFile | Where-Object { $_ -and ($_ -notmatch '^\s*#') }).Count

    if ($ShowPip) {
        Write-Host "deps: installing from $reqFile..."
        & $venvPy -m pip install --disable-pip-version-check -r $reqFile
        if ($LASTEXITCODE -ne 0) { throw "pip failed (see console output)" }
        Write-Host ("deps: ok ({0} item{1})" -f $count, $(if($count -ne 1){"s"}else{""})) -ForegroundColor Green
        return
    }

    # Quiet attempt (no stdout/stderr)
    & $venvPy -m pip install --disable-pip-version-check -r $reqFile --quiet *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host ("deps: ok ({0} item{1})" -f $count, $(if($count -ne 1){"s"}else{""})) -ForegroundColor Green
        return
    }

    # On failure, re-run noisily and save logs
    Write-Host "deps: failed (showing pip output)..."
    try { Remove-Item $logFile -ErrorAction SilentlyContinue } catch {}
    (& $venvPy -m pip install --disable-pip-version-check -r $reqFile *>&1) | Tee-Object -FilePath $logFile
    throw ("pip failed, see log: {0}" -f $logFile)
}

# ---- Main ----
Ensure-Venv

$venvPy = Join-Path $VenvDir "Scripts/python.exe"

Upgrade-Pip-Quiet -venvPy $venvPy

$reqFile = Resolve-RequirementsPath -Override $Requirements
Install-Requirements-Quiet -venvPy $venvPy -reqFile $reqFile

Write-Host ("start: http://{0}:{1}" -f $BindHost, $Port)
& $venvPy app.py --host $BindHost --port $Port
