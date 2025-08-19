# run.ps1 - One-shot launcher for Windows PowerShell (5.1+)
# - Creates a venv if missing
# - Checks/installs dependencies with a minimal checklist
# - Shows pip details only when an install fails
# - Runs app.py using the venv's python

param(
    [string]$VenvDir = "venv",
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 5000,
    # Optional override if your requirements file lives elsewhere
    [string]$Requirements = ""
)

$ErrorActionPreference = "Stop"

function Ensure-Venv {
    $venvPyPath = Join-Path $VenvDir "Scripts/python.exe"
    if (-not (Test-Path -Path $venvPyPath)) {
        Write-Host ("Creating virtual environment in '{0}'..." -f $VenvDir)
        try { py -3 -m venv $VenvDir } catch { python -m venv $VenvDir }
    } else {
        Write-Host ("Virtual environment found at '{0}'." -f $VenvDir)
    }
}

function Upgrade-Pip {
    $venvPy = Join-Path $VenvDir "Scripts/python.exe"
    Write-Host "Upgrading pip (quiet)..."
    & $venvPy -m pip install --upgrade pip --quiet *> $null
}

function Resolve-RequirementsPath {
    param([string]$Override)
    if ($Override -and (Test-Path -Path $Override)) { return $Override }

    $candidates = @(
        "requirements.txt",              # dev portable
        "requirements/requirements.txt", # alt dev location
        "requirements-lock.txt"          # pinned freeze
    )
    foreach ($c in $candidates) {
        if (Test-Path -Path $c) { return $c }
    }
    return $null
}


function Get-ModuleNameFromRequirement([string]$req) {
    # Strip comments and whitespace
    $line = ($req -replace '\s*#.*','').Trim()
    if (-not $line) { return $null }

    # Remove version specifiers and extras
    $name = $line -replace '([=><!~]{1,2}).*$',''
    $name = $name -replace '\[.*\]',''

    # Normalize import name: '-' -> '_', lowercase
    $module = ($name -replace '-','_').ToLower().Trim()
    if (-not $module) { return $null }

    return [PSCustomObject]@{
        Requirement = $line
        Module      = $module
    }
}

function Test-PythonModule {
    param(
        [string]$PythonExe,
        [string]$ModuleName
    )
    # Return $true if importable, $false otherwise; never throw.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $PythonExe -c "import importlib,sys; sys.exit(0) if importlib.util.find_spec('$ModuleName') else sys.exit(1)" *> $null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    return ($code -eq 0)
}

function Install-Requirements-Checklist {
    param(
        [string]$venvPy,
        [string]$reqFile
    )

    if (-not $reqFile -or -not (Test-Path -Path $reqFile)) {
        Write-Host "No requirements file found; skipping dependency check."
        return
    }

    Write-Host ("Checking dependencies from {0}..." -f $reqFile)
    $lines = Get-Content $reqFile | Where-Object { $_ -and ($_ -notmatch '^\s*#') }

    foreach ($req in $lines) {
        $parsed = Get-ModuleNameFromRequirement $req
        if (-not $parsed) { continue }

        $module = $parsed.Module
        $requirement = $parsed.Requirement

        if (Test-PythonModule -PythonExe $venvPy -ModuleName $module) {
            Write-Host ("[OK] {0}" -f $requirement) -ForegroundColor Green
        } else {
            Write-Host ("[..] {0} (installing...)" -f $requirement) -ForegroundColor Yellow
            try {
                & $venvPy -m pip install $requirement
                if ($LASTEXITCODE -eq 0 -and (Test-PythonModule -PythonExe $venvPy -ModuleName $module)) {
                    Write-Host ("[OK] {0}" -f $requirement) -ForegroundColor Green
                } else {
                    Write-Host ("[!!] {0} (install failed)" -f $requirement) -ForegroundColor Red
                }
            } catch {
                Write-Host ("[!!] {0} (error: {1})" -f $requirement, $_.Exception.Message) -ForegroundColor Red
            }
        }
    }
}

# --- Main Execution ---

# 1. Ensure venv exists
Ensure-Venv

# 2. Path to venv's python
$venvPy = Join-Path $VenvDir "Scripts/python.exe"

# 3. Upgrade pip quietly
Upgrade-Pip

# 4. Resolve requirements and install/check them
$reqFile = Resolve-RequirementsPath -Override $Requirements
Install-Requirements-Checklist -venvPy $venvPy -reqFile $reqFile

# 5. Finally, run your app
Write-Host "Launching app.py..."
& $venvPy app.py --host $BindHost --port $Port
