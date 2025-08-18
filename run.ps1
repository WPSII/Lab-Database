# run.ps1 - One-shot launcher for Windows PowerShell (5.1+)
# - Creates a venv if missing
# - Quietly checks/installs dependencies with a minimal checklist
# - Runs app.py using the venv's python (no activation needed)

param(
    [string]$VenvDir = "venv",
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

function Ensure-Venv {
    $venvPyPath = Join-Path $VenvDir "Scripts/python.exe"
    if (-not (Test-Path -Path $venvPyPath)) {
        Write-Host ("Creating virtual environment in '{0}'..." -f $VenvDir)
        try {
            py -3 -m venv $VenvDir
        } catch {
            python -m venv $VenvDir
        }
    } else {
        Write-Host ("Virtual environment found at '{0}'." -f $VenvDir)
    }
}

function Upgrade-Pip {
    $venvPy = Join-Path $VenvDir "Scripts/python.exe"
    Write-Host "Upgrading pip (quiet)..."
    & $venvPy -m pip install --upgrade pip *> $null
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

function Install-Requirements-Checklist {
    $venvPy = Join-Path $VenvDir "Scripts/python.exe"

    if (-not (Test-Path -Path "requirements.txt")) {
        Write-Host "No requirements.txt found; skipping dependency check."
        return
    }

    Write-Host "Checking dependencies..."
    $lines = Get-Content "requirements.txt"

    foreach ($raw in $lines) {
        $info = Get-ModuleNameFromRequirement $raw
        if ($null -eq $info) { continue }

        $req    = $info.Requirement
        $module = $info.Module

        # Try import in the venv
        & $venvPy -c "import $module" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host ('[OK] {0}' -f $req)
            continue
        }

        Write-Host ('[..] {0} (installing...)' -f $req)
        & $venvPy -m pip install $req *> $null

        # Re-check
        & $venvPy -c "import $module" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host ('[OK] {0} (now installed)' -f $req)
        } else {
            Write-Host ('[!!] {0} (install failed)' -f $req)
            throw ('Failed to install requirement: {0}' -f $req)
        }
    }
}

function Run-App {
    $venvPy = Join-Path $VenvDir "Scripts/python.exe"
    $args = @("app.py", "--host=$BindHost", "--port=$Port")
    Write-Host ("Starting app: {0} {1}" -f $venvPy, ($args -join ' '))
    & $venvPy @args
}

Ensure-Venv
Upgrade-Pip
Install-Requirements-Checklist
Run-App
