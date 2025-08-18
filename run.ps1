# run.ps1 - One-shot launcher for Windows PowerShell
# - Creates a venv if missing
# - Installs/updates requirements
# - Runs app.py using the venv's python (no activation needed)

param(
    [string]$VenvDir = "venv",
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

function Ensure-Venv {
    if (-not (Test-Path -Path (Join-Path $VenvDir "Scripts/python.exe"))) {
        Write-Host "Creating virtual environment in '$VenvDir'..."
        try {
            py -3 -m venv $VenvDir
        } catch {
            python -m venv $VenvDir
        }
    } else {
        Write-Host "Virtual environment found at '$VenvDir'."
    }
}

function Install-Requirements {
    $venvPy = Join-Path $VenvDir "Scripts/python.exe"
    if (Test-Path -Path $venvPy) {
        & $venvPy -m pip install --upgrade pip
        if (Test-Path -Path "requirements.txt") {
            Write-Host "Installing dependencies from requirements.txt..."
            & $venvPy -m pip install -r requirements.txt
        } else {
            Write-Host "No requirements.txt found; skipping."
        }
    } else {
        throw "Could not find venv python at $venvPy"
    }
}

function Run-App {
    $venvPy = Join-Path $VenvDir "Scripts/python.exe"
    $args = @("app.py", "--host=$BindHost", "--port=$Port")
    Write-Host "Starting app: $venvPy $($args -join ' ')"
    & $venvPy @args
}

Ensure-Venv
Install-Requirements
Run-App
