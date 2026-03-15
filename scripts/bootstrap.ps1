$ErrorActionPreference = "Stop"

$PythonBin = $env:PYTHON_BIN
if ([string]::IsNullOrWhiteSpace($PythonBin)) {
  $PythonBin = "py -3.11"
}

Invoke-Expression "$PythonBin -m venv .venv"
& .venv\Scripts\python.exe -m pip install --upgrade pip
& .venv\Scripts\python.exe -m pip install -e ".[dev]"

Write-Host ""
Write-Host "Driftwatch bootstrap complete."
Write-Host "Next steps:"
Write-Host "  .venv\Scripts\Activate.ps1"
Write-Host "  driftwatch serve --demo-data"
