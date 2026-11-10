param([ValidateSet('aio','dev','security')][string]$Edition = 'aio')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
Write-Host "CyberForge v1.8.6 Windows Portable Builder ($Edition)" -ForegroundColor Cyan
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) { $python = 'py'; $prefix = @('-3') } else { $python = 'python'; $prefix = @() }
& $python @prefix -m pip install -r requirements-build-windows.txt
if ($LASTEXITCODE -ne 0) { throw 'Build requirements installation failed' }
& $python @prefix build_desktop.py --edition $Edition
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }
