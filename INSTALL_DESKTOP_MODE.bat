@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -m pip install -r requirements-desktop.txt
) else (
  python -m pip install -r requirements-desktop.txt
)
if errorlevel 1 (
  echo Desktop mode installation failed. Browser mode remains available.
  pause
  exit /b 1
)
echo Native desktop mode installed. Start CyberForge with START_WINDOWS.bat.
pause
