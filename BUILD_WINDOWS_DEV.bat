@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
%PY% -m pip install -r requirements-build-windows.txt
if errorlevel 1 exit /b 1
%PY% build_desktop.py --edition dev
exit /b %errorlevel%
