@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ================================================
echo CyberForge AIO v1.8.6 - Windows Portable Builder
echo ================================================
where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
%PY% -m pip install -r requirements-build-windows.txt
if errorlevel 1 goto :failed
%PY% build_desktop.py
if errorlevel 1 goto :failed
pause
exit /b 0
:failed
echo BUILD FAILED. Review the error above.
pause
exit /b 1
