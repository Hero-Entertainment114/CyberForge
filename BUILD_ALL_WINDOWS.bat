@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
%PY% -m pip install -r requirements-build-windows.txt
if errorlevel 1 goto :failed
%PY% build_desktop.py --edition aio
if errorlevel 1 goto :failed
%PY% build_desktop.py --edition dev
if errorlevel 1 goto :failed
%PY% build_desktop.py --edition security
if errorlevel 1 goto :failed
echo All three CyberForge v1.8.6 editions were built.
echo See dist\CyberForge-AIO, dist\CyberForge-Dev and dist\CyberForge-Security.
pause
exit /b 0
:failed
echo BUILD FAILED. Review the error above.
pause
exit /b 1
