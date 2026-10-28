@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto dependencies
where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)
if errorlevel 1 goto failed
:dependencies
".venv\Scripts\python.exe" -c "from importlib.metadata import version; assert version('scapy') == '2.8.0'" >nul 2>nul
if not errorlevel 1 goto run
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
:run
".venv\Scripts\python.exe" main.py --demo
if errorlevel 1 goto failed
exit /b 0
:failed
echo.
echo Setup or startup failed. Install Python 3.10 or later and follow README.md.
pause
exit /b 1
