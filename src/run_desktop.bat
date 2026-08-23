@echo off
rem RedHawk Desktop Launcher (ASCII-safe)
cd /d "%~dp0"

rem --- check python ---
where python >nul 2>nul
if errorlevel 1 (
    echo [X] Python not found. Install Python 3.10+ first.
    pause
    exit /b 1
)

rem --- check deps ---
python -c "import webview, fastapi, uvicorn" >nul 2>nul
if errorlevel 1 (
    echo [*] Installing desktop dependencies...
    pip install pywebview fastapi uvicorn -q
)

rem --- install package editable ---
pip install -e . -q >nul 2>nul

rem --- kill stale processes on our ports first ---
python -c "import sys; sys.path.insert(0, '.'); from redhawk.cleanup import cleanup; print('cleanup:', cleanup())" >nul 2>nul

echo [*] Starting RedHawk Desktop...
python -m redhawk.desktop
