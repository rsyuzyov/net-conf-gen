@echo off
setlocal

if exist ".venv\Scripts\python.exe" (
    echo Reusing existing .venv
    goto :activate
)

where py >nul 2>nul
if not errorlevel 1 (
    set "PYTHON_BOOTSTRAP=py -3"
    goto :create
)

where python >nul 2>nul
if not errorlevel 1 (
    set "PYTHON_BOOTSTRAP=python"
    goto :create
)

echo Python was not found in PATH.
echo Install Python 3.11+ and re-run this script.
exit /b 1

:create
%PYTHON_BOOTSTRAP% -m venv .venv
if errorlevel 1 (
    echo Failed to create virtual environment.
    exit /b 1
)

:activate
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt pytest

echo.
echo Installation complete.
echo Activate later with:
echo   .venv\Scripts\activate.bat
