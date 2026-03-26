@echo off
setlocal

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PYTHON_BOOTSTRAP=py -3"
) else (
    where python >nul 2>nul
    if %ERRORLEVEL% EQU 0 (
        set "PYTHON_BOOTSTRAP=python"
    ) else (
        echo Python was not found in PATH.
        echo Install Python 3.11+ and re-run this script.
        exit /b 1
    )
)

%PYTHON_BOOTSTRAP% -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt pytest

echo.
echo Installation complete.
echo Activate later with:
echo   .venv\Scripts\activate.bat
