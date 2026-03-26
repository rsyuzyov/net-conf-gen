@echo off
setlocal

py -3 -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt pytest

echo.
echo Installation complete.
echo Activate later with:
echo   .venv\Scripts\activate.bat
