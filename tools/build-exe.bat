@echo off
REM Build PGP Vault Desktop EXE
REM Requires: Python 3.9+ with pip installed
REM
REM Usage: tools\build-exe.bat

echo [1/2] Installing dependencies...
python -m pip install flask flask-cors zeroconf pyinstaller --quiet

echo [2/2] Building EXE with PyInstaller...
python -m PyInstaller desktop\pgpvault.spec --clean

echo.
echo Build complete: desktop\dist\pgpvault.exe
echo.
pause
