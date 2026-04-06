@echo off
REM Build PGP Vault Mobile Client
REM Requires: Python 3.9+ with pip installed, Flutter SDK (for Android APK)
REM
REM Usage:
REM   tools\build-mobile.bat desktop   — desktop Windows EXE (includes CA cert)
REM   tools\build-mobile.bat android  — Android APK (requires Flutter SDK)
REM
REM NOTE: This script is for the thin-client Flet app that connects to the
REM desktop Flask server. For a standalone APK with on-device PGP crypto
REM (pgpy, no GPG needed), see the Phase 4 plan in README.md.
REM
REM Flutter installation (once):
REM   1. Download Flutter SDK from https://flutter.dev
REM   2. Add flutter\bin to your PATH
REM   3. Run: flutter doctor
REM   4. Run: flutter config --enable-android
REM   5. Accept Android licenses: flutter doctor --android-licenses

set FLUTTER=
where flutter >nul 2>&1 && set FLUTTER=1

REM ─── Desktop Windows EXE ───────────────────────────────────────────────────
if "%1"=="desktop" (
    echo [1/2] Installing Flet dependencies...
    python -m pip install flet httpx --quiet

    echo [2/2] Building Flet desktop app with bundled CA cert...
    cd pgp_mobile
    flet pack main.py --add-data "..\pgpvault-ca.crt;." --add-data "lib;lib" --product-name "PGP Vault" --company-name "EchoVault" --distpath ..\mobile_dist -y
    if errorlevel 1 (
        echo Build failed. Check errors above.
        pause
        exit /b 1
    )
    echo.
    echo Build complete: mobile_dist\main.exe
    echo CA cert is bundled — the app will trust your self-signed server cert.
    echo.
    pause
    exit /b 0
)

REM ─── Android APK ───────────────────────────────────────────────────────────
if not defined FLUTTER (
    echo ERROR: Flutter SDK not found in PATH.
    echo Install Flutter from https://flutter.dev and add flutter\bin to your PATH.
    echo.
    echo For desktop EXE only: run: tools\build-mobile.bat desktop
    echo.
    pause
    exit /b 1
)

if not "%1"=="android" (
    echo.
    echo Usage:
    echo   tools\build-mobile.bat desktop  — desktop Windows EXE
    echo   tools\build-mobile.bat android — Android APK ^(requires Flutter SDK^)
    echo.
    pause
    exit /b 0
)

echo [1/1] Building Android APK with Flutter...
REM Bundle CA cert as a Flutter asset
if exist "..\pgpvault-ca.crt" (
    if not exist "assets" mkdir assets
    copy /Y "..\pgpvault-ca.crt" "assets\pgpvault-ca.crt" >nul
)
flutter build apk --release
if errorlevel 1 (
    echo Android APK build failed.
    pause
    exit /b 1
)
echo.
echo Android APK: build\app\outputs\flutter-apk\app-release.apk
echo.
echo After installing the APK on Android:
echo   1. Install pgpvault-ca.crt as a trusted CA on your device:
echo      - Copy assets\pgpvault-ca.crt to your Android device
echo      - Settings ^> Security ^> Encryption ^> Trusted credentials ^> Install from storage
echo   2. Start the Flask server on your desktop
echo   3. In the PGP Vault app: enter server URL and auth token
echo.
pause
