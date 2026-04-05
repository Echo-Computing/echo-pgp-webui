@echo off
REM Build PGP Vault Mobile Client (Desktop EXE)
REM Requires: Python 3.9+ with pip installed, Flutter SDK (for Android APK)
REM
REM Usage:
REM   tools\build-mobile.bat          — desktop Windows EXE (no Flutter needed)
REM   tools\build-mobile.bat android  — Android APK (requires Flutter SDK)
REM
REM Note: Android APK build requires:
REM   1. Flutter SDK installed and in PATH (run: flutter doctor)
REM   2. Android SDK configured (run: flutter doctor --android-licenses)
REM   3. Run: flutter config --enable-android

set FLUTTER=
where flutter >nul 2>&1 && set FLUTTER=1

REM ─── Desktop Windows EXE ───────────────────────────────────────────────────
echo [1/2] Installing Flet dependencies...
python -m pip install flet httpx --quiet

echo [2/2] Building Flet desktop app...
python -m pip install flet-cli --quiet
cd pgp_mobile
flet pack main.py --add-data "lib:lib" --product-name "PGP Vault" --company-name "EchoVault" --distpath ../mobile_dist -y

if errorlevel 1 (
    echo Build failed. Check errors above.
    pause
    exit /b 1
)

echo.
echo Build complete: mobile_dist\main.exe
echo.

REM ─── Android APK (only if Flutter is available) ───────────────────────────
if not defined FLUTTER (
    echo.
    echo NOTE: Flutter not found. Android APK cannot be built.
    echo Install Flutter from https://flutter.dev to build Android APK.
    echo.
    echo To build Android APK once Flutter is installed:
    echo   flutter build apk --release
    echo.
    pause
    exit /b 0
)

if "%1"=="android" (
    echo.
    echo [Bonus] Building Android APK with Flutter...
    flutter build apk --release
    if errorlevel 1 (
        echo Android APK build failed.
        pause
        exit /b 1
    )
    echo Android APK: build\app\outputs\flutter-apk\app-release.apk
)
