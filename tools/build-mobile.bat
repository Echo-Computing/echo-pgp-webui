@echo off
REM Build PGP Vault Mobile Client (Android APK)
REM Requires: Python 3.9+ with pip installed, Flutter SDK
REM
REM Usage:
REM   tools\build-mobile.bat          — desktop Windows EXE (no Flutter needed)
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

REM ─── Android APK ───────────────────────────────────────────────────────────
if not defined FLUTTER (
    echo ERROR: Flutter SDK not found in PATH.
    echo Install Flutter from https://flutter.dev and add flutter\bin to your PATH.
    echo.
    echo For desktop-only (no Flutter needed): ignore this error.
    echo.
    pause
    exit /b 1
)

if not "%1"=="android" (
    echo.
    echo Usage: build-mobile.bat android
    echo.
    echo This builds the Android APK. Flutter SDK required.
    echo Run: flutter doctor to check your Flutter setup.
    echo.
    pause
    exit /b 0
)

echo [1/1] Building Android APK with Flutter...
flutter build apk --release
if errorlevel 1 (
    echo Android APK build failed.
    pause
    exit /b 1
)
echo.
echo Android APK: build\app\outputs\flutter-apk\app-release.apk
echo.
pause
