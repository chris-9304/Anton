@echo off
:: Windows-only. On macOS, see build_and_install.sh instead.
setlocal
title Anton - Build and Install

echo.
echo === Anton: Build and Install ===
echo.

REM 1. Build release (anton + demo_ransomware for demo)
echo [1/2] Running: cargo build --release
echo.
cargo build --release
if errorlevel 1 (
    echo.
    echo BUILD FAILED. Check errors above.
    pause
    exit /b 1
)

echo.
echo Build succeeded.
echo.

REM 2. Deploy desktop shortcut
echo [2/2] Creating desktop shortcut...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy_shortcut.ps1"
if errorlevel 1 (
    echo.
    echo Shortcut creation failed or release binary not found.
    pause
    exit /b 1
)

echo.
echo === Done ===
echo You should see "Anton Anti-Ransomware" on your Desktop.
echo Double-click it to run Anton (with Run as Administrator).
echo.
pause
