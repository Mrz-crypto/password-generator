@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if not errorlevel 1 (
    python password_generator.py
    exit /b %errorlevel%
)

where py >nul 2>nul
if not errorlevel 1 (
    py password_generator.py
    exit /b %errorlevel%
)

if errorlevel 1 (
    echo Python is required to run this password generator.
    echo Download Python from https://www.python.org/downloads/
    echo During install, check "Add python.exe to PATH".
    echo.
    pause
    exit /b 1
)
