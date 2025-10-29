@echo off
REM === Auto Git Push Script ===
REM Run this file from within your Cloud-Security folder

echo.
echo ==============================================
echo     Pushing project to GitHub...
echo ==============================================
echo.

REM Navigate to the folder where the script is located
cd /d "%~dp0"

REM Ensure Git is available
git --version >nul 2>&1
if errorlevel 1 (
    echo Git is not installed or not in PATH. Install Git and try again.
    pause
    exit /b
)

REM Stage all changes
git add -A

REM Create a timestamp for commit message
for /f "tokens=1-4 delims=/ " %%a in ("%date%") do (
    set day=%%a
    set month=%%b
    set year=%%c
)
for /f "tokens=1-2 delims=: " %%a in ("%time%") do (
    set hour=%%a
    set minute=%%b
)
set timestamp=%year%-%month%-%day%_%hour%-%minute%

REM Commit the changes
git commit -m "Auto update - %timestamp%"

REM Push to GitHub
git push origin main

echo.
echo ==============================================
echo     ✅ Push Complete!
echo ==============================================
echo.
pause
