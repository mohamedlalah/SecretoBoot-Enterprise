@echo off
setlocal
cd /d "%~dp0\.."
PowerShell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build-Release.ps1"
if errorlevel 1 (
  echo.
  echo Build failed. No boot settings were changed.
  pause
  exit /b 1
)
echo.
pause
endlocal
