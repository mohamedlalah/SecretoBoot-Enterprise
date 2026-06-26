@echo off
title SecretoBoot Enterprise v7.1 FINAL RELEASE Installer
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Apply_SecretoBoot_Enterprise_v7_1.ps1"
echo.
pause
