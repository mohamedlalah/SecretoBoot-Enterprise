@echo off
net session >nul 2>&1 || (echo Run this file as Administrator.& pause & exit /b 1)
bcdedit /set {bootmgr} path \EFI\Microsoft\Boot\bootmgfw.efi
bcdedit /enum {bootmgr}
pause
