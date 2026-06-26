@echo off
mountvol S: /S >nul 2>&1
explorer S:\EFI\refind\backups
pause
