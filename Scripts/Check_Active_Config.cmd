@echo off
title SecretoBoot v7.1 Diagnostic
mountvol S: /S >nul 2>&1
echo ===== ACTIVE REFIND CONFIG =====
findstr /i "scanfor include menuentry icon loader volume" S:\EFI\refind\refind.conf
echo.
echo ===== THEME CONFIG =====
type S:\EFI\refind\themes\SecretoBootV7_1\theme.conf
echo.
echo ===== GOOGLE TV ICON ON BOOT VOLUME =====
for %%d in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist %%d:\EFI\BOOT\BOOTx64.EFI (
  echo Found BOOTX64 on %%d:
  dir %%d:\EFI\BOOT\secreto_os_google_tv.png
)
pause
