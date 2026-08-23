# SecretoBoot V9 — English Guide

## What SecretoBoot does

SecretoBoot provides a simple Windows interface for discovering supported installed operating systems and deploying a branded rEFInd-based UEFI boot menu.

The main dashboard can show Windows, Android/Bliss OS and Linux entries detected on the current machine. The number of cards is dynamic: if two supported systems are found, two cards are shown; if four supported systems are found, four cards are shown. Unknown or stale candidates are kept in Advanced Diagnostics.

## Requirements

- Windows 10 or Windows 11, x64
- UEFI boot mode
- Administrator approval when SecretoBoot asks for it
- Secure Boot must not block the bundled rEFInd loader; SecretoBoot safety checks may stop the operation when Secure Boot is enabled or cannot be validated
- BitLocker/device-encryption protection may need to be suspended or disabled if SecretoBoot reports that the protected OS volume blocks the operation

## Recommended installation flow

1. Extract the SecretoBoot release ZIP to a new local folder.
2. Run `SecretoBoot.exe` normally. Do not force the whole app to run as Administrator.
3. Click **Scan Systems**.
4. Open **rEFInd Setup Preview** and confirm the detected targets.
5. Install SecretoBoot when the app offers the validated install action.
6. Open **Boot Manager Actions** and click **Test Next Restart**.
7. Restart and confirm that the SecretoBoot menu opens and that Windows boots correctly from it.
8. Back in Windows, scan again and click **Make SecretoBoot Default**.
9. Restart normally.
10. If your firmware restores Windows first, SecretoBoot may offer **Enable Windows-First Compatibility**. Enable it only when the app offers it.

Windows remains the automatic default selection inside SecretoBoot with a 10-second timeout.

## Advanced / Recovery

Advanced recovery actions are intentionally separated from the normal workflow. Use them only when needed. The package also includes an emergency native-Windows restore tool for controlled recovery if the normal UI recovery path cannot be used.

## Removing an operating system

After an OS is removed, run **Scan Systems** again. The main dashboard is designed to show recognized detected OS families only. Stale/unknown evidence may still appear in Advanced Diagnostics but should not be presented as a normal OS card.

## Compatibility

SecretoBoot has been real-machine tested on the development test system, but PC firmware varies significantly. Do not describe the software as universally compatible. A safer description is:

> SecretoBoot is designed for compatible UEFI Windows PCs and automatically detects supported installed operating systems. If a firmware or storage layout cannot be safely validated, SecretoBoot stops without applying an unverified change.
