# SecretoBoot Enterprise v7.1 Stable

Stable SecretoBoot Enterprise release for **Windows 11** and **Google TV OS** dual boot using rEFInd.

## Features

- Professional Secretofnet interface.
- Manual entries only.
- No duplicate Windows/Google TV entries.
- Google TV icon fix.
- Automatic `refind.conf` backup.
- One-click installer.
- Diagnostic and restore tools.

## Installation

1. Extract the ZIP file.
2. Open the `Scripts` folder.
3. Right-click:
   `Install_SecretoBoot_Enterprise_v7_1.cmd`
4. Choose **Run as administrator**.
5. Reboot.

## Requirements

- UEFI device.
- rEFInd already installed.
- Windows 11.
- Google TV partition named `BOOT`.
- Existing loader:
  `EFI\BOOT\BOOTx64.EFI`

## Restore

Open:

`Scripts\Open_Backups.cmd`

Then restore the correct `refind.conf` backup.

© 2026 Secretofnet - All rights reserved.
