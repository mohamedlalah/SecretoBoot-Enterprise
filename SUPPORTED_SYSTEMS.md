# Supported systems and detection model

SecretoBoot V9 is designed for compatible **x64 UEFI Windows PCs**.

## Recognized OS families

The main dashboard currently recognizes and presents:

- Windows
- Android-x86 / Bliss OS style installations when a supported boot target is validated
- Linux EFI installations when a supported loader is detected

The dashboard is dynamic. It does not reserve a fixed number of OS cards. Unknown or stale candidates are kept out of the main dashboard and remain available through Advanced Diagnostics.

## Firmware compatibility

UEFI firmware behavior differs across manufacturers and models. SecretoBoot includes a Windows-First Compatibility workflow for systems that repeatedly restore Windows Boot Manager as the first boot target.

Legacy BIOS-only systems are not the target platform.

## Safety behavior

If required firmware, storage, ownership, loader, Secure Boot, BitLocker, or identity checks cannot be validated, SecretoBoot is designed to stop the requested boot-management operation rather than report unverified success.
