# SecretoBoot V9

**SecretoBoot V9** is a Windows boot manager for compatible **UEFI** PCs that can detect and manage supported Windows, Android-x86/Bliss OS, and Linux installations through a branded rEFInd-based boot menu.

Developed by **Mohamed LALAH / SecretoTools**  
Website: **secretotools.com**

[English](docs/README_EN.md) · [Français](docs/README_FR.md) · [العربية](docs/README_AR.md)

## Highlights

- Automatic system scan for supported Windows / Android / Linux installations
- Dynamic dashboard: only recognized OS families are shown on the main screen
- Unknown or stale candidates stay in **Advanced Diagnostics** instead of cluttering the dashboard
- One-time **Test Next Restart** before making SecretoBoot persistent
- Persistent SecretoBoot default mode with Windows remaining the automatic selection inside the menu
- 10-second Windows default timeout inside SecretoBoot
- Windows-First Compatibility mode for firmware that keeps restoring Windows Boot Manager first
- Recovery and uninstall tools under **Advanced / Recovery**
- Bundled rEFInd 0.14.2 with SecretoBoot branding

## Important compatibility note

SecretoBoot is **not claimed to work on every PC**. It is designed for compatible x64 UEFI Windows systems. Firmware implementations vary between manufacturers. If SecretoBoot cannot safely validate a firmware/storage layout, it is designed to stop without applying an unverified change.

## Quick start

For end users, download the ready-to-run ZIP from **GitHub Releases**, extract it to a local folder, run `SecretoBoot.exe`, then follow the guided sequence:

`Scan Systems → Install SecretoBoot → Test Next Restart → Make SecretoBoot Default → Windows-First Compatibility (only if offered)`

Do not run random EFI or BCDEdit commands from tutorials while SecretoBoot is managing the boot configuration.

## Repository layout

- `src/ui/` — Windows Forms UI source
- `runtime/` — verified SecretoBoot runtime, discovery, deployment, rEFInd and theme assets
- `build/` — Windows build/release scripts
- `docs/` — user documentation in English, French and Arabic
- `tools/` — emergency recovery utility

## Building from source

On Windows 10/11 with .NET Framework 4.x installed, run:

`build\BUILD_RELEASE.cmd`

The build process creates a clean package under `dist\SecretoBoot_V9\` and a ZIP release asset. The build step itself does not change EFI, BCD, NVRAM or BootOrder.

## Legal

See [NOTICE](NOTICE.md), [COPYRIGHT](COPYRIGHT.md), [DISCLAIMER](DISCLAIMER.md), and [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES.md).
