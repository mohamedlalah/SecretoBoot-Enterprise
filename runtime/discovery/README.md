# SecretoBoot V9 Android Accessible-Volume MVP

Revision `Android-Initrd-Runtime-MVP.1` is a non-elevated, explicitly authorized Windows validation backend. It checks exact allowlisted Android boot-chain paths and performs bounded in-memory gzip/raw-newc initrd inspection to determine whether the validated init script proves runtime system-image discovery.

It never enumerates directories, mounts a filesystem, assigns a drive letter, inspects an ESP, writes, accesses BCD/NVRAM/Secure Boot/BootOrder, uses the network, or accesses rEFInd. Missing paths are normal. Android naming requires a system/build identity plus at least two independent boot categories; a filesystem, label, or fallback EFI loader is never sufficient.

Run `Invoke-Preflight.ps1` first. Prepare a reviewed single-session manifest with `New-DiscoveryManifest.ps1`, then pass its digest to `Invoke-AndroidAccessibleDiscovery.ps1`. Preflight performs zero inventory and zero filesystem reads.
