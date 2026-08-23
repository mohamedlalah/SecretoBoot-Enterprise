# Release checklist

Before publishing a GitHub Release:

1. Build the package on Windows with `BUILD_RELEASE.cmd`.
2. Extract the generated ZIP into a fresh folder.
3. Run `SecretoBoot.exe` and complete one real-machine validation cycle:
   - Scan Systems
   - Install SecretoBoot
   - Test Next Restart
   - Make SecretoBoot Default
   - Restart normally
   - Enable Windows-First Compatibility only if SecretoBoot offers it
   - Verify Windows, Android/Bliss and Linux entries that exist on the test PC
4. Verify a second normal restart still opens SecretoBoot.
5. Verify the SHA-256 file matches the ZIP.
6. Publish the ZIP and `.sha256` file under GitHub Releases.

Do not publish a release that has only been compiled but not real-machine tested.
