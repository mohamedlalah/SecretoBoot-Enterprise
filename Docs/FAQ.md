# FAQ

## Why do duplicate entries appear?

SecretoBoot uses `scanfor manual` to avoid automatic duplicate entries.

## Why does the Google TV icon not appear?

The Google TV icon must be copied to the BOOT partition. The installer attempts to do this automatically.

## Can I restore the old configuration?

Yes. Use:

```text
Scripts\Open_Backups.cmd
```

and restore the previous `refind.conf`.

## Is this a replacement for rEFInd?

No. SecretoBoot is a professional theme and configuration layer for rEFInd.
