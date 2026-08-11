# Recovery

Normal restoration should always be performed in Win Startup Manager by opening **Prevented** and switching the entry back on.

## Where recovery data lives

```text
%LOCALAPPDATA%\WinStartupManager\Win Startup Manager\data\state.json
%LOCALAPPDATA%\WinStartupManager\Win Startup Manager\data\state.json.lock
%LOCALAPPDATA%\WinStartupManager\Win Startup Manager\data\disabled\
```

The state file is created only after the first reversible change. Writes replace it atomically. The zero-length lock file coordinates multiple app instances; it contains no recovery data and Windows releases its lock automatically if an instance crashes.

## What is preserved

- Registry: current-user key, value name, raw Windows value type, and exact bytes. Machine-wide Registry entries are read-only in v0.1.
- Startup folder: current-user original path, parked path, and a full content fingerprint. The original file itself is moved without modification and is verified again before restore. The common Startup folder is read-only in v0.1.
- Service: service name, exact original start type, delayed-auto flag, and the expected post-change fingerprint.
- Scheduled task: no recovery copy is needed because Windows preserves the definition while its supported enabled flag is changed.

## Conflict handling

The app will not restore over a newly created registry value or file. Move or remove the conflicting item yourself only after you understand why it appeared, then rescan and restore.

If a service or registry value changed after it was scanned, refresh first. A service that no longer matches either the saved original or the expected Manual state is locked rather than overwritten. Inspect `state.json` and the current Windows configuration before taking further action.

The journal is stored in user-writable LocalAppData, so it is never accepted as authority for an elevated HKLM or common-Startup restore. Receipt provenance is recomputed and only supported current-user locations are mutable.

## Uninstalling

Do not delete the data directory while entries are prevented. The recovery journal and parked files intentionally survive a portable executable being removed. Reinstall or rebuild the same/newer app version and restore entries first.

If the GUI cannot start, preserve the entire data directory before troubleshooting. Startup-folder files can be manually moved from their recorded parked path back to the recorded original path, but registry and service recovery should be done with the app or by an experienced administrator.
