# Security policy

Win Startup Manager changes persistence mechanisms, so correctness and least privilege are security requirements rather than optional polish.

## Supported versions

Until a stable release exists, security fixes are applied to the latest `main` branch. After 1.0, the latest minor release will receive security fixes.

## Reporting a vulnerability

Please do not open a public issue for vulnerabilities that could enable privilege escalation, arbitrary registry/file writes, command execution, recovery-journal tampering, or unsafe service changes.

Use GitHub's **Report a vulnerability** / private Security Advisory flow for this repository. Include:

- affected commit or release;
- Windows edition and build;
- required privileges;
- exact source locator and preconditions;
- minimal reproduction steps;
- expected security boundary and observed behavior.

Do not include personal startup commands, usernames, or tokens unless they are essential; redact them where possible.

## Security boundaries

- Scanning is read-only and never executes a discovered command.
- The app starts with the current user's token and requests UAC only after an explicit action.
- Entry locators are structured data, never shell command strings.
- Mutations re-read and fingerprint the source before applying a change.
- Current-user registry bytes/types and file locations are preserved in an atomic local journal.
- Journal provenance is recomputed, and user-writable receipts never authorize elevated HKLM or common-Startup writes; those sources are read-only in v0.1.
- Restore operations fail closed on conflicts.
- Microsoft/Windows components and mixed-trigger tasks are read-only by default.
- Service prevention means `SERVICE_DEMAND_START`, not `SERVICE_DISABLED`; running services are not stopped.

The local user controls the recovery journal. Per-user restores still fail closed on path, identity, fingerprint, and destination conflicts. The journal is not a trust anchor and is not designed to protect data from a process already executing as the same user or as administrator.
