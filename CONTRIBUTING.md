# Contributing

Thank you for helping make Windows startup behavior more transparent.

## Before you begin

- Use Windows 10 or 11 with the Rust toolchain from `rust-toolchain.toml`.
- Install Visual Studio Build Tools and a Windows SDK.
- Keep the main UI unelevated during normal development.
- Never test machine-wide registry, service, or common-Startup mutations on a primary machine. Use a disposable VM.

## Local checks

Run these before opening a pull request:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo run --example scan
cargo build --release --locked
```

`cargo run --example scan` is read-only. Its exact counts are machine-dependent; warnings should be investigated, not asserted away.

## Project boundaries

- Keep Windows API calls and `unsafe` blocks inside `src/platform/windows/`.
- Do not execute discovered commands during scanning or enrichment.
- Do not write undocumented Windows state, including Explorer `StartupApproved` blobs.
- Preserve exact pre-change state and validate a fingerprint immediately before every mutation.
- Restore must refuse conflicts. It must never overwrite a new registry value, file, task definition, or service configuration.
- A provider failure must become a source warning rather than an empty, apparently successful scan.
- New service behavior must not stop, delete, or disable services by default.

## Tests

Pure parsing, IDs, fingerprints, and journals belong in unit tests. Windows integration fixtures must use unique names and guaranteed cleanup:

- Registry: `HKCU\Software\WinStartupManager.Tests\<unique-id>`
- Tasks: `\WinStartupManager.Tests\<unique-id>`
- Files: a temporary directory, not the real Startup folder
- Services and HKLM: disposable elevated VM only

Include a lossless enable → prevent → restore round-trip test for every new mutable source.

## Pull requests

Keep changes focused. Explain:

1. Which startup source or UI behavior changes.
2. Why the Windows API is documented and appropriate.
3. What is journaled and how conflicts are detected.
4. Which checks and Windows versions were tested.

By contributing, you agree that your contribution is licensed under the MIT License.

