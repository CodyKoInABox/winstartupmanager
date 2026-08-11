# Changelog

All notable changes will be documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Native Rust UI with dark/light themes, search, source filters, details, warnings, and virtualized rows.
- Concurrent discovery for registry Run/RunOnce entries, Startup folders, boot/sign-in scheduled tasks, and automatic services.
- Conflict-aware recovery journal for registry values, Startup-folder files, and service start modes.
- Supported Task Scheduler enable/disable control.
- Protected classification for Windows components, launch-protected services, policy entries, per-user services, and mixed-trigger tasks.
- Embedded Windows metadata, per-monitor DPI manifest, and the canonical WSM logo across the UI and executable resources.
- Interprocess recovery locking, parked-file integrity validation, and transactional service rollback.
- Strict receipt-provenance validation; machine-wide Registry/common-Startup recovery stays read-only across the elevation boundary.
- Read-only provider smoke-test example and pinned Windows CI/release workflows.
- Reproducible third-party license notices and self-contained portable release archives.
