# CyberForge AIO v1.8.6

## System Integration & Runtime Reliability

This release hardens the integration points across the application rather than adding a new tool collection.

### System health
- Added a Dashboard health report covering SQLite integrity and foreign keys, writable storage, audit-chain verification, managed engine records and paths, plugin integrity, optional dependencies and backup availability.
- Diagnostics are read-only. The report surfaces warnings and critical conditions but does not automatically rewrite or delete user data.

### Database recovery
- Added acknowledged SQLite online snapshots, independent integrity verification and SHA-256 checksums.
- Retention is limited to the eight newest generated backup files.
- A backup contains the SQLite database only. It does not include evidence blobs, evidence-vault key material, project files, engine environments or plugin files.
- Automated restore is not part of this release. Keep separate backups of excluded data and protect the application data directory.
- Maintenance actions are limited to verification and WAL checkpointing.

### Engine and plugin consistency
- SQLite now enforces at most one active managed version per engine ID, with a migration that resolves duplicate active rows.
- New plugin installs store an archive digest and per-file SHA-256 manifest. The manager checks the installed file set and contents before execution.
- Older plugin installs without per-file manifests are surfaced as `legacy_unverified` for backward compatibility. Reinstall them through Plugin Manager to create a file-integrity manifest.
- Plugin install, update, permission, execution and removal operations are serialized. Uninstall uses a quarantine/rollback sequence to protect the package if database removal fails.
- Per-file SHA-256 verifies integrity after install; it is not a publisher signature and does not establish package origin.

### Runtime reliability
- Added rotating local logs and request correlation IDs.
- Unexpected API failures now return generic error details and a request ID instead of internal stack traces. Detailed diagnostics remain in the local log; request bodies and query strings are not written to access logs.
- Added separate `system_diagnostics` and confirmation-gated `system_maintenance` capabilities.
- Added 27 tests for health reporting, backup creation/verification/retention, plugin integrity, engine uniqueness and sanitized API errors.

## Validation
- 417 regression tests passed across 21 test modules. Suites were run in separate processes.
- Python compilation, inline JavaScript syntax, Linux desktop builder dry-run and frozen-bundle source self-test passed.
- HTML contains 410 unique IDs with no duplicates.
- Native OS binaries were not built in this source-validation environment. The release remains a source archive with the existing desktop build kit.

See `TEST_RESULTS.md` for the full suite matrix and validation limits.
