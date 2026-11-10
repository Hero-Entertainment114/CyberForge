# CyberForge v1.8.6 — Test Results

## Summary

**417 tests passed across 21 test modules.** Each module was run in a separate process during release validation. The 390 previously validated tests are retained; v1.8.6 adds 27 system-integration, database-recovery, plugin-integrity and API-reliability tests.

| Module | Tests | Status |
|---|---:|---|
| `test_core` | 10 | PASS |
| `test_v011` | 11 | PASS |
| `test_v020` | 10 | PASS |
| `test_v040` | 23 | PASS |
| `test_v050` | 14 | PASS |
| `test_v060` | 9 | PASS |
| `test_v090` | 16 | PASS |
| `test_v100_ai` | 15 | PASS |
| `test_v111` | 26 | PASS |
| `test_v120` | 20 | PASS |
| `test_v130` | 12 | PASS |
| `test_v140` | 32 | PASS |
| `test_v150` | 22 | PASS |
| `test_v160` | 24 | PASS |
| `test_v170` | 33 | PASS |
| `test_v180` | 29 | PASS |
| `test_v182_ui` | 7 | PASS |
| `test_v183_desktop` | 21 | PASS |
| `test_v184_managers` | 37 | PASS |
| `test_v185_i18n` | 19 | PASS |
| `test_v186_integration` | 27 | PASS |
| **Total** | **417** | **PASS** |

## System integration coverage

- `system_health_report()` checks SQLite `quick_check` and foreign-key integrity, storage write access/free space, audit-chain integrity, engine registration/path consistency, plugin integrity and optional dependencies.
- Plugin installation creates an `install.json` manifest containing the archive SHA-256 and per-file hashes. Before execution, the manager compares the database registration, manifest, expected path and exact installed file set. Modified, missing, unexpected or symlinked files are rejected.
- Plugin lifecycle calls use a reentrant lock to serialize install, update, permission changes, execution and uninstall. Uninstall uses a quarantine path and attempts rollback if the database transaction fails.
- Existing plugins from earlier releases without per-file manifests remain visible as `legacy_unverified` for backwards compatibility. They are not silently treated as cryptographically verified; reinstall through Plugin Manager to generate a new manifest.
- SQLite migration removes duplicate active engine rows and creates a partial unique index to enforce at most one active version per engine ID.
- Database recovery uses SQLite's online backup API, runs `integrity_check`, returns a SHA-256 digest and retains eight recent generated snapshots. Backup verification rejects path traversal, symlinks, corrupted databases and arbitrary filenames.
- Backups contain only the SQLite database. Evidence blobs, evidence vault keys, project files, engine environments and plugin package files are excluded. There is no automated restore command in this release.
- Maintenance supports verification and WAL checkpointing only. It does not automatically delete records or perform destructive repairs.
- Unexpected HTTP errors are masked from the client, tagged with a request ID and logged locally. Request bodies and query strings are not included in access logs.

## Static checks

- Python compilation (`cyberforge.py`, `desktop_entry.py`, `build_desktop.py`): PASS.
- Inline JavaScript syntax (`node --check`): PASS.
- HTML structure: 410 IDs / 410 unique IDs; duplicate-ID validation PASS.
- Locale JSON resources parse and match release manifest counts; PASS.
- Native desktop builder dry-run for the current Linux host: PASS. Frozen-bundle source self-test: PASS.
- ZIP integrity and SHA-256: verified after packaging v1.8.6.

## Not live-validated / known limits

- No prebuilt Windows EXE, macOS APP or Linux frozen binary is included. Native bundles must be built on their target OS.
- No live PyPI package install was performed in this environment. Engine lifecycle tests use mocked venv/pip operations.
- Plugin SHA-256 manifests detect post-install changes but do not authenticate a publisher. There is no signed publisher trust store or plugin dependency installer.
- The plugin container runtime and required image must already exist locally. CyberForge does not pull images automatically.
- Backups are database-only and cannot restore excluded evidence, projects, engine environments, plugin files or vault keys. A database restore is not automated in this release.
- Health checks report problems; they do not automatically repair or delete data.
