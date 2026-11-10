# CyberForge AIO v1.9.9 — Test Results

## Result

- **Unit tests:** 646 passed / 646 executed.
- **Modules:** 34 passed / 34 executed.
- **Release preflight:** 0 errors, 0 warnings.
- **HTML:** 593 unique IDs; no duplicates.
- **Python:** 57 source/test/tool files compiled successfully.
- **JavaScript:** inline script passed `node --check`.
- **Bundle self-test:** `CyberForge 1.9.9 bundle OK (aio)`.
- **Locale catalogs:** all 12 JSON catalogs parsed and loaded through the allowlist.
- **ZIP:** integrity and SHA-256 verification completed at packaging time.

## Module-by-module execution batches

The suite was executed as independent subprocesses in four batches to avoid conflating a long-running aggregate process with test results.

| Batch | Modules | Tests | Result |
|---|---:|---:|---|
| Core through v1.4.0 | 12 | 198 | PASS |
| v1.5.0 through v1.8.4 | 7 | 173 | PASS |
| v1.8.5 through v1.9.1 | 7 | 101 | PASS |
| v1.9.2 through v1.9.9 | 8 | 174 | PASS |
| **Total** | **34** | **646** | **PASS** |

The v1.9.9-specific `tests.test_v199_ui_i18n_system_settings` contains 14 tests and passed, including default English, upgrade locale preservation, twelve catalog loading, Arabic RTL, System Settings permissions, fixed OS settings targets, backup-result mirroring between the dashboard and System Settings, and language-selector synchronization.

## Platform and translation limitations

- Build/test host: Linux, Python 3.13, Node.js available.
- Native Windows/macOS OS settings launch was not exercised on those operating systems. The fixed target mapping and permission gate were tested; GNOME launch behavior was tested with a mocked process invocation.
- System Settings machine inventory is read-only. The app opens a fixed native OS settings page after `host_app_launch` permission; it does not directly modify registry/preferences, drivers, firewall, routing, power plans or startup entries.
- Fresh/reset profiles default to English. A previously saved Vietnamese or other valid locale is preserved during upgrade.
- Twelve catalogs are bundled. Core navigation, common controls and System Settings have authored translations. Advanced diagnostic/tool output and some dynamically generated technical strings use English fallback where a reviewed translation is not present.
- Arabic sets RTL direction. Other locales use LTR.
- This is a source release; no native EXE/APP installer or cross-platform packaged binary was built in this environment.

## Security and data handling

- Machine inventory is bounded and read-only; it reports selected runtime tool presence rather than enumerating all installed applications/processes.
- OS settings targets are a fixed backend allowlist. Caller-provided commands or URIs are rejected.
- Opening native OS settings requires the existing `host_app_launch` capability policy.
- SQLite backup snapshots include the database only. Evidence blobs, vault keys, project folders, engines, plugins and external data are excluded.
- Backup results are now shown in both legacy dashboard and System Settings surfaces.
