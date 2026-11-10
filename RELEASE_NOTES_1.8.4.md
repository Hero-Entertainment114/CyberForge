# CyberForge v1.8.4 — Engine & Plugin Lifecycle Management

## Engine Manager
- Added a fixed catalog with pinned Bandit 1.9.4 / 1.9.3, oletools 0.60.2 and Volatility 3 2.28.2 / 2.27.0 releases.
- Each installed engine version has a dedicated Python virtual environment under the CyberForge user data directory.
- Added install, update, activate/switch, remove-version and uninstall-all actions. Previous versions remain installed until explicitly removed and can be selected again.
- Package installation uses an explicit PyPI index, binary wheels only, a fixed package/version allowlist, `shell=False`, and a bounded timeout. It does not change system PATH or install system packages.
- Engine binaries are connected to existing Bandit, oletools and Volatility adapters.

## Plugin Package Manager
- Added ZIP import for a flat manifest + Python entrypoint package, with optional README.
- Added SHA-256 verification, 5 MiB archive / 8 MiB expanded-size bounds, entry-count limits, duplicate/path/symlink/encrypted-file rejection, and strict root-file allowlist.
- Added install/update/remove, enable/disable and capability grants in the Manager UI.
- Each installation/update starts disabled and revokes all previous grants. Plugin code is still launched only via the restricted Docker/Podman sandbox, not imported into the host process.
- Added `plugins/packages/example.indicator-enricher-package-1.0.0.zip` as an importable starter package.

## Security and limits
- Engine and plugin administration use separate `engine_admin` and `plugin_admin` Ask/Allow/Deny capabilities. Plugin execution remains a separate permission with explicit run acknowledgement.
- The engine catalog pins top-level package versions, not every transitive dependency hash. Third-party engines run as the current OS user, so package provenance should be reviewed before processing sensitive evidence.
- SHA-256 verifies integrity against the supplied hash but does not authenticate the publisher. Storage-root and install-path symlink escapes are rejected. Plugin runtime image must already exist locally; CyberForge does not pull images or install plugin dependencies.
- This release does not yet include arbitrary package browsing, plugin publisher signatures, dependency resolution for plugins, or automatic engine updates.

## Verification
- Added 37 Engine/Plugin Manager lifecycle and security tests.
- Full regression inventory: 371 passing tests across 19 test modules, run independently per module.
- Python compilation and inline JavaScript syntax checks pass.
- Package installation is validated with mocked subprocess/venv operations; no live third-party package install is claimed for this build environment.
