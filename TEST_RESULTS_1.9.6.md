# CyberForge AIO v1.9.6 Test Results

## Release scope

This report covers the Dev Studio IDE upgrade and regression validation of the existing v1.9.5 codebase.

## Full regression summary

- **597 tests passed across 31 modules.**
- Modules were executed independently in three subprocess batches to isolate failures and avoid relying on a single long-running test process.
- Batch A: 154 tests across 10 modules.
- Batch B: 236 tests across 10 modules. The first run exposed one stale version assertion in `tests.test_v183_desktop`; the assertion was updated to the current v1.9.6 CI tag and the module was rerun successfully (21/21).
- Batch C: 207 tests across 11 modules.
- Final result: **31/31 modules, 597/597 tests passed**.

## New v1.9.6 tests

`tests.test_v196_dev_ide`: 16 tests passed.

Coverage includes version/capabilities, safe project file operations, recoverable delete/restore, metadata validation, path traversal protection, terminal session behavior, project-bound sessions, bounded input, API permission gates, interrupt path, Monaco/Quick Open/palette integration, JavaScript markup integrity, and Monaco vendor tooling.

## Release preflight

- `python cyberforge.py --self-test`: `CyberForge 1.9.6 bundle OK (aio)`.
- `python tools/release_check.py`: 0 failures, 0 warnings.
- Python syntax: 51 files compiled successfully.
- Inline JavaScript: `node --check` passed.
- Locale JSON: valid.
- HTML IDs: 546 unique IDs, no duplicates.

## Target-host terminal smoke test

On the current Linux build host, the integrated shell was opened through the terminal manager and a harmless `printf` command returned the expected output. The shell runs without interactive TTY flags to avoid false job-control support claims.

This is not a Windows PowerShell or ConPTY acceptance test. Terminal sessions are pipe-backed; full-screen TUI applications are unsupported.

## Monaco runtime status

The HTML/JavaScript loader and built-in fallback pass static syntax/preflight checks. Monaco 0.57.0 assets are not bundled because package-registry network access was unavailable in the build environment. The user can run `python tools/vendor_monaco.py` on a connected machine, or the UI can use the pinned CDN if permitted. Offline Monaco rendering is not claimed until the vendor script has completed successfully.

The loader uses Monaco's AMD compatibility build, which upstream deprecates. No VS Code extension host, full LSP client/workbench, or Debug Adapter Protocol client is included.

## Safety and permissions

The integrated terminal executes commands as the current OS user and is not sandboxed. Opening a session requires the existing `code_execution` capability and explicit user action. The terminal enforces bounded sessions, input/output limits and process cleanup, but it does not provide a separate security boundary. The existing isolated runner should be used for supported snippets requiring isolation.

## Not tested in this build environment

- Windows PowerShell/cmd behavior and Windows process-tree interruption.
- Monaco browser rendering with downloaded local assets or CDN connectivity.
- Full-screen terminal applications requiring PTY/ConPTY.
- Full VS Code extension host, LSP client integration and Debug Adapter Protocol.
- Windows Docker Desktop acceptance from v1.9.5 remains pending and was intentionally not repeated in this Dev Studio release.
- Native Windows/macOS/Linux desktop binaries were not produced by this source-only packaging step.
