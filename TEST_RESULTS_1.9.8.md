# CyberForge AIO v1.9.8 — Test Results

## Overall

- **632/632 tests passed** across **33/33 isolated test modules**.
- Modules were run independently in three bounded subprocess batches. Every module returned exit code 0 and unittest `OK`; this report does not claim that a single aggregate invocation completed.
- `python tools/release_check.py`: **0 failures, 0 warnings**.
- Python syntax compilation: 56 files. Inline JavaScript syntax: passed with Node.js. Locale JSON: both `vi` and `en` parsed. HTML IDs: 570 unique, no duplicates.
- `python cyberforge.py --self-test`: `CyberForge 1.9.8 bundle OK (aio)`.
- Source ZIP integrity and SHA-256 were checked after packaging.

## Test modules

| Module | Tests | Result |
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
| `test_v187_workspace_search` | 4 | PASS |
| `test_v188_diagnostics` | 9 | PASS |
| `test_v189_onboarding_resources` | 9 | PASS |
| `test_v190_security_core` | 9 | PASS |
| `test_v191_defensive_workbench` | 24 | PASS |
| `test_v192_dynamic_sandbox` | 33 | PASS |
| `test_v193_sandbox_ai` | 17 | PASS |
| `test_v194_telemetry_orchestration` | 26 | PASS |
| `test_v195_runtime_packet_agent` | 33 | PASS |
| `test_v196_dev_ide` | 16 | PASS |
| `test_v197_ide_protocols` | 15 | PASS |
| `test_v198_extensions_pty_multi_dap` | 20 | PASS |
| **Total** | **632** | **33/33 PASS** |

## v1.9.8-specific coverage

The 20 new tests cover declarative extension package import and archive limits, rejection of a symlinked extension-store root, forbidden executable entrypoints/activation scripts/dependencies, duplicate installs, enable/disable/uninstall, POSIX PTY interactive input/output, resize and process-tree reaping, session project isolation, live host PTY/xterm capability reporting, multi-DAP adapter inventory and launch approval gates.

The POSIX PTY tests run against a real shell on the Linux build host. They verify interactive I/O, terminal resize, reaping the shell leader and killing a descendant that ignores SIGTERM. The module passes with Python `ResourceWarning` escalated to an error.

## Verification boundaries

- **Windows ConPTY:** not executed in this Linux build environment. Windows requires optional `pywinpty==3.1.2` from `requirements-windows-pty.txt`; run the integrated terminal acceptance checks on a Windows host. Without pywinpty, the legacy pipe-backed terminal remains available.
- **xterm assets:** `tools/vendor_xterm.py` is pinned to xterm.js 6.0.0 and FitAddon 0.11.0. The build environment could not resolve the CDN, so vendored JS/CSS/license assets are not included in this ZIP. Run the tool explicitly with network access to enable the full xterm UI; otherwise the command-input fallback remains.
- **C/C++ and .NET DAP:** `lldb-dap`/`lldb-vscode` and `netcoredbg` profiles are implemented and discovered from PATH, but those adapters were not available for a live smoke test here. Python `debugpy` DAP integration remains covered by v1.9.7 tests.
- **Extension support:** this is a data-only declarative extension manager, not a full VS Code Extension Host. Arbitrary extension JavaScript is intentionally not executed.
- No native Windows/macOS binaries were built by this source-release run.

## Expected diagnostic log output

`test_v186_integration` intentionally injects private exceptions to verify that API responses are sanitized. Their stack traces may appear in captured test output; the module returns `OK` and is not a product test failure.
