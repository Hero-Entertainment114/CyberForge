# Test Results CyberForge AIO v1.9.7

## Result

- **612/612 tests passed across 32 test modules.**
- Each module was run independently in bounded subprocess batches. The one-shot aggregate runner exceeded the execution-time limit at a module boundary; it was not recorded as a complete aggregate run. Modules were then verified independently, including the final v1.9.7 module.
- **v1.9.7-specific tests: 15/15 passed.**
- The v1.9.7 protocol tests include live local-tool integration when the tools are present on the build host: `clangd` initialized through LSP, returned document symbols and diagnostics; `debugpy` launched a Python debuggee through DAP, hit a breakpoint and returned stack information. These were real local subprocesses, not mocked protocol responses.

## Release checks

- Release preflight: **0 failures, 0 warnings**.
- Python syntax compilation: **53 files**.
- HTML IDs: **562 unique IDs, no duplicates**.
- Inline JavaScript syntax: passed.
- Vietnamese and English locale JSON: passed.
- `python cyberforge.py --self-test`: `CyberForge 1.9.7 bundle OK (aio)`.
- Git Source Control tests cover init, repository-local identity, explicit-path stage/unstage, commit, branch creation, unsafe filter/include rejection, symlink rejection and API permission policy.
- Protocol tests cover LSP request allowlists, project/session binding, path and secret exclusions, DAP Python-only launch, approval requirements and actual available LSP/DAP tool integrations.

## Environment and verification boundaries

- The test environment was Linux. No native Windows/macOS desktop binaries were built or validated.
- `clangd` and `debugpy` integration tests ran on the build host. Other language-server profiles are capability-discovered and require their respective executables to be installed on the target computer.
- LSP servers and the Python debuggee execute as local host processes under the current OS user's permissions. They are not automatically isolated by the malware-analysis sandbox.
- The debugger currently supports the fixed Python `debugpy` adapter only. Arbitrary DAP adapter executables and VS Code `.vsix` extension execution are not supported.
- Monaco 0.57.0 browser assets are not embedded in this source archive. `python tools/vendor_monaco.py` can vendor the pinned assets on a machine with network access; the built-in editor fallback remains available.
- The integrated shell is pipe-backed and does not provide PTY/ConPTY. Full-screen terminal applications are not supported.
- No claim is made that this workbench is binary-compatible with VS Code or supports its entire extension ecosystem.
