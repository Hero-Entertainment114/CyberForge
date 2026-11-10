# CyberForge AIO v1.9.6 Release Notes

## Dev Studio IDE workbench upgrade

v1.9.6 focuses on evolving Dev Studio from a basic code workspace into a more complete IDE workbench while preserving the existing security, sandbox, AI and project features.

### Editor and workbench

- Added Monaco Editor 0.57.0 integration with one model per open project file, multi-tab state, language-aware tokenization and built-in language services.
- Added Quick Open (`Ctrl+P`) and Command Palette (`Ctrl+Shift+P` / `F1`).
- Added editor actions for save/save all, format document where a formatter is available, Go to Definition and Rename Symbol where providers support them.
- Added a collapsible Explorer, folder/file selection, rename, recoverable delete through `.cf-trash`, and restore.
- Added Find in Files and retained project search, Git status/diff/log/init, syntax diagnostics, toolchain inventory and AI patch review.
- Added Monaco preference integration for editor appearance and behavior.

### Integrated terminal

- Added persistent shell sessions for detected PowerShell, pwsh, cmd, bash, zsh or sh shells.
- Added bounded session counts, input/output limits, idle cleanup, command interruption and process-tree cleanup.
- Terminal commands run with the current OS user's privileges after the user grants the `code_execution` capability and explicitly opens a session.
- The terminal uses redirected pipes, not PTY/ConPTY. Full-screen TUI applications such as Vim, top and htop are not supported in this release. Commands are not sandboxed; use the supported isolated runner for snippets that need isolation.

### Monaco asset delivery

- The source package pins Monaco 0.57.0 and includes `tools/vendor_monaco.py` to fetch and install the upstream MIT-licensed assets into `static/vendor/monaco`.
- If local assets are not installed, the editor may use the pinned jsDelivr CDN when network access is available. Otherwise, the built-in editor remains available.
- Monaco AMD loading remains a compatibility path. Upstream marks AMD as deprecated, so a future release should migrate to the ESM build.
- Monaco assets are not bundled in this source ZIP because the build environment had no package-registry network access.

### Compatibility and scope

- Existing Security Workbench, Windows Sandbox integration, loopback NetLab, telemetry/PCAP, orchestration, AI Analyst and provider policy are retained.
- Existing language-server inventory remains. A full VS Code extension host, full Monaco LSP client integration and Debug Adapter Protocol client are not included.
- The integrated shell is a host terminal, not a sandbox. It is not an unrestricted unattended AI shell.
- Native EXE/APP binaries are not included in this source release.

## Validation

See `TEST_RESULTS_1.9.6.md` for the exact unit test and preflight results. Monaco runtime rendering with the CDN/local vendor asset and Windows PowerShell behavior must still be verified on a target desktop because the build environment does not provide the full desktop runtime or package-registry connectivity.
