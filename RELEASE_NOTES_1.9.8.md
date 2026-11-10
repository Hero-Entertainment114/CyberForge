# CyberForge AIO v1.9.8 — Declarative Extensions, Multi-DAP & Interactive PTY

## Dev Studio

- Added a local extension manager for VSIX/CFEXT archives with strict archive/path/symlink/size validation. Only declarative themes, snippets and language metadata are accepted. `main`, `browser`, activation hooks, npm scripts/dependencies, tasks, command contributions, debuggers and terminal contributions are rejected. No extension JavaScript or Node entrypoint is stored or executed; this is not a general VS Code Extension Host.
- Added theme and snippet contributions to Monaco. Language contributions are recorded as metadata; they do not install language servers or executable providers.
- Added native POSIX PTY sessions and optional Windows ConPTY through `pywinpty==3.1.2`. Supports interactive input/output, terminal resize, bounded output, session limits, process cleanup and idle reaping. If pywinpty is absent, the existing pipe-backed terminal remains available.
- Added fixed-profile DAP adapters for Python `debugpy`, C/C++ `lldb-dap`/`lldb-vscode` and .NET `netcoredbg --interpreter=vscode`. Adapter binaries must already be installed and discovered locally; CyberForge never downloads them. Native debugger launches require explicit approval and project-contained target/source paths.
- Added `tools/vendor_xterm.py` to fetch pinned xterm.js 6.0.0 and FitAddon 0.11.0 assets with SHA-256 manifest and MIT licenses. The assets are not in this source archive because the build environment could not reach the CDN. Run the tool explicitly with network access to enable the full xterm terminal UI; otherwise the command-input fallback remains.
- Updated Dev Studio capability inventory and API routes while preserving previous APIs and workspaces.

## Permissions and limitations

- The terminal shell, language servers, DAP adapters and debuggee programs run with the current OS user's permissions. They are not sandboxed by the malware-analysis sandbox.
- `plugin_admin` permission and explicit confirmation are required for extension import/state/uninstall operations. Imported packages are data-only contributions.
- `code_execution` permission is required for terminal sessions and debuggee launches.
- This is not a full VS Code Extension Host. Arbitrary `.vsix` JavaScript extensions are unsupported.
- Windows ConPTY depends on optional `pywinpty` and requires runtime validation on a Windows host. The current release build host is Linux; native Windows ConPTY was not executed here.
- Native Windows/macOS application binaries are not included.
