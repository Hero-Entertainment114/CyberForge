# Dev Studio Extension / Protocol Compatibility — v1.9.8

## Extension package support

CyberForge accepts VSIX/CFEXT ZIP archives only as a carrier for a restricted declarative subset. It does **not** implement the VS Code Extension Host API. The installer validates package paths, duplicate names, symlinks, compressed/unpacked size and contribution JSON. It rejects executable entrypoints, activation events, extension dependencies, npm lifecycle scripts/dependencies, commands, tasks, debuggers, terminal providers and unsupported contribution points.

Supported contributions:
- Themes: bounded JSON data translated into Monaco theme definitions.
- Snippets: bounded JSON snippet bodies registered as Monaco completion providers.
- Languages: extension and language identifiers stored as metadata only.

A VSIX package may contain additional files, but only files explicitly referenced by supported and validated contributions are retained. Publisher identity and package provenance are not cryptographically authenticated by this import path. Review package provenance before importing.

## Debug Adapter Protocol

- Python: `debugpy` module, launched through the active CyberForge Python interpreter.
- C/C++: `lldb-dap` or legacy `lldb-vscode` from PATH.
- .NET: `netcoredbg --interpreter=vscode` from PATH.

Adapter availability is discovered at runtime. Debuggee and adapter processes execute with the current OS user's permissions. They are not isolated by the malware-analysis sandbox. Each launch requires a confirmation and project-relative program/source paths.

## Integrated terminal

- POSIX: native PTY (`pty.openpty`) with resize, process groups and SIGINT/SIGTERM cleanup.
- Windows: optional `pywinpty==3.1.2` for ConPTY. Without it, CyberForge retains the pipe-backed fallback.
- I/O is bounded and session-count/idle limits apply. A terminal is a host shell, not a security sandbox.
- Pinned xterm.js 6.0.0 / FitAddon 0.11.0 may be vendored with `python tools/vendor_xterm.py`. The tool writes an asset manifest with SHA-256 hashes and copies MIT license files. Internet access is needed only when this tool is run.

## Not supported yet

- Arbitrary VS Code extensions, Extension Host activation or extension JavaScript.
- Extension-provided tasks, commands, debuggers and terminal profiles.
- DAP adapters beyond the fixed profiles listed above.
- Remote Git push/pull from the Dev Studio Source Control panel.
- Automatically installing language servers, debuggers or terminal dependencies.
