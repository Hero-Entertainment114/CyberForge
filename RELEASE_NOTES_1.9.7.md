# CyberForge AIO v1.9.7 Release Notes

## Dev Studio: protocol-native IDE services

v1.9.7 builds on the v1.9.6 Monaco workbench and adds real language/debug protocol clients rather than merely exposing language-server inventory.

### Language Server Protocol

- Added a bounded Content-Length / JSON-RPC 2.0 transport and LSP 3.x manager.
- Fixed local executable profiles: Pyright, BasedPyright, python-lsp-server, TypeScript Language Server, clangd, rust-analyzer, gopls, vscode-json-language-server, vscode-html-language-server, vscode-css-language-server and bash-language-server.
- Exposed completion, hover, definition, references, document symbols, signature help, formatting, rename preview, code-action preview and published diagnostics.
- Bridged Monaco completion, hover, definition, signature help and formatting providers to the active LSP session. Definition navigation is constrained to the selected project.
- Server-originated workspace edits are not automatically applied. Unrecognized server requests are rejected. Document paths exclude traversal, symbolic links, `.git`, dependency folders and environment-secret files.
- Server launch requires `code_execution` permission and runs with the current OS user's permissions. It is not sandboxed.

### Debug Adapter Protocol

- Added a DAP 1.x client with one fixed adapter profile: `python -m debugpy.adapter`.
- Supports breakpoints, threads, stack trace, scopes, variables, continue, next, step-in, step-out, pause, evaluation, variable mutation, exception info and termination.
- Only `.py` and `.pyw` files inside the selected project may be launched. No arbitrary adapter executable or adapter arguments are accepted.
- Launch and sensitive actions require explicit permission/acknowledgement. Debuggee code executes locally with host-user permissions and is not automatically placed inside the malware sandbox.
- DAP reverse requests (including `runInTerminal`) are rejected.

### Git Source Control

- Added staged diff, explicit-path stage/unstage, local commit, branch listing/create/switch and repository-local author identity.
- No remote push/pull or arbitrary Git arguments are exposed.
- Hooks, external diff, pager, GPG signing, fsmonitor and untracked cache are disabled for managed operations.
- Mutating actions refuse repositories with external clean/smudge/process filters, `core.attributesFile`, included config, unsafe attribute symlinks, Git worktree metadata files, or repositories too large to complete the bounded filter scan.

### Architecture and compatibility

- LSP/DAP/Git are protocol providers. This is not a VS Code Extension Host; arbitrary `.vsix` extension code is not executed.
- Monaco 0.57.0, Explorer, multi-tab editing, Quick Open, Command Palette, integrated shell, AI debug and reviewed patch flows are preserved.
- Monaco third-party assets are still not embedded in the source archive. Run `python tools/vendor_monaco.py` on a machine with Internet access for offline Monaco operation; the built-in editor fallback remains available.
- The integrated shell remains pipe-backed, not PTY/ConPTY. Full-screen TUI applications are not supported.

See `TEST_RESULTS_1.9.7.md` and `VSCODE_COMPATIBILITY_1.9.7.md` for verification and feature boundaries.
