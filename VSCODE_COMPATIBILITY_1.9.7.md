# Dev Studio Protocol Compatibility · v1.9.7

CyberForge Dev Studio is a Monaco-based IDE workbench with selected protocol integrations. It is not a binary-compatible VS Code distribution and does not currently host the VS Code Extension Host.

| Feature | v1.9.7 status | Requirement / boundary |
|---|---|---|
| Monaco editor | Supported | Vendor with `python tools/vendor_monaco.py` or use pinned CDN fallback |
| LSP 3.x / JSON-RPC | Supported | Local language server installed on PATH; explicit `code_execution` approval |
| Completion / hover / definition / signature help / formatting | Supported where server advertises the capability | Workspace-bound open document and active LSP session |
| References / document symbols | API preview | Result is shown in the workbench; no full references tree yet |
| Rename / code actions | Preview only | WorkspaceEdit is never applied automatically |
| Diagnostics | Supported | LSP `publishDiagnostics` mapped to Monaco markers for the active open document |
| DAP 1.x | Supported for Python | `debugpy` in CyberForge's active Python environment |
| Breakpoints / stack / scopes / variables / stepping | Supported for Python | Debuggee runs with current OS-user permissions |
| Other debug adapters | Not included | No arbitrary adapter executables or adapter arguments |
| Git Source Control | Local operations | Stage/unstage explicit paths, diff, commit, branch and identity; no push/pull |
| VS Code `.vsix` Extension Host | Not included | Arbitrary extension code is not executed |
| Terminal PTY/ConPTY | Not included | Pipe-backed shell; full-screen TUI apps are not supported |

## Host process boundary

Language servers can read the selected project. The Python debugger executes the selected program. Both are local processes and are not isolated by the malware sandbox. They are gated by CyberForge's `code_execution` capability, and target-specific OS permissions still apply.

## Suggested local tools

Install language servers only from trusted official distributions and check their provenance before use. Examples include:

- Python: Pyright, BasedPyright or python-lsp-server.
- TypeScript/JavaScript: TypeScript Language Server.
- C/C++: clangd.
- Rust: rust-analyzer.
- Go: gopls.
- Python debugging: debugpy installed into the Python environment used to launch CyberForge.

CyberForge detects availability but does not silently install language servers or extensions.
