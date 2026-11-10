# CyberForge AIO v1.8.7

## Workspace Search & Compatibility Audit

- Added in-app workspace search in the top bar, with Ctrl+K / Cmd+K shortcut, keyboard navigation, page/section matching and direct navigation.
- Search is local to the loaded interface. It does not send queries to a search provider or index private project files.
- Preserved existing Dev Studio project search, multi-tab editing, multi-file AI patch review, security workspaces, privacy routes, engine/plugin managers and localization.
- Clarified compatibility boundaries: installed editor/extension manifests are read-only discovery; VS Code extension API execution is not implemented. Language support depends on detected runtimes, LSP servers, formatters and compilers.
- No changes to existing project data schema are required.
