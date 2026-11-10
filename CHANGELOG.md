## v1.9.9.1 — Localization and runtime fixes

- Fixed locale switching, stale translations, attribute restoration and MutationObserver update churn.
- Added 24 localized application error codes and translated permission prompts across all 12 locales.
- Added locale parity checks and an opt-in local Ollama translation-drafting tool.

# Changelog

## v1.9.9 — Modern UI, 12 locales & System Settings
- Complete shared visual refresh with responsive layout, clearer hierarchy, improved component states, and dark/light themes.
- English default for new profiles; 10 additional languages, Vietnamese retained, Arabic RTL. Advanced tool outputs may still fall back to English.
- Added application and machine System Settings, read-only host inventory, fixed OS-settings launch targets, and local maintenance access.

- Added a ConPTY-backed Windows terminal via optional pywinpty and native POSIX PTY with resize, interactive terminal support, bounded I/O and process cleanup. Pipe fallback remains available when the optional Windows runtime or xterm assets are unavailable.
- Expanded DAP adapter profiles to Python debugpy, C/C++ lldb-dap and .NET netcoredbg; adapters are discovered locally and never downloaded automatically. Native debugger launches require explicit approval and project-contained targets.
- Added pinned xterm.js 6.0.0 / FitAddon vendor tool for a local terminal UI; third-party assets are not bundled in this source archive because external downloads are blocked in the release environment.
- Preserved earlier workspaces and API namespaces.

## 1.9.7
- Added an LSP 3.x / JSON-RPC client manager with fixed local profiles for Python, TypeScript/JavaScript, C/C++, Rust, Go, JSON, HTML, CSS and Bash. It supports completion, hover, definition, references, symbols, signature help, formatting, rename/code-action previews and diagnostics events. Monaco completion, hover and format providers are bridged to the active LSP session.
- Added a fixed-profile Python Debug Adapter Protocol client using `debugpy.adapter`, with breakpoints, thread/stack/scopes/variables, stepping, pause, evaluate and terminate. Launch requires explicit code-execution approval; debuggee code runs as the host OS user and is not sandboxed.
- Expanded Git Source Control to explicit-path stage/unstage, staged diff, commit, branch create/switch and repository-local author identity. Mutations require acknowledgement, remote actions are absent, hooks are disabled, and external Git filters/includes are rejected before mutation.
- Added an IDE protocol-provider inventory and explicit note that arbitrary VS Code `.vsix` packages / Extension Host are not supported.
- Added real local integration tests against `clangd` and `debugpy` when available, alongside path, permission and Git filter regressions. Preserved all prior workspaces and API namespaces.

## 1.9.6
- Reworked Dev Studio Workspace as an IDE workbench with Monaco Editor 0.57.0 loader support, multi-model editor tabs, language mapping, minimap, bracket guides, sticky scroll, formatting action, symbol/navigation commands and pinned local/CDN/fallback loading.
- Added Quick Open (`Ctrl+P`), Command Palette (`Ctrl+Shift+P`), collapsible Explorer folders, rename and recoverable delete/restore via hidden `.cf-trash`.
- Added persistent per-project integrated shell sessions, bounded input/output, explicit `code_execution` permission, command echo, interrupt support, process-tree cleanup and an explicit warning that the shell runs with host-user permissions.
- Added `tools/vendor_monaco.py` to safely vendor the pinned MIT-licensed Monaco assets for offline UI operation. The source archive does not include the third-party editor distribution; built-in editor remains a fallback.
- Preserved existing project search, Git, toolchain inventory, syntax diagnostics, AI debug and reviewed multi-file patch workflows. Added 16 new v1.9.6 tests and corrected a malformed duplicate Command Palette markup fragment that failed JavaScript preflight in the inherited v1.9.5 source.

## 1.9.5
- Added Windows/Docker Desktop read-only diagnostics and a user-run PowerShell acceptance probe for Linux engine, `--network none`, guest loopback packet observation and no default route.
- Expanded offline PCAP/PCAPNG parsing including PCAPNG packet block variants and interface timestamp resolution, IPv4/IPv6, DNS over TCP/UDP, HTTP response/request metadata and TLS ClientHello/ServerHello metadata.
- Hardened Docker's inert `NET_RAW` probe to require an actual observed loopback datagram and no default route; no sample or host folder is mounted.
- Added multi-step Defensive Agent workflows with explicit per-step approval, dependency checks, separate consent for sample execution/network calls, one-shot plan lifecycle and audit records.
- Clarified that container smoke tests do not certify VM-grade isolation and that live Windows Docker acceptance must be run on the target host.

# Changelog · CyberForge AIO v1.9.4

## v1.9.4 — PCAP Telemetry, Session Orchestration & Local-first AI Analyst
- Added bounded classic-PCAP capture on the disposable Docker network namespace's `lo` interface. Capture requires host `NET_RAW`; unavailable capture is reported honestly. Packet parsing extracts IP/TCP/UDP header metadata only; the stored PCAP may contain raw payloads and is never automatically sent to AI.
- Added best-effort sample-side PID attribution through `/proc` socket-inode inspection and correlation of sample client ports with loopback PCAP flows. PID gaps remain explicit when sockets are too short-lived or host visibility is restricted.
- Added per-session operation locks, multi-run history, same-session/different-session comparison, sample/evidence checkpoints, staged and reversible restore, and retention cleanup scoped to exact CyberForge-managed container labels.
- Added static/dynamic analyst correlation, PID/process map, timeline, telemetry coverage notes and experimental Sigma detection templates. Rules are marked experimental and require review.
- Added optional local-first OSV network assist for package metadata only after explicit per-request consent; Ollama/local analyst inference remains local. No arbitrary URL fetch or PCAP upload is supported.
- Added QwenCloud `qwen3.8-max` as a paid-by-default provider with separate paid-cost and data-transfer acknowledgements; no automatic free/paid fallback.
- Preserved earlier API namespaces and all legacy workspaces.

## v1.9.3 — Loopback Network Lab & Free-Tier AI Router
- Added a disposable Docker network-lab runtime for bounded Python/shell samples. Samples are staged read-only and run only after per-session acknowledgement; the container uses `--network none`, read-only root, dropped capabilities, no-new-privileges, PID/CPU/memory bounds and a bounded noexec `/tmp`. This is a Linux container boundary, not a VM.
- Added loopback DNS/HTTP/TLS emulators. DNS requests are recorded and pointed to loopback, HTTP metadata (method/host/path) is captured with query values omitted, bounded request-body bytes are hashed and discarded, and TLS ClientHello SNI is recorded without decryption.
- Added bounded process/file timeline, report schema validation, staging SHA-256 and symlink/path checks. Direct-IP attempts are not fully attributed and no real Internet route is provided.
- Added opt-in remote AI routing for Gemini API Free tier and OpenRouter free models, with Groq marked account-tier dependent. OpenRouter/Gemini model selection is constrained to documented free-model identifiers; no paid provider/model fallback is attempted.
- Added heuristic secret redaction, process-memory-only API keys, process-local conversations and per-request consent. Provider billing tier, availability, privacy and quotas remain external and may change.
- Preserved the local Ollama + deterministic Offline Analyst routes and all earlier API namespaces.

## v1.9.2 — Offline AI & Dynamic Windows Sandbox
- Added a local-only AI workbench. Ollama is contacted only via loopback and only if already present; no API key, cloud endpoint, model download or runtime installation is performed. Rule-based offline fallback is labeled non-generative.
- Added a Windows Sandbox adapter with guest networking, vGPU and clipboard disabled; sample/tools are read-only mounts; per-session output is an explicitly untrusted writable channel.
- Added process tree, selected file-system, selected persistence Registry, DNS cache, TCP/UDP endpoint and optional ETW observations. Bounded `tracerpt` CSV parsing now contributes network/process/file/Registry metadata and heuristic IOC extraction to the report.
- The guest collector stops the sample process tree after the observation window. Guest reports are bounded, schema-checked, path-contained and never executed.
- Preserved v1.9.0 and v1.9.1 endpoints and UI workspaces.

# Changelog · CyberForge AIO v1.9.1

## v1.9.1 — Defensive Engineering & Security Advisor 2.0
- Expanded offline static review for Python, JavaScript/TypeScript, shell and generic configuration with line evidence, CWE mapping, severity, confidence and remediation. Secret-like evidence is redacted in findings.
- Added web posture review for HSTS, CSP directives, CORS, cookie flags, framing, Referrer-Policy, Permissions-Policy and cross-origin policies. No network request is made.
- Added discrete-time synthetic defensive traffic simulation with per-agent rate limits, challenges, cache, bounded queue and legitimate-service priority. No packet or HTTP traffic is generated.
- Expanded privacy exposure audit to accept optional user-supplied browser hints; no device fingerprinting scan or anonymity guarantee is made.
- Added v1.9.1 static sample triage for code findings and contextual indicators. Samples are never executed.
- Preserved all v1.9.0 endpoints and workspaces.

## 1.9.0
- Added safe Security & AI Lab: offline review, synthetic availability model, virtual agents, header hardening, privacy audit and static sandbox inspection.

# Changelog

## v1.8.9
- Resource profiles and bounded HTTP concurrency for more predictable CPU/RAM use.
- Best-effort GPU inventory and server resource profile diagnostics.
- Beginner-friendly About, Help/FAQ, Troubleshooting and local bug-report pages.
- Local support report redaction and JSON export.


## v1.8.9 — Compatibility, Performance & Reliability

- Added real host compatibility inventory for OS, CPU architecture, Python, SQLite, optional modules, runtimes, LSPs, scanners, engines and sandbox backends.
- Added bounded CPU/RAM profiling, rolling RSS observations, SQLite query/cache/WAL diagnostics and static frontend profiling.
- Added temporary-database SQLite benchmark, concurrent worker stress test and hard-crash WAL recovery probe.
- Tuned SQLite statement/page caches and WAL checkpoint interval while retaining FULL synchronous durability.
- Added release preflight, reproducible source packaging, ZIP integrity/SHA-256 and CI quality gates before native builds.

## v1.8.7 — Workspace Search

- Added local workspace search with Ctrl+K / Cmd+K.
- Kept VS Code extension discovery read-only; no arbitrary extension code is loaded.


# Changelog — CyberForge v1.8.6

## v1.8.6 — System Integration & Runtime Reliability
- Added a system health report covering SQLite integrity/foreign keys, storage availability, audit chain, engine registrations, plugin file integrity, optional dependencies and recovery snapshots.
- Added user-acknowledged SQLite online backups with integrity verification, SHA-256 manifests, strict generated filenames and an eight-backup retention limit. Backups are database-only; evidence blobs, vault keys, projects, engines and plugins are outside their scope.
- Added safe maintenance actions for verification and WAL checkpointing; no automatic destructive repair or restore is performed.
- Enforced at most one active managed version per engine ID with a partial unique index and migration cleanup.
- Added per-file plugin integrity manifests and pre-execution verification. Legacy installs without manifests are reported as `legacy_unverified` for backward compatibility.
- Serialized plugin install, permission, run and uninstall lifecycles; plugin removal uses a quarantine/rollback sequence.
- Added rotating local logs, request correlation IDs and sanitized unexpected HTTP 500 responses. Request bodies and query strings are not written to the application log.
- Added Dashboard health diagnostics and database backup controls, plus `system_diagnostics` / `system_maintenance` capability separation.
- Added 27 integration/recovery/API reliability tests. Full regression coverage: 417 tests across 21 modules.

## v1.8.5 — Internationalization foundation
- Added persisted interface locale preference with Vietnamese default and English alternative.
- Added independent JSON locale catalogs, a safe loopback catalog endpoint and dynamic DOM translation for static and generated UI content.
- Added localization to preference export/import/reset and backward-compatible migration for profiles created before v1.8.5.
- Bundled both locale catalogs in Windows/macOS/Linux native build commands and made frozen self-test validate both catalogs.
- Kept code, commands, identifiers and user-entered content out of automatic translation.
- Added 19 locale, persistence, endpoint and packaging regression tests; the full suite now has 390 passing tests across 20 modules.
- Full translation of every workflow-specific dynamic status string and additional locales remain future work; this release enables only Vietnamese and English.

## v1.8.4 — Engine & Plugin Lifecycle Management
- Added a fixed, version-pinned Engine Manager catalog for Bandit, oletools and Volatility 3.
- Added isolated per-version Python virtual environments, active version switching, rollback-preserving updates and safe version removal.
- Added a constrained ZIP Plugin Manager with manifest, digest, path, symlink, duplicate-entry, encryption and size validation.
- Plugin install/update starts disabled and clears old grants; plugin code remains container-only with no automatic image pull.
- Added sample importable plugin package and dedicated manager lifecycle/security tests.

## v1.8.3 — Native Desktop Packaging
- Added OS-aware PyInstaller desktop builder for Windows, macOS and Linux.
- Added platform-specific pywebview backends and build requirement files.
- Added frozen-bundle `--self-test` for UI, plugins and edition manifest.
- Added a nine-artifact GitHub Actions build matrix.
- Preserved Windows build scripts while correcting host-platform checks.

# Changelog — CyberForge v1.8.2

## v1.8.2 — Dev Studio Workspace Redesign

### Workspace UX and navigation
- Rebuilt Dev Studio into four focused workspaces: Projects, Workspace, AI Assistant, and Diagnostics & Git.
- Replaced scroll-only navigation with accessible tabs, keyboard navigation, and responsive layouts.
- Separated the AI assistant from the editor so the code workspace has more room and fewer competing panels.
- Added project context summary and direct navigation between editor, AI, and diagnostics.
- Search results and diagnostics now return to the matching editor line.

### Data safety and workflow fixes
- Allowlisted tasks and Git operations save dirty editor buffers first, so results use the content visible in the editor.
- Save All preserves the active editor tab.
- AI debugging saves the current buffer before sending selected-file context.
- Applying a single-file AI patch is blocked if the editor changed after patch generation, preventing accidental loss of newer edits.

### Verification
- Added 7 Dev Studio UI regression tests.
- Dev Studio backend and UI regression suites pass; Python compilation and JavaScript syntax checks pass.
- This remains a source release; browser-level visual verification and native Windows builds are not claimed.

## v1.8.1 — Dual Edition Release

### Product editions
- Added AIO, Dev Edition and Cybersecurity Edition profiles using one shared source core.
- Added edition-aware navigation and independent frozen-app data directories.
- Added three Windows build scripts/artifact matrix.

### Dev Edition
- Expanded language/toolchain discovery to 28 profiles.
- Expanded project templates to 21.
- Added/expanded syntax validation for locally supported parsers and compilers.
- Added IDE interoperability export and detected editor/extension inventory.
- Extended AI patch language tags to C/C++, Rust, C#, Swift, Kotlin, Dart, PowerShell, Terraform, Lua and others supported by the patch layer.

### Cybersecurity Edition
- Added 8 local project scanner adapters: Bandit, Gitleaks, Semgrep, Trivy, Checkov, Syft, Grype and ClamAV.
- Added local project-scanning tool to AI Navigator, with explicit project/scanner selection and opt-in.
- Added actual assessment tool outputs to the AI report; no automatic report persistence or AI summary in the scanner adapter.
- Added whitelist-only scanner result summarization for optional cloud synthesis.

### Security and compatibility
- AI Navigator cannot change the selected project or expand the selected scanner set.
- Scanner execution remains local; no remote target or arbitrary command arguments are accepted.
- Cloud synthesis excludes scanner output excerpts and raw source/file contents.
- Updated Windows CI workflow and edition-specific build launchers.

### Validation
- 277 legacy regression tests + 27 v1.8.1 tests = 304 passing tests. Test modules were run independently.
- 24 navigation targets match 24 page sections; 379 unique HTML IDs.
- Python compilation and JavaScript `node --check` passed.
- External scanner/provider integrations were tested through mocked binaries/provider responses where the build host lacked those tools/services.
