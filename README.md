# CyberForge AIO v1.9.9.1

**Modernized Unified Workbench · 12 interface languages · System Settings**


**Two focused editions, one shared core: Dev Studio + Cybersecurity Workbench.**

CyberForge is a local-first desktop/web-style workbench. It runs a loopback-only Python service and serves a bundled HTML/CSS/JavaScript interface in a browser or optional native desktop shell. v1.9.9.1 is distributed as a source release with a host-native desktop build kit for Windows, macOS and Linux:

- **AIO** — all workspaces in one application.
- **Dev Edition** — a programming-first workspace with language/toolchain discovery, project management, IDE interoperability and AI-assisted code changes.
- **Cybersecurity Edition** — security operations, malware triage, reverse engineering, DFIR, privacy/network research and AI-assisted assessment. Dev Studio remains available as a selected-project source for local security scanning.

These are edition profiles over the same codebase, not three independently developed products. Each frozen edition gets a separate user-data directory on its host operating system.

### v1.9.9.1 release highlights

- Refreshed shared UI design system across existing workspaces, with responsive navigation, cohesive controls/cards/tables and dark/light/system themes.
- English is the fresh-install/reset default. Twelve bundled locales are available: `en`, `vi`, `es`, `fr`, `de`, `pt`, `ja`, `ko`, `zh`, `ru`, `ar`, `hi`; Arabic uses RTL. Advanced tool output may fall back to English.
- System Settings includes app appearance/language, read-only machine inventory, fixed allowlisted native OS settings handoff, health diagnostics and local SQLite backups.
- Validation: 661 tests across 36 modules (modules executed independently); release preflight 0 errors / 0 warnings. See `TEST_RESULTS_1.9.9.1.md` for the exact verification boundaries.

## Release packages

| Package | Edition profile | Primary use |
|---|---|---|
| `CyberForge_AIO_v1.9.9.1_source.zip` | `aio` (with shared `dev` and `security` profiles) | All workspaces and shared core |

The source ZIP contains the complete AIO project. Dev and Cybersecurity profiles remain part of the shared codebase and can be selected through the existing edition/build flow; this release package command emits the AIO source archive. See `EDITION_GUIDE.md` for profile differences.

## Dev Studio v1.8.2

Dev Studio is organized into four dedicated workspaces: Projects, Workspace, AI Assistant, and Diagnostics & Git. The code editor now has its own Explorer + Editor layout rather than competing for space with the AI panel. Search and diagnostic findings can jump to the relevant source line. Before project tasks, Git operations, or multi-agent analysis, dirty editor buffers are saved so the selected context matches the source the user sees. Single-file AI patch application refuses to overwrite edits made after patch generation.

## Engine & Plugin Manager v1.8.4

- **Engine Manager:** fixed catalog for Bandit, oletools and Volatility 3. Each pinned version has its own Python virtual environment; users can install, update, switch versions, remove one version or uninstall all managed versions. Existing versions are kept for rollback.
- **Plugin Package Manager:** import a reviewed ZIP package, validate its manifest/SHA-256/archive structure, update or remove installed plugins, enable/disable, and manage declared capabilities. Every installation/update resets the plugin to disabled with no permissions.
- Engine installation is limited to a reviewed package/version catalog and contacts PyPI only after confirmation. It uses binary wheels, an explicit package index and no shell command. A Python 3.10+ interpreter is required on PATH.
- Plugin packages use a flat manifest + Python entrypoint format and run only through the existing restricted Docker/Podman runtime. The required image must already exist locally. Plugin SHA-256 is an integrity check, not publisher authentication.

The catalog is intentionally small in this phase. It does not yet provide an unrestricted package browser, automatic engine updates, publisher-signature verification or plugin dependency installation.

## Workspace Search v1.8.7

- Ctrl+K / Cmd+K opens local workspace search. Search matches navigation pages, introductions and section labels, then navigates to the selected section. This does not search private project-file contents or contact a remote search provider.
- VS Code/VSCodium/Cursor interoperability remains workspace configuration and extension-manifest discovery. CyberForge does not host the VS Code extension API runtime.

## Compatibility, Performance & Reliability v1.8.8

- **Compatibility Analysis:** reports the actual host OS/release, CPU architecture, Python/SQLite versions, optional Python modules, application data write access, runtimes, LSP servers, scanner CLIs, managed engines and sandbox backends. OS-specific compatibility notes distinguish unsupported integrations from tools that are merely absent.
- **No false readiness:** discovery does not imply that Docker/Podman daemons are reachable, VM isolation is safe, scanner signatures are current, language servers are configured, or extension APIs are executable. Each active capability still needs its own smoke test.
- **CPU/RAM profiling:** runtime snapshots expose process CPU time, RSS/peak RSS and thread count. A 120-sample in-memory ring provides a memory-growth signal; growth is a heuristic, not a definitive leak diagnosis.
- **SQLite optimization:** bounded 2 MiB page cache, 256 prepared-statement cache, in-memory temporary sort storage, WAL auto-checkpoint at 500 pages and `PRAGMA optimize` after schema migrations. FULL synchronous durability is retained. Dashboard profiling reports DB/WAL/SHM bytes, page/free-list counts, cache settings, integrity and foreign-key checks.
- **Frontend profiling:** measures bundled HTML, DOM element/ID counts, duplicate IDs, inline JavaScript/CSS sizes and inline event handlers. It does not substitute for a browser trace of layout, paint, interaction latency or GPU behavior.
- **Stress and crash recovery:** user-confirmed stress tests are capped at 16 workers and 300 local jobs and use a temporary SQLite database. The crash probe terminates a child process with an in-flight WAL transaction and validates recovery in a temporary directory. Neither probe changes production records or contacts external hosts.
- **Release process:** `python tools/release_check.py` validates version metadata, locales, frontend IDs, source syntax and inline JavaScript when Node.js exists. `python tools/package_source.py` runs release gates, creates a clean source ZIP, checks ZIP integrity and writes SHA-256. The desktop build workflow runs the full unit suite and preflight before its Windows/macOS/Linux matrix.

**Durability note:** WAL with FULL synchronous mode prioritizes transaction durability over maximum write throughput. The benchmark uses a disposable DB configured for benchmark throughput and is not a direct prediction of production performance.

## System Integration & Runtime Reliability v1.8.6

- Dashboard health checks cover SQLite integrity and foreign keys, storage write availability, audit-chain validation, managed engine registrations, installed plugin integrity, optional dependencies and recovery backup status.
- Plugin packages installed in v1.8.6 carry per-file SHA-256 manifests. The manifest is checked before execution; modified, missing or unexpected files block execution. Older managed plugins without a manifest are reported as `legacy_unverified` for compatibility and should be reinstalled through Plugin Manager to gain file-level verification.
- Plugin lifecycle operations are serialized. Uninstall first moves the registered package to a quarantine path, commits database removal, then removes the quarantine folder; a failed database transaction attempts to restore the original folder.
- Engine database state enforces at most one active managed version per engine ID.
- SQLite online backups require an explicit acknowledgement, include a SHA-256 checksum and SQLite integrity checks, and retain at most eight recent snapshots. They include only the database, not evidence blobs, evidence-vault keys, project files, engines or plugins. Automated restore is not included.
- Maintenance exposes read-only verification and a WAL checkpoint. It does not delete user data or silently repair corrupted records.
- Unexpected API errors return a generic message and a request ID. Detailed diagnostic stack traces are kept in rotating local logs; request bodies and query strings are excluded.
- New capabilities separate read-only `system_diagnostics` from confirmation-gated `system_maintenance`.

## Internationalization v1.8.6

- Added a locale resource layer with `locales/vi.json` and `locales/en.json`; the catalogs are bundled with native builds and checked by the frozen-bundle self-test.
- Added a persisted `localization.locale` preference. Vietnamese is the default; English is available from Preferences → Appearance & Personalization → Interface language.
- Locale selection is included in preference save, export, import and reset. Existing v1.8.4 profiles migrate to Vietnamese without losing their existing settings.
- Added an allowlisted loopback locale endpoint and a DOM translation observer for static and dynamically rendered UI text/labels. It intentionally excludes code, commands, textareas and user-entered content.
- English covers all Vietnamese-language copy embedded in the shipped static interface. Vietnamese covers all long-form English copy in that interface, the main navigation, common controls, preferences, Dev Studio, manager screens and a broad set of concise labels and input hints. The current catalogs contain 1,171 Vietnamese and 491 English entries. Technical names and identifiers (for example Python, Git, JSON, CVE and YARA) remain unchanged by design.
- Only Vietnamese and English are enabled in this release. Some workflow-specific dynamic status strings, third-party tool output and provider-generated responses can remain in their source language; these are not rewritten blindly. Japanese, Korean, Simplified Chinese, French, German and Spanish remain future locale packs.

## Dev Edition

- **28 language/toolchain profiles:** Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Ruby, Kotlin, Swift, Dart, Bash, PowerShell, SQL, HTML, CSS, JSON, YAML, TOML, Lua, Elixir, Haskell, Scala, Dockerfile and Terraform.
- **21 starter templates:** empty, Python, web, Node.js, TypeScript, Go, Rust, Java, C, C++, C#, PHP, Ruby, Kotlin, Swift, Bash, PowerShell, Dart, Lua, Terraform and security-tool.
- Local runtime, LSP, formatter and compiler discovery. Availability is reported from the local machine; CyberForge does not pretend a missing tool is installed.
- Multi-tab Dev Studio, syntax highlighting, basic autocomplete, project explorer/search, Git status/diff and allowlisted tasks.
- AI debug and multi-file patch preview. Review each hunk and apply explicitly; SHA-256 optimistic locking refuses to overwrite a file changed since the patch was prepared.
- IDE interoperability for VS Code, VSCodium, Cursor, Zed, Sublime and JetBrains families where detected. `.code-workspace`, `.editorconfig` and `.vscode` recommendations can be exported; extensions are suggestions, not auto-installed or executed.
- Optional isolated code runner uses a local Docker/Podman engine and an already available image. It is for ordinary development snippets, not malware detonation.

Syntax validation varies by language and local toolchain. For example, Python/JSON/TOML/XML have built-in parsers; other languages need their compiler, parser, formatter or LSP. C#/Kotlin and some web formats may have editor/toolchain discovery without a full built-in language server. See the Toolchains workspace for detected local support.

## Cybersecurity Edition

- Unified cases, assets, scope, findings, evidence, audit events, workflows and reports.
- Malware file/folder triage, hashes, archive and structure inspection, script heuristics, IOC extraction/correlation, URL phishing checks, PCAP/log triage and local reputation.
- Local project security assessment using an explicit allowlist: Bandit, Gitleaks, Semgrep, Trivy, Checkov, Syft, Grype and ClamAV. Only the selected local Dev project is scanned. The tool does not scan a remote target or update databases automatically.
- Reverse engineering adapters: built-in metadata, `file`, `strings`, `readelf`, `objdump`, `nm`, Rizin/radare2, Ghidra headless and JADX where available.
- BlackArch group inventory (read-only), AnonSurf state/control and Firejail status/selected wrappers on compatible Linux systems.
- CAPE, MobSF, Volatility 3 and MISP connectors when separately installed/configured.
- Privacy Network: Direct, Tor SOCKS5, explicit HTTP proxy and WireGuard-route modes for CyberForge Search/Reader requests. This is not full-system anonymity and does not automatically route AI-provider or unrelated app traffic.
- AI Navigator and Multi-Agent can make bounded plans, execute actual registered adapters, report their status and synthesize minimized tool facts. The project-scanning adapter is available only when the user selects a project, explicitly opts in and chooses 1–8 locally installed scanners.

External engines/services are not bundled in these small source archives. Bandit, oletools and Volatility 3 can be installed through the new Engine Manager; other tools are detected and invoked through fixed adapters only when locally installed or explicitly configured. Missing tools report `not installed` / `unavailable`; no result is fabricated.

## AI and privacy

QwenCloud and xKiro are supported through OpenAI-compatible APIs. Real provider use requires the user's API key and is subject to provider quota/pricing. Tests use mocked provider responses; no live AI call is implied by a passing test.

- Cloud planning can receive the objective, user-supplied context, selected project ID and chosen scanner names. Do not put source, credentials or customer data into cloud context unless permitted.
- Raw scanner output stays local by default. The optional final synthesis sends only a whitelist-minimized summary when the user explicitly opts in.
- The project scanner adapter does not itself call AI and does not persist a report. A user may separately choose the normal Security Operations report-save workflow.
- Local RAG is lexical (BM25-style), not a vector database or neural embedding service.
- AI plans are bounded to registered tools; there is no unrestricted AI shell or arbitrary filesystem capability.

## User data and permissions

Preferences include appearance, editor options, AI behavior and an `Allow / Ask / Deny` matrix. Every registered API capability is enforced by the backend. `Ask` requests one-time approval; `Deny` blocks even in Trusted autonomy. OS-level elevation, destructive operations and explicit patch review remain separately enforced.

- Source mode stores data under `data/` in the extracted application folder.
- Frozen Windows builds use separate user-profile locations for AIO, Dev and Security.
- Evidence Vault encryption uses AES-256-GCM with scrypt-derived keys when the optional cryptography dependency is installed. Back up encrypted evidence and retain the passphrase separately; losing the passphrase may make evidence unrecoverable.

## Run from source

### Windows

1. Extract the chosen edition ZIP to a writable folder.
2. Install Python 3.10 or later.
3. Run `START_WINDOWS.bat`.

### Linux / macOS

```bash
chmod +x start_linux_macos.sh
./start_linux_macos.sh
```

The service binds to loopback only. Do not expose it to a LAN/public Internet without a separately reviewed authentication and deployment design.

## Build native desktop applications

This source archive contains the build kit, not prebuilt EXE / APP / Linux binaries. PyInstaller is not a general cross-compiler, so run the matching build on the target operating system.

### Windows

```powershell
py -3 -m pip install -r requirements-build-windows.txt
.\BUILD_WINDOWS.bat
.\BUILD_WINDOWS_DEV.bat
.\BUILD_WINDOWS_SECURITY.bat
```

Use `BUILD_ALL_WINDOWS.bat` to build all three editions. Each output is a PyInstaller `onedir` folder. Keep the complete folder together. The native window requires the Microsoft Edge WebView2 Runtime and a compatible .NET runtime for pythonnet (prefer the .NET 6+ Desktop Runtime; .NET Framework 4.6.2 is the fallback on supported architectures). The app falls back to the default browser if the native WebView cannot start.

### macOS

```bash
python3 -m pip install -r requirements-build-macos.txt
./BUILD_DESKTOP_MACOS.command --edition aio
```

The result is a `.app` bundle using Cocoa/WebKit. The current build is not code-signed or notarized.

### Linux

```bash
python3 -m pip install -r requirements-build-linux.txt
./BUILD_DESKTOP_LINUX.sh --edition aio
```

The result is a portable folder using Qt WebEngine. The target system needs compatible Qt / desktop libraries. Build on the oldest Linux distribution you intend to support because PyInstaller does not bundle glibc.

All three builders run a frozen-bundle self-test before reporting success. GitHub Actions workflow `.github/workflows/desktop-editions.yml` defines all nine edition/OS combinations and can be run manually or triggered by the `v1.8.6` tag.

## Optional dependencies

- Desktop wrapper for source mode: use `requirements-desktop-windows.txt`, `requirements-desktop-macos.txt`, or `requirements-desktop-linux.txt` for the host OS.
- Windows build dependencies: `pip install -r requirements-build-windows.txt`
- macOS build dependencies: `pip install -r requirements-build-macos.txt`
- Linux build dependencies: `pip install -r requirements-build-linux.txt`
- Evidence Vault cryptography: `pip install -r requirements-vault.txt`
- Other integrations: `requirements-optional.txt`, BlackArch/AnonSurf/Firejail, Ghidra, JADX, MISP, CAPE, MobSF, Docker/Podman and scanners not included in the Engine Manager catalog must be provisioned independently. Bandit, oletools and Volatility 3 can be installed with Engine Manager.

Do not install or launch unfamiliar plugins/scanners without reviewing their source, provenance and permissions.

## Upgrade from v1.7.0

1. Stop the old application.
2. Back up `data/`, especially the database and encrypted Evidence Vault.
3. Extract the selected v1.9.9.1 source edition to a new folder.
4. Restore the old `data/` into the source-mode folder only if you want to preserve the entire AIO workspace. Separate compiled editions store independent data profiles.
5. Start the new app and verify cases/evidence before deleting any old copy.

## Dev Studio v1.9.9.1 · Extension Contributions, Multi-DAP & Interactive Terminal

- **Extension Manager:** import VSIX/CFEXT packages as a restricted declarative subset. Themes and JSON snippets can contribute to Monaco; language IDs/extensions are metadata. Executable entrypoints, activation events, Node dependencies/scripts, commands, tasks, debugger and terminal contributions are rejected. There is no arbitrary VS Code Extension Host. See `IDE_EXTENSION_COMPATIBILITY_1.9.9.md`.
- **DAP adapters:** fixed local profiles for Python `debugpy`, C/C++ `lldb-dap`/`lldb-vscode` and .NET `netcoredbg --interpreter=vscode`. Binaries must already be installed and present on PATH (debugpy must be present in CyberForge's Python environment). Debugger and debuggee run with host-user permissions and require explicit approval.
- **Interactive terminal:** native POSIX PTY and optional Windows ConPTY through `pywinpty==3.1.2`. Terminal resize, interactive I/O, bounded buffers, session limits, idle cleanup and process reaping are included. Install the optional Windows dependency with `python -m pip install -r requirements-windows-pty.txt`. Without pywinpty, Windows retains the pipe-backed fallback.
- **xterm UI:** `tools/vendor_xterm.py` fetches pinned xterm.js 6.0.0, FitAddon 0.11.0 and MIT license files, with an asset SHA-256 manifest. The release environment could not access the CDN, so those third-party assets are not included in this source ZIP. Run `python tools/vendor_xterm.py` explicitly with network access to enable the full local xterm UI; without assets the terminal command-input fallback remains.
- Existing Monaco/LSP, Explorer, Quick Open, Command Palette, Git Source Control, AI patch review and all Security Workbench/sandbox modules are retained.

## Validation snapshot · v1.9.9.1

- **632/632 tests passed across 33 isolated test modules**, including 20/20 new v1.9.9.1 extension/PTY/multi-DAP tests.
- Release preflight: 0 failures, 0 warnings; 56 Python files compiled, JavaScript syntax passed, locale JSON parsed, 570 unique HTML IDs.
- POSIX PTY I/O, resize and process reaping were exercised against a real shell on the Linux build host. Existing `clangd` LSP and `debugpy` DAP smoke tests remain in the suite.
- Windows ConPTY requires optional `pywinpty`; it was not executed on this Linux build host. C/C++ `lldb-dap` and .NET `netcoredbg` profiles are discovery-gated and were not live-tested here. Native Windows/macOS binaries are not included.
- xterm.js and FitAddon are pinned with `tools/vendor_xterm.py`, but their third-party assets are not bundled because CDN access was unavailable during packaging. Without vendored assets the command-input fallback remains.
- Arbitrary VS Code extension JavaScript is not executed; Extension Manager accepts only declarative themes, snippets and language metadata. Terminal, LSP and debugger processes use host-user permissions and are not part of the malware sandbox.
- See `TEST_RESULTS_1.9.9.md`, `RELEASE_NOTES_1.9.9.md` and `IDE_EXTENSION_COMPATIBILITY_1.9.9.md` for exact boundaries.

## Validation snapshot · v1.9.2

- 28 language profiles; 21 project templates; 8 project scanner adapters.
- HTML IDs: no duplicates; see `RELEASE_MANIFEST.json` for the exact preflight count.
- 505/505 tests passed across 27 isolated test modules (including 33 new v1.9.2 dynamic-sandbox / offline-AI tests).
- Python compilation, inline JavaScript `node --check`, locale JSON, HTML ID uniqueness and release preflight passed.
- Windows Sandbox guest execution, ETW provider availability and native desktop builds require validation on a supported Windows host; this source build was validated on Linux and cannot launch Windows Sandbox here.
- GPU detection is informational only. No CUDA/ROCm acceleration benchmark was performed.

Native desktop binaries are not included in this source archive. Engine packages are installed separately on user request; plugin packages are installed separately from reviewed ZIP files. See `RELEASE_NOTES_1.9.2.md`, `TEST_RESULTS_1.9.2.md`, `ARCHITECTURE.md`, `EDITION_GUIDE.md`, `USER_CONTROL_AND_PERMISSIONS.md` and `PRIVACY_GUIDE.md`.

## Security scope

Use only projects, hosts and samples you own or are authorized to assess. Review scope before running security scanners, network tools or dynamic-analysis services. Treat all source files, tool output, URLs, log data and retrieved documents as untrusted. Firejail is defense in depth, not a VM boundary. No tool can promise complete anonymity or perfect malware detection.

## v1.8.9 · Beginner help, support reports and resource profiles

### Resource profiles

CyberForge now applies a bounded HTTP request-thread limit. Select a profile before startup:

- `CYBERFORGE_PROFILE=low_memory`: 4 request workers; intended for small RAM systems.
- `CYBERFORGE_PROFILE=balanced`: 12 workers (default).
- `CYBERFORGE_PROFILE=throughput`: 24 workers; monitor memory and storage latency.
- `CYBERFORGE_MAX_WORKERS` optionally overrides the worker count, bounded to 2–64.

Windows PowerShell example (in the same terminal used to launch CyberForge):

```powershell
$env:CYBERFORGE_PROFILE="low_memory"
$env:CYBERFORGE_MAX_WORKERS="4"
.\START_WINDOWS.bat
```

These profiles bound concurrent HTTP requests; they are not operating-system CPU/RAM quotas. GPU inventory is informational only. Core CyberForge UI, SQLite and scanner integrations do not claim GPU acceleration.

### Help and support

- **About** explains the product and safe-use boundaries.
- **Guides & FAQ** explains beginner terminology and common fixes.
- **Bug report** stores a small JSON report locally in `support_reports/`. It is not automatically sent to a remote service. Review the report before sharing; redaction is heuristic and cannot guarantee every secret is removed.

CyberForge remains a loopback, single-user application. Do not expose its HTTP port directly to the Internet or treat it as a multi-tenant server.


## v1.9.0 Security Core (preserved)
- Offline heuristic secure-code advisor, synthetic capacity model and in-memory virtual-agent fleet.
- User-supplied web security-header hardening, local privacy exposure audit and static-only sandbox inspector.
- Original API namespace: `/api/v190/*` remains available.

## v1.9.4 · PCAP Telemetry, Session Orchestration & Local-first AI Analyst

- **Loopback PCAP:** bounded classic-PCAP capture is scoped to the Docker guest's `lo` interface, max 2 MiB / 12,000 packets. Header-only flow parsing produces IPv4/IPv6 TCP/UDP tuples. When `NET_RAW` is not available, capture is marked unavailable; the application does not synthesize a successful PCAP. Raw captures can contain payloads/secrets and are never sent to AI automatically.
- **PID correlation:** sample-side `/proc` socket-inode attribution is best effort. DNS/HTTP/TLS sink records include local and ephemeral peer ports so the analyst can match loopback PCAP flows to the sample process when the socket remains visible. Missing PID is explicitly an attribution gap.
- **Session orchestration:** multiple sessions, separate runs and history; same-session concurrency locks; checkpoint of the staged sample plus latest/last-five reports and PCAP evidence; prevalidated staged restore with reversible swaps; retention cleanup using exact CyberForge container labels. A checkpoint is not a live VM/RAM/disk snapshot. Docker's normal `--rm` and timeout cleanup remain enabled.
- **Run comparison:** compare the same sample across two runs or compare different sessions. Output is a difference of observed telemetry signatures, not a proof that behavior is identical.
- **AI Analyst:** local correlation combines SAST findings with DNS/HTTP/TLS, PCAP-derived flows, process/PID and file events; produces an evidence timeline, static/dynamic correlations, coverage gaps and experimental Sigma templates. Correlation is not causation; Sigma must be reviewed before production.
- **Local-first network assist:** local Ollama/rule analysis stays local. When explicitly enabled for a specific request, OSV lookup sends only ecosystem/package/version metadata to the fixed OSV endpoint; no source code, report or PCAP is uploaded. Online retrieval and local inference are separate operations.
- **Qwen3.8-Max:** added QwenCloud provider with model ID `qwen3.8-max` and OpenAI-compatible regional endpoint. It is paid by default, requires an explicit per-request paid-cost acknowledgement and never acts as a free-tier fallback. API keys remain process-memory only.
- New APIs live under `/api/v194/*`; v1.9.3 and earlier namespaces remain available.

## v1.9.3 · Loopback Network Lab & Free-Tier AI Router

- **Network Simulation Sandbox:** accepts bounded `.py` and `.sh` samples, stages them read-only with SHA-256 identity, then offers an explicit Docker run using `--network none`, read-only root filesystem, read-only sample mount, dropped capabilities, no-new-privileges, PID/memory/CPU limits and bounded `/tmp`. It is a Linux container, not a VM, and shares the Docker kernel.
- **Loopback fake Internet:** a disposable guest-local DNS/HTTP/TLS emulator resolves requested domains to loopback, records DNS names, HTTP method/host/path and TLS ClientHello SNI, then answers with synthetic responses. No Internet route exists. HTTP query values are omitted, request body payload is discarded after hashing a bounded prefix, and TLS is not decrypted.
- **Behavior timeline:** captures new process metadata and `/tmp` changes, plus bounded DNS, HTTP, TLS SNI and selected TCP telemetry. Direct-IP non-loopback attempts cannot be reliably attributed; no packet-payload capture or host-kernel telemetry is claimed.
- **Free-tier AI router:** Gemini API Free tier and OpenRouter free models are supported; Groq is explicitly tier-dependent because Developer-tier usage is priced. OpenRouter models must use the free router or a `:free` model ID; Gemini is restricted to models currently listed with Free-tier pricing. There is no automatic provider/model fallback.
- **Privacy and cost controls:** remote mode is opt-in per request, common secrets are heuristically redacted, API keys stay in process memory only, conversations are process-local, and no key is written to SQLite/logs/browser storage. Redaction cannot guarantee removal of every secret. Keep provider billing disabled; CyberForge cannot inspect an account's billing tier or promise free quotas forever.
- **Offline AI retained:** local Ollama plus rule-based analyst remain available without cloud. A genuine local generative model still requires Ollama and locally installed model weights; none are bundled or silently downloaded.
- New backend namespace: `/api/v193/*`. All `/api/v192/*`, `/api/v191/*` and prior workspaces remain in the shared core.

## v1.9.2 · Offline AI & Dynamic Windows Sandbox

- **Offline AI Workbench:** task profiles for general reasoning/writing, code review, patch planning, malware triage, sandbox analysis, incident response and architecture. When Ollama is already running locally, inference uses only `127.0.0.1:11434` and a locally installed model. No API key or cloud provider is used by this route. No model weights or runtime are bundled or silently downloaded. Without Ollama/model weights, the app falls back to deterministic rule-based analyst features; that fallback is not a generative LLM.
- **Dynamic sample sandbox adapter:** stages a bounded sample in a read-only mapped folder and generates a Windows Sandbox `.wsb` profile with Networking, vGPU and clipboard disabled, a 2 GiB guest memory limit and a bounded 20–120 second observation window. Launch requires an explicit user confirmation and the existing Windows Sandbox feature. CyberForge does not build a custom hypervisor or auto-enable Windows features.
- **Behavior telemetry:** best-effort process/parent-child observations, selected file-system snapshots and changes, selected Run/RunOnce/Winlogon Registry diffs, DNS cache deltas, TCP connection and UDP endpoint snapshots, plus optional ETW providers for process/file/network/DNS/Registry. `tracerpt` CSV is parsed with size/row caps into bounded event metadata and heuristic domain/IP indicators. Sample process tree is asked to terminate at the end of the observation window.
- **Evidence handling:** only named report artifacts are read; report and trace sizes are capped; the session/report path is checked; symlinks and unsupported schema are rejected; returned artifacts are never executed. The writable guest output share remains an untrusted host-write channel and is isolated per session.
- **Important network limitation:** guest Networking is disabled intentionally. This prevents normal Internet delivery, but means CyberForge cannot claim to capture bytes successfully sent to a remote server. ETW/DNS/socket observations are best-effort; provider coverage varies by Windows build. No packet payload is captured/decrypted, and absence of an endpoint is not a benign verdict. A controlled fake-Internet sink/packet-capture VM is a separate future capability, not part of this release.
- Existing v1.9.0/v1.9.1 routes and workspaces remain available. New routes live under `/api/v192/*`.

## v1.9.1 Defensive Engineering Workbench
- **Offline Secure Code Review 2.0:** Python AST checks plus JavaScript/TypeScript, shell and generic configuration patterns. Findings include line, CWE, severity, confidence and remediation. Secret-like evidence is redacted.
- **Web Posture Review:** HSTS, CSP, CORS, frame embedding, content-type, referrer, permissions, COOP/COEP/CORP, server banner and cookie flags. Cookie values are never returned in findings; no web request is sent.
- **Defensive Traffic Simulation:** discrete-time model of legitimate demand and synthetic agent traffic. Configure per-agent rate limits, challenge filtering, caching, queue bounds and service capacity. It sends no packets or HTTP requests.
- **Privacy Exposure Review:** optionally inspects user-supplied browser hints. It does not fingerprint the device or guarantee anonymity.
- **Static Sample Triage:** extends code review with contextual persistence, credential-store, defense-evasion and network/download indicators. Samples are never executed.
- New API namespace: `/api/v191/*`; existing `/api/v190/*` endpoints are preserved. See `RELEASE_NOTES_1.9.1.md`.


## v1.9.5 · Windows Docker Acceptance, Packet Decoder & Approved Security Agent

- **Windows / Docker Desktop diagnostics:** read-only checks inspect Docker CLI/daemon reachability, active container OS, context, WSL status/distributions and Docker Desktop processes when available. Diagnostics never change WSL, firewall, proxy, VPN, Docker Desktop or Windows security settings.
- **Windows acceptance probe:** `tools/windows_docker_acceptance.ps1 -BuildImage` builds the NetLab image on the target Windows machine, then launches one inert `--network none` container. The probe confirms `NET_RAW`, observes a UDP packet on guest `lo`, verifies no default route, and confirms no sample/host folder is mounted. It does not run user samples. Build-time CI cannot claim that this Windows test has passed; the user must run it on the target host. See `WINDOWS_DOCKER_ACCEPTANCE.md`.
- **PCAP / PCAPNG decoding:** offline metadata-only parsing covers classic PCAP, PCAPNG Enhanced/Obsolete/Simple Packet Blocks, interface timestamp resolution/offsets, Ethernet with VLAN/QinQ, RAW IP, BSD NULL, Linux SLL/SLL2, IPv4/IPv6, TCP/UDP, DNS over UDP/TCP, HTTP request/response metadata, TLS ClientHello/ServerHello/alerts and selected handshake metadata. Output is bounded to 2 MiB / 12,000 packets.
- **Deep HTTP/TLS privacy:** request method, redacted path, selected allowlisted headers, response status, content length, SNI, ALPN, cipher suites, extensions, supported groups/signature algorithms, selected TLS version/cipher and a JA3-like SHA-256 fingerprint. Query values, Authorization values, cookies, body bytes, certificate bodies and TLS application data are not exported/decrypted. Captures may contain secrets; raw PCAP is never automatically sent to AI.
- **Capture correctness:** AF_PACKET loopback frames are normalized whether the capture exposes raw IP or a synthetic Ethernet/VLAN header. Unsupported link types and malformed/truncated packets are counted rather than misreported as decoded. PID mapping remains best-effort and must be joined with NetLab socket-owner events.
- **Defensive workflow Agent:** create a multi-step plan, inspect dependencies, select exact plan steps, approve each selected step, execute in plan order, and receive per-step evidence/results. The plan expires after 30 minutes and is one-shot. Separate approvals are required for sample execution, Docker probe and network OSV lookup. Failed steps stop dependent execution; skipped approved steps are reported.
- **User control:** users can choose scope, steps, local/online data paths and each elevated action. The Agent is deliberately not an unrestricted shell/host-control agent: no arbitrary shell strings, arbitrary target scanning, silent network calls, or unattended host changes. This protects the workstation and evidence from prompt injection and untrusted samples.
- **Build/test limitation:** the source build environment did not have Docker Engine, Windows or AF_PACKET host privileges. Unit tests and static checks pass, but live Windows/Docker acceptance remains pending until the supplied PowerShell probe is run on the target system. Docker container isolation is not a VM or formal security certification.
- New APIs live under `/api/v195/*`; all previous namespaces and workspaces remain available.



## v1.9.9.1 · Localization and error handling fixes

- Fixed stale text/attribute translations when switching languages and batched DOM translation updates to avoid observer churn.
- Added the same 24 localized application error codes and permission-confirmation prompts to all 12 locale catalogs.
- Normalized JSON, binary-upload and common read request errors to the active interface language. Raw stack traces, file paths, code, protocol identifiers and third-party scanner output remain verbatim.
- The 12 catalogs now share an identical message-key set. This is catalog completeness, not a claim that every advanced technical sentence has a human-reviewed translation. Run `python tools/i18n_check.py` to view actual authored translation coverage.
- To draft the remaining untranslated UI strings locally, install/run Ollama and use `python tools/translate_catalogs.py --model qwen2.5:1.5b --languages en,vi,es,fr,de,pt,ja,ko,zh,ru,ar,hi --apply`. This contacts only a local Ollama endpoint (`127.0.0.1`), sends app-owned UI strings rather than project/user content, and should be followed by manual review and `python tools/i18n_check.py`. The translation tool does not auto-install a model or contact a cloud provider.

## v1.9.9.1 · Modern UI, Internationalization & System Settings

- Redesigned the shared application shell with a cohesive dark/light design system, responsive navigation, improved cards/forms/tables, and reduced visual noise while retaining existing workspace IDs and workflows.
- English is the default locale for fresh installations; existing saved locale preferences are preserved. Bundled locales: English, Vietnamese, Spanish, French, German, Brazilian Portuguese, Japanese, Korean, Simplified Chinese, Russian, Arabic (RTL), and Hindi.
- Core navigation, settings and common controls are translated. Advanced diagnostic output and some third-party tool output may remain English.
- Added System Settings for application appearance/language, application runtime/data location, read-only machine inventory, detected tool presence, OS settings handoff through a fixed allowlist, diagnostics and database backups.
- Opening OS settings uses the existing `host_app_launch` capability and asks for one-time approval when policy is Ask. CyberForge does not write system registry/preferences directly.

See `RELEASE_NOTES_1.9.9.md`, `TEST_RESULTS_1.9.9.md` and `I18N_GUIDE.md`.
