# CyberForge AIO v1.8.6 — Architecture

## Overview

```text
┌──────────────────────────────────────────────────────────────┐
│ Dev Edition          AIO Edition          Cybersecurity Ed.   │
│ IDE / Toolchains     All workspaces       Security operations │
└──────────────────────────────┬───────────────────────────────┘
                               │ shared UI / edition profile
┌──────────────────────────────▼───────────────────────────────┐
│ HTML / CSS / JavaScript · 25 pages · loopback HTTP API       │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ Python service · permission matrix · allowlisted adapters   │
├──────────────────────┬─────────────────────┬──────────────────┤
│ Dev Studio           │ AI Control Plane    │ Security Engine  │
│ projects/editor/Git  │ Qwen/xKiro planner  │ scan/DFIR/RE      │
│ syntax/task/patch    │ multi-agent/RAG     │ privacy/connectors│
└──────────────────────┴─────────────────────┴──────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ SQLite · evidence vault · project files · local knowledge    │
└──────────────────────────────────────────────────────────────┘
                               │ optional local/external tools
┌──────────────────────────────▼───────────────────────────────┐
│ Bandit/Gitleaks/Semgrep/Trivy/Checkov/Syft/Grype/ClamAV      │
│ Ghidra/JADX/Rizin/Volatility/Firejail/BlackArch/AnonSurf     │
│ CAPE/MobSF/MISP · Docker/Podman · QwenCloud/xKiro            │
└──────────────────────────────────────────────────────────────┘
```

## Edition loading

`edition.json` (or explicit `CYBERFORGE_EDITION`) accepts `aio`, `dev` or `security`. The UI filters navigation/page targets through `initializeEdition()`. The API `/api/edition` reports the active edition. Frozen builds bundle an edition-specific manifest and use edition-specific OS user-data paths. Source-mode data stays within the selected extracted folder's `data/` directory.

## Dev platform

- `LANGUAGE_TOOLCHAINS`: 28 language/container/IaC profiles used for tool/runtime/LSP/formatter discovery.
- `DEV_PROJECT_TEMPLATES`: 21 project scaffolds.
- Project path helpers constrain file operations to the selected project root and reject traversal/symlink escapes.
- Editor operations use expected SHA-256 values to reject stale writes.
- Workspace export creates `.editorconfig`, `.code-workspace` and VS Code recommendations without installing or executing extensions.
- Syntax checks call fixed local parsers/compilers where available; absent tools produce explicit unavailable/unknown results.
- AI patches are generated as proposed content, diffed into hunks, individually accepted/rejected and applied with hash checks.

## Cybersecurity assessment of a selected Dev project

`run_project_security_assessment()` accepts 1–8 scanner IDs from `SECURITY_SCANNERS`, a project ID from the local Dev Studio inventory, no remote target and no arbitrary command arguments. It traverses the selected project under file-count and byte-size limits. Scanner commands use fixed argument arrays, `shell=False`, restricted child environment and timeouts. Trivy/Grype avoid automatic database updates; Semgrep requires local rules. The AI Navigator adapter is opt-in, binds project ID and scanner IDs to the user's selection, runs with AI summarization and report persistence disabled, and returns actual scanner status/counts. Only a separate optional cloud-synthesis step can receive a minimized whitelist summary.

## AI orchestration

- AI planner output is parsed as strict JSON and validated against `AGENT_TOOL_SPECS`.
- Every tool argument passes `_agent_clean_args`; the planner cannot add arbitrary commands, paths, targets or scanners.
- Plan execution capabilities are calculated dynamically by `_agent_plan_capabilities()` and enforced through Allow/Ask/Deny at the backend.
- Project security assessment additionally requires explicit Navigator opt-in, selected project and selected installed scanner set. The AI cannot expand the scanner set.
- The result sanitizer removes scanner stdout/stderr and raw source/file contents. Cloud synthesis is sent only after the explicit consent checkbox.
- AI providers are QwenCloud/xKiro OpenAI-compatible APIs; real API use requires user's credentials.

## Compatibility

Compatibility is adapter-based rather than an attempt to bundle all upstream tools. The app detects installed IDEs/toolchains/extensions and invokes specific fixed adapters where implemented. Extension manifests are read-only metadata. No arbitrary third-party extension code is loaded into CyberForge.

## Local security

The service binds to `127.0.0.1` and selects a free port by default. Host/Origin checks mitigate unintended cross-origin access. Permissions are checked in backend routes. The UI is not designed for public Internet exposure. Cloud AI, search providers, threat-intelligence connectors and dynamic-analysis services can receive selected data when enabled; each has a separate policy/confirmation path.

## Build

`build_windows.py --edition aio|dev|security` uses PyInstaller `onedir`, includes static assets, plugin manifests and the edition manifest. Build on Windows; the Linux source release does not include prebuilt Windows binaries. GitHub Actions uses a three-edition matrix.


## Native desktop packaging (v1.8.6)

`desktop_entry.py` starts the same local-only Python service used in source mode and presents the UI in the host OS WebView through pywebview. `build_desktop.py` is host-native: Windows uses the WinForms / EdgeChromium backend, macOS uses Cocoa / WebKit, and Linux uses Qt WebEngine. The builder rejects a requested platform that differs from the running host OS.

PyInstaller one-directory output is used for Windows/Linux; macOS produces a `.app` bundle. Each build runs the frozen executable with `--self-test` to check that `static/index.html`, `plugins/` and `edition.json` are available in the bundle. Data stays outside the application directory in OS-specific user profiles.

This is a native desktop shell around the existing web UI, not a rewrite into native widgets. The dashboard also exposes process/resource metrics for the CyberForge process only (PID, uptime, CPU time/average, thread count and memory RSS/peak); it does not enumerate or control unrelated host processes. The source release does not include prebuilt binaries, code signing, notarization, OS installers, or a live auto-update/rollback channel. WebView runtimes and native system libraries remain host prerequisites. A signed update channel requires a configured release repository and maintainer-held signing key before automatic replacement can be enabled safely.

## Engine and plugin lifecycle management

Engine Manager uses a fixed package/version catalog (`ENGINE_CATALOG`) and stores each version in a dedicated virtual environment at `DATA_DIR/engines/<engine-id>/<version>`. It invokes the managed interpreter with a fixed pip argument list (`shell=False`), binary wheels only, explicit PyPI index and bounded timeout. The database records active version and executable path; resolution checks the executable remains inside its registered version directory. Versions can be switched or removed independently. Venvs are created at their final paths because console-script shebangs can embed absolute interpreter paths and a virtual environment should not be relocated.

Plugin Manager accepts a size-limited flat ZIP containing a JSON manifest, one root Python entrypoint and optional README. It rejects traversal, symlinks, duplicates, directories, encrypted entries and files outside the allowlist. Only DB-registered installed packages are enumerated. Updates replace package code and reset the plugin to disabled with empty grants. Plugin source is not imported by the host process; the existing container runner launches it with no network, read-only filesystem/mount, dropped capabilities and resource limits. The SHA-256 field is an integrity check, not publisher authentication.


## Localization (v1.8.6)

- Locale catalogs are bundled under `locales/` and loaded only through the allowlisted `/api/i18n/<locale>` endpoint for the twelve codes in `SUPPORTED_LOCALES`. Catalogs are validated for locale identity, message object type and bounded entry count; fresh/reset profiles default to English while valid saved locale selections are preserved.
- `localization.locale` is part of the validated local app-preference profile. Older profiles without this group receive the Vietnamese default; import/export/reset preserve or restore the setting as expected.
- The client translation observer handles text nodes and safe presentation attributes in both initial and dynamically rendered panels. It does not translate script/style, code/pre blocks, textareas, SVG or user-entered field values.
- The catalogs use exact-source message matching for compatibility with current server-rendered and template-generated UI. Technical product names, language names, file paths, commands, IDs and security standards remain unchanged.
- Only `vi` and `en` are enabled in v1.8.6. The additional languages listed in the product roadmap require reviewed locale catalogs and separate coverage tests before being enabled.

## System integration and recovery (v1.8.6)

- `system_health_report()` provides a bounded health snapshot for SQLite integrity/foreign keys, storage, audit chain, managed engines, installed plugin integrity, optional dependencies and recovery backups. It reports; it does not perform automatic repair.
- SQLite schema migration repairs duplicate active managed-engine rows and enforces at most one active version per engine through a partial unique index.
- Managed plugin operations are serialized by a process-local reentrant lock. Installs write archive and per-file SHA-256 metadata. Execution verifies the exact file set and content; old packages without a file manifest remain `legacy_unverified` for compatibility.
- Uninstall moves the managed directory into a generated quarantine path before database removal, with a best-effort directory rollback on transaction failure.
- Recovery snapshots use SQLite online backup and are independently checked with `integrity_check`, `foreign_key_check` and SHA-256. Retention is limited to eight generated backup files. Snapshot scope is SQLite only; evidence blobs, vault keys, projects, engines and plugin directories are excluded. No automated restore operation exists.
- Maintenance allows verification or WAL checkpointing only. The service never automatically deletes user data to make a health check pass.
- HTTP failures carry a request ID. Expected client errors remain specific; unexpected failures return a generic response while diagnostic details go to a rotating local log. Access logs omit query strings and request bodies.


## Defensive Engineering Workbench (v1.9.1)

- `v191_modules.py` is a pure, deterministic local analysis module. It has no third-party dependencies, network clients, execution hooks or file-system writes.
- `/api/v191/ai/review` provides bounded multi-language static rules with source-line evidence, CWE mapping and remediation text. Evidence matching common secret formats is redacted before the response.
- `/api/v191/web/posture` accepts caller-supplied HTTP headers and cookie strings only. It does not fetch the website and redacts cookie values from evidence.
- `/api/v191/lab/defense` is a bounded discrete-time queue model. It does not open sockets, construct protocol packets, create real agents or contact targets.
- `/api/v191/privacy/posture` reads only the optional values supplied by the user. It performs no device fingerprint scan or OS network changes.
- `/api/v191/sandbox/triage` is static-only; no sample is executed, imported, unpacked or sent outside the application. It is not malware detonation.
- All v1.9.1 POST endpoints are mapped to the existing `static_analysis` capability and use the standard Allow/Ask/Deny policy and scoped acknowledgement mechanism.
- The v1.9.0 Security Core and `/api/v190/*` routes remain available for backward compatibility.


## Offline AI & Dynamic Windows Sandbox (v1.9.2)

- `v192_modules.py` supplies the local AI backend and a Windows Sandbox adapter. The adapter uses Microsoft's existing disposable guest runtime; it is not a custom hypervisor. It is available only when `WindowsSandbox.exe` is present on a supported Windows host.
- Staging writes the sample as an immutable/read-only input mount, the collector tools as a read-only mount, and a per-session writable output share. The `.wsb` profile disables guest networking, vGPU and clipboard redirection and sets a bounded guest memory budget. The output share is an untrusted write boundary: a sample may create malicious files there. CyberForge parses only named, size-capped artifacts and never executes or imports returned content.
- Guest telemetry is best effort: WMI process snapshots with parent IDs, selected filesystem snapshot deltas, selected persistence Registry diffs, DNS cache deltas, TCP connections, UDP endpoints and optional ETW providers. `tracerpt` CSV is parsed as untrusted data with an 8 MiB byte cap and 40,000-row ceiling. Extracted domains/IPs are heuristic metadata, not verified remote deliveries or packet captures. No packet payload is collected. A sample's network remains disabled; lack of observed endpoints is inconclusive.
- The collector requests termination of the sample process tree when the observation window ends. ETW provider availability, command telemetry and filesystem coverage vary with Windows build; a native Windows Sandbox run is required to verify real guest behavior.
- Offline AI uses a local Ollama HTTP API only at `127.0.0.1:11434`. Model enumeration calls `/api/tags`; chat calls `/api/chat`. No cloud provider or API key is used by this path. No runtime or model weights are bundled/downloaded. If no model is installed, the deterministic local analyst rules remain available and are explicitly not represented as a generative LLM. Conversation context is process-local and bounded; no project file is changed automatically.


## Loopback Network Lab & Free-Tier AI Router (v1.9.3)

### Network lab lifecycle

`user-selected .py/.sh → bounded base64 upload → dedicated session/input (read-only, SHA-256) → explicit acknowledgement → Docker image build (base image only) → disposable --network none container → local loopback DNS/HTTP/TLS emulators → bounded JSON report → local/offline AI analysis`

- The build context contains only the bundled runner and Dockerfile; the selected sample is mounted separately at run time and is not sent to the image builder or an external scanner.
- Runtime restrictions include `--network none`, `--read-only`, a read-only bind mount, `--cap-drop ALL` with only `NET_BIND_SERVICE` restored for the root-owned emulator, `no-new-privileges`, a bounded PID/memory/CPU budget, and a `noexec,nosuid,nodev` temporary filesystem. The sample itself runs as the unprivileged `nobody` account.
- DNS A/AAAA requests are observed by a local UDP/TCP DNS emulator and resolve to loopback. HTTP requests record method, host and path without query values; only a bounded body prefix is hashed and discarded. TLS captures only ClientHello SNI and returns an alert; it does not decrypt TLS. Selected local TCP ports have simple observation sinks.
- A bounded `/proc` process snapshot and `/tmp` metadata delta add process and temporary-file context. This is best-effort telemetry, not a syscall-level or kernel-level monitor. Direct-IP non-loopback attempts cannot be fully attributed.
- The sample mount has no writable output share. Reports are generated by the runner and returned over stdout, bounded and schema-checked. Session paths, sample hash and symlink boundaries are validated before use.
- **Trust boundary:** Docker containers share the host Linux kernel. Do not use this lab for kernel exploits, drivers, firmware, Windows PE, or high-risk unknown malware. Use a disposable VM with snapshots and a dedicated virtual network when a stronger boundary or packet-level observation is required.

### AI routing

- Offline remains the default. Ollama is contacted over loopback only; the deterministic analyst remains available when no local model is installed.
- Remote providers are explicit and per-request: Gemini API Free tier, OpenRouter free-model router / `:free` identifiers, and Groq (tier-dependent). Each remote call requires separate data-transfer consent and an acknowledgement that the exact account/model is $0 with paid billing disabled. Arbitrary provider base URLs are not accepted.
- API keys are held in process memory only. Prompt/context redaction is heuristic and cannot guarantee every secret is removed; remote mode requires an explicit consent flag and standard capability policy. Knowledge-base excerpts are forwarded only when separately selected.
- Conversations are process-local and bounded. There is no automatic fallback to another provider/model and no model ID outside the supported free-model policy for OpenRouter/Gemini. Groq may incur charges if the user's external account is on a paid tier; CyberForge cannot read that billing state.
- Free tiers have quotas, model availability restrictions, regional eligibility and provider-specific privacy/retention terms. A genuine, unlimited, always-free online model cannot be guaranteed by the application.


## PCAP Telemetry, Session Orchestration & Local-first AI Analyst (v1.9.4)

### Loopback-only packet telemetry

- `sandbox/netlab/netlab_telemetry.py` opens Linux `AF_PACKET` only on the container's `lo` interface. It is bounded to 12,000 packets and 2 MiB, writes classic PCAP (DLT_RAW) and parses only IPv4/IPv6 TCP/UDP headers for flow tuples. It does not decrypt TLS or infer remote delivery.
- Docker runtime adds `NET_RAW` for the collector. The sample still runs as `nobody`; its process has no Linux capabilities. If the host/runtime denies raw packet access, the report marks PCAP unavailable and continues with sink-level telemetry.
- The loopback DNS/HTTP/TLS sinks log sample-side peer/local ports. `/proc/net` socket inodes are matched against `/proc/<pid>/fd` best-effort; PCAP 5-tuples are enriched with PID/process when a matching sink event exists. Short-lived sockets and host policy can leave attribution unavailable.
- Raw PCAP is stored separately from JSON reports and never appended to AI prompts. PCAP may still contain credentials or request payloads, so it remains local evidence and should be handled as sensitive data.

### Session and evidence lifecycle

- Distinct session IDs allow independent work. A process-local lock prevents conflicting operations inside one session while allowing other sessions to run concurrently.
- A checkpoint contains the staged sample, latest evidence and up to five recent run artifacts. It is an evidence/staging checkpoint, not a hypervisor snapshot or live memory image.
- Restore validates session binding, sample SHA-256, report schemas, PCAP magic/size, allowed run IDs, symlinks and path containment before preparing a replacement tree. It stages replacements and uses same-filesystem swaps with best-effort reverse rollback on commit failure.
- Per-run containers use `--rm`, timeout kill/remove and fixed CyberForge labels. User-triggered retention cleanup only targets matching session directories and containers; active in-process operations are skipped.
- Run comparison uses timeline signatures and can compare two run IDs inside one session or runs from separate sessions. It reports differences, not equivalence or proof of behavior.

### AI correlation and network assist

- `v194_modules.py` accepts bounded supported static findings plus the dynamic report schema, uses the timeline as the canonical event stream, correlates observed endpoints/process/file activity and emits an experimental Sigma template. It never loads or parses raw PCAP bytes.
- The analyst labels direct IOC matches separately from category-only correlation. Static/dynamic correlation is not proof of causality; absent telemetry is not a clean verdict.
- Local-first inference continues to use Ollama on loopback or a deterministic rule fallback. Optional OSV assistance is a separate fixed-host HTTPS request sending only ecosystem, package name and version after per-request consent. It does not send project source, sandbox JSON or PCAP.
- QwenCloud `qwen3.8-max` is an opt-in paid provider using a regional OpenAI-compatible API base. Remote mode requires data-transfer consent; Qwen separately requires paid-cost acknowledgement. It is not represented as a free provider and there is no provider fallback.


## v1.9.5 runtime validation, decoding and agent workflows

- Docker Desktop diagnostics are read-only and distinguish Windows host, Linux engine, context and WSL data. Windows host NIC capture and Linux-container `lo` capture are separate visibility planes.
- The target-host PowerShell acceptance probe builds/uses the pinned NetLab image and runs only an inert built-in probe under `--network none`, `--cap-drop ALL`, `--cap-add NET_RAW`, `no-new-privileges`, read-only rootfs, bounded PID/memory/CPU and a bounded tmpfs. It creates a loopback UDP datagram, observes it through AF_PACKET and checks there is no default route. It mounts no sample or host path.
- PCAP and PCAPNG decoding is offline, bounded and metadata-only. PCAPNG interface timestamp resolution/offsets are honored. Decoder supports classic PCAP, PCAPNG SPB/EPB/obsolete Packet Block, Ethernet/VLAN/QinQ, RAW, BSD NULL, Linux SLL/SLL2, IPv4/IPv6, TCP/UDP, DNS, HTTP/1 metadata, and visible TLS handshake metadata. No HTTP bodies, cookie/authorization values, query values, certificate bodies or TLS application data are returned.
- TCP stream reassembly is directional, bounded and best-effort; out-of-order/overlapping packets can limit application metadata. HTTP/2 and HTTP/3 encrypted application content is not decoded; TLS is never decrypted.
- Defensive Agent plans are deterministic and non-executing until approval. Plans are one-shot and expire after 30 minutes. Execution is restricted to allowlisted steps with exact step IDs, dependency approval and extra confirmation for sample execution, Docker smoke test and external OSV lookup. No arbitrary shell, unscoped network target or unattended host control is exposed.
- Docker containers share the Linux kernel and are not treated as VMs. The target-host acceptance script is a capability smoke test, not a formal isolation or escape-resistance certification.


## v1.9.6 Dev Studio IDE workbench

- The UI remains a loopback-served HTML application. Monaco Editor is loaded from a local vendored `static/vendor/monaco/min/vs` distribution when present, otherwise from a pinned CDN; if neither is available, the built-in editor remains functional. `tools/vendor_monaco.py` performs bounded, path-validated extraction of the upstream MIT package for offline use. The pinned AMD loader is deprecated upstream and is isolated behind `loadMonacoEditor()` so an ESM migration can replace it later.
- Monaco models use per-project/per-file URIs to preserve multi-tab model state, diagnostics and language modes. Built-in editor language services are available for supported Monaco languages. Installed LSP executables are inventoried, but a full LSP client, VS Code extension host and DAP debugger are not included.
- The Explorer consumes the existing bounded project tree. Folder collapse is client-side; file and folder rename uses checked project-relative paths. Delete moves content into hidden `.cf-trash` with a tokenized metadata record and explicit restore. `.cf-trash` is excluded from project search/tree/AI context.
- Integrated terminal sessions run a persistent, pipe-backed host shell with bounded buffers and idle cleanup. Each session is bound to a project working directory and access-controlled by `code_execution`. It is not sandboxed, not a PTY/ConPTY and does not support full-screen TUI programs. Terminal commands may access the host user's files/network according to OS permissions.
- Existing static syntax diagnostics, Git allowlist, multi-file AI patch review and toolchain inventory remain separate capabilities. Shell execution is not silently invoked by AI patches or background analysis.


## v1.9.7 Dev Studio protocol providers

- `v197_modules.py` implements a bounded Content-Length transport for LSP JSON-RPC and DAP messages. It uses fixed executable profiles discovered from PATH / the active Python environment; it does not accept arbitrary adapter executables or command-line arguments. Frames are capped at 8 MiB, event queues are bounded, request timeouts are enforced, and server-initiated workspace writes / DAP reverse requests are rejected.
- Language servers run as local host processes and can read their selected project. Starting an LSP profile requires a `code_execution` grant. The backend exposes only selected language-service methods; document paths are workspace-contained and reject traversal, secret files and symlinks. Workspace edits are returned for review, not applied automatically.
- The Python DAP adapter is fixed to `python -m debugpy.adapter`. Only `.py` / `.pyw` targets inside the selected project are accepted. Debuggee execution, expression evaluation and variable mutation can run arbitrary project code with the OS user's permissions; launch and sensitive debugger actions require explicit approval. This is not the malware sandbox.
- Git Source Control performs fixed local Git operations. Stage/unstage only accept explicit bounded project-relative paths. Hooks and GPG signing are disabled; external diff/pager are disabled; repository config/includes and `.gitattributes` filters are inspected and unsafe mutating operations are refused. No push/pull or arbitrary Git command is available.
- This is a protocol-provider architecture, not a VS Code Extension Host. Arbitrary `.vsix` extension code is not executed.


## v1.9.8 Dev Studio extensions, DAP profiles and PTY

- Extension Manager imports VSIX/CFEXT as a restricted declarative subset. ZIP entries, symlinks, paths, duplicate names, compressed/unpacked size and manifest contribution types are validated. Only theme/snippet assets and language metadata are retained. No extension script, Node entrypoint or activation hook is executed; this is not a VS Code Extension Host.
- Multi-DAP uses fixed stdio profiles for `debugpy`, `lldb-dap`/`lldb-vscode` and `netcoredbg --interpreter=vscode`. Provider binaries are discovered locally and are not downloaded. The debugger and debuggee run with host-user permissions after explicit approval.
- Integrated terminal uses native POSIX PTY or optional Windows ConPTY (`pywinpty`). Input/output is bounded; sessions have limits and idle cleanup. POSIX close terminates the entire process group and reaps the shell. This is an interactive host shell, not a sandbox.
- xterm.js and FitAddon are pinned by `tools/vendor_xterm.py`, which can download the MIT-licensed browser assets and write a SHA-256 manifest. The third-party assets are not prebundled in this source archive.
