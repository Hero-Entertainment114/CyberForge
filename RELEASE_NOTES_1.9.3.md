# CyberForge AIO v1.9.3 — Loopback Network Lab & Free-Tier AI Router

## Highlights

### 1. Loopback Network Simulation Sandbox
- Adds a disposable Docker runtime for `.py` and `.sh` samples (maximum 2 MiB, observation window 5–120 seconds).
- Stages each sample in a dedicated session, calculates SHA-256, makes the input read-only and validates its path/hash again before launch.
- Runs only after explicit per-session confirmation. The Docker command uses `--network none`, a read-only root filesystem, a read-only sample mount, dropped Linux capabilities (only `NET_BIND_SERVICE` restored for the root-owned telemetry emulator), `no-new-privileges`, bounded CPU/RAM/PIDs and a bounded `noexec,nosuid,nodev` `/tmp`.
- The runner starts an isolated loopback DNS/HTTP/TLS emulator. It records DNS names, HTTP method/host/path (not query values), a bounded request-body hash (not the original body), TLS ClientHello SNI (not decrypted payload), selected TCP metadata, newly observed processes and temporary-file metadata.
- The sample runs as unprivileged `nobody`. No output directory is shared back to the host. The structured report is size-bounded, schema-checked and stored locally.

### 2. AI Workbench
- Keeps offline as the default. Existing local Ollama integration and deterministic offline analyst remain available.
- Adds Gemini API Free tier and OpenRouter free-model support. OpenRouter is restricted to `openrouter/free` or explicit `:free` model IDs. Gemini is restricted to model IDs currently published with a Free tier.
- Groq is available but marked **account-tier dependent**. Groq Developer tier publishes paid token pricing; CyberForge cannot inspect a user's billing tier. Do not upgrade or add billing if zero-cost usage is mandatory.
- Remote requests require both a per-request data-transfer consent and a separate acknowledgement that the selected account/model is genuinely on a $0 tier with paid billing disabled. The selected provider is the only provider called. There is no paid provider/model fallback.
- API keys remain in process RAM, are not written to SQLite, browser storage or logs; conversations are process-local. Heuristic redaction covers common secret formats but cannot guarantee detection of every secret.

## API additions

- `GET /api/v193/ai/status`
- `POST /api/v193/ai/config`
- `POST /api/v193/ai/clear`
- `POST /api/v193/ai/chat`
- `GET /api/v193/sandbox/netlab/status`
- `GET /api/v193/sandbox/netlab/report?session_id=...`
- `POST /api/v193/sandbox/netlab/prepare`
- `POST /api/v193/sandbox/netlab/build`
- `POST /api/v193/sandbox/netlab/run`

The older `/api/v190/*`, `/api/v191/*` and `/api/v192/*` namespaces remain available.

## Important limitations

- The network lab is a Linux Docker container, **not a VM**; it shares the Docker host Linux kernel. Do not use it for kernel exploits, drivers, firmware, Windows PE, or high-risk samples.
- No Internet route is provided. DNS/HTTP/TLS interactions are with loopback emulators only. Direct-IP attempts to non-loopback addresses fail and are not fully attributed.
- TLS is not decrypted, packet payloads are not captured, and the runner does not provide kernel-level syscall tracing or host-wide process/file monitoring.
- A Docker image build may download the official Python base image, but does not include or upload the selected sample.
- Free model quotas, model availability, privacy terms, regional eligibility and provider terms can change. Gemini Free-tier prompts may be used to improve Google products. OpenRouter free variants have usage limits. The app cannot guarantee an online provider remains free forever.
- A real offline generative LLM still requires a local runtime and downloaded model weights. No large model weights are included in this source archive.
- Native Windows/macOS/Linux binaries are not included. A native Windows Docker execution test was not possible in this build environment.
