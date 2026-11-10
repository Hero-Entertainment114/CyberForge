# CyberForge AIO v1.9.2 — Release Notes

## What's new

### Offline AI Workbench
- Adds a separate offline assistant route for general reasoning/writing, code review, patch planning, malware triage, dynamic sandbox report analysis, incident response and architecture.
- Uses the local Ollama service on `127.0.0.1:11434` only when it is already available, with model selection from its local `/api/tags` inventory and `/api/chat` inference. No API key, cloud route or silent download is used.
- If no local LLM/model exists, built-in rule-based review and playbooks remain available. This fallback is deterministic and is not a generative LLM.
- AI output is advisory. It does not automatically write project files or execute generated code. Existing cloud AI workbench is preserved as a separate feature.

### Dynamic Windows Sandbox
- Adds a staging/launch/report workflow around the existing Windows Sandbox feature. CyberForge does not implement a custom hypervisor and does not enable Windows features on the user's behalf.
- Uses a read-only sample share and read-only collector share. Per-session result share is writable so the guest can return telemetry; treat everything written there as untrusted.
- Disables guest Networking, vGPU and clipboard redirection, enables Protected Client, and configures 2 GiB guest memory. The user explicitly stages and launches a session; the sample is never executed on the host by these new routes.
- Observation window is 20–120 seconds (default 45 seconds), sample limit is 10 MiB. Supported formats: EXE, COM, SCR, BAT, CMD, PS1, VBS and JS.
- Best-effort collection: process starts and parent/child hints; file changes under bounded Temp/AppData/Startup/Downloads/Documents/ProgramData/Windows Temp roots; selected Run/RunOnce/Winlogon Registry diffs; DNS cache changes; TCP connections and UDP endpoint snapshots; optional ETW for process, file, TCP/IP, DNS and Registry.
- Guest `tracerpt` CSV is parsed with byte/row/event bounds and contributes event metadata plus heuristic domains/IP addresses. The guest sample process tree is asked to stop when the window expires.
- Reports are schema checked and size/path bounded. Symlinks are rejected. CyberForge never executes or imports returned artifacts.

## Important boundaries

- Guest network is disabled intentionally. The collector cannot inspect successful Internet delivery or capture/decrypt packet payloads. ETW/DNS/socket visibility is best effort and varies by Windows build. An absent domain, IP, socket or event is not evidence that the sample is harmless.
- A separate controlled fake-Internet sink / network-observation VM is not included in this version. Enabling the guest's ordinary networking would not be an acceptable substitute for isolation.
- Windows Sandbox must already be supported and enabled on a suitable Windows edition. This source release was not executed inside Windows Sandbox in the Linux build environment.
- A writable mapped output directory is a host write channel. It is isolated per session, but may receive attacker-controlled files. Do not open or run files from it. Review and remove the session only after preserving required evidence.
- A truly generative offline model requires local model weights and an inference runtime. CyberForge does not bundle large weights or download them in the background. Ollama and a suitable model must already be installed locally; otherwise only the non-generative offline analyst fallback is available.
- No native EXE/APP binary is included in the source ZIP.

## Compatibility

- Python core uses standard-library helpers for v1.9.2; no new third-party runtime package is required for the new routes.
- Dynamic detonation adapter: Windows only, dependent on the existing Windows Sandbox component.
- Offline generative inference: optional local Ollama on loopback; model size/speed depend on host memory and CPU/GPU.
- Existing v1.9.0 and v1.9.1 routes are preserved.
