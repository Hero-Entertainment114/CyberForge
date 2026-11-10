# CyberForge AIO v1.9.4 Release Notes

## Highlights

- Bounded loopback PCAP capture and TCP/UDP flow parsing in the Docker network namespace.
- Best-effort sample process attribution through socket inodes, plus DNS/HTTP/TLS port correlation.
- Multi-session orchestration, multi-run history, run comparison, evidence checkpoints, safe staged restore and retention cleanup.
- Static/dynamic AI Analyst correlation, process/PID map, event timeline, telemetry gaps and experimental Sigma templates.
- Local-first AI with opt-in OSV package metadata enrichment.
- QwenCloud Qwen3.8-Max (`qwen3.8-max`) paid API provider with separate cost and data-transfer consent.

## Important operating boundaries

- NetLab is a Docker Linux container using `--network none`, not a VM; it shares the Docker host kernel.
- PCAP requires host/runtime `NET_RAW`. If unavailable, CyberForge shows capture unavailable and does not create a fabricated capture result.
- PCAP is raw loopback packet data and may contain sensitive content. It is not included in AI contexts or remote requests.
- PID attribution is best effort; short-lived sockets may not be attributable.
- Checkpoints preserve staged sample and bounded evidence, not guest RAM, live process state, or a VM disk image.
- Qwen3.8-Max is paid by default. Verify current regional price/account billing before use; it is not a free-tier model.
- Source release only. No native EXE/APP or verified Docker image is embedded.

See `TEST_RESULTS_1.9.4.md` and `ARCHITECTURE.md` for validation and design details.
