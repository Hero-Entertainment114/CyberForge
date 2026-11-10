# CyberForge AIO v1.9.0

## Security & AI Lab
- Added offline heuristic secure-code review for common secret, SQL, shell, TLS, CORS, debug and weak-hash patterns.
- Added a synthetic capacity/availability model. It performs arithmetic only and sends no network traffic.
- Added an in-memory virtual-agent fleet to model bot-like event bursts without controlling real devices.
- Added web security-header hardening review based on headers supplied by the user.
- Added local privacy exposure audit with explicit non-anonymity guarantee.
- Added static sandbox inspection. Submitted samples are never executed by this new module.
- Added `/api/v190/capabilities` and `/api/v190/*` endpoints plus a new UI workspace.

## Important scope and limitations
- This is not a real DDoS tool, botnet, remote agent, exploit framework, or internet-wide scanner.
- Offline AI is a deterministic heuristic advisor, not a hosted large language model. API-key-free hosted inference is not guaranteed; users may configure a provider separately in a future adapter.
- Privacy audit detects selected exposure signals; it cannot hide a device or guarantee anonymity.
- Static sandbox inspection is not an OS-level VM/container. Do not use it as a detonation environment for malware.
- Existing Dev Studio and security modules are preserved; this release adds a focused lab layer rather than replacing every subsystem.
