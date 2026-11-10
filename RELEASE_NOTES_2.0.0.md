# CyberForge Server Edition v2.0.0

## Release type

First Linux-only Server Edition release, separated from CyberForge AIO Desktop v1.9.9.1. The previous Desktop source branch is not overwritten by this release.

## Major capabilities

- Linux control plane with loopback-only HTTP listener, Host allowlist, bounded concurrent requests and systemd hardening.
- Browser dashboard with management branches for fleet, AI, security, observability, infrastructure, integrations, workflows, audit and system status.
- Linux node enrollment, per-node bearer token hashes, timestamp/nonce replay defense, read-only bounded telemetry agent and credential revocation.
- API RBAC roles: admin, operator, analyst and viewer.
- SQLite WAL state store, bounded local backups, audit hash chain and audit integrity verification.
- Multi-deployment OpenAI-compatible AI adapter for Ollama, vLLM, llama.cpp, LiteLLM and other compatible endpoints; up to 32 configured deployments.
- AI paid-call controls: explicit enablement, HTTPS, exact host allowlist, environment-only API key, configured token prices, max-request ceiling, daily budget and atomic spend reservations.
- 43 integration catalog entries spanning AI serving, observability, security operations, application security, infrastructure, databases, commercial services and cloud providers.
- 17 fixed read-only HTTP health adapters. Other integrations are inventory/documentation metadata only.
- Explicit workflows: plan, approval, expiry and execution for a small built-in allowlist of diagnostic/backup steps.
- Caddy and Nginx reverse-proxy examples; systemd installation and node-agent installation scripts.

## Important boundaries

- Control plane and node agent are Linux-only. No Windows/macOS server runtime is included.
- Only the control plane is a server; it is currently a single control-plane instance, not an HA/distributed cluster.
- Node agent sends read-only telemetry and selected allowlisted service states. No remote shell, script execution, package installation, firewall change or service mutation is supported.
- The control plane is not a new LLM inference engine. Model weights/GPU runtimes are provisioned separately.
- RAG/vector DB and commercial services are integration targets; not every catalog entry is a complete product-specific API implementation.
- No proprietary binaries, paid weights, license keys or provider credits are included.
- Source release only. A native binary is not built in this environment; use the supplied Linux systemd installer.
- Server bind is loopback-only. Expose remote access through a same-host TLS reverse proxy and firewall the backend port.
