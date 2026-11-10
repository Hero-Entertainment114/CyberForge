# CyberForge AIO v1.8.9

## Resource efficiency and server operation
- Added bounded HTTP request concurrency to prevent unbounded request-thread growth.
- Added `CYBERFORGE_PROFILE=low_memory|balanced|throughput` and optional `CYBERFORGE_MAX_WORKERS` override. Defaults: 4, 12 and 24 request workers respectively.
- Added best-effort NVIDIA/AMD GPU CLI inventory. GPU is informational only; core application workloads do not claim GPU acceleration.
- Added resource profile and GPU information to performance diagnostics.

## Beginner experience
- Added About, Getting Started / FAQ and Troubleshooting pages.
- Added beginner entry points on Command Center and terminology explanations.
- Added clearer guidance on safe use, sandbox limitations, AI privacy and local/server deployment.

## Support reports
- Added local support report creation with size limits and heuristic redaction for common secret patterns.
- Reports are stored under the local data directory in `support_reports/`; nothing is transmitted to a remote ticketing service.
- Users can inspect and download the JSON report before choosing to share it.

## Compatibility
- Existing Dev Studio, Security workspaces, compatibility diagnostics, SQLite tuning and release gates are retained.
- New support and onboarding pages are available in AIO, Dev and Security editions.

## Limitations
- GPU inventory does not run CUDA/ROCm workloads or accelerate scanners.
- Resource profiles bound HTTP concurrency only; they do not impose OS-level CPU/RAM quotas.
- This remains a loopback single-user application, not a multi-tenant internet-facing server.
- Heuristic redaction cannot guarantee that every secret is removed; inspect reports before sharing.
