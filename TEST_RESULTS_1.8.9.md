# Test Results · CyberForge AIO v1.8.9

## Release verification

- **439/439 tests passed** across 24 test modules, run in isolated module processes to avoid cross-module global state from legacy HTTP/server tests.
- 9/9 new v1.8.9 tests passed, including the HTTP bug-report endpoint, secret redaction, opt-out of environment details, bounded server concurrency and resource profile limits.
- v1.8.7 workspace-search, v1.8.8 compatibility/performance and v1.8.9 onboarding/resource modules passed.
- Locale regression checks passed for Vietnamese and English static copy.
- Python syntax compilation passed for all project Python files.
- Inline JavaScript syntax check passed with Node.js.
- HTML: 421 unique IDs, no duplicates.
- Release preflight: 0 failures, 0 warnings.
- Source ZIP integrity and SHA-256 verified after packaging.

## Resource profile behavior

- `low_memory`: default 4 concurrent HTTP request workers.
- `balanced`: default 12 concurrent HTTP request workers.
- `throughput`: default 24 concurrent HTTP request workers.
- `CYBERFORGE_MAX_WORKERS` overrides the default, clamped to 2–64.
- NVIDIA/AMD GPU inventory is best-effort and informational. No GPU workload or acceleration is claimed.

## Scope and limitations

- Profiles bound HTTP request concurrency; they do not impose operating-system CPU/RAM quotas or limit every external scanner subprocess.
- GPU inventory does not run CUDA/ROCm workloads or accelerate scanners.
- Bug reports are stored locally; no remote ticket is submitted. Secret redaction is heuristic and reports must be reviewed before sharing.
- The service remains loopback-only and single-user; it is not a hardened multi-tenant server.
- Cross-platform native builds and long-duration production soak tests require Windows/macOS/Linux target machines.
- Single-process `unittest discover` did not complete reliably in the current validation container; the isolated module runner is used by the release workflow.
