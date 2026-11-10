# CyberForge Server Edition v2.0.1 — Test Results

## Automated tests

- **99 passed / 99 executed** across **4 test modules**.
- `tests.test_ai_control`: 33 passed.
- `tests.test_server`: 47 passed.
- `tests.test_connectors`: 12 passed.
- `tests.test_cli`: 7 passed.
- Modules were run independently; this report does not claim one aggregate invocation completed.
- The scheduler backpressure test was additionally repeated three times and passed each run.

## Static release checks

`python tools/release_check.py` completed successfully:

- Python syntax compilation: 12 Python source/test/tool files.
- Version consistency: `VERSION.txt`, `edition.json` and `RELEASE_MANIFEST.json` all report `2.0.1`.
- HTML: 59 IDs, no duplicates.
- JavaScript syntax: one inline script passed `node --check`.
- Shell syntax: both deployment shell scripts passed `bash -n`.
- AI Control Plane API markers present.

Additional commands:

- `python server.py --version` → `2.0.1`.
- `python server.py --help` passed.
- `python server.py doctor` passed on the Linux build host and reported host/runtime/GPU-tool inventory, scheduler defaults and audit state.
- Python compilation passed for server, AI control plane, integrations, connectors, node agent and tests.

## v2.0.1 coverage highlights

- Persistent deployment registry, policy validation, default route and paid-model explicit selection.
- Local/free health-aware routing and same-billing-class failover; pinned routing does not fail over.
- Fixed health endpoint construction, bounded response, HTTPS/allowlist enforcement and redirect rejection.
- Asynchronous job submit/poll, token-identity ownership, admin inspection, bounded metadata retention and prompt/answer non-persistence.
- Restart interruption semantics; no prompt replay.
- Queue-full rejection and scheduler backpressure that prevents unbounded growth in the `ThreadPoolExecutor` submission queue.
- GPU inventory behavior when vendor utilities are absent.
- Role-based API access for model, queue, GPU and AI job endpoints; token-bound job ownership; unknown job IDs return localized HTTP 404 responses and terminal job failures include localized error messages.
- Fixed read-only connector health adapters and CLI behavior.

## Environment and verification boundaries

- Build/test host: Debian GNU/Linux 13 (container), Python 3.13.5, Node.js and Bash available.
- The container exposed no `nvidia-smi`, `rocm-smi` or `xpu-smi`, so no GPU telemetry or hardware benchmark was performed.
- AI endpoint/connector integration tests use local loopback fixtures. No paid provider account, real remote inference endpoint, customer license or billing transaction was used.
- No actual model weights or GPU-serving runtime were provisioned. Ollama/vLLM/Triton/LiteLLM compatibility is endpoint-based; the product does not bundle these runtimes.
- No systemd installation was executed as root on a separate production Linux host. Installer scripts passed syntax checks only.
- No production load test, multi-control-plane/HA test, PostgreSQL/Redis cluster test or independent security audit was performed.
- AI dispatch queue is in-process; prompt/answer are memory-only; jobs in progress become interrupted after restart. This is not a distributed durable job queue.
- Cohort scheduling is not tensor batching. True continuous batching is delegated to the configured inference server.
- No prebuilt binary or container image is included. This is a source release.
