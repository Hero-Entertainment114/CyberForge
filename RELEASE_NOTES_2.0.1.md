# CyberForge Server Edition v2.0.1 — AI Control Plane

v2.0.1 continues the dedicated Linux Server Edition track. The Desktop AIO branch is unchanged.

## AI Control Plane

- Added persistent registry for up to 32 configured AI deployments, including model, endpoint hostname, billing class, enabled/default state, priority, health state, latency and per-deployment concurrency policy.
- Added manual, fixed-path `/models` health probes. Remote probes require HTTPS and exact host allowlisting; redirects are not followed and response content is bounded and not persisted.
- Added health-aware routing for local/free deployments. Automatic failover stays within the same billing class. Paid deployments are never selected automatically and never receive automatic failover; a paid deployment must be explicitly selected.
- Added asynchronous AI jobs with high/normal/low priorities, bounded queue, bounded worker count and per-model concurrency semaphore.
- Added dispatcher backpressure before `ThreadPoolExecutor.submit()`. The executor has an unbounded internal queue, so v2.0.1 reserves an in-flight slot before submission and submits no more than the configured global worker count. Waiting jobs remain in the bounded priority queue; at most one small dispatch cohort is temporarily held by the dispatcher.
- Added separate `queued` and `inflight` metrics to API and dashboard; job polling now returns a localized error message for terminal errors, and unknown job IDs correctly return HTTP 404 instead of HTTP 500.
- Added configurable job metadata retention (1–90 days, default 7). Job prompts and answers are not written to SQLite. Results stay in a bounded process-memory cache (up to 256 results); answers may be unavailable after restart/cache eviction. Queued/running jobs become `interrupted` on restart and are never replayed.
- Added read-only NVIDIA `nvidia-smi`, AMD `rocm-smi` and Intel `xpu-smi` inventory with fixed commands, timeouts and output bounds.
- Optimized model registry synchronization to avoid an unnecessary SQLite write on every read when a deployment definition has not changed.

## API additions

- `GET /api/v201/ai/models`
- `GET /api/v201/ai/queue`
- `GET /api/v201/ai/gpu`
- `POST /api/v201/ai/models/health`
- `POST /api/v201/ai/models/{id}/health`
- `POST /api/v201/ai/models/{id}/policy`
- `POST /api/v201/ai/jobs`
- `GET /api/v201/ai/jobs/{id}`

The legacy `/api/v200` endpoints remain available. Job result reads are bound to the unique token identity, not merely the display name; admins can inspect all jobs.

## Dashboard

- Added model registry, billing and health state, explicit default selection and enable/disable controls.
- Added queue depth, in-flight jobs, worker/cohort counts, 24-hour status counts and GPU/VRAM inventory.
- Added labels for model policy and scheduler status in English and Vietnamese.

## Operations and compatibility

- Added bounded scheduler settings to `.env.example` and `doctor` output.
- Added a reproducible `tools/release_check.py` static validation command.
- Added an upgrade procedure from v2.0.0. The systemd installer preserves the existing data directory and existing environment file; take a database backup before upgrading.
- Existing Linux agent, RBAC roles, integration catalog, read-only health adapters, workflow engine, audit hash chain, loopback-only control plane and systemd packaging are retained.

## Important boundaries

- Dispatch cohorts are scheduling groups only, not tensor batches. Actual continuous/tensor batching is performed by compatible upstream inference servers.
- The queue and result cache are process-local. This is not a durable distributed queue or HA deployment.
- GPU inventory is read-only command-based telemetry; it is not a GPU scheduler, CUDA benchmark or VRAM allocator.
- No model weights, GPU runtime, paid licenses, proprietary binaries or provider credits are bundled.
- The agent still has no remote shell or arbitrary command execution channel.
- No root installation on a production Linux host, external paid-provider authentication, real GPU benchmark, production load benchmark or independent security certification was performed in this build environment.
