# CyberForge Server Edition architecture

## Deployment profile

A single Linux control-plane process serves a bundled web UI and `/api/v200/*` JSON API. The server uses Python's standard-library HTTP server and SQLite for a compact, dependency-free initial deployment. Production remote access is expected to pass through a TLS reverse proxy. The control plane is stateful and currently single-node; its SQLite store is local to one instance.

```text
Operator Browser
      | HTTPS
      v
Caddy / Nginx (TLS, optional SSO/WAF at proxy)
      | loopback HTTP
      v
CyberForge Server Control Plane
  | RBAC API tokens
  | Fleet registry + node heartbeat
  | AI gateway adapter + budgets
  | Integration inventory
  | Approval-gated workflows
  | Hash-chained local audit log
  | SQLite WAL database
      ^ HTTPS agent reports
      |
Linux Node Agent (read-only telemetry, no command channel)

Optional external services:
  Ollama / vLLM / llama.cpp / Triton / LiteLLM / Ray Serve
  OpenTelemetry / Prometheus / Grafana / Loki / Tempo
  Wazuh / Suricata / Zeek / Falco / Trivy / osquery
  Docker / Podman / Kubernetes / Ansible / Terraform
  Commercial SIEM/EDR/Cloud/DevSecOps endpoints
```

## Data stores

- `server.sqlite3`: API token hashes, node token hashes, node telemetry, workflow approvals/results, audit hash chain and AI usage counters.
- `backups/`: local SQLite online backups created only by an approved workflow.
- Secrets: environment variables / external secret manager. No raw API key, node token or admin token is stored in SQLite. Node token hashes are stored for verification.
- The UI does not persist bearer tokens beyond the current browser tab session.

## Node protocol

The agent sends a JSON object bounded to 16 KiB using HTTPS. Headers include node ID, per-node bearer token, Unix timestamp and random nonce. The server enforces a ±120-second clock window and uniqueness of `(node_id, nonce)`. Only schema-allowlisted metrics and selected fixed service states are accepted. Stale nodes are computed from last-seen time. Revoke marks the node credential unusable.

This is a low-complexity shared-secret design. It does not provide asymmetric identity, attestation or mutual TLS. For larger or higher-assurance fleets, place agents behind mTLS enrollment or a dedicated device identity system in a later release.

## RBAC

Tokens map to roles and explicit scopes. Current roles: admin, operator, analyst, viewer. The server checks scope on every API route. Token values are random, shown once and stored as SHA-256 hashes. API token revocation is immediate on the next request.

## AI serving and routing

CyberForge is an AI control surface and a lightweight OpenAI-compatible proxy client, not a model inference engine. It detects local runtimes and connects to configured endpoints such as Ollama, vLLM, llama.cpp server, Triton gateway or LiteLLM. Model weights, GPU drivers, CUDA/ROCm, tensor/pipeline parallelism and actual inference batching remain managed by those runtimes.

The AI Control Plane adds a persistent model registry and bounded asynchronous job scheduler. Model policy (enabled/default/priority/per-model concurrency) survives restart. Manual health probes use only the deployment's fixed `/models` endpoint, exact allowlisted host and HTTPS for remote services; redirects are disabled. Routing considers the last recorded health state. Automatic routes only consider local/free models. A specifically requested unhealthy local/free deployment may fail over to another model of the same billing class. Paid models require explicit per-request selection and are never eligible for automatic defaults or automatic failover. The model-policy API rejects attempts to mark a paid deployment as the database-managed default.

Jobs are prioritized (high/normal/low), admitted to a bounded queue, gathered into short dispatch cohorts by deployment and executed with global worker and per-model concurrency limits. Because `ThreadPoolExecutor` uses an unbounded internal queue, the dispatcher reserves a bounded in-flight slot before submitting each job; it never submits more work than the configured worker count, leaving overflow in the bounded priority queue. At most one configured dispatch cohort is temporarily held by the dispatcher. Cohorts are a scheduling optimization only; they are not tensor batches. Upstream inference servers perform actual continuous batching. Legacy synchronous `/api/v200/ai/chat` remains for compatibility; new UI chat uses `/api/v201/ai/jobs` and polls status.

Prompts and model answers are never written to the job table or audit log. Job metadata is persisted, while result payloads remain in a bounded process-memory cache. On restart, queued/running jobs become `interrupted` and are never replayed. A completed answer can become unavailable after restart or cache eviction. Paid spend is still atomically reserved before the upstream call; upstream provider billing remains authoritative.

GPU inventory uses bounded, fixed read-only vendor tools (`nvidia-smi`, `rocm-smi`, `xpu-smi`). It is inventory/telemetry sampling, not a complete DCGM/ROCm monitoring stack or GPU scheduling service.

## Integration model

`integrations.py` is a fixed registry. For local applications it checks `PATH` presence only, never runs version commands or executes tools. For services it checks whether the expected credential variable names are present, but does not claim the credential is valid. Documentation URLs point to vendor/maintainer docs. Actual service APIs, webhooks, license entitlements and product-specific authorization still require dedicated adapters and credentials.

## Workflow engine

Workflow definitions reference stable step IDs from a code-level allowlist. The server stores the plan with a ten-minute expiry, actor identity and approval state. Execution verifies approval and runs only built-in diagnostic or backup operations. The workflow API is intentionally not a general-purpose shell runner.

## Audit

Audit events are appended with previous-event hash and SHA-256 digest over a canonical record. Verification walks the full chain and reports the first broken sequence. This is tamper-evident against incidental edits, not a root-proof audit system. An external append-only log store or WORM object storage is recommended for production.

## Hardening

- systemd unit runs as an unprivileged account with NoNewPrivileges, ProtectSystem, ProtectHome, private temp and narrowly scoped writable data path.
- service bind is strictly loopback-only; every non-loopback bind is refused. Use a same-host Caddy/Nginx reverse proxy for TLS.
- request body bounded to 256 KiB; node data further bounded to 16 KiB.
- HTTP request concurrency is hard-capped (default 64, configurable 4–512); excess connections receive HTTP 503 with Retry-After.
- AI endpoints disable redirects, validate scheme, require HTTPS remotely and apply host allowlist.
- No cross-origin API access is enabled.
- Agent executes only a hard-coded service-status allowlist via `systemctl is-active`; it accepts no remote command input.

## Scale-out roadmap

## v2.0.2 distributed architecture

v2.0.2 adds optional PostgreSQL shared storage and a durable encrypted AI job queue. `FOR UPDATE SKIP LOCKED` distributes job claims across worker processes; shared model-slot leases enforce per-deployment concurrency. Redis is optional for process heartbeats and best-effort publish notifications. SQLite remains a single-node mode.

The deployment is horizontally multi-instance at the application layer, but not a complete HA product: PostgreSQL failover, multi-region consensus, automatic leader election, object storage, external audit sinks, Kubernetes operators and production SLOs are not bundled. Operators must supply reliable PostgreSQL HA/PITR, secret distribution, reverse proxy/load balancing, backups and restore testing.


## v2.0.3 Security Operations ingestion

`JSON/JSONL shipper → sensor-scoped HTTPS API → source normalizer → metadata allowlist/redaction → deduplicated security_events → incident fingerprint/correlation → incident timeline and approved data-only playbooks`.

The six implemented ingestion source IDs are Wazuh, Suricata, Zeek, Falco, Trivy and osquery. Raw source payloads are not persisted; context-only Zeek event classes remain queryable in the normalized event stream without opening incidents. A sensor token receives only the `security:ingest` scope. Incident read, update, plan and approve capabilities are separate scopes.

Playbooks produce evidence summaries, CyberForge-format detection drafts, manual response checklists and metadata manifests. They do not perform host/network containment, shell execution or arbitrary integrations.


## v2.0.4 Security Intelligence

The Security Operations pipeline now enriches normalized events with an allowlist of process/container/file/network entities, then feeds an evidence-anchored correlation engine. Correlation is explicitly heuristic; host-only similarity is insufficient. Context-only network events can join an incident timeline without opening an incident. ATT&CK mappings are candidate labels from static metadata/text rules, not confirmation of technique execution.

`tools/tail_jsonl.py` continuously follows selected JSONL telemetry files. It persists file device/inode/offset, uses one `flock` per input file, sends bounded batches, and commits offsets only after the server acknowledges ingestion. The server-side source-event uniqueness constraint provides replay deduplication. Trivy JSON reports remain batch-ingested. The optional systemd template is hardened and is not enabled automatically.

The AI Analyst builds a compact prompt from normalized timeline and selected evidence only. It does not include raw event payloads, command lines, secrets, request/response bodies or PCAP. It uses the existing AI job queue and billing controls. The model may explain and recommend; it cannot invoke host commands or perform containment.


## v2.0.5 Threat Intelligence

The Threat Intelligence subsystem is a local IOC store with explicit feed synchronization. It supports a bounded STIX 2.1 observable-equality subset, bounded TAXII 2.1 collection pagination, CISA KEV import and on-demand FIRST EPSS lookup. It never fetches or resolves indicator values. Feed URLs must be HTTPS and match an exact hostname allowlist; redirects are rejected. The STIX parser does not implement the full STIX pattern grammar. Revoked and time-expired indicators are excluded from lookup, and IOC imports invalidate corresponding local cache entries. PostgreSQL deployments apply `migrations/0005_threat_intelligence.sql`; SQLite initializes the tables idempotently.
