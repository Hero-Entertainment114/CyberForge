# Integration matrix

| Branch | Tool / service | License / billing class | v2.0.4 integration behavior |
|---|---|---|---|
| AI serving | Ollama | Open source | PATH detect; OpenAI-compatible endpoint configuration |
| AI serving | vLLM | Open source | PATH detect; OpenAI-compatible endpoint configuration |
| AI serving | llama.cpp server | Open source | PATH detect; OpenAI-compatible endpoint configuration |
| AI serving | NVIDIA Triton | Open source / vendor components | PATH detect; endpoint integration point |
| AI gateway | LiteLLM | Open source, commercial options | PATH/env detect; endpoint can front the AI adapter |
| AI serving | Ray Serve | Open source | PATH detect; distributed serving integration point |
| AI observability | Langfuse | Open source / cloud plans | Env credential presence detection |
| Observability | OpenTelemetry Collector | Open source | PATH detect; deployment template/documentation |
| Observability | Prometheus | Open source | PATH detect; CyberForge `/metrics` exporter |
| Observability | Grafana / Loki / Tempo | Open source / commercial cloud | PATH detect |
| Observability | VictoriaMetrics | Open source / enterprise | PATH detect |
| Security | Wazuh | Open source | PATH detection + implemented `alerts.json` JSONL ingestion; no full Manager REST API integration |
| Security | Suricata / Zeek | Open source | PATH detection + implemented Suricata EVE and Zeek JSON ingestion |
| Security | Falco | Open source | PATH detection + implemented JSON alert ingestion |
| Security | Trivy | Open source | PATH detection + implemented JSON report ingestion; CyberForge does not invoke scans |
| Security | osquery / Velociraptor | Open source / support | osquery JSON result ingestion; Velociraptor remains catalog/inventory only |
| AppSec | Semgrep | Community + paid tiers | PATH/env detect |
| AppSec | Gitleaks | Open source | PATH detect |
| AppSec | Snyk | Free tier + commercial plans | PATH/env detect |
| Containers | Docker / Podman | Open source components; commercial terms vary | PATH detect |
| Orchestration | Kubernetes | Open source | kubectl/KUBECONFIG detect |
| Automation | Ansible | Open source / Automation Platform commercial | PATH detect; no arbitrary playbook execution exposed |
| IaC | Terraform / OpenTofu | Business Source / MPL | PATH/env detect; no plan/apply execution exposed |
| Data | PostgreSQL / Redis / Qdrant / MinIO | Open source or mixed commercial terms | PATH/env detect |
| Commercial observability | Datadog | Commercial subscription | API key variable presence detection |
| Commercial SIEM | Splunk | Commercial license | HEC endpoint/token variable presence detection |
| Commercial EDR | CrowdStrike Falcon / SentinelOne | Commercial subscription | API credential presence detection; product-specific API implementation follows separately |
| Cloud security | Wiz | Commercial subscription | API credential presence detection |
| DevOps | GitHub Enterprise / GitLab | Free + paid tiers | CLI/token variable presence detection |
| Cloud providers | AWS / Azure / Google Cloud | Usage-based commercial services | CLI/credential presence detection |
| Edge | Cloudflare | Free + paid plans | API token variable presence detection |

## Active connector health checks

The current read-only health-check adapter supports fixed paths for Ollama, vLLM, llama.cpp server, LiteLLM, Prometheus, Grafana, Loki, Tempo, Langfuse, Qdrant, MinIO, Datadog, Splunk HEC, Cloudflare, GitHub and GitLab, and Snyk. Endpoint URLs and credentials are read only from server environment variables. The browser may choose only a fixed connector ID; it cannot supply an arbitrary URL, method, path or header. Remote endpoints require HTTPS and an exact hostname in `CF_CONNECTOR_ALLOWED_HOSTS`; redirects are not followed and response bodies are discarded.

## Security Operations ingestion adapters (v2.0.3, retained in v2.0.4)

The following six sources now have implemented JSON/JSONL ingestion and normalized-event persistence, beyond the earlier catalog/inventory detection. This does not install or operate the source product itself.

| Source | Input | Implemented behavior |
|---|---|---|
| Wazuh | `alerts.json` JSONL | Rule/agent metadata, level-to-severity mapping, source IP and incident correlation |
| Suricata | EVE JSONL | Alert/anomaly records; other event types are intentionally ignored by the incident adapter |
| Zeek | JSON logs | Notice/weird can create incidents; conn/DNS/HTTP/SSL/x509/files remain context-only timeline events |
| Falco | JSON output | Priority, rule, host and selected process/container labels; command-line and arbitrary output fields are excluded |
| Trivy | JSON report | Vulnerability/misconfiguration/secret/license findings; secret match/code contents are excluded from shipper envelopes |
| osquery | Differential/result JSON | Query/action and column names; arbitrary result column values are excluded |

The legacy ingestion route is `POST /api/v203/security/ingest/{source}`; v2.0.4 adds `/api/v204/security/ingest/{source}`. The `sensor` token role is limited to `security:ingest`. `tools/tail_jsonl.py` continuously follows Wazuh, Suricata, Zeek, Falco and osquery JSONL files; Trivy remains batch-based. See `docs/SECURITY_OPERATIONS.md` and `docs/SECURITY_INTELLIGENCE.md`.

## Important

A detected executable or environment variable is not proof of a healthy or authenticated connector. CyberForge deliberately reports only what it can verify without executing unknown tools or spending provider credits. Product-specific API calls, webhook validation, license checks and health endpoints are future adapter work. No third-party paid license or binary is redistributed.

## v2.0.1 AI Control Plane additions

The AI model registry and asynchronous scheduler are first-party CyberForge modules rather than third-party products. They connect to configured inference endpoints; they do not bundle or replace inference engines.

| Capability | v2.0.1 behavior | Boundary |
|---|---|---|
| Model registry | Persistent metadata for up to 32 deployments | Credentials remain in environment/secret manager, not in registry |
| Health-aware routing | Manual `/models` probes and same-billing-class local/free failover | No HA monitor; health state remains last-known until another manual probe |
| Async AI queue | Priority queue, bounded worker admission and per-model concurrency | In-process; queued/running work is interrupted at restart |
| Dispatch cohorts | Groups nearby jobs by deployment | Scheduler grouping only; not tensor or continuous batching |
| GPU inventory | NVIDIA/AMD/Intel vendor CLI sampling | Requires local vendor tools; not a scheduler or full GPU monitoring stack |
| AI observability | Catalog/endpoint integration points | Langfuse, OpenTelemetry and telemetry backends must be installed/configured separately |


## v2.0.2 distributed infrastructure

| Component | Integration mode | Responsibility | Limit |
|---|---|---|---|
| PostgreSQL | Native storage adapter | Shared identities, fleet, workflows, audit, AI registry/usage and durable job rows | Operator supplies HA, PITR, TLS and backups |
| Redis | Optional coordination adapter | Instance heartbeats and best-effort job notifications | Not a source of truth; queue still polls PostgreSQL |
| psycopg 3 | Optional Python driver | PostgreSQL wire protocol and transactions | Installed separately via `requirements-distributed.txt` |
| cryptography | Optional Python dependency, required for distributed jobs | AES-256-GCM job payload/result envelopes | Shared external key required on every replica |
| pg_dump | Fixed backup executable | PostgreSQL custom-format backups | Must be installed and restore-tested by operator |


## Security Intelligence (v2.0.4)

- `security_intelligence.py` enriches allowlisted entities, scores cross-source incident candidates and creates read-only evidence timelines.
- Candidate ATT&CK mappings are heuristic and require analyst validation.
- `GET /api/v204/security/incidents/{id}/analysis` provides a read-only summary; `POST .../correlate` persists analyst-reviewed correlation links; `POST .../ai-analysis` submits sanitized evidence to the AI job queue.
- AI analysis requires `ai:invoke` and `security:analysis`; persistent correlation requires `security:correlate`.


## Continuous JSONL tailer and incident intelligence (v2.0.4)

| Capability | Implemented behavior | Boundary |
|---|---|---|
| Continuous JSONL tailer | Wazuh, Suricata, Zeek, Falco and osquery; durable file offsets, rename rotation, per-input locks | At-least-once; Trivy remains batch |
| Event enrichment | Allowlisted PID/process, file hash/path, container and network metadata | No command line or raw source payload |
| Cross-source correlation | SHA-256, process/host, file path, domain/IP anchors | Heuristic confidence, not attribution |
| ATT&CK mapping | Candidate technique labels in event and incident view | Not proof of execution or coverage |
| AI Security Analyst | Sanitized evidence timeline routed through the existing AI queue | AI recommends; it cannot contain or execute responses |


## Threat Intelligence (v2.0.5)

| Source / standard | Integration type | Behavior and boundary |
|---|---|---|
| CISA KEV | Built-in HTTPS JSON feed | Disabled until explicitly enabled; CVE records imported with source attribution; conditional ETag sync |
| FIRST EPSS | Built-in on-demand API | 1–50 CVEs per request, positive cache 6h and negative cache 5m; use official daily CSV for bulk workflows |
| STIX 2.1 | Manual bundle import | Bounded observable-equality subset for IP/domain/URL/file hash; unsupported/negated patterns ignored |
| TAXII 2.1 | Custom collection sync | Explicit hostname allowlist, HTTPS, no redirects, named environment variable for auth, max five pages / 5,000 objects |
| Normalized JSON IOC | Manual import | IPv4/IPv6, domain, URL, MD5/SHA-1/SHA-256 and CVE; values normalized and deduplicated per feed |

Threat Intelligence endpoints use `threatintel:read`, `threatintel:manage` and `threatintel:enrich`. Indicator values are never resolved, opened or fetched. This is not a full STIX pattern engine or a commercial threat-intelligence platform. See [Threat Intelligence Guide](THREAT_INTELLIGENCE.md).
