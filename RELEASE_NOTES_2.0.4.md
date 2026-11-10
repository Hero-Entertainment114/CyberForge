# CyberForge Server Edition v2.0.4 Release Notes

## Security Intelligence and AI Analyst

- Added `security_intelligence.py` for process/file/container/network entity enrichment, bounded cross-source correlation, incident analysis, candidate MITRE ATT&CK mapping and sanitized AI prompt construction.
- Added read-only incident analysis and MITRE summary APIs, explicit correlation persistence with audit evidence, and AI-analysis submission to the existing AI job queue.
- Correlation uses explicit anchors such as file SHA-256, host/container + PID, host + path, domain/IP and process/network context. A common hostname alone does not create a correlation.
- Zeek JSON decoding now handles both nested objects and literal dotted keys such as `id.orig_h`, `id.resp_h`, `id.orig_p` and `id.resp_p`.
- Endpoint `hostname` is not treated as a DNS domain, preventing false domain matches from host inventory fields.
- Incident analysis includes related context-only network events in the evidence timeline without opening incidents from those events.
- Candidate ATT&CK mappings are clearly labeled as heuristic candidates, not proof of technique execution.
- AI Analyst submits allowlisted normalized evidence only. Raw source payloads, command lines, request/response bodies and secrets are excluded. The AI can recommend but cannot execute response actions.

## Continuous telemetry ingestion

- Added `tools/tail_jsonl.py` for continuously following Wazuh, Suricata, Zeek, Falco and osquery JSONL logs. Trivy JSON reports remain batch-ingested.
- Durable SQLite checkpoints track device/inode/byte offset; per-input locks allow multiple log sources to share a checkpoint database safely.
- The tailer sends bounded batches and advances the checkpoint only after HTTP 202 acknowledgement. A crash after acknowledgement can replay a batch; server-side source-event deduplication handles stable source IDs.
- Added safe token-file and log-file opens (`O_NOFOLLOW`, regular-file checks, bounded reads), mode-0600 token/checkpoint files and mode-0700 state directories.
- Added optional hardened systemd template `cyberforge-security-tail@.service`. The installer installs it but never enables it automatically.
- Added a live loopback integration test that exercises tailer → HTTP API → server normalization/persistence → checkpoint advancement.

## API and RBAC

- New routes are under `/api/v204/security/*`; existing `/api/v203/security/*` routes remain available.
- Viewer can read incident analysis. Analyst/operator can persist correlation subject to `security:correlate`. AI analysis requires both `ai:invoke` and `security:analysis`. Sensor remains limited to `security:ingest`.
- Added bounds for analysis windows and event context; malformed windows return HTTP 400.

## Dashboard and documentation

- Added per-incident Security Analyst view, candidate ATT&CK summary, related incidents and a unified timeline with context-only event indicators.
- Updated the security role descriptions and v2.0.4 ingestion endpoint labels.
- Added `docs/SECURITY_INTELLIGENCE.md`, continuous tailer/systemd guidance and release verification notes.

## Known boundaries

- Source products and their agents still must be installed/configured independently; this is not a full product-specific Wazuh/Suricata/Zeek/Falco/Trivy/osquery API connector.
- Correlation confidence and ATT&CK mappings are heuristic ranking/candidate labels, not probabilities, attribution or proof.
- Continuous tailing is at-least-once, not a transactional broker. Stable upstream source IDs are needed for robust server deduplication.
- Rename-rotation recovery requires the rotated inode to remain available. `copytruncate` detection is best-effort if truncation and fast regrowth occur between polls.
- Three PostgreSQL integration tests are skipped unless `CF_TEST_POSTGRES_URL` points to a disposable test database. No live PostgreSQL/Redis cluster, production source product, GPU inference stack or customer Linux host was available for acceptance testing.
- The systemd template was syntax-verified with `systemd-analyze verify`; it was not installed/enabled as root on a customer's host.
- This source release is not a native binary, HA certification or independent security audit.
