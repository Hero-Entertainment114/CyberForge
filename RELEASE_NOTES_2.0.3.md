# CyberForge Server Edition v2.0.3

## Security Operations: normalized telemetry and incident management

v2.0.3 turns the Security Operations catalog into a bounded ingestion and triage workspace for six defensive telemetry formats.

### Implemented source adapters

- **Wazuh:** alerts JSON; maps rule level, agent identity and selected source/destination metadata.
- **Suricata:** EVE JSON; imports alert/anomaly events and intentionally ignores unrelated EVE record types in the incident adapter.
- **Zeek:** JSON logs; notice/weird events can create incidents, while conn/DNS/HTTP/SSL/x509/files are retained as context-only timeline events.
- **Falco:** JSON alert output; retains priority, rule, host, short redacted output summary and selected process/container labels. Arbitrary output fields and command lines are excluded.
- **Trivy:** JSON report; flattens vulnerability, misconfiguration, secret and license findings. The batch shipper sends only an allowlisted metadata subset and strips secret match/code snippets before transmission.
- **osquery:** differential/result logs; retains action, query name and column names, not arbitrary column values.

### Event and incident pipeline

- `security_events` stores a bounded normalized metadata object, not the original raw source payload.
- `security_incidents` correlates alert-like events by normalized fingerprint, tracks event count and severity, and maintains first/last-seen bounds.
- Deduplication is enforced by `(source, source_event_id)`.
- New `GET /api/v203/security/events` API and Normalized Event Stream dashboard expose context-only events as well as alert events.
- Prometheus `/metrics` includes normalized security-event and incident counts.
- The PostgreSQL DDL is supplied as `migrations/0003_security_operations.sql`; runtime initialization is idempotent.

### RBAC and sensor shipper

- Added `sensor` API token role with only `security:ingest`.
- Existing tokens retain their originally assigned scope set; v2.0.2 tokens are not silently expanded.
- Added `tools/ingest_jsonl.py`, a bounded batch shipper for JSONL/JSON and Trivy JSON report files. It supports dry-run, HTTPS-only remote destinations, no redirects, mode-0600 token files and a fixed source allowlist.
- Added example Wazuh, Suricata, Zeek, Falco, Trivy and osquery records.

### Approved data-only playbooks

- Incident triage and timeline summary.
- CyberForge normalized-event detection rule draft (not Sigma).
- Manual response checklist.
- Evidence metadata manifest.

Plans expire after 10 minutes and require a different principal to approve. Execution is one-shot and data-only; `side_effects` is empty. No endpoint isolation, process termination, firewall modification, remote shell or arbitrary command execution is included.

## Compatibility

- Retains v2.0.2 PostgreSQL/Redis distributed infrastructure and AI control-plane features.
- Retains SQLite single-node mode and systemd deployment.
- No mandatory third-party Python dependency was added.
- Source distribution only; no native executable/container image is included.

See `docs/SECURITY_OPERATIONS.md`, `docs/INTEGRATION_MATRIX.md`, and `TEST_RESULTS_2.0.3.md`.
