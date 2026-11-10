# Security Operations (v2.0.3 foundation, enhanced in v2.0.4)

CyberForge Security Operations is a **defensive telemetry ingestion and incident-triage layer**. It accepts bounded JSON/JSONL events from six sources, normalizes selected metadata, creates incidents from alert-like records, and retains context-only events for timelines. It does not install or execute scanners, detonate samples, isolate hosts, change firewall rules, kill processes, or expose a remote shell.

## Supported input sources

| Source | Accepted shape | Normalized behavior |
|---|---|---|
| Wazuh | Alert JSON (`rule`, `agent`, `data`) | Maps Wazuh rule level to severity and records agent/rule/source-IP metadata |
| Suricata | EVE JSON | Imports `alert` and `anomaly`; other EVE event types are ignored by this adapter |
| Zeek | JSON log rows | `notice` and `weird` can create incidents; `conn`, `dns`, `http`, `ssl`, `x509`, and `files` are context-only |
| Falco | JSON output | Maps priority and retains a short redacted summary plus selected process/container labels |
| Trivy | JSON report | Flattens vulnerability, misconfiguration, secret and license findings; secret values are not retained |
| osquery | Differential/result JSON | Retains query name, action and column names, not arbitrary column values |

The normalized event schema retains source ID, observed/received timestamps, severity, category, title, host/node, validated IP/port fields, process/rule labels and a small allowlisted metadata object. Raw source payloads are not stored. The adapter intentionally drops fields that commonly contain credentials, command lines, HTTP bodies, arbitrary query columns or secrets.

## Sensor token

Create a dedicated least-privilege token. Never put an administrator token in a shipper configuration.

```bash
python3 server.py create-token --name suricata-shipper --role sensor
```

The token is printed once. Store it in a secret manager or a mode-0600 file. The `sensor` role has only `security:ingest`.

The authenticated read/triage roles are:

- `viewer`: read security events/incidents/playbooks.
- `analyst`: read, update incident status/assignee and create a playbook plan.
- `operator`: ingest, update, plan and approve/execute allowlisted playbooks.
- `admin`: full server administration.

Existing tokens retain their originally stored scopes. After upgrading from v2.0.2, create fresh tokens for roles that need the new `security:*` scopes.

## Batch shipper

The included `tools/ingest_jsonl.py` reads a local JSONL/JSON file and sends bounded batches. It is a batch shipper, not a long-running tail daemon.

```bash
export CF_SECURITY_INGEST_TOKEN='cf_...'
python3 tools/ingest_jsonl.py \
  --source suricata \
  --server https://cyberforge.example.net \
  --input /var/log/suricata/eve.json \
  --format jsonl --dry-run
```

After reviewing the dry-run result, remove `--dry-run` to send. For Trivy reports, use `--source trivy --format trivy`; the shipper splits findings into small envelopes instead of transmitting the full report. Remote server URLs require HTTPS, redirects are not followed, and the token is never printed. A token file must be mode 0600 or stricter.

The legacy ingestion endpoint is `POST /api/v203/security/ingest/{source}`; v2.0.4 also exposes `POST /api/v204/security/ingest/{source}` with a JSON body containing `events` (1–100 objects). The server caps normalized events at 500 per request. The response reports accepted, duplicate and ignored counts.

## Read APIs

- `GET /api/v203/security/sources`
- `GET /api/v203/security/overview`
- `GET /api/v203/security/events?source=zeek&severity=info&limit=100`
- `GET /api/v203/security/incidents?status=open&severity=high&limit=100`
- `GET /api/v203/security/incidents/{incident_id}`
- `GET /api/v203/security/playbooks`

The event stream includes context-only events such as Zeek connection/DNS/HTTP records. Such records do not necessarily open an incident.

## Incident correlation and idempotency

Alert-like events are grouped by a normalized fingerprint. Source event deduplication uses `(source, source_event_id)`; re-ingesting the same source event does not increment the event count twice. Repeated observations can raise incident severity. Late-arriving events update first/last-seen bounds monotonically.

A fingerprint is a triage convenience, not proof that two events came from the same attacker or campaign. Analysts should inspect the source event timeline before making attribution claims.

## Approval-gated playbooks

The built-in playbooks are data-only:

- `incident_triage`: collect events and create a chronological evidence summary.
- `detection_rule_draft`: create a CyberForge normalized-event rule draft. It is **not** a Sigma rule.
- `response_checklist`: create a manual verification/response checklist.
- `evidence_manifest`: hash selected event metadata identifiers.

A different principal must approve a plan. Plans expire after 10 minutes and can execute once. `side_effects` is always empty in this release. No host/network containment or remote command execution is implemented.

## PostgreSQL migration

The service creates the Security Operations schema idempotently during startup/API initialization. The equivalent PostgreSQL DDL is supplied in `migrations/0003_security_operations.sql` for review and change-management workflows. Back up the database before applying schema changes to a production deployment.

## Operational boundaries

- Source products must be configured separately to write the expected JSON/JSONL format.
- The batch shipper remains available. v2.0.4 adds a continuous JSONL follower for Wazuh, Suricata, Zeek, Falco and osquery; Trivy reports remain batch-based.
- This release does not ship live Wazuh/Falco/Suricata/Zeek daemons or their rules/signature packs.
- Vendor catalog entries for commercial EDR/SIEM products are not equivalent to an authenticated product-specific API connector.
- Do not ingest full packet captures or raw HTTP bodies into this event adapter. Use a dedicated evidence store with its own access, retention and encryption policy.


## Continuous JSONL tailer (v2.0.4)

The continuous tailer stores per-file device/inode/offset checkpoints and advances the offset only after HTTP 202 acknowledgement. It handles rename-based rotation and detects common copytruncate cases. Multiple inputs can share one checkpoint database because file locks are scoped per canonical input path. A missing checkpointed rotated inode is an explicit error, not a silent reset.

```bash
python3 tools/tail_jsonl.py \
  --source falco \
  --server https://cyberforge.example.net \
  --input /var/log/falco/events.jsonl \
  --token-file /etc/cyberforge-server/telemetry/falco.token \
  --state-file /var/lib/cyberforge-telemetry/checkpoints.sqlite3
```

First start defaults to EOF. Use `--from-beginning` only when intentionally backfilling. Each batch is at most 50 records. Remote URLs require HTTPS and redirects are disabled. Malformed record contents are never printed. The sender is at-least-once: a crash after server acknowledgement but before checkpoint commit can replay records, and the server deduplicates by `(source, source_event_id)`. Sources without stable source IDs can still produce duplicate derived event IDs if the same record is replayed at a different observed time; monitor the source adapter's IDs.

An optional systemd template is provided at `deploy/systemd/cyberforge-security-tail@.service.example`. It is installed but not enabled by default. Create one environment file per input at `/etc/cyberforge-server/telemetry/<instance>.env`, create a mode-0600 token file owned by `cyberforge-server`, grant the service account read-only access to the selected log through a dedicated group/ACL, then enable the matching template instance. Do not run the shipper as root solely to read logs.

For the correlation and AI analysis APIs, ATT&CK candidate rules and data-handling boundaries see [Security Intelligence Guide](SECURITY_INTELLIGENCE.md).

## v2.0.4 correlation and AI analyst

The v2.0.4 intelligence layer enriches allowlisted process, file-hash, container and network metadata, correlates incident/context evidence, adds candidate ATT&CK labels and exposes read-only incident analysis. The analysis endpoint can submit sanitized context to the existing AI queue when the caller has both `ai:invoke` and `security:analysis`. It does not execute host or endpoint response actions. See [Security Intelligence Guide](SECURITY_INTELLIGENCE.md).
