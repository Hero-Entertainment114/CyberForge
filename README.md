# CyberForge Server Edition v2.1.0 — Official Stable

**Linux-first control plane for AI infrastructure, fleet management, defensive security operations, threat intelligence and detection engineering.**

This is the official stable source release of the Server Edition. It is a separate distribution from **CyberForge AIO Desktop v1.9.9.1**; the Desktop branch is not modified by this package.

> **Release scope:** Official Stable means the source package, release checks and stated test suite passed in the recorded build environment. It is not a third-party security certification, a guarantee of high availability, or proof that optional commercial products and every PostgreSQL/Redis multi-replica topology have been validated on a production system.

## 1. Highlights

### Control plane and fleet
- Linux host inventory for OS, kernel, CPU, RAM, disk, load and optional GPU tooling.
- Node enrollment, per-node credentials, revocation, heartbeat and stale-node status.
- Read-only Linux telemetry agent. It does not accept remote shell commands or administer the endpoint.
- RBAC: `admin`, `operator`, `analyst`, `viewer` and least-privilege `sensor`.
- Hash-chained audit events and audit verification.
- Loopback-only default bind, bounded HTTP concurrency and request-size limits.

### AI Control Plane
- Local-first OpenAI-compatible model endpoints, including Ollama, vLLM, llama.cpp server, LiteLLM and compatible gateways.
- Model registry, health-aware routing for local/free deployments, per-model concurrency and bounded priority queue.
- GPU inventory through NVIDIA, AMD and Intel vendor utilities when installed.
- Paid model use requires explicit selection, HTTPS, hostname allowlisting, configured token prices and per-request/daily budget limits.
- PostgreSQL mode stores AI job payload/results encrypted with AES-256-GCM. SQLite single-node mode keeps job payload/results in bounded process memory.
- Paid jobs are not automatically replayed after a lost worker lease. Local/free jobs may be retried once (at-least-once semantics).

### Security Operations and Threat Intelligence
- Normalized telemetry ingestion for Wazuh, Suricata, Zeek, Falco, Trivy and osquery.
- Continuous JSONL tailer with checkpointing, rotation handling and sensor-only credentials for Wazuh, Suricata, Zeek, Falco and osquery. Trivy remains batch-oriented.
- Cross-source incident correlation, context timelines and heuristic MITRE ATT&CK candidates.
- IOC management for IP, domain, URL, file hashes and CVE; CISA KEV, FIRST EPSS, bounded STIX 2.1 import and TAXII 2.1 collection sync.
- IOC values under investigation are not fetched, resolved, visited or downloaded.
- AI Analyst receives selected sanitized evidence, not raw packet payloads, secrets, HTTP bodies or unrestricted command lines.

### Detection Engineering (new in v2.1.0)
- Versioned normalized-event rules: **draft → validate → test → publish → retire**.
- Published rules evaluate new normalized telemetry and create deduplicated detection matches.
- Rollback creates a new draft from a previously published version; it never silently rewrites the rule history.
- Two-person publishing is enabled by default (`CF_DETECTION_REQUIRE_TWO_PERSON=1`) and checks distinct API actor labels/token identities; it is not proof of two separate humans. Pair it with your organization's identity and access process.
- The rule language is bounded and data-only: allowlisted fields, fixed operators and bounded values. Arbitrary scripts, expressions and user-provided regular expressions are not executed.
- The format is `cyberforge.normalized-event-rule.v1`. **It is not a full Sigma parser and does not claim Sigma compatibility.**

### Workflows
- Plan → approval → execution lease → fixed allowlisted actions.
- Expiring approvals, two-person approval where configured, audit events and partial step results.
- Workflows cover diagnostics, inventory, backup and audit verification. There is no arbitrary shell, SSH, firewall, process-kill or remote endpoint-control step.

## 2. Architecture and supported modes

| Mode | Storage | Queue | Intended use |
|---|---|---|---|
| Single node | SQLite | Bounded in-process scheduler | Small/private server, lab or one control plane |
| Distributed | PostgreSQL shared state | Durable PostgreSQL job claims; optional Redis coordination | Multiple control-plane instances with shared configuration |

PostgreSQL is the shared source of truth in distributed mode. Redis is optional coordination/cache; it is not the durable job database and does not provide consensus. Automatic PostgreSQL failover, leader election, multi-region replication and a Kubernetes operator are not included.

Supported release targets: Linux x86-64 and Linux aarch64, Python 3.10+, systemd for the official installer. Core SQLite mode uses Python standard-library modules. PostgreSQL/Redis mode needs optional dependencies from `requirements-distributed.txt`.

## 3. Recommended installation (systemd)

1. Extract the source archive on a supported Linux host.
2. Review the environment example and ensure the host has Python 3.10+ and systemd.
3. Run the transactional installer:

```bash
sudo ./deploy/install.sh
```

The installer:
- creates a service account `cyberforge-server`;
- creates a staged virtual environment and installs optional distributed drivers only when PostgreSQL/Redis is configured;
- keeps release code under `/opt/cyberforge-server/releases/<version>` and switches `/opt/cyberforge-server/current` atomically;
- keeps data in `/var/lib/cyberforge-server` and secrets in `/etc/cyberforge-server/server.env`;
- stops an existing service, backs up the database and verifies the backup, performs schema/audit preflight, starts the new release and checks `/api/v200/health`;
- restores the previous release pointer and systemd unit if the new service fails its health check. Old release directories are retained.

Review `/etc/cyberforge-server/server.env` before remote access. It is not overwritten on upgrades. The shipped systemd unit pins the control plane to `127.0.0.1:8787`. Put Caddy or Nginx in front for TLS; do not expose the backend port directly to the Internet. A private-IP bind requires a separately reviewed systemd drop-in, explicit `CF_SERVER_ALLOW_PRIVATE_BIND=1`, proxy trust enablement and a narrow `CF_SERVER_TRUST_PROXY_CIDRS` allowlist. Public and unspecified binds remain refused.

### First administrator token

On a new installation the installer creates the first admin token and displays it once. Store it in a password manager. The raw token is not recoverable from the database. If the terminal output was lost, create a new token using the local CLI after confirming your admin bootstrap procedure.

### Check the service

```bash
sudo systemctl status cyberforge-server
sudo journalctl -u cyberforge-server -n 100 --no-pager
curl -fsS http://127.0.0.1:8787/api/v200/health
```

### Agent installation on monitored Linux nodes

Enroll a node on the control plane and copy its one-time node token to the monitored node using a protected channel. On the node, extract the same source package, edit `/etc/cyberforge-node/agent.env` as prompted, then run:

```bash
sudo ./deploy/agent-install.sh
```

The agent is installed separately at `/opt/cyberforge-node/agent.py`; it reports bounded read-only telemetry over HTTPS. It does not execute commands received from the control plane.

## 4. Upgrade and rollback

The official installer supports upgrades from the previous v2.x source layout. It does not overwrite `/etc/cyberforge-server/server.env` or `/var/lib/cyberforge-server`.

```bash
sudo ./deploy/install.sh
```

Before switching releases, the installer creates a backup under `/var/backups/cyberforge-server/` (SQLite online backup or PostgreSQL custom-format `pg_dump`) and verifies it. On failure after switching, the installer restores the old `current` symlink and old systemd unit. Previous release directories are not automatically deleted.

For manual rollback, stop the service and point `current` at a retained previous release directory, restore the corresponding systemd unit if it changed, then run `systemctl daemon-reload` and start the service. Do not roll database schema backwards by deleting tables; migrations are additive. Restore a database backup only after checking the backup and understanding any events written after that backup.

## 5. Backup and restore

### Create and verify a backup

```bash
sudo -u cyberforge-server /opt/cyberforge-server/current/.venv/bin/python \
  /opt/cyberforge-server/current/server.py --data-dir /var/lib/cyberforge-server backup

sudo -u cyberforge-server /opt/cyberforge-server/current/.venv/bin/python \
  /opt/cyberforge-server/current/server.py --data-dir /var/lib/cyberforge-server \
  verify-backup --path /var/backups/cyberforge-server/your-backup.sqlite3
```

For PostgreSQL, the backup command uses `pg_dump --format=custom`; verification uses `pg_restore --list`. Both `pg_dump` and `pg_restore` must be installed. The database password is passed through a temporary mode-0600 `PGPASSFILE`, not command-line arguments.

### Restore SQLite

1. Stop the service: `sudo systemctl stop cyberforge-server`.
2. Verify the chosen backup with `verify-backup`.
3. Preserve the current database by moving it to a separate recovery filename.
4. Copy the verified backup to `/var/lib/cyberforge-server/server.sqlite3`, owned by `cyberforge-server:cyberforge-server`, mode `0600`.
5. Start the service and verify health, audit chain and expected records.

### Restore PostgreSQL

Use a separately prepared recovery database and the organization's PostgreSQL restore process, for example `pg_restore --clean --if-exists --no-owner --no-acl -d <recovery-dsn> <backup.dump>`. Validate the restored database before directing control-plane instances to it. Do not restore over a live shared database without a maintenance window and a tested recovery plan.

Back up `/etc/cyberforge-server/server.env` separately. In distributed mode, preserve `CF_DISTRIBUTED_DATA_KEY`; losing or changing it can make previously encrypted AI job payload/results unreadable. Store off-host copies with access controls and retention appropriate to your environment. Database backups do not include all external project files, endpoint logs, model weights or vendor-side data.

## 6. PostgreSQL / Redis distributed configuration

- Set `CF_STORAGE_BACKEND=postgres` and configure `CF_DATABASE_URL`.
- Remote PostgreSQL requires TLS (`sslmode=require`, `verify-ca` or `verify-full`; prefer certificate verification).
- Generate the shared 256-bit data key with `python server.py generate-data-key` and set the same `CF_DISTRIBUTED_DATA_KEY` on every control-plane replica.
- Set a unique `CF_INSTANCE_ID` for each instance.
- Set `CF_REDIS_URL=rediss://...` for remote Redis; local loopback Redis may use `redis://`.
- Apply the PostgreSQL migrations using the organization's schema-change process. The application also initializes supported additive schema idempotently during startup/preflight.

See `docs/DISTRIBUTED_DEPLOYMENT.md` and `deploy/distributed/docker-compose.yml`. The Compose file is an example topology, not a production HA blueprint.

## 7. AI configuration and cost controls

Configure model endpoints using the examples in `examples/ai-deployments.example.json` and environment variables. Model weights and inference runtimes are not bundled. Start with a local endpoint (for example Ollama on loopback) if data locality matters.

Paid model calls require explicit user selection plus `CF_AI_ALLOW_PAID=1`, an HTTPS endpoint, exact host allowlisting, API key environment variable, token prices, per-request maximum and daily budget. A paid deployment is not an automatic default or automatic failover target. Usage costs are estimates based on provider usage and configured rates; the provider invoice remains authoritative.

For external AI endpoints, prompts are transmitted to that provider only when an operator configures and invokes the deployment. Keep sensitive incident evidence out of external AI prompts unless the organization's data policy permits it.

## 8. Security, privacy and boundaries

- Loopback bind by default. Private bind requires explicit opt-in plus trusted reverse-proxy CIDR configuration. Public/unspecified bind addresses are refused.
- TLS is required for remote node, connector, Threat Intelligence and remote AI connections. Redirects are disabled for fixed connector/feed requests.
- Sensor tokens can only ingest security telemetry. Do not reuse admin tokens in shippers.
- Raw telemetry payloads, HTTP bodies, secrets and arbitrary command lines are not persisted or forwarded into the AI Analyst context.
- STIX parsing supports a bounded observable-equality subset; TAXII has same-host, page/object and HTTPS limits. This is not full STIX pattern conformance.
- ATT&CK correlations are heuristic candidates, not proof that a technique occurred.
- Detection rules use a restricted data-only CyberForge format, not full Sigma compatibility.
- The local audit hash chain is tamper-evident for accidental/local edits, not non-repudiation against a privileged root administrator.
- The security ingestion and analytics pipeline does not automatically block traffic, kill processes, isolate hosts, change firewall rules or execute remote commands.
- A passing test suite is not a penetration test, independent security audit, compliance certification or production load benchmark.

## 9. Integrations and licensing

The catalog describes open-source and commercial systems, including AI runtimes, telemetry, SIEM/EDR/NIDS, AppSec, infrastructure and cloud vendors. A catalog entry is not necessarily a fully implemented control connector. The release contains 17 fixed, read-only health-check adapters; other entries are capability or integration metadata only.

No proprietary binaries, paid model weights, commercial subscriptions, customer API keys or license files are bundled. Operators must obtain vendor licenses and credentials and review upstream licenses and terms before installing or connecting third-party tools. See `LICENSES_AND_COMPONENTS.md` and `docs/INTEGRATION_MATRIX.md`.

## 10. Release verification

Run the included tests:

```bash
python3 -m unittest discover -s tests -q
python3 tools/release_check.py
python3 server.py --version
python3 server.py --help
```

The release test report records passed/skipped tests and environmental limits. PostgreSQL live integration tests are skipped unless `CF_TEST_POSTGRES_URL` points to a dedicated disposable test database.

## Documentation map

- `docs/ARCHITECTURE.md` — system architecture and trust boundaries.
- `docs/AI_PLATFORM_PATTERNS.md` — model serving and AI topology.
- `docs/DISTRIBUTED_DEPLOYMENT.md` — PostgreSQL/Redis multi-instance deployment.
- `docs/SECURITY_OPERATIONS.md` — telemetry ingestion, incidents and sensor setup.
- `docs/SECURITY_INTELLIGENCE.md` — event correlation and AI analysis.
- `docs/THREAT_INTELLIGENCE.md` — IOC sources, STIX/TAXII and EPSS boundaries.
- `docs/DETECTION_ENGINEERING.md` — rule lifecycle, supported fields/operators and testing.
- `docs/UPGRADE_BACKUP_RESTORE.md` — transactional upgrade, backup, restore and rollback.
- `LICENSES_AND_COMPONENTS.md` — component and license boundaries.
- `RELEASE_NOTES_2.1.0.md` and `TEST_RESULTS_2.1.0.md` — release details and verification.
