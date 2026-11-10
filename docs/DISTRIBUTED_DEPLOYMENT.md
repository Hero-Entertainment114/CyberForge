# Distributed deployment (v2.0.2)

## Scope

PostgreSQL is the shared source of truth for API tokens, nodes, workflows, audit events, AI model policy, AI usage reservations and AI job metadata. Multiple CyberForge Server Edition processes can use the same PostgreSQL database. Each process runs a bounded worker pool and claims jobs using PostgreSQL row locks with `FOR UPDATE SKIP LOCKED`.

Redis is optional. It provides best-effort instance heartbeats and job notifications only. The database remains authoritative; workers poll PostgreSQL, so Redis loss does not lose queued jobs or stop durable queue processing.

The AI job payload and completed result are AES-256-GCM encrypted before insertion into PostgreSQL. Every control-plane instance must use the exact same `CF_DISTRIBUTED_DATA_KEY`. Store this key in a secret manager or protected environment file. Do not put it in source control, a container image, or the database. Losing it makes encrypted queued payloads/results unrecoverable. Key rotation is a maintenance operation and is not automatic in v2.0.2.

## Dependencies

Install the optional database/cache drivers in the same Python environment used by systemd:

```bash
python3 -m pip install -r requirements-distributed.txt
```

`cryptography` is required for encrypted distributed jobs. `psycopg` is required for PostgreSQL. `redis` is only required if Redis coordination/heartbeat visibility is desired.

## Provision PostgreSQL and optional Redis

A loopback-bound development reference is included:

```bash
cd deploy/distributed
# Create a protected .env file with CF_POSTGRES_PASSWORD and CF_REDIS_PASSWORD.
docker compose up -d
```

The Compose example binds database ports to `127.0.0.1`; it is not a production HA recipe. For production, use managed PostgreSQL or a separately hardened PostgreSQL cluster, enforce `sslmode=require` (or certificate verification) for remote database links, use dedicated least-privilege credentials, and configure backups/PITR. Remote Redis connections require `rediss://`; use ACL/TLS and private networking if enabled. Never expose either service to the public Internet.

## Configure all control-plane replicas

Example `/etc/cyberforge-server/instances/cp-a.env`:

```ini
CF_STORAGE_BACKEND=postgres
CF_DATABASE_URL=postgresql://cyberforge:URL_ENCODED_PASSWORD@db.internal:5432/cyberforge?sslmode=require
CF_DISTRIBUTED_DATA_KEY=PASTE_THE_SAME_64_HEX_CHARACTER_KEY_ON_EVERY_REPLICA
CF_INSTANCE_ID=cp-a
CF_REDIS_URL=rediss://:URL_ENCODED_REDIS_PASSWORD@redis.internal:6379/0
CF_SERVER_BIND=10.0.1.20
CF_SERVER_ALLOW_PRIVATE_BIND=1
CF_SERVER_TRUST_PROXY=1
CF_SERVER_TRUST_PROXY_CIDRS=10.0.1.10/32
CF_SERVER_ALLOWED_HOSTS=cyberforge.example.com,10.0.1.20
CF_SERVER_PORT=8787
CF_SERVER_DATA_DIR=/var/lib/cyberforge-server
CF_AI_WORKERS=4
CF_AI_QUEUE_LIMIT=256
CF_AI_DISTRIBUTED_LEASE_SECONDS=240
CF_DISTRIBUTED_POLL_MS=500
```

Generate one encryption key once, then distribute it through your secret manager:

```bash
python3 server.py generate-data-key
```

Every replica must use the same database URL, encryption key, AI deployment configuration, AI provider credentials, allowlists and compatible code version. Each replica must have a unique `CF_INSTANCE_ID` and its own listening port. Example second instance: `cp-b`, port `8788`.

Install the example systemd template as `/etc/systemd/system/cyberforge-server@.service`, create one environment file per replica with mode `0640` and group `cyberforge-server`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cyberforge-server@cp-a
sudo systemctl enable --now cyberforge-server@cp-b
```

Put a TLS reverse proxy or load balancer in front of the instances. Same-host deployments should keep each instance bound to loopback. For a multi-host deployment, set `CF_SERVER_ALLOW_PRIVATE_BIND=1`, bind only a numeric private IP, set `CF_SERVER_TRUST_PROXY=1`, and populate `CF_SERVER_TRUST_PROXY_CIDRS` with the exact reverse-proxy/load-balancer source IPs or smallest practical CIDRs. The backend rejects other remote clients even when proxy trust is enabled. Configure `CF_SERVER_ALLOWED_HOSTS` to the expected Host names. Public and unspecified bind addresses are always rejected. The stock service unit is still for the single-node SQLite installation; the `@` unit is an example to review for your host.

## Queue and delivery semantics

- PostgreSQL job rows are claimed in a transaction using `FOR UPDATE SKIP LOCKED`, so multiple workers do not normally claim the same queued row.
- Queue capacity is enforced against shared queued/running rows. Worker count is bounded per process and model concurrency uses shared leased slots in PostgreSQL.
- Model payloads/results are encrypted at rest. Payload ciphertext is removed when a job reaches a terminal state; result ciphertext remains until job retention cleanup.
- Non-paid jobs with an expired worker lease may be attempted again once. This is **at-least-once** delivery: a worker can die after a provider accepted a request but before the result was committed. Do not assume exactly-once inference.
- Paid jobs with expired leases are marked `interrupted` and are never replayed automatically, avoiding an unapproved duplicate charge. Reconcile provider usage before manually resubmitting.
- AI result reads remain scoped to the creating token ID; administrators can inspect all jobs.
- Redis is not required for correctness. Redis publishes job-ready/completed notifications and maintains 30-second instance heartbeats; polling and the durable queue continue when Redis is unavailable.
- The database-backed audit chain append uses a transaction-scoped PostgreSQL advisory lock to serialize events across replicas. The chain remains tamper-evident, not non-repudiation against a database superuser.

## Distributed workflow execution

Workflow approval and execution are separate atomic transitions. Only one replica can move an approved plan into `executing`; the claim carries a random owner token and a renewable 120-second lease. A crashed worker can be reclaimed after lease expiry. The currently supported workflow steps are inventory/diagnostic reads and database backup, so a reclaimed execution may repeat a backup. The previous owner cannot renew, fail or finalize the workflow after a new owner takes over. A failure stores completed step results and a sanitized error code. This lease is not a general-purpose remote job execution channel.

## Backup and restore

The `backup_database` workflow uses `pg_dump --format=custom` when PostgreSQL is configured. The helper writes a temporary mode-0600 PGPASSFILE instead of passing the database password in command-line arguments. Install a compatible `pg_dump` client. Use PostgreSQL-native PITR/WAL archiving for production recovery; one `pg_dump` file is not a substitute for tested disaster recovery.

Backups must be copied to separate protected storage. Test restore to a separate database before relying on a backup.

## Compatibility and limitations

- SQLite remains the default and continues to serve single-instance deployments. It is not made multi-writer by this release.
- PostgreSQL shared storage enables multiple control-plane instances, but v2.0.2 does not provide automatic leader election, HA failover for PostgreSQL itself, schema rollback, multi-region consensus or Kubernetes operators.
- Redis is optional and does not store authoritative state or AI prompts/results.
- All replicas must upgrade together. Do not run incompatible schema/code revisions against the same database.
- Live PostgreSQL/Redis integration tests require `CF_TEST_POSTGRES_URL` and optional Redis test configuration. The source release test host may not include these services.
