# CyberForge Server Edition v2.0.2 — Distributed Server Architecture

## PostgreSQL shared storage
- Added an optional psycopg 3 PostgreSQL Store adapter. SQLite remains the default single-node backend.
- Shared API tokens, nodes, replay nonces, workflows, audit events, AI spend ledger and AI model registry can be used by multiple control-plane processes through one PostgreSQL database.
- PostgreSQL audit-chain appends and paid spend reservations use transaction-scoped advisory locks to serialize cross-process writes.
- Added a safe `pg_dump --format=custom` backup helper using a temporary mode-0600 PGPASSFILE instead of exposing the password in command-line arguments.

## Distributed AI job queue
- Added durable shared job rows claimed by multiple workers using PostgreSQL `FOR UPDATE SKIP LOCKED`.
- Added shared per-model concurrency slots with database leases.
- Prompt payloads and completed answers are sealed using AES-256-GCM before PostgreSQL persistence. A shared `CF_DISTRIBUTED_DATA_KEY` is required across all replicas.
- Queue limits are checked against shared queued/running records; worker submission remains bounded per process.
- Local/free jobs may receive one retry after an expired lease (at-least-once delivery). Paid jobs are marked interrupted and are not automatically replayed after lease expiry to avoid duplicate charges.
- Results remain scoped to the creating API token ID or admin.

## Optional Redis coordination
- Redis supports short-lived control-plane heartbeats and best-effort job-ready/completed notifications.
- PostgreSQL remains authoritative. Dispatch polls PostgreSQL and continues when Redis is unavailable.
- Added authenticated `/api/v202/cluster` endpoint and a System page card for backend/instance status.

## Distributed workflow safety
- Added atomic workflow approval transitions and per-execution leases shared across PostgreSQL replicas.
- An instance must own the active lease to renew, finish or fail a workflow. A stale owner cannot overwrite a reclaimed execution.
- Expired execution leases can be reclaimed by another instance; failure results retain completed steps but store only sanitized error codes.
- SQLite installs receive idempotent workflow lease columns and an index on upgrade. PostgreSQL schema bootstrap/migration includes the same fields.
- `pg_dump` backup propagates only the allowlisted TLS options (`sslmode`, `sslrootcert`, `sslcert`, `sslkey`) from the database URL.

## Deployment and operations
- Added optional dependencies, PostgreSQL schema migration, local-only PostgreSQL/Redis Compose reference, systemd multi-instance example and distributed deployment runbook.
- Added `server.py generate-data-key` and `server.py token-count` commands.
- Installer now reads its simple EnvironmentFile settings without evaluating shell code, supports choosing PostgreSQL for bootstrap verification and checks distributed driver/key prerequisites.
- Loopback remains the default bind. Multi-host deployment can opt into a numeric private IP only with `CF_SERVER_ALLOW_PRIVATE_BIND=1`, `CF_SERVER_TRUST_PROXY=1` and an explicit `CF_SERVER_TRUST_PROXY_CIDRS` source allowlist; public/unspecified binds remain rejected.
- Remote PostgreSQL connections require `sslmode=require` or stronger certificate verification; remote Redis URLs require `rediss://`.
- Kept the v2.0.1 SQLite path unchanged when `CF_STORAGE_BACKEND=sqlite`.

## Explicit boundaries
- PostgreSQL multi-instance mode is not a bundled PostgreSQL HA cluster and does not provide consensus, automatic DB failover, multi-region replication or a Kubernetes operator.
- Redis is optional and not used as the source of truth.
- Distributed AI delivery is not exactly-once. Paid jobs deliberately are not automatically replayed after lease expiry.
- All replicas must share the same encryption key and compatible configuration. Key rotation is manual; loss of the key makes stored encrypted payloads/results unreadable.
- No live PostgreSQL/Redis integration or production load benchmark is claimed unless the optional integration test environment is provided.
- No native binaries, model weights, GPU drivers or commercial licenses are bundled.
