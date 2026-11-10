# CyberForge Server Edition v2.0.2 — Test Results

## Build-host result

- **123 passed; 3 optional PostgreSQL integration tests skipped; 126 tests discovered across five modules.**
- The five modules were run independently: `tests.test_ai_control` 33/33, `tests.test_connectors` 12/12, `tests.test_server` 54/54, `tests.test_cli` 9/9 and `tests.test_distributed` 15 passed / 3 skipped.
- The three skipped tests require `CF_TEST_POSTGRES_URL` and a disposable live PostgreSQL database. They cover cross-instance shared token/audit state, durable AI jobs polled across control planes, and workflow claim/reclaim across replicas.
- Workflow tests cover SQLite schema migration from the v2.0.1 layout, atomic approval (one winner), execution claim ownership, expired lease reclaim, stale-owner rejection, partial failure persistence and error sanitization. Distributed AI lease cleanup covers paid-job interruption and exhausted local/free retries without replay.
- Network binding tests cover default loopback, explicit private-IP opt-in, rejection of public/unspecified addresses, trusted proxy CIDR enforcement and IPv4-mapped IPv6 clients.
- Distributed transport tests cover requiring TLS for remote PostgreSQL (`sslmode=require` or certificate verification) and remote Redis (`rediss://`), while allowing loopback development URLs.

## Static release checks

- `python tools/release_check.py`: PASS; 0 failures.
- Python source compilation: 14 files.
- Inline dashboard JavaScript syntax: PASS.
- Deployment/tool shell syntax: PASS (2 scripts).
- HTML: 60 unique IDs, no duplicates.
- Version consistency: `VERSION.txt`, `edition.json` and `RELEASE_MANIFEST.json` all report 2.0.2.
- CLI: `--help`, `--version`, `doctor`, `generate-data-key` and `token-count` checks passed.
- Source ZIP integrity and SHA-256 are verified after packaging.

## What was not live-tested

The build environment did not include a PostgreSQL server or Redis server. Therefore this report does not claim live execution of `FOR UPDATE SKIP LOCKED`, concurrent PostgreSQL lease contention, cross-replica job completion, Redis heartbeat/pubsub, PostgreSQL backup/restore, PostgreSQL failover or production load behavior. The optional integration tests are included and can be enabled with `CF_TEST_POSTGRES_URL`.

The build host also did not provide a production GPU workload or commercial provider credentials. GPU inventory is read-only capability detection; no inference throughput benchmark or vendor billing validation is claimed. No native Linux package/installer was executed as root on a customer host.

## Delivery and recovery semantics

- PostgreSQL is the shared source of truth; Redis is optional, best-effort coordination only.
- AI payloads/results are AES-256-GCM encrypted at rest using a shared operator-provisioned key.
- Eligible local/free jobs can be retried once after worker lease expiry (at-least-once, not exactly-once).
- Paid jobs are not automatically replayed after lease expiry to avoid duplicate provider charges.
- Workflows use an owner-bound execution lease. Expired claims can be reclaimed because the allowlisted steps are diagnostics and backups; stale owners cannot finalize.
- Loopback is default. Private binds require an explicit opt-in plus a trusted reverse-proxy CIDR allowlist. Public and unspecified bind addresses remain refused.
- Remote PostgreSQL requires `sslmode=require` or stronger certificate verification. Remote Redis requires TLS via `rediss://`.
- Loss of `CF_DISTRIBUTED_DATA_KEY` makes encrypted queued payloads/results unrecoverable. Key rotation remains a manual maintenance procedure.
