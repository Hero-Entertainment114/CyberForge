# CyberForge Server Edition v2.1.0 — Official Stable

## Release channel

**Official Stable** · Linux x86-64 / aarch64 · Python 3.10+ · systemd source installer.

This release retains the v2.0.0–v2.0.5 server platform and closes the first stable feature cycle with Detection Engineering plus a staged, backup-verified installer and recovery process.

## Detection Engineering

- Added the `cyberforge.normalized-event-rule.v1` versioned rule format.
- Added draft, revise, validate, test, publish, retire and rollback-to-new-draft lifecycle operations.
- Added an allowlisted field/operator evaluator; arbitrary scripts, expressions and user regex are not accepted or executed.
- Published rules evaluate normalized security events during ingestion and create deduplicated match records with rule/version/event provenance.
- Added Detection Engineering API and dashboard workspace.
- Added rule RBAC scopes. `sensor` remains ingestion-only.
- Two-person publish is enabled by default through `CF_DETECTION_REQUIRE_TWO_PERSON=1`; it distinguishes API actor labels/token identities, not verified human identities.
- Added PostgreSQL migration `0006_detection_engineering.sql`.
- The CyberForge rule format is not a full Sigma parser and does not claim Sigma compatibility.

## Official installer hardening

- Releases are staged in version-specific directories under `/opt/cyberforge-server/releases/`.
- The active `/opt/cyberforge-server/current` pointer is switched atomically after staging.
- A dedicated Python virtual environment is created for the release. PostgreSQL/Redis drivers are installed only when configured.
- Existing service is stopped before schema preflight and database backup.
- SQLite uses the online backup API; PostgreSQL uses custom-format `pg_dump` with a temporary mode-0600 `PGPASSFILE`.
- Backup verification and additive schema/audit preflight run before the symlink switch.
- The new service must pass a local `/api/v200/health` check.
- A failed post-switch start/health check restores the previous release pointer and systemd unit. Old release folders are retained.
- Persistent data and environment secrets remain separate from versioned application code.
- Node agent installs into its own `/opt/cyberforge-node` path, not inside a versioned server release.

## Operations and recovery

- Added CLI `preflight`, `backup` and `verify-backup` commands.
- SQLite backup verification runs `PRAGMA quick_check`; PostgreSQL custom-format verification uses `pg_restore --list`.
- Invalid/truncated SQLite backup files now return an explicit invalid result instead of an uncaught exception.
- Added backup/restore, upgrade/rollback and detection engineering documentation.

## Preserved platform capabilities

- AI Control Plane, model registry, bounded scheduler, budget policy and GPU inventory.
- SQLite single-node mode and PostgreSQL distributed mode with optional Redis coordination.
- Security telemetry ingestion, continuous JSONL tailing, incident correlation and AI analyst.
- IOC feeds, CISA KEV, FIRST EPSS, bounded STIX/TAXII integration.
- Linux fleet/node management, integration catalog, fixed read-only connector checks, audit and approval-gated data-only workflows.

## Deliberate boundaries

- No arbitrary remote shell or endpoint command execution.
- No automatic firewall edits, process termination or host isolation.
- No claim of full Sigma compatibility.
- No bundled commercial binaries, paid model weights, API keys, vendor licenses or proprietary subscriptions.
- No claim of HA/consensus, automatic PostgreSQL failover, multi-region replication, independent security certification or production load benchmark.

See `README.md`, `docs/DETECTION_ENGINEERING.md`, `docs/UPGRADE_BACKUP_RESTORE.md`, `LICENSES_AND_COMPONENTS.md` and `TEST_RESULTS_2.1.0.md`.
