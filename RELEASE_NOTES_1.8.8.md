# CyberForge AIO v1.8.8

## Compatibility Analysis, Performance Profiling & Reliability Engineering

- Added read-only host compatibility analysis for OS, CPU architecture, Python, SQLite, app data path, frontend bundle, optional Python modules, language runtimes, LSP servers, scanners, managed engines and sandbox backends.
- Compatibility results distinguish detected binaries from operational readiness. A detected CLI does not prove daemon access, image availability, signatures, ABI compatibility or a complete end-to-end workflow.
- Added local process performance profiling with RSS/peak RSS, CPU time, thread count and a bounded rolling memory trend window. Possible memory growth is a heuristic requiring repeatable workloads, not an automatic leak verdict.
- Added SQLite diagnostics for WAL/SHM size, journal mode, page/cache settings, integrity, foreign keys, table/index counts and a temporary-database benchmark.
- SQLite connections now use a bounded 2 MiB page cache, in-memory temporary storage, a 500-page WAL auto-checkpoint and a 256-statement prepared-statement cache. FULL synchronous durability is retained. Startup runs `PRAGMA optimize` after schema migrations.
- Added static frontend profiling for HTML size, DOM element/ID counts, duplicate IDs, inline JS/CSS size and inline event-handler count. Real browser rendering performance remains a target-device test.
- Added an explicit, bounded concurrency stress harness (2–16 workers, up to 300 jobs) using temporary SQLite WAL storage; no production database or external network target is used.
- Added an isolated crash-recovery probe that hard-exits a child process during an uncommitted WAL transaction and verifies committed-row recovery, uncommitted-row rollback and SQLite integrity.
- Added HTTP endpoints and Dashboard controls for compatibility, performance, SQLite benchmark, concurrency stress and crash recovery. Active probes require explicit acknowledgement.
- Added a release preflight checker, source packaging script with ZIP integrity and SHA-256 output, plus a CI quality gate before the native desktop build matrix.
- Preserved all earlier workspaces, editions, privacy features, Dev Studio, AI workflows, scanner adapters, Engine Manager, Plugin Manager and localization.

## Validation boundaries

- Local tests validate the diagnostic logic and temporary-database probes only.
- Windows/macOS native builds, target-machine browser profiling, installed external scanner behavior, real container daemon health, and long-duration memory-leak observation require separate execution on those hosts.
