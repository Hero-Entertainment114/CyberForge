# CyberForge AIO v1.8.8 — Validation Results

Validation run: 2026-11-05 (containerized Linux build environment)

## Release gates

- `python tools/release_check.py`: **PASS**, 0 failures, 0 warnings.
- Python syntax compilation: **PASS**, 32 Python files.
- Inline JavaScript syntax (`node --check`): **PASS**.
- Frontend static profile: **PASS**; 295,826 HTML bytes, 2,224 elements, 410 unique IDs, 0 duplicate IDs, 149,097 inline JavaScript bytes, 20,478 inline CSS bytes, 214 inline event handlers. The bundle remains below the configured 512 KiB HTML and 320 KiB inline-JS warning budgets.
- Full regression suite: **430 tests passed**, 0 failures, in 32.345 seconds (`python -m unittest discover -s tests -v`).

## Host used for this validation

- OS: Linux 6.18.57, x86_64, glibc 2.41.
- Python: 3.13.5; SQLite library: 3.46.1.
- Logical CPUs: 3; reported physical memory: approximately 5.81 GiB.
- Compatibility discovery inventoried 30 detected version entries. Runtime availability: Python 2/3, JavaScript/TypeScript 3/7, Java/Kotlin 4/6, .NET 0/1, systems languages 5/7, scripting 4/7, data/build 3/6. LSP, scanner and sandbox availability is environment-dependent and is not inferred from this count.
- No Docker/Podman daemon or VM runtime was available in this environment. Linux isolation utilities were partially detected. This does not imply that the host has a functioning malware sandbox.

## Isolated performance and recovery probes

All probes below use temporary directories/databases. They do not write to the CyberForge production database or make external network requests.

- SQLite benchmark, 1,200 rows: write 2.13 ms, read 0.09 ms, integrity `ok`; `EXPLAIN QUERY PLAN` used `idx_measurements_group`.
- Concurrent stress, 8 workers / 80 tasks: 80 completed, 80 database rows, 0 failures, integrity `ok`; 336.35 tasks/s in this run; median latency 0.69 ms, p95 105.54 ms, max 233.42 ms. Process RSS delta during the short probe was +1,683,456 bytes. These are single-host observations, not promised throughput on other machines.
- Crash-recovery probe: child process exited abruptly with code 23 during an uncommitted WAL transaction; the previously committed row was recovered, the uncommitted transaction was rolled back, and integrity remained `ok`.

## SQLite and memory notes

- Application connections use WAL, FULL synchronous durability, a bounded 2 MiB page cache, in-memory temporary storage, WAL auto-checkpoint at 500 pages and a 256-statement prepared-statement cache. Startup applies `PRAGMA optimize` after schema setup/migrations.
- The new cases priority expression index complements the asset, finding and workflow composite indexes. Query-plan profiling verifies whether the relevant paths are using indexes on the actual database.
- Process RSS/peak RSS, CPU time, thread count, GC counters and open descriptor/handle counts are exposed by runtime diagnostics. The rolling 120-sample memory trend flags only possible growth. A short test cannot prove the absence of a memory leak; a repeatable long-duration workload on the target host is still required.
- Static frontend analysis is not a substitute for browser-based layout/paint/interaction traces. This validation did not run Playwright or browser performance tooling.

## Platform and integration limits

- This run validates Linux only. Windows and macOS desktop builds must be produced and tested on their respective CI/host environments.
- External scanners, LSP servers, native desktop wrappers, container daemons, VM hypervisors and their signatures/images were not all installed here. Discovery accurately reports missing components; no operational success is claimed for absent tools.
- This ZIP is a source/build-kit release, not a prebuilt Windows EXE, macOS APP or Linux binary.
