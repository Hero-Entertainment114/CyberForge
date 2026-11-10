# CyberForge Server Edition v2.0.5 — Test Results

## Result

- **260 passed, 3 skipped, 0 failed.**
- **263 tests discovered across 11 modules.**
- Modules were executed independently with `python -m unittest tests.<module> -q`; this report does not claim a single aggregate invocation.
- The 3 skipped cases are live PostgreSQL integration tests and require `CF_TEST_POSTGRES_URL` pointing to a disposable test database.

## Module results

| Module | Passed | Skipped |
|---|---:|---:|
| `test_ai_control` | 33 | 0 |
| `test_cli` | 9 | 0 |
| `test_connectors` | 12 | 0 |
| `test_distributed` | 15 | 3 |
| `test_security_ops` | 38 | 0 |
| `test_security_shipper` | 7 | 0 |
| `test_server` | 54 | 0 |
| `test_v204_security_api` | 10 | 0 |
| `test_v204_security_intelligence` | 15 | 0 |
| `test_v204_telemetry_tail` | 20 | 0 |
| `test_v205_threat_intel` | 47 | 0 |
| **Total** | **260** | **3** |

## v2.0.5 coverage

The 47 Threat Intelligence tests cover IOC normalization (IPv4/IPv6, IDNA, URLs, hashes, CVE), unsafe URL rejection, exact host allowlisting, feed credential redaction, manual JSON/STIX import, STIX positive-equality subset and negation rejection, revoked/expired/not-yet-valid handling, cache invalidation, CISA KEV sync/ETag/error handling, FIRST EPSS API shape and cache TTL behavior, TAXII discovery/collection/pagination/cross-host rejection, local enrichment, AI prompt context and real HTTP loopback API/RBAC/error localization.

HTTP provider responses and TAXII pages are fixture-based. No production CISA/TAXII/FIRST account or remote feed was contacted by automated tests. The FIRST/CISA network path is explicit and can be exercised by an operator from the UI/API.

## Static release validation

- Python source syntax compilation: performed by `tools/release_check.py`.
- Inline dashboard JavaScript: checked with Node.js when present.
- Deployment and helper shell scripts: `bash -n` checked.
- HTML IDs: duplicate-free.
- Manifest, edition and `VERSION.txt`: consistent at 2.0.5.
- Server CLI `--version`, `--help` and `doctor`: smoke-tested.
- PostgreSQL migration `0005_threat_intelligence.sql` is present; live PostgreSQL execution was not possible without `CF_TEST_POSTGRES_URL`.

## Verification boundaries

- STIX 2.1 support is a bounded equality-observable subset, not full pattern grammar or formal conformance.
- TAXII supports a bounded same-host collection sync; no arbitrary external API root or redirects.
- No indicator URL/domain/IP is fetched or resolved.
- Commercial feeds and paid TI subscriptions are not bundled or activated.
- No native binary, live production service validation, load benchmark or independent security certification is claimed.
