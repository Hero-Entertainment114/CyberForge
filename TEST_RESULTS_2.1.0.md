# CyberForge Server Edition v2.1.0 — Official Stable Test Results

## Summary

- **294 tests discovered.**
- **291 passed; 3 skipped; 0 failures.**
- **13 test modules.**
- `python tools/release_check.py`: PASS, no reported failures/warnings.
- Python syntax compilation, inline JavaScript syntax, shell syntax, HTML duplicate-ID audit, CLI checks and systemd unit verification completed as recorded below (control-plane, telemetry-tail and node-agent units).

The three skipped tests are PostgreSQL live integration tests in `test_distributed`; they require a dedicated disposable database through `CF_TEST_POSTGRES_URL`. They are not recorded as passed.

## Test modules

| Module | Tests discovered | Result |
|---|---:|---|
| `test_ai_control` | 33 | PASS |
| `test_cli` | 9 | PASS |
| `test_connectors` | 12 | PASS |
| `test_detection_engine` | 20 | PASS |
| `test_distributed` | 18 | 15 PASS / 3 SKIP |
| `test_official_release` | 11 | PASS |
| `test_security_ops` | 38 | PASS |
| `test_security_shipper` | 7 | PASS |
| `test_server` | 54 | PASS |
| `test_v204_security_api` | 10 | PASS |
| `test_v204_security_intelligence` | 15 | PASS |
| `test_v204_telemetry_tail` | 20 | PASS |
| `test_v205_threat_intel` | 47 | PASS |
| **Total** | **294** | **291 PASS / 3 SKIP** |

## New v2.1.0 coverage

- Official release metadata consistency, environment-file preservation, and rollback restoration of the prior systemd enabled/active state.

### Detection Engineering (20 tests)
- Rule normalization and field/operator allowlists.
- Rejection of arbitrary regex, unknown fields and malformed ATT&CK IDs.
- Draft, revision, validation, test bench, publish, retire and rollback-to-draft.
- Two-person publishing and separation of duties.
- Existing active rule remains active while a new version is reviewed.
- Match creation during normalized-event ingestion and deduplication.
- Detection summaries and ATT&CK annotation coverage.
- API authorization: analyst can manage drafts, operator can publish, viewer can read and sensor cannot access Detection Engineering.

### Official release/installer (11 tests)
- `preflight` initializes additive Threat Intelligence and Detection Engineering schemas and verifies the audit chain.
- SQLite backup create, SHA-256, mode 0600 and verification.
- Corrupt/missing backup rejection; offline verification does not connect to the live DB; existing backup targets are never overwritten.
- Installer staging, backup, preflight, atomic switch, rollback and health-check markers.
- systemd uses the versioned release virtual environment and data-only write path.
- PostgreSQL backup uses a temporary mode-0600 PGPASSFILE and a minimal child-process environment; DSN/password and AI keys are not passed in argv/environment to `pg_dump`.

## Static and CLI verification

- Python syntax: all Python source, tools and test files compiled.
- JavaScript: inline dashboard script passed `node --check`.
- Shell: installer and agent installer passed `bash -n`.
- HTML: unique element IDs, no duplicates.
- CLI: `--version`, `--help`, `doctor`, `preflight`, `backup` and `verify-backup` tests passed.
- systemd: control-plane and telemetry shipper unit templates passed `systemd-analyze verify` in the build environment.
- Release metadata: `VERSION.txt`, `edition.json`, `RELEASE_MANIFEST.json` and `RELEASE_CHANNEL.txt` match v2.1.0 Official Stable.

## Environment and limitations

- Build/test host was Linux with Python 3.13 and Node.js. This does not substitute for installation testing across all supported Linux distributions.
- PostgreSQL live integration tests were skipped because no disposable PostgreSQL test server was supplied. SQLite integration tests passed.
- Redis multi-instance coordination was not load-tested against a production Redis deployment.
- The installer was statically checked and its backup/preflight/CLI helpers were exercised, but it was not run as root on a customer Linux host. Review system paths, package manager and service policy before rollout.
- Docker Desktop/Windows acceptance from the separate v1.9.x Desktop branch was not retested by this Linux Server release.
- No GPU inference benchmark, vendor commercial credential test, multi-region test, failover drill, penetration test or independent security audit is claimed.
- Third-party service integrations were not all connected to live vendor accounts. Only fixed read-only health adapters are actively implemented for the selected connector subset; other catalog entries are integration metadata.
- The source archive does not include prebuilt native binaries, third-party scanner packages, model weights, commercial API keys or license files.

## Release artifact checks

The release package was verified for ZIP integrity and SHA-256. The extracted artifact was checked again with `tools/release_check.py` and the test suite before publishing. The exact checksum is provided in the accompanying `.sha256` file.
