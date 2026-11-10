# Contributing to CyberForge Server Edition

Thank you for considering a contribution.

## Contribution requirements

- Keep changes focused and document operational impact.
- Never commit API keys, passwords, private keys, `.env` files, database backups, logs, customer telemetry, or incident evidence.
- Preserve loopback-by-default binding, TLS requirements for remote databases/providers, RBAC, audit logging, and approval gates.
- Do not add arbitrary remote-shell or endpoint-control capabilities without a separately reviewed threat model and explicit authorization design.
- Clearly distinguish tested connectors from catalog metadata and simulated fixtures.
- Include regression tests and migration coverage for database changes.

## Local checks

Use Python 3.10 or newer. From the repository root:

```bash
python -m compileall -q .
python -m unittest discover -s tests -v
python tools/release_check.py
```

The three PostgreSQL integration tests require a test database configured with `CF_TEST_POSTGRES_URL`. Redis, GPU, and vendor-specific checks require the respective services/hardware/accounts and should be reported separately.

## Pull requests

Describe the problem, operational assumptions, migration behavior, security impact, test environment, and rollback strategy. Third-party integrations must retain their upstream license and attribution.
