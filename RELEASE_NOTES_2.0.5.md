# CyberForge Server Edition v2.0.5 — Threat Intelligence

## Added

- Local IOC registry and exact-match enrichment for IPv4/IPv6, IDNA domains, HTTP(S) URLs, MD5, SHA-1, SHA-256 and CVE IDs.
- Built-in CISA KEV JSON catalog (disabled by default, explicit operator enable/sync, ETag support).
- FIRST EPSS on-demand CVE lookup for 1–50 unique CVEs, with local 6-hour positive and 5-minute negative cache.
- Manual STIX 2.1 bundle import, bounded to 5,000 objects and a supported observable equality subset.
- TAXII 2.1 discovery, collection selection, same-host API root validation, bounded pagination and environment-based credentials.
- Manual normalized JSON IOC import.
- IOC validity/revocation processing, cache invalidation, incident enrichment and sanitized Threat Intelligence context in AI Analyst prompts.
- Threat Intelligence dashboard and `/api/v205/threat-intel/*` API routes with separate read/manage/enrich scopes.

## Security and correctness

- Remote feed sync is operator-initiated, HTTPS-only, exact-host-allowlisted and redirect-free. Custom TAXII hosts must be explicitly listed in `CF_THREAT_INTEL_ALLOWED_HOSTS`.
- Indicator values are never opened, DNS-resolved or fetched. Feed source URLs are separate from indicator values.
- Credentials are referenced by environment-variable name and never returned in feed API responses.
- Secret-bearing feed URL query parameters, userinfo, fragments, IP-literal hosts and nonstandard ports are rejected.
- STIX NOT/inequality/compound and unsupported patterns are ignored rather than interpreted as positive IOCs.
- Expired, revoked and not-yet-valid indicators are excluded from lookup and active counts.
- Threat-intelligence matches are contextual evidence, not proof of compromise.

## Data and compatibility

- SQLite schema initializes idempotently. PostgreSQL migration: `migrations/0005_threat_intelligence.sql`.
- Existing v2.0.0–v2.0.4 API namespaces remain available.
- No proprietary executable, paid feed, model weight or vendor license is bundled.

See `docs/THREAT_INTELLIGENCE.md`, `LICENSES_AND_COMPONENTS.md` and `TEST_RESULTS_2.0.5.md`.
