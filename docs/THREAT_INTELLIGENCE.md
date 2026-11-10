# Threat Intelligence Guide (CyberForge Server Edition v2.0.5)

## Scope

The v2.0.5 Threat Intelligence subsystem is a bounded local IOC registry and enrichment layer. It is not a full STIX pattern engine, commercial threat-intelligence subscription, malware sandbox or proof of compromise. It stores normalized indicators and selected STIX object summaries, provides local exact-match lookup, and enriches incidents from evidence already present in CyberForge.

## Built-in sources

| Source | Default state | Behavior |
|---|---|---|
| CISA KEV | Disabled | Explicit operator enable and sync of the public JSON catalog; conditional ETag support |
| FIRST EPSS | Enabled for lookup | On-demand CVE query, 1–50 IDs per request, positive cache 6 hours and negative cache 5 minutes |

CISA KEV source URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. FIRST EPSS API: `https://api.first.org/data/v1/epss`. CISA attribution is retained in feed metadata. FIRST.org attribution is included in lookup responses. Check current source terms before redistributing feed data. FIRST documents the API as a lookup path for an individual CVE or a small batch; use its published daily data file for bulk data.

## Supported import types

- **STIX 2.1 bundle:** bounded bundle import, up to 5,000 objects. The parser extracts selected IP, domain, URL and file-hash equality observables, object summaries and relationships. Negated, inequality, temporal/compound and unsupported patterns are ignored. It does not implement the full STIX pattern grammar. STIX revocation and `valid_from` / `valid_until` are respected.
- **TAXII 2.1:** custom discovery/API-root/collection sync. One host only, HTTPS, exact hostname allowlist, no redirects, max five pages and 5,000 objects per sync. API root must use the same hostname as discovery. The client does not discover or contact a second host.
- **Normalized JSON IOC:** manual import from an enabled `json_iocs` feed. Supported types are IPv4, IPv6, IDNA domain, HTTP(S) URL, MD5, SHA-1, SHA-256 and CVE. Values are canonicalized and deduplicated per feed.

## Network policy

Remote feed requests are explicit operator actions. They use HTTPS only, exact host allowlisting and redirect rejection. Built-in hostnames are `www.cisa.gov` and `api.first.org`. Add custom TAXII server hostnames to `CF_THREAT_INTEL_ALLOWED_HOSTS` as a comma-separated list of exact DNS names. IP-literal hosts, nonstandard ports, userinfo, fragments and secret-bearing URL query parameters are rejected.

Feed credentials are read from a named environment variable, such as `TAXII_API_TOKEN`; the secret value is not written to the database or returned by the API. Do not put tokens in URL query parameters. For remote PostgreSQL/control-plane deployments, secure the whole control-plane channel with TLS at the reverse proxy.

**Indicator values are never fetched, opened, DNS-resolved or navigated to.** A URL stored as an IOC is a string for matching only. The feed client fetches only the configured source URL. TAXII redirects are not followed, API root and pagination links are same-host checked, and the page/object count is bounded. These controls reduce risk but do not constitute an independent SSRF or supply-chain security certification; operators should keep custom feeds to trusted hosts.

## Local cache and validity

- Positive local IOC lookup cache: bounded by indicator validity and expiry.
- Negative local IOC lookup cache: 5 minutes.
- IOC import/revocation invalidates the matching IOC lookup cache.
- Revoked, expired and not-yet-valid indicators are excluded from list and lookup.
- FIRST EPSS positive cache: 6 hours; negative cache: 5 minutes.
- EPSS requests are limited to 50 unique CVEs. This is not a bulk EPSS ingestion route.

## API routes

| Method | Route | Scope |
|---|---|---|
| GET | `/api/v205/threat-intel/overview` | `threatintel:read` |
| GET | `/api/v205/threat-intel/feeds` | `threatintel:read` |
| GET | `/api/v205/threat-intel/iocs` | `threatintel:read` |
| GET | `/api/v205/threat-intel/lookup` | `threatintel:read` |
| GET | `/api/v205/threat-intel/incidents/{id}/enrichment` | `threatintel:read` |
| POST | `/api/v205/threat-intel/feeds` | `threatintel:manage` |
| POST | `/api/v205/threat-intel/feeds/{id}/enable` | `threatintel:manage` |
| POST | `/api/v205/threat-intel/feeds/{id}/sync` | `threatintel:manage` |
| POST | `/api/v205/threat-intel/import/stix` | `threatintel:manage` |
| POST | `/api/v205/threat-intel/import/json` | `threatintel:manage` |
| POST | `/api/v205/threat-intel/lookup/batch` | `threatintel:enrich` |
| POST | `/api/v205/threat-intel/epss/lookup` | `threatintel:enrich` |

Roles: admin has all scopes; operator manages feeds and enrichment; analyst reads/enriches; viewer can read; sensor only ingests security telemetry. Creating/enabling/syncing feeds requires an operator or admin.

## Incident and AI enrichment

Incident enrichment checks normalized source/destination IPs and allowlisted domain/file-hash entities already stored in event records. A match is contextual only. The response includes feed attribution, confidence, severity and description. It does not prove the endpoint executed or connected to the indicator.

AI Analyst receives the sanitized enrichment summary together with normalized event evidence. Its system instructions require it to state the feed/source, indicator type and confidence, distinguish a match from independently observed execution, and state uncertainty. Raw feed payloads, credentials, command lines and packet payloads are not sent as threat-intelligence context. Upstream model provider retention and privacy terms still apply if a cloud model is selected.

## PostgreSQL migration and upgrade

For PostgreSQL deployments, apply `migrations/0005_threat_intelligence.sql` using the organization's schema-change process before rolling out v2.0.5 to replicas. SQLite initializes the schema idempotently when the handler starts. Back up the database and test PITR/restore before production upgrades. Keep `CF_THREAT_INTEL_ALLOWED_HOSTS` and TAXII environment credentials in a protected environment file or secret manager; do not replace an existing `server.env` with the sample file.

## Source standards and attribution

- OASIS STIX 2.1 / TAXII 2.1 are standards; CyberForge implements only the bounded functionality listed above.
- CISA KEV: public U.S. government catalog; attribution is retained. Review current catalog terms before redistribution.
- FIRST EPSS: public FIRST.org API; attribution is retained. The API is used for small lookups, not bulk data download.
- Custom feeds are subject to their own license, attribution, privacy, retention and commercial-use terms.
