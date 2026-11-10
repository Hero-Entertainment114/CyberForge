# Third-party integrations and license boundaries

CyberForge Server Edition is a control plane and integration layer. This source archive does not redistribute proprietary executables, paid model weights, paid subscriptions, customer credentials, vendor API keys or license files.

## Open-source integration targets

The catalog includes local runtimes and services such as Ollama, vLLM, llama.cpp, NVIDIA Triton, LiteLLM, Ray Serve, OpenTelemetry Collector, Prometheus, Grafana, Loki, Tempo, VictoriaMetrics, Wazuh, Suricata, Zeek, Falco, Trivy, osquery, Velociraptor, Semgrep Community, Gitleaks, Docker Engine, Podman, Kubernetes, Ansible, OpenTofu, PostgreSQL, Redis, Qdrant and MinIO. Each project has its own license and installation requirements. The operator must check the current upstream license and compatibility before deployment.

## Commercial / paid integration targets

The catalog can describe commercial services including Datadog, Splunk, CrowdStrike Falcon, SentinelOne, Wiz, Snyk commercial plans, GitHub Enterprise, GitLab paid tiers, AWS, Azure, Google Cloud and commercial model endpoints. Product-specific health adapters are enabled only for a selected subset. Other entries are inventory/documentation metadata, not complete native control integrations.

To use a commercial connector, the customer must obtain the vendor account, appropriate subscription/entitlement and API credentials. Credentials are configured in root-owned environment files or an external secrets manager. CyberForge neither obtains a license nor bypasses vendor billing or rate limits.

## Redistribution

- No proprietary binary is bundled in this release.
- No model weights are bundled.
- Third-party tools are installed and upgraded by the operator from official vendor/maintainer channels.
- Connector metadata and documentation links do not imply endorsement, certification or license compatibility.


## Threat intelligence sources and standards

- **CISA Known Exploited Vulnerabilities (KEV):** CyberForge references the public CISA JSON catalog. Attribution is retained in feed metadata and reports. Review the current CISA catalog terms and notices before redistributing snapshots.
- **FIRST EPSS:** CyberForge calls the public FIRST.org EPSS API on demand for small CVE batches and records attribution. The API is a lookup path; it is not used as a bulk-feed downloader. For bulk data, follow FIRST's published download guidance.
- **STIX 2.1 / TAXII 2.1:** These are OASIS standards. CyberForge implements a bounded STIX observable-equality subset and TAXII collection client; it does not redistribute OASIS specifications or claim full standard conformance.
- **Custom feeds:** The operator is responsible for reviewing the source license, terms of use, data-retention restrictions and commercial-use conditions. CyberForge stores the feed name/type and selected attribution metadata, not a license grant.
