"""Curated integration registry for CyberForge Server Edition.

The registry describes optional tools and commercial services. It never installs,
executes, or licenses third-party software on behalf of the operator.
"""
from __future__ import annotations

import os
import shutil
from typing import Any

# IDs are stable API identifiers. Binary discovery is PATH-only and non-executing.
INTEGRATIONS: list[dict[str, Any]] = [
    # AI serving and gateway
    {"id": "ollama", "name": "Ollama", "branch": "ai_serving", "license": "Open source", "kind": "runtime", "bins": ["ollama"], "env": ["OLLAMA_HOST", "OLLAMA_URL"], "docs": "https://docs.ollama.com/", "description": "Local model runtime for CPU/GPU inference."},
    {"id": "vllm", "name": "vLLM", "branch": "ai_serving", "license": "Open source", "kind": "runtime", "bins": ["vllm"], "env": ["VLLM_API_KEY", "VLLM_BASE_URL"], "docs": "https://docs.vllm.ai/", "description": "High-throughput GPU model serving and OpenAI-compatible API."},
    {"id": "llamacpp", "name": "llama.cpp", "branch": "ai_serving", "license": "Open source", "kind": "runtime", "bins": ["llama-server", "llama-cli"], "env": ["LLAMACPP_BASE_URL"], "docs": "https://github.com/ggml-org/llama.cpp", "description": "Efficient local inference across supported CPU/GPU backends."},
    {"id": "triton", "name": "NVIDIA Triton", "branch": "ai_serving", "license": "Open source / NVIDIA components", "kind": "runtime", "bins": ["tritonserver"], "env": [], "docs": "https://github.com/triton-inference-server/server", "description": "Multi-framework inference serving and model management."},
    {"id": "litellm", "name": "LiteLLM Gateway", "branch": "ai_gateway", "license": "Open source; enterprise options", "kind": "gateway", "bins": ["litellm"], "env": ["LITELLM_MASTER_KEY", "LITELLM_URL", "DATABASE_URL"], "docs": "https://docs.litellm.ai/", "description": "Unified model gateway, routing, virtual keys, budgets and provider abstraction."},
    {"id": "langfuse", "name": "Langfuse", "branch": "ai_observability", "license": "Open source; cloud plans", "kind": "observability", "bins": [], "env": ["LANGFUSE_HOST", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"], "docs": "https://langfuse.com/docs", "description": "LLM tracing, prompt management and evaluation."},
    {"id": "ray", "name": "Ray Serve", "branch": "ai_serving", "license": "Open source", "kind": "orchestrator", "bins": ["ray"], "env": [], "docs": "https://docs.ray.io/en/latest/serve/", "description": "Scale model serving across processes and nodes."},
    # Observability
    {"id": "prometheus", "name": "Prometheus", "branch": "observability", "license": "Open source", "kind": "metrics", "bins": ["prometheus", "promtool"], "env": ["PROMETHEUS_URL"], "docs": "https://prometheus.io/docs/", "description": "Metrics collection, querying and alert rules."},
    {"id": "grafana", "name": "Grafana", "branch": "observability", "license": "Open source / commercial editions", "kind": "dashboard", "bins": ["grafana-server", "grafana"], "env": ["GRAFANA_URL", "GRAFANA_USER", "GRAFANA_PASSWORD"], "docs": "https://grafana.com/docs/", "description": "Dashboards and operational visualization."},
    {"id": "otel", "name": "OpenTelemetry Collector", "branch": "observability", "license": "Open source", "kind": "telemetry", "bins": ["otelcol", "otelcol-contrib"], "env": [], "docs": "https://opentelemetry.io/docs/collector/", "description": "Vendor-neutral telemetry receivers, processors and exporters."},
    {"id": "loki", "name": "Grafana Loki", "branch": "observability", "license": "Open source / commercial cloud", "kind": "logs", "bins": ["loki"], "env": ["LOKI_URL"], "docs": "https://grafana.com/docs/loki/latest/", "description": "Log aggregation and LogQL querying."},
    {"id": "tempo", "name": "Grafana Tempo", "branch": "observability", "license": "Open source / commercial cloud", "kind": "tracing", "bins": ["tempo"], "env": ["TEMPO_URL"], "docs": "https://grafana.com/docs/tempo/latest/", "description": "Distributed tracing backend."},
    {"id": "victoriametrics", "name": "VictoriaMetrics", "branch": "observability", "license": "Open source / enterprise", "kind": "metrics", "bins": ["victoria-metrics-prod", "vmagent"], "env": [], "docs": "https://docs.victoriametrics.com/", "description": "Efficient time-series storage and metrics collection."},
    # Security operations
    {"id": "wazuh", "name": "Wazuh", "branch": "security_ops", "license": "Open source", "kind": "siem_edr", "bins": ["wazuh-control", "wazuh-logtest"], "env": ["WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD"], "docs": "https://documentation.wazuh.com/", "description": "Endpoint telemetry, security analytics, integrity monitoring and compliance."},
    {"id": "suricata", "name": "Suricata", "branch": "security_ops", "license": "Open source", "kind": "nids", "bins": ["suricata", "suricatasc"], "env": [], "docs": "https://docs.suricata.io/", "description": "Network intrusion detection and protocol metadata via EVE JSON."},
    {"id": "zeek", "name": "Zeek", "branch": "security_ops", "license": "Open source", "kind": "network_monitor", "bins": ["zeek", "zeekctl"], "env": [], "docs": "https://docs.zeek.org/", "description": "Network security monitoring and protocol logs."},
    {"id": "falco", "name": "Falco", "branch": "security_ops", "license": "Open source", "kind": "runtime_security", "bins": ["falco", "falcoctl"], "env": [], "docs": "https://falco.org/docs/", "description": "Runtime threat detection across Linux hosts and containers."},
    {"id": "trivy", "name": "Trivy", "branch": "security_ops", "license": "Open source", "kind": "vulnerability_scanner", "bins": ["trivy"], "env": [], "docs": "https://trivy.dev/", "description": "Vulnerability, misconfiguration, secret and SBOM scanning."},
    {"id": "osquery", "name": "osquery", "branch": "security_ops", "license": "Open source", "kind": "endpoint_query", "bins": ["osqueryi", "osqueryd"], "env": [], "docs": "https://osquery.io/", "description": "SQL-style endpoint inventory and telemetry."},
    {"id": "velociraptor", "name": "Velociraptor", "branch": "security_ops", "license": "Open source / enterprise support", "kind": "dfir", "bins": ["velociraptor"], "env": ["VELOCIRAPTOR_API_URL"], "docs": "https://docs.velociraptor.app/", "description": "Digital forensics, incident response and endpoint collection."},
    {"id": "semgrep", "name": "Semgrep", "branch": "appsec", "license": "Community + commercial plans", "kind": "sast", "bins": ["semgrep"], "env": ["SEMGREP_APP_TOKEN"], "docs": "https://semgrep.dev/docs/", "description": "Static analysis and supply-chain security."},
    {"id": "gitleaks", "name": "Gitleaks", "branch": "appsec", "license": "Open source", "kind": "secret_scanner", "bins": ["gitleaks"], "env": [], "docs": "https://github.com/gitleaks/gitleaks", "description": "Secret scanning for repositories and build pipelines."},
    # Infrastructure and delivery
    {"id": "docker", "name": "Docker Engine", "branch": "containers", "license": "Open source components; commercial Desktop plans", "kind": "container_runtime", "bins": ["docker", "dockerd"], "env": ["DOCKER_HOST"], "docs": "https://docs.docker.com/engine/", "description": "Container lifecycle and image management."},
    {"id": "podman", "name": "Podman", "branch": "containers", "license": "Open source", "kind": "container_runtime", "bins": ["podman"], "env": [], "docs": "https://podman.io/docs", "description": "Daemonless container and pod management."},
    {"id": "kubernetes", "name": "Kubernetes / kubectl", "branch": "orchestration", "license": "Open source", "kind": "orchestrator", "bins": ["kubectl"], "env": ["KUBECONFIG"], "docs": "https://kubernetes.io/docs/", "description": "Cluster workloads, nodes and declarative operations."},
    {"id": "ansible", "name": "Ansible", "branch": "automation", "license": "Open source / Automation Platform commercial", "kind": "automation", "bins": ["ansible", "ansible-playbook"], "env": [], "docs": "https://docs.ansible.com/", "description": "Agentless configuration management and deployment automation."},
    {"id": "terraform", "name": "Terraform / OpenTofu", "branch": "iac", "license": "Business Source / OpenTofu MPL", "kind": "iac", "bins": ["terraform", "tofu"], "env": ["TF_TOKEN"], "docs": "https://developer.hashicorp.com/terraform/docs", "description": "Infrastructure as code; execution remains external and approval-gated."},
    {"id": "postgres", "name": "PostgreSQL", "branch": "data_platform", "license": "Open source", "kind": "database", "bins": ["psql", "pg_isready"], "env": ["DATABASE_URL"], "docs": "https://www.postgresql.org/docs/", "description": "Relational database for scalable server deployments."},
    {"id": "redis", "name": "Redis", "branch": "data_platform", "license": "Source-available / commercial terms vary by distribution", "kind": "cache", "bins": ["redis-server", "redis-cli"], "env": ["REDIS_URL"], "docs": "https://redis.io/docs/", "description": "Caching, rate-limit counters and queues."},
    {"id": "qdrant", "name": "Qdrant", "branch": "ai_data", "license": "Open source / cloud", "kind": "vector_db", "bins": ["qdrant"], "env": ["QDRANT_URL", "QDRANT_API_KEY"], "docs": "https://qdrant.tech/documentation/", "description": "Vector search for RAG and retrieval workloads."},
    {"id": "minio", "name": "MinIO", "branch": "ai_data", "license": "AGPL / commercial terms vary", "kind": "object_storage", "bins": ["minio", "mc"], "env": ["MINIO_ENDPOINT", "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"], "docs": "https://min.io/docs/", "description": "S3-compatible object storage for model and evidence artifacts."},
    # Commercial integrations - API credentials and licenses remain customer-provided.
    {"id": "datadog", "name": "Datadog", "branch": "commercial_observability", "license": "Commercial subscription", "kind": "saas", "bins": [], "env": ["DD_API_KEY", "DD_APP_KEY", "DATADOG_API_URL"], "docs": "https://docs.datadoghq.com/api/latest/", "description": "Commercial metrics, logs, traces and security monitoring."},
    {"id": "splunk", "name": "Splunk Enterprise / Cloud", "branch": "commercial_siem", "license": "Commercial license", "kind": "saas", "bins": [], "env": ["SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN"], "docs": "https://dev.splunk.com/", "description": "Commercial SIEM, log analytics and security investigations."},
    {"id": "crowdstrike", "name": "CrowdStrike Falcon", "branch": "commercial_edr", "license": "Commercial subscription", "kind": "saas", "bins": [], "env": ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL"], "docs": "https://developer.crowdstrike.com/", "description": "Commercial endpoint detection and response API adapter slot."},
    {"id": "sentinelone", "name": "SentinelOne Singularity", "branch": "commercial_edr", "license": "Commercial subscription", "kind": "saas", "bins": [], "env": ["S1_API_TOKEN", "S1_BASE_URL"], "docs": "https://usea1-partners.sentinelone.net/docs/en", "description": "Commercial endpoint security API adapter slot."},
    {"id": "wiz", "name": "Wiz", "branch": "commercial_cloud_security", "license": "Commercial subscription", "kind": "saas", "bins": [], "env": ["WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET", "WIZ_API_URL"], "docs": "https://docs.wiz.io/", "description": "Cloud security posture and workload risk integration slot."},
    {"id": "snyk", "name": "Snyk", "branch": "commercial_appsec", "license": "Free tier + commercial plans", "kind": "saas", "bins": ["snyk"], "env": ["SNYK_TOKEN", "SNYK_API_URL"], "docs": "https://docs.snyk.io/", "description": "Application and dependency security integrations."},
    {"id": "github", "name": "GitHub Enterprise", "branch": "commercial_devops", "license": "Free + paid plans", "kind": "saas", "bins": ["gh"], "env": ["GITHUB_TOKEN", "GITHUB_API_URL"], "docs": "https://docs.github.com/en/enterprise-cloud@latest/rest", "description": "Repository, CI/CD, security alerts and code review integration."},
    {"id": "gitlab", "name": "GitLab", "branch": "commercial_devops", "license": "Free + paid tiers", "kind": "saas", "bins": ["glab"], "env": ["GITLAB_TOKEN", "GITLAB_URL"], "docs": "https://docs.gitlab.com/api/", "description": "Repository, CI/CD, package and security workflows."},
    {"id": "aws", "name": "AWS", "branch": "cloud_providers", "license": "Usage-based commercial cloud", "kind": "cloud", "bins": ["aws"], "env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"], "docs": "https://docs.aws.amazon.com/", "description": "Cloud inventory, cost and workload management integration slot."},
    {"id": "azure", "name": "Microsoft Azure", "branch": "cloud_providers", "license": "Usage-based commercial cloud", "kind": "cloud", "bins": ["az"], "env": ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"], "docs": "https://learn.microsoft.com/azure/", "description": "Cloud resources, cost and identity integration slot."},
    {"id": "gcp", "name": "Google Cloud", "branch": "cloud_providers", "license": "Usage-based commercial cloud", "kind": "cloud", "bins": ["gcloud"], "env": ["GOOGLE_APPLICATION_CREDENTIALS"], "docs": "https://cloud.google.com/docs", "description": "Cloud project, compute and billing integration slot."},
    {"id": "cloudflare", "name": "Cloudflare", "branch": "cloud_edge", "license": "Free + paid plans", "kind": "saas", "bins": [], "env": ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_URL"], "docs": "https://developers.cloudflare.com/api/", "description": "DNS, edge configuration and security analytics integration slot."},
]


def inventory() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in INTEGRATIONS:
        found = [name for name in item.get("bins", []) if shutil.which(name)]
        configured = [name for name in item.get("env", []) if os.environ.get(name)]
        status = "available" if found or configured else "not_configured"
        out.append({
            "id": item["id"], "name": item["name"], "branch": item["branch"],
            "license": item["license"], "kind": item["kind"],
            "status": status, "detected_binaries": found,
            "configured_credentials": configured,
            "credential_count": len(configured), "required_env": item.get("env", []),
            "docs": item["docs"], "description": item["description"],
        })
    return out


def catalog_summary() -> dict[str, Any]:
    items = inventory()
    branches: dict[str, int] = {}
    for x in items:
        branches[x["branch"]] = branches.get(x["branch"], 0) + 1
    return {"total": len(items), "available": sum(x["status"] == "available" for x in items),
            "not_configured": sum(x["status"] == "not_configured" for x in items),
            "branches": branches}
