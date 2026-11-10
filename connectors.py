"""Explicit, read-only health checks for selected third-party integrations.

Only fixed HTTP paths and fixed credential headers are supported. No URLs,
headers, methods, or request bodies are accepted from browser input.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


class ConnectorError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Connector IDs and paths are source-controlled; clients can only choose an ID.
# base_env, path, required credentials, and header scheme are fixed per connector.
CHECKS = {
    "ollama": {"base_env": "OLLAMA_URL", "default": "http://127.0.0.1:11434", "path": "/api/tags", "headers": "none"},
    "vllm": {"base_env": "VLLM_BASE_URL", "path": "/health", "headers": "bearer_optional", "key_env": "VLLM_API_KEY"},
    "llamacpp": {"base_env": "LLAMACPP_BASE_URL", "path": "/health", "headers": "none"},
    "litellm": {"base_env": "LITELLM_URL", "path": "/health/liveliness", "headers": "bearer_optional", "key_env": "LITELLM_MASTER_KEY"},
    "prometheus": {"base_env": "PROMETHEUS_URL", "path": "/-/healthy", "headers": "none"},
    "grafana": {"base_env": "GRAFANA_URL", "path": "/api/health", "headers": "basic_optional", "user_env": "GRAFANA_USER", "key_env": "GRAFANA_PASSWORD"},
    "loki": {"base_env": "LOKI_URL", "path": "/ready", "headers": "none"},
    "tempo": {"base_env": "TEMPO_URL", "path": "/ready", "headers": "none"},
    "langfuse": {"base_env": "LANGFUSE_HOST", "path": "/api/public/health", "headers": "none"},
    "qdrant": {"base_env": "QDRANT_URL", "path": "/collections", "headers": "api_key", "key_env": "QDRANT_API_KEY"},
    "minio": {"base_env": "MINIO_ENDPOINT", "path": "/minio/health/live", "headers": "none"},
    "datadog": {"base_env": "DATADOG_API_URL", "default": "https://api.datadoghq.com", "path": "/api/v1/validate", "headers": "datadog", "key_env": "DD_API_KEY"},
    "splunk": {"base_env": "SPLUNK_HEC_URL", "path": "/services/collector/health", "headers": "splunk", "key_env": "SPLUNK_HEC_TOKEN"},
    "cloudflare": {"base_env": "CLOUDFLARE_API_URL", "default": "https://api.cloudflare.com/client/v4", "path": "/user/tokens/verify", "headers": "bearer", "key_env": "CLOUDFLARE_API_TOKEN"},
    "github": {"base_env": "GITHUB_API_URL", "default": "https://api.github.com", "path": "/user", "headers": "bearer", "key_env": "GITHUB_TOKEN"},
    "gitlab": {"base_env": "GITLAB_URL", "path": "/api/v4/user", "headers": "private_token", "key_env": "GITLAB_TOKEN"},
    "snyk": {"base_env": "SNYK_API_URL", "default": "https://api.snyk.io/rest", "path": "/orgs?version=2024-10-15", "headers": "bearer", "key_env": "SNYK_TOKEN"},
}


def test_supported(connector_id: str) -> bool:
    return connector_id in CHECKS


def test_connector(connector_id: str) -> dict:
    cfg = CHECKS.get(connector_id)
    if not cfg:
        raise ConnectorError("connector_test_not_supported")
    base = (os.getenv(cfg["base_env"]) or cfg.get("default") or "").strip().rstrip("/")
    if not base:
        raise ConnectorError("connector_endpoint_not_configured")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConnectorError("connector_invalid_endpoint")
    host = parsed.hostname.lower()
    local = host in {"127.0.0.1", "localhost", "::1"}
    allow = {x.strip().lower() for x in os.getenv("CF_CONNECTOR_ALLOWED_HOSTS", "").split(",") if x.strip()}
    if not local and host not in allow:
        raise ConnectorError("connector_host_not_allowlisted")
    if not local and parsed.scheme != "https":
        raise ConnectorError("connector_remote_requires_https")
    headers = {"Accept": "application/json, text/plain, */*", "User-Agent": "CyberForge-Server/2.1.0"}
    mode = cfg["headers"]
    key = os.getenv(cfg.get("key_env", ""), "") if cfg.get("key_env") else ""
    if mode in {"bearer", "api_key", "splunk", "datadog", "private_token"} and not key:
        raise ConnectorError("connector_credentials_missing")
    if mode in {"bearer", "bearer_optional"} and key:
        headers["Authorization"] = "Bearer " + key
    elif mode == "api_key" and key:
        headers["api-key"] = key
    elif mode == "splunk" and key:
        headers["Authorization"] = "Splunk " + key
    elif mode == "datadog" and key:
        headers["DD-API-KEY"] = key
    elif mode == "private_token" and key:
        headers["PRIVATE-TOKEN"] = key
    elif mode == "basic_optional":
        user, password = os.getenv(cfg.get("user_env", ""), ""), key
        if user and password:
            import base64
            headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    url = base + cfg["path"]
    req = urllib.request.Request(url, headers=headers, method="GET")
    started = time.monotonic()
    try:
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=7) as response:
            code = int(response.status)
            content = response.read(65536)
    except urllib.error.HTTPError as exc:
        # Do not expose provider response bodies; they may contain account or tenant data.
        code = int(exc.code)
        content = b""
    except urllib.error.URLError as exc:
        raise ConnectorError("connector_unreachable") from exc
    except (TimeoutError, OSError) as exc:
        raise ConnectorError("connector_unreachable") from exc
    elapsed = int((time.monotonic() - started) * 1000)
    connected = 200 <= code < 300
    summary = "HTTP health check succeeded" if connected else ("Authentication rejected" if code in {401, 403} else "Health check returned a non-success status")
    return {"id": connector_id, "connected": connected, "http_status": code, "latency_ms": elapsed,
            "summary": summary, "tested_at": time.time()}
