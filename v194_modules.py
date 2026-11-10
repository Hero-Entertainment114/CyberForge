"""CyberForge v1.9.4: telemetry correlation, sandbox orchestration and safe network enrichment.

All external retrieval is fixed-host, bounded and explicitly opt-in. Network analysis
is defensive: reports distinguish observed facts from hypotheses and coverage gaps.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

VERSION = "1.9.4"
OSV_ENDPOINT = "https://api.osv.dev/v1/query"
ALLOWED_ECOSYSTEMS = {
    "PyPI", "npm", "Maven", "Go", "crates.io", "NuGet", "RubyGems",
    "Packagist", "Hex", "Debian", "Ubuntu", "Alpine", "Pub",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _short(value: Any, limit: int = 500) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(api[_-]?key|token|secret|password)=([^\s&]+)", r"\1=[REDACTED]", text)
    text = re.sub(r"\b(?:sk-|gsk_)[A-Za-z0-9_-]{12,}\b", "[REDACTED_KEY]", text)
    return text[:limit]


def _dynamic_report(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("report"), dict):
        value = value["report"]
    if not isinstance(value, dict):
        raise ValueError("Dynamic report must be a JSON object.")
    schema = str(value.get("schema", ""))
    if schema not in {"cyberforge.netlab.v1", "cyberforge.netlab.v2", "cyberforge.dynamic-sandbox.v1"}:
        raise ValueError("Unsupported dynamic report schema.")
    return value


def _event_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    timeline = report.get("timeline")
    # The NetLab timeline is the canonical merged source. Falling back to events
    # keeps earlier report schemas readable without double-counting current v2 data.
    source = timeline if isinstance(timeline, list) and timeline else report.get("events", [])
    if isinstance(source, list):
        for item in source[:6000]:
            if not isinstance(item, dict): continue
            data = item.get("data", {})
            if not isinstance(data, dict): data = {}
            rows.append({"time": item.get("time", item.get("timestamp")),
                         "type": _short(item.get("type", "event"), 80), "data": data})
    # Legacy Windows reports may keep process/file deltas outside the timeline.
    if not (isinstance(timeline, list) and timeline):
        for key, event_type in (("process_events", "process_start_observed"), ("file_events", "file_change_observed")):
            source = report.get(key)
            if isinstance(source, list):
                for item in source[:1000]:
                    if isinstance(item, dict):
                        data = dict(item); observed = data.pop("observed_at", None)
                        rows.append({"time": observed, "type": event_type, "data": data})
    seen = set(); unique = []
    for row in rows:
        key = (str(row.get("time")), row["type"], json.dumps(row["data"], sort_keys=True, ensure_ascii=False, default=str)[:1200])
        if key not in seen:
            seen.add(key); unique.append(row)
    unique.sort(key=lambda x: str(x.get("time") or ""))
    return unique[:8000]

def _finding_text(finding: dict[str, Any]) -> str:
    fields = ("title", "name", "description", "evidence", "recommendation", "rule_id", "cwe", "code", "snippet")
    return " ".join(_short(finding.get(k, ""), 1500) for k in fields).lower()


def _risk_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(value.lower(), 1)


def _sigma_rule(title: str, log_category: str, field: str, values: list[str], level: str) -> dict[str, Any]:
    clean_values = sorted({_short(x, 180) for x in values if isinstance(x, str) and x.strip()})[:25]
    digest = hashlib.sha256((title + "|" + "|".join(clean_values)).encode("utf-8")).hexdigest()
    return {
        "title": title[:180], "id": f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}",
        "status": "experimental", "description": "Generated from observed sandbox telemetry. Validate field mappings and false positives before deployment.",
        "logsource": {"category": log_category, "product": "linux"},
        "detection": {"selection": {field: clean_values}, "condition": "selection"},
        "falsepositives": ["Legitimate development or administration activity using the same process/domain"],
        "level": level, "confidence": "medium" if clean_values else "low",
    }


def correlate_static_dynamic(static_findings: Any, dynamic_report: Any) -> dict[str, Any]:
    """Correlate static indicators with dynamic behavior without claiming causality."""
    report = _dynamic_report(dynamic_report)
    if isinstance(static_findings, dict):
        static_findings = static_findings.get("findings", [])
    if not isinstance(static_findings, list):
        raise ValueError("static_findings must be a list or a static-analysis result object.")
    findings = [x for x in static_findings[:250] if isinstance(x, dict)]
    events = _event_rows(report)
    # Match PCAP 5-tuples to sink records carrying the sample-side client socket.
    # The PID is best-effort: a short-lived socket may disappear before /proc is read.
    socket_owners = {}
    for event in events:
        data = event["data"]
        if data.get("pid") is None or data.get("peer_port") is None or data.get("local_port") is None:
            continue
        try: socket_owners[(int(data["peer_port"]), int(data["local_port"]))] = (int(data["pid"]), _short(data.get("process", "unknown"), 120))
        except Exception: pass
    for event in events:
        if event["type"].lower() != "pcap_flow_observed": continue
        data = event["data"]
        try: owner = socket_owners.get((int(data.get("src_port", -1)), int(data.get("dst_port", -1))))
        except Exception: owner = None
        if owner:
            data["pid"], data["process"] = owner
            data["attribution"] = "matched_loopback_socket_event"
    domains: set[str] = set(); hosts: set[str] = set(); snis: set[str] = set()
    process_names: set[str] = set(); file_paths: set[str] = set(); registry_items: list[dict[str, Any]] = []
    pids: dict[int, str] = {}
    network_events = []
    for row in events:
        data = row["data"]; typ = row["type"].lower()
        if typ.startswith("dns_"):
            val = _short(data.get("domain", data.get("name", "")), 253).lower().rstrip(".")
            if val: domains.add(val)
            network_events.append(row)
        elif "http" in typ:
            val = _short(data.get("host", ""), 253).lower()
            if val: hosts.add(val)
            network_events.append(row)
        elif "tls" in typ:
            val = _short(data.get("sni", ""), 253).lower()
            if val: snis.add(val)
            network_events.append(row)
        elif "tcp_connection" in typ or "udp_endpoint" in typ or "network_connection" in typ or "pcap_flow" in typ:
            if typ == "pcap_flow_observed":
                dst_ip = _short(data.get("dst", ""), 64)
                if dst_ip: hosts.add(dst_ip.lower())
            network_events.append(row)
        if data.get("pid") is not None:
            try: pids[int(data["pid"])] = _short(data.get("process", data.get("name", "unknown")), 120)
            except Exception: pass
        name = data.get("name") or data.get("process")
        if isinstance(name, str) and name.strip() and ("process" in typ or "start" in typ):
            process_names.add(_short(name, 120))
        path = data.get("path")
        if isinstance(path, str) and ("file" in typ or "created" in typ or "modified" in typ):
            file_paths.add(_short(path, 400))
        if "registry" in typ:
            registry_items.append(row)
    endpoints = sorted(domains | hosts | snis)
    correlations = []
    for index, finding in enumerate(findings):
        txt = _finding_text(finding)
        evidence_hits = []
        for endpoint in endpoints:
            if endpoint and endpoint in txt:
                evidence_hits.append({"type": "endpoint_match", "value": endpoint})
        category = []
        if any(x in txt for x in ("socket", "requests.", "urllib", "urlopen", "http", "https", "dns", "connect(", "network")):
            category.append("network")
        if any(x in txt for x in ("subprocess", "popen", "exec(", "os.system", "child_process", "createprocess", "powershell")):
            category.append("process")
        if any(x in txt for x in ("file write", "write file", "open(", "unlink", "delete", "filesystem", "file path")):
            category.append("file")
        if any(x in txt for x in ("registry", "runonce", "autorun", "startup")):
            category.append("registry")
        observed = []
        if "network" in category and network_events:
            observed.extend({"type": x["type"], "time": x.get("time"), "pid": x["data"].get("pid"),
                             "process": x["data"].get("process"), "domain": x["data"].get("domain", x["data"].get("host", x["data"].get("sni")))}
                            for x in network_events[:8])
        if "process" in category and process_names:
            observed.extend({"type": "process_start_observed", "process": x} for x in sorted(process_names)[:8])
        if "file" in category and file_paths:
            observed.extend({"type": "file_change_observed", "path": x} for x in sorted(file_paths)[:8])
        if "registry" in category and registry_items:
            observed.extend({"type": x["type"], "time": x.get("time"), "data": x["data"]} for x in registry_items[:8])
        if observed or evidence_hits:
            severity = str(finding.get("severity", finding.get("level", "medium"))).lower()
            confidence = "high" if evidence_hits else "medium"
            correlations.append({"finding_index": index, "finding": _short(finding.get("title", finding.get("name", f"Finding {index+1}")), 180),
                                 "severity": severity, "static_categories": category or ["other"],
                                 "correlation_strength": confidence,
                                 "matches": evidence_hits, "dynamic_observations": observed[:16],
                                 "interpretation": "Có sự trùng khớp trực tiếp về IOC." if evidence_hits else
                                                  "Có hành vi động cùng nhóm với finding tĩnh; đây là tương quan, chưa chứng minh chính finding đã được thực thi.",
                                 "false_positive_note": "Một process/domain/file event có thể thuộc runtime hoặc tác vụ hợp pháp; cần xem PID, command line và thời điểm."})
    event_counts: dict[str, int] = {}
    for row in events: event_counts[row["type"]] = event_counts.get(row["type"], 0) + 1
    timeline = [{"time": x.get("time"), "type": x["type"], "pid": x["data"].get("pid"),
                 "process": x["data"].get("process", x["data"].get("name")), "details": x["data"]}
                for x in events[:6000]]
    sigma_rules = []
    if domains:
        sigma_rules.append(_sigma_rule("Observed DNS destinations from CyberForge NetLab", "dns_query", "query|contains", sorted(domains), "medium"))
    if process_names:
        filtered = [x for x in process_names if x.lower() not in {"python3", "python", "sh", "dash", "bash"}]
        if filtered:
            sigma_rules.append(_sigma_rule("Observed child process names from CyberForge NetLab", "process_creation", "Image|endswith", filtered, "medium"))
    high_static = sum(1 for f in findings if _risk_rank(str(f.get("severity", "medium"))) >= 3)
    risk = "high" if high_static and correlations else "medium" if correlations else "undetermined"
    return {
        "schema": "cyberforge.ai.correlation.v1", "created_at": _utc_now(),
        "sample": report.get("sample", {}), "dynamic_schema": report.get("schema"),
        "static_finding_count": len(findings), "dynamic_event_count": len(events),
        "event_counts": event_counts, "risk_posture": risk,
        "observed_network_destinations": endpoints[:500], "observed_processes": sorted(process_names)[:500],
        "observed_file_paths": sorted(file_paths)[:500], "process_pid_map": pids,
        "correlations": correlations[:250], "timeline": timeline,
        "detection_rules": {"sigma": sigma_rules, "status": "experimental; review before production"},
        "coverage": report.get("coverage", {}), "pcap": report.get("pcap", {}),
        "interpretation_limits": [
            "Correlation is not proof that a static finding caused a dynamic event.",
            "Missing telemetry is not evidence of benign behavior; sandbox evasion and coverage gaps are possible.",
            "PID attribution is best-effort and may be unavailable for short-lived sockets.",
            "PCAP may contain raw payloads; it is intentionally excluded from this analysis object and should not be sent to remote AI.",
        ],
    }


def offline_correlation_brief(analysis: dict[str, Any]) -> dict[str, Any]:
    """Deterministic fallback briefing when no local generative model is available."""
    if not isinstance(analysis, dict) or analysis.get("schema") != "cyberforge.ai.correlation.v1":
        raise ValueError("Invalid correlation analysis object.")
    counts = analysis.get("event_counts", {})
    corr = analysis.get("correlations", [])
    destinations = analysis.get("observed_network_destinations", [])
    processes = analysis.get("observed_processes", [])
    lines = ["CyberForge Local Analyst · tương quan tĩnh/động", "",
             f"- Static findings: {analysis.get('static_finding_count', 0)}",
             f"- Dynamic events: {analysis.get('dynamic_event_count', 0)}",
             f"- Correlations: {len(corr)}",
             f"- Risk posture: {analysis.get('risk_posture', 'undetermined')}",
             f"- Network destinations: {len(destinations)}",
             f"- Observed child processes: {len(processes)}", "",
             "Event counts:"]
    lines.extend(f"- {k}: {v}" for k, v in sorted(counts.items())[:30])
    lines.extend(["", "Interpretation:"])
    if corr:
        lines.extend(f"- {x.get('finding')} [{x.get('correlation_strength')}]: {x.get('interpretation')}" for x in corr[:20])
    else:
        lines.append("- Chưa có finding tĩnh nào tương quan được với telemetry hiện tại. Không đồng nghĩa mẫu an toàn.")
    lines.extend(["", "Coverage note: " + "; ".join(analysis.get("interpretation_limits", [])[:4])])
    return {"answer": "\n".join(lines), "provider": "cyberforge-local-correlation-rules", "model": None,
            "offline": True, "cloud_used": False, "correlation_count": len(corr),
            "privacy": "Analysis was computed locally from report metadata; PCAP payload bytes were not included."}


def query_osv_package(ecosystem: str, package: str, version: str, acknowledged: bool = False,
                      timeout: float = 10.0) -> dict[str, Any]:
    """Query OSV with package metadata only; never accepts arbitrary URLs or source files."""
    if acknowledged is not True:
        raise PermissionError("External OSV lookup requires explicit per-request network consent.")
    ecosystem = str(ecosystem or "").strip()
    package = str(package or "").strip()
    version = str(version or "").strip()
    if ecosystem not in ALLOWED_ECOSYSTEMS:
        raise ValueError("Unsupported package ecosystem.")
    if (not package or len(package) > 200 or "\\" in package or package.startswith("/")
            or any(part in {".", ".."} for part in package.split("/"))
            or not re.fullmatch(r"[A-Za-z0-9_.@+:/-]+", package)):
        raise ValueError("Package name is invalid.")
    if not version or len(version) > 100 or not re.fullmatch(r"[A-Za-z0-9_.+!-]+", version):
        raise ValueError("Package version is invalid.")
    body = json.dumps({"package": {"name": package, "ecosystem": ecosystem}, "version": version}).encode("utf-8")
    request = urllib.request.Request(OSV_ENDPOINT, data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "CyberForge-AIO/1.9.4"},
        method="POST")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise urllib.error.HTTPError(req.full_url, code, "redirect blocked", headers, fp)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=max(2.0, min(float(timeout), 15.0))) as response:
            raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise RuntimeError("OSV response exceeded the 1 MB limit.")
            payload = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429: raise RuntimeError("OSV rate limit reached; retry later.") from None
        raise RuntimeError(f"OSV lookup failed (HTTP {exc.code}).") from None
    except urllib.error.URLError as exc:
        raise RuntimeError("OSV is unreachable: " + type(exc.reason).__name__) from None
    except TimeoutError:
        raise RuntimeError("OSV lookup timed out.") from None
    vulns = []
    for item in (payload.get("vulns") or [])[:50]:
        if not isinstance(item, dict): continue
        refs = []
        for ref in (item.get("references") or [])[:8]:
            if isinstance(ref, dict) and str(ref.get("url", "")).startswith("https://"):
                refs.append(_short(ref.get("url"), 300))
        vulns.append({"id": _short(item.get("id", ""), 80), "summary": _short(item.get("summary", ""), 600),
                      "modified": _short(item.get("modified", ""), 80),
                      "aliases": [_short(x, 80) for x in (item.get("aliases") or [])[:10]],
                      "references": refs})
    return {"source": "OSV.dev", "query": {"ecosystem": ecosystem, "package": package, "version": version},
            "checked_at": _utc_now(), "vulnerability_count": len(vulns), "vulnerabilities": vulns,
            "data_sent": "Only ecosystem, package name and version were sent to api.osv.dev. No source code, PCAP or local file was uploaded.",
            "limits": "OSV results are a vulnerability index, not proof of exploitability or completeness."}
