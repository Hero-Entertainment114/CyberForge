"""CyberForge Security Operations: bounded event ingestion, incident correlation and approved playbooks.

The module is deliberately defensive and data-oriented. It parses telemetry from
fixed source formats; it does not run scanners, execute commands, block traffic,
kill processes, or remotely administer endpoints.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import uuid

import detection_engine
from datetime import datetime, timezone
from typing import Any

SOURCES = ("wazuh", "suricata", "zeek", "falco", "trivy", "osquery")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: len(SEVERITIES) - rank for rank, name in enumerate(SEVERITIES)}
INCIDENT_STATUSES = ("open", "acknowledged", "investigating", "contained", "resolved", "closed")
MAX_BATCH = 100
MAX_DETAILS_BYTES = 8192

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "incident_triage": {
        "title": "Incident triage and timeline",
        "description": "Collect related normalized events, order them into a timeline and summarize observed evidence.",
        "steps": ["collect_recent_events", "build_timeline", "summarize_evidence"],
    },
    "detection_rule_draft": {
        "title": "Draft a CyberForge detection rule",
        "description": "Create a data-only rule for matching this incident in CyberForge normalized events.",
        "steps": ["collect_recent_events", "draft_detection_rule"],
    },
    "response_checklist": {
        "title": "Prepare a manual response checklist",
        "description": "Prepare defensive verification and containment recommendations. No host or network changes are made.",
        "steps": ["collect_recent_events", "prepare_response_checklist"],
    },
    "evidence_manifest": {
        "title": "Build an evidence manifest",
        "description": "Create a hashed manifest of collected event identifiers and normalized metadata.",
        "steps": ["collect_recent_events", "preserve_evidence_manifest"],
    },
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_incidents(
  incident_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  event_count BIGINT NOT NULL DEFAULT 0,
  assigned_to TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE TABLE IF NOT EXISTS security_events(
  event_id TEXT PRIMARY KEY,
  incident_id TEXT,
  source TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  host TEXT,
  node_id TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  process_name TEXT,
  rule_id TEXT,
  details_json TEXT NOT NULL,
  UNIQUE(source, source_event_id)
);
CREATE INDEX IF NOT EXISTS idx_security_events_incident_time ON security_events(incident_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_security_events_source_time ON security_events(source, observed_at);
CREATE INDEX IF NOT EXISTS idx_security_incidents_status_severity ON security_incidents(status, severity, updated_at);
CREATE TABLE IF NOT EXISTS security_playbook_runs(
  run_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  playbook_id TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_by_id TEXT NOT NULL,
  approved_by TEXT,
  approved_by_id TEXT,
  created_at TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  approved_at TEXT,
  executed_at TEXT,
  result_json TEXT,
  error_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_security_playbook_incident ON security_playbook_runs(incident_id, created_at);
CREATE INDEX IF NOT EXISTS idx_security_playbook_status ON security_playbook_runs(status, expires_at);
CREATE TABLE IF NOT EXISTS security_incident_links(
  incident_a TEXT NOT NULL,
  incident_b TEXT NOT NULL,
  confidence REAL NOT NULL,
  relation TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(incident_a, incident_b),
  CHECK(incident_a < incident_b)
);
CREATE INDEX IF NOT EXISTS idx_security_incident_links_b ON security_incident_links(incident_b, confidence);
"""


def initialize(store) -> None:
    with store.lock, store.connect() as con:
        con.executescript(_SCHEMA)
    detection_engine.initialize(store)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _text(value: Any, limit: int = 240) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = str(value).replace("\x00", " ").strip()
    # Remove common inline credentials from tool-generated summaries.
    text = re.sub(r"(?i)\b(password|passwd|token|secret|authorization|cookie|api[_-]?key)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
    return text[:limit]


def _pick(mapping: Any, *keys: str, default=None):
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default


def _nested(mapping: Any, *paths: str, default=None):
    for path in paths:
        # Zeek JSON commonly emits dotted field names literally (e.g. `id.orig_h`),
        # while some adapters wrap those values in nested objects. Support both.
        if isinstance(mapping, dict) and mapping.get(path) not in (None, ""):
            return mapping[path]
        current = mapping
        for part in path.split("."):
            current = current.get(part) if isinstance(current, dict) else None
        if current not in (None, ""):
            return current
    return default


def _ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    try:
        number = int(value)
        return number if 1 <= number <= 65535 else None
    except (TypeError, ValueError):
        return None


def _timestamp(value: Any) -> str:
    if value in (None, ""):
        return _now()
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace(".", "", 1).isdigit()):
            number = float(value)
            if number > 10_000_000_000:
                number /= 1000
            return datetime.fromtimestamp(number, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        # Wazuh/Suricata timestamps may use +0000 without a colon.
        if re.search(r"[+-]\d{4}$", raw):
            raw = raw[:-5] + raw[-5:-2] + ":" + raw[-2:]
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError, TypeError):
        return _now()


def _severity(value: Any, *, source: str) -> str:
    if source == "wazuh":
        try:
            level = int(value or 0)
        except (TypeError, ValueError):
            level = 0
        return "critical" if level >= 14 else "high" if level >= 11 else "medium" if level >= 7 else "low" if level >= 3 else "info"
    if source == "suricata":
        try:
            level = int(value)
        except (TypeError, ValueError):
            level = 4
        return {1: "critical", 2: "high", 3: "medium", 4: "low"}.get(level, "info")
    if source == "falco":
        token = _text(value, 40).lower()
        return {"emergency": "critical", "alert": "critical", "critical": "critical", "error": "high",
                "warning": "medium", "notice": "low", "informational": "info", "info": "info", "debug": "info"}.get(token, "medium")
    if source == "trivy":
        token = _text(value, 30).lower()
        return token if token in SEVERITIES else "info"
    if source == "zeek":
        token = _text(value, 60).lower()
        return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(token, "medium")
    if source == "osquery":
        return "low" if _text(value, 20).lower() == "added" else "info"
    token = _text(value, 20).lower()
    return token if token in SEVERITIES else "info"


def _details(source: str, raw: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"source": source}
    # Only selected metadata fields are retained. Raw payloads, headers, file
    # contents, arbitrary columns and credentials are deliberately excluded.
    allow = ("event_type", "action", "protocol", "proto", "service", "category", "tags", "location",
             "signature_id", "flow_id", "uid", "query", "query_name", "package", "installed_version",
             "fixed_version", "vulnerability_id", "target", "resource", "file_path", "rule_level")
    for key in allow:
        val = raw.get(key)
        if val in (None, ""):
            continue
        if isinstance(val, list):
            result[key] = [_text(x, 100) for x in val[:20]]
        elif isinstance(val, (str, int, float, bool)):
            result[key] = _text(val, 240)
    if extra:
        for key, value in extra.items():
            if value not in (None, ""):
                result[key] = _text(value, 240)
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_DETAILS_BYTES:
        result = {"source": source, "truncated": True}
    return result


def _event(source: str, *, source_id: Any, observed_at: Any, severity: str, category: str,
           title: str, host: Any = None, node_id: Any = None, src_ip: Any = None, dst_ip: Any = None,
           src_port: Any = None, dst_port: Any = None, process_name: Any = None, rule_id: Any = None,
           details: dict[str, Any] | None = None, create_incident: bool = True) -> dict[str, Any]:
    details = details or {"source": source}
    canonical = json.dumps({"source": source, "source_id": source_id, "title": title, "observed_at": observed_at},
                           ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    source_event_id = _text(source_id, 180) or hashlib.sha256(canonical.encode()).hexdigest()
    # Avoid extremely long or control-character event identifiers.
    source_event_id = re.sub(r"[\x00-\x1f]", "", source_event_id)[:180] or hashlib.sha256(canonical.encode()).hexdigest()
    norm = {
        "source": source, "source_event_id": source_event_id,
        "observed_at": _timestamp(observed_at), "severity": severity if severity in SEVERITIES else "info",
        "category": _text(category or "general", 80) or "general", "title": _text(title or "Security event", 240),
        "host": _text(host, 100) or None, "node_id": _text(node_id, 80) or None,
        "src_ip": _ip(src_ip), "dst_ip": _ip(dst_ip), "src_port": _port(src_port), "dst_port": _port(dst_port),
        "process_name": _text(process_name, 120) or None, "rule_id": _text(rule_id, 120) or None,
        "details": details, "create_incident": bool(create_incident),
    }
    fp_base = {"source": source, "rule_id": norm["rule_id"], "category": norm["category"],
               "title": norm["title"], "src_ip": norm["src_ip"], "dst_ip": norm["dst_ip"]}
    norm["fingerprint"] = hashlib.sha256(json.dumps(fp_base, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return norm


def _normalize_one(source: str, raw: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(raw, dict):
        raise ValueError("security_event_invalid")
    source = source.lower()
    if source not in SOURCES:
        raise ValueError("security_source_not_supported")

    if source == "wazuh":
        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        level = _pick(rule, "level", default=0)
        severity = _severity(level, source=source)
        rule_id = _pick(rule, "id", default="wazuh")
        title = _pick(rule, "description", default="Wazuh security alert")
        extra = {"rule_level": level, "location": raw.get("location")}
        return [_event(source, source_id=_pick(raw, "id", default=f"{raw.get('timestamp','')}:{rule_id}:{agent.get('id','')}"),
                       observed_at=raw.get("timestamp"), severity=severity, category=_pick(rule, "groups", default="wazuh_alert"),
                       title=title, host=_pick(agent, "name"), node_id=_pick(agent, "id"),
                       src_ip=_pick(data, "srcip", "src_ip"), dst_ip=_pick(data, "dstip", "dst_ip"),
                       process_name=_pick(data, "process", "process_name"), rule_id=rule_id,
                       details=_details(source, raw, extra), create_incident=severity != "info")]

    if source == "suricata":
        kind = _pick(raw, "event_type", default="unknown")
        if kind not in {"alert", "anomaly"}:
            return []
        alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
        severity = _severity(_pick(alert, "severity", default=4), source=source)
        rule_id = _pick(alert, "signature_id", default=kind)
        title = _pick(alert, "signature", default=f"Suricata {kind}")
        return [_event(source, source_id=_pick(raw, "event_id", default=f"{raw.get('flow_id','')}:{kind}:{rule_id}:{raw.get('pcap_cnt','')}:{raw.get('timestamp','')}"),
                       observed_at=raw.get("timestamp"), severity=severity, category=_pick(alert, "category", default=kind),
                       title=title, host=raw.get("host"), src_ip=raw.get("src_ip"), dst_ip=raw.get("dest_ip"),
                       src_port=raw.get("src_port"), dst_port=raw.get("dest_port"), rule_id=rule_id,
                       details=_details(source, raw, {"event_type": kind, "action": alert.get("action"), "protocol": raw.get("proto"),
                                                        "signature_id": rule_id, "flow_id": raw.get("flow_id")}))]

    if source == "falco":
        output_fields = raw.get("output_fields") if isinstance(raw.get("output_fields"), dict) else {}
        priority = _pick(raw, "priority", default="warning")
        severity = _severity(priority, source=source)
        rule_id = _pick(raw, "rule", default="falco")
        process = _pick(output_fields, "proc.name", "proc.exepath", "proc.pname")
        title = _pick(raw, "rule", default="Falco runtime alert")
        summary = _text(_pick(raw, "output", default=title), 240)
        # Falco output_fields can contain command lines/credentials; keep only
        # a few non-secret process/container labels.
        allowed_fields = {}
        for key in ("proc.name", "proc.pname", "container.name", "k8s.pod.name", "evt.type", "fd.type"):
            if key in output_fields:
                allowed_fields[key] = _text(output_fields[key], 120)
        return [_event(source, source_id=_pick(raw, "event_id", default=f"{raw.get('time','')}:{raw.get('hostname','')}:{rule_id}:{process or ''}:{summary}"),
                       observed_at=raw.get("time"), severity=severity, category="runtime_detection", title=title,
                       host=raw.get("hostname"), process_name=process, rule_id=rule_id,
                       details=_details(source, raw, {"priority": priority, "output_summary": summary, **allowed_fields}))]

    if source == "zeek":
        kind = _pick(raw, "_path", "log_type", default="zeek_event")
        if kind in {"conn", "dns", "http", "ssl", "x509", "files"}:
            severity, create_incident = "info", False
        elif kind == "notice":
            severity, create_incident = _severity(_pick(raw, "severity", default="medium"), source=source), True
        elif kind == "weird":
            severity, create_incident = "low", True
        else:
            severity, create_incident = "info", False
        src_port = _nested(raw, "id.orig_p")
        dst_port = _nested(raw, "id.resp_p")
        title = _pick(raw, "note", "msg", default=f"Zeek {kind} event")
        return [_event(source, source_id=f"{_pick(raw, 'uid', default='zeek')}:{kind}:{title}:{raw.get('ts','')}:{raw.get('id.orig_h','')}:{raw.get('id.resp_h','')}",
                       observed_at=raw.get("ts"), severity=severity, category=_text(kind, 80), title=title,
                       host=_pick(raw, "host", "server_name"), src_ip=_nested(raw, "id.orig_h"), dst_ip=_nested(raw, "id.resp_h"),
                       src_port=src_port, dst_port=dst_port, rule_id=_pick(raw, "note", default=kind),
                       details=_details(source, raw, {"event_type": kind, "uid": raw.get("uid"), "service": raw.get("service"),
                                                        "protocol": raw.get("proto")} ), create_incident=create_incident)]

    if source == "trivy":
        output: list[dict[str, Any]] = []
        results = raw.get("Results") if isinstance(raw.get("Results"), list) else []
        if not results:
            # Accept a single finding-shaped payload as well.
            results = [raw]
        for result in results[:200]:
            if not isinstance(result, dict):
                continue
            target = _pick(result, "Target", "target", default="unknown-target")
            for collection, kind in (("Vulnerabilities", "vulnerability"), ("Misconfigurations", "misconfiguration"),
                                     ("Secrets", "secret"), ("Licenses", "license")):
                findings = result.get(collection) if isinstance(result.get(collection), list) else []
                for finding in findings[:300]:
                    if not isinstance(finding, dict):
                        continue
                    severity = _severity(_pick(finding, "Severity", "severity"), source=source)
                    vuln_id = _pick(finding, "VulnerabilityID", "ID", "AVDID", default=kind)
                    pkg = _pick(finding, "PkgName", "PackageName", default="")
                    title = _pick(finding, "Title", "Message", default=f"{kind.title()} {vuln_id}")
                    fid = f"{target}:{kind}:{vuln_id}:{pkg}:{_pick(finding,'InstalledVersion',default='')}"
                    output.append(_event(source, source_id=fid, observed_at=_pick(raw, "CreatedAt", "created_at"),
                                         severity=severity, category=kind, title=title, host=target,
                                         rule_id=vuln_id, details=_details(source, {}, {
                                             "target": target, "package": pkg, "installed_version": _pick(finding, "InstalledVersion"),
                                             "fixed_version": _pick(finding, "FixedVersion"), "vulnerability_id": vuln_id,
                                             "file_path": _pick(finding, "PrimaryURL", "PkgPath", "Target"),
                                             "severity": severity, "finding_type": kind,
                                         })))
        return output

    # osquery differential/result logs. Query result columns may contain secrets,
    # so only a short process label and column names are retained.
    action = _pick(raw, "action", default="snapshot")
    columns = raw.get("columns") if isinstance(raw.get("columns"), dict) else {}
    process = _pick(columns, "name", "process_name", "path")
    query_name = _pick(raw, "name", default="osquery event")
    severity = _severity(action, source=source)
    details = _details(source, raw, {"action": action, "query_name": query_name,
                                     "column_names": ",".join(sorted(_text(k, 50) for k in columns.keys())[:24])})
    return [_event(source, source_id=_pick(raw, "uuid", default=f"{raw.get('hostIdentifier','')}:{query_name}:{action}:{raw.get('unixTime','')}:{process or ''}"),
                   observed_at=_pick(raw, "calendarTime", "unixTime"), severity=severity, category="endpoint_query",
                   title=f"osquery {action}: {query_name}", host=raw.get("hostIdentifier"),
                   process_name=process, rule_id=query_name, details=details, create_incident=severity != "info")]


def normalize(source: str, raw: dict[str, Any]) -> list[dict[str, Any]]:
    if source not in SOURCES:
        raise ValueError("security_source_not_supported")
    events = _normalize_one(source, raw)
    # Enrichment is a separate bounded layer: parser output remains normalized,
    # while process/network entities and ATT&CK candidate labels are attached
    # only from explicitly allowlisted metadata fields.
    from security_intelligence import enrich_event
    return [enrich_event(event, source, raw) for event in events]


def ingest(store, source: str, items: list[dict[str, Any]], actor: str) -> dict[str, Any]:
    source = source.lower()
    if source not in SOURCES:
        raise ValueError("security_source_not_supported")
    if not isinstance(items, list) or not items or len(items) > MAX_BATCH:
        raise ValueError("security_batch_invalid")
    normalized: list[dict[str, Any]] = []
    ignored = 0
    for item in items:
        events = normalize(source, item)
        if not events:
            ignored += 1
        normalized.extend(events)
        if len(normalized) > 500:
            raise ValueError("security_batch_too_large")
    accepted, duplicates, incident_ids, detection_matches = 0, 0, set(), 0
    now = _now()
    with store.lock, store.connect() as con:
        active_detection_rules = detection_engine.load_active_rules(con) if normalized else []
        for event in normalized:
            incident_id = None
            if event["create_incident"]:
                proposed = "inc_" + uuid.uuid4().hex[:20]
                con.execute("""INSERT INTO security_incidents(incident_id,fingerprint,status,severity,title,category,first_seen,last_seen,event_count,created_at,updated_at)
                              VALUES(?,?,?,?,?,?,?,?,0,?,?) ON CONFLICT(fingerprint) DO NOTHING""",
                            (proposed, event["fingerprint"], "open", event["severity"], event["title"], event["category"],
                             event["observed_at"], event["observed_at"], now, now))
                inc = con.execute("SELECT incident_id,severity,status FROM security_incidents WHERE fingerprint=?", (event["fingerprint"],)).fetchone()
                incident_id = inc["incident_id"]
            event_id = "evt_" + uuid.uuid4().hex[:20]
            details_json = json.dumps(event["details"], ensure_ascii=False, separators=(",", ":"))
            cur = con.execute("""INSERT INTO security_events(event_id,incident_id,source,source_event_id,observed_at,received_at,severity,category,title,host,node_id,src_ip,dst_ip,src_port,dst_port,process_name,rule_id,details_json)
                                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source,source_event_id) DO NOTHING""",
                              (event_id, incident_id, source, event["source_event_id"], event["observed_at"], now, event["severity"],
                               event["category"], event["title"], event["host"], event["node_id"], event["src_ip"], event["dst_ip"],
                               event["src_port"], event["dst_port"], event["process_name"], event["rule_id"], details_json))
            if getattr(cur, "rowcount", 0) == 0:
                duplicates += 1
                continue
            accepted += 1
            detection_matches += detection_engine.evaluate_in_transaction(con, event, event_id, active_detection_rules)
            if incident_id:
                incident_ids.add(incident_id)
                inc_severity = inc["severity"]
                strongest = event["severity"] if SEVERITY_RANK[event["severity"]] > SEVERITY_RANK[inc_severity] else inc_severity
                new_status = "open" if inc["status"] in {"resolved", "closed"} else inc["status"]
                con.execute("UPDATE security_incidents SET event_count=event_count+1,first_seen=CASE WHEN first_seen>? THEN ? ELSE first_seen END,last_seen=CASE WHEN last_seen<? THEN ? ELSE last_seen END,severity=?,status=?,updated_at=?,closed_at=CASE WHEN ?='open' THEN NULL ELSE closed_at END WHERE incident_id=?",
                            (event["observed_at"], event["observed_at"], event["observed_at"], event["observed_at"], strongest, new_status, now, new_status, incident_id))
        if accepted:
            store.audit(con, actor, "security.events.ingested", source, {"accepted": accepted, "duplicates": duplicates, "ignored": ignored, "incidents_touched": len(incident_ids)})
    return {"accepted": accepted, "duplicates": duplicates, "ignored": ignored,
            "detection_matches": detection_matches,
            "incidents_touched": len(incident_ids), "incident_ids": sorted(incident_ids)[:100]}


def overview(store) -> dict[str, Any]:
    with store.lock, store.connect() as con:
        incidents = con.execute("SELECT status,severity,COUNT(*) AS n FROM security_incidents GROUP BY status,severity").fetchall()
        event_count = con.execute("SELECT COUNT(*) AS n FROM security_events").fetchone()["n"]
        recent_count = con.execute("SELECT COUNT(*) AS n FROM security_events WHERE received_at>=?", (_timestamp(time.time() - 86400),)).fetchone()["n"]
        sources = con.execute("SELECT source,COUNT(*) AS n,MAX(received_at) AS last_seen FROM security_events GROUP BY source ORDER BY source").fetchall()
    counts = {s: 0 for s in INCIDENT_STATUSES}
    severities = {s: 0 for s in SEVERITIES}
    total_incidents = 0
    for row in incidents:
        counts[row["status"]] = counts.get(row["status"], 0) + int(row["n"])
        severities[row["severity"]] = severities.get(row["severity"], 0) + int(row["n"])
        total_incidents += int(row["n"])
    return {"incidents_total": total_incidents, "by_status": counts, "by_severity": severities,
            "events_total": int(event_count), "events_24h": int(recent_count),
            "sources": [{"source": r["source"], "events": int(r["n"]), "last_seen": r["last_seen"]} for r in sources],
            "supported_sources": list(SOURCES)}


def list_incidents(store, *, status: str | None = None, severity: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    if status and status not in INCIDENT_STATUSES:
        raise ValueError("security_invalid_status")
    if severity and severity not in SEVERITIES:
        raise ValueError("security_invalid_severity")
    limit = max(1, min(200, int(limit)))
    sql = "SELECT * FROM security_incidents WHERE 1=1"
    params: list[Any] = []
    if status:
        sql += " AND status=?"; params.append(status)
    if severity:
        sql += " AND severity=?"; params.append(severity)
    sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, updated_at DESC LIMIT ?"
    params.append(limit)
    with store.lock, store.connect() as con:
        rows = con.execute(sql, tuple(params)).fetchall()
    return [dict(r) for r in rows]


def list_events(store, *, source: str | None = None, severity: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """List bounded normalized events, including context-only network telemetry."""
    if source and source not in SOURCES:
        raise ValueError("security_source_not_supported")
    if severity and severity not in SEVERITIES:
        raise ValueError("security_invalid_severity")
    limit = max(1, min(250, int(limit)))
    sql = "SELECT * FROM security_events WHERE 1=1"
    params: list[Any] = []
    if source:
        sql += " AND source=?"; params.append(source)
    if severity:
        sql += " AND severity=?"; params.append(severity)
    sql += " ORDER BY observed_at DESC, received_at DESC LIMIT ?"
    params.append(limit)
    with store.lock, store.connect() as con:
        rows = con.execute(sql, tuple(params)).fetchall()
    events: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json"))
        except (ValueError, TypeError):
            item["details"] = {}
        events.append(item)
    return events


def incident_detail(store, incident_id: str) -> dict[str, Any]:
    with store.lock, store.connect() as con:
        inc = con.execute("SELECT * FROM security_incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if not inc:
            raise KeyError("security_incident_not_found")
        rows = con.execute("SELECT * FROM security_events WHERE incident_id=? ORDER BY observed_at DESC LIMIT 250", (incident_id,)).fetchall()
        runs = con.execute("SELECT * FROM security_playbook_runs WHERE incident_id=? ORDER BY created_at DESC LIMIT 20", (incident_id,)).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        try: item["details"] = json.loads(item.pop("details_json"))
        except (ValueError, TypeError): item["details"] = {}
        events.append(item)
    run_items = []
    for row in runs:
        item = dict(row)
        if item.get("result_json"):
            try: item["result"] = json.loads(item.pop("result_json"))
            except (ValueError, TypeError): item["result"] = {}
        else: item.pop("result_json", None)
        run_items.append(item)
    return {"incident": dict(inc), "events": events, "playbook_runs": run_items}


def update_incident(store, incident_id: str, body: dict[str, Any], actor: str) -> dict[str, Any]:
    status = body.get("status")
    assigned_to = body.get("assigned_to")
    if status is not None and status not in INCIDENT_STATUSES:
        raise ValueError("security_invalid_status")
    if assigned_to is not None and (not isinstance(assigned_to, str) or len(assigned_to) > 80):
        raise ValueError("security_invalid_assignee")
    now = _now()
    with store.lock, store.connect() as con:
        row = con.execute("SELECT * FROM security_incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if not row:
            raise KeyError("security_incident_not_found")
        new_status = status or row["status"]
        new_assignee = assigned_to if assigned_to is not None else row["assigned_to"]
        closed_at = now if new_status in {"resolved", "closed"} else None
        con.execute("UPDATE security_incidents SET status=?,assigned_to=?,updated_at=?,closed_at=? WHERE incident_id=?",
                    (new_status, new_assignee, now, closed_at, incident_id))
        store.audit(con, actor, "security.incident.updated", incident_id, {"status": new_status, "assigned_to": new_assignee})
    return {"incident_id": incident_id, "status": new_status, "assigned_to": new_assignee, "updated_at": now}


def list_playbooks() -> list[dict[str, Any]]:
    return [{"id": pid, **definition} for pid, definition in PLAYBOOKS.items()]


def plan_playbook(store, incident_id: str, playbook_id: str, actor: dict[str, Any]) -> dict[str, Any]:
    definition = PLAYBOOKS.get(playbook_id)
    if not definition:
        raise ValueError("security_playbook_not_allowed")
    with store.lock, store.connect() as con:
        if not con.execute("SELECT 1 FROM security_incidents WHERE incident_id=?", (incident_id,)).fetchone():
            raise KeyError("security_incident_not_found")
        run_id = "sop_" + uuid.uuid4().hex[:20]
        now = _now(); expires = int(time.time()) + 600
        con.execute("INSERT INTO security_playbook_runs(run_id,incident_id,playbook_id,status,requested_by,requested_by_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
                    (run_id, incident_id, playbook_id, "pending_approval", actor["name"], actor["id"], now, expires))
        store.audit(con, actor["name"], "security.playbook.planned", run_id, {"incident_id": incident_id, "playbook_id": playbook_id})
    return {"run_id": run_id, "incident_id": incident_id, "playbook_id": playbook_id,
            "title": definition["title"], "steps": definition["steps"], "status": "pending_approval", "expires_at": expires}


def approve_playbook(store, run_id: str, actor: dict[str, Any]) -> dict[str, Any]:
    now_epoch = int(time.time()); now = _now(); expired = False
    with store.lock, store.connect() as con:
        row = con.execute("SELECT * FROM security_playbook_runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            raise KeyError("security_playbook_not_found")
        if int(row["expires_at"]) < now_epoch:
            con.execute("UPDATE security_playbook_runs SET status='expired' WHERE run_id=? AND status='pending_approval'", (run_id,))
            expired = True
        else:
            if row["status"] != "pending_approval":
                raise ValueError("security_playbook_not_pending")
            if actor["id"] == row["requested_by_id"]:
                raise PermissionError("security_two_person_approval_required")
            cur = con.execute("UPDATE security_playbook_runs SET status='approved',approved_by=?,approved_by_id=?,approved_at=? WHERE run_id=? AND status='pending_approval'",
                              (actor["name"], actor["id"], now, run_id))
            if cur.rowcount != 1:
                raise ValueError("security_playbook_not_pending")
            store.audit(con, actor["name"], "security.playbook.approved", run_id, {"incident_id": row["incident_id"]})
    if expired:
        raise TimeoutError("security_playbook_expired")
    return {"run_id": run_id, "status": "approved", "approved_at": now}


def _execute_step(step: str, incident: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    if step == "collect_recent_events":
        return {"step": step, "events_collected": len(events), "event_ids": [e["event_id"] for e in events]}
    if step == "build_timeline":
        timeline = [{"timestamp": e["observed_at"], "source": e["source"], "severity": e["severity"],
                    "title": e["title"], "host": e["host"], "src_ip": e["src_ip"], "dst_ip": e["dst_ip"]}
                    for e in sorted(events, key=lambda x: x["observed_at"])]
        return {"step": step, "timeline": timeline}
    if step == "summarize_evidence":
        by_source: dict[str, int] = {}
        for event in events: by_source[event["source"]] = by_source.get(event["source"], 0) + 1
        return {"step": step, "incident_id": incident["incident_id"], "title": incident["title"],
                "severity": incident["severity"], "event_count": len(events), "events_by_source": by_source,
                "summary": "Correlated normalized telemetry only; validate source fidelity and host context before response."}
    if step == "draft_detection_rule":
        rule = {"format": "cyberforge.normalized-event-rule.v1", "id": "cfrule_" + uuid.uuid4().hex[:16],
                "title": "Observed pattern: " + incident["title"], "status": "experimental",
                "match": {"source": events[0]["source"] if events else None,
                          "rule_id": events[0]["rule_id"] if events else None,
                          "category": incident["category"]},
                "severity": incident["severity"],
                "note": "Data-only CyberForge rule draft. Review before loading; not a Sigma rule."}
        return {"step": step, "rule": rule}
    if step == "prepare_response_checklist":
        return {"step": step, "checklist": [
            "Confirm the affected host and business owner using an independent asset inventory.",
            "Validate timestamps and correlate with endpoint, identity and network telemetry.",
            "Preserve original logs and relevant forensic evidence with access controls.",
            "Assess scope and impact before selecting a containment action.",
            "Obtain the required change or incident-command approval before changing production systems.",
            "After authorized remediation, verify recovery and document lessons learned.",
        ], "actions_performed": []}
    if step == "preserve_evidence_manifest":
        evidence = [{"event_id": e["event_id"], "source": e["source"], "observed_at": e["observed_at"],
                     "details": json.loads(e["details_json"]) if isinstance(e.get("details_json"), str) else e.get("details", {})}
                    for e in events]
        canonical = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return {"step": step, "event_count": len(evidence), "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                "event_ids": [e["event_id"] for e in evidence], "note": "Manifest only; this does not copy raw logs or change retention."}
    raise ValueError("security_playbook_step_not_allowed")


def execute_playbook(store, run_id: str, actor: dict[str, Any]) -> dict[str, Any]:
    now_epoch = int(time.time()); now = _now(); expired = False
    with store.lock, store.connect() as con:
        row = con.execute("SELECT * FROM security_playbook_runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            raise KeyError("security_playbook_not_found")
        if row["status"] != "approved":
            raise ValueError("security_playbook_not_approved")
        if int(row["expires_at"]) < now_epoch:
            con.execute("UPDATE security_playbook_runs SET status='expired' WHERE run_id=? AND status='approved'", (run_id,))
            expired = True
        else:
            cur = con.execute("UPDATE security_playbook_runs SET status='executing' WHERE run_id=? AND status='approved'", (run_id,))
            if cur.rowcount != 1:
                raise ValueError("security_playbook_not_approved")
            incident = con.execute("SELECT * FROM security_incidents WHERE incident_id=?", (row["incident_id"],)).fetchone()
            events_rows = con.execute("SELECT * FROM security_events WHERE incident_id=? ORDER BY observed_at ASC LIMIT 250", (row["incident_id"],)).fetchall()
            incident = dict(incident)
            events = [dict(item) for item in events_rows]
    if expired:
        raise TimeoutError("security_playbook_expired")
    try:
        definition = PLAYBOOKS[row["playbook_id"]]
        results = [_execute_step(step, incident, events) for step in definition["steps"]]
        result = {"run_id": run_id, "incident_id": row["incident_id"], "playbook_id": row["playbook_id"],
                  "completed_at": _now(), "steps": results, "side_effects": []}
        with store.lock, store.connect() as con:
            con.execute("UPDATE security_playbook_runs SET status='completed',executed_at=?,result_json=?,error_code=NULL WHERE run_id=? AND status='executing'",
                        (result["completed_at"], json.dumps(result, ensure_ascii=False, separators=(",", ":")), run_id))
            store.audit(con, actor["name"], "security.playbook.executed", run_id, {"incident_id": row["incident_id"], "playbook_id": row["playbook_id"]})
        return result
    except Exception:
        with store.lock, store.connect() as con:
            con.execute("UPDATE security_playbook_runs SET status='failed',executed_at=?,error_code='execution_failed' WHERE run_id=? AND status='executing'",
                        (_now(), run_id))
            store.audit(con, actor["name"], "security.playbook.failed", run_id, {"incident_id": row["incident_id"]})
        raise


def list_playbook_runs(store, incident_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(100, int(limit)))
    with store.lock, store.connect() as con:
        if incident_id:
            rows = con.execute("SELECT * FROM security_playbook_runs WHERE incident_id=? ORDER BY created_at DESC LIMIT ?", (incident_id, limit)).fetchall()
        else:
            rows = con.execute("SELECT * FROM security_playbook_runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        if item.get("result_json"):
            try: item["result"] = json.loads(item.pop("result_json"))
            except (ValueError, TypeError): item["result"] = {}
        else: item.pop("result_json", None)
        output.append(item)
    return output
