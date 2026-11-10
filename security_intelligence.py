"""Defensive event enrichment, cross-source correlation and evidence analysis.

This module never executes response actions. MITRE mappings are candidate labels
based on observed text/metadata and must be reviewed by an analyst.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any

# Public ATT&CK technique identifiers. Matching is deliberately conservative:
# output is a candidate mapping, not a finding that proves the technique occurred.
ATTACK_RULES = (
    ("T1059.004", "Unix Shell", re.compile(r"\b(bash|sh|zsh|shell|/bin/sh|/bin/bash)\b", re.I), "medium"),
    ("T1059.001", "PowerShell", re.compile(r"\b(powershell|pwsh)\b", re.I), "medium"),
    ("T1059", "Command and Scripting Interpreter", re.compile(r"\b(command execution|script execution|scripting interpreter|cmd\.exe)\b", re.I), "low"),
    ("T1053.003", "Cron", re.compile(r"\b(cron|crontab)\b", re.I), "medium"),
    ("T1053.005", "Scheduled Task", re.compile(r"\b(scheduled task|schtasks|task scheduler)\b", re.I), "medium"),
    ("T1543.002", "Systemd Service", re.compile(r"\b(systemd service|systemctl enable|\.service unit)\b", re.I), "medium"),
    ("T1105", "Ingress Tool Transfer", re.compile(r"\b(curl|wget|download|payload transfer|tool transfer)\b", re.I), "low"),
    ("T1071.001", "Web Protocols", re.compile(r"\b(http|https|web request|http beacon|web c2)\b", re.I), "low"),
    ("T1003", "OS Credential Dumping", re.compile(r"\b(credential dump|credential dumping|lsass|mimikatz|password dump)\b", re.I), "medium"),
    ("T1055", "Process Injection", re.compile(r"\b(process injection|inject(?:ed|ion)? into process)\b", re.I), "medium"),
    ("T1041", "Exfiltration Over C2 Channel", re.compile(r"\b(exfiltrat(?:e|ion)|data theft over c2)\b", re.I), "medium"),
    ("T1547", "Boot or Logon Autostart Execution", re.compile(r"\b(autorun|autostart|run key|startup folder)\b", re.I), "low"),
    ("T1082", "System Information Discovery", re.compile(r"\b(system information discovery|uname -a|systeminfo)\b", re.I), "low"),
    ("T1016", "System Network Configuration Discovery", re.compile(r"\b(ipconfig|ifconfig|ip addr|network configuration discovery)\b", re.I), "low"),
    ("T1087", "Account Discovery", re.compile(r"\b(account discovery|user enumeration|whoami|/etc/passwd)\b", re.I), "low"),
)


def _get(mapping: Any, *keys: str):
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def _safe(value: Any, limit: int = 180) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple)):
        return None
    text = str(value).replace("\x00", " ").strip()
    text = re.sub(r"(?i)\b(password|passwd|token|secret|authorization|cookie|api[_-]?key)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
    if not text:
        return None
    return text[:limit]


def _positive_int(value: Any) -> int | None:
    try:
        n = int(value)
        return n if 0 <= n <= 2**31 - 1 else None
    except (TypeError, ValueError):
        return None


def _extract_entities(source: str, raw: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    fields = raw.get("output_fields") if isinstance(raw.get("output_fields"), dict) else {}
    proc = raw.get("process") if isinstance(raw.get("process"), dict) else {}
    parent = proc.get("parent") if isinstance(proc.get("parent"), dict) else {}
    file_obj = raw.get("file") if isinstance(raw.get("file"), dict) else {}
    hashes = file_obj.get("hash") if isinstance(file_obj.get("hash"), dict) else {}
    columns = raw.get("columns") if isinstance(raw.get("columns"), dict) else {}

    aliases = {
        "process_pid": _get(fields, "proc.pid") or _get(proc, "pid") or _get(data, "pid") or _get(raw, "pid", "process_id"),
        "parent_pid": _get(fields, "proc.ppid") or _get(proc, "parent_pid") or _get(parent, "pid") or _get(data, "ppid"),
        "process_name": _get(fields, "proc.name", "proc.pname") or _get(proc, "name") or event.get("process_name") or _get(columns, "name"),
        "process_path": _get(fields, "proc.exepath") or _get(proc, "executable", "path") or _get(data, "exe", "path"),
        "username": _get(fields, "user.name", "user.loginname") or _get(raw.get("user") if isinstance(raw.get("user"), dict) else {}, "name", "username") or _get(data, "user", "username"),
        "container_id": _get(fields, "container.id") or _get(raw.get("container") if isinstance(raw.get("container"), dict) else {}, "id") or _get(raw, "container_id"),
        "container_name": _get(fields, "container.name") or _get(raw.get("container") if isinstance(raw.get("container"), dict) else {}, "name"),
        "file_path": _get(fields, "fd.name", "evt.abspath") or _get(file_obj, "path", "name") or _get(data, "path", "filename") or event.get("details", {}).get("file_path"),
        "file_sha256": _get(hashes, "sha256") or _get(raw, "sha256", "file_sha256") or _get(columns, "sha256"),
        # `hostname` identifies the endpoint in Falco/Wazuh, not a DNS domain.
        # Treat only explicit query/SNI/server-name fields as network-name evidence.
        "domain": _get(raw, "query", "query_name", "server_name", "sni", "tls.sni") or _get(fields, "fd.sname"),
        "flow_id": _get(raw, "flow_id"),
        "zeek_uid": _get(raw, "uid"),
    }
    result: dict[str, Any] = {}
    for key, value in aliases.items():
        if key in {"process_pid", "parent_pid"}:
            parsed = _positive_int(value)
            if parsed is not None:
                result[key] = parsed
        else:
            safe = _safe(value, 180)
            if safe:
                result[key] = safe
    digest = result.get("file_sha256", "")
    if digest and not re.fullmatch(r"(?i)[a-f0-9]{64}", digest):
        result.pop("file_sha256", None)
    if "domain" in result:
        domain = result["domain"].strip().lower().rstrip(".")
        # Never retain a whole URL or path in the domain entity.
        if "/" in domain or len(domain) > 253:
            result.pop("domain", None)
        else:
            result["domain"] = domain
    return result


def _mitre_candidates(event: dict[str, Any], raw: dict[str, Any]) -> list[dict[str, str]]:
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    parts = [event.get("title", ""), event.get("category", ""), event.get("rule_id", ""),
             details.get("output_summary", ""), details.get("event_type", ""), details.get("action", "")]
    entities = details.get("entities") if isinstance(details.get("entities"), dict) else {}
    parts.extend(str(entities.get(k, "")) for k in ("process_name", "process_path", "file_path"))
    text = " ".join(str(x) for x in parts if x)
    found = []
    for technique_id, name, pattern, confidence in ATTACK_RULES:
        match = pattern.search(text)
        if match:
            found.append({"id": technique_id, "name": name, "confidence": confidence,
                          "basis": match.group(0)[:80]})
    return found[:8]


def enrich_event(event: dict[str, Any], source: str, raw: dict[str, Any]) -> dict[str, Any]:
    details = event.setdefault("details", {})
    entities = _extract_entities(source, raw, event)
    if entities:
        details["entities"] = entities
    techniques = _mitre_candidates(event, raw)
    if techniques:
        details["mitre_candidates"] = techniques
    # Keep normalized details under the existing bounded schema limit.
    encoded = json.dumps(details, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 8192:
        details.clear()
        details.update({"source": source, "truncated": True})
    return event


def _parse_details(row: Any) -> dict[str, Any]:
    try:
        value = json.loads(row["details_json"])
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError, KeyError):
        return {}


def _event_entities(row: Any) -> dict[str, Any]:
    details = _parse_details(row)
    entities = details.get("entities") if isinstance(details.get("entities"), dict) else {}
    result = dict(entities)
    for key in ("process_name", "file_path", "query", "query_name", "uid", "flow_id"):
        try:
            value = row[key]
        except (KeyError, IndexError):
            value = None
        if key not in result and value not in (None, ""):
            result[key] = value
    return result


def _anchors(row: Any) -> dict[str, str]:
    entities = _event_entities(row)
    result: dict[str, str] = {}
    for key in ("node_id", "host", "src_ip", "dst_ip"):
        try:
            value = row[key]
        except (KeyError, IndexError):
            value = None
        if value:
            result[key] = str(value).strip().lower()
    for key in ("process_pid", "process_name", "file_sha256", "file_path", "container_id", "domain"):
        value = entities.get(key)
        if value not in (None, ""):
            result[key] = str(value).strip().lower()
    return result


def _score(left: dict[str, str], right: dict[str, str]) -> tuple[float, list[str]]:
    matched: list[str] = []
    def same(key: str) -> bool:
        return bool(left.get(key) and right.get(key) and left[key] == right[key])
    if same("file_sha256"):
        matched.append("same_file_sha256")
    if same("node_id") and same("process_pid"):
        matched.append("same_node_and_pid")
    if same("container_id") and same("process_pid"):
        matched.append("same_container_and_pid")
    if same("host") and same("process_pid"):
        matched.append("same_host_and_pid")
    if same("domain"):
        matched.append("same_domain")
    if same("file_path") and same("host"):
        matched.append("same_host_and_file_path")
    if same("process_name") and (same("host") or same("node_id")):
        matched.append("same_host_and_process")
    ip_left = {left.get("src_ip"), left.get("dst_ip"), None, ""}
    ip_right = {right.get("src_ip"), right.get("dst_ip"), None, ""}
    ip_overlap = len((ip_left - {None, ""}) & (ip_right - {None, ""})) > 0
    if ip_overlap:
        matched.append("shared_network_endpoint")
    if "same_file_sha256" in matched:
        return 0.99, matched
    if any(x in matched for x in ("same_node_and_pid", "same_container_and_pid", "same_host_and_pid")):
        return 0.96, matched
    if "same_host_and_file_path" in matched:
        return 0.82, matched
    if "same_domain" in matched and ip_overlap:
        return 0.88, matched
    if "same_domain" in matched:
        return 0.72, matched
    if "same_host_and_process" in matched and ip_overlap:
        return 0.78, matched
    if ip_overlap and (same("host") or same("node_id")):
        return 0.74, matched
    return 0.0, matched


def correlate_incident(store, incident_id: str, window_minutes: int = 30, actor: str = "analyst", persist: bool = True) -> dict[str, Any]:
    try:
        if isinstance(window_minutes, bool):
            raise ValueError
        window_minutes = int(window_minutes)
    except (TypeError, ValueError):
        raise ValueError("security_correlation_invalid_window")
    if not 1 <= window_minutes <= 240:
        raise ValueError("security_correlation_invalid_window")
    with store.lock, store.connect() as con:
        incident = con.execute("SELECT * FROM security_incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if not incident:
            raise KeyError("security_incident_not_found")
        seeds = con.execute("SELECT * FROM security_events WHERE incident_id=? ORDER BY observed_at LIMIT 250", (incident_id,)).fetchall()
        if not seeds:
            return {"incident_id": incident_id, "links": [], "context_events": [], "scanned_events": 0}
        times = [str(r["observed_at"]) for r in seeds]
        # ISO UTC strings are lexicographically sortable after normalization.
        start_epoch = min(_to_epoch(x) for x in times) - window_minutes * 60
        end_epoch = max(_to_epoch(x) for x in times) + window_minutes * 60
        start = datetime.fromtimestamp(start_epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        end = datetime.fromtimestamp(end_epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        candidates = con.execute("SELECT * FROM security_events WHERE observed_at>=? AND observed_at<=? ORDER BY observed_at LIMIT 3000", (start, end)).fetchall()
        seed_anchors = [(r, _anchors(r)) for r in seeds]
        link_best: dict[str, dict[str, Any]] = {}
        context_best: dict[str, dict[str, Any]] = {}
        for candidate in candidates:
            cid = candidate["incident_id"]
            if cid == incident_id:
                continue
            c_anchors = _anchors(candidate)
            best_score, best_evidence = 0.0, []
            for seed, anchors in seed_anchors:
                score, evidence = _score(anchors, c_anchors)
                if score > best_score:
                    best_score, best_evidence = score, evidence
            if best_score < 0.70:
                continue
            candidate_entities = _event_entities(candidate)
            summary = {"event_id": candidate["event_id"], "source": candidate["source"],
                       "title": candidate["title"], "observed_at": candidate["observed_at"],
                       "severity": candidate["severity"], "host": candidate["host"],
                       "src_ip": candidate["src_ip"], "dst_ip": candidate["dst_ip"],
                       "src_port": candidate["src_port"], "dst_port": candidate["dst_port"],
                       "entities": {k: candidate_entities[k] for k in ("process_pid", "parent_pid", "process_name", "process_path",
                           "container_id", "container_name", "file_path", "file_sha256", "domain", "flow_id", "zeek_uid") if k in candidate_entities},
                       "confidence": round(best_score, 2), "evidence": best_evidence}
            if cid:
                current = link_best.get(cid)
                if not current or best_score > current["confidence"]:
                    link_best[cid] = {**summary, "incident_id": cid}
            elif len(context_best) < 100:
                context_best[candidate["event_id"]] = summary
        if persist:
            for related_id, info in link_best.items():
                a, b = sorted((incident_id, related_id))
                relation = "cross_source_evidence_correlation"
                evidence_json = json.dumps({"evidence": info["evidence"], "confidence": info["confidence"]}, separators=(",", ":"))
                con.execute("""INSERT INTO security_incident_links(incident_a,incident_b,confidence,relation,evidence_json,created_at)
                    VALUES(?,?,?,?,?,?) ON CONFLICT(incident_a,incident_b) DO UPDATE SET
                    confidence=excluded.confidence,
                    evidence_json=excluded.evidence_json,created_at=excluded.created_at""",
                    (a, b, info["confidence"], relation, evidence_json, _now()))
            if link_best:
                store.audit(con, actor, "security.incidents.correlated", incident_id,
                            {"related_incidents": len(link_best), "context_events": len(context_best)})
            links = con.execute("""SELECT l.*,i.title,i.severity,i.status,i.last_seen,i.event_count
                FROM security_incident_links l JOIN security_incidents i
                ON i.incident_id=CASE WHEN l.incident_a=? THEN l.incident_b ELSE l.incident_a END
                WHERE l.incident_a=? OR l.incident_b=? ORDER BY l.confidence DESC,i.last_seen DESC LIMIT 50""",
                (incident_id, incident_id, incident_id)).fetchall()
            link_items = []
            for row in links:
                try: evidence = json.loads(row["evidence_json"])
                except (ValueError, TypeError): evidence = {}
                link_items.append({"incident_id": row["incident_b"] if row["incident_a"] == incident_id else row["incident_a"],
                    "title": row["title"], "severity": row["severity"], "status": row["status"],
                    "last_seen": row["last_seen"], "event_count": row["event_count"],
                    "confidence": float(row["confidence"]), "evidence": evidence})
        else:
            link_items = [{"incident_id": key, **value} for key, value in sorted(link_best.items(), key=lambda kv: kv[1]["confidence"], reverse=True)[:50]]
    return {"incident_id": incident_id, "links": link_items,
            "context_events": sorted(context_best.values(), key=lambda x: x["observed_at"], reverse=True)[:50],
            "scanned_events": len(candidates), "window_minutes": window_minutes}


def _now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _now():
    return _now_text()


def _to_epoch(value: str) -> float:
    try:
        raw = value[:-1] + "+00:00" if value.endswith("Z") else value
        return datetime.fromisoformat(raw).timestamp()
    except (ValueError, TypeError, OverflowError):
        return time.time()


def incident_analysis(store, incident_id: str, window_minutes: int = 30) -> dict[str, Any]:
    correlations = correlate_incident(store, incident_id, window_minutes=window_minutes, actor="analyst-read", persist=False)
    with store.lock, store.connect() as con:
        incident = con.execute("SELECT * FROM security_incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if not incident:
            raise KeyError("security_incident_not_found")
        rows = con.execute("SELECT * FROM security_events WHERE incident_id=? ORDER BY observed_at ASC LIMIT 250", (incident_id,)).fetchall()
        related_ids = [x["incident_id"] for x in correlations["links"]]
        related_rows = []
        if related_ids:
            placeholders = ",".join("?" for _ in related_ids[:50])
            related_rows = con.execute(f"SELECT * FROM security_events WHERE incident_id IN ({placeholders}) ORDER BY observed_at ASC LIMIT 250", tuple(related_ids[:50])).fetchall()
    all_rows = list(rows) + list(related_rows)
    techniques: dict[str, dict[str, Any]] = {}
    timeline = []
    sources: set[str] = set()
    for row in all_rows:
        details = _parse_details(row)
        sources.add(row["source"])
        entities = details.get("entities") if isinstance(details.get("entities"), dict) else {}
        timeline.append({"observed_at": row["observed_at"], "source": row["source"], "severity": row["severity"],
                         "title": row["title"], "host": row["host"], "event_id": row["event_id"],
                         "incident_id": row["incident_id"], "context_only": False,
                         "src_ip": row["src_ip"], "dst_ip": row["dst_ip"],
                         "src_port": row["src_port"], "dst_port": row["dst_port"],
                         "entities": {k: entities[k] for k in ("process_pid", "parent_pid", "process_name", "process_path",
                             "container_id", "container_name", "file_path", "file_sha256", "domain", "flow_id", "zeek_uid") if k in entities}})
        for candidate in details.get("mitre_candidates", []) if isinstance(details.get("mitre_candidates"), list) else []:
            if not isinstance(candidate, dict) or not candidate.get("id"):
                continue
            tid = str(candidate["id"])[:24]
            item = techniques.setdefault(tid, {"id": tid, "name": str(candidate.get("name", ""))[:100],
                "confidence": candidate.get("confidence", "low"), "event_count": 0, "evidence": []})
            item["event_count"] += 1
            if len(item["evidence"]) < 5:
                item["evidence"].append({"source": row["source"], "event_id": row["event_id"],
                                         "title": row["title"], "basis": str(candidate.get("basis", ""))[:80]})
    for context in correlations["context_events"]:
        timeline.append({"observed_at": context.get("observed_at", ""), "source": context.get("source", ""),
                         "severity": context.get("severity", "info"), "title": context.get("title", "Context event"),
                         "host": context.get("host"), "event_id": context.get("event_id"),
                         "src_ip": context.get("src_ip"), "dst_ip": context.get("dst_ip"),
                         "src_port": context.get("src_port"), "dst_port": context.get("dst_port"),
                         "entities": context.get("entities", {}),
                         "incident_id": None, "context_only": True, "correlation_confidence": context.get("confidence"),
                         "correlation_evidence": context.get("evidence", [])})
    timeline.sort(key=lambda x: x["observed_at"])
    risk = "critical" if incident["severity"] == "critical" else "high" if incident["severity"] == "high" else "moderate" if incident["severity"] == "medium" else "low"
    hypotheses = []
    for technique in sorted(techniques.values(), key=lambda x: (-x["event_count"], x["id"])):
        hypotheses.append({"statement": f"Possible activity related to {technique['name']} ({technique['id']}).",
                           "confidence": technique["confidence"], "supporting_events": technique["event_count"],
                           "evidence": technique["evidence"]})
    recommendations = ["Review the correlated event timeline and validate host/process identity.",
                       "Preserve original source logs and compare event timestamps with endpoint telemetry.",
                       "Review candidate ATT&CK mappings before using them as detection coverage claims."]
    if risk in {"critical", "high"}:
        recommendations.insert(0, "Escalate to the on-call analyst and follow the organization's approved incident response procedure.")
    return {"incident": {"incident_id": incident_id, "title": incident["title"], "severity": incident["severity"],
                          "status": incident["status"], "event_count": incident["event_count"]},
            "generated_at": _now_text(), "classification": risk,
            "evidence_summary": {"events": len(all_rows), "primary_events": len(rows),
                                 "related_incidents": len(correlations["links"]), "context_events": len(correlations["context_events"]),
                                 "sources": sorted(sources)},
            "timeline": timeline[-200:], "related_incidents": correlations["links"],
            "context_events": correlations["context_events"], "attack_techniques": sorted(techniques.values(), key=lambda x: x["id"]),
            "hypotheses": hypotheses, "recommendations": recommendations,
            "recommended_playbooks": ["incident_triage", "evidence_manifest", "response_checklist"],
            "confidence_note": "ATT&CK mappings and correlations are heuristic candidates. Validate against original telemetry; absence of a mapping does not imply absence of activity."}


def build_ai_messages(analysis: dict[str, Any]) -> list[dict[str, str]]:
    # Deliberately compact context. Raw payloads, secrets, request headers and file
    # contents are never included. The model is asked to distinguish observations
    # from hypotheses and to recommend, not execute, response steps.
    compact = {
        "incident": analysis.get("incident"),
        "evidence_summary": analysis.get("evidence_summary"),
        "timeline": (analysis.get("timeline") or [])[-120:],
        "related_incidents": (analysis.get("related_incidents") or [])[:30],
        "context_events": (analysis.get("context_events") or [])[:30],
        "attack_techniques": analysis.get("attack_techniques"),
        "hypotheses": analysis.get("hypotheses"),
        "threat_intelligence": analysis.get("threat_intelligence"),
    }
    encoded = json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
    encoded = encoded[:18_000]
    system = ("You are CyberForge Defensive Security Analyst. Analyze only the supplied normalized evidence. "
              "Threat-intelligence matches are contextual indicators, not proof of compromise; state the feed/source, indicator type and confidence, "
              "and distinguish a match from independently observed execution. Never open, resolve or fetch indicator values. "
              "Separate direct observations from hypotheses, state uncertainty and evidence gaps, avoid asserting attribution, "
              "and propose defensive validation steps. Never propose destructive actions as automatic actions. "
              "Do not ask for secrets or attempt commands. Return concise sections: Summary, Observed facts, Timeline, "
              "Candidate ATT&CK mappings, Confidence and gaps, Recommended human-approved next steps.")
    user = "Analyze this sanitized CyberForge incident evidence JSON:\n" + encoded
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def mitre_coverage(store, limit: int = 3000) -> dict[str, Any]:
    limit = max(1, min(5000, int(limit)))
    with store.lock, store.connect() as con:
        rows = con.execute("SELECT event_id,source,incident_id,title,details_json,observed_at FROM security_events ORDER BY observed_at DESC LIMIT ?", (limit,)).fetchall()
    aggregate: dict[str, dict[str, Any]] = {}
    for row in rows:
        details = _parse_details(row)
        candidates = details.get("mitre_candidates", [])
        if not isinstance(candidates, list):
            continue
        for item in candidates:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            tid = str(item["id"])[:24]
            entry = aggregate.setdefault(tid, {"id": tid, "name": str(item.get("name", ""))[:100],
                "event_count": 0, "incident_ids": set(), "sources": set(), "latest": ""})
            entry["event_count"] += 1
            if row["incident_id"]:
                entry["incident_ids"].add(row["incident_id"])
            entry["sources"].add(row["source"])
            entry["latest"] = max(entry["latest"], row["observed_at"] or "")
    techniques = []
    for item in aggregate.values():
        techniques.append({**item, "incident_count": len(item["incident_ids"]),
                           "incident_ids": sorted(item["incident_ids"])[:100],
                           "sources": sorted(item["sources"])})
    techniques.sort(key=lambda x: (-x["event_count"], x["id"]))
    return {"techniques": techniques, "events_scanned": len(rows),
            "mapping_type": "heuristic_candidate", "note": "Candidate ATT&CK mappings are not proof of technique execution."}
