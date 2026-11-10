"""CyberForge Detection Engineering: versioned, reviewable normalized-event rules.

This engine deliberately implements a small data-only rule language. It does not
execute scripts, evaluate arbitrary expressions, accept user-supplied regex, or
claim full Sigma compatibility. Published rules are evaluated against normalized
security events during ingestion and produce auditable detection-match records.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

FORMAT = "cyberforge.normalized-event-rule.v1"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SOURCES = ("wazuh", "suricata", "zeek", "falco", "trivy", "osquery")
MAX_RULE_BYTES = 32 * 1024
MAX_CONDITIONS = 20
MAX_TEST_EVENTS = 250

DIRECT_FIELDS = {
    "source", "observed_at", "severity", "category", "title", "host", "node_id",
    "src_ip", "dst_ip", "src_port", "dst_port", "process_name", "rule_id",
}
DETAIL_FIELDS = {
    "details.event_type", "details.signature_id", "details.flow_id", "details.protocol",
    "details.vulnerability_id", "details.package", "details.finding_type", "details.priority",
    "details.target", "details.uid", "details.service", "details.action",
}
ALLOWED_FIELDS = DIRECT_FIELDS | DETAIL_FIELDS
ALLOWED_OPERATORS = {"equals", "not_equals", "contains", "starts_with", "in"}
ATTACK_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
RULE_ID_RE = re.compile(r"^cfr_[a-f0-9]{16}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS detection_rules(
  rule_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  state TEXT NOT NULL,
  current_version BIGINT NOT NULL,
  active_version BIGINT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_rule_versions(
  rule_id TEXT NOT NULL,
  version BIGINT NOT NULL,
  definition_json TEXT NOT NULL,
  validation_json TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  published_by TEXT,
  published_at TEXT,
  PRIMARY KEY(rule_id, version)
);
CREATE INDEX IF NOT EXISTS idx_detection_rule_state ON detection_rules(state, updated_at);
CREATE INDEX IF NOT EXISTS idx_detection_rule_version_state ON detection_rule_versions(rule_id, state, version);
CREATE TABLE IF NOT EXISTS detection_matches(
  match_id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  rule_version BIGINT NOT NULL,
  event_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(rule_id, rule_version, event_id)
);
CREATE INDEX IF NOT EXISTS idx_detection_matches_event ON detection_matches(event_id, created_at);
CREATE INDEX IF NOT EXISTS idx_detection_matches_rule ON detection_matches(rule_id, created_at);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _clean_text(value: Any, maximum: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("detection_rule_invalid")
    value = value.strip()
    if len(value) > maximum or (required and not value):
        raise ValueError("detection_rule_invalid")
    return value


def normalize_definition(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise ValueError("detection_rule_invalid")
    title = _clean_text(body.get("title"), 120, required=True)
    description = _clean_text(body.get("description", ""), 1000)
    severity = str(body.get("severity", "medium")).lower().strip()
    if severity not in SEVERITIES:
        raise ValueError("detection_rule_invalid")
    source = str(body.get("source", "any")).lower().strip()
    if source not in set(SOURCES) | {"any"}:
        raise ValueError("detection_rule_invalid")
    raw_match = body.get("match")
    if not isinstance(raw_match, dict) or set(raw_match) - {"all", "any"}:
        raise ValueError("detection_rule_invalid")
    conditions: dict[str, list[dict[str, Any]]] = {"all": [], "any": []}
    count = 0
    for group in ("all", "any"):
        entries = raw_match.get(group, [])
        if not isinstance(entries, list):
            raise ValueError("detection_rule_invalid")
        for item in entries:
            count += 1
            if count > MAX_CONDITIONS or not isinstance(item, dict) or set(item) - {"field", "op", "value"}:
                raise ValueError("detection_rule_invalid")
            field = str(item.get("field", "")).strip()
            operator = str(item.get("op", "equals")).strip().lower()
            value = item.get("value")
            if field not in ALLOWED_FIELDS or operator not in ALLOWED_OPERATORS:
                raise ValueError("detection_rule_invalid")
            if operator == "in":
                if not isinstance(value, list) or not 1 <= len(value) <= 25:
                    raise ValueError("detection_rule_invalid")
                values = []
                for part in value:
                    if not isinstance(part, (str, int)) or isinstance(part, bool):
                        raise ValueError("detection_rule_invalid")
                    text = str(part)
                    if not text or len(text) > 256:
                        raise ValueError("detection_rule_invalid")
                    values.append(text)
                normalized_value: Any = values
            else:
                if not isinstance(value, (str, int)) or isinstance(value, bool):
                    raise ValueError("detection_rule_invalid")
                normalized_value = str(value)
                if not normalized_value or len(normalized_value) > 256:
                    raise ValueError("detection_rule_invalid")
            conditions[group].append({"field": field, "op": operator, "value": normalized_value})
    if count == 0:
        raise ValueError("detection_rule_condition_required")
    tags_raw = body.get("tags", [])
    if not isinstance(tags_raw, list) or len(tags_raw) > 20:
        raise ValueError("detection_rule_invalid")
    tags = sorted({ _clean_text(x, 48, required=True).lower() for x in tags_raw })
    attack_raw = body.get("attack_ids", [])
    if not isinstance(attack_raw, list) or len(attack_raw) > 20:
        raise ValueError("detection_rule_invalid")
    attack_ids = sorted({str(x).upper() for x in attack_raw})
    if any(not ATTACK_RE.fullmatch(x) for x in attack_ids):
        raise ValueError("detection_rule_invalid_attack_id")
    return {
        "format": FORMAT, "title": title, "description": description,
        "source": source, "severity": severity,
        "tags": tags, "attack_ids": attack_ids, "match": conditions,
    }


def validate_definition(body: Any) -> dict[str, Any]:
    try:
        definition = normalize_definition(body)
        encoded = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_RULE_BYTES:
            return {"valid": False, "issues": ["rule_too_large"], "bytes": len(encoded)}
        return {"valid": True, "issues": [], "bytes": len(encoded), "condition_count": sum(len(definition["match"][k]) for k in ("all", "any"))}
    except ValueError as exc:
        return {"valid": False, "issues": [str(exc) or "detection_rule_invalid"]}


def _field_value(event: dict[str, Any], field: str) -> Any:
    if field.startswith("details."):
        details = event.get("details")
        return details.get(field.split(".", 1)[1]) if isinstance(details, dict) else None
    return event.get(field)


def _condition_matches(event: dict[str, Any], condition: dict[str, Any]) -> bool:
    actual = _field_value(event, condition["field"])
    if actual is None:
        return False
    op, expected = condition["op"], condition["value"]
    left = str(actual).casefold()
    if op == "equals":
        return left == str(expected).casefold()
    if op == "not_equals":
        return left != str(expected).casefold()
    if op == "contains":
        return str(expected).casefold() in left
    if op == "starts_with":
        return left.startswith(str(expected).casefold())
    if op == "in":
        return left in {str(x).casefold() for x in expected}
    return False


def matches_rule(definition: dict[str, Any], event: dict[str, Any]) -> bool:
    if definition.get("source", "any") not in {"any", event.get("source")}:
        return False
    match = definition.get("match") or {}
    all_conditions = match.get("all") or []
    any_conditions = match.get("any") or []
    return all(_condition_matches(event, c) for c in all_conditions) and (
        not any_conditions or any(_condition_matches(event, c) for c in any_conditions)
    )


def initialize(store) -> None:
    with store.lock, store.connect() as con:
        con.executescript(_SCHEMA)


def _load_version(con, rule_id: str, version: int) -> dict[str, Any]:
    row = con.execute("SELECT * FROM detection_rule_versions WHERE rule_id=? AND version=?", (rule_id, version)).fetchone()
    if not row:
        raise KeyError("detection_rule_not_found")
    item = dict(row)
    item["definition"] = json.loads(item.pop("definition_json"))
    item["validation"] = json.loads(item.pop("validation_json") or "{}")
    return item


def create_draft(store, body: dict[str, Any], actor: str) -> dict[str, Any]:
    definition = normalize_definition(body)
    encoded = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_RULE_BYTES:
        raise ValueError("detection_rule_too_large")
    now, rule_id = _now(), "cfr_" + uuid.uuid4().hex[:16]
    with store.lock, store.connect() as con:
        con.execute("INSERT INTO detection_rules(rule_id,title,state,current_version,active_version,created_by,created_at,updated_at) VALUES(?,?,?,1,NULL,?,?,?)",
                    (rule_id, definition["title"], "draft", actor[:80], now, now))
        con.execute("INSERT INTO detection_rule_versions(rule_id,version,definition_json,validation_json,state,created_by,created_at) VALUES(?,1,?,?,?, ?,?)",
                    (rule_id, encoded, "{}", "draft", actor[:80], now))
        store.audit(con, actor, "detection.rule.draft_created", rule_id, {"version": 1, "title": definition["title"]})
    return get_rule(store, rule_id)


def revise_draft(store, rule_id: str, body: dict[str, Any], actor: str) -> dict[str, Any]:
    if not RULE_ID_RE.fullmatch(rule_id):
        raise KeyError("detection_rule_not_found")
    definition = normalize_definition(body)
    encoded = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_RULE_BYTES:
        raise ValueError("detection_rule_too_large")
    now = _now()
    with store.lock, store.connect() as con:
        row = con.execute("SELECT * FROM detection_rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row or row["state"] == "retired":
            raise KeyError("detection_rule_not_found")
        version = int(row["current_version"]) + 1
        con.execute("INSERT INTO detection_rule_versions(rule_id,version,definition_json,validation_json,state,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (rule_id, version, encoded, "{}", "draft", actor[:80], now))
        con.execute("UPDATE detection_rules SET title=?,state='draft',current_version=?,updated_at=? WHERE rule_id=?",
                    (definition["title"], version, now, rule_id))
        store.audit(con, actor, "detection.rule.revised", rule_id, {"version": version})
    return get_rule(store, rule_id)


def validate_rule(store, rule_id: str, actor: str) -> dict[str, Any]:
    if not RULE_ID_RE.fullmatch(rule_id):
        raise KeyError("detection_rule_not_found")
    with store.lock, store.connect() as con:
        row = con.execute("SELECT current_version,state FROM detection_rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row or row["state"] == "retired":
            raise KeyError("detection_rule_not_found")
        version = int(row["current_version"])
        current = _load_version(con, rule_id, version)
        result = validate_definition(current["definition"])
        state = "validated" if result["valid"] else "draft"
        con.execute("UPDATE detection_rule_versions SET validation_json=?,state=? WHERE rule_id=? AND version=?",
                    (json.dumps(result, separators=(",", ":")), state, rule_id, version))
        con.execute("UPDATE detection_rules SET state=?,updated_at=? WHERE rule_id=?",
                    (state, _now(), rule_id))
        store.audit(con, actor, "detection.rule.validated", rule_id, {"version": version, "valid": result["valid"], "issues": result["issues"]})
    return {"rule_id": rule_id, "version": version, **result}


def _event_dict(row: Any) -> dict[str, Any]:
    event = dict(row)
    if "details_json" in event:
        try:
            event["details"] = json.loads(event.pop("details_json") or "{}")
        except (ValueError, TypeError):
            event["details"] = {}
    return event


def test_rule(store, rule_id: str, actor: str, limit: int = MAX_TEST_EVENTS) -> dict[str, Any]:
    if not RULE_ID_RE.fullmatch(rule_id):
        raise KeyError("detection_rule_not_found")
    limit = max(1, min(MAX_TEST_EVENTS, int(limit)))
    with store.connect() as con:
        row = con.execute("SELECT current_version FROM detection_rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise KeyError("detection_rule_not_found")
        version = int(row["current_version"])
        rule = _load_version(con, rule_id, version)
    valid = validate_definition(rule["definition"])
    if not valid["valid"]:
        raise ValueError("detection_rule_not_valid")
    with store.connect() as con:
        rows = con.execute("SELECT * FROM security_events ORDER BY observed_at DESC,received_at DESC LIMIT ?", (limit,)).fetchall()
    matches = []
    for row in rows:
        event = _event_dict(row)
        if matches_rule(rule["definition"], event):
            matches.append({k: event.get(k) for k in ("event_id", "source", "observed_at", "severity", "category", "title", "host", "src_ip", "dst_ip", "process_name", "rule_id")})
    result = {"rule_id": rule_id, "version": version, "events_examined": len(rows), "matches": len(matches), "matched_events": matches[:100]}
    with store.lock, store.connect() as con:
        store.audit(con, actor, "detection.rule.tested", rule_id, {"version": version, "events_examined": len(rows), "matches": len(matches)})
    return result


def publish_rule(store, rule_id: str, actor: str) -> dict[str, Any]:
    if not RULE_ID_RE.fullmatch(rule_id):
        raise KeyError("detection_rule_not_found")
    with store.lock, store.connect() as con:
        row = con.execute("SELECT * FROM detection_rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row or row["state"] == "retired":
            raise KeyError("detection_rule_not_found")
        version = int(row["current_version"])
        version_row = _load_version(con, rule_id, version)
        if version_row["state"] != "validated" or not version_row["validation"].get("valid"):
            raise ValueError("detection_rule_not_valid")
        if os.getenv("CF_DETECTION_REQUIRE_TWO_PERSON", "1") == "1" and row["created_by"] == actor:
            raise PermissionError("detection_two_person_publish_required")
        now = _now()
        con.execute("UPDATE detection_rule_versions SET state='published',published_by=?,published_at=? WHERE rule_id=? AND version=?",
                    (actor[:80], now, rule_id, version))
        con.execute("UPDATE detection_rules SET state='published',active_version=?,updated_at=? WHERE rule_id=?",
                    (version, now, rule_id))
        store.audit(con, actor, "detection.rule.published", rule_id, {"version": version, "created_by": row["created_by"]})
    return get_rule(store, rule_id)


def retire_rule(store, rule_id: str, actor: str) -> dict[str, Any]:
    if not RULE_ID_RE.fullmatch(rule_id):
        raise KeyError("detection_rule_not_found")
    with store.lock, store.connect() as con:
        row = con.execute("SELECT state,active_version FROM detection_rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row or row["state"] == "retired":
            raise KeyError("detection_rule_not_found")
        con.execute("UPDATE detection_rules SET state='retired',active_version=NULL,updated_at=? WHERE rule_id=?", (_now(), rule_id))
        store.audit(con, actor, "detection.rule.retired", rule_id, {"previous_active_version": row["active_version"]})
    return get_rule(store, rule_id)


def rollback_to_version(store, rule_id: str, target_version: int, actor: str) -> dict[str, Any]:
    if not RULE_ID_RE.fullmatch(rule_id):
        raise KeyError("detection_rule_not_found")
    try:
        target_version = int(target_version)
    except (TypeError, ValueError):
        raise ValueError("detection_rule_invalid_version")
    if target_version < 1:
        raise ValueError("detection_rule_invalid_version")
    with store.lock, store.connect() as con:
        rule = con.execute("SELECT * FROM detection_rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not rule or rule["state"] == "retired":
            raise KeyError("detection_rule_not_found")
        target = con.execute("SELECT definition_json,state FROM detection_rule_versions WHERE rule_id=? AND version=?", (rule_id, target_version)).fetchone()
        if not target or target["state"] != "published":
            raise ValueError("detection_rule_rollback_target_invalid")
        version = int(rule["current_version"]) + 1
        now = _now()
        con.execute("INSERT INTO detection_rule_versions(rule_id,version,definition_json,validation_json,state,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (rule_id, version, target["definition_json"], "{}", "draft", actor[:80], now))
        definition = json.loads(target["definition_json"])
        con.execute("UPDATE detection_rules SET title=?,state='draft',current_version=?,updated_at=? WHERE rule_id=?",
                    (definition["title"], version, now, rule_id))
        store.audit(con, actor, "detection.rule.rollback_draft_created", rule_id, {"target_version": target_version, "new_version": version})
    return get_rule(store, rule_id)


def get_rule(store, rule_id: str) -> dict[str, Any]:
    if not RULE_ID_RE.fullmatch(rule_id):
        raise KeyError("detection_rule_not_found")
    with store.connect() as con:
        row = con.execute("SELECT * FROM detection_rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise KeyError("detection_rule_not_found")
        result = dict(row)
        current = _load_version(con, rule_id, int(row["current_version"]))
        versions = con.execute("SELECT version,state,created_by,created_at,published_by,published_at FROM detection_rule_versions WHERE rule_id=? ORDER BY version DESC", (rule_id,)).fetchall()
    result["definition"] = current["definition"]
    result["validation"] = current["validation"]
    result["versions"] = [dict(x) for x in versions[:50]]
    return result


def list_rules(store, state: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    if state and state not in {"draft", "validated", "published", "retired"}:
        raise ValueError("detection_rule_invalid_state")
    limit = max(1, min(200, int(limit)))
    sql = "SELECT * FROM detection_rules"
    params: list[Any] = []
    if state:
        sql += " WHERE state=?"; params.append(state)
    sql += " ORDER BY updated_at DESC LIMIT ?"; params.append(limit)
    with store.connect() as con:
        rows = con.execute(sql, tuple(params)).fetchall()
    return [dict(x) for x in rows]


def load_active_rules(con) -> list[dict[str, Any]]:
    """Load and decode the active immutable rule versions once per ingest batch."""
    rows = con.execute("""SELECT r.rule_id,r.active_version,v.definition_json
        FROM detection_rules r JOIN detection_rule_versions v
          ON v.rule_id=r.rule_id AND v.version=r.active_version
        WHERE r.active_version IS NOT NULL AND v.state='published'""").fetchall()
    active = []
    for row in rows:
        try:
            active.append({"rule_id": row["rule_id"], "version": int(row["active_version"]),
                           "definition": json.loads(row["definition_json"])})
        except (ValueError, TypeError, KeyError):
            continue
    return active


def evaluate_in_transaction(con, event: dict[str, Any], event_id: str,
                            active_rules: list[dict[str, Any]] | None = None) -> int:
    """Evaluate active published rules in the caller's ingestion transaction."""
    active_rules = load_active_rules(con) if active_rules is None else active_rules
    count = 0
    for rule in active_rules:
        try:
            if not matches_rule(rule["definition"], event):
                continue
            cur = con.execute("INSERT INTO detection_matches(match_id,rule_id,rule_version,event_id,created_at) VALUES(?,?,?,?,?) ON CONFLICT(rule_id,rule_version,event_id) DO NOTHING",
                              ("dcm_" + uuid.uuid4().hex[:18], rule["rule_id"], rule["version"], event_id, _now()))
            count += int(getattr(cur, "rowcount", 0) == 1)
        except (ValueError, TypeError, KeyError):
            # A malformed published record must not break security telemetry ingestion.
            continue
    return count


def list_matches(store, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(250, int(limit)))
    with store.connect() as con:
        rows = con.execute("""SELECT m.match_id,m.rule_id,m.rule_version,m.event_id,m.created_at,
            r.title AS rule_title,v.definition_json,e.source,e.observed_at,e.title AS event_title,
            e.host,e.src_ip,e.dst_ip,e.process_name
            FROM detection_matches m
            JOIN detection_rules r ON r.rule_id=m.rule_id
            JOIN detection_rule_versions v ON v.rule_id=m.rule_id AND v.version=m.rule_version
            JOIN security_events e ON e.event_id=m.event_id
            ORDER BY m.created_at DESC LIMIT ?""", (limit,)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        try:
            definition = json.loads(item.pop("definition_json"))
            item["rule_severity"] = definition.get("severity", "medium")
            item["attack_ids"] = definition.get("attack_ids", [])
        except (ValueError, TypeError):
            item["definition_json"] = "[invalid]"
            item["rule_severity"] = "unknown"
            item["attack_ids"] = []
        output.append(item)
    return output


def summary(store) -> dict[str, Any]:
    with store.connect() as con:
        rules = con.execute("SELECT state,COUNT(*) n FROM detection_rules GROUP BY state").fetchall()
        matches = con.execute("SELECT COUNT(*) n FROM detection_matches").fetchone()["n"]
        recent = con.execute("SELECT COUNT(*) n FROM detection_matches WHERE created_at>=?", (_now()[:10],)).fetchone()["n"]
        coverage = con.execute("""SELECT COUNT(DISTINCT json_extract) AS unused FROM detection_rules""") if False else None
        rule_rows = con.execute("""SELECT v.definition_json FROM detection_rules r JOIN detection_rule_versions v
            ON v.rule_id=r.rule_id AND v.version=r.active_version WHERE r.state='published' AND r.active_version IS NOT NULL""").fetchall()
    counts = {x["state"]: int(x["n"]) for x in rules}
    attack_ids: set[str] = set()
    sources: set[str] = set()
    for row in rule_rows:
        try:
            definition = json.loads(row["definition_json"])
            attack_ids.update(definition.get("attack_ids", []))
            sources.add(definition.get("source", "any"))
        except (ValueError, TypeError):
            continue
    return {"rules_total": sum(counts.values()), "by_state": counts, "published_rules": counts.get("published", 0),
            "matches_total": int(matches), "matches_today_utc": int(recent),
            "attack_techniques_covered": sorted(attack_ids), "rule_sources": sorted(sources),
            "rule_format": FORMAT, "sigma_compatibility": "not_claimed"}
