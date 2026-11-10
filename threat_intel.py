"""CyberForge Threat Intelligence: bounded IOC feeds, STIX/TAXII and enrichment.

Network operations are explicit, HTTPS-only, host-allowlisted and redirect-free.
Indicator values are never fetched/resolved/opened. This module is data-only.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

MAX_IMPORT_OBJECTS = 5000
MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_TAXII_OBJECTS = 1000
MAX_LIST = 500
CACHE_NEGATIVE_SECONDS = 300
CACHE_POSITIVE_SECONDS = 1800

BUILTIN_FEEDS = {
    "cisa-kev": {
        "feed_id": "cisa-kev", "name": "CISA Known Exploited Vulnerabilities",
        "feed_type": "cisa_kev", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "license": "U.S. government public data; retain attribution", "enabled": False,
        "description": "Public catalog of vulnerabilities known to be exploited in the wild.",
    },
    "first-epss": {
        "feed_id": "first-epss", "name": "FIRST EPSS API", "feed_type": "epss_api",
        "url": "https://api.first.org/data/v1/epss", "license": "Free public API; attribution to FIRST.org",
        "enabled": True, "description": "On-demand CVE exploitation-probability lookup; not a bulk-feed downloader.",
    },
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_feeds(
 feed_id TEXT PRIMARY KEY, name TEXT NOT NULL, feed_type TEXT NOT NULL, url TEXT NOT NULL,
 config_json TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 0,
 last_sync_at TEXT, last_status TEXT NOT NULL DEFAULT 'never', last_error TEXT NOT NULL DEFAULT '',
 etag TEXT, last_modified TEXT, object_count BIGINT NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_iocs(
 ioc_id TEXT PRIMARY KEY, ioc_type TEXT NOT NULL, value_norm TEXT NOT NULL,
 source_feed TEXT NOT NULL, source_object_id TEXT NOT NULL DEFAULT '',
 confidence INTEGER NOT NULL DEFAULT 50, severity TEXT NOT NULL DEFAULT 'medium',
 description TEXT NOT NULL DEFAULT '', tags_json TEXT NOT NULL DEFAULT '[]',
 metadata_json TEXT NOT NULL DEFAULT '{}', valid_from TEXT, valid_until TEXT,
 revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(ioc_type,value_norm,source_feed)
);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_lookup ON threat_iocs(ioc_type,value_norm,revoked,valid_until);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_source ON threat_iocs(source_feed,updated_at);
CREATE TABLE IF NOT EXISTS threat_objects(
 object_id TEXT NOT NULL, source_feed TEXT NOT NULL, object_type TEXT NOT NULL,
 modified_at TEXT NOT NULL DEFAULT '', summary_json TEXT NOT NULL DEFAULT '{}',
 PRIMARY KEY(object_id,source_feed)
);
CREATE TABLE IF NOT EXISTS threat_relationships(
 source_object TEXT NOT NULL, target_object TEXT NOT NULL, relationship_type TEXT NOT NULL,
 source_feed TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(source_object,target_object,relationship_type,source_feed)
);
CREATE TABLE IF NOT EXISTS threat_intel_cache(
 cache_key TEXT PRIMARY KEY, result_json TEXT NOT NULL, created_at TEXT NOT NULL,
 expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_cache_expiry ON threat_intel_cache(expires_at);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _clean(value: Any, limit: int = 300) -> str:
    if value is None or isinstance(value, (dict, list, tuple)):
        return ""
    text = str(value).replace("\x00", " ").strip()
    text = re.sub(r"(?i)\b(password|passwd|token|secret|authorization|cookie|api[_-]?key)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
    return text[:limit]


def _parse_time(value: Any) -> str | None:
    if not value:
        return None
    try:
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError):
        return None


def normalize_ioc(ioc_type: str, value: Any) -> tuple[str, str]:
    kind = str(ioc_type or "").strip().lower()
    raw = _clean(value, 2048)
    if not raw or len(raw) > 2048:
        raise ValueError("threat_ioc_invalid")
    if kind in {"ip", "ipv4", "ipv6"}:
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ValueError("threat_ioc_invalid") from exc
        if kind == "ipv4" and addr.version != 4 or kind == "ipv6" and addr.version != 6:
            raise ValueError("threat_ioc_invalid")
        return ("ipv4" if addr.version == 4 else "ipv6", addr.compressed)
    if kind in {"domain", "domain-name", "hostname"}:
        candidate = raw.rstrip(".").lower()
        if "://" in candidate or "/" in candidate or "@" in candidate or "*" in candidate:
            raise ValueError("threat_ioc_invalid")
        try:
            ascii_name = candidate.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("threat_ioc_invalid") from exc
        if len(ascii_name) > 253 or not ascii_name or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in ascii_name.split(".")):
            raise ValueError("threat_ioc_invalid")
        return "domain", ascii_name
    if kind in {"url", "uri"}:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
            raise ValueError("threat_ioc_invalid")
        parts = urllib.parse.urlsplit(raw)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("threat_ioc_invalid")
        if re.search(r"(?i)(?:^|[&;])(token|access_token|api[_-]?key|password|passwd|authorization|auth|secret)=", parts.query):
            raise ValueError("threat_ioc_invalid")
        try:
            port = parts.port
        except ValueError as exc:
            raise ValueError("threat_ioc_invalid") from exc
        try:
            literal = ipaddress.ip_address(parts.hostname)
        except ValueError:
            literal = None
            try:
                host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
            except UnicodeError as exc:
                raise ValueError("threat_ioc_invalid") from exc
            if not host or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                raise ValueError("threat_ioc_invalid")
        if literal is not None:
            host = f"[{literal.compressed}]" if literal.version == 6 else literal.compressed
        netloc = host
        if port and not ((parts.scheme.lower() == "http" and port == 80) or (parts.scheme.lower() == "https" and port == 443)):
            netloc += f":{port}"
        return "url", urllib.parse.urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    if kind in {"sha256", "sha-256", "sha1", "sha-1", "md5"}:
        normalized = kind.replace("-", "")
        expected = {"sha256": 64, "sha1": 40, "md5": 32}[normalized]
        if not re.fullmatch(rf"(?i)[a-f0-9]{{{expected}}}", raw):
            raise ValueError("threat_ioc_invalid")
        return normalized, raw.lower()
    if kind in {"cve", "cve-id"}:
        if not re.fullmatch(r"(?i)CVE-\d{4}-\d{4,}", raw):
            raise ValueError("threat_ioc_invalid")
        return "cve", raw.upper()
    raise ValueError("threat_ioc_type_unsupported")


# Conservative supported subset of STIX patterning: observable equality expressions only.
_PATTERN_MAP = [
    (re.compile(r"(?i)(?<![!<>])ipv4-addr:value\s*=\s*'([^']{1,64})'"), "ipv4"),
    (re.compile(r"(?i)(?<![!<>])ipv6-addr:value\s*=\s*'([^']{1,128})'"), "ipv6"),
    (re.compile(r"(?i)(?<![!<>])domain-name:value\s*=\s*'([^']{1,253})'"), "domain"),
    (re.compile(r"(?i)(?<![!<>])url:value\s*=\s*'([^']{1,2048})'"), "url"),
    (re.compile(r"(?i)(?<![!<>])file:hashes\.(?:'SHA-256'|SHA-256)\s*=\s*'([a-f0-9]{64})'"), "sha256"),
    (re.compile(r"(?i)(?<![!<>])file:hashes\.(?:'SHA-1'|SHA-1)\s*=\s*'([a-f0-9]{40})'"), "sha1"),
    (re.compile(r"(?i)(?<![!<>])file:hashes\.(?:'MD5'|MD5)\s*=\s*'([a-f0-9]{32})'"), "md5"),
]


def parse_stix_bundle(bundle: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("threat_stix_bundle_invalid")
    objects = bundle["objects"]
    if len(objects) > MAX_IMPORT_OBJECTS:
        raise ValueError("threat_stix_object_limit")
    indicators: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    ignored = 0
    for obj in objects:
        if not isinstance(obj, dict):
            ignored += 1
            continue
        typ = obj.get("type")
        object_id = _clean(obj.get("id"), 255)
        modified = _parse_time(obj.get("modified") or obj.get("created")) or ""
        if object_id:
            summary = {k: _clean(obj.get(k), 240) for k in ("name", "description", "created_by_ref", "revoked") if obj.get(k) not in (None, "")}
            with_id = {"object_id": object_id, "object_type": _clean(typ, 60), "modified_at": modified,
                       "summary": summary}
            # Object summaries intentionally exclude arbitrary external references and granular payloads.
            indicators.append({"_object_summary": with_id})
        if typ == "relationship":
            source_ref, target_ref = _clean(obj.get("source_ref"), 255), _clean(obj.get("target_ref"), 255)
            rel = _clean(obj.get("relationship_type"), 100)
            if source_ref and target_ref and rel:
                relationships.append({"source_object": source_ref, "target_object": target_ref,
                                      "relationship_type": rel})
        if typ != "indicator":
            continue
        if obj.get("revoked") is True:
            if object_id:
                indicators.append({"_revoke_object_id": object_id})
            ignored += 1
            continue
        if any(obj.get(field) and not _parse_time(obj.get(field)) for field in ("valid_from", "valid_until")):
            ignored += 1
            continue
        valid_from = _parse_time(obj.get("valid_from"))
        valid_until = _parse_time(obj.get("valid_until"))
        if valid_from and valid_until and valid_until <= valid_from:
            ignored += 1
            continue
        if valid_until and valid_until <= _now():
            ignored += 1
            continue
        pattern = obj.get("pattern")
        if obj.get("pattern_type") != "stix" or not isinstance(pattern, str) or len(pattern) > 4096:
            ignored += 1
            continue
        # Do not interpret negated, inequality or compound temporal patterns as positive IOCs.
        if re.search(r"(?i)\bNOT\b|!=|\bLIKE\b|\bMATCHES\b|\bISSUBSET\b|\bISSUPERSET\b|\bFOLLOWEDBY\b|\bWITHIN\b|\bREPEATS\b", pattern):
            ignored += 1
            continue
        hits = []
        for regex, ioc_type in _PATTERN_MAP:
            for match in regex.finditer(pattern):
                try:
                    kind, value = normalize_ioc(ioc_type, match.group(1))
                except ValueError:
                    continue
                hits.append((kind, value))
        if not hits:
            ignored += 1
            continue
        try:
            confidence = max(0, min(100, int(obj.get("confidence", 50))))
        except (TypeError, ValueError):
            confidence = 50
        labels = obj.get("labels") if isinstance(obj.get("labels"), list) else []
        tags = [_clean(x, 64) for x in labels[:20] if _clean(x, 64)]
        severity = "high" if any(x.lower() in {"malicious-activity", "compromised", "ransomware"} for x in tags) else "medium"
        for kind, value in sorted(set(hits)):
            indicators.append({
                "ioc_type": kind, "value": value, "source_object_id": object_id,
                "confidence": confidence, "severity": severity,
                "description": _clean(obj.get("name") or obj.get("description"), 300),
                "tags": tags, "valid_from": _parse_time(obj.get("valid_from")),
                "valid_until": _parse_time(obj.get("valid_until")), "revoked": False,
            })
    return indicators, relationships, ignored


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _allowed_hosts() -> set[str]:
    hosts = {"www.cisa.gov", "api.first.org"}
    hosts.update(x.strip().lower().rstrip(".") for x in os.getenv("CF_THREAT_INTEL_ALLOWED_HOSTS", "").split(",") if x.strip())
    return hosts


def _validate_remote_url(url: str, *, allow_builtin: bool = True) -> urllib.parse.SplitResult:
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("threat_feed_url_invalid")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("threat_feed_https_required")
    if re.search(r"(?i)(?:^|[&;])(token|access_token|api[_-]?key|password|passwd|authorization|auth|secret)=", parts.query):
        raise ValueError("threat_feed_url_invalid")
    try:
        host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("threat_feed_url_invalid") from exc
    if host not in _allowed_hosts():
        raise ValueError("threat_feed_host_not_allowlisted")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("threat_feed_url_invalid") from exc
    if port not in (None, 443):
        raise ValueError("threat_feed_url_invalid")
    try:
        ipaddress.ip_address(host)
        raise ValueError("threat_feed_host_not_allowlisted")
    except ValueError as exc:
        if str(exc) == "threat_feed_host_not_allowlisted":
            raise
    return parts


def _request(url: str, *, headers: dict[str, str] | None = None, max_bytes: int = MAX_FEED_BYTES) -> tuple[int, dict[str, str], bytes]:
    _validate_remote_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": "CyberForge-Server/2.1.0", "Accept": "application/json", **(headers or {})})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=10) as response:
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("threat_feed_too_large")
            return response.status, dict(response.headers.items()), data
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, dict(exc.headers.items()), b""
        if 300 <= exc.code < 400:
            raise ValueError("threat_feed_redirect_rejected") from exc
        raise ValueError("threat_feed_http_error") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ValueError("threat_feed_unreachable") from exc


def initialize(store) -> None:
    with store.lock, store.connect() as con:
        con.executescript(_SCHEMA)
        now = _now()
        for feed in BUILTIN_FEEDS.values():
            con.execute("""INSERT INTO threat_feeds(feed_id,name,feed_type,url,config_json,enabled,last_status,created_at,updated_at)
                          VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(feed_id) DO NOTHING""",
                        (feed["feed_id"], feed["name"], feed["feed_type"], feed["url"],
                         json.dumps({"license": feed["license"], "description": feed["description"]}),
                         int(feed["enabled"]), "never", now, now))


def list_feeds(store) -> list[dict[str, Any]]:
    with store.connect() as con:
        rows = con.execute("SELECT * FROM threat_feeds ORDER BY feed_id").fetchall()
    result = []
    for row in rows:
        cfg = json.loads(row["config_json"] or "{}")
        result.append({k: row[k] for k in ("feed_id", "name", "feed_type", "url", "enabled", "last_sync_at", "last_status", "last_error", "object_count", "created_at", "updated_at")} |
                      {"config": {k: v for k, v in cfg.items() if k not in {"auth_env"}}, "has_auth_env": bool(cfg.get("auth_env"))})
    return result


def create_feed(store, body: dict[str, Any], actor: str) -> dict[str, Any]:
    feed_type = str(body.get("feed_type", "")).strip().lower()
    if feed_type not in {"stix_bundle", "taxii21", "json_iocs"}:
        raise ValueError("threat_feed_type_unsupported")
    url = str(body.get("url", "")).strip()
    if feed_type == "taxii21":
        _validate_remote_url(url)
    elif url:
        # Imported/uploaded data feeds do not fetch arbitrary URLs.
        raise ValueError("threat_feed_url_not_used")
    name = _clean(body.get("name"), 100)
    if not name:
        raise ValueError("threat_feed_invalid")
    feed_id = "feed_" + uuid.uuid4().hex[:16]
    enabled_value = body.get("enabled", True)
    if not isinstance(enabled_value, bool):
        raise ValueError("threat_feed_invalid")
    auth_env = str(body.get("auth_env", "")).strip()
    if auth_env and not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", auth_env):
        raise ValueError("threat_feed_auth_env_invalid")
    try:
        collection_id = _clean(body.get("collection_id"), 120)
        api_root = str(body.get("api_root", "")).strip()
        if api_root:
            _validate_remote_url(api_root)
    except ValueError:
        raise
    config = {"collection_id": collection_id, "api_root": api_root, "auth_env": auth_env,
              "auth_header": body.get("auth_header", "Authorization") if body.get("auth_header") in {"Authorization", "X-TAXII-API-Key"} else "Authorization",
              "auth_scheme": body.get("auth_scheme", "Bearer") if body.get("auth_scheme", "Bearer") in {"Bearer", "Basic", "none"} else "Bearer"}
    now = _now()
    with store.lock, store.connect() as con:
        con.execute("INSERT INTO threat_feeds(feed_id,name,feed_type,url,config_json,enabled,last_status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (feed_id, name, feed_type, url, json.dumps(config), int(enabled_value), "never", now, now))
        store.audit(con, actor, "threat_feed.created", feed_id, {"feed_type": feed_type, "name": name})
    return {"feed_id": feed_id, "name": name, "feed_type": feed_type, "enabled": enabled_value}


def set_feed_enabled(store, feed_id: str, enabled: bool, actor: str) -> dict[str, Any]:
    if not isinstance(enabled, bool):
        raise ValueError("threat_feed_invalid")
    with store.lock, store.connect() as con:
        cur = con.execute("UPDATE threat_feeds SET enabled=?,updated_at=? WHERE feed_id=?", (int(bool(enabled)), _now(), feed_id))
        if not cur.rowcount:
            raise KeyError("threat_feed_not_found")
        store.audit(con, actor, "threat_feed.enabled_changed", feed_id, {"enabled": bool(enabled)})
    return {"feed_id": feed_id, "enabled": bool(enabled)}


def _insert_iocs(store, feed_id: str, indicators: list[dict[str, Any]], relationships: list[dict[str, Any]] | None = None) -> dict[str, int]:
    added = updated = ignored = 0
    now = _now()
    with store.lock, store.connect() as con:
        for item in indicators:
            if "_revoke_object_id" in item:
                object_id = _clean(item.get("_revoke_object_id"), 255)
                if object_id:
                    old_rows = con.execute("SELECT ioc_type,value_norm FROM threat_iocs WHERE source_feed=? AND source_object_id=? AND revoked=0", (feed_id, object_id)).fetchall()
                    con.execute("UPDATE threat_iocs SET revoked=1,updated_at=? WHERE source_feed=? AND source_object_id=?", (now, feed_id, object_id))
                    for old in old_rows:
                        cache_key = hashlib.sha256((old["ioc_type"] + "\0" + old["value_norm"]).encode()).hexdigest()
                        con.execute("DELETE FROM threat_intel_cache WHERE cache_key=?", (cache_key,))
                continue
            if "_object_summary" in item:
                obj = item["_object_summary"]
                con.execute("""INSERT INTO threat_objects(object_id,source_feed,object_type,modified_at,summary_json) VALUES(?,?,?,?,?)
                              ON CONFLICT(object_id,source_feed) DO UPDATE SET object_type=excluded.object_type,modified_at=excluded.modified_at,summary_json=excluded.summary_json""",
                            (obj["object_id"], feed_id, obj["object_type"], obj["modified_at"], json.dumps(obj["summary"], ensure_ascii=False)))
                continue
            try:
                kind, value = normalize_ioc(item.get("ioc_type", ""), item.get("value"))
                confidence = max(0, min(100, int(item.get("confidence", 50))))
                valid_from = _parse_time(item.get("valid_from"))
                valid_until = _parse_time(item.get("valid_until"))
                if (item.get("valid_from") and not valid_from) or (item.get("valid_until") and not valid_until):
                    raise ValueError("invalid validity timestamp")
                if valid_from and valid_until and valid_until <= valid_from:
                    raise ValueError("validity window is empty")
            except (ValueError, TypeError):
                ignored += 1
                continue
            severity = item.get("severity") if item.get("severity") in {"critical", "high", "medium", "low", "info"} else "medium"
            description = _clean(item.get("description"), 300)
            tags = [_clean(t, 64) for t in (item.get("tags") if isinstance(item.get("tags"), list) else [])[:20] if _clean(t, 64)]
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            metadata = {str(k)[:64]: _clean(v, 300) if not isinstance(v, (dict, list)) else "" for k, v in list(metadata.items())[:20]}
            ioc_id = "ioc_" + hashlib.sha256((kind + "\0" + value + "\0" + feed_id).encode()).hexdigest()[:24]
            existing = con.execute("SELECT ioc_id FROM threat_iocs WHERE ioc_type=? AND value_norm=? AND source_feed=?", (kind, value, feed_id)).fetchone()
            cache_key = hashlib.sha256((kind + "\0" + value).encode()).hexdigest()
            con.execute("DELETE FROM threat_intel_cache WHERE cache_key=?", (cache_key,))
            con.execute("""INSERT INTO threat_iocs(ioc_id,ioc_type,value_norm,source_feed,source_object_id,confidence,severity,description,tags_json,metadata_json,valid_from,valid_until,revoked,created_at,updated_at)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)
                          ON CONFLICT(ioc_type,value_norm,source_feed) DO UPDATE SET source_object_id=excluded.source_object_id,confidence=excluded.confidence,severity=excluded.severity,description=excluded.description,tags_json=excluded.tags_json,metadata_json=excluded.metadata_json,valid_from=excluded.valid_from,valid_until=excluded.valid_until,revoked=0,updated_at=excluded.updated_at""",
                        (ioc_id, kind, value, feed_id, _clean(item.get("source_object_id"), 255), confidence, severity, description,
                         json.dumps(tags, ensure_ascii=False), json.dumps(metadata, ensure_ascii=False), valid_from,
                         valid_until, now, now))
            if existing:
                updated += 1
            else:
                added += 1
        for rel in (relationships or [])[:MAX_IMPORT_OBJECTS]:
            con.execute("INSERT INTO threat_relationships(source_object,target_object,relationship_type,source_feed,created_at) VALUES(?,?,?,?,?) ON CONFLICT(source_object,target_object,relationship_type,source_feed) DO NOTHING",
                        (rel["source_object"], rel["target_object"], rel["relationship_type"], feed_id, now))
        con.execute("DELETE FROM threat_intel_cache WHERE expires_at<?", (int(time.time()),))
    return {"added": added, "updated": updated, "ignored": ignored, "relationships": len(relationships or [])}


def import_stix(store, feed_id: str, bundle: Any, actor: str) -> dict[str, Any]:
    with store.connect() as con:
        feed = con.execute("SELECT feed_type,enabled FROM threat_feeds WHERE feed_id=?", (feed_id,)).fetchone()
    if not feed:
        raise KeyError("threat_feed_not_found")
    if feed["feed_type"] not in {"stix_bundle", "taxii21"}:
        raise ValueError("threat_feed_type_mismatch")
    if not feed["enabled"]:
        raise ValueError("threat_feed_disabled")
    indicators, relationships, ignored = parse_stix_bundle(bundle)
    result = _insert_iocs(store, feed_id, indicators, relationships)
    result["ignored"] += ignored
    with store.lock, store.connect() as con:
        con.execute("UPDATE threat_feeds SET last_sync_at=?,last_status='ok',last_error='',object_count=?,updated_at=? WHERE feed_id=?",
                    (_now(), result["added"] + result["updated"], _now(), feed_id))
        store.audit(con, actor, "threat_feed.stix_imported", feed_id, result)
    return result


def import_json_iocs(store, feed_id: str, records: Any, actor: str) -> dict[str, Any]:
    with store.connect() as con:
        feed = con.execute("SELECT feed_type,enabled FROM threat_feeds WHERE feed_id=?", (feed_id,)).fetchone()
    if not feed:
        raise KeyError("threat_feed_not_found")
    if feed["feed_type"] != "json_iocs" or not feed["enabled"]:
        raise ValueError("threat_feed_type_mismatch" if feed["enabled"] else "threat_feed_disabled")
    if not isinstance(records, list) or not records or len(records) > MAX_IMPORT_OBJECTS:
        raise ValueError("threat_ioc_batch_invalid")
    result = _insert_iocs(store, feed_id, records)
    with store.lock, store.connect() as con:
        con.execute("UPDATE threat_feeds SET last_sync_at=?,last_status='ok',last_error='',object_count=?,updated_at=? WHERE feed_id=?",
                    (_now(), result["added"] + result["updated"], _now(), feed_id))
        store.audit(con, actor, "threat_feed.json_imported", feed_id, result)
    return result


def _feed(store, feed_id: str):
    with store.connect() as con:
        row = con.execute("SELECT * FROM threat_feeds WHERE feed_id=?", (feed_id,)).fetchone()
    if not row:
        raise KeyError("threat_feed_not_found")
    return row


def _decode_feed_json(raw: bytes) -> dict[str, Any]:
    """Decode a bounded feed response and normalize malformed JSON errors."""
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError("threat_feed_format_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("threat_feed_format_invalid")
    return value


def _taxii_objects(feed: dict[str, Any], cfg: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    discovery = str(feed["url"])
    dparts = _validate_remote_url(discovery)
    headers = {"Accept": "application/taxii+json;version=2.1"}
    auth_env = cfg.get("auth_env", "")
    if auth_env:
        secret = os.getenv(auth_env, "")
        if not secret or len(secret) > 4096 or any(ch in secret for ch in "\r\n\x00"):
            raise ValueError("threat_feed_credentials_missing")
        header_name = cfg.get("auth_header", "Authorization")
        scheme = cfg.get("auth_scheme", "Bearer")
        headers[header_name] = secret if scheme == "none" or header_name == "X-TAXII-API-Key" else f"{scheme} {secret}"
    _, _, raw = _request(discovery, headers=headers, max_bytes=256 * 1024)
    disc = _decode_feed_json(raw)
    api_root = cfg.get("api_root") or ((disc.get("api_roots") or [None])[0])
    if not api_root:
        raise ValueError("threat_taxii_no_api_root")
    api_root_url = urllib.parse.urljoin(discovery, api_root)
    aparts = _validate_remote_url(api_root_url)
    if aparts.hostname != dparts.hostname:
        raise ValueError("threat_taxii_cross_host_rejected")
    base = api_root_url.rstrip("/") + "/"
    _, _, collection_raw = _request(urllib.parse.urljoin(base, "collections/"), headers=headers, max_bytes=512 * 1024)
    collections = _decode_feed_json(collection_raw).get("collections", [])
    collection_id = cfg.get("collection_id")
    if not collection_id:
        if len(collections) != 1:
            raise ValueError("threat_taxii_collection_required")
        collection_id = collections[0].get("id")
    if not any(c.get("id") == collection_id for c in collections if isinstance(c, dict)):
        raise ValueError("threat_taxii_collection_not_found")
    coll_path = "collections/" + urllib.parse.quote(str(collection_id), safe="") + "/objects/"
    next_token = ""
    seen_tokens: set[str] = set()
    objects: list[dict[str, Any]] = []
    for _page in range(5):
        query = {"limit": "1000"}
        if next_token:
            query["next"] = next_token
        page_url = urllib.parse.urljoin(base, coll_path) + "?" + urllib.parse.urlencode(query)
        page_parts = _validate_remote_url(page_url)
        if page_parts.hostname != dparts.hostname:
            raise ValueError("threat_taxii_cross_host_rejected")
        _, _, objects_raw = _request(page_url, headers=headers, max_bytes=MAX_FEED_BYTES)
        envelope = _decode_feed_json(objects_raw)
        page_objects = envelope.get("objects", [])
        if not isinstance(page_objects, list):
            raise ValueError("threat_feed_format_invalid")
        objects.extend(x for x in page_objects if isinstance(x, dict))
        if len(objects) > MAX_IMPORT_OBJECTS:
            raise ValueError("threat_taxii_object_limit")
        token = str(envelope.get("next") or "")
        if not token:
            break
        if len(token) > 1024 or token in seen_tokens:
            raise ValueError("threat_feed_format_invalid")
        seen_tokens.add(token)
        next_token = token
    else:
        raise ValueError("threat_taxii_object_limit")
    return {"type": "bundle", "id": "bundle--" + uuid.uuid4().hex, "objects": objects}, {}


def sync_feed(store, feed_id: str, actor: str) -> dict[str, Any]:
    feed = _feed(store, feed_id)
    if not feed["enabled"]:
        raise ValueError("threat_feed_disabled")
    feed_type = feed["feed_type"]
    try:
        if feed_type == "cisa_kev":
            status, headers, raw = _request(feed["url"], headers={"If-None-Match": feed["etag"]} if feed["etag"] else {}, max_bytes=MAX_FEED_BYTES)
            if status == 304:
                result = {"added": 0, "updated": 0, "ignored": 0, "not_modified": True}
            else:
                data = _decode_feed_json(raw)
                vulns = data.get("vulnerabilities")
                if not isinstance(vulns, list) or len(vulns) > 25000:
                    raise ValueError("threat_feed_format_invalid")
                records = []
                for item in vulns:
                    if not isinstance(item, dict):
                        continue
                    cve = item.get("cveID")
                    records.append({"ioc_type": "cve", "value": cve, "confidence": 100, "severity": "high",
                                    "description": item.get("vulnerabilityName") or item.get("shortDescription"),
                                    "tags": ["CISA-KEV", "known-exploited"],
                                    "metadata": {k: item.get(src, "") for k, src in {
                                        "vendor": "vendorProject", "product": "product", "date_added": "dateAdded",
                                        "due_date": "dueDate", "required_action": "requiredAction",
                                        "known_ransomware_use": "knownRansomwareCampaignUse"}.items()}})
                result = _insert_iocs(store, feed_id, records)
            with store.lock, store.connect() as con:
                con.execute("UPDATE threat_feeds SET last_sync_at=?,last_status='ok',last_error='',etag=?,last_modified=?,object_count=?,updated_at=? WHERE feed_id=?",
                            (_now(), headers.get("ETag", feed["etag"]) if status != 304 else feed["etag"],
                             headers.get("Last-Modified", feed["last_modified"]) if status != 304 else feed["last_modified"],
                             result.get("added", 0) + result.get("updated", 0), _now(), feed_id))
                store.audit(con, actor, "threat_feed.synced", feed_id, result)
            return result
        if feed_type == "taxii21":
            cfg = json.loads(feed["config_json"] or "{}")
            bundle, _ = _taxii_objects(dict(feed), cfg)
            indicators, relationships, ignored = parse_stix_bundle(bundle)
            result = _insert_iocs(store, feed_id, indicators, relationships)
            result["ignored"] += ignored
            with store.lock, store.connect() as con:
                con.execute("UPDATE threat_feeds SET last_sync_at=?,last_status='ok',last_error='',object_count=?,updated_at=? WHERE feed_id=?",
                            (_now(), result["added"] + result["updated"], _now(), feed_id))
                store.audit(con, actor, "threat_feed.synced", feed_id, result)
            return result
        raise ValueError("threat_feed_manual_import_only")
    except Exception as exc:
        code = str(exc)[:120] if str(exc).startswith("threat_") else "threat_feed_sync_failed"
        with store.lock, store.connect() as con:
            con.execute("UPDATE threat_feeds SET last_sync_at=?,last_status='error',last_error=?,updated_at=? WHERE feed_id=?",
                        (_now(), code, _now(), feed_id))
            store.audit(con, actor, "threat_feed.sync_failed", feed_id, {"error_code": code})
        raise ValueError(code) from exc


def _lookup_raw(store, ioc_type: str, value: str) -> list[dict[str, Any]]:
    now = _now()
    with store.connect() as con:
        rows = con.execute("""SELECT i.* , f.name AS feed_name FROM threat_iocs i LEFT JOIN threat_feeds f ON f.feed_id=i.source_feed
                             WHERE i.ioc_type=? AND i.value_norm=? AND i.revoked=0
                             AND (i.valid_until IS NULL OR i.valid_until=''
                                  OR i.valid_until>?)
                             AND (i.valid_from IS NULL OR i.valid_from='' OR i.valid_from<=?)
                             ORDER BY i.confidence DESC,i.updated_at DESC LIMIT 50""",
                           (ioc_type, value, now, now)).fetchall()
    out = []
    for row in rows:
        out.append({"ioc_id": row["ioc_id"], "type": row["ioc_type"], "value": row["value_norm"],
                    "source_feed": row["source_feed"], "feed_name": row["feed_name"] or row["source_feed"],
                    "source_object_id": row["source_object_id"], "confidence": row["confidence"],
                    "severity": row["severity"], "description": row["description"],
                    "tags": json.loads(row["tags_json"] or "[]"), "metadata": json.loads(row["metadata_json"] or "{}"),
                    "valid_from": row["valid_from"], "valid_until": row["valid_until"]})
    return out


def lookup(store, ioc_type: str, value: Any, *, use_cache: bool = True) -> dict[str, Any]:
    kind, normalized = normalize_ioc(ioc_type, value)
    cache_key = hashlib.sha256((kind + "\0" + normalized).encode()).hexdigest()
    now_epoch = int(time.time())
    if use_cache:
        with store.connect() as con:
            row = con.execute("SELECT result_json,expires_at FROM threat_intel_cache WHERE cache_key=?", (cache_key,)).fetchone()
        if row and int(row["expires_at"]) > now_epoch:
            result = json.loads(row["result_json"])
            result["cache"] = "hit"
            return result
    matches = _lookup_raw(store, kind, normalized)
    result = {"type": kind, "value": normalized, "matched": bool(matches), "matches": matches,
              "sources": sorted({x["source_feed"] for x in matches}), "cache": "miss",
              "checked_at": _now(), "note": "Local feed lookup only; the indicator was not resolved, opened or fetched."}
    ttl = CACHE_POSITIVE_SECONDS if matches else CACHE_NEGATIVE_SECONDS
    now_dt = datetime.now(timezone.utc)
    boundaries = []
    for match in matches:
        boundary = _parse_time(match.get("valid_until"))
        if boundary:
            try: boundaries.append(datetime.fromisoformat(boundary.replace("Z", "+00:00")))
            except ValueError: pass
    if boundaries:
        ttl = min(ttl, max(0, int((min(boundaries) - now_dt).total_seconds())))
    # A future valid_from can make a negative cache entry stale before its normal TTL.
    with store.connect() as con:
        future = con.execute("SELECT MIN(valid_from) AS starts_at FROM threat_iocs WHERE ioc_type=? AND value_norm=? AND revoked=0 AND valid_from>?", (kind, normalized, _now())).fetchone()
    if future and future["starts_at"]:
        start = _parse_time(future["starts_at"])
        if start:
            ttl = min(ttl, max(0, int((datetime.fromisoformat(start.replace("Z", "+00:00")) - now_dt).total_seconds())))
    with store.lock, store.connect() as con:
        con.execute("INSERT INTO threat_intel_cache(cache_key,result_json,created_at,expires_at) VALUES(?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET result_json=excluded.result_json,created_at=excluded.created_at,expires_at=excluded.expires_at",
                    (cache_key, json.dumps(result, ensure_ascii=False), _now(), now_epoch + ttl))
    return result


def lookup_many(store, indicators: Any) -> list[dict[str, Any]]:
    if not isinstance(indicators, list) or not indicators or len(indicators) > 100:
        raise ValueError("threat_ioc_batch_invalid")
    results = []
    for item in indicators:
        if not isinstance(item, dict):
            raise ValueError("threat_ioc_invalid")
        results.append(lookup(store, item.get("type", ""), item.get("value")))
    return results


def enrich_incident(store, incident_id: str) -> dict[str, Any]:
    with store.connect() as con:
        incident = con.execute("SELECT incident_id FROM security_incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if not incident:
            raise KeyError("security_incident_not_found")
        rows = con.execute("SELECT * FROM security_events WHERE incident_id=? ORDER BY observed_at ASC LIMIT 250", (incident_id,)).fetchall()
    indicators: set[tuple[str, str]] = set()
    for row in rows:
        for field, kind in (("src_ip", "ip"), ("dst_ip", "ip")):
            if row[field]: indicators.add((kind, str(row[field])))
        try:
            details = json.loads(row["details_json"] or "{}")
        except (TypeError, ValueError):
            details = {}
        entities = details.get("entities") if isinstance(details, dict) else {}
        if isinstance(entities, dict):
            for field, kind in (("domain", "domain"), ("file_sha256", "sha256")):
                if entities.get(field): indicators.add((kind, str(entities[field])))
    matches = []
    for kind, value in sorted(indicators):
        entry = lookup(store, kind, value)
        if entry["matched"]:
            matches.append(entry)
    return {"incident_id": incident_id, "checked_indicators": len(indicators), "matched_indicators": len(matches),
            "matches": matches, "note": "Only normalized incident evidence was checked against local IOC feeds."}


def epss_lookup(cves: list[str], store=None) -> dict[str, Any]:
    normalized = []
    for cve in cves:
        kind, value = normalize_ioc("cve", cve)
        if kind != "cve":
            continue
        normalized.append(value)
    normalized = sorted(set(normalized))
    if not normalized or len(normalized) > 50:
        raise ValueError("threat_epss_batch_invalid")

    # Optional local cache. Cache keys are namespaced so EPSS values cannot collide
    # with IOC reputation keys in the shared cache table.
    cached: dict[str, dict[str, Any]] = {}
    missing = list(normalized)
    now_epoch = int(time.time())
    if store is not None:
        with store.connect() as con:
            for cve in normalized:
                key = hashlib.sha256(("epss\0" + cve).encode()).hexdigest()
                row = con.execute("SELECT result_json,expires_at FROM threat_intel_cache WHERE cache_key=?", (key,)).fetchone()
                if row and int(row["expires_at"]) > now_epoch:
                    try:
                        cached[cve] = json.loads(row["result_json"])
                        missing.remove(cve)
                    except (ValueError, TypeError):
                        pass

    fetched: dict[str, dict[str, Any]] = {}
    if missing:
        query = urllib.parse.urlencode({"cve": ",".join(missing)})
        url = "https://api.first.org/data/v1/epss?" + query
        try:
            _, _, raw = _request(url, max_bytes=256 * 1024)
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError("threat_epss_response_invalid") from exc
        data = obj.get("data") if isinstance(obj, dict) else None
        if not isinstance(data, list):
            raise ValueError("threat_epss_response_invalid")
        for item in data[:50]:
            if not isinstance(item, dict):
                continue
            cve = str(item.get("cve", "")).upper()
            if cve not in missing:
                continue
            try:
                epss = max(0.0, min(1.0, float(item.get("epss"))))
                percentile = max(0.0, min(1.0, float(item.get("percentile"))))
            except (TypeError, ValueError):
                continue
            fetched[cve] = {"cve": cve, "epss": epss, "percentile": percentile, "date": _clean(item.get("date"), 20)}
        if store is not None:
            with store.lock, store.connect() as con:
                for cve in missing:
                    key = hashlib.sha256(("epss\0" + cve).encode()).hexdigest()
                    result = fetched.get(cve)
                    if result:
                        con.execute("INSERT INTO threat_intel_cache(cache_key,result_json,created_at,expires_at) VALUES(?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET result_json=excluded.result_json,created_at=excluded.created_at,expires_at=excluded.expires_at",
                                    (key, json.dumps(result, ensure_ascii=False), _now(), now_epoch + 6 * 3600))
                    else:
                        # Short negative cache; a newly published score will become visible shortly.
                        con.execute("INSERT INTO threat_intel_cache(cache_key,result_json,created_at,expires_at) VALUES(?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET result_json=excluded.result_json,created_at=excluded.created_at,expires_at=excluded.expires_at",
                                    (key, json.dumps({"missing": True}), _now(), now_epoch + CACHE_NEGATIVE_SECONDS))

    results = []
    for cve in normalized:
        item = fetched.get(cve) or cached.get(cve)
        if item and not item.get("missing"):
            results.append(item)
    return {"provider": "FIRST EPSS", "results": results, "attribution": "FIRST.org EPSS", "checked_at": _now(),
            "cache": "hit" if cached and not fetched else ("partial" if cached else "miss")}


def summary(store) -> dict[str, Any]:
    with store.connect() as con:
        now = _now()
        counts = con.execute("SELECT ioc_type,COUNT(*) AS count FROM threat_iocs WHERE revoked=0 AND (valid_from IS NULL OR valid_from='' OR valid_from<=?) AND (valid_until IS NULL OR valid_until='' OR valid_until>?) GROUP BY ioc_type ORDER BY ioc_type", (now, now)).fetchall()
        feeds = con.execute("SELECT COUNT(*) AS n FROM threat_feeds").fetchone()["n"]
        iocs = con.execute("SELECT COUNT(*) AS n FROM threat_iocs WHERE revoked=0 AND (valid_from IS NULL OR valid_from='' OR valid_from<=?) AND (valid_until IS NULL OR valid_until='' OR valid_until>?)", (now, now)).fetchone()["n"]
        recent = con.execute("SELECT COUNT(*) AS n FROM threat_iocs WHERE revoked=0 AND updated_at>=? AND (valid_until IS NULL OR valid_until='' OR valid_until>?) AND (valid_from IS NULL OR valid_from='' OR valid_from<=?)", (_now()[:10] + "T00:00:00Z", _now(), _now())).fetchone()["n"]
    return {"feeds_total": int(feeds), "active_iocs": int(iocs), "updated_today": int(recent),
            "by_type": [{"type": r["ioc_type"], "count": int(r["count"])} for r in counts],
            "supported_types": ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "cve"],
            "remote_policy": "Explicit operator action; HTTPS; exact host allowlist; redirects rejected."}


def list_iocs(store, *, ioc_type: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    sql = "SELECT i.*,f.name AS feed_name FROM threat_iocs i LEFT JOIN threat_feeds f ON f.feed_id=i.source_feed WHERE i.revoked=0 AND (i.valid_until IS NULL OR i.valid_until='' OR i.valid_until>?) AND (i.valid_from IS NULL OR i.valid_from='' OR i.valid_from<=?)"
    params: list[Any] = [_now(), _now()]
    if ioc_type:
        sql += " AND i.ioc_type=?"
        params.append(ioc_type)
    sql += " ORDER BY i.updated_at DESC LIMIT ?"
    params.append(max(1, min(MAX_LIST, int(limit))))
    with store.connect() as con:
        rows = con.execute(sql, tuple(params)).fetchall()
    return [{"ioc_id": r["ioc_id"], "type": r["ioc_type"], "value": r["value_norm"], "source_feed": r["source_feed"],
             "feed_name": r["feed_name"] or r["source_feed"], "confidence": r["confidence"], "severity": r["severity"],
             "description": r["description"], "tags": json.loads(r["tags_json"] or "[]"), "updated_at": r["updated_at"]} for r in rows]
