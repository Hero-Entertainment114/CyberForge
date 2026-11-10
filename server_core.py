"""CyberForge Server Edition core: Linux inventory, nodes, RBAC, AI routing and audit."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import integrations

VERSION = "2.1.0"
APP_NAME = "CyberForge Server Edition"
ALLOWED_WORKFLOW_STEPS = {
    "collect_fleet_health", "check_ai_runtimes", "check_integrations",
    "backup_database", "verify_audit_chain",
}
ROLE_SCOPES = {
    "admin": ["*"],
    "operator": ["detection:read", "detection:manage", "detection:publish", "threatintel:read", "threatintel:manage", "threatintel:enrich", "fleet:read", "integrations:read", "ai:invoke", "ai:models:read", "ai:jobs:read", "ai:health", "workflows:read", "workflows:plan", "workflows:approve", "audit:read", "system:read", "metrics:read", "integrations:test", "security:read", "security:ingest", "security:incident:update", "security:playbook:plan", "security:playbook:approve", "security:analysis", "security:correlate"],
    "analyst": ["detection:read", "detection:manage", "threatintel:read", "threatintel:enrich", "fleet:read", "integrations:read", "ai:invoke", "ai:models:read", "ai:jobs:read", "workflows:read", "workflows:plan", "audit:read", "system:read", "metrics:read", "security:read", "security:incident:update", "security:playbook:plan", "security:analysis", "security:correlate"],
    "viewer": ["detection:read", "threatintel:read", "fleet:read", "integrations:read", "ai:models:read", "ai:jobs:read", "workflows:read", "audit:read", "system:read", "security:read", "security:analysis"],
    "sensor": ["security:ingest"],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_meminfo() -> dict[str, int]:
    data: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii", errors="replace").splitlines():
            key, _, rest = line.partition(":")
            parts = rest.strip().split()
            if parts and parts[0].isdigit():
                data[key] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    except OSError:
        pass
    return data


def host_inventory(data_dir: Path) -> dict[str, Any]:
    mem = _read_meminfo()
    disk = shutil.disk_usage(data_dir if data_dir.exists() else data_dir.parent)
    try:
        load = list(os.getloadavg())
    except (AttributeError, OSError):
        load = []
    uname = platform.uname()
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            k, sep, v = line.partition("=")
            if sep and k in {"NAME", "VERSION", "ID", "VERSION_ID", "PRETTY_NAME"}:
                os_release[k] = v.strip().strip('"')[:160]
    except OSError:
        pass
    cpu_model = "Unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith(("model name", "hardware")):
                cpu_model = line.split(":", 1)[-1].strip()[:160]
                break
    except OSError:
        pass
    gpu = {"nvidia_smi": bool(shutil.which("nvidia-smi")), "rocm_smi": bool(shutil.which("rocm-smi")),
           "xpu_smi": bool(shutil.which("xpu-smi"))}
    return {
        "hostname": platform.node(), "platform": uname.system, "kernel": uname.release,
        "architecture": uname.machine, "os_release": os_release,
        "cpu_model": cpu_model, "cpu_logical_cores": os.cpu_count() or 1,
        "load_average": load,
        "memory_total_bytes": mem.get("MemTotal", 0), "memory_available_bytes": mem.get("MemAvailable", 0),
        "disk_total_bytes": disk.total, "disk_free_bytes": disk.free,
        "gpu_tooling": gpu, "python": platform.python_version(),
        "data_dir": str(data_dir), "collected_at": utc_now(),
    }


class _ClosingConnection(sqlite3.Connection):
    """SQLite context manager that also closes the handle on exit."""
    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


class Store:
    backend = "sqlite"

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10, isolation_level="IMMEDIATE", factory=_ClosingConnection)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=10000")
        return con

    def _init_db(self) -> None:
        with self.lock, self.connect() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript("""
            CREATE TABLE IF NOT EXISTS api_tokens(
              token_id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL,
              role TEXT NOT NULL, scopes_json TEXT NOT NULL, created_at TEXT NOT NULL,
              revoked INTEGER NOT NULL DEFAULT 0, last_used TEXT
            );
            CREATE TABLE IF NOT EXISTS nodes(
              node_id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL,
              labels_json TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT,
              status TEXT NOT NULL DEFAULT 'pending', payload_json TEXT NOT NULL DEFAULT '{}', revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS node_nonces(
              node_id TEXT NOT NULL, nonce TEXT NOT NULL, created_at INTEGER NOT NULL,
              PRIMARY KEY(node_id, nonce)
            );
            CREATE TABLE IF NOT EXISTS workflows(
              workflow_id TEXT PRIMARY KEY, title TEXT NOT NULL, steps_json TEXT NOT NULL,
              created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at INTEGER NOT NULL,
              status TEXT NOT NULL, approved_by TEXT, approved_at TEXT, result_json TEXT
            );
            CREATE TABLE IF NOT EXISTS audit(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, actor TEXT NOT NULL,
              action TEXT NOT NULL, object_id TEXT NOT NULL, detail_json TEXT NOT NULL,
              prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS ai_usage(
              request_id TEXT PRIMARY KEY, actor TEXT NOT NULL, model TEXT NOT NULL,
              created_at TEXT NOT NULL, input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL,
              cost_usd REAL NOT NULL, status TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ai_usage_created ON ai_usage(created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);
            """)
            # Idempotent SQLite schema evolution for v2.0.2 workflow claims; v2.0.4 adds cross-source security intelligence.
            workflow_columns = {r["name"] for r in con.execute("PRAGMA table_info(workflows)").fetchall()}
            if "execution_owner" not in workflow_columns:
                con.execute("ALTER TABLE workflows ADD COLUMN execution_owner TEXT")
            if "execution_lease_until" not in workflow_columns:
                con.execute("ALTER TABLE workflows ADD COLUMN execution_lease_until INTEGER NOT NULL DEFAULT 0")
            con.execute("CREATE INDEX IF NOT EXISTS idx_workflows_execution_lease ON workflows(status,execution_lease_until)")
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def create_token(self, name: str, role: str, scopes: list[str] | None = None) -> dict[str, str]:
        if role not in ROLE_SCOPES:
            raise ValueError("invalid_role")
        raw = "cf_" + secrets.token_urlsafe(36)
        tid = uuid.uuid4().hex
        grants = sorted(set(scopes or ROLE_SCOPES[role]))
        with self.lock, self.connect() as con:
            con.execute("INSERT INTO api_tokens(token_id,name,token_hash,role,scopes_json,created_at) VALUES(?,?,?,?,?,?)",
                        (tid, name[:80], sha256_text(raw), role, json.dumps(grants), utc_now()))
            self.audit(con, "system", "token.created", tid, {"name": name[:80], "role": role, "scopes": grants})
        return {"token_id": tid, "token": raw, "role": role}

    def authenticate(self, raw: str) -> dict[str, Any] | None:
        if not raw or len(raw) > 256:
            return None
        digest = sha256_text(raw)
        with self.lock, self.connect() as con:
            row = con.execute("SELECT * FROM api_tokens WHERE token_hash=? AND revoked=0", (digest,)).fetchone()
            if not row:
                return None
            con.execute("UPDATE api_tokens SET last_used=? WHERE token_id=?", (utc_now(), row["token_id"]))
            return {"id": row["token_id"], "name": row["name"], "role": row["role"],
                    "scopes": json.loads(row["scopes_json"])}

    @staticmethod
    def has_scope(actor: dict[str, Any], scope: str) -> bool:
        return "*" in actor.get("scopes", []) or scope in actor.get("scopes", [])

    def revoke_token(self, token_id: str, actor: str) -> bool:
        with self.lock, self.connect() as con:
            cur = con.execute("UPDATE api_tokens SET revoked=1 WHERE token_id=? AND revoked=0", (token_id,))
            if cur.rowcount:
                self.audit(con, actor, "token.revoked", token_id, {})
            return bool(cur.rowcount)

    def create_node(self, name: str, labels: dict[str, str] | None = None) -> dict[str, str]:
        if not name or len(name) > 80:
            raise ValueError("invalid_node_name")
        node_id = "node_" + uuid.uuid4().hex[:16]
        raw = "cfn_" + secrets.token_urlsafe(40)
        with self.lock, self.connect() as con:
            con.execute("INSERT INTO nodes(node_id,name,token_hash,labels_json,created_at) VALUES(?,?,?,?,?)",
                        (node_id, name, sha256_text(raw), json.dumps(_clean_labels(labels or {})), utc_now()))
            self.audit(con, "admin", "node.enrolled", node_id, {"name": name})
        return {"node_id": node_id, "token": raw}

    def accept_node_report(self, node_id: str, raw_token: str, timestamp: int, nonce: str, payload: dict[str, Any]) -> None:
        now = int(time.time())
        if abs(now - int(timestamp)) > 120:
            raise ValueError("node_timestamp_out_of_range")
        if not nonce or len(nonce) > 80 or not nonce.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid_nonce")
        clean = validate_node_payload(payload)
        with self.lock, self.connect() as con:
            row = con.execute("SELECT token_hash,revoked FROM nodes WHERE node_id=?", (node_id,)).fetchone()
            if not row or row["revoked"] or not hmac.compare_digest(row["token_hash"], sha256_text(raw_token)):
                raise PermissionError("node_auth_failed")
            try:
                con.execute("INSERT INTO node_nonces(node_id,nonce,created_at) VALUES(?,?,?)", (node_id, nonce, now))
            except Exception as exc:
                # SQLite and PostgreSQL expose different exception classes.
                code = getattr(exc, "sqlstate", None) or getattr(getattr(exc, "diag", None), "sqlstate", None)
                if isinstance(exc, sqlite3.IntegrityError) or code == "23505":
                    raise PermissionError("replayed_node_request") from exc
                raise
            con.execute("DELETE FROM node_nonces WHERE created_at < ?", (now - 600,))
            con.execute("UPDATE nodes SET last_seen=?,status='online',payload_json=? WHERE node_id=?",
                        (utc_now(), json.dumps(clean, separators=(",", ":")), node_id))

    def list_nodes(self) -> list[dict[str, Any]]:
        now = time.time()
        with self.lock, self.connect() as con:
            rows = con.execute("SELECT * FROM nodes ORDER BY lower(name)").fetchall()
        out = []
        for r in rows:
            if r["revoked"]:
                status = "revoked"
            elif not r["last_seen"]:
                status = "pending"
            else:
                try:
                    seen = datetime.fromisoformat(r["last_seen"]).timestamp()
                except ValueError:
                    seen = 0
                status = "online" if now - seen < int(os.getenv("CF_NODE_STALE_SECONDS", "120")) else "stale"
            out.append({"node_id": r["node_id"], "name": r["name"], "labels": json.loads(r["labels_json"]),
                        "created_at": r["created_at"], "last_seen": r["last_seen"], "status": status,
                        "metrics": json.loads(r["payload_json"])})
        return out

    def revoke_node(self, node_id: str, actor: str) -> bool:
        with self.lock, self.connect() as con:
            cur = con.execute("UPDATE nodes SET revoked=1,status='revoked' WHERE node_id=? AND revoked=0", (node_id,))
            if cur.rowcount:
                self.audit(con, actor, "node.revoked", node_id, {})
            return bool(cur.rowcount)

    def add_workflow(self, title: str, steps: list[str], actor: str) -> str:
        if not title or len(title) > 120 or not steps or len(steps) > 12:
            raise ValueError("invalid_workflow")
        if any(s not in ALLOWED_WORKFLOW_STEPS for s in steps):
            raise ValueError("workflow_step_not_allowed")
        wid = "wf_" + uuid.uuid4().hex[:16]
        expires = int(time.time()) + 600
        with self.lock, self.connect() as con:
            con.execute("INSERT INTO workflows(workflow_id,title,steps_json,created_by,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?)",
                        (wid, title, json.dumps(steps), actor, utc_now(), expires, "pending_approval"))
            self.audit(con, actor, "workflow.planned", wid, {"steps": steps})
        return wid

    def list_workflows(self) -> list[dict[str, Any]]:
        with self.lock, self.connect() as con:
            rows = con.execute("SELECT * FROM workflows ORDER BY created_at DESC LIMIT 100").fetchall()
        return [{"workflow_id": r["workflow_id"], "title": r["title"], "steps": json.loads(r["steps_json"]),
                 "created_by": r["created_by"], "created_at": r["created_at"], "expires_at": r["expires_at"],
                 "status": r["status"], "approved_by": r["approved_by"], "approved_at": r["approved_at"],
                 "result": json.loads(r["result_json"]) if r["result_json"] else None} for r in rows]

    def approve_workflow(self, workflow_id: str, actor: str) -> None:
        expired = False
        with self.lock, self.connect() as con:
            row = con.execute("SELECT * FROM workflows WHERE workflow_id=?", (workflow_id,)).fetchone()
            if not row:
                raise KeyError("workflow_not_found")
            if row["expires_at"] < int(time.time()):
                con.execute("UPDATE workflows SET status='expired' WHERE workflow_id=? AND status='pending_approval'", (workflow_id,))
                expired = True
            else:
                if row["status"] != "pending_approval":
                    raise ValueError("workflow_not_pending")
                if os.getenv("CF_WORKFLOW_REQUIRE_TWO_PERSON", "0") == "1" and row["created_by"] == actor:
                    raise PermissionError("two_person_approval_required")
                cur = con.execute("UPDATE workflows SET status='approved',approved_by=?,approved_at=? WHERE workflow_id=? AND status='pending_approval' AND expires_at>=?",
                                  (actor, utc_now(), workflow_id, int(time.time())))
                if cur.rowcount != 1:
                    raise ValueError("workflow_not_pending")
                self.audit(con, actor, "workflow.approved", workflow_id, {})
        if expired:
            raise TimeoutError("workflow_expired")

    def claim_workflow(self, workflow_id: str, actor: str, lease_seconds: int = 120) -> str:
        """Atomically claim an approved or abandoned read-only workflow on any replica."""
        owner = uuid.uuid4().hex
        now = int(time.time())
        lease_until = now + max(30, min(600, int(lease_seconds)))
        expired = False
        conflict = ""
        with self.lock, self.connect() as con:
            row = con.execute("SELECT status,expires_at,execution_lease_until FROM workflows WHERE workflow_id=?", (workflow_id,)).fetchone()
            if not row:
                raise KeyError("workflow_not_found")
            if row["status"] == "approved" and int(row["expires_at"]) < now:
                con.execute("UPDATE workflows SET status='expired' WHERE workflow_id=? AND status='approved'", (workflow_id,))
                expired = True
            else:
                # A crashed instance may leave an execution lease behind. All currently
                # permitted workflow steps are diagnostic/read-only or database backup,
                # so reclaiming an expired lease is safe and duplicate-resistant.
                cur = con.execute("""UPDATE workflows SET status='executing',execution_owner=?,execution_lease_until=?
                    WHERE workflow_id=? AND ((status='approved' AND expires_at>=?) OR
                    (status='executing' AND execution_lease_until<?))""",
                    (owner, lease_until, workflow_id, now, now))
                if cur.rowcount != 1:
                    current = con.execute("SELECT status FROM workflows WHERE workflow_id=?", (workflow_id,)).fetchone()
                    conflict = "workflow_already_executing" if current and current["status"] == "executing" else "workflow_not_approved"
                else:
                    self.audit(con, actor, "workflow.execution_claimed", workflow_id, {"lease_seconds": lease_until - now})
        if expired:
            raise TimeoutError("workflow_expired")
        if conflict:
            raise ValueError(conflict)
        return owner

    def renew_workflow(self, workflow_id: str, owner: str, lease_seconds: int = 120) -> bool:
        lease_until = int(time.time()) + max(30, min(600, int(lease_seconds)))
        with self.lock, self.connect() as con:
            cur = con.execute("UPDATE workflows SET execution_lease_until=? WHERE workflow_id=? AND status='executing' AND execution_owner=?",
                              (lease_until, workflow_id, owner))
            return cur.rowcount == 1

    def finish_workflow(self, workflow_id: str, actor: str, result: dict[str, Any], owner: str) -> None:
        with self.lock, self.connect() as con:
            row = con.execute("SELECT status,execution_owner FROM workflows WHERE workflow_id=?", (workflow_id,)).fetchone()
            if not row:
                raise KeyError("workflow_not_found")
            if row["status"] != "executing" or row["execution_owner"] != owner:
                raise ValueError("workflow_execution_lease_lost")
            cur = con.execute("UPDATE workflows SET status='completed',result_json=?,execution_owner=NULL,execution_lease_until=0 WHERE workflow_id=? AND status='executing' AND execution_owner=?",
                        (json.dumps(result, separators=(",", ":")), workflow_id, row["execution_owner"]))
            if cur.rowcount != 1:
                raise ValueError("workflow_execution_lease_lost")
            self.audit(con, actor, "workflow.executed", workflow_id, {"status": "completed"})

    def fail_workflow(self, workflow_id: str, actor: str, result: dict[str, Any], owner: str) -> bool:
        with self.lock, self.connect() as con:
            cur = con.execute("UPDATE workflows SET status='failed',result_json=?,execution_owner=NULL,execution_lease_until=0 WHERE workflow_id=? AND status='executing' AND execution_owner=?",
                              (json.dumps(result, separators=(",", ":")), workflow_id, owner))
            if cur.rowcount:
                self.audit(con, actor, "workflow.executed", workflow_id, {"status": "failed", "failed_step": result.get("failed_step", "")})
                return True
            return False

    def audit(self, con: sqlite3.Connection, actor: str, action: str, object_id: str, detail: dict[str, Any]) -> None:
        # A transaction-scoped advisory lock serializes hash-chain appends across
        # PostgreSQL control-plane processes. SQLite already has a write lock.
        if getattr(self, "backend", "sqlite") == "postgres":
            con.execute("SELECT pg_advisory_xact_lock(hashtext(?))", ("cyberforge:audit-chain",))
        row = con.execute("SELECT event_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["event_hash"] if row else "0" * 64
        created = utc_now()
        detail_json = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        canonical = "|".join([created, actor[:80], action[:100], object_id[:120], detail_json, prev])
        digest = sha256_text(canonical)
        con.execute("INSERT INTO audit(created_at,actor,action,object_id,detail_json,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
                    (created, actor[:80], action[:100], object_id[:120], detail_json, prev, digest))

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock, self.connect() as con:
            rows = con.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (max(1, min(500, limit)),)).fetchall()
        return [{"seq": r["seq"], "created_at": r["created_at"], "actor": r["actor"], "action": r["action"],
                 "object_id": r["object_id"], "detail": json.loads(r["detail_json"]), "prev_hash": r["prev_hash"],
                 "event_hash": r["event_hash"]} for r in rows]

    def verify_audit(self) -> dict[str, Any]:
        with self.lock, self.connect() as con:
            rows = con.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        prev = "0" * 64
        for row in rows:
            if row["prev_hash"] != prev:
                return {"valid": False, "broken_at": row["seq"], "events_checked": row["seq"]}
            canonical = "|".join([row["created_at"], row["actor"], row["action"], row["object_id"], row["detail_json"], prev])
            expected = sha256_text(canonical)
            if not hmac.compare_digest(expected, row["event_hash"]):
                return {"valid": False, "broken_at": row["seq"], "events_checked": row["seq"]}
            prev = row["event_hash"]
        return {"valid": True, "events_checked": len(rows), "head": prev}

    @staticmethod
    def _expire_ai_reservations(con: sqlite3.Connection) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")
        con.execute("UPDATE ai_usage SET cost_usd=0,status='reservation_expired' WHERE status='pending' AND created_at<?", (cutoff,))

    def ai_spend_today(self, model: str | None = None) -> float:
        today = datetime.now(timezone.utc).date().isoformat()
        with self.lock, self.connect() as con:
            self._expire_ai_reservations(con)
            if model is None:
                row = con.execute("SELECT COALESCE(SUM(cost_usd),0) amount FROM ai_usage WHERE substr(created_at,1,10)=?", (today,)).fetchone()
            else:
                row = con.execute("SELECT COALESCE(SUM(cost_usd),0) amount FROM ai_usage WHERE substr(created_at,1,10)=? AND model=?", (today, model)).fetchone()
        return float(row["amount"] or 0)

    def reserve_ai_usage(self, actor: str, model: str, estimated_cost: float, daily_budget: float | None) -> str | None:
        """Atomically reserve estimated spend before contacting a model provider."""
        amount = max(0.0, min(1e6, float(estimated_cost)))
        request_id = uuid.uuid4().hex
        today = datetime.now(timezone.utc).date().isoformat()
        with self.lock, self.connect() as con:
            if getattr(self, "backend", "sqlite") == "postgres":
                con.execute("SELECT pg_advisory_xact_lock(hashtext(?))", ("cyberforge:ai-spend:" + today + ":" + (model or "*"),))
            else:
                con.execute("BEGIN IMMEDIATE")
            self._expire_ai_reservations(con)
            if daily_budget is not None:
                row = con.execute(
                    "SELECT COALESCE(SUM(cost_usd),0) amount FROM ai_usage WHERE substr(created_at,1,10)=? AND model=?",
                    (today, model)).fetchone()
                if float(row["amount"] or 0) + amount > float(daily_budget):
                    return None
            con.execute("INSERT INTO ai_usage(request_id,actor,model,created_at,input_tokens,output_tokens,cost_usd,status) VALUES(?,?,?,?,?,?,?,?)",
                        (request_id, actor[:80], model, utc_now(), 0, 0, amount, "pending"))
        return request_id

    def finish_ai_usage(self, request_id: str, in_tokens: int, out_tokens: int, cost: float, status: str) -> None:
        with self.lock, self.connect() as con:
            con.execute("UPDATE ai_usage SET input_tokens=?,output_tokens=?,cost_usd=?,status=? WHERE request_id=? AND status='pending'",
                        (max(0, int(in_tokens)), max(0, int(out_tokens)), max(0.0, min(1e6, float(cost))), status, request_id))

    def add_ai_usage(self, actor: str, model: str, in_tokens: int, out_tokens: int, cost: float, status: str) -> None:
        # Backward-compatible helper used by older callers/tests.
        with self.lock, self.connect() as con:
            con.execute("INSERT INTO ai_usage(request_id,actor,model,created_at,input_tokens,output_tokens,cost_usd,status) VALUES(?,?,?,?,?,?,?,?)",
                        (uuid.uuid4().hex, actor[:80], model, utc_now(), max(0, int(in_tokens)), max(0, int(out_tokens)), max(0.0, float(cost)), status))


def _clean_labels(labels: dict[str, Any]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for k, v in list(labels.items())[:12]:
        if isinstance(k, str) and isinstance(v, (str, int, float, bool)):
            kk, vv = k[:40].strip(), str(v)[:80]
            if kk and not any(c in kk for c in "\r\n"):
                clean[kk] = vv
    return clean


def validate_node_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict) or len(json.dumps(payload)) > 16_000:
        raise ValueError("invalid_node_payload")
    allowed = {"hostname", "platform", "kernel", "architecture", "cpu_logical_cores", "cpu_model", "os_release",
               "load_average", "memory_total_bytes", "memory_available_bytes", "disk_total_bytes",
               "disk_free_bytes", "gpu_tooling", "python", "services", "collected_at"}
    out = {k: v for k, v in payload.items() if k in allowed}
    for key in ("hostname", "platform", "kernel", "architecture", "cpu_model", "python", "collected_at"):
        if key in out and (not isinstance(out[key], str) or len(out[key]) > 180):
            raise ValueError("invalid_node_payload")
    for key in ("cpu_logical_cores", "memory_total_bytes", "memory_available_bytes", "disk_total_bytes", "disk_free_bytes"):
        if key in out and (not isinstance(out[key], int) or out[key] < 0 or out[key] > 2**63 - 1):
            raise ValueError("invalid_node_payload")
    if "load_average" in out:
        if not isinstance(out["load_average"], list) or len(out["load_average"]) > 3:
            raise ValueError("invalid_node_payload")
        out["load_average"] = [max(0.0, min(1_000_000.0, float(x))) for x in out["load_average"]]
    if "gpu_tooling" in out and not isinstance(out["gpu_tooling"], dict):
        raise ValueError("invalid_node_payload")
    if "services" in out:
        if not isinstance(out["services"], dict) or len(out["services"]) > 20:
            raise ValueError("invalid_node_payload")
        out["services"] = {str(k)[:60]: str(v)[:40] for k, v in out["services"].items()}
    return out


class AIService:
    """Local-first multi-deployment OpenAI-compatible adapter with budget gates."""
    def __init__(self, store: Store):
        self.store = store

    def deployments(self) -> list[dict[str, Any]]:
        raw = os.getenv("CF_AI_DEPLOYMENTS_JSON", "").strip()
        specs: list[dict[str, Any]] = []
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid_ai_deployments_json") from exc
            if not isinstance(parsed, list) or len(parsed) > 32:
                raise ValueError("invalid_ai_deployments_json")
            specs = [x for x in parsed if isinstance(x, dict)]
            if len(specs) != len(parsed):
                raise ValueError("invalid_ai_deployments_json")
        else:
            specs = [{
                "id": "default", "model": os.getenv("CF_AI_MODEL", ""),
                "base_url": os.getenv("CF_AI_BASE_URL", "http://127.0.0.1:11434/v1"),
                "billing_mode": os.getenv("CF_AI_BILLING_MODE", "local"),
                "api_key_env": "CF_AI_API_KEY",
                "input_price_per_1m": _env_float("CF_AI_INPUT_PRICE_PER_1M", 0.0),
                "output_price_per_1m": _env_float("CF_AI_OUTPUT_PRICE_PER_1M", 0.0),
                "daily_budget_usd": _env_float("CF_AI_DAILY_BUDGET_USD", 0.0),
                "max_request_usd": _env_float("CF_AI_MAX_REQUEST_USD", 0.0),
            }]
        deployments: list[dict[str, Any]] = []
        ids: set[str] = set()
        for spec in specs:
            did = str(spec.get("id", "")).strip()
            model = str(spec.get("model", "")).strip()
            base = str(spec.get("base_url", "")).strip().rstrip("/")
            billing = str(spec.get("billing_mode", "local")).lower()
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", did) or did in ids:
                raise ValueError("invalid_ai_deployment_id")
            ids.add(did)
            if billing not in {"local", "free", "paid"}:
                raise ValueError("invalid_ai_billing_mode")
            parsed_url = urllib.parse.urlsplit(base)
            if base and (parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname or parsed_url.username or parsed_url.password):
                raise ValueError("invalid_ai_endpoint")
            api_key_env = str(spec.get("api_key_env", "CF_AI_API_KEY"))
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,100}", api_key_env):
                raise ValueError("invalid_ai_key_env")
            deployments.append({
                "id": did, "model": model, "base_url": base, "billing_mode": billing,
                "api_key_env": api_key_env, "api_key_configured": bool(os.getenv(api_key_env)),
                "input_price_per_1m": max(0.0, min(1e6, float(spec.get("input_price_per_1m", 0) or 0))),
                "output_price_per_1m": max(0.0, min(1e6, float(spec.get("output_price_per_1m", 0) or 0))),
                "daily_budget_usd": max(0.0, min(1e6, float(spec.get("daily_budget_usd", 0) or 0))),
                "max_request_usd": max(0.0, min(1e6, float(spec.get("max_request_usd", 0) or 0))),
            })
        return deployments

    def status(self) -> dict[str, Any]:
        items = self.deployments()
        default_id = os.getenv("CF_AI_DEFAULT_DEPLOYMENT", "").strip()
        hosts_allow = {x.strip().lower() for x in os.getenv("CF_AI_ALLOWED_HOSTS", "").split(",") if x.strip()}
        safe = []
        for d in items:
            parsed = urllib.parse.urlsplit(d["base_url"])
            host = (parsed.hostname or "").lower()
            local = host in {"127.0.0.1", "localhost", "::1"}
            safe.append({"id": d["id"], "model": d["model"], "endpoint_host": host,
                         "local_endpoint": local, "host_allowlisted": local or host in hosts_allow,
                         "billing_mode": d["billing_mode"], "configured": bool(d["model"] and d["base_url"]),
                         "api_key_configured": d["api_key_configured"],
                         "paid_enabled": os.getenv("CF_AI_ALLOW_PAID", "0") == "1",
                         "daily_budget_usd": d["daily_budget_usd"],
                         "daily_spend_usd": self.store.ai_spend_today(d["id"]),
                         "prices_configured": d["input_price_per_1m"] > 0 or d["output_price_per_1m"] > 0})
        # The persistent AI Control Plane policy takes precedence over the legacy env default.
        try:
            with self.store.connect() as con:
                policy_rows = con.execute("SELECT deployment_id,enabled,is_default FROM ai_model_registry").fetchall()
            policy = {r["deployment_id"]: r for r in policy_rows}
            for item in safe:
                if item["id"] in policy:
                    item["enabled"] = bool(policy[item["id"]]["enabled"])
                    item["is_default"] = bool(policy[item["id"]]["is_default"])
            persisted_default = next((r["deployment_id"] for r in policy_rows if r["is_default"] and r["enabled"]), None)
            if persisted_default:
                default_id = persisted_default
        except Exception as exc:
            sqlstate = getattr(exc, "sqlstate", None)
            if not isinstance(exc, sqlite3.Error) and sqlstate != "42P01":
                raise
        chosen = next((x for x in safe if x["id"] == default_id and x.get("enabled", True)), None)
        if chosen is None:
            chosen = next((x for x in safe if x.get("enabled", True) and x["billing_mode"] in {"local", "free"}), None)
        return {"configured": bool(chosen and chosen["configured"]),
                "default_deployment": chosen["id"] if chosen else None,
                "model": chosen["model"] if chosen else "",
                "endpoint_host": chosen["endpoint_host"] if chosen else "",
                "local_endpoint": chosen["local_endpoint"] if chosen else False,
                "billing_mode": chosen["billing_mode"] if chosen else "local",
                "api_key_configured": chosen["api_key_configured"] if chosen else False,
                "paid_enabled": os.getenv("CF_AI_ALLOW_PAID", "0") == "1",
                "daily_budget_usd": chosen["daily_budget_usd"] if chosen else 0.0,
                "daily_spend_usd": self.store.ai_spend_today(),
                "prices_configured": bool(chosen and chosen["prices_configured"]),
                "deployments": safe, "runtimes": runtime_inventory()}

    def chat(self, actor: str, body: dict[str, Any]) -> dict[str, Any]:
        messages = body.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 30:
            raise ValueError("invalid_messages")
        clean = []
        total_chars = 0
        for item in messages:
            if not isinstance(item, dict) or item.get("role") not in {"system", "user", "assistant"}:
                raise ValueError("invalid_messages")
            content = item.get("content")
            if not isinstance(content, str) or len(content) > 20_000:
                raise ValueError("invalid_messages")
            total_chars += len(content)
            clean.append({"role": item["role"], "content": content})
        if total_chars > 60_000:
            raise ValueError("prompt_too_large")
        deployments = self.deployments()
        status = self.status()
        deployment_id = str(body.get("deployment_id") or status.get("default_deployment") or "")
        deployment = next((x for x in deployments if x["id"] == deployment_id), None)
        if not deployment:
            if not deployment_id and any(x["billing_mode"] == "paid" for x in deployments):
                raise PermissionError("ai_paid_requires_explicit_selection")
            raise ValueError("ai_deployment_not_found")
        try:
            with self.store.connect() as con:
                policy_row = con.execute("SELECT enabled FROM ai_model_registry WHERE deployment_id=?", (deployment_id,)).fetchone()
            if policy_row and not policy_row["enabled"]:
                raise ValueError("ai_deployment_disabled")
        except Exception as exc:
            sqlstate = getattr(exc, "sqlstate", None)
            if not isinstance(exc, sqlite3.Error) and sqlstate != "42P01":
                raise
        if not deployment["model"] or not deployment["base_url"]:
            raise RuntimeError("ai_model_not_configured")
        parsed = urllib.parse.urlsplit(deployment["base_url"])
        host = (parsed.hostname or "").lower()
        local = host in {"127.0.0.1", "localhost", "::1"}
        allow = {x.strip().lower() for x in os.getenv("CF_AI_ALLOWED_HOSTS", "").split(",") if x.strip()}
        if not local and host not in allow:
            raise PermissionError("ai_endpoint_host_not_allowlisted")
        if not local and parsed.scheme != "https":
            raise PermissionError("remote_ai_requires_https")
        if deployment["billing_mode"] == "paid":
            if os.getenv("CF_AI_ALLOW_PAID", "0") != "1" or not os.getenv(deployment["api_key_env"]):
                raise PermissionError("paid_ai_not_enabled")
            if not deployment["input_price_per_1m"] and not deployment["output_price_per_1m"]:
                raise PermissionError("paid_ai_budget_not_configured")
            if deployment["daily_budget_usd"] <= 0 or deployment["max_request_usd"] <= 0:
                raise PermissionError("paid_ai_budget_not_configured")
        max_tokens = max(1, min(4096, int(body.get("max_tokens", 1024))))
        temperature = float(body.get("temperature", 0.2))
        if not 0 <= temperature <= 2:
            raise ValueError("invalid_temperature")
        in_price, out_price = deployment["input_price_per_1m"], deployment["output_price_per_1m"]
        estimated_input = max(1, total_chars // 4)
        estimate = (estimated_input * in_price + max_tokens * out_price) / 1_000_000
        if deployment["billing_mode"] == "paid" and estimate > deployment["max_request_usd"]:
            raise PermissionError("ai_request_budget_exceeded")
        reservation_id = self.store.reserve_ai_usage(
            actor, deployment_id, estimate if deployment["billing_mode"] == "paid" else 0.0,
            deployment["daily_budget_usd"] if deployment["billing_mode"] == "paid" else None)
        if not reservation_id:
            raise PermissionError("ai_daily_budget_exceeded")
        req_body = json.dumps({"model": deployment["model"], "messages": clean,
                               "max_tokens": max_tokens, "temperature": temperature,
                               "stream": False}).encode()
        req = urllib.request.Request(deployment["base_url"] + "/chat/completions", data=req_body,
                                     headers={"Content-Type": "application/json", "Accept": "application/json",
                                              **({"Authorization": "Bearer " + os.getenv(deployment["api_key_env"], "")} if os.getenv(deployment["api_key_env"]) else {})},
                                     method="POST")
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(req, timeout=90) as response:
                if response.status != 200:
                    raise RuntimeError("ai_provider_http_error")
                raw = response.read(2_000_000)
            obj = json.loads(raw.decode("utf-8"))
            answer = obj.get("choices", [{}])[0].get("message", {}).get("content", "")
            if not isinstance(answer, str) or len(answer) > 500_000:
                raise RuntimeError("ai_provider_invalid_response")
            usage = obj.get("usage") or {}
            in_tokens = _bounded_int(usage.get("prompt_tokens"), estimated_input)
            out_tokens = _bounded_int(usage.get("completion_tokens"), max(1, len(answer) // 4))
            cost = (in_tokens * in_price + out_tokens * out_price) / 1_000_000 if deployment["billing_mode"] == "paid" else 0.0
            self.store.finish_ai_usage(reservation_id, in_tokens, out_tokens, cost, "success")
            return {"deployment_id": deployment_id, "model": deployment["model"], "answer": answer,
                    "usage": {"input_tokens": in_tokens, "output_tokens": out_tokens,
                              "estimated_cost_usd": round(cost, 8), "billing_mode": deployment["billing_mode"]}}
        except urllib.error.HTTPError as exc:
            self.store.finish_ai_usage(reservation_id, 0, 0, 0.0, "http_error")
            raise RuntimeError("ai_provider_http_error") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.store.finish_ai_usage(reservation_id, 0, 0, 0.0, "connection_error")
            raise RuntimeError("ai_provider_unreachable") from exc
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            self.store.finish_ai_usage(reservation_id, 0, 0, 0.0, "invalid_response")
            raise RuntimeError("ai_provider_invalid_response") from exc
        except Exception:
            self.store.finish_ai_usage(reservation_id, 0, 0, 0.0, "failed")
            raise


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _env_float(name: str, default: float) -> float:
    try:
        v = float(os.getenv(name, str(default)))
        return v if 0 <= v < 1e9 else default
    except (TypeError, ValueError):
        return default


def _bounded_int(value: Any, default: int) -> int:
    try:
        return max(0, min(10_000_000, int(value)))
    except (TypeError, ValueError):
        return default


def runtime_inventory() -> list[dict[str, Any]]:
    specs = [
        ("ollama", "Ollama", ["ollama"], "http://127.0.0.1:11434"),
        ("vllm", "vLLM", ["vllm"], "OpenAI-compatible API"),
        ("llamacpp", "llama.cpp", ["llama-server"], "OpenAI-compatible API"),
        ("triton", "NVIDIA Triton", ["tritonserver"], "HTTP/gRPC inference endpoints"),
        ("litellm", "LiteLLM", ["litellm"], "OpenAI-compatible gateway"),
        ("ray", "Ray Serve", ["ray"], "Distributed serving"),
    ]
    return [{"id": i, "name": n, "installed": any(shutil.which(b) for b in bins), "bins": [b for b in bins if shutil.which(b)], "endpoint_hint": hint}
            for i, n, bins, hint in specs]


def run_workflow(store: Store, workflow_id: str, actor: str, data_dir: Path) -> dict[str, Any]:
    workflow = next((x for x in store.list_workflows() if x["workflow_id"] == workflow_id), None)
    if not workflow:
        raise KeyError("workflow_not_found")
    if workflow["status"] != "approved":
        raise ValueError("workflow_not_approved")
    owner = store.claim_workflow(workflow_id, actor)
    result: dict[str, Any] = {"workflow_id": workflow_id, "started_at": utc_now(), "steps": []}
    stop_heartbeat = threading.Event()
    lease_lost = threading.Event()

    def heartbeat():
        while not stop_heartbeat.wait(20):
            try:
                if not store.renew_workflow(workflow_id, owner):
                    lease_lost.set()
                    return
            except Exception:
                lease_lost.set()
                return

    renewal = threading.Thread(target=heartbeat, name="cf-workflow-lease", daemon=True)
    renewal.start()
    current_step = ""
    try:
        for step in workflow["steps"]:
            if lease_lost.is_set():
                raise RuntimeError("workflow_execution_lease_lost")
            current_step = step
            if step == "collect_fleet_health":
                data = {"host": host_inventory(data_dir), "nodes": store.list_nodes()}
            elif step == "check_ai_runtimes":
                data = runtime_inventory()
            elif step == "check_integrations":
                data = integrations.catalog_summary()
            elif step == "backup_database":
                target = data_dir / "backups"
                target.mkdir(parents=True, exist_ok=True)
                if getattr(store, "backend", "sqlite") == "postgres":
                    dest = target / f"server-{int(time.time())}-{uuid.uuid4().hex[:6]}.dump"
                    data = store.backup_database(dest)
                else:
                    dest = target / f"server-{int(time.time())}-{uuid.uuid4().hex[:6]}.sqlite3"
                    with store.lock, store.connect() as source:
                        backup = sqlite3.connect(dest)
                        try:
                            source.backup(backup)
                        finally:
                            backup.close()
                    try:
                        os.chmod(dest, 0o600)
                    except OSError:
                        pass
                    data = {"path": str(dest), "size_bytes": dest.stat().st_size, "sha256": hashlib.sha256(dest.read_bytes()).hexdigest()}
            elif step == "verify_audit_chain":
                data = store.verify_audit()
            else:
                raise ValueError("workflow_step_not_allowed")
            result["steps"].append({"id": step, "status": "completed", "result": data})
            if lease_lost.is_set():
                raise RuntimeError("workflow_execution_lease_lost")
        result["completed_at"] = utc_now()
        stop_heartbeat.set()
        renewal.join(timeout=1)
        store.finish_workflow(workflow_id, actor, result, owner=owner)
        return result
    except Exception as exc:
        result["failed_at"] = utc_now()
        result["failed_step"] = current_step or "claim"
        result["error_code"] = str(exc)[:80] if str(exc).isidentifier() else type(exc).__name__
        try:
            store.fail_workflow(workflow_id, actor, result, owner)
        except Exception:
            pass
        raise
    finally:
        stop_heartbeat.set()
        renewal.join(timeout=1)

