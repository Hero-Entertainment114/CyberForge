"""CyberForge AI Control Plane v2.1.0.

Persistent deployment policy/health registry, bounded asynchronous job queue,
cohort scheduling, and read-only GPU telemetry. Prompts and model outputs are
kept in process memory only; only job metadata is persisted.
"""
from __future__ import annotations

import csv
import io
import json
import os
import queue
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from distributed import EnvelopeCipher, RedisCoordinator


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))

def _env_float(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    if not (value == value and abs(value) != float("inf")):
        value = default
    return max(low, min(high, value))

def scheduler_config() -> dict[str, float | int]:
    return {
        "workers": _env_int("CF_AI_WORKERS", 4, 1, 32),
        "queue_limit": _env_int("CF_AI_QUEUE_LIMIT", 256, 8, 4096),
        "cohort_size": _env_int("CF_AI_COHORT_SIZE", 8, 1, 16),
        "cohort_wait_ms": _env_float("CF_AI_COHORT_WAIT_MS", 25, 0, 200),
        "job_retention_days": _env_int("CF_AI_JOB_RETENTION_DAYS", 7, 1, 90),
    }


def gpu_inventory() -> dict[str, Any]:
    """Read-only, fixed-command GPU inventory with strict time/output bounds."""
    result: dict[str, Any] = {"available": False, "vendors": [], "devices": [], "collected_at": _utc()}
    nvidia = shutil.which("nvidia-smi")
    if nvidia:
        cmd = [nvidia, "--query-gpu=index,name,uuid,utilization.gpu,memory.total,memory.used,temperature.gpu,power.draw",
               "--format=csv,noheader,nounits"]
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False, env={**os.environ, "LC_ALL": "C"})
            if cp.returncode == 0 and len(cp.stdout) <= 64_000:
                for row in csv.reader(io.StringIO(cp.stdout)):
                    if len(row) != 8:
                        continue
                    idx, name, uid, util, mem_total, mem_used, temp, power = [x.strip() for x in row]
                    def number(s):
                        try: return float(s) if s not in {"", "[Not Supported]", "N/A"} else None
                        except ValueError: return None
                    result["devices"].append({"vendor": "NVIDIA", "index": idx, "name": name[:120], "uuid": uid[:80],
                        "utilization_percent": number(util), "memory_total_mib": number(mem_total),
                        "memory_used_mib": number(mem_used), "temperature_c": number(temp), "power_w": number(power)})
                if result["devices"]:
                    result["vendors"].append("NVIDIA")
        except (OSError, subprocess.TimeoutExpired):
            pass
    rocm = shutil.which("rocm-smi")
    if rocm:
        try:
            cp = subprocess.run([rocm, "--json"], capture_output=True, text=True, timeout=3, check=False,
                                env={**os.environ, "LC_ALL": "C"})
            if cp.returncode == 0 and len(cp.stdout) <= 128_000:
                obj = json.loads(cp.stdout)
                devices = obj if isinstance(obj, dict) else {}
                for key, item in devices.items():
                    if isinstance(item, dict):
                        result["devices"].append({"vendor": "AMD", "index": str(key)[:32],
                            "name": str(item.get("Card series", item.get("Product Name", "AMD GPU")))[:120],
                            "metrics_raw": {str(k)[:80]: str(v)[:80] for k, v in list(item.items())[:24]}})
                if result["devices"] and "AMD" not in result["vendors"]:
                    result["vendors"].append("AMD")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    xpu = shutil.which("xpu-smi")
    if xpu:
        try:
            cp = subprocess.run([xpu, "discovery", "-j"], capture_output=True, text=True, timeout=3, check=False,
                                env={**os.environ, "LC_ALL": "C"})
            if cp.returncode == 0 and len(cp.stdout) <= 128_000:
                obj = json.loads(cp.stdout)
                result["devices"].append({"vendor": "Intel", "name": "Intel XPU", "inventory": obj})
                result["vendors"].append("Intel")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    result["available"] = bool(result["devices"])
    result["device_count"] = len(result["devices"])
    return result


class AdjustableSemaphore:
    """Semaphore whose capacity can be adjusted without replacing active permits."""
    def __init__(self, capacity: int):
        self.capacity = max(1, min(32, int(capacity)))
        self.active = 0
        self.condition = threading.Condition()

    def acquire(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self.condition:
            while self.active >= self.capacity:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return False
                self.condition.wait(remaining)
            self.active += 1
            return True

    def release(self):
        with self.condition:
            if self.active > 0:
                self.active -= 1
            self.condition.notify_all()

    def resize(self, capacity: int):
        with self.condition:
            self.capacity = max(1, min(32, int(capacity)))
            self.condition.notify_all()


class AIControlPlane:
    def __init__(self, store, ai_service):
        self.store = store
        self.ai = ai_service
        config = scheduler_config()
        self.max_workers = int(config["workers"])
        self.queue_limit = int(config["queue_limit"])
        self.batch_size = int(config["cohort_size"])
        self.batch_wait = float(config["cohort_wait_ms"]) / 1000
        self.distributed = getattr(store, "backend", "sqlite") == "postgres"
        self.instance_id = os.getenv("CF_INSTANCE_ID", "")[:80] or (platform_node_id() + "-" + uuid.uuid4().hex[:8])
        self.coordinator = RedisCoordinator() if self.distributed else None
        self.cipher = EnvelopeCipher() if self.distributed else None
        self.queue: queue.PriorityQueue[tuple[int, float, str]] | None = None if self.distributed else queue.PriorityQueue(maxsize=self.queue_limit)
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="cf-ai-job")
        # ThreadPoolExecutor has an unbounded internal work queue. Reserve a slot
        # before submit() so the dispatcher cannot drain the bounded PriorityQueue
        # into an effectively unbounded second queue.
        self.dispatch_slots = threading.BoundedSemaphore(self.max_workers)
        self.inflight_jobs = 0
        self.lock = threading.RLock()
        self.pending: dict[str, tuple[str, dict[str, Any], int]] = {}
        self.results: dict[str, dict[str, Any]] = {}
        self.result_order: list[str] = []
        self.model_locks: dict[str, AdjustableSemaphore] = {}
        self.stopping = threading.Event()
        self.cohorts_dispatched = 0
        self.jobs_dispatched = 0
        self._init_db()
        self.sync_models()
        loop = self._distributed_dispatch_loop if self.distributed else self._dispatch_loop
        self.dispatcher = threading.Thread(target=loop, name="cf-ai-dispatcher", daemon=True)
        self.dispatcher.start()

    def _init_db(self):
        with self.store.lock, self.store.connect() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS ai_model_registry(
              deployment_id TEXT PRIMARY KEY, model TEXT NOT NULL, endpoint_host TEXT NOT NULL,
              billing_mode TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
              priority INTEGER NOT NULL DEFAULT 50, max_concurrency INTEGER NOT NULL DEFAULT 2,
              is_default INTEGER NOT NULL DEFAULT 0, health_state TEXT NOT NULL DEFAULT 'unknown',
              health_checked_at TEXT, health_latency_ms REAL, health_detail TEXT NOT NULL DEFAULT '',
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_jobs(
              job_id TEXT PRIMARY KEY, actor TEXT NOT NULL, actor_id TEXT NOT NULL DEFAULT '', deployment_id TEXT NOT NULL,
              priority INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
              started_at TEXT, finished_at TEXT, error_code TEXT NOT NULL DEFAULT '',
              result_available INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_ai_jobs_created ON ai_jobs(created_at);
            CREATE INDEX IF NOT EXISTS idx_ai_jobs_status ON ai_jobs(status,priority,created_at);
            """)
            if self.distributed:
                for ddl in (
                    "ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS payload_ciphertext BYTEA",
                    "ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS result_ciphertext BYTEA",
                    "ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS lease_owner TEXT",
                    "ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS lease_until BIGINT NOT NULL DEFAULT 0",
                    "ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0",
                    "ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS actor_id TEXT NOT NULL DEFAULT ''",
                ):
                    con.execute(ddl)
                con.executescript("""
                    CREATE TABLE IF NOT EXISTS ai_model_slots(
                      deployment_id TEXT NOT NULL, slot_no INTEGER NOT NULL,
                      lease_owner TEXT, lease_until BIGINT NOT NULL DEFAULT 0,
                      PRIMARY KEY(deployment_id,slot_no));
                    CREATE INDEX IF NOT EXISTS idx_ai_jobs_lease ON ai_jobs(status,lease_until,priority,created_at);
                    """)
                # Paid jobs with an expired worker lease are never replayed automatically:
                # the provider may already have billed the request before worker loss.
                con.execute("""UPDATE ai_jobs j SET status='interrupted',finished_at=?,
                    error_code='paid_job_interrupted_no_retry',lease_owner=NULL,lease_until=0
                    FROM ai_model_registry m WHERE j.deployment_id=m.deployment_id
                    AND j.status='running' AND j.lease_until<? AND m.billing_mode='paid'""", (_utc(), int(time.time())))
            else:
                columns = {r["name"] for r in con.execute("PRAGMA table_info(ai_jobs)").fetchall()}
                if "actor_id" not in columns:
                    con.execute("ALTER TABLE ai_jobs ADD COLUMN actor_id TEXT NOT NULL DEFAULT ''")
                con.execute("UPDATE ai_jobs SET status='interrupted',finished_at=?,error_code='server_restarted' WHERE status IN ('queued','running')", (_utc(),))
            retention_days = int(scheduler_config()["job_retention_days"])
            from datetime import timedelta
            cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(timespec="seconds")
            con.execute("DELETE FROM ai_jobs WHERE created_at<? AND status IN ('succeeded','failed','rejected','cancelled','interrupted')", (cutoff,))

    def sync_models(self):
        configured = self.ai.deployments()
        with self.store.lock, self.store.connect() as con:
            existing = {r["deployment_id"] for r in con.execute("SELECT deployment_id FROM ai_model_registry").fetchall()}
            for spec in configured:
                host = (urllib.parse.urlsplit(spec["base_url"]).hostname or "").lower()
                con.execute("""INSERT INTO ai_model_registry(deployment_id,model,endpoint_host,billing_mode,updated_at)
                    VALUES(?,?,?,?,?) ON CONFLICT(deployment_id) DO UPDATE SET
                    model=excluded.model,endpoint_host=excluded.endpoint_host,billing_mode=excluded.billing_mode,updated_at=excluded.updated_at
                    WHERE ai_model_registry.model!=excluded.model OR ai_model_registry.endpoint_host!=excluded.endpoint_host OR ai_model_registry.billing_mode!=excluded.billing_mode""",
                    (spec["id"], spec["model"], host, spec["billing_mode"], _utc()))
                cap_row = con.execute("SELECT max_concurrency FROM ai_model_registry WHERE deployment_id=?", (spec["id"],)).fetchone()
                if spec["id"] not in self.model_locks:
                    self.model_locks[spec["id"]] = AdjustableSemaphore(cap_row["max_concurrency"] if cap_row else 2)
            for did in existing - {x["id"] for x in configured}:
                con.execute("UPDATE ai_model_registry SET enabled=0,health_state='removed',updated_at=? WHERE deployment_id=?", (_utc(), did))
            if configured and not con.execute("SELECT 1 FROM ai_model_registry WHERE is_default=1 AND enabled=1").fetchone():
                first = next((x for x in configured if x["billing_mode"] in {"local", "free"}), None)
                if first:
                    con.execute("UPDATE ai_model_registry SET is_default=CASE WHEN deployment_id=? THEN 1 ELSE 0 END", (first["id"],))

    def _configured(self) -> dict[str, dict[str, Any]]:
        return {x["id"]: x for x in self.ai.deployments()}

    def models(self) -> list[dict[str, Any]]:
        self.sync_models()
        with self.store.lock, self.store.connect() as con:
            rows = con.execute("SELECT * FROM ai_model_registry ORDER BY is_default DESC,priority ASC,deployment_id").fetchall()
        cfg = self._configured()
        out = []
        for row in rows:
            item = dict(row)
            spec = cfg.get(item["deployment_id"])
            item["configured"] = bool(spec and spec.get("model") and spec.get("base_url"))
            item["api_key_configured"] = bool(spec and spec.get("api_key_configured"))
            item.pop("updated_at", None)
            out.append(item)
        return out

    def set_policy(self, deployment_id: str, body: dict[str, Any], actor: str) -> dict[str, Any]:
        enabled = body.get("enabled")
        priority = body.get("priority")
        max_concurrency = body.get("max_concurrency")
        is_default = body.get("is_default")
        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError("invalid_model_policy")
        if priority is not None and (isinstance(priority, bool) or not isinstance(priority, int) or not -100 <= priority <= 100):
            raise ValueError("invalid_model_policy")
        if max_concurrency is not None and (isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int) or not 1 <= max_concurrency <= 32):
            raise ValueError("invalid_model_policy")
        if is_default is not None and not isinstance(is_default, bool):
            raise ValueError("invalid_model_policy")
        with self.store.lock, self.store.connect() as con:
            row = con.execute("SELECT billing_mode,enabled FROM ai_model_registry WHERE deployment_id=?", (deployment_id,)).fetchone()
            if not row:
                raise KeyError("ai_deployment_not_found")
            if is_default and row["billing_mode"] == "paid":
                raise ValueError("paid_model_cannot_be_default")
            if is_default and (enabled is False or not row["enabled"]):
                raise ValueError("disabled_model_cannot_be_default")
            if is_default:
                con.execute("UPDATE ai_model_registry SET is_default=0")
            con.execute("UPDATE ai_model_registry SET enabled=COALESCE(?,enabled),priority=COALESCE(?,priority),max_concurrency=COALESCE(?,max_concurrency),is_default=COALESCE(?,is_default),updated_at=? WHERE deployment_id=?",
                        (None if enabled is None else int(enabled), priority, max_concurrency,
                         None if is_default is None else int(is_default), _utc(), deployment_id))
            self.store.audit(con, actor, "ai.model_policy_updated", deployment_id,
                             {"enabled": enabled, "priority": priority, "max_concurrency": max_concurrency, "is_default": is_default})
        # Refresh semaphore for future work; existing workers retain their acquired lock.
        if max_concurrency is not None:
            self.model_locks.setdefault(deployment_id, AdjustableSemaphore(max_concurrency)).resize(max_concurrency)
        return next(x for x in self.models() if x["deployment_id"] == deployment_id)

    def route(self, requested: str | None = None, strategy: str = "auto") -> tuple[str, dict[str, Any]]:
        if strategy not in {"auto", "pinned"}:
            raise ValueError("invalid_route_strategy")
        configs = self._configured()
        rows = self.models()
        byid = {x["deployment_id"]: x for x in rows}
        if requested:
            if requested not in configs or requested not in byid:
                raise ValueError("ai_deployment_not_found")
            selected = byid[requested]
            if not selected["enabled"]:
                raise ValueError("ai_deployment_disabled")
            if strategy == "pinned":
                return requested, {"reason": "pinned", "failover": False}
            if selected["billing_mode"] == "paid":
                return requested, {"reason": "explicit_paid_selection", "failover": False}
            if selected["health_state"] != "unhealthy":
                return requested, {"reason": "requested_preferred", "failover": False}
            pool = [x for x in rows if x["enabled"] and x["billing_mode"] == selected["billing_mode"] and x["deployment_id"] != requested and x["health_state"] != "unhealthy" and x["configured"]]
        else:
            pool = [x for x in rows if x["enabled"] and x["billing_mode"] in {"local", "free"} and x["configured"] and x["health_state"] != "unhealthy"]
        if not requested:
            default = next((x for x in pool if x["is_default"]), None)
            if default:
                return default["deployment_id"], {"reason": "default_healthy_or_unknown", "failover": False}
        if not pool:
            if not requested and any(x["enabled"] and x["billing_mode"] == "paid" and x["configured"] for x in rows):
                raise RuntimeError("ai_paid_requires_explicit_selection")
            raise RuntimeError("ai_no_healthy_deployment")
        chosen = sorted(pool, key=lambda x: (0 if x["health_state"] == "healthy" else 1, x["priority"], x["deployment_id"]))[0]
        return chosen["deployment_id"], {"reason": "health_aware_failover" if requested else "priority_routing", "failover": bool(requested)}

    def health_check(self, deployment_id: str) -> dict[str, Any]:
        specs = self._configured()
        spec = specs.get(deployment_id)
        if not spec:
            raise KeyError("ai_deployment_not_found")
        if not spec["base_url"]:
            raise RuntimeError("ai_model_not_configured")
        parsed = urllib.parse.urlsplit(spec["base_url"])
        host = (parsed.hostname or "").lower()
        local = host in {"127.0.0.1", "localhost", "::1"}
        allow = {x.strip().lower() for x in os.getenv("CF_AI_ALLOWED_HOSTS", "").split(",") if x.strip()}
        if not local and (host not in allow or parsed.scheme != "https"):
            raise PermissionError("ai_endpoint_host_not_allowlisted" if host not in allow else "remote_ai_requires_https")
        path = parsed.path.rstrip("/") + "/models"
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        headers = {"Accept": "application/json"}
        key = os.getenv(spec["api_key_env"], "")
        if key:
            headers["Authorization"] = "Bearer " + key
        req = urllib.request.Request(url, headers=headers, method="GET")
        started = time.monotonic()
        healthy, detail = False, "unreachable"
        status = None
        try:
            with urllib.request.build_opener(NoRedirect()).open(req, timeout=3) as response:
                status = response.status
                raw = response.read(1_000_000)
                obj = json.loads(raw.decode("utf-8")) if raw else {}
                healthy = status == 200 and isinstance(obj, (dict, list))
                detail = "ok" if healthy else "unexpected_response"
        except urllib.error.HTTPError as exc:
            status, detail = exc.code, "http_error"
        except urllib.error.URLError:
            detail = "unreachable"
        except (OSError, TimeoutError):
            detail = "unreachable"
        except (json.JSONDecodeError, UnicodeDecodeError):
            detail = "invalid_json"
        latency = round((time.monotonic() - started) * 1000, 2)
        state = "healthy" if healthy else "unhealthy"
        with self.store.lock, self.store.connect() as con:
            con.execute("UPDATE ai_model_registry SET health_state=?,health_checked_at=?,health_latency_ms=?,health_detail=? WHERE deployment_id=?",
                        (state, _utc(), latency, detail, deployment_id))
            self.store.audit(con, "system", "ai.model_health_checked", deployment_id,
                             {"health_state": state, "http_status": status, "latency_ms": latency})
        return {"deployment_id": deployment_id, "health_state": state, "http_status": status,
                "latency_ms": latency, "detail": detail}

    def check_all(self) -> list[dict[str, Any]]:
        return [self.health_check(x["deployment_id"]) for x in self.models() if x["enabled"] and x["configured"]]

    def submit(self, actor: str, body: dict[str, Any], actor_id: str | None = None) -> dict[str, Any]:
        if self.distributed:
            return self._submit_distributed(actor, body, actor_id)
        requested = str(body.get("deployment_id", "")).strip() or None
        deployment_id, route = self.route(requested, str(body.get("route_strategy", "auto")))
        payload = dict(body)
        payload.pop("route_strategy", None)
        payload["deployment_id"] = deployment_id
        priority = body.get("priority", "normal")
        priority_map = {"high": 0, "normal": 5, "low": 9}
        if priority not in priority_map:
            raise ValueError("invalid_job_priority")
        job_id = "aij_" + uuid.uuid4().hex[:20]
        created = _utc()
        with self.store.lock, self.store.connect() as con:
            con.execute("INSERT INTO ai_jobs(job_id,actor,actor_id,deployment_id,priority,status,created_at) VALUES(?,?,?,?,?,?,?)",
                        (job_id, actor[:80], (actor_id or actor)[:80], deployment_id, priority_map[priority], "queued", created))
        with self.lock:
            self.pending[job_id] = (actor, payload, priority_map[priority])
        try:
            self.queue.put_nowait((priority_map[priority], time.monotonic(), job_id))
        except queue.Full:
            with self.lock:
                self.pending.pop(job_id, None)
            with self.store.lock, self.store.connect() as con:
                con.execute("UPDATE ai_jobs SET status='rejected',finished_at=?,error_code='ai_queue_full' WHERE job_id=?", (_utc(), job_id))
            raise OverflowError("ai_queue_full")
        return {"job_id": job_id, "status": "queued", "deployment_id": deployment_id,
                "route": route, "queue_position": self.queue.qsize(), "created_at": created}

    def _submit_distributed(self, actor: str, body: dict[str, Any], actor_id: str | None) -> dict[str, Any]:
        requested = str(body.get("deployment_id", "")).strip() or None
        deployment_id, route = self.route(requested, str(body.get("route_strategy", "auto")))
        payload = dict(body)
        payload.pop("route_strategy", None)
        payload["deployment_id"] = deployment_id
        priority = body.get("priority", "normal")
        priority_map = {"high": 0, "normal": 5, "low": 9}
        if priority not in priority_map:
            raise ValueError("invalid_job_priority")
        job_id, created = "aij_" + uuid.uuid4().hex[:20], _utc()
        sealed = self.cipher.seal(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                                  ("payload:" + job_id).encode())
        with self.store.lock, self.store.connect() as con:
            con.execute("SELECT pg_advisory_xact_lock(hashtext(?))", ("cyberforge:ai-queue-capacity",))
            counts = con.execute("SELECT COUNT(*) n FROM ai_jobs WHERE status IN ('queued','running')").fetchone()
            if int(counts["n"] or 0) >= self.queue_limit:
                raise OverflowError("ai_queue_full")
            con.execute("""INSERT INTO ai_jobs(job_id,actor,actor_id,deployment_id,priority,status,created_at,
                payload_ciphertext,lease_until,attempts) VALUES(?,?,?,?,?,?,?,?,0,0)""",
                (job_id, actor[:80], (actor_id or actor)[:80], deployment_id, priority_map[priority], "queued", created, sealed))
            ahead = con.execute("SELECT COUNT(*) n FROM ai_jobs WHERE status='queued' AND (priority<? OR (priority=? AND created_at<=?))",
                                 (priority_map[priority], priority_map[priority], created)).fetchone()["n"]
        if self.coordinator:
            self.coordinator.publish("ai:jobs:ready", job_id)
        return {"job_id": job_id, "status": "queued", "deployment_id": deployment_id,
                "route": route, "queue_position": int(ahead), "created_at": created, "distributed": True}

    def _claim_distributed(self) -> dict[str, Any] | None:
        """Claim one job and one shared model slot in a single PostgreSQL transaction."""
        now = int(time.time())
        lease_secs = max(120, min(900, _env_int("CF_AI_DISTRIBUTED_LEASE_SECONDS", 240, 120, 900)))
        with self.store.connect() as con:
            row = con.execute("""SELECT j.job_id,j.deployment_id,j.attempts,m.billing_mode,m.max_concurrency
                FROM ai_jobs j JOIN ai_model_registry m ON m.deployment_id=j.deployment_id
                WHERE (j.status='queued' OR (j.status='running' AND j.lease_until<? AND m.billing_mode!='paid' AND j.attempts<2))
                AND (SELECT COUNT(*) FROM ai_model_slots s WHERE s.deployment_id=m.deployment_id
                     AND s.lease_owner IS NOT NULL AND s.lease_until>=?) < m.max_concurrency
                ORDER BY j.priority ASC,j.created_at ASC LIMIT 1 FOR UPDATE OF j SKIP LOCKED""", (now, now)).fetchone()
            if not row:
                return None
            deployment_id = row["deployment_id"]
            lease_owner = self.instance_id + ":" + uuid.uuid4().hex[:12]
            cap = max(1, min(32, int(row["max_concurrency"] or 1)))
            for slot_no in range(cap):
                con.execute("INSERT INTO ai_model_slots(deployment_id,slot_no,lease_until) VALUES(?,?,0) ON CONFLICT(deployment_id,slot_no) DO NOTHING",
                            (deployment_id, slot_no))
            slot = con.execute("""SELECT slot_no FROM ai_model_slots WHERE deployment_id=?
                AND (lease_owner IS NULL OR lease_until<?) ORDER BY slot_no LIMIT 1 FOR UPDATE SKIP LOCKED""",
                (deployment_id, now)).fetchone()
            if not slot:
                return None
            con.execute("UPDATE ai_model_slots SET lease_owner=?,lease_until=? WHERE deployment_id=? AND slot_no=?",
                        (lease_owner, now + lease_secs, deployment_id, slot["slot_no"]))
            attempts = int(row["attempts"] or 0) + 1
            con.execute("""UPDATE ai_jobs SET status='running',started_at=?,lease_owner=?,lease_until=?,attempts=?,error_code=''
                WHERE job_id=?""", (_utc(), lease_owner, now + lease_secs, attempts, row["job_id"]))
            return {"job_id": row["job_id"], "deployment_id": deployment_id,
                    "slot_no": int(slot["slot_no"]), "lease_owner": lease_owner}

    def _expire_distributed_leases(self, now: int | None = None) -> dict[str, int]:
        """Finalize expired paid jobs and exhausted local/free retries."""
        now = int(time.time()) if now is None else int(now)
        finished_at = _utc()
        with self.store.connect() as con:
            paid = con.execute("""UPDATE ai_jobs j SET status='interrupted',finished_at=?,
                error_code='paid_job_interrupted_no_retry',lease_owner=NULL,lease_until=0
                FROM ai_model_registry m WHERE j.deployment_id=m.deployment_id
                AND j.status='running' AND j.lease_until<? AND m.billing_mode='paid'""",
                (finished_at, now)).rowcount
            exhausted = con.execute("""UPDATE ai_jobs j SET status='interrupted',finished_at=?,
                error_code='ai_job_retry_exhausted',lease_owner=NULL,lease_until=0
                FROM ai_model_registry m WHERE j.deployment_id=m.deployment_id
                AND j.status='running' AND j.lease_until<? AND m.billing_mode!='paid' AND j.attempts>=2""",
                (finished_at, now)).rowcount
        return {"paid_interrupted": max(0, int(paid)), "retry_exhausted": max(0, int(exhausted))}

    def _distributed_dispatch_loop(self):
        poll = max(0.1, min(5.0, _env_int("CF_DISTRIBUTED_POLL_MS", 500, 100, 5000) / 1000))
        last_heartbeat = 0.0
        while not self.stopping.is_set():
            if self.coordinator and time.monotonic() - last_heartbeat >= 5.0:
                self.coordinator.heartbeat(self.instance_id, self.max_workers)
                last_heartbeat = time.monotonic()
            try:
                self._expire_distributed_leases()
            except Exception:
                pass
            if not self.dispatch_slots.acquire(timeout=poll):
                continue
            try:
                claimed = self._claim_distributed()
            except Exception:
                claimed = None
                time.sleep(poll)
            if not claimed:
                self.dispatch_slots.release()
                self.stopping.wait(poll)
                continue
            with self.lock:
                self.inflight_jobs += 1
            try:
                self.executor.submit(self._run_distributed_job, claimed)
            except RuntimeError:
                with self.lock:
                    self.inflight_jobs = max(0, self.inflight_jobs - 1)
                self._release_distributed_slot(claimed)
                with self.store.connect() as con:
                    con.execute("UPDATE ai_jobs SET status='queued',lease_owner=NULL,lease_until=0 WHERE job_id=? AND lease_owner=?",
                                (claimed["job_id"], claimed["lease_owner"]))
                self.dispatch_slots.release()

    def _release_distributed_slot(self, claimed: dict[str, Any]):
        try:
            with self.store.connect() as con:
                con.execute("UPDATE ai_model_slots SET lease_owner=NULL,lease_until=0 WHERE deployment_id=? AND slot_no=? AND lease_owner=?",
                            (claimed["deployment_id"], claimed["slot_no"], claimed["lease_owner"]))
        except Exception:
            pass

    def _run_distributed_job(self, claimed: dict[str, Any]):
        job_id = claimed["job_id"]
        try:
            with self.store.connect() as con:
                row = con.execute("SELECT actor,payload_ciphertext FROM ai_jobs WHERE job_id=? AND lease_owner=?",
                                  (job_id, claimed["lease_owner"])).fetchone()
            if not row or row["payload_ciphertext"] is None:
                self._finish_distributed(job_id, claimed["lease_owner"], "failed", "invalid_encrypted_job", None)
                return
            try:
                raw = self.cipher.open(row["payload_ciphertext"], ("payload:" + job_id).encode())
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict): raise ValueError("invalid_encrypted_job")
            except Exception:
                self._finish_distributed(job_id, claimed["lease_owner"], "failed", "invalid_encrypted_job", None)
                return
            actor = row["actor"]
            try:
                result = self.ai.chat(actor, payload)
                self._finish_distributed(job_id, claimed["lease_owner"], "succeeded", "", result)
            except Exception as exc:
                code = str(exc).strip("'\"") or "internal_error"
                safe = code if code.startswith(("ai_", "paid_ai", "remote_ai", "invalid_", "prompt_")) else "ai_job_failed"
                self._finish_distributed(job_id, claimed["lease_owner"], "failed", safe[:80], None)
        finally:
            self._release_distributed_slot(claimed)
            with self.lock:
                self.inflight_jobs = max(0, self.inflight_jobs - 1)
            self.dispatch_slots.release()

    def _finish_distributed(self, job_id: str, lease_owner: str, status: str, error_code: str, result: dict[str, Any] | None):
        sealed = self.cipher.seal(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                                  ("result:" + job_id).encode()) if result is not None else None
        with self.store.connect() as con:
            cur = con.execute("""UPDATE ai_jobs SET status=?,finished_at=?,error_code=?,result_available=?,
                result_ciphertext=?,payload_ciphertext=NULL,lease_owner=NULL,lease_until=0 WHERE job_id=? AND lease_owner=?""",
                (status, _utc(), error_code, int(sealed is not None), sealed, job_id, lease_owner))
            completed = cur.rowcount == 1
        if completed and self.coordinator:
            self.coordinator.publish("ai:jobs:completed", job_id)

    def _dispatch_loop(self):
        while not self.stopping.is_set():
            try:
                first = self.queue.get(timeout=0.25)
            except queue.Empty:
                continue
            batch = [first]
            deadline = time.monotonic() + self.batch_wait
            while len(batch) < self.batch_size and time.monotonic() < deadline:
                try:
                    batch.append(self.queue.get(timeout=max(0.001, deadline - time.monotonic())))
                except queue.Empty:
                    break
            # Scheduling cohort groups jobs by deployment to maximise provider-side continuous batching.
            # The gateway/model server performs actual tensor batching; this layer never invents a batch API.
            grouped: dict[str, list[str]] = {}
            for _priority, _submitted, job_id in batch:
                with self.lock:
                    item = self.pending.get(job_id)
                if item:
                    deployment_id = str(item[1].get("deployment_id", ""))
                    grouped.setdefault(deployment_id, []).append(job_id)
            with self.lock:
                self.cohorts_dispatched += 1
                self.jobs_dispatched += len(batch)
            for deployment_id, ids in grouped.items():
                for job_id in ids:
                    # Backpressure here keeps pending work in the bounded priority
                    # queue instead of accumulating in ThreadPoolExecutor's queue.
                    slot_acquired = False
                    while not self.stopping.is_set():
                        slot_acquired = self.dispatch_slots.acquire(timeout=0.25)
                        if slot_acquired:
                            break
                    if not slot_acquired:
                        with self.lock:
                            self.pending.pop(job_id, None)
                        self._finish(job_id, "cancelled", "ai_scheduler_stopped", None)
                        continue
                    with self.lock:
                        self.inflight_jobs += 1
                    try:
                        self.executor.submit(self._run_job, job_id, deployment_id)
                    except RuntimeError:
                        with self.lock:
                            self.inflight_jobs = max(0, self.inflight_jobs - 1)
                        self.dispatch_slots.release()
                        with self.lock:
                            self.pending.pop(job_id, None)
                        self._finish(job_id, "failed", "ai_scheduler_stopped", None)
            for _ in batch:
                self.queue.task_done()

    def _run_job(self, job_id: str, deployment_id: str):
        try:
            with self.lock:
                item = self.pending.pop(job_id, None)
            if not item:
                return
            actor, payload, _priority = item
            semaphore = self.model_locks.setdefault(deployment_id, AdjustableSemaphore(2))
            acquired = semaphore.acquire(timeout=90)
            if not acquired:
                self._finish(job_id, "failed", "ai_model_concurrency_timeout", None)
                return
            try:
                with self.store.lock, self.store.connect() as con:
                    con.execute("UPDATE ai_jobs SET status='running',started_at=? WHERE job_id=? AND status='queued'", (_utc(), job_id))
                try:
                    result = self.ai.chat(actor, payload)
                    self._finish(job_id, "succeeded", "", result)
                except Exception as exc:
                    code = str(exc).strip("'\"") or "internal_error"
                    safe = code if code.startswith(("ai_", "paid_ai", "remote_ai", "invalid_", "prompt_")) else "ai_job_failed"
                    self._finish(job_id, "failed", safe[:80], None)
            finally:
                semaphore.release()
        finally:
            with self.lock:
                self.inflight_jobs = max(0, self.inflight_jobs - 1)
            self.dispatch_slots.release()

    def _finish(self, job_id: str, status: str, error_code: str, result: dict[str, Any] | None):
        with self.store.lock, self.store.connect() as con:
            con.execute("UPDATE ai_jobs SET status=?,finished_at=?,error_code=?,result_available=? WHERE job_id=?",
                        (status, _utc(), error_code, int(result is not None), job_id))
        if result is not None:
            with self.lock:
                self.results[job_id] = result
                self.result_order.append(job_id)
                while len(self.result_order) > 256:
                    old = self.result_order.pop(0)
                    self.results.pop(old, None)

    def get_job(self, job_id: str, actor: dict[str, Any]) -> dict[str, Any]:
        with self.store.lock, self.store.connect() as con:
            row = con.execute("SELECT * FROM ai_jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            raise KeyError("ai_job_not_found")
        identity = str(actor.get("id") or actor.get("name") or "")
        owner = row["actor_id"] or row["actor"]
        if owner != identity and actor.get("role") != "admin":
            raise PermissionError("forbidden")
        out = dict(row)
        if self.distributed:
            result = None
            ciphertext = out.get("result_ciphertext")
            if ciphertext:
                try:
                    raw = self.cipher.open(ciphertext, ("result:" + job_id).encode())
                    result = json.loads(raw.decode("utf-8"))
                except Exception:
                    out["error_code"] = "distributed_job_decryption_failed"
            out.pop("payload_ciphertext", None)
            out.pop("result_ciphertext", None)
            out.pop("lease_owner", None)
            out.pop("lease_until", None)
            out.pop("attempts", None)
        else:
            with self.lock:
                result = self.results.get(job_id)
        if result is not None:
            out["result"] = result
            out["result_available"] = True
        else:
            out["result"] = None
            if out["status"] == "succeeded":
                out["result_available"] = False
        return out

    def queue_status(self) -> dict[str, Any]:
        with self.store.lock, self.store.connect() as con:
            counts = {r["status"]: r["n"] for r in con.execute("SELECT status,COUNT(*) n FROM ai_jobs WHERE created_at>=? GROUP BY status",
                      (datetime_window_start(),)).fetchall()}
            models = con.execute("SELECT COUNT(*) n FROM ai_model_registry WHERE enabled=1").fetchone()["n"]
        with self.lock:
            cohorts, dispatched = self.cohorts_dispatched, self.jobs_dispatched
        queued = int(counts.get("queued", 0)) if self.distributed else self.queue.qsize()
        with self.lock:
            inflight = int(counts.get("running", 0)) if self.distributed else self.inflight_jobs
        return {"backend": "postgresql_shared" if self.distributed else "process_local",
                "distributed": self.distributed, "queued": queued, "inflight": inflight, "queue_limit": self.queue_limit,
                "queue_utilization_percent": round(queued * 100 / self.queue_limit, 1), "workers": self.max_workers,
                "counts_24h": counts, "enabled_models": models, "cohorts_dispatched": cohorts,
                "jobs_dispatched": dispatched, "batch_size_limit": self.batch_size,
                "batch_wait_ms": round(self.batch_wait * 1000, 1),
                "batching_note": "Scheduling cohorts only. Actual continuous/tensor batching is handled by the configured inference server."}

    def cluster_status(self) -> dict[str, Any]:
        if not self.distributed:
            return {"mode": "single_node", "database": "sqlite", "redis": {"configured": False, "available": False},
                    "instance_id": self.instance_id, "active_instances": [self.instance_id],
                    "note": "Use PostgreSQL storage to enable shared multi-instance state and durable AI jobs."}
        redis_status = self.coordinator.status() if self.coordinator else {"configured": False, "available": False}
        active = self.coordinator.instances() if self.coordinator else []
        if self.instance_id not in active:
            active.append(self.instance_id)
        return {"mode": "distributed", "database": "postgresql", "redis": redis_status,
                "instance_id": self.instance_id, "active_instances": sorted(set(active))[:128],
                "scheduler": "postgresql_skip_locked", "queue_durability": "encrypted_database_payloads",
                "redis_role": "best_effort_notifications_and_heartbeats"}

    def close(self):
        self.stopping.set()
        self.dispatcher.join(timeout=2)
        self.executor.shutdown(wait=False, cancel_futures=True)


def datetime_window_start() -> str:
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")


def platform_node_id() -> str:
    import platform
    import socket
    return (socket.gethostname().split(".")[0] or platform.system() or "node")[:48]
