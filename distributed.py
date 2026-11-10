"""Optional PostgreSQL/Redis distributed infrastructure for CyberForge Server Edition.

PostgreSQL is the source of truth. Redis is an optional notification/lease adjunct;
losing Redis never loses jobs or metadata. All payload/result blobs are AES-GCM
sealed before they are written to PostgreSQL.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from server_core import Store


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return True
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_QMARK = re.compile(r"\?")


class PostgresConnection:
    """Small DB-API adapter allowing the existing Store SQL to run on psycopg 3."""
    def __init__(self, raw):
        self.raw = raw

    def execute(self, sql: str, params=()):
        sql = sql.replace("COLLATE NOCASE", "")
        sql = _QMARK.sub("%s", sql)
        # SQLite's BEGIN IMMEDIATE has no direct PostgreSQL equivalent. Callers
        # that need cross-process serialization use explicit advisory locks.
        if sql.strip().upper() == "BEGIN IMMEDIATE":
            sql = "BEGIN"
        return self.raw.execute(sql, tuple(params or ()))

    def executescript(self, script: str):
        # Schema scripts in this project contain DDL only; semicolons do not
        # occur inside quoted literals. Keep this intentionally narrow.
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                self.execute(statement)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.raw.commit()
            else:
                self.raw.rollback()
        finally:
            self.raw.close()
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class PostgresStore(Store):
    backend = "postgres"

    def __init__(self, dsn: str, data_dir: Path):
        if not dsn:
            raise RuntimeError("CF_DATABASE_URL is required for PostgreSQL storage")
        parsed = urlsplit(dsn)
        if parsed.scheme not in {"postgres", "postgresql"}:
            raise RuntimeError("CF_DATABASE_URL must be a PostgreSQL URI")
        sslmode = parse_qs(parsed.query).get("sslmode", [""])[0].lower()
        if not _is_loopback_host(parsed.hostname) and sslmode not in {"require", "verify-ca", "verify-full"}:
            raise RuntimeError("remote_postgres_requires_tls")
        self.dsn = dsn
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / "server.sqlite3"  # compatibility path only; not used as storage
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("Install distributed dependencies: pip install -r requirements-distributed.txt") from exc
        self._psycopg = psycopg
        self._dict_row = dict_row
        self._init_db()

    def connect(self):
        def bounded_env(name: str, default: int, low: int, high: int) -> int:
            try:
                value = int(os.getenv(name, str(default)))
            except (TypeError, ValueError):
                value = default
            return max(low, min(high, value))
        raw = self._psycopg.connect(self.dsn, row_factory=self._dict_row,
                                    connect_timeout=bounded_env("CF_PG_CONNECT_TIMEOUT", 5, 1, 60))
        statement_timeout = bounded_env("CF_PG_STATEMENT_TIMEOUT_MS", 30000, 1000, 300000)
        raw.execute("SELECT set_config(%s, %s, false)", ("statement_timeout", str(statement_timeout)))
        return PostgresConnection(raw)

    def _init_db(self):
        schema = """
        CREATE TABLE IF NOT EXISTS api_tokens(
          token_id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL,
          role TEXT NOT NULL, scopes_json TEXT NOT NULL, created_at TEXT NOT NULL,
          revoked INTEGER NOT NULL DEFAULT 0, last_used TEXT);
        CREATE TABLE IF NOT EXISTS nodes(
          node_id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL,
          labels_json TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT,
          status TEXT NOT NULL DEFAULT 'pending', payload_json TEXT NOT NULL DEFAULT '{}', revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS node_nonces(
          node_id TEXT NOT NULL, nonce TEXT NOT NULL, created_at BIGINT NOT NULL,
          PRIMARY KEY(node_id, nonce));
        CREATE TABLE IF NOT EXISTS workflows(
          workflow_id TEXT PRIMARY KEY, title TEXT NOT NULL, steps_json TEXT NOT NULL,
          created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at BIGINT NOT NULL,
          status TEXT NOT NULL, approved_by TEXT, approved_at TEXT, result_json TEXT,
          execution_owner TEXT, execution_lease_until BIGINT NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit(
          seq BIGSERIAL PRIMARY KEY, created_at TEXT NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, object_id TEXT NOT NULL, detail_json TEXT NOT NULL,
          prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS ai_usage(
          request_id TEXT PRIMARY KEY, actor TEXT NOT NULL, model TEXT NOT NULL,
          created_at TEXT NOT NULL, input_tokens BIGINT NOT NULL, output_tokens BIGINT NOT NULL,
          cost_usd DOUBLE PRECISION NOT NULL, status TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_ai_usage_created ON ai_usage(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);
        CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
        CREATE INDEX IF NOT EXISTS idx_workflows_status_created ON workflows(status, created_at);
        """
        with self.connect() as con:
            con.executescript(schema)
            con.execute("ALTER TABLE workflows ADD COLUMN IF NOT EXISTS execution_owner TEXT")
            con.execute("ALTER TABLE workflows ADD COLUMN IF NOT EXISTS execution_lease_until BIGINT NOT NULL DEFAULT 0")
            con.execute("CREATE INDEX IF NOT EXISTS idx_workflows_execution_lease ON workflows(status, execution_lease_until)")
            con.execute("CREATE TABLE IF NOT EXISTS cf_schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            con.execute("INSERT INTO cf_schema_migrations(version,applied_at) VALUES(2,now()::text) ON CONFLICT(version) DO NOTHING")

    def backup_database(self, target: Path) -> dict[str, Any]:
        """Use pg_dump with a temporary mode-0600 PGPASSFILE; never place secrets in argv."""
        import hashlib
        import shutil
        import subprocess
        import tempfile
        from urllib.parse import urlsplit, unquote, parse_qs
        pg_dump = shutil.which("pg_dump")
        if not pg_dump:
            raise RuntimeError("pg_dump is required for PostgreSQL backup")
        parts = urlsplit(self.dsn)
        if parts.scheme not in {"postgres", "postgresql"}:
            raise RuntimeError("CF_DATABASE_URL must be a PostgreSQL URI for pg_dump backup")
        host, port = parts.hostname or "localhost", str(parts.port or 5432)
        db, user, password = unquote(parts.path.lstrip("/")), unquote(parts.username or ""), unquote(parts.password or "")
        if not db or not user:
            raise RuntimeError("PostgreSQL backup requires database and username in CF_DATABASE_URL")
        if any(ch in value for value in (host, port, db, user, password) for ch in ("\n", "\r", "\x00")):
            raise RuntimeError("PostgreSQL connection fields contain invalid control characters")
        def pgpass_escape(v): return str(v).replace("\\", "\\\\").replace(":", "\\:")
        fd, passfile = tempfile.mkstemp(prefix="cf-pgpass-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(":".join(pgpass_escape(x) for x in (host, port, db, user, password)) + "\n")
            target = Path(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Pass only the minimum environment pg_dump needs. In particular,
            # do not leak CF_DATABASE_URL, AI keys or unrelated connector secrets
            # into the child process environment; the database password is in
            # the mode-0600 PGPASSFILE only.
            keep = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ"}
            pg_env = {k: v for k, v in os.environ.items() if k in keep}
            pg_env.update({"PGPASSFILE": passfile, "PGCONNECT_TIMEOUT": "5"})
            query = parse_qs(parts.query)
            for param, env_name in (("sslmode", "PGSSLMODE"), ("sslrootcert", "PGSSLROOTCERT"),
                                    ("sslcert", "PGSSLCERT"), ("sslkey", "PGSSLKEY")):
                value = query.get(param, [None])[0]
                if value:
                    pg_env[env_name] = value
            cp = subprocess.run([pg_dump, "--format=custom", "--no-owner", "--no-acl", "--no-password", "--host", host,
                                 "--port", port, "--username", user, "--dbname", db, "--file", str(target)],
                                env=pg_env,
                                capture_output=True, text=True, timeout=300, check=False)
            if cp.returncode != 0:
                target.unlink(missing_ok=True)
                raise RuntimeError("PostgreSQL backup failed: " + (cp.stderr or "pg_dump error")[:300])
            try: os.chmod(target, 0o600)
            except OSError: pass
            digest = _sha256_file(target)
            return {"path": str(target), "size_bytes": target.stat().st_size, "sha256": digest, "format": "pg_dump_custom"}
        finally:
            try: os.unlink(passfile)
            except OSError: pass


def create_store(data_dir: Path):
    backend = os.getenv("CF_STORAGE_BACKEND", "sqlite").strip().lower()
    if backend == "postgres":
        return PostgresStore(os.getenv("CF_DATABASE_URL", ""), data_dir)
    if backend != "sqlite":
        raise RuntimeError("CF_STORAGE_BACKEND must be sqlite or postgres")
    from server_core import Store
    return Store(Path(data_dir) / "server.sqlite3")


class EnvelopeCipher:
    """AES-256-GCM envelope for request payloads/results stored in shared Postgres."""
    def __init__(self, raw_key: str | None = None):
        raw_key = (raw_key if raw_key is not None else os.getenv("CF_DISTRIBUTED_DATA_KEY", "")).strip()
        if not raw_key:
            raise RuntimeError("CF_DISTRIBUTED_DATA_KEY is required for distributed AI jobs")
        try:
            key = bytes.fromhex(raw_key) if re.fullmatch(r"[0-9a-fA-F]{64}", raw_key) else base64.urlsafe_b64decode(raw_key + "=" * (-len(raw_key) % 4))
        except Exception as exc:
            raise RuntimeError("CF_DISTRIBUTED_DATA_KEY must be 32-byte hex or URL-safe base64") from exc
        if len(key) != 32:
            raise RuntimeError("CF_DISTRIBUTED_DATA_KEY must decode to exactly 32 bytes")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise RuntimeError("Install cryptography to enable encrypted distributed jobs") from exc
        self._aes = AESGCM(key)

    def seal(self, value: bytes, aad: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return b"CF2" + nonce + self._aes.encrypt(nonce, value, aad)

    def open(self, sealed: bytes, aad: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        if not isinstance(sealed, (bytes, bytearray)) or len(sealed) < 31 or bytes(sealed[:3]) != b"CF2":
            raise ValueError("invalid_encrypted_job")
        try:
            return self._aes.decrypt(bytes(sealed[3:15]), bytes(sealed[15:]), aad)
        except InvalidTag as exc:
            raise ValueError("distributed_job_decryption_failed") from exc

    @staticmethod
    def generate_key() -> str:
        return secrets.token_hex(32)


class RedisCoordinator:
    """Best-effort pub/sub + short leases. PostgreSQL remains authoritative."""
    _RELEASE_SCRIPT = "if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end"

    def __init__(self, url: str | None = None):
        self.url = (url if url is not None else os.getenv("CF_REDIS_URL", "")).strip()
        self.client = None
        self.error = "not_configured"
        if self.url:
            parsed = urlsplit(self.url)
            if parsed.scheme not in {"redis", "rediss"}:
                self.error = "invalid_redis_url"
                return
            if not _is_loopback_host(parsed.hostname) and parsed.scheme != "rediss":
                self.error = "remote_redis_requires_tls"
                return
            try:
                import redis
                self.client = redis.Redis.from_url(self.url, socket_connect_timeout=2, socket_timeout=2,
                                                   health_check_interval=30, decode_responses=True)
                self.client.ping()
                self.error = ""
            except Exception as exc:
                self.client = None
                self.error = type(exc).__name__

    def publish(self, channel: str, message: str = "ready") -> bool:
        if not self.client: return False
        try:
            self.client.publish("cyberforge:" + channel, message[:200]); return True
        except Exception:
            return False

    def acquire_lease(self, name: str, ttl_seconds: int = 30) -> str | None:
        if not self.client: return None
        token = uuid.uuid4().hex
        try:
            ok = self.client.set("cyberforge:lease:" + name, token, nx=True, ex=max(2, min(300, int(ttl_seconds))))
            return token if ok else None
        except Exception:
            return None

    def release_lease(self, name: str, token: str) -> bool:
        if not self.client: return False
        try: return bool(self.client.eval(self._RELEASE_SCRIPT, 1, "cyberforge:lease:" + name, token))
        except Exception: return False

    def heartbeat(self, instance_id: str, workers: int) -> bool:
        if not self.client: return False
        try:
            key = "cyberforge:instance:" + instance_id
            self.client.set(key, str(max(1, min(32, int(workers)))), ex=30)
            return True
        except Exception:
            return False

    def instances(self) -> list[str]:
        if not self.client: return []
        try:
            return sorted(str(k).split(":", 2)[-1] for k in self.client.scan_iter(match="cyberforge:instance:*", count=100))[:128]
        except Exception:
            return []

    def status(self) -> dict[str, Any]:
        if not self.url: return {"configured": False, "available": False, "role": "optional_not_configured"}
        if not self.client: return {"configured": True, "available": False, "role": "best_effort_coordination", "error": self.error}
        try:
            info = self.client.info("server")
            return {"configured": True, "available": True, "role": "best_effort_coordination",
                    "redis_version": str(info.get("redis_version", "unknown"))[:40]}
        except Exception as exc:
            return {"configured": True, "available": False, "role": "best_effort_coordination", "error": type(exc).__name__}
