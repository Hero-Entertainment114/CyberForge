from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from distributed import EnvelopeCipher, PostgresConnection, RedisCoordinator, create_store
from server_core import Store


class FakeRaw:
    def __init__(self):
        self.calls = []
        self.committed = self.rolled_back = self.closed = False

    def execute(self, sql, params=()):
        self.calls.append((sql, tuple(params)))
        return self

    def commit(self): self.committed = True
    def rollback(self): self.rolled_back = True
    def close(self): self.closed = True


class DistributedUtilityTests(unittest.TestCase):
    def test_postgres_connection_translates_placeholders_and_sqlite_collation(self):
        raw = FakeRaw()
        con = PostgresConnection(raw)
        con.execute("SELECT * FROM nodes WHERE node_id=? ORDER BY name COLLATE NOCASE", ("n1",))
        self.assertEqual(raw.calls[-1][0], "SELECT * FROM nodes WHERE node_id=%s ORDER BY name ")
        self.assertEqual(raw.calls[-1][1], ("n1",))

    def test_begin_immediate_is_translated_for_postgres(self):
        raw = FakeRaw()
        PostgresConnection(raw).execute("BEGIN IMMEDIATE")
        self.assertEqual(raw.calls[-1][0], "BEGIN")

    def test_context_commits_and_closes(self):
        raw = FakeRaw()
        with PostgresConnection(raw) as con:
            con.execute("SELECT 1")
        self.assertTrue(raw.committed)
        self.assertTrue(raw.closed)
        self.assertFalse(raw.rolled_back)

    def test_context_rolls_back_and_closes_on_error(self):
        raw = FakeRaw()
        with self.assertRaises(RuntimeError):
            with PostgresConnection(raw):
                raise RuntimeError("fail")
        self.assertTrue(raw.rolled_back)
        self.assertTrue(raw.closed)
        self.assertFalse(raw.committed)

    def test_envelope_cipher_roundtrip_and_context_binding(self):
        key = EnvelopeCipher.generate_key()
        cipher = EnvelopeCipher(key)
        sealed = cipher.seal(b"sensitive prompt", b"payload:job-1")
        self.assertNotIn(b"sensitive prompt", sealed)
        self.assertEqual(cipher.open(sealed, b"payload:job-1"), b"sensitive prompt")
        with self.assertRaises(ValueError):
            cipher.open(sealed, b"payload:job-2")

    def test_envelope_cipher_rejects_wrong_key(self):
        one = EnvelopeCipher(EnvelopeCipher.generate_key())
        two = EnvelopeCipher(EnvelopeCipher.generate_key())
        sealed = one.seal(b"result", b"result:id")
        with self.assertRaises(ValueError):
            two.open(sealed, b"result:id")

    def test_envelope_key_validation(self):
        for bad in ("", "abc", "x" * 64):
            with self.subTest(key=bad), self.assertRaises(RuntimeError):
                EnvelopeCipher(bad)

    def test_redis_unconfigured_degrades_cleanly(self):
        with patch.dict(os.environ, {"CF_REDIS_URL": ""}):
            redis = RedisCoordinator()
        self.assertFalse(redis.status()["available"])
        self.assertFalse(redis.publish("ai:jobs:ready", "x"))
        self.assertIsNone(redis.acquire_lease("unit"))

    def test_store_factory_keeps_sqlite_as_default(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            store = create_store(Path(tmp))
            self.assertIsInstance(store, Store)
            self.assertEqual(store.backend, "sqlite")

    def test_store_factory_rejects_unknown_backend(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"CF_STORAGE_BACKEND": "mysql"}):
            with self.assertRaisesRegex(RuntimeError, "CF_STORAGE_BACKEND"):
                create_store(Path(tmp))

    def test_postgres_mode_requires_connection_url(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"CF_STORAGE_BACKEND": "postgres", "CF_DATABASE_URL": ""}):
            with self.assertRaisesRegex(RuntimeError, "CF_DATABASE_URL"):
                create_store(Path(tmp))

    def test_remote_postgres_requires_tls(self):
        from distributed import PostgresStore
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "remote_postgres_requires_tls"):
                PostgresStore("postgresql://u:p@db.example:5432/cf", Path(tmp))

    def test_expired_distributed_lease_cleanup_finalizes_paid_and_exhausted_jobs(self):
        from ai_control import AIControlPlane
        class Cursor:
            def __init__(self, rowcount): self.rowcount = rowcount
        class Connection:
            def __init__(self): self.calls = []
            def execute(self, sql, params=()):
                self.calls.append((sql, params))
                return Cursor(1 if "billing_mode='paid'" in sql else 2)
            def __enter__(self): return self
            def __exit__(self, *args): return False
        class FakeStore:
            def __init__(self): self.connection = Connection()
            def connect(self): return self.connection
        control = AIControlPlane.__new__(AIControlPlane)
        control.store = FakeStore()
        result = control._expire_distributed_leases(now=1234)
        self.assertEqual(result, {"paid_interrupted": 1, "retry_exhausted": 2})
        self.assertEqual(len(control.store.connection.calls), 2)
        self.assertIn("attempts>=2", control.store.connection.calls[1][0])

    def test_remote_redis_requires_tls(self):
        redis = RedisCoordinator("redis://:password@cache.example:6379/0")
        self.assertFalse(redis.status()["available"])
        self.assertEqual(redis.error, "remote_redis_requires_tls")

    def test_local_redis_url_allows_plaintext_loopback(self):
        redis = RedisCoordinator("redis://127.0.0.1:6379/0")
        # The test host may or may not have the optional redis-py client installed.
        self.assertFalse(redis.status()["available"])
        self.assertNotEqual(redis.error, "remote_redis_requires_tls")


@unittest.skipUnless(os.getenv("CF_TEST_POSTGRES_URL"), "Set CF_TEST_POSTGRES_URL to run live PostgreSQL integration tests")
class LivePostgresIntegrationTests(unittest.TestCase):
    def test_postgres_shared_token_and_audit_state(self):
        from distributed import PostgresStore
        dsn = os.environ["CF_TEST_POSTGRES_URL"]
        with tempfile.TemporaryDirectory() as tmp:
            a = PostgresStore(dsn, Path(tmp) / "a")
            b = PostgresStore(dsn, Path(tmp) / "b")
            created = a.create_token("cf-v202-test", "viewer")
            actor = b.authenticate(created["token"])
            self.assertIsNotNone(actor)
            self.assertEqual(actor["role"], "viewer")
            self.assertTrue(b.verify_audit()["valid"])
            a.revoke_token(created["token_id"], "integration-test")
            self.assertIsNone(b.authenticate(created["token"]))

    def test_postgres_workflow_claim_is_shared_and_reclaimable(self):
        import time
        from distributed import PostgresStore
        dsn = os.environ["CF_TEST_POSTGRES_URL"]
        with tempfile.TemporaryDirectory() as tmp:
            a = PostgresStore(dsn, Path(tmp) / "a")
            b = PostgresStore(dsn, Path(tmp) / "b")
            wid = a.add_workflow("cross-instance claim", ["check_integrations"], "admin")
            a.approve_workflow(wid, "operator")
            owner_a = a.claim_workflow(wid, "instance-a")
            with self.assertRaisesRegex(ValueError, "workflow_already_executing"):
                b.claim_workflow(wid, "instance-b")
            with a.connect() as con:
                con.execute("UPDATE workflows SET execution_lease_until=? WHERE workflow_id=?", (int(time.time()) - 1, wid))
            owner_b = b.claim_workflow(wid, "instance-b")
            self.assertNotEqual(owner_a, owner_b)
            self.assertFalse(a.fail_workflow(wid, "instance-a", {"failed_step": "stale"}, owner_a))
            self.assertTrue(b.fail_workflow(wid, "instance-b", {"failed_step": "reclaimed"}, owner_b))

    def test_distributed_ai_job_is_visible_across_control_planes(self):
        import json
        import time
        from ai_control import AIControlPlane

        class FakeAI:
            def deployments(self):
                return [{"id": "cfv202-test-local", "model": "test-model", "base_url": "http://127.0.0.1:11434/v1",
                         "billing_mode": "local", "api_key_env": "CF_AI_API_KEY", "api_key_configured": False,
                         "input_price_per_1m": 0, "output_price_per_1m": 0, "daily_budget_usd": 0, "max_request_usd": 0}]
            def chat(self, actor, body):
                return {"deployment_id": "cfv202-test-local", "model": "test-model", "answer": "distributed-ok",
                        "usage": {"input_tokens": 1, "output_tokens": 1, "estimated_cost_usd": 0, "billing_mode": "local"}}

        from distributed import PostgresStore
        dsn = os.environ["CF_TEST_POSTGRES_URL"]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            "CF_DISTRIBUTED_DATA_KEY": EnvelopeCipher.generate_key(),
            "CF_AI_DEPLOYMENTS_JSON": json.dumps([FakeAI().deployments()[0]]),
            "CF_AI_WORKERS": "1", "CF_AI_QUEUE_LIMIT": "32", "CF_DISTRIBUTED_POLL_MS": "100",
            "CF_INSTANCE_ID": "integration-a",
        }):
            a = PostgresStore(dsn, Path(tmp) / "a")
            ai_a = FakeAI()
            control_a = AIControlPlane(a, ai_a)
            # Separate server process/store sees the same metadata and job payload.
            with patch.dict(os.environ, {"CF_INSTANCE_ID": "integration-b"}):
                b = PostgresStore(dsn, Path(tmp) / "b")
                control_b = AIControlPlane(b, FakeAI())
            try:
                result = control_a.submit("test-user", {"messages": [{"role": "user", "content": "hello"}]}, actor_id="shared-token-id")
                deadline = time.monotonic() + 10
                job = None
                while time.monotonic() < deadline:
                    job = control_b.get_job(result["job_id"], {"id": "shared-token-id", "name": "test-user", "role": "viewer"})
                    if job["status"] in {"succeeded", "failed", "interrupted"}:
                        break
                    time.sleep(0.05)
                self.assertEqual(job["status"], "succeeded", job)
                self.assertEqual(job["result"]["answer"], "distributed-ok")
            finally:
                control_b.close()
                control_a.close()
