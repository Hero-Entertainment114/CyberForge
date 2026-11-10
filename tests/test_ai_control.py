from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from ai_control import AIControlPlane, AdjustableSemaphore, gpu_inventory
from server_core import AIService, Store


class ModelHealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            body = json.dumps({"data": [{"id": "stub-model"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/steal")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args):
        pass


class AIControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        self.store = Store(self.data / "server.sqlite3")
        self.env = {
            "CF_AI_DEPLOYMENTS_JSON": json.dumps([
                {"id": "local-a", "model": "stub-model", "base_url": "http://127.0.0.1:11434/v1", "billing_mode": "local"},
                {"id": "local-b", "model": "stub-model-b", "base_url": "http://127.0.0.1:11435/v1", "billing_mode": "local"},
                {"id": "paid-a", "model": "paid-model", "base_url": "https://paid.example.test/v1", "billing_mode": "paid",
                 "api_key_env": "CF_TEST_PAID_KEY", "input_price_per_1m": 1, "output_price_per_1m": 2,
                 "daily_budget_usd": 10, "max_request_usd": 1},
            ]),
            "CF_AI_ALLOWED_HOSTS": "paid.example.test",
            "CF_AI_ALLOW_PAID": "1",
            "CF_TEST_PAID_KEY": "test-key",
            "CF_AI_DEFAULT_DEPLOYMENT": "",
            "CF_AI_WORKERS": "2",
            "CF_AI_QUEUE_LIMIT": "16",
            "CF_AI_COHORT_SIZE": "4",
            "CF_AI_COHORT_WAIT_MS": "10",
        }
        self.patch = patch.dict(os.environ, self.env, clear=False)
        self.patch.start()
        self.ai = AIService(self.store)
        self.control = AIControlPlane(self.store, self.ai)

    def tearDown(self):
        self.control.close()
        self.patch.stop()
        self.tmp.cleanup()

    def wait_job(self, job_id, actor="alice", timeout=3):
        deadline = time.monotonic() + timeout
        identity = {"name": actor, "role": "admin"}
        while time.monotonic() < deadline:
            job = self.control.get_job(job_id, identity)
            if job["status"] in {"succeeded", "failed", "rejected", "interrupted"}:
                return job
            time.sleep(0.01)
        self.fail("job did not reach a terminal state")

    def test_registry_syncs_configured_models_without_secrets(self):
        models = self.control.models()
        self.assertEqual({x["deployment_id"] for x in models}, {"local-a", "local-b", "paid-a"})
        self.assertTrue(next(x for x in models if x["deployment_id"] == "local-a")["is_default"])
        self.assertNotIn("test-key", json.dumps(models))

    def test_model_policy_update_and_audit(self):
        updated = self.control.set_policy("local-b", {"priority": -10, "max_concurrency": 3}, "admin")
        self.assertEqual(updated["priority"], -10)
        self.assertEqual(updated["max_concurrency"], 3)
        self.assertTrue(self.store.verify_audit()["valid"])

    def test_default_route_can_be_changed_to_local_model(self):
        self.control.set_policy("local-b", {"is_default": True}, "admin")
        models = self.control.models()
        self.assertTrue(next(x for x in models if x["deployment_id"] == "local-b")["is_default"])
        self.assertFalse(next(x for x in models if x["deployment_id"] == "local-a")["is_default"])

    def test_paid_model_cannot_be_auto_default(self):
        with self.assertRaisesRegex(ValueError, "paid_model_cannot_be_default"):
            self.control.set_policy("paid-a", {"is_default": True}, "admin")

    def test_disabled_model_cannot_become_default(self):
        with self.assertRaisesRegex(ValueError, "disabled_model_cannot_be_default"):
            self.control.set_policy("local-a", {"enabled": False, "is_default": True}, "admin")

    def test_disabled_model_is_not_routable(self):
        self.control.set_policy("local-a", {"enabled": False}, "admin")
        with self.assertRaisesRegex(ValueError, "ai_deployment_disabled"):
            self.control.route("local-a")

    def test_paid_deployment_is_not_selected_implicitly(self):
        selected, _ = self.control.route()
        self.assertNotEqual(selected, "paid-a")

    def test_explicit_paid_selection_is_pinned_and_auditable(self):
        selected, meta = self.control.route("paid-a")
        self.assertEqual(selected, "paid-a")
        self.assertEqual(meta["reason"], "explicit_paid_selection")
        self.assertFalse(meta["failover"])

    def test_paid_only_configuration_has_no_automatic_default(self):
        paid_only = json.dumps([{"id": "paid-only", "model": "paid", "base_url": "https://paid.example.test/v1",
                                 "billing_mode": "paid", "api_key_env": "CF_TEST_PAID_KEY",
                                 "input_price_per_1m": 1, "output_price_per_1m": 1,
                                 "daily_budget_usd": 10, "max_request_usd": 1}])
        with patch.dict(os.environ, {"CF_AI_DEPLOYMENTS_JSON": paid_only, "CF_AI_DEFAULT_DEPLOYMENT": ""}):
            store = Store(self.data / "paid-only.sqlite3")
            ai = AIService(store)
            manager = AIControlPlane(store, ai)
            try:
                self.assertIsNone(ai.status()["default_deployment"])
                with self.assertRaisesRegex(RuntimeError, "ai_paid_requires_explicit_selection"):
                    manager.route()
            finally:
                manager.close()

    def test_legacy_direct_chat_respects_disabled_model_policy(self):
        self.control.set_policy("local-a", {"enabled": False}, "admin")
        with self.assertRaisesRegex(ValueError, "ai_deployment_disabled"):
            self.ai.chat("alice", {"deployment_id": "local-a", "messages": [{"role": "user", "content": "hello"}]})

    def test_restart_marks_inflight_jobs_interrupted_and_does_not_replay_prompts(self):
        with self.store.connect() as con:
            con.execute("INSERT INTO ai_jobs(job_id,actor,actor_id,deployment_id,priority,status,created_at) VALUES(?,?,?,?,?,?,?)",
                        ("aij_restart_test", "alice", "token-1", "local-a", 5, "running", "2026-11-08T00:00:00+00:00"))
        self.control.close()
        manager = AIControlPlane(self.store, self.ai)
        self.control = manager
        with self.store.connect() as con:
            row = con.execute("SELECT status,error_code FROM ai_jobs WHERE job_id='aij_restart_test'").fetchone()
        self.assertEqual(row["status"], "interrupted")
        self.assertEqual(row["error_code"], "server_restarted")

    def test_health_check_uses_fixed_models_endpoint(self):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), ModelHealthHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = json.loads(self.env["CF_AI_DEPLOYMENTS_JSON"])
            cfg[0]["base_url"] = f"http://127.0.0.1:{httpd.server_port}/v1"
            with patch.dict(os.environ, {"CF_AI_DEPLOYMENTS_JSON": json.dumps(cfg)}):
                result = self.control.health_check("local-a")
            self.assertEqual(result["health_state"], "healthy")
            self.assertEqual(result["http_status"], 200)
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)

    def test_unhealthy_requested_local_model_fails_over_only_within_same_billing_class(self):
        with self.store.lock, self.store.connect() as con:
            con.execute("UPDATE ai_model_registry SET health_state='unhealthy' WHERE deployment_id='local-a'")
            con.execute("UPDATE ai_model_registry SET health_state='healthy' WHERE deployment_id='local-b'")
        selected, meta = self.control.route("local-a", "auto")
        self.assertEqual(selected, "local-b")
        self.assertTrue(meta["failover"])

    def test_pinned_route_does_not_fail_over(self):
        with self.store.lock, self.store.connect() as con:
            con.execute("UPDATE ai_model_registry SET health_state='unhealthy' WHERE deployment_id='local-a'")
        selected, meta = self.control.route("local-a", "pinned")
        self.assertEqual(selected, "local-a")
        self.assertFalse(meta["failover"])

    def test_health_probe_never_follows_redirects(self):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), ModelHealthHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = json.loads(self.env["CF_AI_DEPLOYMENTS_JSON"])
            cfg[0]["base_url"] = f"http://127.0.0.1:{httpd.server_port}/redirect"
            with patch.dict(os.environ, {"CF_AI_DEPLOYMENTS_JSON": json.dumps(cfg)}):
                result = self.control.health_check("local-a")
            self.assertEqual(result["health_state"], "unhealthy")
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)

    def test_remote_health_probe_requires_allowlist_and_https(self):
        with patch.dict(os.environ, {"CF_AI_ALLOWED_HOSTS": ""}):
            with self.assertRaises(PermissionError):
                self.control.health_check("paid-a")

    def test_async_job_executes_and_result_is_available_in_process(self):
        self.ai.chat = lambda actor, body: {"answer": "done", "model": "stub-model", "usage": {"input_tokens": 1, "output_tokens": 1, "billing_mode": "local"}}
        submitted = self.control.submit("alice", {"deployment_id": "local-a", "messages": [{"role": "user", "content": "hello"}]})
        job = self.wait_job(submitted["job_id"])
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["result"]["answer"], "done")

    def test_dispatcher_backpressures_before_unbounded_executor_queue(self):
        self.control.close()
        started = threading.Event()
        release = threading.Event()
        self.ai.chat = lambda actor, body: (started.set(), release.wait(5), {"answer": "ok"})[2]
        with patch.dict(os.environ, {"CF_AI_WORKERS": "1", "CF_AI_QUEUE_LIMIT": "8",
                                     "CF_AI_COHORT_SIZE": "1", "CF_AI_COHORT_WAIT_MS": "0"}):
            control = AIControlPlane(self.store, self.ai)
        self.control = control
        try:
            accepted = 0
            rejected = 0
            for i in range(40):
                try:
                    control.submit("alice", {"deployment_id": "local-a", "messages": [{"role": "user", "content": str(i)}]})
                    accepted += 1
                except OverflowError:
                    rejected += 1
                if started.is_set() and rejected:
                    break
            self.assertTrue(started.wait(1))
            self.assertGreater(rejected, 0)
            # One active worker, at most one item held by dispatcher, plus the
            # configured bounded queue. The executor's internal queue stays empty.
            self.assertLessEqual(accepted, control.queue_limit + control.max_workers + control.batch_size)
            status = control.queue_status()
            self.assertLessEqual(status["inflight"], 1)
        finally:
            release.set()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with control.lock:
                    pending_count = len(control.pending)
                    inflight_count = control.inflight_jobs
                if control.queue.empty() and pending_count == 0 and inflight_count == 0:
                    break
                time.sleep(0.02)
            self.assertTrue(control.queue.empty(), "backpressure test left queued jobs behind")
            with control.lock:
                self.assertEqual(control.pending, {})
                self.assertEqual(control.inflight_jobs, 0)
            control.close()

    def test_job_metadata_does_not_persist_prompt_or_answer(self):
        self.ai.chat = lambda actor, body: {"answer": "private-answer"}
        submitted = self.control.submit("alice", {"deployment_id": "local-a", "messages": [{"role": "user", "content": "private-prompt"}]})
        self.wait_job(submitted["job_id"])
        with self.store.connect() as con:
            cols = {x["name"] for x in con.execute("PRAGMA table_info(ai_jobs)")}
            row = con.execute("SELECT * FROM ai_jobs WHERE job_id=?", (submitted["job_id"],)).fetchone()
        self.assertNotIn("prompt", cols)
        self.assertNotIn("result_json", cols)
        self.assertNotIn("private-prompt", json.dumps(dict(row)))
        self.assertNotIn("private-answer", json.dumps(dict(row)))

    def test_job_result_is_private_to_creator(self):
        self.ai.chat = lambda actor, body: {"answer": "private"}
        submitted = self.control.submit("alice", {"deployment_id": "local-a", "messages": [{"role": "user", "content": "hi"}]})
        self.wait_job(submitted["job_id"])
        with self.assertRaises(PermissionError):
            self.control.get_job(submitted["job_id"], {"name": "bob", "role": "analyst"})

    def test_queue_full_rejects_and_persists_rejection(self):
        # Fill the scheduler queue directly to deterministically exercise backpressure.
        self.control.stopping.set()
        self.control.dispatcher.join(timeout=1)
        for i in range(self.control.queue_limit):
            self.control.queue.put_nowait((0, time.monotonic(), f"block-{i}"))
        with self.assertRaises(OverflowError):
            self.control.submit("alice", {"deployment_id": "local-a", "messages": [{"role": "user", "content": "hi"}]})
        with self.store.connect() as con:
            row = con.execute("SELECT status,error_code FROM ai_jobs ORDER BY created_at DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "rejected")
        self.assertEqual(row["error_code"], "ai_queue_full")

    def test_adjustable_semaphore_resizes_with_active_permits(self):
        sem = AdjustableSemaphore(1)
        self.assertTrue(sem.acquire(timeout=0.01))
        sem.resize(2)
        self.assertTrue(sem.acquire(timeout=0.01))
        sem.release(); sem.release()
        self.assertEqual(sem.active, 0)

    def test_gpu_inventory_is_bounded_read_only_when_no_cli_present(self):
        with patch("ai_control.shutil.which", return_value=None):
            result = gpu_inventory()
        self.assertFalse(result["available"])
        self.assertEqual(result["device_count"], 0)

    def test_queue_metrics_report_bounded_capacity_and_scheduling_note(self):
        status = self.control.queue_status()
        self.assertEqual(status["queue_limit"], 16)
        self.assertEqual(status["workers"], 2)
        self.assertEqual(status["inflight"], 0)
        self.assertIn("Actual continuous/tensor batching", status["batching_note"])

    def test_invalid_scheduler_environment_uses_safe_bounds(self):
        from ai_control import scheduler_config
        with patch.dict(os.environ, {"CF_AI_WORKERS": "nan", "CF_AI_QUEUE_LIMIT": "-1", "CF_AI_COHORT_WAIT_MS": "9000"}):
            cfg = scheduler_config()
        self.assertEqual(cfg["workers"], 4)
        self.assertEqual(cfg["queue_limit"], 8)
        self.assertEqual(cfg["cohort_wait_ms"], 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)

class AIControlAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        from server import create_handler
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = Path(cls.tmp.name)
        cls.env_patch = patch.dict(os.environ, {
            "CF_AI_DEPLOYMENTS_JSON": json.dumps([
                {"id": "local-a", "model": "stub-model", "base_url": "http://127.0.0.1:11434/v1", "billing_mode": "local"},
                {"id": "local-b", "model": "stub-model-b", "base_url": "http://127.0.0.1:11435/v1", "billing_mode": "local"},
            ]),
            "CF_AI_WORKERS": "2",
            "CF_AI_QUEUE_LIMIT": "16",
        }, clear=False)
        cls.env_patch.start()
        cls.store = Store(cls.data / "server.sqlite3")
        cls.admin = cls.store.create_token("admin", "admin")
        cls.operator = cls.store.create_token("operator", "operator")
        cls.viewer = cls.store.create_token("viewer", "viewer")
        cls.ai = AIService(cls.store)
        cls.ai.chat = lambda actor, body: {"deployment_id": body["deployment_id"], "model": "stub", "answer": "api-done",
                                           "usage": {"input_tokens": 1, "output_tokens": 1, "billing_mode": "local"}}
        cls.control = AIControlPlane(cls.store, cls.ai)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(cls.store, cls.ai, cls.data, cls.control))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=2)
        cls.control.close(); cls.env_patch.stop(); cls.tmp.cleanup()

    def request(self, token, path, method="GET", body=None, lang="en"):
        import urllib.request, urllib.error
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept-Language": lang})
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_operator_can_read_model_registry(self):
        status, data = self.request(self.operator["token"], "/api/v201/ai/models")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["models"]), 2)

    def test_viewer_can_read_queue_summary_but_not_submit_jobs(self):
        status, data = self.request(self.viewer["token"], "/api/v201/ai/queue")
        self.assertEqual(status, 200)
        status, data = self.request(self.viewer["token"], "/api/v201/ai/jobs", "POST", {"messages": [{"role": "user", "content": "no"}]})
        self.assertEqual(status, 403)

    def test_unknown_job_returns_localized_not_found(self):
        status, body = self.request(self.operator["token"], "/api/v201/ai/jobs/aij_missing", lang="vi")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "ai_job_not_found")
        self.assertIn("Không tìm thấy", body["error"]["message"])

    def test_operator_can_submit_and_poll_private_job(self):
        status, data = self.request(self.operator["token"], "/api/v201/ai/jobs", "POST",
            {"deployment_id": "local-a", "messages": [{"role": "user", "content": "hello"}]})
        self.assertEqual(status, 202)
        job_id = data["job_id"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status, job = self.request(self.operator["token"], "/api/v201/ai/jobs/" + job_id)
            if job.get("status") == "succeeded":
                break
            time.sleep(0.02)
        self.assertEqual(status, 200)
        self.assertEqual(job["result"]["answer"], "api-done")

    def test_job_poll_is_bound_to_token_identity_not_display_name(self):
        status, data = self.request(self.operator["token"], "/api/v201/ai/jobs", "POST",
            {"deployment_id": "local-a", "messages": [{"role": "user", "content": "hello"}]})
        self.assertEqual(status, 202)
        other = self.store.create_token("operator", "operator")
        status, body = self.request(other["token"], "/api/v201/ai/jobs/" + data["job_id"])
        self.assertEqual(status, 403)

    def test_admin_can_change_model_policy(self):
        status, body = self.request(self.admin["token"], "/api/v201/ai/models/local-b/policy", "POST", {"is_default": True})
        self.assertEqual(status, 200)
        self.assertTrue(body["model"]["is_default"])

    def test_operator_cannot_change_model_policy(self):
        status, body = self.request(self.operator["token"], "/api/v201/ai/models/local-b/policy", "POST", {"enabled": False})
        self.assertEqual(status, 403)

    def test_gpu_endpoint_requires_system_read(self):
        status, body = self.request(self.viewer["token"], "/api/v201/ai/gpu")
        self.assertEqual(status, 200)
        self.assertIn("available", body)
