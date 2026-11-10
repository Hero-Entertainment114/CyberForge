from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

from server import create_handler
from server_core import AIService, Store
from tools import tail_jsonl


class FakeAIControl:
    def __init__(self):
        self.calls = []

    def submit(self, actor, body, actor_id=None):
        self.calls.append({"actor": actor, "actor_id": actor_id, "body": body})
        return {"job_id": "aij_security_test", "status": "queued", "deployment_id": body.get("deployment_id", "unit-model"),
                "route": {"reason": "unit-test"}, "queue_position": 1}


class SecurityIntelligenceAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = Path(cls.tmp.name)
        cls.store = Store(cls.data / "server.sqlite3")
        cls.tokens = {role: cls.store.create_token("v204-" + role, role)["token"]
                      for role in ("admin", "operator", "analyst", "viewer", "sensor")}
        cls.ai_control = FakeAIControl()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(
            cls.store, AIService(cls.store), cls.data, ai_control=cls.ai_control))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)
        cls.tmp.cleanup()

    def request(self, role, method, path, body=None):
        raw = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Authorization": "Bearer " + self.tokens[role], "Accept-Language": "en"}
        if raw is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=raw, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def seed_incident(self, suffix="one"):
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        status, body = self.request("sensor", "POST", "/api/v204/security/ingest/falco", {"events": [{
            "time": timestamp, "rule": "Terminal shell detected " + suffix, "priority": "Warning",
            "hostname": "node-v204", "output_fields": {"proc.pid": 4242, "proc.name": "bash", "proc.pname": "systemd"},
            "output": "test password=not-for-storage"}]})
        self.assertEqual(status, 202)
        with self.store.connect() as con:
            row = con.execute("SELECT incident_id FROM security_incidents ORDER BY created_at DESC LIMIT 1").fetchone()
        self.assertIsNotNone(row)
        return row["incident_id"]

    def test_v204_sensor_route_accepts_event(self):
        status, body = self.request("sensor", "POST", "/api/v204/security/ingest/wazuh", {"events": [{
            "id": "v204-api-wazuh", "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {"id": "5710", "level": 12, "description": "SSH authentication failure"},
            "agent": {"name": "node-api"}}]})
        self.assertEqual(status, 202)
        self.assertEqual(body["result"]["accepted"], 1)


    def test_continuous_tailer_delivers_to_live_v204_api_and_checkpoints(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            log = root / "wazuh.jsonl"
            log.write_text(json.dumps({
                "id": "v204-tail-live-001",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "rule": {"id": "5710", "level": 12, "description": "SSH authentication failure"},
                "agent": {"name": "node-tail-live"},
            }) + "\n", encoding="utf-8")
            state = tail_jsonl.CheckpointDB(root / "state" / "checkpoints.sqlite3")
            runner = None
            try:
                runner = tail_jsonl.TailRunner(
                    log, "wazuh", state, self.base, self.tokens["sensor"],
                    batch_size=1, start_at_end=False,
                )
                first = runner.poll_once()
                self.assertEqual(first["accepted"], 1)
                self.assertEqual(first["sent"], 1)
                second = runner.poll_once()
                self.assertEqual(second["sent"], 0)
                with self.store.connect() as con:
                    row = con.execute(
                        "SELECT source_event_id FROM security_events WHERE source=? AND source_event_id=?",
                        ("wazuh", "v204-tail-live-001"),
                    ).fetchone()
                self.assertIsNotNone(row)
            finally:
                if runner:
                    runner.close()
                state.close()

    def test_v204_sources_advertise_v204_ingestion_path(self):
        status, body = self.request("viewer", "GET", "/api/v204/security/sources")
        self.assertEqual(status, 200)
        self.assertTrue(all(x["ingest_path"].startswith("/api/v204/") for x in body["sources"]))

    def test_mitre_summary_available_to_viewer(self):
        self.seed_incident("mitre")
        status, body = self.request("viewer", "GET", "/api/v204/security/mitre/summary")
        self.assertEqual(status, 200)
        self.assertIn("mapping_type", body)

    def test_incident_analysis_read_only_available_to_viewer(self):
        incident_id = self.seed_incident("read-only")
        status, body = self.request("viewer", "GET", f"/api/v204/security/incidents/{incident_id}/analysis")
        self.assertEqual(status, 200)
        self.assertEqual(body["incident"]["incident_id"], incident_id)
        self.assertIn("timeline", body)
        self.assertIn("confidence_note", body)

    def test_invalid_analysis_window_returns_400(self):
        incident_id = self.seed_incident("bad-window")
        status, body = self.request("viewer", "GET", f"/api/v204/security/incidents/{incident_id}/analysis?window_minutes=999")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "security_correlation_invalid_window")

    def test_analyst_can_persist_correlation(self):
        incident_id = self.seed_incident("correlate")
        status, body = self.request("analyst", "POST", f"/api/v204/security/incidents/{incident_id}/correlate", {"window_minutes": 30})
        self.assertEqual(status, 200)
        self.assertIn("correlation", body)

    def test_viewer_cannot_persist_correlation(self):
        incident_id = self.seed_incident("rbac")
        status, body = self.request("viewer", "POST", f"/api/v204/security/incidents/{incident_id}/correlate", {})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")

    def test_sensor_cannot_read_security_analysis(self):
        status, body = self.request("sensor", "GET", "/api/v204/security/mitre/summary")
        self.assertEqual(status, 403)

    def test_ai_analysis_queues_only_sanitized_context(self):
        incident_id = self.seed_incident("ai")
        status, body = self.request("analyst", "POST", f"/api/v204/security/incidents/{incident_id}/ai-analysis", {})
        self.assertEqual(status, 202)
        self.assertEqual(body["job"]["job_id"], "aij_security_test")
        self.assertTrue(self.ai_control.calls)
        encoded = json.dumps(self.ai_control.calls[-1]["body"], ensure_ascii=False)
        self.assertNotIn("not-for-storage", encoded)
        self.assertIn("CyberForge Defensive Security Analyst", encoded)


if __name__ == "__main__":
    unittest.main(verbosity=2)
