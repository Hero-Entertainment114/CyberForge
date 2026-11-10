from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import security_ops
from server import create_handler
from server_core import AIService, Store


class SecurityOpsCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "server.sqlite3")
        security_ops.initialize(self.store)
        self.admin = {"id": "admin-id", "name": "admin", "role": "admin", "scopes": ["*"]}
        self.analyst = {"id": "analyst-id", "name": "analyst", "role": "analyst", "scopes": ["security:read", "security:incident:update", "security:playbook:plan"]}
        self.operator = {"id": "operator-id", "name": "operator", "role": "operator", "scopes": ["security:read", "security:incident:update", "security:playbook:approve"]}

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, source, event, actor="sensor"):
        return security_ops.ingest(self.store, source, [event], actor)

    def test_wazuh_normalizes_alert_and_severity(self):
        out = security_ops.normalize("wazuh", {"id": "w1", "timestamp": "2026-11-09T10:00:00Z",
            "rule": {"id": "5710", "level": 12, "description": "SSH authentication failure", "groups": ["authentication_failed"]},
            "agent": {"id": "004", "name": "linux-node"}, "data": {"srcip": "203.0.113.7"}})[0]
        self.assertEqual(out["severity"], "high")
        self.assertEqual(out["src_ip"], "203.0.113.7")
        self.assertEqual(out["host"], "linux-node")
        self.assertEqual(out["rule_id"], "5710")

    def test_suricata_normalizes_eve_alert(self):
        out = security_ops.normalize("suricata", {"timestamp": "2026-11-09T10:00:00.123456+0000", "event_type": "alert",
            "flow_id": 100, "src_ip": "192.0.2.10", "src_port": 44321, "dest_ip": "198.51.100.20", "dest_port": 443,
            "proto": "TCP", "alert": {"signature_id": 201, "signature": "Test rule", "severity": 1}})[0]
        self.assertEqual(out["severity"], "critical")
        self.assertEqual(out["dst_ip"], "198.51.100.20")
        self.assertEqual(out["src_port"], 44321)
        self.assertIn("T", out["observed_at"])

    def test_suricata_non_alert_record_is_ignored(self):
        self.assertEqual(security_ops.normalize("suricata", {"event_type": "flow", "flow_id": 1}), [])

    def test_falco_priority_and_sensitive_output_redaction(self):
        out = security_ops.normalize("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Terminal shell in container",
            "priority": "Warning", "output": "shell password=hunter2 token=abc", "hostname": "node-a",
            "output_fields": {"proc.name": "bash", "proc.cmdline": "bash -c secret=foo", "container.name": "api"}})[0]
        self.assertEqual(out["severity"], "medium")
        encoded = json.dumps(out["details"])
        self.assertNotIn("hunter2", encoded)
        self.assertNotIn("proc.cmdline", encoded)
        self.assertIn("[REDACTED]", encoded)

    def test_zeek_conn_is_context_only_and_does_not_open_incident(self):
        out = security_ops.normalize("zeek", {"ts": 1794220000.1, "uid": "Cabc", "_path": "conn",
            "id.orig_h": "192.0.2.1", "id.orig_p": 12345, "id.resp_h": "192.0.2.2", "id.resp_p": 443})[0]
        self.assertEqual(out["severity"], "info")
        self.assertFalse(out["create_incident"])
        self.assertEqual(out["src_ip"], "192.0.2.1")
        self.assertEqual(out["dst_ip"], "192.0.2.2")
        self.assertEqual(out["src_port"], 12345)
        self.assertEqual(out["dst_port"], 443)
        result = self.add("zeek", {"ts": 1794220000.1, "uid": "Cabc", "_path": "conn",
            "id.orig_h": "192.0.2.1", "id.resp_h": "192.0.2.2"})
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(security_ops.overview(self.store)["incidents_total"], 0)

    def test_zeek_notice_creates_incident(self):
        out = security_ops.normalize("zeek", {"ts": 1794220000.1, "uid": "Cnotice", "_path": "notice",
            "note": "SSH::Password_Guessing", "msg": "Possible password guessing", "id.orig_h": "192.0.2.7"})[0]
        self.assertEqual(out["severity"], "medium")
        self.assertTrue(out["create_incident"])

    def test_trivy_report_flattens_findings_without_secret_values(self):
        report = {"CreatedAt": "2026-11-09T10:00:00Z", "ArtifactName": "demo:1",
                  "Results": [{"Target": "app", "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-0001", "PkgName": "libx", "Severity": "CRITICAL", "InstalledVersion": "1.0", "FixedVersion": "1.1"}],
                                "Secrets": [{"RuleID": "generic-secret", "Title": "API key", "Severity": "HIGH", "Match": "AKIA-VERY-SECRET"}]}]}
        events = security_ops.normalize("trivy", report)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["severity"], "critical")
        self.assertEqual(events[0]["details"]["package"], "libx")
        self.assertNotIn("AKIA-VERY-SECRET", json.dumps(events))

    def test_osquery_add_event_low_severity(self):
        out = security_ops.normalize("osquery", {"name": "process_events", "hostIdentifier": "node1",
            "unixTime": 1794220000, "action": "added", "columns": {"name": "unknown.bin", "path": "/tmp/unknown.bin", "password": "dont-store"}})[0]
        self.assertEqual(out["severity"], "low")
        self.assertNotIn("dont-store", json.dumps(out))

    def test_event_fingerprint_aggregates_repeated_rule(self):
        event = {"id": "w1", "timestamp": "2026-11-09T10:00:00Z", "rule": {"id": "5710", "level": 12, "description": "SSH auth failure"}, "agent": {"name": "n"}, "data": {"srcip": "203.0.113.7"}}
        first = self.add("wazuh", event)
        second = self.add("wazuh", {**event, "id": "w2", "timestamp": "2026-11-09T10:01:00Z"})
        self.assertEqual(first["incidents_touched"], 1)
        self.assertEqual(second["incidents_touched"], 1)
        incidents = security_ops.list_incidents(self.store)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_count"], 2)

    def test_duplicate_source_event_id_is_idempotent(self):
        event = {"time": "2026-11-09T10:00:00Z", "rule": "Test", "priority": "Error", "hostname": "node"}
        self.assertEqual(self.add("falco", event)["accepted"], 1)
        result = self.add("falco", event)
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(security_ops.overview(self.store)["events_total"], 1)

    def test_severity_escalation_uses_critical_as_highest(self):
        low = {"id": "w1", "timestamp": "2026-11-09T10:00:00Z", "rule": {"id": "5710", "level": 4, "description": "SSH auth failure"}, "agent": {"name": "n"}, "data": {"srcip": "203.0.113.7"}}
        high = {**low, "id": "w2", "rule": {"id": "5710", "level": 14, "description": "SSH auth failure"}}
        self.add("wazuh", low)
        self.add("wazuh", high)
        self.assertEqual(security_ops.list_incidents(self.store)[0]["severity"], "critical")

    def test_invalid_ip_is_discarded(self):
        out = security_ops.normalize("suricata", {"event_type": "alert", "src_ip": "999.999.1.2", "alert": {"severity": 2}})[0]
        self.assertIsNone(out["src_ip"])

    def test_unsupported_source_rejected(self):
        with self.assertRaisesRegex(ValueError, "security_source_not_supported"):
            security_ops.normalize("arbitrary", {})

    def test_batch_limit_enforced(self):
        with self.assertRaisesRegex(ValueError, "security_batch_invalid"):
            security_ops.ingest(self.store, "falco", [{"time": "x"}] * 101, "shipper")

    def test_event_details_are_bounded(self):
        out = security_ops.normalize("falco", {"time": "2026-11-09T10:00:00Z", "rule": "x", "priority": "Warning",
            "output": "x" * 50000, "hostname": "node"})[0]
        self.assertLessEqual(len(json.dumps(out["details"]).encode()), security_ops.MAX_DETAILS_BYTES)

    def test_incident_status_update(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Critical", "hostname": "node"})
        inc = security_ops.list_incidents(self.store)[0]
        result = security_ops.update_incident(self.store, inc["incident_id"], {"status": "acknowledged", "assigned_to": "analyst"}, "operator")
        self.assertEqual(result["status"], "acknowledged")
        self.assertEqual(result["assigned_to"], "analyst")

    def test_invalid_status_rejected(self):
        with self.assertRaisesRegex(ValueError, "security_invalid_status"):
            security_ops.update_incident(self.store, "missing", {"status": "do-everything"}, "operator")

    def test_incident_filters(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Critical process", "priority": "Critical", "hostname": "node"})
        self.assertEqual(len(security_ops.list_incidents(self.store, severity="critical")), 1)
        self.assertEqual(len(security_ops.list_incidents(self.store, status="resolved")), 0)

    def test_list_events_includes_context_only_zeek_and_filters(self):
        self.add("zeek", {"ts": 1794220000.1, "uid": "Cctx-list", "_path": "conn",
            "id.orig_h": "192.0.2.1", "id.resp_h": "192.0.2.2", "id.resp_p": 443})
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Warning", "hostname": "node-list"})
        all_events = security_ops.list_events(self.store, limit=250)
        self.assertGreaterEqual(len(all_events), 2)
        context = [x for x in all_events if x["source"] == "zeek"]
        self.assertTrue(context)
        self.assertIsNone(context[0]["incident_id"])
        self.assertEqual(security_ops.list_events(self.store, source="zeek")[0]["source"], "zeek")
        self.assertTrue(all(x["severity"] == "medium" for x in security_ops.list_events(self.store, severity="medium")))

    def test_list_events_rejects_unknown_source(self):
        with self.assertRaisesRegex(ValueError, "security_source_not_supported"):
            security_ops.list_events(self.store, source="unknown")

    def test_incident_not_found(self):
        with self.assertRaisesRegex(KeyError, "security_incident_not_found"):
            security_ops.incident_detail(self.store, "missing")

    def test_playbook_plan_requires_different_approver(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Warning", "hostname": "node"})
        inc = security_ops.list_incidents(self.store)[0]
        plan = security_ops.plan_playbook(self.store, inc["incident_id"], "incident_triage", self.analyst)
        with self.assertRaisesRegex(PermissionError, "security_two_person_approval_required"):
            security_ops.approve_playbook(self.store, plan["run_id"], self.analyst)
        approved = security_ops.approve_playbook(self.store, plan["run_id"], self.operator)
        self.assertEqual(approved["status"], "approved")

    def test_playbook_execution_returns_data_only_results(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Warning", "hostname": "node"})
        inc = security_ops.list_incidents(self.store)[0]
        plan = security_ops.plan_playbook(self.store, inc["incident_id"], "response_checklist", self.analyst)
        security_ops.approve_playbook(self.store, plan["run_id"], self.operator)
        result = security_ops.execute_playbook(self.store, plan["run_id"], self.operator)
        self.assertEqual(len(result["steps"]), 2)
        self.assertEqual(result["side_effects"], [])
        self.assertIn("checklist", result["steps"][-1])

    def test_detection_rule_is_cyberforge_format_not_sigma(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Warning", "hostname": "node"})
        inc = security_ops.list_incidents(self.store)[0]
        plan = security_ops.plan_playbook(self.store, inc["incident_id"], "detection_rule_draft", self.analyst)
        security_ops.approve_playbook(self.store, plan["run_id"], self.operator)
        result = security_ops.execute_playbook(self.store, plan["run_id"], self.operator)
        rule = result["steps"][-1]["rule"]
        self.assertEqual(rule["format"], "cyberforge.normalized-event-rule.v1")
        self.assertIn("not a Sigma rule", rule["note"])

    def test_playbook_cannot_execute_twice(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Warning", "hostname": "node"})
        inc = security_ops.list_incidents(self.store)[0]
        plan = security_ops.plan_playbook(self.store, inc["incident_id"], "incident_triage", self.analyst)
        security_ops.approve_playbook(self.store, plan["run_id"], self.operator)
        security_ops.execute_playbook(self.store, plan["run_id"], self.operator)
        with self.assertRaisesRegex(ValueError, "security_playbook_not_approved"):
            security_ops.execute_playbook(self.store, plan["run_id"], self.operator)

    def test_playbook_expiry(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Warning", "hostname": "node"})
        inc = security_ops.list_incidents(self.store)[0]
        plan = security_ops.plan_playbook(self.store, inc["incident_id"], "incident_triage", self.analyst)
        with patch("security_ops.time.time", return_value=time_value(plan["expires_at"] + 1)):
            with self.assertRaisesRegex(TimeoutError, "security_playbook_expired"):
                security_ops.approve_playbook(self.store, plan["run_id"], self.operator)
        with self.store.connect() as con:
            row = con.execute("SELECT status FROM security_playbook_runs WHERE run_id=?", (plan["run_id"],)).fetchone()
        self.assertEqual(row["status"], "expired")

    def test_overview_tracks_sources_and_recent_event_counts(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Warning", "hostname": "node"})
        ov = security_ops.overview(self.store)
        self.assertEqual(ov["events_total"], 1)
        self.assertEqual(ov["events_24h"], 1)
        self.assertEqual(ov["sources"][0]["source"], "falco")

    def test_database_persistence(self):
        self.add("falco", {"time": "2026-11-09T10:00:00Z", "rule": "Shell", "priority": "Warning", "hostname": "node"})
        reopened = Store(self.store.db_path)
        security_ops.initialize(reopened)
        self.assertEqual(security_ops.overview(reopened)["events_total"], 1)


def time_value(value):
    return float(value)


class SecurityOpsAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = Path(cls.tmp.name)
        cls.store = Store(cls.data / "server.sqlite3")
        cls.tokens = {role: cls.store.create_token(role, role)["token"] for role in ("admin", "operator", "analyst", "viewer", "sensor")}
        cls.ai = AIService(cls.store)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(cls.store, cls.ai, cls.data))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=3); cls.tmp.cleanup()

    def request(self, role, method, path, body=None, lang="en"):
        raw = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": "Bearer " + self.tokens[role], "Accept-Language": lang}
        if raw is not None: headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=raw, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                data = response.read()
                content_type = response.headers.get("Content-Type", "")
                return response.status, json.loads(data) if "json" in content_type else data.decode()
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_sensor_can_ingest_wazuh_alert(self):
        status, body = self.request("sensor", "POST", "/api/v203/security/ingest/wazuh", {"events": [{
            "id": "api-w1", "timestamp": "2026-11-09T10:00:00Z", "rule": {"id": "5710", "level": 12, "description": "SSH auth failure"},
            "agent": {"name": "linux-a"}, "data": {"srcip": "203.0.113.55"}}]})
        self.assertEqual(status, 202)
        self.assertEqual(body["result"]["accepted"], 1)

    def test_viewer_cannot_ingest(self):
        status, body = self.request("viewer", "POST", "/api/v203/security/ingest/falco", {"events": [{"rule": "test"}]})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")

    def test_unknown_source_rejected_with_clear_error(self):
        status, body = self.request("sensor", "POST", "/api/v203/security/ingest/other", {"events": [{}]})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "security_source_not_supported")

    def test_incident_reader_can_list_and_detail(self):
        status, body = self.request("analyst", "GET", "/api/v203/security/incidents")
        self.assertEqual(status, 200)
        self.assertIsInstance(body["incidents"], list)
        if body["incidents"]:
            incident_id = body["incidents"][0]["incident_id"]
            status2, detail = self.request("viewer", "GET", "/api/v203/security/incidents/" + incident_id)
            self.assertEqual(status2, 200)
            self.assertIn("events", detail)

    def test_viewer_can_list_normalized_events_including_context(self):
        status, _ = self.request("sensor", "POST", "/api/v203/security/ingest/zeek", {"events": [{
            "ts": 1794220000.1, "uid": "Capi-ctx", "_path": "conn",
            "id.orig_h": "192.0.2.11", "id.resp_h": "192.0.2.12", "id.resp_p": 443}]})
        self.assertEqual(status, 202)
        status, body = self.request("viewer", "GET", "/api/v203/security/events?source=zeek&limit=10")
        self.assertEqual(status, 200)
        self.assertTrue(body["events"])
        self.assertEqual(body["events"][0]["source"], "zeek")
        self.assertIsNone(body["events"][0]["incident_id"])

    def test_viewer_cannot_update_incident(self):
        incs = security_ops.list_incidents(self.store)
        self.assertTrue(incs)
        status, body = self.request("viewer", "POST", "/api/v203/security/incidents/update", {"incident_id": incs[0]["incident_id"], "status": "acknowledged"})
        self.assertEqual(status, 403)

    def test_analyst_plan_operator_approve_and_execute(self):
        status_seed, _ = self.request("sensor", "POST", "/api/v203/security/ingest/falco", {"events": [{"time": "2026-11-09T10:00:00Z", "rule": "Test shell", "priority": "Warning", "hostname": "playbook-node"}]})
        self.assertEqual(status_seed, 202)
        incs = security_ops.list_incidents(self.store)
        self.assertTrue(incs)
        incident_id = incs[0]["incident_id"]
        status, plan = self.request("operator", "POST", "/api/v203/security/playbooks/plan", {"incident_id": incident_id, "playbook_id": "incident_triage"})
        self.assertEqual(status, 201)
        status_self, self_error = self.request("operator", "POST", f"/api/v203/security/playbooks/{plan['run']['run_id']}/approve", {})
        self.assertEqual(status_self, 403)
        self.assertEqual(self_error["error"]["code"], "security_two_person_approval_required")
        status_approve, _ = self.request("admin", "POST", f"/api/v203/security/playbooks/{plan['run']['run_id']}/approve", {})
        self.assertEqual(status_approve, 200)
        status_execute, result = self.request("operator", "POST", f"/api/v203/security/playbooks/{plan['run']['run_id']}/execute", {})
        self.assertEqual(status_execute, 200)
        self.assertEqual(result["result"]["side_effects"], [])

    def test_error_message_is_localized_to_vietnamese(self):
        status, body = self.request("sensor", "POST", "/api/v203/security/ingest/nope", {"events": [{}]}, lang="vi-VN,vi;q=0.9")
        self.assertEqual(status, 400)
        self.assertIn("chưa được hỗ trợ", body["error"]["message"])

    def test_metrics_include_security_counts(self):
        status, body = self.request("admin", "GET", "/metrics")
        self.assertEqual(status, 200)
        self.assertIn("cyberforge_security_incidents_total", body)

    def test_playbook_catalog_requires_security_read(self):
        status, body = self.request("viewer", "GET", "/api/v203/security/playbooks")
        self.assertEqual(status, 200)
        self.assertIn("response_checklist", [p["id"] for p in body["playbooks"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
