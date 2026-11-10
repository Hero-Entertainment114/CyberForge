from __future__ import annotations

import json
import os
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
import detection_engine
import security_ops


def timestamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def rule_definition(title="Wazuh SSH auth finding"):
    return {
        "title": title,
        "description": "Detect a normalized Wazuh rule identifier in endpoint telemetry.",
        "source": "wazuh",
        "severity": "high",
        "tags": ["authentication", "endpoint"],
        "attack_ids": ["T1110"],
        "match": {"all": [
            {"field": "source", "op": "equals", "value": "wazuh"},
            {"field": "rule_id", "op": "equals", "value": "5710"},
        ]},
    }


class DetectionEngineUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "server.sqlite3")
        security_ops.initialize(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def seed_event(self, suffix="one", rule_id="5710"):
        return security_ops.ingest(self.store, "wazuh", [{
            "id": "detection-test-" + suffix,
            "timestamp": timestamp(),
            "rule": {"id": rule_id, "level": 12, "description": "SSH authentication failure"},
            "agent": {"name": "node-detection"},
        }], "sensor")

    def test_definition_normalizes_and_validates(self):
        result = detection_engine.validate_definition(rule_definition())
        self.assertTrue(result["valid"])
        self.assertEqual(result["condition_count"], 2)

    def test_rejects_arbitrary_regex_and_unknown_field(self):
        body = rule_definition()
        body["match"]["all"][0] = {"field": "source", "op": "regex", "value": ".*"}
        with self.assertRaisesRegex(ValueError, "detection_rule_invalid"):
            detection_engine.normalize_definition(body)
        body = rule_definition()
        body["match"]["all"][0] = {"field": "details.command_line", "op": "contains", "value": "curl"}
        with self.assertRaisesRegex(ValueError, "detection_rule_invalid"):
            detection_engine.normalize_definition(body)

    def test_requires_at_least_one_condition(self):
        body = rule_definition(); body["match"] = {"all": [], "any": []}
        with self.assertRaisesRegex(ValueError, "detection_rule_condition_required"):
            detection_engine.normalize_definition(body)

    def test_rejects_bad_attack_technique(self):
        body = rule_definition(); body["attack_ids"] = ["T1059.9999"]
        with self.assertRaisesRegex(ValueError, "detection_rule_invalid_attack_id"):
            detection_engine.normalize_definition(body)

    def test_create_validate_and_test_against_normalized_events(self):
        self.seed_event()
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        rid = created["rule_id"]
        validated = detection_engine.validate_rule(self.store, rid, "alice")
        self.assertTrue(validated["valid"])
        result = detection_engine.test_rule(self.store, rid, "alice")
        self.assertEqual(result["events_examined"], 1)
        self.assertEqual(result["matches"], 1)
        self.assertNotIn("details", result["matched_events"][0])

    def test_two_person_publish_required(self):
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        with self.assertRaisesRegex(PermissionError, "detection_two_person_publish_required"):
            detection_engine.publish_rule(self.store, created["rule_id"], "alice")
        published = detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        self.assertEqual(published["state"], "published")
        self.assertEqual(published["active_version"], 1)

    def test_published_rule_matches_events_during_ingestion(self):
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        result = self.seed_event("published")
        self.assertEqual(result["detection_matches"], 1)
        matches = detection_engine.list_matches(self.store)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_id"], created["rule_id"])

    def test_event_dedup_does_not_duplicate_detection_match(self):
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        first = self.seed_event("same-id")
        second = self.seed_event("same-id")
        self.assertEqual(first["detection_matches"], 1)
        self.assertEqual(second["detection_matches"], 0)
        self.assertEqual(len(detection_engine.list_matches(self.store)), 1)

    def test_nonmatching_event_does_not_create_match(self):
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        result = self.seed_event("nonmatch", "9999")
        self.assertEqual(result["detection_matches"], 0)

    def test_rule_revision_is_draft_while_previous_active_version_stays_active(self):
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        revised = rule_definition("Revised Wazuh SSH finding")
        updated = detection_engine.revise_draft(self.store, created["rule_id"], revised, "alice")
        self.assertEqual(updated["state"], "draft")
        self.assertEqual(updated["current_version"], 2)
        self.assertEqual(updated["active_version"], 1)
        self.seed_event("still-active")
        self.assertEqual(len(detection_engine.list_matches(self.store)), 1)

    def test_rollback_creates_new_draft_not_immediate_publish(self):
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        revised = rule_definition("Second version")
        revised["match"]["all"][1]["value"] = "9999"
        version2 = detection_engine.revise_draft(self.store, created["rule_id"], revised, "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        rolled = detection_engine.rollback_to_version(self.store, created["rule_id"], 1, "bob")
        self.assertEqual(rolled["state"], "draft")
        self.assertEqual(rolled["current_version"], 3)
        self.assertEqual(rolled["active_version"], 2)
        self.assertEqual(rolled["definition"]["title"], "Wazuh SSH auth finding")

    def test_retired_rule_stops_matching(self):
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        detection_engine.retire_rule(self.store, created["rule_id"], "bob")
        result = self.seed_event("retired")
        self.assertEqual(result["detection_matches"], 0)

    def test_summary_reports_attack_coverage(self):
        created = detection_engine.create_draft(self.store, rule_definition(), "alice")
        detection_engine.validate_rule(self.store, created["rule_id"], "alice")
        detection_engine.publish_rule(self.store, created["rule_id"], "bob")
        result = detection_engine.summary(self.store)
        self.assertEqual(result["published_rules"], 1)
        self.assertIn("T1110", result["attack_techniques_covered"])
        self.assertEqual(result["sigma_compatibility"], "not_claimed")


class DetectionEngineAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = Path(cls.tmp.name)
        cls.store = Store(cls.data / "server.sqlite3")
        cls.tokens = {role: cls.store.create_token("v210-" + role, role)["token"]
                      for role in ("admin", "operator", "analyst", "viewer", "sensor")}
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(cls.store, AIService(cls.store), cls.data))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=3); cls.tmp.cleanup()

    def request(self, role, method, path, body=None):
        raw = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Authorization": "Bearer " + self.tokens[role], "Accept-Language": "en"}
        if raw is not None: headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=raw, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_viewer_can_read_detection_summary(self):
        status, body = self.request("viewer", "GET", "/api/v210/detection/overview")
        self.assertEqual(status, 200)
        self.assertIn("published_rules", body)

    def test_sensor_cannot_read_detection_summary(self):
        status, body = self.request("sensor", "GET", "/api/v210/detection/overview")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")

    def test_analyst_can_create_draft_but_cannot_publish(self):
        status, body = self.request("analyst", "POST", "/api/v210/detection/rules", rule_definition())
        self.assertEqual(status, 201)
        rid = body["rule"]["rule_id"]
        self.assertEqual(self.request("analyst", "POST", f"/api/v210/detection/rules/{rid}/validate", {})[0], 200)
        status, body = self.request("analyst", "POST", f"/api/v210/detection/rules/{rid}/publish", {})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")

    def test_operator_can_publish_analyst_rule(self):
        status, body = self.request("analyst", "POST", "/api/v210/detection/rules", rule_definition("API-created rule"))
        rid = body["rule"]["rule_id"]
        self.assertEqual(self.request("analyst", "POST", f"/api/v210/detection/rules/{rid}/validate", {})[0], 200)
        status, body = self.request("operator", "POST", f"/api/v210/detection/rules/{rid}/publish", {})
        self.assertEqual(status, 200)
        self.assertEqual(body["rule"]["state"], "published")

    def test_admin_cannot_bypass_two_person_publish_by_self_approval(self):
        status, body = self.request("admin", "POST", "/api/v210/detection/rules", rule_definition("Admin rule"))
        rid = body["rule"]["rule_id"]
        self.request("admin", "POST", f"/api/v210/detection/rules/{rid}/validate", {})
        status, body = self.request("admin", "POST", f"/api/v210/detection/rules/{rid}/publish", {})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "detection_two_person_publish_required")

    def test_invalid_rule_definition_returns_localized_error(self):
        body = rule_definition(); body["match"] = {"all": [], "any": []}
        status, result = self.request("analyst", "POST", "/api/v210/detection/rules", body)
        self.assertEqual(status, 400)
        self.assertEqual(result["error"]["code"], "detection_rule_condition_required")
        self.assertTrue(result["error"]["message"])

    def test_rules_and_matches_are_available(self):
        status, body = self.request("viewer", "GET", "/api/v210/detection/rules")
        self.assertEqual(status, 200)
        self.assertIn("rules", body)
        status, body = self.request("viewer", "GET", "/api/v210/detection/matches")
        self.assertEqual(status, 200)
        self.assertIn("matches", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
