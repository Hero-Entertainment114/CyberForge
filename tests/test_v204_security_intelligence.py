from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
import unittest
from pathlib import Path

import security_ops
import security_intelligence
from server_core import Store


class SecurityIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "server.sqlite3")
        security_ops.initialize(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def ingest(self, source, event):
        return security_ops.ingest(self.store, source, [event], "sensor")

    def test_falco_enrichment_extracts_pid_and_process_without_cmdline(self):
        event = security_ops.normalize("falco", {
            "time": "2026-11-09T10:00:00Z", "hostname": "node-a", "rule": "Terminal shell in container",
            "priority": "Warning", "output": "shell started password=hunter2",
            "output_fields": {"proc.pid": 4321, "proc.ppid": 100, "proc.name": "bash",
                             "proc.exepath": "/usr/bin/bash", "proc.cmdline": "bash -c secret=not-for-store",
                             "container.id": "container-abc", "user.name": "analyst"}
        })[0]
        entities = event["details"]["entities"]
        self.assertEqual(entities["process_pid"], 4321)
        self.assertEqual(entities["parent_pid"], 100)
        self.assertEqual(entities["process_name"], "bash")
        encoded = json.dumps(event["details"])
        self.assertNotIn("proc.cmdline", encoded)
        self.assertNotIn("hunter2", encoded)
        self.assertNotIn("not-for-store", encoded)


    def test_host_name_is_not_misclassified_as_network_domain(self):
        event = security_ops.normalize("falco", {
            "time": "2026-11-09T10:00:00Z", "hostname": "prod-node-01", "rule": "Package check",
            "priority": "Warning", "output_fields": {"proc.name": "dpkg"}
        })[0]
        self.assertNotIn("domain", event["details"].get("entities", {}))

    def test_wazuh_process_metadata_and_mitre_candidate(self):
        event = security_ops.normalize("wazuh", {
            "id": "wazuh-1", "timestamp": "2026-11-09T10:00:00Z",
            "rule": {"id": "90001", "level": 12, "description": "Suspicious bash shell command execution"},
            "agent": {"id": "node-1", "name": "linux-a"},
            "data": {"pid": "77", "process": "bash", "exe": "/bin/bash"}
        })[0]
        self.assertEqual(event["details"]["entities"]["process_pid"], 77)
        ids = {x["id"] for x in event["details"]["mitre_candidates"]}
        self.assertIn("T1059.004", ids)

    def test_file_hash_mitre_and_entities_are_allowlisted(self):
        event = security_ops.normalize("falco", {
            "time": "2026-11-09T10:00:00Z", "hostname": "node", "rule": "Credential dump detected",
            "priority": "Error", "output_fields": {"proc.pid": 99, "proc.name": "mimikatz"},
            "sha256": "a" * 64, "api_key": "very-secret"
        })[0]
        self.assertEqual(event["details"]["entities"]["file_sha256"], "a" * 64)
        ids = {x["id"] for x in event["details"]["mitre_candidates"]}
        self.assertIn("T1003", ids)
        self.assertNotIn("very-secret", json.dumps(event))

    def test_cross_source_correlates_same_host_and_pid(self):
        self.ingest("wazuh", {
            "id": "wz-1", "timestamp": "2026-11-09T10:00:00Z",
            "rule": {"id": "90001", "level": 12, "description": "Suspicious shell process"},
            "agent": {"id": "node-x", "name": "node-x"},
            "data": {"pid": 4321, "process": "bash"}
        })
        self.ingest("falco", {
            "time": "2026-11-09T10:01:00Z", "hostname": "node-x", "rule": "Terminal shell in container",
            "priority": "Warning", "output_fields": {"proc.pid": 4321, "proc.name": "bash"}
        })
        incidents = security_ops.list_incidents(self.store)
        self.assertEqual(len(incidents), 2)
        result = security_intelligence.correlate_incident(self.store, incidents[0]["incident_id"], persist=True)
        self.assertEqual(len(result["links"]), 1)
        self.assertGreaterEqual(result["links"][0]["confidence"], 0.9)

    def test_correlation_persists_canonical_link_only_once(self):
        self.ingest("wazuh", {
            "id": "wz-2", "timestamp": "2026-11-09T10:00:00Z",
            "rule": {"id": "1", "level": 12, "description": "bash shell execution"},
            "agent": {"id": "node-y", "name": "node-y"}, "data": {"pid": 123, "process": "bash"}
        })
        self.ingest("falco", {"time": "2026-11-09T10:02:00Z", "hostname": "node-y", "rule": "shell",
            "priority": "Warning", "output_fields": {"proc.pid": 123, "proc.name": "bash"}})
        incident = security_ops.list_incidents(self.store)[0]
        first = security_intelligence.correlate_incident(self.store, incident["incident_id"])
        second = security_intelligence.correlate_incident(self.store, incident["incident_id"])
        self.assertEqual(len(first["links"]), 1)
        self.assertEqual(len(second["links"]), 1)
        with self.store.connect() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) n FROM security_incident_links").fetchone()["n"], 1)

    def test_common_host_alone_is_not_enough_to_correlate(self):
        self.ingest("wazuh", {"id": "wz-3", "timestamp": "2026-11-09T10:00:00Z",
            "rule": {"id": "1", "level": 12, "description": "SSH authentication failure"},
            "agent": {"id": "node-z", "name": "node-z"}, "data": {"srcip": "203.0.113.10"}})
        self.ingest("falco", {"time": "2026-11-09T10:01:00Z", "hostname": "node-z", "rule": "Unrelated package check",
            "priority": "Warning", "output_fields": {"proc.name": "package-manager"}})
        incident = security_ops.list_incidents(self.store)[0]
        result = security_intelligence.correlate_incident(self.store, incident["incident_id"])
        self.assertEqual(result["links"], [])

    def test_same_sha256_correlates_across_hosts(self):
        digest = "b" * 64
        self.ingest("falco", {"time": "2026-11-09T10:00:00Z", "hostname": "node-a", "rule": "Suspicious file",
            "priority": "Error", "sha256": digest})
        self.ingest("falco", {"time": "2026-11-09T10:01:00Z", "hostname": "node-b", "rule": "Different suspicious file",
            "priority": "Warning", "sha256": digest})
        incident = security_ops.list_incidents(self.store)[0]
        result = security_intelligence.correlate_incident(self.store, incident["incident_id"])
        self.assertEqual(result["links"][0]["confidence"], 0.99)
        self.assertIn("same_file_sha256", result["links"][0]["evidence"]["evidence"])

    def test_context_event_is_returned_and_added_to_incident_timeline(self):
        import time
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.ingest("wazuh", {"id": "wz-context-seed", "timestamp": now,
            "rule": {"id": "ssh-context", "level": 12, "description": "SSH auth failure from 203.0.113.44"},
            "agent": {"id": "node-c", "name": "node-c"}, "data": {"srcip": "203.0.113.44"}})
        self.ingest("zeek", {"ts": time.time(), "uid": "CTX44", "_path": "conn", "host": "node-c",
            "id.orig_h": "203.0.113.44", "id.resp_h": "198.51.100.4", "id.resp_p": 443})
        incident = security_ops.list_incidents(self.store)[0]
        result = security_intelligence.correlate_incident(self.store, incident["incident_id"])
        self.assertTrue(result["context_events"])
        self.assertIsNone(security_ops.list_events(self.store, source="zeek")[0]["incident_id"])
        analysis = security_intelligence.incident_analysis(self.store, incident["incident_id"])
        self.assertTrue(any(x.get("context_only") for x in analysis["timeline"]))

    def test_incident_analysis_contains_timeline_attack_candidates_and_caveat(self):
        self.ingest("falco", {"time": "2026-11-09T10:00:00Z", "hostname": "node-d", "rule": "Terminal shell in container",
            "priority": "Warning", "output_fields": {"proc.pid": 42, "proc.name": "bash"}})
        incident = security_ops.list_incidents(self.store)[0]
        result = security_intelligence.incident_analysis(self.store, incident["incident_id"])
        self.assertTrue(result["timeline"])
        self.assertIn("T1059.004", {x["id"] for x in result["attack_techniques"]})
        self.assertIn("candidate", result["confidence_note"].lower())
        self.assertIn("response_checklist", result["recommended_playbooks"])

    def test_read_only_analysis_does_not_persist_links(self):
        self.ingest("falco", {"time": "2026-11-09T10:00:00Z", "hostname": "node-e", "rule": "Terminal shell",
            "priority": "Warning", "output_fields": {"proc.pid": 42, "proc.name": "bash"}})
        self.ingest("wazuh", {"id": "wz-4", "timestamp": "2026-11-09T10:01:00Z", "rule": {"id": "1", "level": 12, "description": "shell"},
            "agent": {"id": "node-e", "name": "node-e"}, "data": {"pid": 42, "process": "bash"}})
        incident = security_ops.list_incidents(self.store)[0]
        security_intelligence.incident_analysis(self.store, incident["incident_id"])
        with self.store.connect() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) n FROM security_incident_links").fetchone()["n"], 0)

    def test_ai_prompt_contains_no_raw_payload_or_secret(self):
        self.ingest("falco", {"time": "2026-11-09T10:00:00Z", "hostname": "node-f", "rule": "Credential dump",
            "priority": "Error", "output": "secret=PRIVATEVALUE", "output_fields": {"proc.name": "mimikatz"}})
        incident = security_ops.list_incidents(self.store)[0]
        analysis = security_intelligence.incident_analysis(self.store, incident["incident_id"])
        encoded = json.dumps(security_intelligence.build_ai_messages(analysis))
        self.assertNotIn("PRIVATEVALUE", encoded)
        self.assertIn("Observed facts", encoded)

    def test_mitre_coverage_aggregates_candidate_labels(self):
        self.ingest("falco", {"time": "2026-11-09T10:00:00Z", "hostname": "node-g", "rule": "bash shell",
            "priority": "Warning", "output_fields": {"proc.name": "bash"}})
        result = security_intelligence.mitre_coverage(self.store)
        self.assertIn("T1059.004", {x["id"] for x in result["techniques"]})
        self.assertEqual(result["mapping_type"], "heuristic_candidate")

    def test_invalid_correlation_window_rejected(self):
        with self.assertRaisesRegex(ValueError, "security_correlation_invalid_window"):
            security_intelligence.correlate_incident(self.store, "missing", window_minutes=999)

    def test_unknown_incident_rejected(self):
        with self.assertRaisesRegex(KeyError, "security_incident_not_found"):
            security_intelligence.incident_analysis(self.store, "missing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
