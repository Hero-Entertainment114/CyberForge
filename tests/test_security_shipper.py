from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cf_ingest_jsonl", ROOT / "tools" / "ingest_jsonl.py")
shipper = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(shipper)


class ShipperTests(unittest.TestCase):
    def test_remote_http_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Remote CyberForge servers require HTTPS"):
            shipper.validate_server("http://cyberforge.example.net")

    def test_loopback_http_is_allowed(self):
        self.assertEqual(shipper.validate_server("http://127.0.0.1:8787/"), "http://127.0.0.1:8787")

    def test_userinfo_and_custom_path_are_rejected(self):
        for value in ("https://user:pass@example.net", "https://example.net/custom"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                shipper.validate_server(value)

    def test_jsonl_reads_object_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"id":"one"}\n\n{"id":"two"}\n', encoding="utf-8")
            rows = list(shipper.iter_records(path, "wazuh", "jsonl"))
            self.assertEqual(rows, [{"id": "one"}, {"id": "two"}])

    def test_trivy_secret_value_is_removed_before_transmission(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trivy.json"
            path.write_text(json.dumps({"CreatedAt": "2026-11-09T09:00:00Z", "Results": [{"Target": "app", "Secrets": [{
                "RuleID": "secret-rule", "Title": "Private key", "Severity": "HIGH", "Match": "PRIVATE-SECRET-CONTENT", "Code": {"Lines": [{"Content": "PRIVATE-SECRET-CONTENT"}]}
            }]}]}), encoding="utf-8")
            rows = list(shipper.iter_records(path, "trivy", "trivy"))
            encoded = json.dumps(rows)
            self.assertNotIn("PRIVATE-SECRET-CONTENT", encoded)
            self.assertEqual(rows[0]["Results"][0]["Secrets"][0]["RuleID"], "secret-rule")

    def test_token_file_requires_restrictive_permissions(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions required")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "token"
            path.write_text("cf_sensor_token", encoding="utf-8")
            os.chmod(path, 0o644)
            args = type("Args", (), {"token_file": str(path), "token_env": "CF_TEST_TOKEN"})()
            with self.assertRaisesRegex(ValueError, "0600"):
                shipper.load_token(args)
            os.chmod(path, 0o600)
            self.assertEqual(shipper.load_token(args), "cf_sensor_token")

    def test_jsonl_rejects_non_object_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('[1,2,3]\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not a JSON object"):
                list(shipper.iter_records(path, "wazuh", "jsonl"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
