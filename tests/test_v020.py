import hashlib
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V020WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf020-test-")
        base = Path(self.tmp.name)
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        cf.DATA_DIR = base / "data"
        cf.DB_PATH = cf.DATA_DIR / "test.sqlite3"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.init_database()
        cf.VAULT_KEY = None
        cf.vault_create("unit-test-passphrase-123", "unit-test-passphrase-123")
        self.case = cf.create_case({"title": "Test engagement", "scope": "Only local test data"})

    def tearDown(self):
        cf.VAULT_KEY = None
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old
        self.tmp.cleanup()

    def test_create_case_and_workspace_summary(self):
        self.assertEqual(self.case["status"], "open")
        self.assertEqual(cf.workspace_summary()["cases"], 1)

    def test_case_validation(self):
        with self.assertRaises(ValueError):
            cf.create_case({"title": ""})
        with self.assertRaises(ValueError):
            cf.update_case({"id": self.case["id"], "status": "pwned"})

    def test_asset_scope_validation_and_duplicate(self):
        asset = cf.save_asset({"case_id": self.case["id"], "name": "My domain", "asset_type": "domain",
                               "identifier": "example.org", "scope_status": "in_scope"})
        self.assertEqual(asset["identifier"], "example.org")
        with self.assertRaises(ValueError):
            cf.save_asset({"case_id": self.case["id"], "name": "Bad url", "asset_type": "url",
                           "identifier": "javascript:alert(1)", "scope_status": "in_scope"})
        with self.assertRaises(ValueError):
            cf.save_asset({"case_id": self.case["id"], "name": "Duplicate", "asset_type": "domain",
                           "identifier": "example.org", "scope_status": "in_scope"})

    def test_finding_must_belong_to_case_asset(self):
        asset = cf.save_asset({"case_id": self.case["id"], "name": "Repo", "asset_type": "repository",
                               "identifier": "local-repo", "scope_status": "in_scope"})
        finding = cf.save_finding({"case_id": self.case["id"], "asset_id": asset["id"], "title": "Unsafe eval",
                                   "severity": "high", "confidence": 88})
        self.assertEqual(finding["severity"], "high")
        with self.assertRaises(ValueError):
            cf.save_finding({"case_id": self.case["id"], "asset_id": "not-an-asset", "title": "Bad"})

    def test_evidence_stored_hashed_and_download_verified(self):
        content = b"evidence bytes - not executable"
        evidence = cf.store_evidence(content, "trace.log", self.case["id"], "Collected during lab test")
        self.assertEqual(evidence["sha256"], hashlib.sha256(content).hexdigest())
        row, downloaded = cf.get_evidence_bytes(evidence["id"])
        self.assertEqual(downloaded, content)
        cf.delete_evidence(evidence["id"])
        with self.assertRaises(ValueError):
            cf.get_evidence_bytes(evidence["id"])

    def test_ioc_workflow_persists_run_and_finding(self):
        out = cf.run_case_workflow({"case_id": self.case["id"], "workflow_id": "ioc_triage",
                                    "source": "ERROR from 192.0.2.20 https://example.org/a"})
        self.assertEqual(out["workflow_id"], "ioc_triage")
        self.assertEqual(len(cf.list_workflow_runs(self.case["id"])), 1)
        self.assertGreaterEqual(len(cf.list_findings(self.case["id"])), 1)

    def test_source_review_workflow_records_findings_without_execution(self):
        source = "import os\npassword = 'secret'\neval(input())\n"
        out = cf.run_case_workflow({"case_id": self.case["id"], "workflow_id": "source_review",
                                    "source": source, "language": "python"})
        self.assertIn("heuristic_sast", out["result"])
        self.assertGreaterEqual(out["result"]["findings_saved"], 1)

    def test_web_workflow_requires_authorization_and_in_scope_asset(self):
        with self.assertRaises(PermissionError):
            cf.run_case_workflow({"case_id": self.case["id"], "workflow_id": "web_baseline",
                                  "target": "example.org", "authorized": False})
        with self.assertRaises(PermissionError):
            cf.run_case_workflow({"case_id": self.case["id"], "workflow_id": "web_baseline",
                                  "target": "example.org", "authorized": True})
        cf.save_asset({"case_id": self.case["id"], "name": "Example", "asset_type": "domain",
                       "identifier": "example.org", "scope_status": "out_of_scope"})
        with self.assertRaises(PermissionError):
            cf.run_case_workflow({"case_id": self.case["id"], "workflow_id": "web_baseline",
                                  "target": "example.org", "authorized": True})

    def test_capture_result_links_legacy_module_output_to_case(self):
        captured = cf.capture_case_result({"case_id": self.case["id"], "module_id": "static_file_triage",
                                           "summary": "Static sample report", "result": {"sha256": "a" * 64}})
        self.assertEqual(captured["status"], "captured")
        self.assertEqual(captured["result"]["sha256"], "a" * 64)
        self.assertEqual(cf.list_workflow_runs(self.case["id"])[0]["workflow_id"], "module_capture:static_file_triage")
        with self.assertRaises(ValueError):
            cf.capture_case_result({"case_id": self.case["id"], "module_id": "raw_shell", "result": "no"})

    def test_case_report_includes_related_records(self):
        cf.save_asset({"case_id": self.case["id"], "name": "Repo", "asset_type": "repository",
                       "identifier": "local-repo", "scope_status": "in_scope"})
        report = cf.case_report(self.case["id"])
        self.assertEqual(report["schema"], "cyberforge.case-report.v1")
        self.assertEqual(report["case"]["id"], self.case["id"])
        self.assertEqual(len(report["assets"]), 1)


if __name__ == "__main__":
    unittest.main()
