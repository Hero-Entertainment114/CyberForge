import io
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V090SecurityCenterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf090-test-")
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        base = Path(self.tmp.name)
        cf.DATA_DIR = base / "data"
        cf.DB_PATH = cf.DATA_DIR / "cyberforge.db"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.init_database()
        cf.VAULT_KEY = None
        cf.vault_create("unit-test-passphrase-123", "unit-test-passphrase-123")

    def tearDown(self):
        cf.VAULT_KEY = None
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old
        self.tmp.cleanup()

    def test_legacy_security_center_reports_current_version(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))

    def test_multiengine_static_scan_reports_independent_builtin_engines(self):
        with mock.patch.object(cf.shutil, "which", return_value=None):
            report = cf.multi_engine_scan_bytes(b"plain text sample", "notes.txt")
        names = {x["engine"] for x in report["engines"]}
        self.assertTrue({"CF Signature Scanner", "CF Script Inspector", "CF Structure & Entropy",
                         "CF Archive Inspector", "CF Local Hash Reputation"}.issubset(names))
        self.assertEqual(report["built_in_engines"], 5)
        self.assertIn("not_installed", {x["status"] for x in report["external_engine_status"]})
        self.assertIn("not uploaded", report["privacy"])

    def test_empty_file_is_reported_without_aborting_batch_scan(self):
        with mock.patch.object(cf.shutil, "which", return_value=None):
            report = cf.multi_engine_scan_bytes(b"", "empty.txt")
        self.assertEqual(report["size"], 0)
        self.assertEqual(report["kind"], "Empty file")
        self.assertEqual(len(report["sha256"]), 64)
        self.assertEqual(report["risk_score"], 0)

    def test_empty_executable_extension_is_flagged_as_format_mismatch(self):
        with mock.patch.object(cf.shutil, "which", return_value=None):
            report = cf.multi_engine_scan_bytes(b"", "empty.exe")
        self.assertTrue(any("extension and detected format mismatch" in x.get("title", "")
                            for e in report["engines"] for x in e.get("detections", [])))

    def test_eicar_is_only_reported_as_harmless_test_signature(self):
        with mock.patch.object(cf.shutil, "which", return_value=None):
            report = cf.multi_engine_scan_bytes(cf.EICAR_TEST_STRING, "eicar.com")
        self.assertTrue(any("EICAR harmless" in x.get("title", "") for x in report["engines"][0]["detections"]))
        self.assertEqual(report["risk_score"], 0)
        self.assertIn("Harmless EICAR", report["assessment"])
        self.assertTrue(any("never executed" in x for x in report["limitations"]))

    def test_script_inspector_finds_encoded_execution_indicators(self):
        data = b'powershell -enc '+b'A'*80+b' Invoke-Expression DownloadString'
        findings = cf._script_static_findings(data)
        self.assertTrue(findings)
        self.assertTrue(any("PowerShell" in x["title"] or "Encoded" in x["title"] for x in findings))

    def test_archive_inspector_flags_traversal_without_extracting(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as zf:
            zf.writestr("../../outside.txt", "harmless")
        result = cf._archive_member_findings(out.getvalue())
        self.assertIsNotNone(result)
        self.assertTrue(any("path traversal" in " ".join(x.get("warnings", [])) for x in result["flagged_members"]))
        self.assertIn("Nothing was extracted", result["note"])

    def test_url_scanner_flags_openphish_feed_match(self):
        feed_dir, feed_path, meta_path = cf._openphish_paths()
        feed_dir.mkdir(parents=True)
        feed_path.write_text("https://fake-login.example.test/auth\n", encoding="utf-8")
        meta_path.write_text(json.dumps({"updated_at": "2026-11-02T08:00:00+07:00"}), encoding="utf-8")
        result = cf.scan_suspicious_url("https://fake-login.example.test/auth")
        self.assertEqual(result["verdict"], "HIGH RISK")
        self.assertTrue(result["feed"]["match"])
        self.assertEqual(result["risk_score"], 100)

    def test_url_scanner_detects_lookalike_but_never_visits_url(self):
        with mock.patch.object(cf.urllib.request, "urlopen", side_effect=AssertionError("must not fetch target")):
            result = cf.scan_suspicious_url("https://faccbook.com/login/verify")
        codes = {x["code"] for x in result["flags"]}
        self.assertTrue({"BRAND_LOOKALIKE_CANDIDATE", "CREDENTIAL_LURE_WORDS"}.issubset(codes))
        self.assertIn("None.", result["network_actions"])

    def test_openphish_feed_refresh_uses_fixed_public_source_and_saves_local_copy(self):
        class FakeResponse:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return b"https://phish-example.test/login\nnot-a-url\n"
        with mock.patch.object(cf.urllib.request, "urlopen", return_value=FakeResponse()) as mocked:
            result = cf.refresh_openphish_feed()
        self.assertTrue(result["updated"])
        self.assertEqual(result["entries"], 1)
        feed_dir, feed_path, meta_path = cf._openphish_paths()
        self.assertTrue(feed_path.exists())
        self.assertTrue(meta_path.exists())
        self.assertEqual(mocked.call_args.args[0].full_url, cf.OPENPHISH_FEED_URL)
        self.assertIn("phish-example.test", feed_path.read_text(encoding="utf-8"))

    def test_url_scanner_rejects_non_web_schemes(self):
        with self.assertRaises(ValueError):
            cf.scan_suspicious_url("file:///etc/passwd")
        with self.assertRaises(ValueError):
            cf.scan_suspicious_url("javascript:alert(1)")

    def test_url_scanner_flags_credentials_in_authority(self):
        result = cf.scan_suspicious_url("https://user:pass@example.com/login")
        self.assertTrue(any(x["code"] == "CREDENTIALS_IN_AUTHORITY" for x in result["flags"]))

    def test_local_advisor_suggests_reviewable_code_changes(self):
        result = cf.local_ai_advisor("code", {"source": "yaml.load(user_input)\nrequests.get(url, verify=False)"})
        self.assertIsNotNone(result["fix_preview"])
        self.assertIn("yaml.safe_load", result["fix_preview"]["suggested_source"])
        self.assertIn("verify=True", result["fix_preview"]["suggested_source"])
        self.assertIn("does not overwrite", result["fix_preview"]["warning"])
        self.assertIn("not a generative LLM", result["capability_note"])

    def test_local_advisor_malware_guidance(self):
        result = cf.local_ai_advisor("file", {"name": "suspect.exe", "assessment": "Suspicious", "risk_score": 42, "engines": []})
        self.assertTrue(any("disposable VM" in x for x in result["recommended_actions"]))

    def test_http_routes_multiscan_url_and_advisor(self):
        server = ThreadingHTTPServer((cf.HOST, 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://{cf.HOST}:{server.server_address[1]}"
            req = Request(base + "/api/multiscan-upload", data=b"sample", method="POST",
                          headers={"Content-Type": "application/octet-stream", "X-File-Name": "sample.txt"})
            with mock.patch.object(cf.shutil, "which", return_value=None):
                with urlopen(req, timeout=5) as r:
                    data = json.loads(r.read())
            self.assertEqual(data["name"], "sample.txt")
            url_req = Request(base + "/api/security/url-scan", data=json.dumps({"url": "https://example.com/"}).encode(),
                              method="POST", headers={"Content-Type": "application/json"})
            with urlopen(url_req, timeout=5) as r:
                url_data = json.loads(r.read())
            self.assertEqual(url_data["hostname"], "example.com")
            ai_req = Request(base + "/api/security/ai-advisor", data=json.dumps({"kind": "general", "payload": {"text": "password token exposed"}}).encode(),
                             method="POST", headers={"Content-Type": "application/json"})
            with urlopen(ai_req, timeout=5) as r:
                ai_data = json.loads(r.read())
            self.assertTrue(ai_data["recommended_actions"])
            with urlopen(base + "/api/security/status", timeout=5) as r:
                status = json.loads(r.read())
            self.assertEqual(status["version"], cf.APP_VERSION)
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_ui_has_folder_scanner_url_checker_and_offline_ai(self):
        ui = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="multiFolder" webkitdirectory', ui)
        self.assertIn('id="threatUrl"', ui)
        self.assertIn('id="aiInput"', ui)
        self.assertIn("function scanMultiFiles", ui)
        self.assertIn("Offline Analyst", ui)


if __name__ == "__main__":
    unittest.main()
