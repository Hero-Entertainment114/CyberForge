import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V040Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf040-test-")
        base = Path(self.tmp.name)
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.ROOT)
        cf.DATA_DIR = base / "data"
        cf.DB_PATH = cf.DATA_DIR / "test.sqlite3"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.ROOT = base
        cf.init_database()
        cf.VAULT_KEY = None
        cf.vault_create("unit-test-passphrase-123", "unit-test-passphrase-123")
        self.case = cf.create_case({"title": "v0.4.0 test case", "scope": "test-only"})

    def tearDown(self):
        cf.VAULT_KEY = None
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.ROOT = self.old
        self.tmp.cleanup()

    def test_cvss_31_known_critical_vector(self):
        out = cf._parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(out["score"], 9.8)
        self.assertEqual(out["severity"], "critical")

    def test_cvss_requires_complete_valid_vector(self):
        with self.assertRaises(ValueError):
            cf._parse_cvss31("CVSS:3.1/AV:N/AC:L")
        with self.assertRaises(ValueError):
            cf._parse_cvss31("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_sbom_python_requirements(self):
        sbom = cf.generate_sbom("requests==2.31.0\nflask==3.0.0", "requirements.txt")
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(len(sbom["components"]), 2)

    def test_sbom_package_json(self):
        src = json.dumps({"dependencies": {"express": "^4.18.2"}, "devDependencies": {"vite": "5.1.0"}})
        out = cf.generate_sbom(src, "package.json")
        self.assertEqual(len(out["components"]), 2)
        self.assertTrue(all(x["purl"].startswith("pkg:npm/") for x in out["components"]))

    def test_sbom_bad_json_rejected(self):
        with self.assertRaises(ValueError):
            cf.generate_sbom("{bad", "package.json")

    def test_cve_upsert_and_exact_version_match(self):
        cf.upsert_cve({"cve_id": "CVE-2024-12345", "package_name": "requests", "ecosystem": "pypi",
                       "affected_versions": ["2.31.0"], "cvss": 8.1, "description": "test advisory"})
        result = cf.sbom_audit("requests==2.31.0", "requirements.txt", self.case["id"])
        self.assertEqual(len(result["local_advisory_matches"]), 1)
        self.assertEqual(result["findings_saved"], 1)
        clean = cf.sbom_audit("requests==2.32.0", "requirements.txt")
        self.assertEqual(len(clean["local_advisory_matches"]), 0)

    def test_cve_import_generic_feed(self):
        feed = [{"cve_id": "CVE-2023-1234", "package_name": "urllib3", "ecosystem": "pypi",
                 "affected_versions": ["1.0"], "severity": "high", "cvss": 7.5}]
        result = cf.import_cve_feed(json.dumps(feed), "unit-test-feed")
        self.assertEqual(result["imported"], 1)
        self.assertEqual(cf.list_cves()[0]["source"], "unit-test-feed")

    def test_ioc_feed_import_dedup_and_correlation(self):
        a = cf.import_ioc_feed("192.0.2.10\nevil-example.com\nhttps://evil-example.com/a", "feed-A", 75, ["test"])
        b = cf.import_ioc_feed("192.0.2.10", "feed-A", 75)
        self.assertEqual(a["imported"], 3)
        self.assertEqual(b["imported"], 0)
        out = cf.correlate_iocs("connection to 192.0.2.10 and evil-example.com")
        self.assertEqual(out["matched_count"], 2)

    def test_stix_indicator_import(self):
        bundle = {"type": "bundle", "objects": [{"type": "indicator", "pattern_type": "stix",
                  "pattern": "[ipv4-addr:value = '192.0.2.99']"}]}
        out = cf.import_ioc_feed(json.dumps(bundle), "stix-unit")
        self.assertEqual(out["imported"], 1)

    def test_apk_static_triage_no_execution(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("AndroidManifest.xml", '<manifest package="org.example"><uses-permission android:name="android.permission.READ_SMS" xmlns:android="http://schemas.android.com/apk/res/android"/></manifest>')
            z.writestr("classes.dex", b"dex\n035")
            z.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFsample")
        out = cf.analyze_forensic_bytes(b.getvalue(), "sample.apk")
        self.assertEqual(out["kind"], "Android APK archive")
        self.assertEqual(len(out["dex_files"]), 1)
        self.assertIn("android.permission.READ_SMS", out["permissions"])

    def test_firmware_signature_scan(self):
        out = cf.analyze_forensic_bytes(b"HEAD" + b"\x7fELF" + b"x" * 100 + b"hsqs", "router.img")
        self.assertEqual(out["kind"], "Firmware / embedded binary triage")
        self.assertGreaterEqual(len(out["embedded_signatures"]), 2)

    def test_browser_sqlite_history_read_only(self):
        tmp = Path(self.tmp.name) / "History"
        con = sqlite3.connect(tmp)
        con.execute("CREATE TABLE urls(url TEXT,title TEXT,visit_count INTEGER,last_visit_time INTEGER)")
        con.execute("INSERT INTO urls VALUES(?,?,?,?)", ("https://example.org", "Example", 3, 123))
        con.commit(); con.close()
        out = cf.analyze_forensic_bytes(tmp.read_bytes(), "History.db")
        self.assertEqual(out["schema"], "Chromium History")
        self.assertEqual(out["records_preview"][0]["url"], "https://example.org")

    def test_pe_deep_parser_rejects_truncated_dos_and_bad_signature(self):
        self.assertIsNone(cf._pe_deep_info(b"not a PE"))
        out = cf._pe_deep_info(b"MZ" + b"\x00" * 100)
        self.assertIsNotNone(out)
        self.assertFalse(out["valid_pe"])

    def test_evtx_triage_has_explicit_fallback_state(self):
        out = cf.analyze_forensic_bytes(b"ElfFile\x00" + b"System\x00Provider\x00" * 16, "sample.evtx")
        self.assertEqual(out["kind"], "Windows EVTX")
        self.assertIn(out["parser"], {"not installed", "python-evtx", "python-evtx error"})

    def test_registry_signature_routes_to_registry_analyzer(self):
        out = cf.analyze_forensic_bytes(b"regf" + b"x" * 100, "SYSTEM.hive")
        self.assertEqual(out["kind"], "Windows Registry hive")

    def test_generic_dat_not_forced_to_registry(self):
        out = cf.analyze_forensic_bytes(b"plain data", "misc.dat")
        self.assertEqual(out["kind"], "Generic forensic file")

    def test_audit_chain_integrity_and_tamper_detection(self):
        cf.create_case({"title": "second case"})
        self.assertTrue(cf.verify_audit_chain()["valid"])
        con = cf._db_connect()
        try:
            con.execute("UPDATE activity SET summary='tampered' WHERE id=1")
            con.commit()
        finally:
            con.close()
        self.assertFalse(cf.verify_audit_chain()["valid"])

    def test_custom_workflow_allowlist(self):
        wf = cf.save_custom_workflow({"name": "Log pipeline", "steps": [{"type": "ioc_triage"}]})
        out = cf.run_custom_workflow({"id": wf["id"], "case_id": self.case["id"],
                                      "inputs": {"log_source": "error connecting from 192.0.2.10"}})
        self.assertEqual(out["status"], "completed")
        with self.assertRaises(ValueError):
            cf.save_custom_workflow({"name": "Unsafe", "steps": [{"type": "shell"}]})


    def test_unlocked_manifest_constraint_is_not_claimed_as_resolved_version(self):
        sbom = cf.generate_sbom("urllib3>=2.0", "requirements.txt")
        comp = sbom["components"][0]
        self.assertEqual(comp["version"], "unknown")
        self.assertIn("declared-constraint", comp["properties"][-1]["name"])

    def test_cve_vector_score_is_used_when_imported(self):
        item = cf.upsert_cve({"cve_id": "CVE-2024-54321", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        self.assertEqual(item["cvss"], 9.8)
        self.assertEqual(item["severity"], "critical")


    def test_legacy_v020_activity_migration(self):
        legacy = Path(self.tmp.name) / "legacy.sqlite3"
        con = sqlite3.connect(legacy)
        con.executescript("CREATE TABLE activity(id INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT NOT NULL,entity_type TEXT NOT NULL,entity_id TEXT NOT NULL DEFAULT '',summary TEXT NOT NULL,detail_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL); INSERT INTO activity(action,entity_type,entity_id,summary,detail_json,created_at) VALUES('legacy','case','OLD','old event','{}','2026-10-30T10:00:00+00:00');")
        con.commit(); con.close()
        current = cf.DB_PATH
        cf.DB_PATH = legacy
        try:
            cf.init_database()
            self.assertTrue(cf.verify_audit_chain()["valid"])
            check = sqlite3.connect(legacy)
            try:
                cols = {r[1] for r in check.execute("PRAGMA table_info(activity)")}
            finally:
                check.close()
            self.assertIn("event_hash", cols)
        finally:
            cf.DB_PATH = current

    def test_http_api_v040_smoke(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with urllib.request.urlopen(base + "/api/version", timeout=3) as r:
                self.assertEqual(json.loads(r.read())["version"], cf.APP_VERSION)
            req = urllib.request.Request(base + "/api/sbom/generate", data=json.dumps({"source":"requests==2.31.0","filename":"requirements.txt"}).encode(), headers={"Content-Type":"application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=3) as r:
                self.assertEqual(json.loads(r.read())["bomFormat"], "CycloneDX")
            req = urllib.request.Request(base + "/api/forensics/analyze", data=b"\x7fELF"+b"x"*80, headers={"X-File-Name":"sample.elf"}, method="POST")
            with urllib.request.urlopen(req, timeout=3) as r:
                self.assertEqual(json.loads(r.read())["kind"], "Generic forensic file")
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_case_html_report_and_backup_include_evidence(self):
        evidence = cf.store_evidence(b"test evidence", "trace.txt", self.case["id"])
        report = cf.case_report(self.case["id"])
        self.assertTrue(report["audit_integrity"]["valid"])
        html = cf.case_report_html(self.case["id"])
        self.assertIn("CyberForge Case Report", html)
        backup = cf.export_case_backup(self.case["id"])
        with zipfile.ZipFile(io.BytesIO(backup)) as z:
            self.assertIn("report.json", z.namelist())
            self.assertIn("manifest.json", z.namelist())
            self.assertTrue(any(x.startswith(("evidence-encrypted/", "evidence-legacy/")) for x in z.namelist()))


if __name__ == "__main__":
    unittest.main()
