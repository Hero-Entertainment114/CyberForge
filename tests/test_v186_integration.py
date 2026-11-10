"""System integration, recovery and runtime reliability tests for CyberForge v1.8.6."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class IntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf186-integration-")
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.RECOVERY_BACKUP_RETENTION)
        base = Path(self.tmp.name) / "data"
        cf.DATA_DIR = base
        cf.DB_PATH = base / "cyberforge.db"
        cf.EVIDENCE_DIR = base / "evidence"
        cf.RECOVERY_BACKUP_RETENTION = 8
        cf.init_database()

    def tearDown(self):
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.RECOVERY_BACKUP_RETENTION = self.old
        self.tmp.cleanup()

    def add_case(self):
        con = cf._db_connect()
        try:
            con.execute(
                "INSERT INTO cases(id,title,description,scope,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                ("CASE-INT-01", "Integration fixture", "test record", "local test", "open", "normal", cf._now(), cf._now()),
            )
            con.commit()
        finally:
            con.close()

    @staticmethod
    def plugin_package(plugin_id="test.integrity-plugin", version="1.0.0"):
        import base64
        import hashlib
        import io
        import zipfile
        manifest = {
            "id": plugin_id, "name": "Integrity fixture", "version": version,
            "api_version": "1", "description": "Test plugin", "runtime": "python:3.12-alpine",
            "entrypoint": "plugin.py", "capabilities": ["knowledge.read"], "required_permissions": [],
        }
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            archive.writestr("plugin.py", "print('{}')\n")
        value = raw.getvalue()
        return {"archive_base64": base64.b64encode(value).decode(), "sha256": hashlib.sha256(value).hexdigest(), "acknowledged": True}


class HealthReportTests(IntegrationTestCase):
    def test_01_fresh_install_reports_core_components(self):
        report = cf.system_health_report()
        self.assertIn(report["status"], {"healthy", "warning"})
        components = {item["component"] for item in report["checks"]}
        self.assertTrue({"database", "storage", "engine_registry", "plugin_registry", "engines", "plugins", "audit", "dependencies"}.issubset(components))

    def test_02_database_integrity_is_ok_on_new_profile(self):
        database = next(x for x in cf.system_health_report()["checks"] if x["component"] == "database")
        self.assertEqual(database["status"], "ok")
        self.assertEqual(database["journal_mode"].lower(), "wal")

    def test_03_audit_chain_tampering_is_critical(self):
        self.add_case()
        con = cf._db_connect()
        try:
            cf._audit(con, "fixture", "test", "tamper", "Integrity test fixture", {})
            con.commit()
            con.execute("UPDATE activity SET event_hash=? WHERE id=(SELECT MAX(id) FROM activity)", ("f" * 64,))
            con.commit()
        finally:
            con.close()
        report = cf.system_health_report()
        audit = next(x for x in report["checks"] if x["component"] == "audit")
        self.assertEqual(audit["status"], "critical")
        self.assertEqual(report["status"], "critical")

    def test_04_write_probe_is_removed_after_health_check(self):
        cf._recovery_backup_root()
        before = set(cf.DATA_DIR.iterdir())
        cf.system_health_report()
        after = set(cf.DATA_DIR.iterdir())
        self.assertEqual(before, after)

    def test_05_diagnostics_permission_is_read_only_allow_by_default(self):
        self.assertEqual(cf.PREFERENCE_DEFAULTS["permissions"]["system_diagnostics"], "allow")
        self.assertEqual(cf._api_capabilities("GET", "/api/system/health"), ["system_diagnostics"])

    def test_06_maintenance_permission_is_ask_by_default(self):
        self.assertEqual(cf.PREFERENCE_DEFAULTS["permissions"]["system_maintenance"], "ask")
        self.assertEqual(cf._api_capabilities("POST", "/api/system/backup", {}), ["system_maintenance"])

    def test_07_legacy_profile_receives_new_capabilities_without_losing_locale(self):
        legacy = {"localization": {"locale": "en"}, "permissions": {"case_read": "allow"}}
        profile = cf._validate_preferences(legacy)
        self.assertEqual(profile["localization"]["locale"], "en")
        self.assertEqual(profile["permissions"]["system_maintenance"], "ask")
        self.assertEqual(profile["permissions"]["case_read"], "allow")


class DatabaseRecoveryTests(IntegrationTestCase):
    def test_08_online_backup_is_created_and_verified(self):
        self.add_case()
        result = cf.create_recovery_backup({"acknowledged": True})
        self.assertTrue(result["created"])
        self.assertEqual(result["integrity"], "ok")
        verify = cf.verify_recovery_backup({"backup_name": result["name"], "acknowledged": True})
        self.assertTrue(verify["valid"])
        self.assertEqual(verify["sha256"], result["sha256"])

    def test_09_backup_is_a_consistent_snapshot(self):
        self.add_case()
        result = cf.create_recovery_backup({"acknowledged": True})
        con = cf._db_connect()
        try:
            con.execute("UPDATE cases SET status='resolved' WHERE id='CASE-INT-01'")
            con.commit()
        finally:
            con.close()
        backup = cf._recovery_backup_root() / result["name"]
        snap = __import__("sqlite3").connect(str(backup))
        try:
            status = snap.execute("SELECT status FROM cases WHERE id='CASE-INT-01'").fetchone()[0]
        finally:
            snap.close()
        self.assertEqual(status, "open")

    def test_10_backup_requires_explicit_acknowledgement(self):
        with self.assertRaises(PermissionError):
            cf.create_recovery_backup({})

    def test_11_backup_name_rejects_path_traversal(self):
        with self.assertRaises(ValueError):
            cf.verify_recovery_backup({"backup_name": "../cyberforge-db-20261104T000000Z-deadbeef.sqlite3", "acknowledged": True})

    def test_12_backup_verification_detects_corruption(self):
        result = cf.create_recovery_backup({"acknowledged": True})
        path = cf._recovery_backup_root() / result["name"]
        path.write_bytes(b"not a sqlite database")
        verification = cf.verify_recovery_backup({"backup_name": result["name"], "acknowledged": True})
        self.assertFalse(verification["valid"])

    def test_13_backup_retention_keeps_only_latest_limit(self):
        cf.RECOVERY_BACKUP_RETENTION = 3
        names = []
        for _ in range(5):
            names.append(cf.create_recovery_backup({"acknowledged": True})["name"])
        listed = cf.list_recovery_backups()["backups"]
        self.assertEqual(len(listed), 3)
        self.assertTrue(set(names[-3:]).issubset({x["name"] for x in listed}))

    @unittest.skipIf(os.name == "nt", "symlink creation may require elevated Windows privileges")
    def test_14_backup_root_symlink_is_rejected(self):
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        link = cf.DATA_DIR / "backups"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(PermissionError):
            cf.create_recovery_backup({"acknowledged": True})
        self.assertEqual(list(outside.iterdir()), [])

    def test_15_list_backup_does_not_expose_arbitrary_files(self):
        root = cf.DATA_DIR / "backups"
        root.mkdir()
        (root / "my-important-file.txt").write_text("do not list", encoding="utf-8")
        self.assertEqual(cf.list_recovery_backups()["backups"], [])

    def test_16_checkpoint_does_not_delete_cases(self):
        self.add_case()
        result = cf.run_system_maintenance({"action": "checkpoint", "acknowledged": True})
        self.assertEqual(result["action"], "checkpoint")
        con = cf._db_connect()
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM cases").fetchone()[0], 1)
        finally:
            con.close()

    def test_17_unknown_maintenance_action_is_rejected(self):
        with self.assertRaises(ValueError):
            cf.run_system_maintenance({"action": "delete-old-data", "acknowledged": True})


class CrossModuleIntegrityTests(IntegrationTestCase):
    def test_18_new_plugin_install_records_per_file_hashes(self):
        cf.install_plugin_archive(self.plugin_package())
        root = cf.DATA_DIR / "plugins" / "test.integrity-plugin"
        metadata = json.loads((root / "install.json").read_text(encoding="utf-8"))
        self.assertIn("manifest.json", metadata["files"])
        self.assertIn("plugin.py", metadata["files"])
        self.assertEqual(cf._verify_managed_plugin_integrity("test.integrity-plugin")["status"], "verified")

    def test_19_modified_plugin_file_is_detected(self):
        cf.install_plugin_archive(self.plugin_package())
        path = cf.DATA_DIR / "plugins" / "test.integrity-plugin" / "plugin.py"
        path.write_text("print('modified')\n", encoding="utf-8")
        result = cf._verify_managed_plugin_integrity("test.integrity-plugin")
        self.assertEqual(result["status"], "invalid")
        self.assertFalse(result["verified"])

    def test_20_unexpected_plugin_file_is_detected(self):
        cf.install_plugin_archive(self.plugin_package())
        path = cf.DATA_DIR / "plugins" / "test.integrity-plugin" / "extra.py"
        path.write_text("# unexpected\n", encoding="utf-8")
        self.assertEqual(cf._verify_managed_plugin_integrity("test.integrity-plugin")["status"], "invalid")

    def test_21_plugin_lifecycle_lock_is_a_reentrant_lock(self):
        self.assertIsInstance(cf.PLUGIN_MANAGER_LOCK, type(threading.RLock()))

    def test_22_duplicate_active_engine_rows_are_migrated_to_single_active(self):
        con = cf._db_connect()
        try:
            con.execute("DROP INDEX uq_managed_engine_one_active")
            for version in ("1.9.4", "1.9.3"):
                con.execute("INSERT INTO managed_engine_versions(engine_id,version,install_path,executable_path,package_name,package_sha256,active,installed_at) VALUES(?,?,?,?,?,?,1,?)",
                            ("bandit", version, str(cf.DATA_DIR / "bad" / version), str(cf.DATA_DIR / "bad" / version / "bandit"), "bandit", "", cf._now()))
            con.commit()
        finally:
            con.close()
        cf.init_database()
        con = cf._db_connect()
        try:
            active = con.execute("SELECT COUNT(*) FROM managed_engine_versions WHERE engine_id='bandit' AND active=1").fetchone()[0]
            self.assertEqual(active, 1)
            with self.assertRaises(Exception):
                con.execute("INSERT INTO managed_engine_versions(engine_id,version,install_path,executable_path,package_name,package_sha256,active,installed_at) VALUES(?,?,?,?,?,?,1,?)",
                            ("bandit", "another", "x", "y", "bandit", "", cf._now()))
        finally:
            con.close()


class APIReliabilityTests(IntegrationTestCase):
    def setUp(self):
        super().setUp()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        super().tearDown()

    def test_23_system_health_endpoint_returns_report(self):
        with urllib.request.urlopen(self.base + "/api/system/health", timeout=10) as response:
            data = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertTrue(response.headers.get("X-CyberForge-Request-ID"))
        self.assertIn(data["status"], {"healthy", "warning"})

    def test_24_backup_endpoint_requires_capability_acknowledgement(self):
        request = urllib.request.Request(self.base + "/api/system/backup", data=json.dumps({"acknowledged": True}).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 403)

    def test_25_backup_endpoint_accepts_scoped_acknowledgement(self):
        body = {"acknowledged": True, "_permission_acknowledged": ["system_maintenance"]}
        request = urllib.request.Request(self.base + "/api/system/backup", data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertTrue(response.headers.get("X-CyberForge-Request-ID"))
        self.assertTrue(data["created"])

    def test_26_unexpected_get_exception_is_masked_and_has_request_reference(self):
        with patch.object(cf, "system_health_report", side_effect=RuntimeError("private-internal-detail")):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(self.base + "/api/system/health", timeout=10)
        self.assertEqual(caught.exception.code, 500)
        body = json.loads(caught.exception.read())
        self.assertNotIn("private-internal-detail", json.dumps(body))
        self.assertTrue(body["request_id"])

    def test_27_unexpected_post_exception_is_masked_and_has_request_reference(self):
        body = {"acknowledged": True, "_permission_acknowledged": ["system_maintenance"]}
        request = urllib.request.Request(self.base + "/api/system/backup", data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        with patch.object(cf, "create_recovery_backup", side_effect=OSError("private-post-detail")):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 500)
        data = json.loads(caught.exception.read())
        self.assertNotIn("private-post-detail", json.dumps(data))
        self.assertTrue(data["request_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
