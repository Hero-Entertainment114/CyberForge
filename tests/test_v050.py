import json
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V050Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf050-test-")
        base = Path(self.tmp.name)
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.ROOT, cf.PORT)
        cf.DATA_DIR = base / "data"
        cf.DB_PATH = cf.DATA_DIR / "test.sqlite3"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.ROOT = base
        cf.init_database()
        cf.VAULT_KEY = None
        cf.vault_create("unit-test-passphrase-123", "unit-test-passphrase-123")
        self.case = cf.create_case({"title": "v0.5.0 lab test", "scope": "offline fixtures"})

    def tearDown(self):
        cf.VAULT_KEY = None
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.ROOT, cf.PORT = self.old
        self.tmp.cleanup()

    def test_engine_catalog_has_fixed_allowlist(self):
        with mock.patch.object(cf.shutil, "which", return_value=None):
            result = cf.v050_engine_catalog()
        ids = {x["id"] for x in result["engines"]}
        self.assertTrue({"capa", "floss", "jadx", "tshark", "suricata", "checkov"}.issubset(ids))
        self.assertEqual(result["available_count"], 0)
        self.assertEqual(len(ids), len(result["engines"]))

    def test_unknown_engine_rejected(self):
        with self.assertRaises(ValueError):
            cf.run_v050_static_engine(b"abc", "x.bin", "arbitrary-command")

    def test_missing_engine_reports_install_requirement(self):
        with mock.patch.object(cf.shutil, "which", return_value=None):
            with self.assertRaises(FileNotFoundError):
                cf.run_v050_static_engine(b"fixture", "sample.exe", "capa")

    def test_android_engine_requires_apk(self):
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/jadx"):
            with self.assertRaises(ValueError):
                cf.run_v050_static_engine(b"not-an-apk", "sample.bin", "jadx")

    def test_pcap_engine_requires_capture_extension(self):
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/tshark"):
            with self.assertRaises(ValueError):
                cf.run_v050_static_engine(b"capture", "sample.txt", "tshark")

    def test_checkov_requires_infrastructure_manifest_extension(self):
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/checkov"):
            with self.assertRaises(ValueError):
                cf.run_v050_static_engine(b"not IaC", "payload.bin", "checkov")

    def test_static_engine_uses_fixed_argv_no_shell(self):
        captured = {}
        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["shell"] = kwargs.get("shell")
            captured["cwd"] = kwargs.get("cwd")
            kwargs["stdout"].write(b"{\"metadata\":true}")
            kwargs["stderr"].write(b"")
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(cf.shutil, "which", return_value="/opt/tools/exiftool"), mock.patch.object(cf.subprocess, "run", side_effect=fake_run):
            result = cf.run_v050_static_engine(b"image-bytes", "../weird image.jpg", "exiftool")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stdout"], '{"metadata":true}')
        self.assertEqual(captured["shell"], False)
        self.assertEqual(captured["args"][0], "/opt/tools/exiftool")
        self.assertEqual(captured["args"][1:3], ["-json", "--"])
        self.assertEqual(Path(captured["args"][3]).name, "weird_image.jpg")

    def test_vm_inventory_flags_disabled_adapter_and_sharing(self):
        vmid = "12345678-1234-1234-1234-123456789abc"
        calls = [
            subprocess.CompletedProcess([], 0, f'"Offline Lab" {{{vmid}}}\n', ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, 'VMState="poweroff"\nnic1="none"\nclipboard="disabled"\ndraganddrop="disabled"\n', ""),
        ]
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/VBoxManage"), mock.patch.object(cf, "_vbox_run", side_effect=calls):
            data = cf.vm_lab_info()
        self.assertTrue(data["available"])
        self.assertEqual(len(data["vms"]), 1)
        self.assertTrue(data["vms"][0]["basic_isolation_checks_passed"])

    def test_vm_inventory_does_not_mark_unknown_sharing_safe(self):
        vmid = "12345678-1234-1234-1234-123456789abc"
        calls = [
            subprocess.CompletedProcess([], 0, f'"Lab" {{{vmid}}}\n', ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, 'VMState="poweroff"\nnic1="none"\n', ""),
        ]
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/VBoxManage"), mock.patch.object(cf, "_vbox_run", side_effect=calls):
            data = cf.vm_lab_info()
        self.assertFalse(data["vms"][0]["basic_isolation_checks_passed"])

    def test_vm_snapshot_requires_acknowledgement(self):
        with self.assertRaises(PermissionError):
            cf.vm_lab_snapshot({"action": "create", "vm_uuid": "12345678-1234-1234-1234-123456789abc", "snapshot_name": "clean"})

    def test_vm_snapshot_action_audited(self):
        vmid = "12345678-1234-1234-1234-123456789abc"
        fake_info = {"available": True, "vms": [{"uuid": vmid}]}
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/VBoxManage"), \
             mock.patch.object(cf, "vm_lab_info", return_value=fake_info), \
             mock.patch.object(cf, "_vbox_run", return_value=subprocess.CompletedProcess([], 0, "Snapshot created", "")):
            result = cf.vm_lab_snapshot({"action": "create", "vm_uuid": vmid, "snapshot_name": "clean-01", "acknowledged": True})
        self.assertTrue(result["success"])
        self.assertTrue(cf.verify_audit_chain()["valid"])

    def test_vm_snapshot_name_validation_prevents_argument_injection(self):
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/VBoxManage"), mock.patch.object(cf, "vm_lab_info", return_value={"available": True, "vms": [{"uuid": "12345678-1234-1234-1234-123456789abc"}]}):
            with self.assertRaises(ValueError):
                cf.vm_lab_snapshot({"action": "create", "vm_uuid": "12345678-1234-1234-1234-123456789abc", "snapshot_name": "x; rm -rf /", "acknowledged": True})

    def test_v050_status_version(self):
        with mock.patch.object(cf.shutil, "which", return_value=None):
            status = cf.v050_status()
        self.assertEqual(status["version"], cf.APP_VERSION)
        self.assertFalse(status["vm_lab_available"])

    def test_http_v050_routes_and_binary_upload(self):
        server = ThreadingHTTPServer((cf.HOST, 0), cf.Handler)
        cf.PORT = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://{cf.HOST}:{cf.PORT}"
        try:
            self.assertEqual(json.loads(urllib_request(base + "/api/version"))["version"], cf.APP_VERSION)
            self.assertIn("engines", json.loads(urllib_request(base + "/api/v050/engines")))
            with mock.patch.object(cf, "run_v050_static_engine", return_value={"status": "completed", "engine": "mock"}):
                request = urllib_request_obj(base + "/api/v050/static-engine", b"test-data", {"Content-Type": "application/octet-stream", "X-File-Name": "x.bin", "X-Engine-ID": "capa"})
                self.assertEqual(json.loads(urllib_request(request))["engine"], "mock")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


def urllib_request_obj(url, data=None, headers=None):
    from urllib.request import Request
    return Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")


def urllib_request(value):
    from urllib.request import urlopen
    return urlopen(value, timeout=4).read()


if __name__ == "__main__":
    unittest.main()
