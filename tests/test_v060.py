import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.request import Request, urlopen
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V060DesktopTests(unittest.TestCase):
    def test_version_and_source_data_default(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        with mock.patch.object(cf, "FROZEN", False), mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(cf._default_data_dir(), cf.ROOT / "data")

    def test_frozen_data_uses_os_user_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(cf, "FROZEN", True), \
                 mock.patch.object(cf, "sys") as fake_sys, \
                 mock.patch.object(cf, "os") as fake_os, \
                 mock.patch.dict(os.environ, {"XDG_DATA_HOME": tmp}, clear=False):
                fake_sys.platform = "linux"
                fake_os.name = "posix"
                fake_os.environ = os.environ
                result = cf._default_data_dir()
            self.assertEqual(result, Path(tmp) / "CyberForgeAIO")

    def test_data_dir_environment_override(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"CYBERFORGE_DATA_DIR": tmp}, clear=False):
            self.assertEqual(cf._default_data_dir(), Path(tmp).resolve())

    def test_legacy_data_migration_copies_database_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            old_install = base / "old"
            legacy = old_install / "data"
            legacy.mkdir(parents=True)
            (legacy / "cyberforge.db").write_bytes(b"sqlite-fixture")
            (legacy / "evidence").mkdir()
            (legacy / "evidence" / "sample.bin").write_bytes(b"evidence")
            new_data = base / "profile" / "CyberForgeAIO"
            with mock.patch.object(cf, "FROZEN", True), \
                 mock.patch.object(cf, "INSTALL_DIR", old_install), \
                 mock.patch.object(cf, "DATA_DIR", new_data), \
                 mock.patch.object(cf, "DB_PATH", new_data / "cyberforge.db"), \
                 mock.patch.object(cf, "EVIDENCE_DIR", new_data / "evidence"):
                migrated = cf._migrate_legacy_data_if_needed()
            self.assertEqual(migrated, str(legacy))
            self.assertEqual((new_data / "cyberforge.db").read_bytes(), b"sqlite-fixture")
            self.assertEqual((new_data / "evidence" / "sample.bin").read_bytes(), b"evidence")

    def test_http_version_returns_runtime_metadata(self):
        server = ThreadingHTTPServer((cf.HOST, 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://{cf.HOST}:{server.server_address[1]}"
            with urlopen(base + "/api/version", timeout=3) as response:
                data = json.loads(response.read())
            self.assertEqual(data["version"], cf.APP_VERSION)
            self.assertTrue(data["local_only"])
            self.assertIn(data["runtime"], {"source", "desktop-webview", "packaged-browser"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_dynamic_port_origin_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_dir = Path(tmp) / "data"
            old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
            cf.DATA_DIR = base_dir
            cf.DB_PATH = base_dir / "test.sqlite3"
            cf.EVIDENCE_DIR = base_dir / "evidence"
            cf.init_database()
            server = ThreadingHTTPServer((cf.HOST, 0), cf.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                url = f"http://{cf.HOST}:{port}/api/cases"
                request = Request(url, data=json.dumps({"title": "Origin test", "scope": "localhost", "_permission_acknowledged": ["case_write"]}).encode(), headers={
                    "Content-Type": "application/json",
                    "Origin": f"http://127.0.0.1:{port}",
                }, method="POST")
                with urlopen(request, timeout=3) as response:
                    self.assertEqual(response.status, 200)
                bad = Request(url, data=json.dumps({"title": "Blocked", "scope": "localhost"}).encode(), headers={
                    "Content-Type": "application/json",
                    "Origin": "https://attacker.invalid",
                }, method="POST")
                with self.assertRaises(Exception) as ctx:
                    urlopen(bad, timeout=3)
                self.assertIn("403", str(ctx.exception))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
                cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = old

    def test_native_webview_lifecycle_starts_and_stops_local_server(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "data"
            old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.PORT, cf.DESKTOP_MODE)
            cf.DATA_DIR = base
            cf.DB_PATH = base / "cyberforge.db"
            cf.EVIDENCE_DIR = base / "evidence"
            cf.PORT = 0
            fake = SimpleNamespace(create_window=Mock(), start=Mock())
            try:
                with mock.patch.dict(sys.modules, {"webview": fake}), mock.patch.object(sys, "argv", ["cyberforge.py"]):
                    cf.main()
                fake.create_window.assert_called_once()
                fake.start.assert_called_once()
                self.assertTrue(cf.DESKTOP_MODE)
            finally:
                cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.PORT, cf.DESKTOP_MODE = old

    def test_foreign_host_header_is_rejected(self):
        server = ThreadingHTTPServer((cf.HOST, 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            req = Request(
                f"http://{cf.HOST}:{port}/api/version",
                headers={"Host": f"attacker.invalid:{port}"},
            )
            with self.assertRaises(Exception) as ctx:
                urlopen(req, timeout=3)
            self.assertIn("403", str(ctx.exception))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_build_scripts_and_desktop_dependencies_exist(self):
        self.assertTrue((ROOT / "desktop_entry.py").is_file())
        self.assertTrue((ROOT / "requirements-desktop.txt").is_file())
        self.assertTrue((ROOT / "requirements-build.txt").is_file())
        self.assertTrue((ROOT / "BUILD_WINDOWS.bat").is_file())
        self.assertTrue((ROOT / ".github" / "workflows" / "desktop-editions.yml").is_file())
        self.assertTrue((ROOT / "build_desktop.py").is_file())
        self.assertTrue((ROOT / "requirements-build-windows.txt").is_file())
        self.assertTrue((ROOT / "requirements-build-macos.txt").is_file())
        self.assertTrue((ROOT / "requirements-build-linux.txt").is_file())


if __name__ == "__main__":
    unittest.main()
