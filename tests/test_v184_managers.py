"""Engine and plugin lifecycle tests for CyberForge v1.8.5."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class ManagerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf184-manager-")
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        base = Path(self.tmp.name) / "data"
        cf.DATA_DIR = base
        cf.DB_PATH = base / "cyberforge.db"
        cf.EVIDENCE_DIR = base / "evidence"
        cf.init_database()

    def tearDown(self):
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old
        self.tmp.cleanup()

    @staticmethod
    def package(plugin_id="test.local-plugin", version="1.0.0", capabilities=None,
                required=None, entrypoint="plugin.py", extra=None):
        manifest = {
            "id": plugin_id,
            "name": "Test Local Plugin",
            "version": version,
            "api_version": "1",
            "description": "A test plugin package.",
            "runtime": "python:3.12-alpine",
            "entrypoint": entrypoint,
            "capabilities": capabilities if capabilities is not None else ["knowledge.read"],
            "required_permissions": required if required is not None else [],
        }
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            archive.writestr(entrypoint, "import json, sys\ndata=json.load(sys.stdin)\nprint(json.dumps({'ok': True, 'grants': data['granted_permissions']}))\n")
            if extra:
                for name, content in extra.items():
                    archive.writestr(name, content)
        data = raw.getvalue()
        return {"archive_base64": base64.b64encode(data).decode(),
                "sha256": hashlib.sha256(data).hexdigest(), "acknowledged": True}, data

    @staticmethod
    def fake_venv_builder():
        class FakeBuilder:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def create(self, path):
                path.mkdir(parents=True, exist_ok=True)
                py = path / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                py.parent.mkdir(parents=True, exist_ok=True)
                py.write_text("fake python", encoding="utf-8")
        return FakeBuilder

    def fake_pip(self, command, **kwargs):
        if command[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout=f"Python {sys.version_info.major}.{sys.version_info.minor}.0", stderr="")
        stage = Path(command[0]).parent.parent
        engine_id = "bandit"
        binary = cf._engine_venv_executable(stage, cf.ENGINE_CATALOG[engine_id]["binary"])
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        if os.name != "nt":
            binary.chmod(0o755)
        return SimpleNamespace(returncode=0, stdout="installed", stderr="")


class EngineManagerTests(ManagerTestCase):
    def test_01_catalog_is_fixed_and_versions_are_pinned(self):
        inventory = cf.engine_manager_inventory()
        self.assertEqual({x["id"] for x in inventory["engines"]}, {"bandit", "oletools", "volatility3"})
        for engine in inventory["engines"]:
            self.assertTrue(engine["available_versions"])
            self.assertEqual(engine["package"], cf.ENGINE_CATALOG[engine["id"]]["package"])

    def test_02_engine_install_requires_explicit_acknowledgement(self):
        with self.assertRaises(PermissionError):
            cf.manage_engine({"engine_id": "bandit", "action": "install"})

    @unittest.skipIf(os.name == "nt", "symlink creation may require elevated Windows privileges")
    def test_03_engine_storage_root_symlink_is_rejected(self):
        outside = Path(self.tmp.name) / "outside-engines"
        outside.mkdir()
        link = cf.DATA_DIR / "engines"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(PermissionError):
            cf.manage_engine({"engine_id": "bandit", "action": "install", "acknowledged": True})
        self.assertEqual(list(outside.iterdir()), [])

    def test_03_unknown_engine_is_rejected(self):
        with self.assertRaises(ValueError):
            cf.manage_engine({"engine_id": "custom-shell", "action": "install", "acknowledged": True})

    def test_04_unknown_version_is_rejected(self):
        with self.assertRaises(ValueError):
            cf.manage_engine({"engine_id": "bandit", "version": "999.0", "action": "install", "acknowledged": True})

    def test_05_install_uses_isolated_venv_and_no_shell(self):
        with patch.object(cf.venv, "EnvBuilder", self.fake_venv_builder()), \
             patch.object(cf.subprocess, "run", side_effect=self.fake_pip) as run:
            result = cf.manage_engine({"engine_id": "bandit", "action": "install", "version": "1.9.4", "acknowledged": True})
        self.assertTrue(result["installed"])
        self.assertEqual(run.call_args.kwargs["shell"], False)
        self.assertIn("--only-binary=:all:", run.call_args.args[0])
        self.assertIn("--index-url", run.call_args.args[0])
        self.assertIn("bandit==1.9.4", run.call_args.args[0])
        self.assertIn(str(cf.DATA_DIR / "engines" / "bandit" / "1.9.4"), run.call_args.args[0][0])
        self.assertTrue(result["inventory"]["engines"][0]["managed"])

    def test_06_install_another_version_keeps_rollback_version(self):
        with patch.object(cf.venv, "EnvBuilder", self.fake_venv_builder()), patch.object(cf.subprocess, "run", side_effect=self.fake_pip):
            cf.manage_engine({"engine_id": "bandit", "action": "install", "version": "1.9.4", "acknowledged": True})
            cf.manage_engine({"engine_id": "bandit", "action": "update", "version": "1.9.3", "acknowledged": True})
        inventory = cf.engine_manager_inventory()
        bandit = next(x for x in inventory["engines"] if x["id"] == "bandit")
        self.assertEqual({x["version"] for x in bandit["installed_versions"]}, {"1.9.4", "1.9.3"})
        self.assertEqual(bandit["active_version"], "1.9.3")

    def test_07_switch_requires_version_already_installed(self):
        with self.assertRaises(ValueError):
            cf.manage_engine({"engine_id": "bandit", "action": "switch", "version": "1.9.3", "acknowledged": True})

    def test_08_switch_and_remove_version_restore_previous_active(self):
        with patch.object(cf.venv, "EnvBuilder", self.fake_venv_builder()), patch.object(cf.subprocess, "run", side_effect=self.fake_pip):
            cf.manage_engine({"engine_id": "bandit", "action": "install", "version": "1.9.4", "acknowledged": True})
            cf.manage_engine({"engine_id": "bandit", "action": "install", "version": "1.9.3", "acknowledged": True})
        switched = cf.manage_engine({"engine_id": "bandit", "action": "switch", "version": "1.9.4", "acknowledged": True})
        bandit = next(x for x in switched["inventory"]["engines"] if x["id"] == "bandit")
        self.assertEqual(bandit["active_version"], "1.9.4")
        removed = cf.manage_engine({"engine_id": "bandit", "action": "remove_version", "version": "1.9.4", "acknowledged": True})
        bandit = next(x for x in removed["inventory"]["engines"] if x["id"] == "bandit")
        self.assertEqual(bandit["active_version"], "1.9.3")

    def test_09_uninstall_all_removes_registered_versions(self):
        with patch.object(cf.venv, "EnvBuilder", self.fake_venv_builder()), patch.object(cf.subprocess, "run", side_effect=self.fake_pip):
            cf.manage_engine({"engine_id": "bandit", "action": "install", "version": "1.9.4", "acknowledged": True})
        result = cf.manage_engine({"engine_id": "bandit", "action": "remove", "acknowledged": True})
        self.assertTrue(result["removed"])
        self.assertFalse(next(x for x in result["inventory"]["engines"] if x["id"] == "bandit")["managed"])

    def test_10_existing_unregistered_engine_folder_is_not_deleted(self):
        target = cf.DATA_DIR / "engines" / "bandit" / "1.9.4"
        target.mkdir(parents=True)
        sentinel = target / "keep.txt"
        sentinel.write_text("user data", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            cf.manage_engine({"engine_id": "bandit", "action": "install", "version": "1.9.4", "acknowledged": True})
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "user data")

    def test_10_failed_pip_install_does_not_register_engine(self):
        class FakeFail:
            def __init__(self, **kwargs): pass
            def create(self, path):
                path.mkdir(parents=True, exist_ok=True)
                (path / ("Scripts" if os.name == "nt" else "bin")).mkdir()
        with patch.object(cf.venv, "EnvBuilder", FakeFail), patch.object(cf.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="", stderr="network unavailable")):
            with self.assertRaises(RuntimeError):
                cf.manage_engine({"engine_id": "bandit", "action": "install", "version": "1.9.4", "acknowledged": True})
        self.assertIsNone(cf._managed_engine_executable("bandit", "bandit"))
        self.assertFalse((cf.DATA_DIR / "engines" / "bandit" / "1.9.4").exists())

    def test_11_managed_executable_must_stay_inside_registered_venv(self):
        external = Path(self.tmp.name) / "outside"
        external.write_text("not an engine")
        con = cf._db_connect()
        try:
            con.execute("INSERT INTO managed_engine_versions(engine_id,version,install_path,executable_path,package_name,active,installed_at) VALUES(?,?,?,?,?,1,?)",
                        ("bandit", "1.9.4", str(cf.DATA_DIR), str(external), "bandit", "now"))
            con.commit()
        finally:
            con.close()
        self.assertIsNone(cf._managed_engine_executable("bandit", "bandit"))

    def test_11_recorded_engine_without_expected_executable_cannot_be_activated(self):
        engine_dir = cf.DATA_DIR / "engines" / "bandit" / "1.9.4"
        engine_dir.mkdir(parents=True)
        stale_binary = cf._engine_venv_executable(engine_dir, "bandit")
        con = cf._db_connect()
        try:
            con.execute("INSERT INTO managed_engine_versions(engine_id,version,install_path,executable_path,package_name,active,installed_at) VALUES(?,?,?,?,?,0,?)",
                        ("bandit", "1.9.4", str(engine_dir), str(stale_binary), "bandit", "now"))
            con.commit()
        finally:
            con.close()
        with self.assertRaisesRegex(RuntimeError, "executable/venv"):
            cf.manage_engine({"engine_id": "bandit", "action": "switch", "version": "1.9.4", "acknowledged": True})

    def test_12_v050_inventory_can_resolve_a_managed_oletools_binary(self):
        engine_dir = cf.DATA_DIR / "engines" / "oletools" / "0.60.2"
        binary = cf._engine_venv_executable(engine_dir, "olevba")
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\nexit 0\n")
        if os.name != "nt": binary.chmod(0o755)
        con = cf._db_connect()
        try:
            con.execute("INSERT INTO managed_engine_versions(engine_id,version,install_path,executable_path,package_name,active,installed_at) VALUES(?,?,?,?,?,1,?)",
                        ("oletools", "0.60.2", str(engine_dir), str(binary), "oletools", "now"))
            con.commit()
        finally:
            con.close()
        result = cf.v050_engine_catalog()
        ole = next(x for x in result["engines"] if x["id"] == "olevba")
        self.assertTrue(ole["installed"])
        self.assertIn("olevba", ole["path"])


class PluginManagerTests(ManagerTestCase):
    def test_13_plugin_install_is_disabled_and_starts_with_no_grants(self):
        payload, _ = self.package()
        result = cf.install_plugin_archive(payload)
        self.assertEqual(result["plugin_id"], "test.local-plugin")
        plugin = next(x for x in cf.list_plugin_access() if x["id"] == "test.local-plugin")
        self.assertTrue(plugin["installed"])
        self.assertTrue(plugin["runnable"])
        self.assertFalse(plugin["enabled"])
        self.assertEqual(plugin["granted_permissions"], [])
        self.assertEqual(plugin["permission_policy"], "deny-by-default")

    @unittest.skipIf(os.name == "nt", "symlink creation may require elevated Windows privileges")
    def test_14_plugin_storage_root_symlink_is_rejected(self):
        outside = Path(self.tmp.name) / "outside-plugins"
        outside.mkdir()
        link = cf.DATA_DIR / "plugins"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside, target_is_directory=True)
        payload, _ = self.package(plugin_id="test.root-symlink")
        with self.assertRaises(PermissionError):
            cf.install_plugin_archive(payload)
        self.assertEqual(list(outside.iterdir()), [])

    def test_14_plugin_install_requires_acknowledgement(self):
        payload, _ = self.package()
        payload["acknowledged"] = False
        with self.assertRaises(PermissionError):
            cf.install_plugin_archive(payload)

    def test_15_plugin_hash_mismatch_is_rejected(self):
        payload, _ = self.package()
        payload["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            cf.install_plugin_archive(payload)

    def test_16_registered_plugin_path_must_match_update_target(self):
        target = cf.DATA_DIR / "plugins" / "test.local-plugin"
        target.mkdir(parents=True)
        (target / "marker.txt").write_text("keep", encoding="utf-8")
        outside = Path(self.tmp.name) / "different-path"
        outside.mkdir()
        con = cf._db_connect()
        try:
            con.execute("INSERT INTO managed_plugins(plugin_id,version,install_path,archive_sha256,installed_at,updated_at) VALUES(?,?,?,?,?,?)",
                        ("test.local-plugin", "1.0.0", str(outside), "0" * 64, "now", "now"))
            con.commit()
        finally:
            con.close()
        payload, _ = self.package(plugin_id="test.local-plugin", version="1.1.0")
        with self.assertRaises(PermissionError):
            cf.install_plugin_archive(payload)
        self.assertEqual((target / "marker.txt").read_text(encoding="utf-8"), "keep")

    def test_16_plugin_zip_slip_is_rejected(self):
        payload, _ = self.package(extra={"../escape.py": "bad"})
        with self.assertRaises(ValueError):
            cf.install_plugin_archive(payload)
        self.assertFalse((Path(self.tmp.name) / "escape.py").exists())

    def test_17_plugin_zip_symlink_is_rejected(self):
        payload, _ = self.package()
        raw = base64.b64decode(payload["archive_base64"])
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as z:
            z.writestr("manifest.json", json.dumps({"id":"bad.symlink","name":"Bad","version":"1.0.0","runtime":"python:3.12-alpine","entrypoint":"plugin.py","capabilities":[],"required_permissions":[]}))
            info = zipfile.ZipInfo("plugin.py")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "../../outside")
        raw = stream.getvalue()
        bad = {"archive_base64": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest(), "acknowledged": True}
        with self.assertRaises(ValueError):
            cf.install_plugin_archive(bad)

    def test_18_plugin_capabilities_and_required_permissions_are_validated(self):
        payload, _ = self.package(capabilities=["network.shell"], required=["network.shell"])
        with self.assertRaises(ValueError):
            cf.install_plugin_archive(payload)
        payload, _ = self.package(capabilities=["knowledge.read"], required=["case.read"])
        with self.assertRaises(ValueError):
            cf.install_plugin_archive(payload)

    def test_19_plugin_update_revokes_old_permissions(self):
        payload, _ = self.package(version="1.0.0")
        cf.install_plugin_archive(payload)
        cf.update_plugin_access({"plugin_id":"test.local-plugin", "permissions":["knowledge.read"], "enabled":True})
        update, _ = self.package(version="1.1.0")
        result = cf.install_plugin_archive(update)
        self.assertTrue(result["updated"])
        item = next(x for x in cf.list_plugin_access() if x["id"] == "test.local-plugin")
        self.assertEqual(item["version"], "1.1.0")
        self.assertFalse(item["enabled"])
        self.assertEqual(item["granted_permissions"], [])

    def test_20_plugin_remove_deletes_code_and_permissions(self):
        payload, _ = self.package()
        cf.install_plugin_archive(payload)
        root = cf.DATA_DIR / "plugins" / "test.local-plugin"
        self.assertTrue(root.exists())
        result = cf.remove_managed_plugin({"plugin_id":"test.local-plugin", "acknowledged":True})
        self.assertTrue(result["removed"])
        self.assertFalse(root.exists())
        self.assertNotIn("test.local-plugin", {x["id"] for x in cf.list_plugin_access()})

    @unittest.skipIf(os.name == "nt", "symlink creation may require elevated Windows privileges")
    def test_22_plugin_remove_refuses_registered_symlink_path(self):
        outside = Path(self.tmp.name) / "outside-plugin"
        outside.mkdir()
        (outside / "marker.txt").write_text("keep", encoding="utf-8")
        managed_root = cf.DATA_DIR / "plugins"
        managed_root.mkdir(parents=True)
        link = managed_root / "test.local-plugin"
        link.symlink_to(outside, target_is_directory=True)
        con = cf._db_connect()
        try:
            con.execute("INSERT INTO managed_plugins(plugin_id,version,install_path,archive_sha256,installed_at,updated_at) VALUES(?,?,?,?,?,?)",
                        ("test.local-plugin", "1.0.0", str(link), "0" * 64, "now", "now"))
            con.commit()
        finally:
            con.close()
        with self.assertRaises(PermissionError):
            cf.remove_managed_plugin({"plugin_id":"test.local-plugin", "acknowledged":True})
        self.assertEqual((outside / "marker.txt").read_text(encoding="utf-8"), "keep")

    def test_21_bundled_plugin_cannot_be_removed_by_manager(self):
        with self.assertRaises(ValueError):
            cf.remove_managed_plugin({"plugin_id":"example.indicator-enricher", "acknowledged":True})

    def test_22_only_db_registered_managed_plugins_are_discovered(self):
        rogue = cf.DATA_DIR / "plugins" / "rogue.plugin"
        rogue.mkdir(parents=True)
        (rogue / "manifest.json").write_text(json.dumps({"id":"rogue.plugin","name":"Rogue","version":"1.0.0","runtime":"python:3.12-alpine","entrypoint":"plugin.py","capabilities":[]}), encoding="utf-8")
        (rogue / "plugin.py").write_text("print('not trusted')")
        self.assertNotIn("rogue.plugin", {x["id"] for x in cf.list_plugin_manifests()})

    def test_23_optional_capabilities_do_not_all_have_to_be_granted(self):
        payload, _ = self.package(capabilities=["knowledge.read", "case.read"], required=["knowledge.read"])
        cf.install_plugin_archive(payload)
        cf.update_plugin_access({"plugin_id":"test.local-plugin", "permissions":["knowledge.read"], "enabled":True})
        calls = []
        def fake_run(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout="{}" if "inspect" in command else '{"ok": true, "grants": ["knowledge.read"]}', stderr="")
        with patch.object(cf.shutil, "which", side_effect=lambda name: "/usr/bin/docker" if name == "docker" else None), patch.object(cf.subprocess, "run", side_effect=fake_run):
            result = cf.run_plugin_sandbox({"plugin_id":"test.local-plugin", "acknowledged":True, "query":"test"})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["permissions"], ["knowledge.read"])
        self.assertIn("--network", calls[1])
        self.assertIn("none", calls[1])

    def test_24_plugin_enable_policy_rejects_undeclared_permission(self):
        payload, _ = self.package()
        cf.install_plugin_archive(payload)
        with self.assertRaises(ValueError):
            cf.update_plugin_access({"plugin_id":"test.local-plugin", "permissions":["case.read"], "enabled":True})

    def test_25_plugin_package_size_limit_is_enforced(self):
        giant = b"x" * (cf.PLUGIN_ARCHIVE_MAX_BYTES + 1)
        payload = {"archive_base64": base64.b64encode(giant).decode(), "sha256": hashlib.sha256(giant).hexdigest(), "acknowledged":True}
        with self.assertRaises(ValueError):
            cf.install_plugin_archive(payload)


class ManagerApiAndUiTests(ManagerTestCase):
    def test_26_preferences_default_engine_installation_to_ask(self):
        self.assertEqual(cf.PREFERENCE_DEFAULTS["permissions"]["engine_admin"], "ask")
        self.assertIn("engine_admin", cf.PREFERENCE_CAPABILITIES)

    def test_27_manager_api_permissions_are_scoped(self):
        self.assertEqual(cf._api_capabilities("POST", "/api/engines/manage", {}), ["engine_admin"])
        self.assertEqual(cf._api_capabilities("POST", "/api/plugins/install", {}), ["plugin_admin"])
        self.assertEqual(cf._api_capabilities("POST", "/api/plugins/remove", {}), ["plugin_admin"])

    def test_28_api_handlers_expose_manager_endpoints(self):
        source = (ROOT / "cyberforge.py").read_text(encoding="utf-8")
        self.assertIn('path == "/api/engines/manager"', source)
        self.assertIn('self.path == "/api/engines/manage"', source)
        self.assertIn('self.path == "/api/plugins/install"', source)
        self.assertIn('self.path == "/api/plugins/remove"', source)

    def test_29_ui_exposes_install_switch_remove_and_policy_review(self):
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        for text in ("id=\"engineplugins\"", "installPluginPackageUI", "manageEngineUI", "removeManagedPluginUI", "required_permissions", "SHA-256", "updateEngineVersionButtons", "engineRemoveVersion_"):
            self.assertIn(text, html)

    def test_31_installable_sample_package_round_trips(self):
        archive = ROOT / "plugins" / "packages" / "example.indicator-enricher-package-1.0.0.zip"
        raw = archive.read_bytes()
        result = cf.install_plugin_archive({
            "archive_base64": base64.b64encode(raw).decode(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "acknowledged": True,
        })
        item = next(x for x in cf.list_plugin_access() if x["id"] == result["plugin_id"])
        self.assertTrue(item["installed"])
        self.assertFalse(item["enabled"])
        self.assertEqual(item["granted_permissions"], [])
        self.assertTrue(cf.remove_managed_plugin({"plugin_id": result["plugin_id"], "acknowledged": True})["removed"])

    def test_30_plugin_run_remains_container_only(self):
        source = (ROOT / "cyberforge.py").read_text(encoding="utf-8")
        self.assertIn('"--network", "none"', source)
        self.assertIn('"--read-only"', source)
        self.assertIn('"--pull=never"', source)
        self.assertIn('"--cap-drop", "ALL"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
