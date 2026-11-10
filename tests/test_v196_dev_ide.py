from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

import cyberforge as cf
import v196_modules as v196


class V196DevIDETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-v196-test-")
        self.old_paths = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.OPENPHISH_DIR,
                          cf.OPENPHISH_PATH, cf.OPENPHISH_META_PATH)
        root = Path(self.temp.name)
        cf.DATA_DIR = root
        cf.DB_PATH = root / "cyberforge.db"
        cf.EVIDENCE_DIR = root / "evidence"
        cf.OPENPHISH_DIR = root / "threat_feeds"
        cf.OPENPHISH_PATH = cf.OPENPHISH_DIR / "openphish_community.txt"
        cf.OPENPHISH_META_PATH = cf.OPENPHISH_DIR / "openphish_meta.json"
        cf.DATA_DIR.mkdir(parents=True, exist_ok=True)
        cf.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        cf.init_database()
        self.project = cf.create_dev_project({"name": "v196 test project", "template": "empty"})
        self.project_id = self.project["id"]

    def tearDown(self):
        # Ensure this test does not leave host-shell processes behind.
        for session in list(cf.DEV_TERMINAL_MANAGER.list_sessions(self.project_id)):
            try:
                cf.DEV_TERMINAL_MANAGER.close(session["session_id"], self.project_id)
            except Exception:
                pass
        (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.OPENPHISH_DIR,
         cf.OPENPHISH_PATH, cf.OPENPHISH_META_PATH) = self.old_paths
        self.temp.cleanup()

    def test_01_app_version_and_capabilities(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        data = v196.capabilities()
        self.assertEqual(data["version"], "1.9.6")
        self.assertEqual(data["editor"]["engine"], "Monaco Editor")
        self.assertTrue(data["editor"]["local_vendor_supported"])
        self.assertTrue(data["terminal"]["runs_with_host_user_permissions"])
        self.assertFalse(data["terminal"]["pty_available"])

    def test_02_file_rename_operation(self):
        cf.create_dev_project_folder({"project_id": self.project_id, "path": "src"})
        cf.write_dev_project_file({"project_id": self.project_id, "path": "src/main.py",
                                   "content": "print('hello')\n", "expected_sha256": ""})
        result = cf.dev_project_file_operation({"project_id": self.project_id, "action": "rename",
                                                "path": "src/main.py", "new_path": "src/app.py",
                                                "acknowledged": True})
        self.assertTrue(result["renamed"])
        self.assertTrue((cf._dev_project_root(self.project_id) / "src" / "app.py").is_file())
        self.assertFalse((cf._dev_project_root(self.project_id) / "src" / "main.py").exists())

    def test_03_delete_is_recoverable_and_restore_checks_metadata(self):
        cf.write_dev_project_file({"project_id": self.project_id, "path": "main.py",
                                   "content": "print('recover me')\n", "expected_sha256": ""})
        result = cf.dev_project_file_operation({"project_id": self.project_id, "action": "delete",
                                                "path": "main.py", "acknowledged": True})
        self.assertTrue(result["recoverable"])
        root = cf._dev_project_root(self.project_id)
        self.assertFalse((root / "main.py").exists())
        restored = cf.dev_project_file_operation({"project_id": self.project_id, "action": "restore",
                                                  "trash_id": result["trash_id"], "acknowledged": True})
        self.assertTrue(restored["restored"])
        self.assertEqual((root / "main.py").read_text(encoding="utf-8"), "print('recover me')\n")

    def test_04_delete_directory_and_restore(self):
        cf.create_dev_project_folder({"project_id": self.project_id, "path": "src"})
        cf.create_dev_project_folder({"project_id": self.project_id, "path": "src/components"})
        cf.write_dev_project_file({"project_id": self.project_id, "path": "src/components/app.js",
                                   "content": "console.log('x')\n", "expected_sha256": ""})
        result = cf.dev_project_file_operation({"project_id": self.project_id, "action": "delete",
                                                "path": "src", "acknowledged": True})
        self.assertFalse((cf._dev_project_root(self.project_id) / "src").exists())
        cf.dev_project_file_operation({"project_id": self.project_id, "action": "restore",
                                       "trash_id": result["trash_id"], "acknowledged": True})
        self.assertTrue((cf._dev_project_root(self.project_id) / "src" / "components" / "app.js").is_file())

    def test_05_trash_path_is_hidden_from_project_tree(self):
        cf.write_dev_project_file({"project_id": self.project_id, "path": "hidden.txt",
                                   "content": "x", "expected_sha256": ""})
        result = cf.dev_project_file_operation({"project_id": self.project_id, "action": "delete",
                                                "path": "hidden.txt", "acknowledged": True})
        paths = {x["path"] for x in cf._dev_tree(self.project_id)}
        self.assertFalse(any(path.startswith(".cf-trash") for path in paths))
        self.assertNotIn("hidden.txt", paths)

    def test_06_restore_rejects_malformed_metadata(self):
        cf.write_dev_project_file({"project_id": self.project_id, "path": "malformed.txt",
                                   "content": "x", "expected_sha256": ""})
        result = cf.dev_project_file_operation({"project_id": self.project_id, "action": "delete",
                                                "path": "malformed.txt", "acknowledged": True})
        entry = cf._dev_project_root(self.project_id) / ".cf-trash" / result["trash_id"]
        (entry / "metadata.json").write_text("[]", encoding="utf-8")
        with self.assertRaises(PermissionError):
            cf.dev_project_file_operation({"project_id": self.project_id, "action": "restore",
                                           "trash_id": result["trash_id"], "acknowledged": True})

    def test_07_file_operation_requires_acknowledgement(self):
        with self.assertRaises(PermissionError):
            cf.dev_project_file_operation({"project_id": self.project_id, "action": "rename",
                                           "path": "a", "new_path": "b"})

    def test_08_file_operation_rejects_traversal(self):
        with self.assertRaises(ValueError):
            cf.dev_project_file_operation({"project_id": self.project_id, "action": "rename",
                                           "path": "../outside", "new_path": "inside", "acknowledged": True})

    def test_09_terminal_manager_runs_commands_and_retains_session_state(self):
        manager = v196.DeveloperTerminalManager()
        with tempfile.TemporaryDirectory(prefix="cf-term-") as temp:
            session = manager.open("TEST", Path(temp), "auto")
            try:
                self.assertEqual(session["backend"], "pipe")
                command = "Write-Output CF_TERMINAL_OK\n" if os.name == "nt" else "printf 'CF_TERMINAL_OK\\n'\n"
                manager.write(session["session_id"], "TEST", command)
                output = ""
                deadline = time.time() + 5
                while time.time() < deadline:
                    read = manager.read(session["session_id"], "TEST", 0)
                    output = read["output"]
                    if "CF_TERMINAL_OK" in output:
                        break
                    time.sleep(0.05)
                self.assertIn("CF_TERMINAL_OK", output)
                # Shell state must survive successive command submissions.
                command2 = "Write-Output CF_SECOND_OK\n" if os.name == "nt" else "printf 'CF_SECOND_OK\\n'\n"
                manager.write(session["session_id"], "TEST", command2)
                deadline = time.time() + 5
                while time.time() < deadline:
                    output = manager.read(session["session_id"], "TEST", 0)["output"]
                    if "CF_SECOND_OK" in output:
                        break
                    time.sleep(0.05)
                self.assertIn("CF_SECOND_OK", output)
            finally:
                manager.close(session["session_id"], "TEST")

    def test_10_terminal_session_is_project_bound(self):
        manager = v196.DeveloperTerminalManager()
        with tempfile.TemporaryDirectory(prefix="cf-term-") as temp:
            session = manager.open("PROJECT_A", Path(temp), "auto")
            try:
                with self.assertRaises(PermissionError):
                    manager.read(session["session_id"], "PROJECT_B", 0)
                with self.assertRaises(PermissionError):
                    manager.write(session["session_id"], "PROJECT_B", "echo bad\n")
            finally:
                manager.close(session["session_id"], "PROJECT_A")

    def test_11_terminal_input_is_bounded_and_rejects_nul(self):
        manager = v196.DeveloperTerminalManager()
        with tempfile.TemporaryDirectory(prefix="cf-term-") as temp:
            session = manager.open("PROJECT", Path(temp), "auto")
            try:
                with self.assertRaises(ValueError):
                    manager.write(session["session_id"], "PROJECT", "x" * (v196.MAX_INPUT_BYTES + 1))
                with self.assertRaises(ValueError):
                    manager.write(session["session_id"], "PROJECT", "\x00")
            finally:
                manager.close(session["session_id"], "PROJECT")

    def test_12_api_capabilities_gate_shell_input(self):
        self.assertIn("code_execution", cf._api_capabilities("POST", "/api/dev/terminal/open", {}))
        self.assertIn("code_execution", cf._api_capabilities("POST", "/api/dev/terminal/input", {}))
        self.assertIn("code_execution", cf._api_capabilities("POST", "/api/dev/terminal/interrupt", {}))
        self.assertEqual(cf._api_capabilities("GET", "/api/dev/ide/capabilities", {}), [])

    def test_13_terminal_interrupt_api_manager(self):
        manager = v196.DeveloperTerminalManager()
        with tempfile.TemporaryDirectory(prefix="cf-term-") as temp:
            session = manager.open("PROJECT", Path(temp), "auto")
            try:
                result = manager.interrupt(session["session_id"], "PROJECT")
                self.assertIn("interrupted", result)
            finally:
                manager.close(session["session_id"], "PROJECT")

    def test_14_ui_has_monaco_terminal_quickopen_and_single_palette(self):
        html = (Path(__file__).resolve().parents[1] / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("monaco-editor@0.57.0", html)
        self.assertIn("/static/vendor/monaco/min/vs", html)
        self.assertIn("function openDevQuickOpen()", html)
        self.assertIn("function interruptDevTerminal()", html)
        self.assertIn("function formatDevDocument()", html)
        self.assertEqual(html.count('id="devCommandPalette"'), 1)
        self.assertIn("devExplorerSelectedPath", html)

    def test_15_inline_script_has_no_html_markup_leak(self):
        html = (Path(__file__).resolve().parents[1] / "static" / "index.html").read_text(encoding="utf-8")
        script = html.split("<script>", 1)[1].split("</script>", 1)[0]
        self.assertNotIn('<div id="devCommandPalette"', script)

    def test_16_vendoring_script_and_release_docs_exist(self):
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / "tools" / "vendor_monaco.py").is_file())
        self.assertIn("MAX_ARCHIVE", (root / "tools" / "vendor_monaco.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
