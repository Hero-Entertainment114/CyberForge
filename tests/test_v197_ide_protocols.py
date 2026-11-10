from __future__ import annotations

import importlib.util
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import cyberforge as cf
import v197_modules as v197


class V197ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-v197-test-")
        self.old_paths = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.OPENPHISH_DIR,
                          cf.OPENPHISH_PATH, cf.OPENPHISH_META_PATH)
        root = Path(self.temp.name)
        cf.DATA_DIR = root / "data"
        cf.DB_PATH = cf.DATA_DIR / "cyberforge.db"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.OPENPHISH_DIR = cf.DATA_DIR / "threat_feeds"
        cf.OPENPHISH_PATH = cf.OPENPHISH_DIR / "openphish_community.txt"
        cf.OPENPHISH_META_PATH = cf.OPENPHISH_DIR / "openphish_meta.json"
        cf.DATA_DIR.mkdir(parents=True, exist_ok=True)
        cf.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        cf.init_database()
        self.project = cf.create_dev_project({"name": "v197 protocol project", "template": "empty"})
        self.project_id = self.project["id"]
        self.root = cf._dev_project_root(self.project_id)

    def tearDown(self):
        for row in list(cf.DEV_LSP_MANAGER.list_sessions(self.project_id)):
            try:
                cf.DEV_LSP_MANAGER.stop(row["session_id"], self.project_id)
            except Exception:
                pass
        for row in list(cf.DEV_DAP_MANAGER.list_sessions(self.project_id)):
            try:
                cf.DEV_DAP_MANAGER.stop(row["session_id"], self.project_id)
            except Exception:
                pass
        (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.OPENPHISH_DIR,
         cf.OPENPHISH_PATH, cf.OPENPHISH_META_PATH) = self.old_paths
        self.temp.cleanup()

    def test_01_version_and_protocol_inventory(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        self.assertEqual(v197.capabilities()["lsp"]["protocol"], "LSP 3.x / JSON-RPC 2.0")
        self.assertEqual(v197.capabilities()["dap"]["protocol"], "DAP 1.x")
        self.assertIn("python", {x["language"] for x in v197.capabilities()["lsp"]["servers"]})
        self.assertFalse(v197.capabilities()["extension_architecture"]["vscode_vsix_execution"])

    def test_02_lsp_requires_explicit_acknowledgement(self):
        manager = v197.LanguageServerManager()
        with self.assertRaises(PermissionError):
            manager.start(self.project_id, self.root, "c", False)

    def test_03_lsp_rejects_unknown_language_and_method(self):
        manager = v197.LanguageServerManager()
        with self.assertRaises(ValueError):
            manager.start(self.project_id, self.root, "arbitrary", True)
        with self.assertRaises(ValueError):
            manager.request("LSP-not-real", self.project_id, "main.c", "executeCommand", 0, 0)

    def test_04_protocol_paths_reject_traversal_and_secrets(self):
        with self.assertRaises(ValueError):
            v197.safe_relative("../outside.py")
        with self.assertRaises(PermissionError):
            v197.safe_relative(".env")
        with self.assertRaises(PermissionError):
            v197.safe_relative(".git/config")
        with self.assertRaises(PermissionError):
            v197.safe_relative("node_modules/pkg/index.js")

    def test_05_lsp_project_binding_is_enforced(self):
        manager = v197.LanguageServerManager()
        with self.assertRaises(FileNotFoundError):
            manager.events("LSP-unknown", "another-project")

    @unittest.skipUnless(shutil.which("clangd"), "clangd is not installed on this test host")
    def test_06_real_clangd_lsp_initializes_and_returns_document_symbols(self):
        manager = v197.LanguageServerManager()
        source = self.root / "main.c"
        code = "int add(int a, int b) { return a + b; }\nint main(void) { return add(2, 3); }\n"
        source.write_text(code, encoding="utf-8")
        started = manager.start(self.project_id, self.root, "c", True)
        try:
            self.assertEqual(started["server"], "clangd")
            manager.open_document(started["session_id"], self.project_id, "main.c", "c", code)
            result = manager.request(started["session_id"], self.project_id, "main.c", "documentSymbol", 0, 0)
            names = {x.get("name") for x in result["result"] or []}
            self.assertIn("main", names)
            self.assertIn("add", names)
        finally:
            manager.stop(started["session_id"], self.project_id)

    def test_07_debugger_requires_explicit_acknowledgement(self):
        manager = v197.DebugAdapterManager()
        source = self.root / "safe.py"
        source.write_text("print('hello')\n", encoding="utf-8")
        with self.assertRaises(PermissionError):
            manager.start_python(self.project_id, self.root, "safe.py", [], [], False)

    def test_08_debugger_only_accepts_python_files(self):
        manager = v197.DebugAdapterManager()
        source = self.root / "main.js"
        source.write_text("console.log('hello')\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            manager.start_python(self.project_id, self.root, "main.js", [], [], True)

    @unittest.skipUnless(importlib.util.find_spec("debugpy") is not None, "debugpy is not installed on this test host")
    def test_09_real_debugpy_dap_launch_stacktrace_and_terminate(self):
        manager = v197.DebugAdapterManager()
        source = self.root / "debug_target.py"
        source.write_text("value = 40\nvalue += 2\nprint(value)\n", encoding="utf-8")
        started = manager.start_python(self.project_id, self.root, "debug_target.py", [], [2], True)
        sid = started["session_id"]
        try:
            self.assertEqual(started["adapter"], "debugpy")
            # debugpy may stop at entry before the requested line breakpoint.
            time.sleep(.25)
            threads = manager.command(sid, self.project_id, "threads", {}, False)
            self.assertTrue(threads["body"].get("threads"))
            trace = manager.command(sid, self.project_id, "stackTrace", {"thread_id": threads["body"]["threads"][0]["id"]}, False)
            self.assertIn("stackFrames", trace["body"])
            stopped = manager.command(sid, self.project_id, "terminate", {}, True)
            self.assertEqual(stopped["command"], "terminate")
        finally:
            manager.stop(sid, self.project_id)

    def test_10_git_local_source_control_flow(self):
        if not shutil.which("git"):
            self.skipTest("Git CLI is not installed")
        source = self.root / "README.md"
        source.write_text("CyberForge Dev Studio\n", encoding="utf-8")
        init = cf.dev_project_git({"project_id": self.project_id, "action": "init", "acknowledged": True})
        self.assertEqual(init["exit_code"], 0)
        with self.assertRaises(PermissionError):
            cf.dev_project_git({"project_id": self.project_id, "action": "identity", "name": "Dev", "email": "dev@example.test"})
        identity = cf.dev_project_git({"project_id": self.project_id, "action": "identity", "name": "Dev Tester", "email": "dev@example.test", "acknowledged": True})
        self.assertEqual(identity["exit_code"], 0)
        stage = cf.dev_project_git({"project_id": self.project_id, "action": "stage", "paths": ["README.md"], "acknowledged": True})
        self.assertEqual(stage["exit_code"], 0)
        unstage = cf.dev_project_git({"project_id": self.project_id, "action": "unstage", "paths": ["README.md"], "acknowledged": True})
        self.assertEqual(unstage["exit_code"], 0)
        stage = cf.dev_project_git({"project_id": self.project_id, "action": "stage", "paths": ["README.md"], "acknowledged": True})
        self.assertEqual(stage["exit_code"], 0)
        commit = cf.dev_project_git({"project_id": self.project_id, "action": "commit", "message": "Initial local commit", "acknowledged": True})
        self.assertEqual(commit["exit_code"], 0)
        create = cf.dev_project_git({"project_id": self.project_id, "action": "branch-create", "branch": "feature/ide-test", "acknowledged": True})
        self.assertEqual(create["exit_code"], 0)
        branches = cf.dev_project_git({"project_id": self.project_id, "action": "branches"})
        self.assertIn("feature/ide-test", branches["output"])

    def test_11_git_identity_rejects_control_characters(self):
        if not shutil.which("git"):
            self.skipTest("Git CLI is not installed")
        cf.dev_project_git({"project_id": self.project_id, "action": "init", "acknowledged": True})
        with self.assertRaises(ValueError):
            cf.dev_project_git({"project_id": self.project_id, "action": "identity", "name": "Bad\nName", "email": "dev@example.test", "acknowledged": True})

    def test_12_git_external_filter_is_rejected_before_staging(self):
        if not shutil.which("git"):
            self.skipTest("Git CLI is not installed")
        cf.dev_project_git({"project_id": self.project_id, "action": "init", "acknowledged": True})
        (self.root / ".gitattributes").write_text("*.txt filter=external-tool\n", encoding="utf-8")
        (self.root / "note.txt").write_text("sample\n", encoding="utf-8")
        with self.assertRaises(PermissionError):
            cf.dev_project_git({"project_id": self.project_id, "action": "stage", "paths": ["note.txt"], "acknowledged": True})

    def test_13_git_include_configuration_is_rejected_before_branch_switch(self):
        if not shutil.which("git"):
            self.skipTest("Git CLI is not installed")
        cf.dev_project_git({"project_id": self.project_id, "action": "init", "acknowledged": True})
        config = self.root / ".git" / "config"
        config.write_text(config.read_text(encoding="utf-8") + "\n[include]\n    path = ../external-config\n", encoding="utf-8")
        with self.assertRaises(PermissionError):
            cf.dev_project_git({"project_id": self.project_id, "action": "branch-switch", "branch": "main", "acknowledged": True})

    def test_14_git_attribute_symlink_is_rejected(self):
        if not shutil.which("git"):
            self.skipTest("Git CLI is not installed")
        cf.dev_project_git({"project_id": self.project_id, "action": "init", "acknowledged": True})
        outside = Path(self.temp.name) / "outside-attributes"
        outside.write_text("*.bin filter=external\n", encoding="utf-8")
        target = self.root / ".gitattributes"
        try:
            target.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are not available on this host")
        with self.assertRaises(PermissionError):
            cf.dev_project_git({"project_id": self.project_id, "action": "stage", "paths": ["README.md"], "acknowledged": True})

    def test_15_permission_matrix_for_lsp_dap_and_git(self):
        self.assertIn("code_execution", cf._api_capabilities("POST", "/api/dev/lsp/start", {}))
        self.assertIn("code_execution", cf._api_capabilities("POST", "/api/dev/debugger/start", {}))
        self.assertIn("project_write", cf._api_capabilities("POST", "/api/dev/project/git", {"action": "identity"}))
        self.assertIn("project_read", cf._api_capabilities("POST", "/api/dev/project/git", {"action": "status"}))


if __name__ == "__main__":
    unittest.main()
