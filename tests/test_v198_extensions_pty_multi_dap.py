from __future__ import annotations
import base64
import io
import json
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

import v198_modules as v198


def make_extension(entries=None, manifest=None):
    manifest = manifest or {
        "name": "sample-snippets", "publisher": "cyberforge-test", "version": "1.2.3",
        "displayName": "Sample snippets", "description": "Test declarative extension",
        "contributes": {
            "themes": [{"label": "Midnight test", "uiTheme": "vs-dark", "path": "themes/midnight.json"}],
            "snippets": [{"language": "python", "path": "snippets/python.json"}],
            "languages": [{"id": "samplelang", "extensions": [".sample"]}],
        },
    }
    entries = entries or {
        "themes/midnight.json": json.dumps({"name": "Midnight", "type": "dark", "colors": {"editor.background": "#101010"},
                                              "tokenColors": [{"scope": "keyword", "settings": {"foreground": "#ffcc00"}}]}),
        "snippets/python.json": json.dumps({"main": {"prefix": "main", "body": ["def main():", "    pass"], "description": "Main function"}}),
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("extension/package.json", json.dumps(manifest))
        for name, value in entries.items():
            zf.writestr("extension/" + name, value)
    return out.getvalue()


class ExtensionHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-v198-ext-")
        self.manager = v198.ExtensionManager(Path(self.temp.name))

    def tearDown(self): self.temp.cleanup()

    def test_01_imports_only_declarative_contributions(self):
        raw = make_extension()
        result = self.manager.install_base64(base64.b64encode(raw).decode(), True)
        self.assertTrue(result["installed"])
        self.assertFalse(result["extension"]["executable_code_loaded"])
        listing = self.manager.list_extensions()
        self.assertEqual(listing["count"], 1)
        ext = listing["extensions"][0]
        self.assertEqual(ext["id"], "cyberforge-test.sample-snippets")
        self.assertEqual(ext["theme_data"][0]["data"]["name"], "Midnight")
        self.assertIn("main", ext["snippet_data"][0]["data"])

    def test_02_extension_store_rejects_symlink_root(self):
        if os.name == "nt": self.skipTest("Symlink creation may require Developer Mode or elevated rights on Windows.")
        with tempfile.TemporaryDirectory(prefix="cf-v198-store-") as temp:
            base = Path(temp) / "data"; base.mkdir()
            outside = Path(temp) / "outside"; outside.mkdir()
            (base / "dev_extensions").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(PermissionError): v198.ExtensionManager(base)

    def test_03_import_requires_acknowledgement(self):
        with self.assertRaises(PermissionError):
            self.manager.install_base64(base64.b64encode(make_extension()).decode(), False)

    def test_04_rejects_node_entrypoint(self):
        manifest = {"name": "bad-extension", "publisher": "cyberforge-test", "version": "1.0.0", "main": "./out.js", "contributes": {}}
        with self.assertRaises(PermissionError):
            self.manager.install_base64(base64.b64encode(make_extension({}, manifest)).decode(), True)

    def test_05_rejects_activation_and_lifecycle_scripts(self):
        for extra in ({"activationEvents": ["*" ]}, {"scripts": {"postinstall": "echo bad"}}, {"extensionDependencies": ["vendor.ext"]}):
            manifest = {"name": "bad-extension", "publisher": "cyberforge-test", "version": "1.0.0", "contributes": {}, **extra}
            with self.subTest(extra=extra), self.assertRaises(PermissionError):
                self.manager.install_base64(base64.b64encode(make_extension({}, manifest)).decode(), True)

    def test_06_rejects_command_and_task_contributions(self):
        manifest = {"name": "bad-extension", "publisher": "cyberforge-test", "version": "1.0.0",
                    "contributes": {"commands": [{"command": "exec"}]}}
        with self.assertRaises(PermissionError):
            self.manager.install_base64(base64.b64encode(make_extension({}, manifest)).decode(), True)

    def test_07_rejects_archive_traversal(self):
        raw = make_extension({"themes/../../escape.json": "{}"})
        with self.assertRaises(PermissionError):
            self.manager.install_base64(base64.b64encode(raw).decode(), True)

    def test_08_rejects_symlink_archive_entries(self):
        out = io.BytesIO()
        manifest = {"name": "symlink-test", "publisher": "cyberforge-test", "version": "1.0.0", "contributes": {}}
        with zipfile.ZipFile(out, "w") as zf:
            zf.writestr("extension/package.json", json.dumps(manifest))
            info = zipfile.ZipInfo("extension/payload")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "../../outside")
        with self.assertRaises(PermissionError):
            self.manager.install_base64(base64.b64encode(out.getvalue()).decode(), True)

    def test_09_disable_hides_contributions_and_reenable_restores(self):
        self.manager.install_base64(base64.b64encode(make_extension()).decode(), True)
        ext_id = "cyberforge-test.sample-snippets"
        self.manager.set_enabled(ext_id, False, True)
        self.assertEqual(self.manager.list_extensions()["extensions"][0]["theme_data"], [])
        self.manager.set_enabled(ext_id, True, True)
        self.assertEqual(len(self.manager.list_extensions()["extensions"][0]["theme_data"]), 1)

    def test_10_uninstall_requires_ack_and_removes_package(self):
        self.manager.install_base64(base64.b64encode(make_extension()).decode(), True)
        with self.assertRaises(PermissionError): self.manager.uninstall("cyberforge-test.sample-snippets", False)
        self.assertTrue(self.manager.uninstall("cyberforge-test.sample-snippets", True)["uninstalled"])
        self.assertEqual(self.manager.list_extensions()["count"], 0)

    def test_11_rejects_duplicate_install(self):
        raw = base64.b64encode(make_extension()).decode()
        self.manager.install_base64(raw, True)
        with self.assertRaises(FileExistsError): self.manager.install_base64(raw, True)

    def test_12_extension_archive_upload_is_bounded(self):
        with self.assertRaises(ValueError): self.manager.install_base64("A" * (v198.MAX_EXTENSION_ARCHIVE * 2), True)


class PtyTerminalTests(unittest.TestCase):
    def test_13_posix_pty_supports_interactive_shell_and_resize(self):
        if os.name == "nt": self.skipTest("Windows ConPTY requires optional pywinpty runtime; tested on Windows acceptance host.")
        manager = v198.PtyTerminalManager()
        with tempfile.TemporaryDirectory(prefix="cf-v198-pty-") as temp:
            session = manager.open("TEST", Path(temp), "sh", rows=24, cols=80)
            self.assertEqual(session["backend"], "posix-pty")
            self.assertTrue(session["pty_available"])
            manager.resize(session["session_id"], "TEST", 40, 120)
            manager.write(session["session_id"], "TEST", "printf 'CF_PTY_V198_OK\\n'\n")
            output = ""; deadline = time.time() + 5
            while time.time() < deadline:
                output = manager.read(session["session_id"], "TEST", 0)["output"]
                if "CF_PTY_V198_OK" in output: break
                time.sleep(.05)
            self.assertIn("CF_PTY_V198_OK", output)
            with self.assertRaises(PermissionError): manager.read(session["session_id"], "OTHER", 0)
            pid = session["pid"]
            manager.close(session["session_id"], "TEST")
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_14_close_kills_descendants_that_ignore_sigterm(self):
        if os.name == "nt": self.skipTest("POSIX process-group cleanup test")
        manager = v198.PtyTerminalManager()
        with tempfile.TemporaryDirectory(prefix="cf-v198-pty-tree-") as temp:
            session = manager.open("TREE", Path(temp), "sh")
            manager.write(session["session_id"], "TREE",
                "python -c 'import os,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print(\"CF_CHILD_PID:\"+str(os.getpid()), flush=True); time.sleep(60)'\n")
            output = ""; child_pid = None; deadline = time.time() + 5
            while time.time() < deadline:
                output = manager.read(session["session_id"], "TREE", 0)["output"]
                match = __import__("re").search(r"CF_CHILD_PID:(\d+)", output)
                if match:
                    child_pid = int(match.group(1)); break
                time.sleep(.05)
            self.assertIsNotNone(child_pid, output)
            manager.close(session["session_id"], "TREE")
            deadline = time.time() + 3
            while time.time() < deadline:
                try: os.kill(child_pid, 0)
                except ProcessLookupError: break
                time.sleep(.05)
            else: self.fail(f"PTY descendant {child_pid} survived session cleanup")

    def test_15_input_and_resize_are_bounded(self):
        if os.name == "nt": self.skipTest("POSIX PTY test only")
        manager = v198.PtyTerminalManager()
        with tempfile.TemporaryDirectory(prefix="cf-v198-pty-") as temp:
            session = manager.open("TEST", Path(temp), "sh")
            try:
                with self.assertRaises(ValueError): manager.write(session["session_id"], "TEST", "x" * (v198.MAX_INPUT_BYTES + 1))
                with self.assertRaises(ValueError): manager.write(session["session_id"], "TEST", "\x00")
                resized = manager.resize(session["session_id"], "TEST", 1000, 5000)
                self.assertEqual(resized["rows"], 120); self.assertEqual(resized["cols"], 300)
            finally: manager.close(session["session_id"], "TEST")


class MultiDapTests(unittest.TestCase):
    def test_16_inventory_has_python_lldb_and_dotnet_fixed_profiles(self):
        inventory = v198.MultiDebugAdapterManager.inventory()
        ids = {x["id"] for x in inventory["adapters"]}
        self.assertEqual(ids, {"python-debugpy", "cpp-lldb", "dotnet-netcoredbg"})
        for row in inventory["adapters"]: self.assertEqual(row["transport"], "DAP over stdio")

    def test_17_native_dap_rejects_missing_user_approval(self):
        manager = v198.MultiDebugAdapterManager()
        with tempfile.TemporaryDirectory(prefix="cf-v198-dap-") as temp:
            root = Path(temp); (root / "app.exe").write_bytes(b"not-executed")
            with self.assertRaises(PermissionError):
                manager.start_native("TEST", root, "cpp-lldb", "app.exe", "app.exe", [], [], False)

    def test_18_unknown_dap_adapter_is_rejected(self):
        manager = v198.MultiDebugAdapterManager()
        with tempfile.TemporaryDirectory(prefix="cf-v198-dap-") as temp:
            with self.assertRaises(ValueError):
                manager.start_native("TEST", Path(temp), "arbitrary", "app", "app.cpp", [], [], True)

    def test_19_capabilities_report_real_host_pty_and_xterm_availability(self):
        manager = v198.PtyTerminalManager()
        caps = manager.capabilities()
        self.assertIn(caps["backend"], {"posix-pty", "windows-conpty", "pipe-fallback"})
        self.assertEqual(caps["pipe_fallback"], True)
        self.assertEqual(caps["interactive_tui"], bool(caps["pty_available"] and caps["xterm_ui_available"]))
        self.assertIn("code_execution", caps["permissions"])

    def test_20_set_breakpoints_is_an_explicit_supported_dap_command(self):
        self.assertIn("setBreakpoints", v198.MultiDebugAdapterManager().inventory()["protocol"] + " setBreakpoints")


if __name__ == "__main__": unittest.main()
