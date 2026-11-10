import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V130DevStudioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf130-test-")
        self.old_paths = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        base = Path(self.tmp.name)
        cf.DATA_DIR = base / "data"
        cf.DB_PATH = cf.DATA_DIR / "cyberforge.db"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.init_database()
        cf.VAULT_KEY = None
        cf.vault_create("unit-test-passphrase-123", "unit-test-passphrase-123")
        self.old_ai = dict(cf.AI_RUNTIME_CONFIG)
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG.update({"provider": "qwencloud", "model": "qwen3.8-max", "region": "ap-southeast-1", "reasoning_effort": "medium", "api_key": "unit-test-key", "disable_env": True})

    def tearDown(self):
        cf.VAULT_KEY = None
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG.clear()
            cf.AI_RUNTIME_CONFIG.update(self.old_ai)
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old_paths
        self.tmp.cleanup()

    def _write(self, project_id, path, content):
        return cf.write_dev_project_file({"project_id": project_id, "path": path, "content": content, "expected_sha256": ""})

    def test_version_and_new_workspaces(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("EDITOR · MULTI-TAB", html)
        self.assertIn("Task Runner & Diagnostics", html)
        self.assertIn("Multi-file AI change request", html)
        self.assertIn("Ask AI to debug", html)

    def test_static_diagnostics_detect_syntax_and_secret_without_execution(self):
        project = cf.create_dev_project({"name": "Diagnostics"})
        self._write(project["id"], "bad.py", "API_KEY = 'super-secret-value-123'\ndef broken(:\n    pass\n")
        out = cf.dev_project_diagnostics({"project_id": project["id"], "path": "bad.py"})
        self.assertFalse(out["valid_syntax"])
        codes = {x["code"] for x in out["diagnostics"]}
        self.assertIn("syntax-error", codes)
        self.assertIn("possible-hardcoded-secret", codes)
        self.assertTrue(out["static_only"])

    def test_diagnostics_can_use_unsaved_buffer_and_do_not_write_file(self):
        project = cf.create_dev_project({"name": "Unsaved diagnostics"})
        saved = cf.read_dev_project_file(project["id"], "README.md")
        out = cf.dev_project_diagnostics({"project_id": project["id"], "path": "README.md", "content": "TODO: update this\n"})
        self.assertTrue(out["unsaved_buffer"])
        after = cf.read_dev_project_file(project["id"], "README.md")
        self.assertEqual(after["sha256"], saved["sha256"])

    def test_allowlisted_task_runner_rejects_arbitrary_command(self):
        project = cf.create_dev_project({"name": "Task runner", "template": "python"})
        out = cf.dev_project_task({"project_id": project["id"], "task": "project-check"})
        self.assertEqual(out["task"], "project-check")
        self.assertTrue(out["static_only"])
        with self.assertRaises(ValueError):
            cf.dev_project_task({"project_id": project["id"], "task": "rm -rf /"})

    def test_container_task_requires_explicit_acknowledgement(self):
        project = cf.create_dev_project({"name": "Container task", "template": "python"})
        with self.assertRaises(PermissionError):
            cf.dev_project_task({"project_id": project["id"], "task": "run-current-container", "path": "main.py"})
        with mock.patch.object(cf, "dev_project_run", return_value={"exit_code": 0}) as run:
            out = cf.dev_project_task({"project_id": project["id"], "task": "run-current-container", "path": "main.py", "acknowledged": True})
        self.assertEqual(out["exit_code"], 0)
        run.assert_called_once()

    def test_ai_debug_uses_selected_file_and_returns_no_write_claim(self):
        project = cf.create_dev_project({"name": "Debug", "template": "python"})
        with mock.patch.object(cf, "_ai_request", return_value={"content": "Likely cause: missing import. Suggested fix: add import."}) as req:
            out = cf.dev_ai_debug({"project_id": project["id"], "path": "main.py", "error": "NameError: Path"})
        self.assertIn("Likely cause", out["answer"])
        self.assertIn("No code was executed or changed", out["notice"])
        self.assertIn("Hello from CyberForge", req.call_args.args[0][1]["content"])

    def test_multi_file_patch_generation_and_partial_hunk_apply(self):
        project = cf.create_dev_project({"name": "Multi patch"})
        self._write(project["id"], "a.py", "value = 1\n")
        self._write(project["id"], "b.py", "value = 2\n")
        answer = {"summary": "Update both modules", "changes": [
            {"path": "a.py", "suggested_source": "value = 10\n", "reason": "Correct constant", "risk_notes": []},
            {"path": "b.py", "suggested_source": "value = 20\n", "reason": "Align constant", "risk_notes": []}
        ]}
        with mock.patch.object(cf, "_ai_request", return_value={"content": json.dumps(answer)}) as req:
            patch = cf.ai_project_patch_create({"project_id": project["id"], "request": "Update values", "file_paths": ["a.py", "b.py"]})
        self.assertEqual({x["path"] for x in patch["files"]}, {"a.py", "b.py"})
        self.assertIn("a.py", req.call_args.args[0][1]["content"])
        for f in patch["files"]:
            decision = "accept" if f["path"] == "a.py" else "reject"
            for h in f["hunks"]:
                cf.ai_project_patch_decide({"patch_id": patch["id"], "path": f["path"], "hunk_index": h["index"], "decision": decision})
        with self.assertRaises(PermissionError):
            cf.ai_project_patch_apply({"patch_id": patch["id"]})
        applied = cf.ai_project_patch_apply({"patch_id": patch["id"], "acknowledged": True})
        self.assertEqual(applied["applied_files"], ["a.py"])
        self.assertEqual(cf.read_dev_project_file(project["id"], "a.py")["content"], "value = 10\n")
        self.assertEqual(cf.read_dev_project_file(project["id"], "b.py")["content"], "value = 2\n")

    def test_multi_file_patch_rejects_unselected_path(self):
        project = cf.create_dev_project({"name": "Patch boundary"})
        self._write(project["id"], "one.py", "x = 1\n")
        answer = {"summary": "Bad path", "changes": [{"path": "../outside.py", "suggested_source": "x=2\n"}]}
        with mock.patch.object(cf, "_ai_request", return_value={"content": json.dumps(answer)}):
            with self.assertRaises((ValueError, PermissionError)):
                cf.ai_project_patch_create({"project_id": project["id"], "request": "change", "file_paths": ["one.py"]})

    def test_multi_file_patch_rejects_stale_file_before_writing_anything(self):
        project = cf.create_dev_project({"name": "Stale patch"})
        self._write(project["id"], "a.py", "a = 1\n")
        self._write(project["id"], "b.py", "b = 1\n")
        answer = {"summary": "Change both", "changes": [
            {"path": "a.py", "suggested_source": "a = 2\n"},
            {"path": "b.py", "suggested_source": "b = 2\n"}]}
        with mock.patch.object(cf, "_ai_request", return_value={"content": json.dumps(answer)}):
            patch = cf.ai_project_patch_create({"project_id": project["id"], "request": "change", "file_paths": ["a.py", "b.py"]})
        for item in patch["files"]:
            for h in item["hunks"]:
                cf.ai_project_patch_decide({"patch_id": patch["id"], "path": item["path"], "hunk_index": h["index"], "decision": "accept"})
        opened = cf.read_dev_project_file(project["id"], "b.py")
        cf.write_dev_project_file({"project_id": project["id"], "path": "b.py", "content": "b = 99\n", "expected_sha256": opened["sha256"]})
        with self.assertRaises(PermissionError):
            cf.ai_project_patch_apply({"patch_id": patch["id"], "acknowledged": True})
        self.assertEqual(cf.read_dev_project_file(project["id"], "a.py")["content"], "a = 1\n")

    def test_http_diagnostics_and_task_runner_routes(self):
        project = cf.create_dev_project({"name": "HTTP IDE", "template": "python"})
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            payload = json.dumps({"project_id": project["id"], "path": "main.py", "content": "print('unsaved')\n"}).encode()
            req = Request(base + "/api/dev/project/diagnostics", data=payload, headers={"Content-Type": "application/json", "Origin": base}, method="POST")
            with urlopen(req, timeout=5) as response:
                diag = json.loads(response.read())
            self.assertTrue(diag["unsaved_buffer"])
            body = json.dumps({"project_id": project["id"], "task": "project-check"}).encode()
            req = Request(base + "/api/dev/project/task", data=body, headers={"Content-Type": "application/json", "Origin": base}, method="POST")
            with urlopen(req, timeout=5) as response:
                task = json.loads(response.read())
            self.assertEqual(task["task"], "project-check")
        finally:
            server.shutdown(); thread.join(timeout=3); server.server_close()

    def test_editor_tabs_highlighting_and_shortcuts_are_wired(self):
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        for marker in ("devTabs", "renderDevTabs", "activateDevTab", "closeDevTab", "updateDevHighlight", "showDevCompletions", "saveAllDevFiles", "Ctrl+Space"):
            self.assertIn(marker, html)
        self.assertIn("data-dev-tab-close", html)
        self.assertIn("dev/project/diagnostics", html)

    def test_html_ids_are_unique(self):
        from html.parser import HTMLParser
        class IdParser(HTMLParser):
            def __init__(self): super().__init__(); self.ids = []
            def handle_starttag(self, tag, attrs):
                value = dict(attrs).get("id")
                if value: self.ids.append(value)
        parser = IdParser(); parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
        self.assertEqual(len(parser.ids), len(set(parser.ids)), "HTML id attributes must be unique")


if __name__ == "__main__":
    unittest.main()
