import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from unittest import mock
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V120DevStudioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf120-test-")
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
            cf.AI_RUNTIME_CONFIG.clear(); cf.AI_RUNTIME_CONFIG.update(self.old_ai)
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old_paths
        self.tmp.cleanup()

    def test_version_and_agent_roles(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        roles = cf.multi_agent_roles()
        self.assertEqual(len(roles["development"]), 5)
        self.assertEqual(len(roles["security"]), 5)
        self.assertEqual(roles["development"][-1]["id"], "lead")

    def test_create_python_project_and_templates(self):
        project = cf.create_dev_project({"name": "Demo App", "description": "demo", "template": "python"})
        self.assertRegex(project["id"], r"^PRJ-[a-f0-9]{12}$")
        paths = {x["path"] for x in project["tree"]}
        self.assertIn("main.py", paths)
        self.assertIn("tests/test_main.py", paths)
        self.assertEqual(project["template"], "python")
        listed = cf.list_dev_projects()
        self.assertEqual(listed[0]["id"], project["id"])
        self.assertGreaterEqual(listed[0]["file_count"], 3)

    def test_create_templates_web_node_empty_and_security(self):
        for template, expected in [("web", "index.html"), ("node", "src/index.js"), ("empty", "README.md"), ("security-tool", "analyzer.py")]:
            p = cf.create_dev_project({"name": "Project " + template, "template": template})
            self.assertIn(expected, {x["path"] for x in p["tree"]})

    def test_file_read_write_and_optimistic_lock(self):
        p = cf.create_dev_project({"name": "Write Test", "template": "python"})
        opened = cf.read_dev_project_file(p["id"], "main.py")
        result = cf.write_dev_project_file({"project_id": p["id"], "path": "main.py", "content": "print('updated')\n", "expected_sha256": opened["sha256"]})
        self.assertTrue(result["saved"])
        reread = cf.read_dev_project_file(p["id"], "main.py")
        self.assertEqual(reread["content"], "print('updated')\n")
        self.assertEqual(reread["sha256"], result["sha256"])
        with self.assertRaises(PermissionError):
            cf.write_dev_project_file({"project_id": p["id"], "path": "main.py", "content": "stale\n", "expected_sha256": opened["sha256"]})

    def test_file_create_requires_existing_parent_and_supports_folder(self):
        p = cf.create_dev_project({"name": "Folders"})
        with self.assertRaises(FileNotFoundError):
            cf.write_dev_project_file({"project_id": p["id"], "path": "src/app.py", "content": "x=1\n", "expected_sha256": ""})
        cf.create_dev_project_folder({"project_id": p["id"], "path": "src"})
        out = cf.write_dev_project_file({"project_id": p["id"], "path": "src/app.py", "content": "x=1\n", "expected_sha256": ""})
        self.assertTrue(out["saved"])

    def test_path_traversal_and_secret_files_are_rejected(self):
        p = cf.create_dev_project({"name": "Path Safety"})
        for rel in ("../outside.txt", "/tmp/out.txt", "C:/temp/x.py", "a/../../x", ".git/config", ".env", "secrets/.env.local"):
            with self.subTest(rel=rel):
                with self.assertRaises((ValueError, PermissionError)):
                    cf.read_dev_project_file(p["id"], rel)

    def test_symlinks_are_rejected(self):
        p = cf.create_dev_project({"name": "Symlink Safety"})
        root = cf._dev_project_root(p["id"])
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret", encoding="utf-8")
        try:
            (root / "linked").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable on this platform")
        with self.assertRaises(PermissionError):
            cf.read_dev_project_file(p["id"], "linked/secret.txt")

    def test_literal_project_search_and_excluded_dirs(self):
        p = cf.create_dev_project({"name": "Search", "template": "python"})
        opened = cf.read_dev_project_file(p["id"], "main.py")
        cf.write_dev_project_file({"project_id": p["id"], "path": "main.py", "content": "SECRET_MARKER = 'find-me'\n", "expected_sha256": opened["sha256"]})
        root = cf._dev_project_root(p["id"])
        (root / ".env").write_text("find-me", encoding="utf-8")
        (root / "node_modules").mkdir()
        (root / "node_modules" / "bad.js").write_text("find-me", encoding="utf-8")
        result = cf.search_dev_project({"project_id": p["id"], "query": "find-me"})
        self.assertEqual(result["total_hits"], 1)
        self.assertEqual(result["hits"][0]["path"], "main.py")

    def test_archive_preserves_project_and_restore(self):
        p = cf.create_dev_project({"name": "Archive"})
        archived = cf.update_dev_project({"project_id": p["id"], "status": "archived"})
        self.assertEqual(archived["status"], "archived")
        with self.assertRaises(ValueError):
            cf.get_dev_project(p["id"])
        restored = cf.update_dev_project({"project_id": p["id"], "status": "active"})
        self.assertEqual(restored["status"], "active")
        self.assertIn("README.md", {x["path"] for x in cf.get_dev_project(p["id"])["tree"]})

    def test_syntax_check_is_static(self):
        p = cf.create_dev_project({"name": "Syntax", "template": "python"})
        opened = cf.read_dev_project_file(p["id"], "main.py")
        cf.write_dev_project_file({"project_id": p["id"], "path": "main.py", "content": "def broken(:\n", "expected_sha256": opened["sha256"]})
        out = cf.dev_project_syntax({"project_id": p["id"], "path": "main.py"})
        self.assertFalse(out["valid_syntax"])
        self.assertEqual(out["path"], "main.py")
        self.assertEqual(cf.list_dev_project_runs(p["id"])[0]["run_type"], "syntax")

    def test_git_actions_are_fixed_and_no_shell(self):
        p = cf.create_dev_project({"name": "Git"})
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/git"), mock.patch.object(cf.subprocess, "run", return_value=subprocess.CompletedProcess(["git"], 0, "ok", "")) as run:
            with self.assertRaises(PermissionError):
                cf.dev_project_git({"project_id": p["id"], "action": "init"})
            result = cf.dev_project_git({"project_id": p["id"], "action": "init", "acknowledged": True})
        self.assertEqual(result["exit_code"], 0)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/git")
        self.assertEqual(argv[-1], "init")
        self.assertIn("--no-pager", argv)
        self.assertTrue(any(x.startswith("core.hooksPath=") for x in argv))
        self.assertIn("core.fsmonitor=false", argv)
        self.assertIn("core.untrackedCache=false", argv)
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        with self.assertRaises(ValueError):
            cf.dev_project_git({"project_id": p["id"], "action": "-c core.hooksPath=/tmp"})

    def test_container_run_requires_ack_and_calls_only_project_file_content(self):
        p = cf.create_dev_project({"name": "Run", "template": "python"})
        with self.assertRaises(PermissionError):
            cf.dev_project_run({"project_id": p["id"], "path": "main.py"})
        with mock.patch.object(cf, "sandbox_run", return_value={"exit_code": 0, "output": "ok", "notice": "container"}) as runner:
            result = cf.dev_project_run({"project_id": p["id"], "path": "main.py", "acknowledged": True})
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("Hello from CyberForge", runner.call_args.args[0])
        with self.assertRaises(ValueError):
            cf.dev_project_run({"project_id": p["id"], "path": "README.md", "acknowledged": True})

    def test_multi_agent_pipeline_collaborates_sequentially(self):
        p = cf.create_dev_project({"name": "Agent Project", "template": "python"})
        with mock.patch.object(cf, "_ai_request", side_effect=[{"content": f"Agent report {n}"} for n in range(1, 6)]) as req:
            result = cf.multi_agent_run({"objective": "Design and implement a safe feature", "mode": "development", "depth": "full", "project_id": p["id"], "file_paths": ["main.py"]})
        self.assertEqual(result["completed_agents"], 5)
        self.assertEqual(len(req.call_args_list), 5)
        second_user = req.call_args_list[1].args[0][1]["content"]
        self.assertIn("Agent report 1", second_user)
        last_user = req.call_args_list[-1].args[0][1]["content"]
        self.assertIn("Agent report 4", last_user)
        history = cf.list_dev_project_runs(p["id"])
        self.assertEqual(history[0]["run_type"], "multi-agent")
        self.assertEqual(history[0]["result"]["completed_agents"], 5)

    def test_multi_agent_quick_has_three_specialists(self):
        with mock.patch.object(cf, "_ai_request", side_effect=[{"content": "stage"} for _ in range(3)]) as req:
            result = cf.multi_agent_run({"objective": "Review project requirements", "mode": "development", "depth": "quick"})
        self.assertEqual(result["total_agents"], 3)
        self.assertEqual(req.call_count, 3)

    def test_multi_agent_rejects_bad_mode_context_and_file_count(self):
        with self.assertRaises(ValueError):
            cf.multi_agent_run({"objective": "x", "mode": "shell"})
        with self.assertRaises(ValueError):
            cf.multi_agent_run({"objective": "x", "context": "a" * 70_001})
        p = cf.create_dev_project({"name": "Too many"})
        with self.assertRaises(ValueError):
            cf.multi_agent_run({"objective": "x", "project_id": p["id"], "file_paths": ["a"] * 7})

    def test_multi_agent_requires_provider_key_before_any_call(self):
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG["api_key"] = None
            cf.AI_RUNTIME_CONFIG["disable_env"] = True
        with mock.patch.object(cf, "_ai_request") as req:
            with self.assertRaises(RuntimeError):
                cf.multi_agent_run({"objective": "x", "mode": "security"})
            req.assert_not_called()

    def test_multi_agent_partial_stage_failures_are_reported_not_fabricated(self):
        responses = [{"content": "ok"}, RuntimeError("simulated quota"), {"content": "ok"}, {"content": "ok"}, {"content": "final"}]
        with mock.patch.object(cf, "_ai_request", side_effect=responses):
            result = cf.multi_agent_run({"objective": "Triage incident", "mode": "security", "depth": "full"})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["completed_agents"], 4)
        self.assertEqual(result["stages"][1]["status"], "failed")
        self.assertIn("simulated quota", result["stages"][1]["error"])

    def test_project_context_cannot_read_env_or_outside_path(self):
        p = cf.create_dev_project({"name": "Project Context"})
        root = cf._dev_project_root(p["id"])
        (root / ".env").write_text("VERY_SECRET", encoding="utf-8")
        with self.assertRaises(PermissionError):
            cf._multi_agent_project_context(p["id"], [".env"])
        with self.assertRaises(ValueError):
            cf._multi_agent_project_context(p["id"], ["../../outside.py"])


    def test_user_controlled_project_paths_are_bound_with_event_listeners(self):
        p = cf.create_dev_project({"name": "Quoted path"})
        cf.create_dev_project_folder({"project_id": p["id"], "path": "src"})
        out = cf.write_dev_project_file({"project_id": p["id"], "path": "src/it's-safe.js", "content": "const value = 1;\n", "expected_sha256": ""})
        self.assertTrue(out["saved"])
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("data-dev-open=", html)
        self.assertIn("data-dev-context=", html)
        self.assertIn("data-dev-search-path=", html)
        self.assertNotIn("onclick=\"openDevProjectFile('${esc(x.path)}')\"", html)
        self.assertNotIn("onclick=\"openDevProjectFile('${esc(h.path)}')\"", html)

    def test_http_project_and_multi_agent_routes(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(base + "/api/ai/multi-agent/roles", timeout=5) as response:
                roles = json.loads(response.read())
            self.assertIn("development", roles)
            body = json.dumps({"action": "create", "name": "HTTP project", "template": "python", "_permission_acknowledged": ["project_write"]}).encode()
            request = Request(base + "/api/dev/projects", data=body, headers={"Content-Type": "application/json", "Origin": base}, method="POST")
            with urlopen(request, timeout=5) as response:
                project = json.loads(response.read())
            with urlopen(base + "/api/dev/project?id=" + project["id"], timeout=5) as response:
                detail = json.loads(response.read())
            self.assertEqual(detail["id"], project["id"])
            self.assertIn("main.py", {x["path"] for x in detail["tree"]})
            with urlopen(base + "/api/dev/project/file?project_id=" + project["id"] + "&path=main.py", timeout=5) as response:
                opened = json.loads(response.read())
            save_body = json.dumps({"project_id": project["id"], "path": "main.py", "content": "print('HTTP saved')\n", "expected_sha256": opened["sha256"], "_permission_acknowledged": ["project_write"]}).encode()
            save_req = Request(base + "/api/dev/project/file/write", data=save_body, headers={"Content-Type": "application/json", "Origin": base}, method="POST")
            with urlopen(save_req, timeout=5) as response:
                saved = json.loads(response.read())
            self.assertTrue(saved["saved"])
            agent_body = json.dumps({"objective": "Review this development project", "mode": "development", "depth": "quick", "project_id": project["id"], "file_paths": ["main.py"], "_permission_acknowledged": ["ai_provider_access", "_cloud_context_ack"]}).encode()
            agent_req = Request(base + "/api/ai/multi-agent/run", data=agent_body, headers={"Content-Type": "application/json", "Origin": base}, method="POST")
            with mock.patch.object(cf, "_ai_request", side_effect=[{"content": "architect report"}, {"content": "review report"}, {"content": "lead report"}]):
                with urlopen(agent_req, timeout=10) as response:
                    team = json.loads(response.read())
            self.assertEqual(team["completed_agents"], 3)
            self.assertEqual(team["status"], "completed")
        finally:
            server.shutdown(); thread.join(timeout=3); server.server_close()


if __name__ == "__main__":
    unittest.main()
