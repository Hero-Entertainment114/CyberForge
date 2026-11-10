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


class V111ControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf111-test-")
        self.old_paths = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        base = Path(self.tmp.name)
        cf.DATA_DIR = base / "data"
        cf.DB_PATH = cf.DATA_DIR / "cyberforge.db"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.init_database()
        cf.VAULT_KEY = None
        cf.vault_create("unit-test-passphrase-123", "unit-test-passphrase-123")
        self.case = cf.create_case({"title": "AI Navigator test case", "scope": "Local test fixtures only"})
        self.old_ai = dict(cf.AI_RUNTIME_CONFIG)
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG.update({"provider": "qwencloud", "model": "qwen3.8-max", "region": "ap-southeast-1", "reasoning_effort": "medium", "api_key": None, "disable_env": True})
        with cf.AI_AGENT_LOCK:
            cf.AI_AGENT_PLANS.clear()
        with cf.AI_PATCH_LOCK:
            cf.AI_PATCHES.clear()
        self.old_connectors = {k: dict(v) for k, v in cf.CONNECTOR_CONFIG.items()}
        with cf.CONNECTOR_LOCK:
            cf.CONNECTOR_CONFIG["misp"] = {"base_url": "", "api_key": None}
            cf.CONNECTOR_CONFIG["cape"] = {"base_url": "", "token": None}

    def tearDown(self):
        cf.VAULT_KEY = None
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG.clear(); cf.AI_RUNTIME_CONFIG.update(self.old_ai)
        with cf.CONNECTOR_LOCK:
            cf.CONNECTOR_CONFIG.clear(); cf.CONNECTOR_CONFIG.update(self.old_connectors)
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old_paths
        self.tmp.cleanup()

    def test_version_and_agent_tool_registry(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        self.assertIn("evidence_triage", cf.AGENT_TOOL_SPECS)
        self.assertIn("knowledge_search", cf.AGENT_TOOL_SPECS)
        self.assertLessEqual(len(cf.AGENT_TOOL_SPECS), 20)

    def test_bundled_knowledge_is_indexed_and_retrievable(self):
        docs = cf.list_knowledge_documents()
        self.assertGreaterEqual(len(docs), 3)
        result = cf.search_knowledge_base("unsafe deserialization safe loader", 5)
        self.assertTrue(result["results"])
        self.assertIn("secure-code-review.md", json.dumps(result))
        self.assertIn("untrusted reference material", result["notice"])

    def test_knowledge_seed_files_live_in_user_data_directory(self):
        cf.list_knowledge_documents()
        seed_dir = cf.DATA_DIR / "knowledge_base"
        self.assertTrue((seed_dir / "secure-code-review.md").is_file())
        self.assertTrue(seed_dir.is_dir())

    def test_local_knowledge_search_supports_vietnamese_terms(self):
        item = cf.index_knowledge_document("viet-playbook.md", "Điều tra sự cố cần bảo toàn bằng chứng, dấu thời gian và chuỗi bàn giao.")
        results = cf.search_knowledge_base("điều tra sự cố bảo toàn bằng chứng", 10)["results"]
        self.assertTrue(any(x["document_id"] == item["document_id"] for x in results))

    def test_local_knowledge_upload_search_and_deduplicate(self):
        text = "Incident responders should preserve evidence hashes and maintain chain of custody."
        one = cf.index_knowledge_document("my-playbook.md", text)
        two = cf.index_knowledge_document("copy.md", text)
        self.assertTrue(one["indexed"])
        self.assertTrue(two["duplicate"])
        results = cf.search_knowledge_base("preserve evidence hashes chain custody", 5)["results"]
        self.assertTrue(any(x["document_id"] == one["document_id"] for x in results))

    def test_bundled_reference_cannot_be_deleted(self):
        bundled = next(x for x in cf.list_knowledge_documents() if x["source"] == "bundled-reference")
        with self.assertRaises(PermissionError):
            cf.delete_knowledge_document(bundled["id"])

    def test_ai_planner_offline_routes_code_review_and_executes_once(self):
        plan = cf.ai_agent_plan({"objective": "Review this Python code for bugs and security", "context": "password = 'hardcoded'\neval(input())", "case_id": self.case["id"]})
        self.assertEqual(plan["planning_mode"], "offline-keyword-router")
        self.assertEqual(plan["steps"][0]["tool"], "code_review")
        run = cf.ai_agent_execute({"plan_id": plan["plan_id"]})
        self.assertEqual(run["results"][0]["status"], "completed")
        with self.assertRaises(ValueError):
            cf.ai_agent_execute({"plan_id": plan["plan_id"]})
        saved = cf.capture_case_result({"case_id": self.case["id"], "module_id": "ai_agent_run", "summary": "Agent test", "result": run})
        self.assertEqual(saved["status"], "captured")

    def test_ai_planner_uses_selected_evidence_and_static_triage(self):
        evidence = cf.store_evidence(b"plain static sample with harmless content", "sample.txt", self.case["id"], "test fixture")
        plan = cf.ai_agent_plan({"objective": "Please analyze this malware sample file", "case_id": self.case["id"], "evidence_id": evidence["id"]})
        self.assertEqual(plan["steps"][0]["tool"], "evidence_triage")
        self.assertEqual(plan["steps"][0]["args"]["evidence_id"], evidence["id"])
        with mock.patch.object(cf.shutil, "which", return_value=None):
            run = cf.ai_agent_execute({"plan_id": plan["plan_id"]})
        self.assertEqual(run["results"][0]["status"], "completed")
        self.assertIn("not uploaded", json.dumps(run["results"][0]["result"]).lower())

    def test_planner_rejects_evidence_from_another_case(self):
        other = cf.create_case({"title": "Other case"})
        evidence = cf.store_evidence(b"data", "x.bin", other["id"])
        with self.assertRaises(PermissionError):
            cf.ai_agent_plan({"objective": "triage malware sample", "case_id": self.case["id"], "evidence_id": evidence["id"]})

    def test_planner_requires_case_for_evidence(self):
        evidence = cf.store_evidence(b"data", "x.bin", self.case["id"])
        with self.assertRaises(ValueError):
            cf.ai_agent_plan({"objective": "triage file", "evidence_id": evidence["id"]})

    def test_agent_case_overview_cannot_escape_selected_case(self):
        other = cf.create_case({"title": "Private second case"})
        with self.assertRaises(PermissionError):
            cf._agent_clean_args("case_overview", {"case_id": other["id"]}, "read case", "", self.case["id"])
        with self.assertRaises(ValueError):
            cf._agent_clean_args("case_overview", {"case_id": other["id"]}, "read case", "", "")

    def test_connector_steps_require_explicit_objective_intent(self):
        cf.configure_connector({"kind": "misp", "base_url": "https://misp.example.org", "api_key": "key"})
        with self.assertRaises(PermissionError):
            cf._agent_clean_args("misp_search", {"value": "192.0.2.1"}, "analyze incident", "", self.case["id"])

    def test_cloud_planner_is_allowlisted_and_receives_selected_evidence_id(self):
        evidence = cf.store_evidence(b"data", "x.bin", self.case["id"])
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG["api_key"] = "test-key"
        planned = {"goal": "triage", "steps": [{"tool": "evidence_triage", "args": {"evidence_id": evidence["id"]}, "why": "inspect evidence"}]}
        with mock.patch.object(cf, "_ai_request", return_value={"content": json.dumps(planned)}) as call:
            out = cf.ai_agent_plan({"objective": "triage malware", "case_id": self.case["id"], "evidence_id": evidence["id"]})
        self.assertEqual(out["planning_mode"], "cloud-ai-planner")
        self.assertEqual(out["steps"][0]["tool"], "evidence_triage")
        self.assertIn(evidence["id"], call.call_args.args[0][1]["content"])

    def test_offline_router_includes_configured_misp_and_cape_as_read_only_steps(self):
        cf.configure_connector({"kind": "misp", "base_url": "https://misp.example.org", "api_key": "misp-secret"})
        cf.configure_connector({"kind": "cape", "base_url": "https://cape.example.org", "token": "cape-secret"})
        plan = cf.ai_agent_plan({"objective": "Investigate incident, check MISP and CAPE status", "context": "Failed auth from 192.0.2.55"})
        tools = [x["tool"] for x in plan["steps"]]
        self.assertIn("misp_search", tools)
        self.assertIn("cape_status", tools)
        misp = next(x for x in plan["steps"] if x["tool"] == "misp_search")
        self.assertEqual(misp["args"]["value"], "192.0.2.55")
        self.assertEqual(misp["permission"], "configured-network-read-only")
        self.assertEqual(next(x for x in plan["steps"] if x["tool"] == "cape_status")["permission"], "configured-network-read-only")

    def test_offline_router_uses_volatility_only_for_selected_memory_evidence(self):
        evidence = cf.store_evidence(b"memory capture fixture", "memory.raw", self.case["id"])
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/vol"):
            plan = cf.ai_agent_plan({"objective": "Analyze memory dump process list", "case_id": self.case["id"], "evidence_id": evidence["id"]})
        self.assertEqual(plan["steps"][0]["tool"], "volatility_analysis")
        self.assertEqual(plan["steps"][0]["args"]["plugin"], "windows.pslist")
        self.assertEqual(plan["steps"][0]["permission"], "local-evidence-analysis")

    def test_cloud_planner_rejects_arbitrary_shell_tool(self):
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG["api_key"] = "test-key"
        planned = {"goal": "bad", "steps": [{"tool": "shell", "args": {"command": "whoami"}}]}
        with mock.patch.object(cf, "_ai_request", return_value={"content": json.dumps(planned)}):
            with self.assertRaises(ValueError):
                cf.ai_agent_plan({"objective": "do something"})

    def test_diff_review_exports_only_accepted_hunks_without_overwrite(self):
        source = "value = 1\nprint(value)\n"
        suggested = "value = 2\nprint(value)\n"
        fake = {"content": json.dumps({"summary": "Fix value", "suggested_source": suggested, "risk_notes": ["Review semantics"], "tests": ["run unit tests"]})}
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG["api_key"] = "test-key"
        with mock.patch.object(cf, "_ai_request", return_value=fake):
            patch = cf.ai_patch_create({"source": source, "request": "Change value to 2", "language": "python"})
        self.assertEqual(len(patch["hunks"]), 1)
        cf.ai_patch_decide({"patch_id": patch["id"], "hunk_index": 0, "decision": "accept"})
        exported = cf.ai_patch_export({"patch_id": patch["id"]})
        self.assertEqual(exported["source"], suggested)
        self.assertEqual(exported["accepted_hunks"], 1)
        self.assertIn("did not overwrite", exported["notice"])
        self.assertEqual(source, "value = 1\nprint(value)\n")

    def test_patch_requires_at_least_one_accepted_hunk(self):
        source = "a = 1\n"
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG["api_key"] = "test-key"
        with mock.patch.object(cf, "_ai_request", return_value={"content": json.dumps({"summary": "edit", "suggested_source": "a = 2\n", "risk_notes": [], "tests": []})}):
            patch = cf.ai_patch_create({"source": source, "request": "change value", "language": "python"})
        with self.assertRaises(ValueError):
            cf.ai_patch_export({"patch_id": patch["id"]})

    def test_chat_can_attach_local_knowledge_with_citations(self):
        from tests.test_v100_ai import FakeResponse
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG["api_key"] = "test-key"
        fake = FakeResponse({"choices": [{"message": {"content": "Use parameterized SQL."}}], "usage": {"total_tokens": 5}})
        with mock.patch.object(cf, "_ai_open_request", return_value=fake) as call:
            out = cf.ai_chat({"message": "unsafe deserialization secure code review", "use_knowledge": True})
        self.assertTrue(out["knowledge_sources"])
        body = json.loads(call.call_args.args[0].data.decode())
        user_text = "\n".join(m["content"] for m in body["messages"] if m["role"] == "user")
        self.assertIn("LOCAL KNOWLEDGE RETRIEVAL", user_text)
        self.assertIn("UNTRUSTED REFERENCE MATERIAL", user_text)

    def test_plugin_access_is_deny_by_default_and_capability_limited(self):
        item = next(x for x in cf.list_plugin_access() if x["id"] == "example.indicator-enricher")
        self.assertFalse(item["enabled"])
        self.assertEqual(item["granted_permissions"], [])
        with self.assertRaises(ValueError):
            cf.update_plugin_access({"plugin_id": item["id"], "permissions": ["shell.execute"], "enabled": True})
        updated = cf.update_plugin_access({"plugin_id": item["id"], "permissions": ["knowledge.read"], "enabled": True})
        self.assertTrue(updated["enabled"])
        self.assertEqual(updated["granted_permissions"], ["knowledge.read"])

    def test_connector_base_requires_https_except_loopback(self):
        self.assertEqual(cf._validate_connector_base("https://misp.example.org/"), "https://misp.example.org")
        self.assertEqual(cf._validate_connector_base("http://127.0.0.1:8080/"), "http://127.0.0.1:8080")
        with self.assertRaises(ValueError):
            cf._validate_connector_base("http://misp.example.org")
        with self.assertRaises(ValueError):
            cf._validate_connector_base("https://user:pass@misp.example.org")

    def test_misp_adapter_is_read_only_post_and_never_returns_api_key(self):
        cf.configure_connector({"kind": "misp", "base_url": "https://misp.example.org", "api_key": "misp-secret"})
        seen = {}
        def fake(url, method="GET", headers=None, body=None, **kwargs):
            seen.update({"url": url, "method": method, "headers": headers, "body": json.loads(body.decode())})
            return {"response": [{"value": "192.0.2.1"}]}
        with mock.patch.object(cf, "_connector_request", side_effect=fake):
            result = cf.query_misp_attribute("192.0.2.1")
        self.assertTrue(seen["url"].endswith("/attributes/restSearch"))
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["headers"]["Authorization"], "misp-secret")
        self.assertNotIn("misp-secret", json.dumps(cf.connector_status()))
        self.assertEqual(result["count"], 1)
        self.assertIn("No event or attribute was created", result["notice"])

    def test_cape_adapter_only_reads_known_status_paths(self):
        cf.configure_connector({"kind": "cape", "base_url": "https://cape.example.org", "token": "cape-secret"})
        calls = []
        with mock.patch.object(cf, "_connector_request", side_effect=lambda url, **kw: calls.append((url, kw)) or {"ok": True}):
            result = cf.cape_readonly_status()
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(x[1].get("method", "GET") == "GET" for x in calls))
        self.assertTrue(all("/apiv2/" in x[0] for x in calls))
        self.assertEqual(result["mode"], "read-only")

    def test_cape_lite_report_rejects_invalid_task_ids_and_only_gets_existing_task(self):
        cf.configure_connector({"kind": "cape", "base_url": "https://cape.example.org", "token": "cape-secret"})
        with self.assertRaises(ValueError):
            cf.cape_task_report("../../submit")
        seen = {}
        with mock.patch.object(cf, "_connector_request", side_effect=lambda url, **kw: seen.update({"url": url, "kw": kw}) or {"report": "existing"}):
            result = cf.cape_task_report(42)
        self.assertTrue(seen["url"].endswith("/apiv2/tasks/get/report/42/lite/"))
        self.assertEqual(seen["kw"].get("method", "GET"), "GET")
        self.assertEqual(result["task_id"], 42)

    def test_volatility_plugin_allowlist_and_fixed_argv(self):
        evidence = cf.store_evidence(b"memory image test", "memory.raw", self.case["id"])
        with mock.patch.object(cf.shutil, "which", return_value="/usr/bin/vol"):
            with self.assertRaises(ValueError):
                cf.run_volatility_evidence(evidence["id"], "--help;whoami")
            with mock.patch.object(cf.subprocess, "run", return_value=subprocess.CompletedProcess(["vol"], 0, "PID output", "")) as call:
                result = cf.run_volatility_evidence(evidence["id"], "windows.pslist")
        args = call.call_args.args[0]
        self.assertEqual(args[-1], "windows.pslist")
        self.assertFalse(call.call_args.kwargs.get("shell", False))
        self.assertEqual(result["exit_code"], 0)

    def test_http_ai_navigator_status_rag_and_planner_routes(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(base + "/api/ai/navigator/status", timeout=5) as response:
                status = json.loads(response.read())
            self.assertIn("evidence_triage", status["tools"])
            self.assertGreaterEqual(len(status["knowledge"]), 3)
            payload = json.dumps({"objective": "review this code", "context": "x = 1\n"}).encode()
            request = Request(base + "/api/ai/agent/plan", data=payload, headers={"Content-Type": "application/json", "Origin": base}, method="POST")
            with urlopen(request, timeout=5) as response:
                plan = json.loads(response.read())
            self.assertEqual(plan["planning_mode"], "offline-keyword-router")
        finally:
            server.shutdown(); thread.join(timeout=3); server.server_close()


if __name__ == "__main__":
    unittest.main()
