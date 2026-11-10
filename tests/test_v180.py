import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V180EditionAndIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf180-")
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, dict(cf.AI_RUNTIME_CONFIG))
        base = Path(self.tmp.name) / "data"
        cf.DATA_DIR = base
        cf.DB_PATH = base / "cyberforge.db"
        cf.EVIDENCE_DIR = base / "evidence"
        cf.init_database()
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG.clear()
            cf.AI_RUNTIME_CONFIG.update({"provider":"qwencloud", "model":"qwen3.8-max", "api_key":"test-key", "region":"ap-southeast-1", "disable_env":True})
        self.project = cf.create_dev_project({"name":"v1.8 integration fixture", "template":"python"})

    def tearDown(self):
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old[:3]
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG.clear()
            cf.AI_RUNTIME_CONFIG.update(self.old[3])
        self.tmp.cleanup()

    def test_01_version_and_edition_manifest(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        manifest = json.loads((ROOT / "edition.json").read_text())
        self.assertIn(manifest["edition"], {"aio", "dev", "security"})
        self.assertEqual(cf.EDITION_PROFILE["id"], "aio")

    def test_02_language_inventory_has_broad_language_coverage(self):
        inv = cf.dev_language_inventory()
        ids = {x["id"] for x in inv["languages"]}
        self.assertGreaterEqual(len(ids), 25)
        for name in ("python", "typescript", "rust", "go", "java", "cpp", "csharp", "php", "ruby", "kotlin", "swift", "dart", "powershell", "terraform"):
            self.assertIn(name, ids)
        self.assertIn("notice", inv)

    def test_03_ide_integration_detects_known_editor_families(self):
        result = cf.dev_ide_integrations()
        names = {x["name"] for x in result["ides"]}
        self.assertTrue({"Visual Studio Code", "VSCodium", "Cursor", "Zed"}.issubset(names))
        self.assertIn("extensions", result)

    def test_04_workspace_export_creates_interop_files(self):
        result = cf.export_project_ide_config({"project_id":self.project["id"], "acknowledged":True})
        paths = {x["path"] for x in result["written"]}
        self.assertIn(".editorconfig", paths)
        self.assertIn(".vscode/settings.json", paths)
        self.assertIn(".vscode/extensions.json", paths)
        self.assertTrue(any(x.endswith(".code-workspace") for x in paths))
        config = cf.read_dev_project_file(self.project["id"], ".vscode/settings.json")
        self.assertTrue(json.loads(config["content"]))

    def test_05_workspace_export_preserves_existing_without_overwrite(self):
        cf.export_project_ide_config({"project_id":self.project["id"], "acknowledged":True})
        second = cf.export_project_ide_config({"project_id":self.project["id"], "acknowledged":True})
        self.assertGreaterEqual(len(second["skipped_existing"]), 4)

    def test_06_scanner_inventory_lists_fixed_allowlist(self):
        inv = cf.security_scanner_inventory()
        ids = {x["id"] for x in inv["scanners"]}
        self.assertEqual(ids, set(cf.SECURITY_SCANNERS))
        self.assertIn("bandit", ids)
        self.assertIn("gitleaks", ids)
        self.assertIn("trivy", ids)
        self.assertIn("syft", ids)

    def test_07_unknown_scanner_is_rejected(self):
        with self.assertRaises(ValueError):
            cf.run_project_security_assessment({"project_id":self.project["id"], "scanners":["arbitrary-shell"]})

    def test_08_missing_scanner_is_reported_not_fabricated(self):
        with mock.patch.object(cf.shutil, "which", return_value=None):
            result = cf.run_project_security_assessment({"project_id":self.project["id"], "scanners":["bandit"], "save_report":False})
        self.assertEqual(result["results"][0]["status"], "not_installed")
        self.assertEqual(result["completed"], 0)
        self.assertFalse(result["report_persisted"])

    def test_09_scanner_uses_fixed_argv_no_shell(self):
        output = json.dumps({"results":[{"issue_severity":"HIGH"}]}).encode()
        completed = subprocess.CompletedProcess(args=[], returncode=1, stdout=output, stderr=b"")
        def fake_which(name):
            return "/usr/bin/bandit" if name == "bandit" else None
        with mock.patch.object(cf.shutil, "which", side_effect=fake_which), mock.patch.object(cf.subprocess, "run", return_value=completed) as run:
            result = cf.run_project_security_assessment({"project_id":self.project["id"], "scanners":["bandit"], "save_report":False})
        self.assertEqual(result["results"][0]["finding_count"], 1)
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        self.assertEqual(result["results"][0]["status"], "completed")

    def test_10_security_assessment_refuses_large_scanner_selection(self):
        with self.assertRaises(ValueError):
            cf.run_project_security_assessment({"project_id":self.project["id"], "scanners":list(cf.SECURITY_SCANNERS)+["bandit"]})

    def test_11_security_summary_failure_does_not_discard_scanner_report(self):
        with mock.patch.object(cf.shutil, "which", return_value=None), mock.patch.object(cf, "_ai_active_key", side_effect=RuntimeError("no provider")):
            result = cf.run_project_security_assessment({"project_id":self.project["id"], "scanners":["bandit"], "summarize_with_ai":True, "save_report":False})
        self.assertIn("ai_error", result)
        self.assertEqual(result["results"][0]["status"], "not_installed")

    def test_12_api_permission_matrix_covers_new_endpoints(self):
        get_caps = cf._api_capabilities("GET", "/api/dev/toolchains", {})
        sec_caps = cf._api_capabilities("POST", "/api/security/assessment", {"project_id":self.project["id"], "scanners":["bandit"]})
        self.assertIn("local_lint", get_caps)
        self.assertIn("static_analysis", sec_caps)
        self.assertIn("project_read", sec_caps)

    def test_13_cloud_security_summary_requires_cloud_permission(self):
        caps = cf._api_capabilities("POST", "/api/security/assessment", {"project_id":self.project["id"], "scanners":["bandit"], "summarize_with_ai":True})
        self.assertIn("ai_provider_access", caps)
        self.assertIn("_cloud_context_ack", caps)

    def test_14_language_templates_create_valid_project_trees(self):
        expected = {"python", "web", "node", "typescript", "c", "cpp", "go", "rust", "java", "csharp", "php", "ruby", "kotlin", "swift", "bash", "powershell", "dart", "lua", "terraform", "security-tool", "empty"}
        self.assertTrue(expected.issubset(set(cf.DEV_PROJECT_TEMPLATES)))
        for template in sorted(expected):
            project = cf.create_dev_project({"name":"template-"+template, "template":template})
            paths = {entry["path"] for entry in project["tree"] if entry["type"] == "file"}
            self.assertIn("README.md", paths, template)
            self.assertIn(".gitignore", paths, template)

    def test_15_syntax_support_is_explicit_for_extended_languages(self):
        self.assertTrue(cf.code_syntax("print('ok')", "python")["valid_syntax"])
        self.assertTrue(cf.code_syntax("name = 'ok'", "toml")["valid_syntax"])
        self.assertTrue(cf.code_syntax("<root/>", "xml")["valid_syntax"])
        for language in ("c", "cpp", "rust", "swift", "powershell", "dart", "csharp", "kotlin", "terraform", "html", "css"):
            result = cf.code_syntax("// syntax fixture\n", language)
            self.assertIn(result.get("valid_syntax"), (True, False, None), language)
        with self.assertRaises(ValueError):
            cf.code_syntax("x", "not-a-language")

    def test_16_ai_patch_accepts_extended_language_ids_and_validates_when_parser_exists(self):
        source = "export const value: number = 1;\n"
        suggested = "export const value: number = 2;\n"
        fake = {"content":json.dumps({"summary":"Update value", "suggested_source":suggested, "risk_notes":[], "tests":["typecheck"]})}
        with mock.patch.object(cf, "_ai_request", return_value=fake):
            patch = cf.ai_patch_create({"source":source, "request":"Change value to 2", "language":"typescript"})
        self.assertEqual(patch["language"], "typescript")
        self.assertGreater(len(patch["hunks"]), 0)

    def test_17_edition_profiles_support_separate_dev_and_security_builds(self):
        with mock.patch.dict(cf.os.environ, {"CYBERFORGE_EDITION":"dev"}):
            dev = cf._load_edition_profile()
        with mock.patch.dict(cf.os.environ, {"CYBERFORGE_EDITION":"security"}):
            security = cf._load_edition_profile()
        self.assertEqual(dev["id"], "dev")
        self.assertTrue(dev["features"]["dev"])
        self.assertFalse(dev["features"]["security"])
        self.assertEqual(security["id"], "security")
        self.assertTrue(security["features"]["security"])
        self.assertFalse(security["features"]["dev"])

    def test_18_all_project_templates_are_exposed_in_dev_studio(self):
        ui = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        template_select = ui.split('id="devNewTemplate"', 1)[1].split("</select>", 1)[0]
        values = set(__import__("re").findall(r'<option value="([^"]+)"', template_select))
        self.assertEqual(values, set(cf.DEV_PROJECT_TEMPLATES))
        self.assertIn("devstudio", ui.split("security:new Set([", 1)[1].split("]),aio:null", 1)[0])

    def test_19_invalid_ai_python_patch_is_rejected_before_review(self):
        source = "value = 1\n"
        fake = {"content":json.dumps({"summary":"Broken syntax", "suggested_source":"def (:\n", "risk_notes":[], "tests":[]})}
        with mock.patch.object(cf, "_ai_request", return_value=fake):
            with self.assertRaisesRegex(ValueError, "kiểm tra cú pháp"):
                cf.ai_patch_create({"source":source, "request":"Change value", "language":"python"})

    def test_20_agent_security_assessment_requires_opt_in_and_selected_project(self):
        with self.assertRaises(PermissionError):
            cf._agent_clean_args("security_assessment", {"project_id":self.project["id"], "scanners":["bandit"], "allow_scan":True},
                                  "security assessment scan project", "", "", default_project=self.project["id"],
                                  allow_security_assessment=False, selected_security_scanners=["bandit"])
        with mock.patch.object(cf, "security_scanner_inventory", return_value={"scanners":[{"id":"bandit", "available":True}]}):
            clean = cf._agent_clean_args("security_assessment", {"project_id":self.project["id"], "scanners":["bandit"], "allow_scan":True},
                                         "security assessment scan project", "", "", default_project=self.project["id"],
                                         allow_security_assessment=True, selected_security_scanners=["bandit"])
        self.assertEqual(clean["project_id"], self.project["id"])
        with self.assertRaises(PermissionError):
            cf._agent_clean_args("security_assessment", {"project_id":"OTHER", "scanners":["bandit"], "allow_scan":True},
                                 "security assessment scan project", "", "", default_project=self.project["id"],
                                 allow_security_assessment=True, selected_security_scanners=["bandit"])

    def test_21_agent_security_assessment_cannot_expand_selected_scanners(self):
        with self.assertRaises(PermissionError):
            cf._agent_clean_args("security_assessment", {"project_id":self.project["id"], "scanners":["bandit", "trivy"], "allow_scan":True},
                                 "security assessment scan project", "", "", default_project=self.project["id"],
                                 allow_security_assessment=True, selected_security_scanners=["bandit"])

    def test_22_offline_agent_planner_adds_local_project_scan_only_after_opt_in(self):
        plan = cf._agent_offline_plan("Please run a security assessment scan project", "", "", "",
                                      self.project["id"], True, ["bandit"])
        self.assertTrue(any(x["tool"] == "security_assessment" for x in plan["steps"]))
        denied = cf._agent_offline_plan("Please run a security assessment scan project", "", "", "",
                                        self.project["id"], False, ["bandit"])
        self.assertFalse(any(x["tool"] == "security_assessment" for x in denied["steps"]))

    def test_23_security_assessment_adapter_never_persists_or_calls_ai(self):
        fake = {"run_id":"SEC-test", "project_id":self.project["id"], "project_name":"test", "files_considered":1,
                "bytes_considered":10, "scanners_requested":["bandit"], "results":[{"scanner":"bandit", "status":"completed",
                "finding_count":2, "output_excerpt":"SECRET_RAW_SOURCE_OUTPUT"}], "total_findings":2,
                "report_persisted":False, "scope":"local project"}
        with mock.patch.object(cf, "run_project_security_assessment", return_value=fake) as scan:
            result = cf._run_agent_tool("security_assessment", {"project_id":self.project["id"], "scanners":["bandit"], "allow_scan":True})
        scan.assert_called_once_with({"project_id":self.project["id"], "scanners":["bandit"], "summarize_with_ai":False, "save_report":False})
        self.assertFalse(result["report_persisted"])

    def test_24_agent_security_summary_sanitizes_scanner_output(self):
        raw = {"project_id":self.project["id"], "project_name":"fixture", "files_considered":4, "bytes_considered":99,
               "results":[{"scanner":"bandit", "status":"completed", "finding_count":1,
                           "output_excerpt":"SECRET_RAW_SOURCE_OUTPUT", "stderr_excerpt":"PRIVATE_TOKEN"}],
               "total_findings":1, "scope":"local project", "report_persisted":False}
        clean = cf._agent_sanitize_result("security_assessment", raw)
        serialized = json.dumps(clean)
        self.assertIn("finding_count", serialized)
        self.assertNotIn("SECRET_RAW_SOURCE_OUTPUT", serialized)
        self.assertNotIn("PRIVATE_TOKEN", serialized)
        self.assertFalse(clean["report_persisted"])

    def test_25_agent_plan_security_capabilities_are_dynamic(self):
        plan_id = "AG-test-security"
        try:
            with cf.AI_AGENT_LOCK:
                cf.AI_AGENT_PLANS[plan_id] = {"status":"ready", "case_id":"", "steps":[{"tool":"security_assessment", "args":{}}]}
            caps = cf._agent_plan_capabilities(plan_id)
            self.assertIn("static_analysis", caps)
            self.assertIn("project_read", caps)
            self.assertNotIn("code_execution", caps)
        finally:
            with cf.AI_AGENT_LOCK:
                cf.AI_AGENT_PLANS.pop(plan_id, None)

    def test_26_navigator_ui_exposes_explicit_project_scan_consent(self):
        ui = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        for marker in ('id="agentProject"', 'id="agentAllowSecurityAssessment"', 'id="agentSecurityScanners"', "security_assessment"):
            self.assertIn(marker, ui)
        self.assertIn("selectedScanners", ui)
        self.assertIn("Local project security assessment", ui)

    def test_27_agent_plan_execute_security_assessment_end_to_end(self):
        planned = {"goal":"Review selected local project security", "steps":[
            {"tool":"security_assessment", "args":{"project_id":self.project["id"], "scanners":["bandit"], "allow_scan":True},
             "why":"Run the one selected local scanner."}]}
        fake_result = {"run_id":"SEC-e2e", "project_id":self.project["id"], "project_name":"fixture", "files_considered":2,
                       "bytes_considered":120, "scanners_requested":["bandit"],
                       "results":[{"scanner":"bandit", "status":"completed", "finding_count":1,
                                   "output_excerpt":"PRIVATE_SOURCE_MUST_NOT_BE_CLOUDED"}],
                       "completed":1, "available":1, "total_findings":1, "scope":"Local project only.",
                       "report_persisted":False}
        with mock.patch.object(cf, "security_scanner_inventory", return_value={"scanners":[{"id":"bandit", "available":True}]}), \
             mock.patch.object(cf, "_ai_request", return_value={"content":json.dumps(planned)}), \
             mock.patch.object(cf, "run_project_security_assessment", return_value=fake_result) as scanner:
            plan_request = {"objective":"Please perform a security assessment scan project", "project_id":self.project["id"],
                            "allow_security_assessment":True, "security_scanners":["bandit"], "use_knowledge":False}
            plan_caps = cf._api_capabilities("POST", "/api/ai/agent/plan", plan_request)
            self.assertIn("project_read", plan_caps)
            self.assertIn("static_analysis", plan_caps)
            plan = cf.ai_agent_plan(plan_request)
            self.assertEqual(len(plan["steps"]), 1)
            self.assertEqual(plan["steps"][0]["tool"], "security_assessment")
            caps = cf._api_capabilities("POST", "/api/ai/agent/execute", {"plan_id":plan["plan_id"]})
            self.assertIn("static_analysis", caps)
            self.assertIn("project_read", caps)
            executed = cf.ai_agent_execute({"plan_id":plan["plan_id"], "share_sanitized_results_with_ai":False})
        scanner.assert_called_once_with({"project_id":self.project["id"], "scanners":["bandit"],
                                         "summarize_with_ai":False, "save_report":False})
        self.assertEqual(executed["results"][0]["status"], "completed")
        self.assertEqual(executed["report"]["tool_steps"][0]["total_findings"], 1)
        self.assertFalse(executed["cloud_synthesis"])


    def test_20_nested_folder_and_file_creation(self):
        pid = self.project["id"]
        created = cf.create_dev_project_folder({"project_id":pid, "path":"src/components/ui"})
        self.assertTrue(created["created"])
        saved = cf.write_dev_project_file({"project_id":pid, "path":"src/components/ui/Button.tsx", "content":"export const Button = () => null;", "expected_sha256":""})
        self.assertTrue(saved["saved"])
        opened = cf.read_dev_project_file(pid, "src/components/ui/Button.tsx")
        self.assertIn("Button", opened["content"])

    def test_21_ai_patch_export_supports_extended_extensions(self):
        patch_id = "PT-EXTENSION-TEST"
        with cf.AI_PATCH_LOCK:
            cf.AI_PATCHES[patch_id] = {"source":"const x = 1;\n", "language":"typescript", "hunks":[{"decision":"accept", "original_start":0, "original_end":1, "before":"const x = 1;\n", "after":"const x = 2;\n"}]}
        try:
            exported = cf.ai_patch_export({"patch_id":patch_id})
            self.assertEqual(exported["filename"], "cyberforge-reviewed-patch.ts")
            self.assertIn("const x = 2", exported["source"])
        finally:
            with cf.AI_PATCH_LOCK:
                cf.AI_PATCHES.pop(patch_id, None)



if __name__ == "__main__":
    unittest.main()
