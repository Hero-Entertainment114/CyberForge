import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V170UserControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf170-test-")
        self.old_paths = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        self.old_ai = dict(cf.AI_RUNTIME_CONFIG)
        self.old_conversations = dict(cf.AI_CONVERSATIONS)
        base = Path(self.tmp.name) / "data"
        cf.DATA_DIR = base
        cf.DB_PATH = base / "cyberforge.db"
        cf.EVIDENCE_DIR = base / "evidence"
        cf.init_database()
        with cf.AI_LOCK:
            cf.AI_CONVERSATIONS.clear()
            cf.AI_RUNTIME_CONFIG.clear()
            cf.AI_RUNTIME_CONFIG.update({
                "provider": "qwencloud", "model": "qwen3.8-max", "region": "ap-southeast-1",
                "reasoning_effort": "medium", "api_key": "test-provider-key", "disable_env": True,
            })

    def tearDown(self):
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG.clear()
            cf.AI_RUNTIME_CONFIG.update(self.old_ai)
            cf.AI_CONVERSATIONS.clear()
            cf.AI_CONVERSATIONS.update(self.old_conversations)
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old_paths
        self.tmp.cleanup()

    def _prefs(self):
        return cf.get_app_preferences()

    def _save_permissions(self, **values):
        prefs = self._prefs()
        prefs["permissions"].update(values)
        return cf.save_app_preferences({"profile": prefs})["profile"]

    def _project(self):
        return cf.create_dev_project({"name": "AI optimization fixture", "template": "python"})

    def _run_multi_agent(self, project, **prefs_override):
        prefs = self._prefs()
        prefs["ai"].update(prefs_override)
        cf.save_app_preferences({"profile": prefs})
        fake_reports = [{"content": "Architect report"}, {"content": "Reviewer report"}, {"content": "Lead report"}]
        with mock.patch.object(cf, "_ai_request", side_effect=fake_reports) as call:
            result = cf.multi_agent_run({
                "objective": "Review and improve this project", "mode": "development", "depth": "quick",
                "project_id": project["id"], "file_paths": ["main.py"],
            })
        return result, call

    def test_01_release_version_matches_current_source(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        self.assertEqual((ROOT / "VERSION.txt").read_text().strip(), cf.APP_VERSION)

    def test_02_profile_has_all_customization_groups_and_capabilities(self):
        profile = self._prefs()
        self.assertEqual(set(profile), {"schema_version", "localization", "appearance", "editor", "ai", "permissions"})
        self.assertEqual(profile["localization"], {"locale": "en"})
        self.assertGreaterEqual(len(profile["permissions"]), 19)
        self.assertEqual(set(profile["permissions"]), set(cf.PREFERENCE_CAPABILITIES))

    def test_03_permission_policies_are_explicit_allow_ask_deny_values(self):
        self.assertEqual({"allow", "ask"}, {cf.PREFERENCE_DEFAULTS["permissions"][x] for x in cf.PREFERENCE_DEFAULTS["permissions"] if cf.PREFERENCE_DEFAULTS["permissions"][x] != "deny"})
        self.assertTrue(all(v in {"allow", "ask", "deny"} for v in self._prefs()["permissions"].values()))

    def test_04_partial_profile_update_preserves_untouched_preferences(self):
        before = self._prefs()
        out = cf.save_app_preferences({"profile": {"appearance": {"accent": "#123456"}}})["profile"]
        self.assertEqual(out["appearance"]["accent"], "#123456")
        self.assertEqual(out["editor"], before["editor"])
        self.assertEqual(out["ai"], before["ai"])
        self.assertEqual(out["permissions"], before["permissions"])

    def test_05_invalid_appearance_and_unknown_fields_are_rejected(self):
        with self.assertRaises(ValueError): cf.save_app_preferences({"profile": {"appearance": {"theme": "invisible"}}})
        with self.assertRaises(ValueError): cf.save_app_preferences({"profile": {"unknown_group": {}}})
        with self.assertRaises(ValueError): cf.save_app_preferences({"profile": {"appearance": {"accent": "red"}}})

    def test_06_invalid_permission_policy_is_rejected(self):
        with self.assertRaises(ValueError): cf.save_app_preferences({"profile": {"permissions": {"project_write": "unrestricted"}}})
        with self.assertRaises(ValueError): cf.save_app_preferences({"profile": {"permissions": {"not_a_capability": "allow"}}})

    def test_07_restore_defaults_restores_preferences(self):
        cf.save_app_preferences({"profile": {"appearance": {"theme": "light"}, "permissions": {"project_write": "deny"}}})
        reset = cf.reset_app_preferences()["profile"]
        self.assertEqual(reset, cf.PREFERENCE_DEFAULTS)

    def test_08_audit_records_policy_change_without_recording_custom_instruction_text(self):
        secret_text = "do-not-copy-this-private-instruction-6d4e"
        cf.save_app_preferences({"profile": {"ai": {"custom_instructions": secret_text}, "permissions": {"project_write": "deny"}}})
        con = cf._db_connect()
        try:
            details = [r[0] for r in con.execute("SELECT detail_json FROM activity WHERE action='preferences-updated'").fetchall()]
        finally:
            con.close()
        self.assertTrue(details)
        self.assertNotIn(secret_text, "".join(details))
        self.assertIn('"project_write": "deny"', "".join(details))

    def test_09_ai_prompt_applies_custom_style_and_optimization_goal(self):
        cf.save_app_preferences({"profile": {"ai": {
            "response_style": "technical", "optimization_goal": "security",
            "custom_instructions": "Prefer type hints and regression tests.",
        }}})
        prompt = cf._ai_profile_system_prompt("base system")
        self.assertIn("precise technical language", prompt)
        self.assertIn("security", prompt)
        self.assertIn("Prefer type hints and regression tests", prompt)

    def test_10_each_autonomy_mode_is_descriptive_and_non_escalating(self):
        expected = {"manual": "manual", "guided": "guided", "trusted": "trusted"}
        for mode, token in expected.items():
            with self.subTest(mode=mode):
                cf.save_app_preferences({"profile": {"ai": {"autonomy": mode}}})
                prompt = cf._ai_profile_system_prompt("base")
                self.assertIn("Autonomy mode: " + token, prompt)
                self.assertIn("Deny", prompt)

    def test_11_allow_policy_runs_without_one_time_acknowledgement(self):
        self._save_permissions(project_write="allow")
        self.assertEqual(cf.require_user_permission("project_write"), "allow")

    def test_12_ask_policy_requests_confirmation(self):
        self._save_permissions(project_write="ask")
        with self.assertRaisesRegex(PermissionError, r"CONFIRM_PERMISSION\|project_write"):
            cf.require_user_permission("project_write")

    def test_13_ask_policy_accepts_explicit_scoped_acknowledgement(self):
        self._save_permissions(project_write="ask")
        self.assertEqual(cf.require_user_permission("project_write", acknowledged=True), "ask")

    def test_14_deny_policy_cannot_be_overridden_by_acknowledgement(self):
        self._save_permissions(project_write="deny")
        with self.assertRaisesRegex(PermissionError, r"PERMISSION_DENIED\|project_write"):
            cf.require_user_permission("project_write", acknowledged=True)

    def test_15_unknown_capability_is_denied(self):
        with self.assertRaisesRegex(PermissionError, r"PERMISSION_DENIED\|unknown"):
            cf.require_user_permission("root_shell")

    def test_16_boolean_true_never_acknowledges_a_capability(self):
        self._save_permissions(project_write="ask")
        with self.assertRaisesRegex(PermissionError, r"CONFIRM_PERMISSION\|project_write"):
            cf.enforce_api_permissions("POST", "/api/dev/project/file/write", {}, acknowledged=True)

    def test_17_acknowledgement_is_scoped_to_the_named_capability(self):
        self._save_permissions(project_write="ask", evidence_write="ask")
        with self.assertRaisesRegex(PermissionError, r"CONFIRM_PERMISSION\|evidence_write"):
            cf.enforce_api_permissions("POST", "/api/evidence/delete", {"id": "x"}, acknowledged=["project_write"])

    def test_18_sensitive_endpoint_map_includes_linux_reverse_plugins_and_app_launch(self):
        checks = [
            ("GET", "/api/linux/blackarch", "static_analysis"),
            ("GET", "/api/linux/reverse/engines", "static_analysis"),
            ("GET", "/api/plugins", "plugin_admin"),
            ("GET", "/api/analysis/engines", "static_analysis"),
            ("POST", "/api/launch", "host_app_launch"),
            ("POST", "/api/clamav-eicar", "static_analysis"),
            ("POST", "/api/ioc-stix", "knowledge_access"),
            ("POST", "/api/connectors/cape/status", "network_connectors"),
        ]
        for method, path, capability in checks:
            with self.subTest(path=path):
                self.assertIn(capability, cf._api_capabilities(method, path, {}))
        self.assertEqual(cf._api_capabilities("POST", "/api/sbom/audit", {"filename": "requirements.txt"}), ["static_analysis"])
        self.assertEqual(set(cf._api_capabilities("POST", "/api/sbom/audit", {"filename": "requirements.txt", "case_id": "CASE-1"})), {"static_analysis", "case_write"})

    def test_19_git_init_and_read_actions_have_distinct_capabilities(self):
        self.assertIn("project_write", cf._api_capabilities("POST", "/api/dev/project/git", {"action": "init"}))
        self.assertIn("project_read", cf._api_capabilities("POST", "/api/dev/project/git", {"action": "status"}))
        self.assertNotIn("project_write", cf._api_capabilities("POST", "/api/dev/project/git", {"action": "status"}))

    def test_20_agent_plan_capabilities_derive_from_allowlisted_steps(self):
        plan_id = "AG-V170-CAPS"
        with cf.AI_AGENT_LOCK:
            previous = cf.AI_AGENT_PLANS.get(plan_id)
            cf.AI_AGENT_PLANS[plan_id] = {"id": plan_id, "status": "ready", "case_id": "CASE-X", "steps": [
                {"tool": "evidence_triage"}, {"tool": "misp_search"}, {"tool": "code_review"},
            ]}
        try:
            caps = cf._agent_plan_capabilities(plan_id)
            self.assertEqual(set(caps), {"case_read", "evidence_read", "static_analysis", "network_connectors"})
        finally:
            with cf.AI_AGENT_LOCK:
                if previous is None: cf.AI_AGENT_PLANS.pop(plan_id, None)
                else: cf.AI_AGENT_PLANS[plan_id] = previous

    def test_21_cloud_context_consent_is_separate_from_provider_permission(self):
        self._save_permissions(ai_provider_access="allow")
        prefs = self._prefs(); prefs["ai"]["acknowledge_cloud_context"] = True
        cf.save_app_preferences({"profile": prefs})
        with self.assertRaisesRegex(PermissionError, r"CONFIRM_PERMISSION\|cloud_context"):
            cf.enforce_api_permissions("POST", "/api/ai/chat", {"message": "hello"})
        cf.enforce_api_permissions("POST", "/api/ai/chat", {"message": "hello"}, acknowledged=["_cloud_context_ack"])

    def test_22_cloud_context_opt_out_removes_only_the_extra_consent_gate(self):
        self._save_permissions(ai_provider_access="allow")
        prefs = self._prefs(); prefs["ai"]["acknowledge_cloud_context"] = False
        cf.save_app_preferences({"profile": prefs})
        self.assertEqual(cf._api_capabilities("POST", "/api/ai/chat", {"message": "hello"}), ["ai_provider_access"])
        cf.enforce_api_permissions("POST", "/api/ai/chat", {"message": "hello"})

    def test_23_ui_exposes_profile_import_export_and_policy_matrix(self):
        ui = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        for token in ("prefPermissionsGrid", "prefAutonomy", "prefOptimization", "prefCustomAI", "importPreferencesFile", "exportPreferencesUI", "restore defaults", "Allow", "Ask", "Deny"):
            self.assertIn(token.lower(), ui.lower())
        self.assertIn("data-pref-cap", ui)

    def test_24_autosave_is_paused_for_ask_and_deny(self):
        ui = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        start = ui.index("function scheduleDevAutosave")
        end = ui.index("\n", start)
        js = ui[start:end]
        self.assertIn("policy!=='allow'", js)
        self.assertIn("Autosave paused", js)

    def test_25_preferences_http_profile_can_be_read_without_granting_other_capabilities(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with urlopen(base + "/api/preferences", timeout=3) as response:
                data = json.loads(response.read())
            self.assertIn("profile", data)
            self.assertIn("host_app_launch", data["capabilities"])
            self.assertEqual(data["profile"]["permissions"]["project_write"], "ask")
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_26_http_case_create_requires_ask_then_accepts_scoped_ack_and_respects_deny(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            def post(payload):
                req = Request(base + "/api/cases", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "Origin": base}, method="POST")
                try:
                    with urlopen(req, timeout=3) as resp: return resp.status, json.loads(resp.read())
                except HTTPError as exc: return exc.code, json.loads(exc.read())
            status, body = post({"title": "Ask case"})
            self.assertEqual(status, 403); self.assertIn("CONFIRM_PERMISSION|case_write", body["error"])
            status, body = post({"title": "Allowed once", "_permission_acknowledged": ["case_write"]})
            self.assertEqual(status, 200); self.assertIn("id", body)
            self._save_permissions(case_write="deny")
            status, body = post({"title": "Still denied", "_permission_acknowledged": ["case_write"]})
            self.assertEqual(status, 403); self.assertIn("PERMISSION_DENIED|case_write", body["error"])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_27_http_evidence_read_requires_scoped_ack(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with self.assertRaises(HTTPError) as err: urlopen(base + "/api/evidence", timeout=3)
            self.assertEqual(err.exception.code, 403)
            with urlopen(base + "/api/evidence?permission_ack=evidence_read", timeout=3) as response:
                self.assertEqual(json.loads(response.read()), [])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_28_http_plugin_listing_requires_plugin_admin_policy(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with self.assertRaises(HTTPError) as err: urlopen(base + "/api/plugins", timeout=3)
            self.assertEqual(err.exception.code, 403)
            with urlopen(base + "/api/plugins?permission_ack=plugin_admin", timeout=3) as response:
                self.assertIsInstance(json.loads(response.read()), list)
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_29_host_application_launch_requires_separate_permission(self):
        with self.assertRaisesRegex(PermissionError, r"CONFIRM_PERMISSION\|host_app_launch"):
            cf.enforce_api_permissions("POST", "/api/launch", {"id": "not-installed"})
        self._save_permissions(host_app_launch="deny")
        with self.assertRaisesRegex(PermissionError, r"PERMISSION_DENIED\|host_app_launch"):
            cf.enforce_api_permissions("POST", "/api/launch", {"id": "not-installed"}, acknowledged=["host_app_launch"])

    def test_30_multi_agent_attaches_local_diagnostics_when_enabled(self):
        project = self._project()
        result, call = self._run_multi_agent(project, auto_static_analysis=True)
        self.assertEqual(result["completed_agents"], 3)
        user_payload = json.loads(call.call_args_list[0].args[0][-1]["content"])
        self.assertIn("LOCAL STATIC DIAGNOSTICS", user_payload["untrusted_context"])

    def test_31_multi_agent_skips_local_diagnostics_when_static_analysis_denied(self):
        project = self._project()
        self._save_permissions(static_analysis="deny")
        result, call = self._run_multi_agent(project, auto_static_analysis=True)
        self.assertEqual(result["status"], "completed")
        user_payload = json.loads(call.call_args_list[0].args[0][-1]["content"])
        self.assertNotIn("LOCAL STATIC DIAGNOSTICS", user_payload["untrusted_context"])

    def test_32_multi_agent_report_persistence_obeys_user_preference(self):
        project = self._project()
        result, _ = self._run_multi_agent(project, auto_save_reports=False)
        con = cf._db_connect()
        try:
            row = con.execute("SELECT result_json FROM dev_project_runs WHERE project_id=? ORDER BY created_at DESC LIMIT 1", (project["id"],)).fetchone()
        finally:
            con.close()
        stored = json.loads(row["result_json"])
        self.assertIn("report_excerpt", stored["stages"][0])
        self.assertNotIn("report", stored["stages"][0])

        project_full = self._project()
        result_full, _ = self._run_multi_agent(project_full, auto_save_reports=True)
        con = cf._db_connect()
        try:
            row_full = con.execute("SELECT result_json FROM dev_project_runs WHERE project_id=? ORDER BY created_at DESC LIMIT 1", (project_full["id"],)).fetchone()
        finally:
            con.close()
        stored_full = json.loads(row_full["result_json"])
        self.assertTrue(result_full["stages"][0].get("report"))
        self.assertIn("report", stored_full["stages"][0])
        self.assertNotIn("report_excerpt", stored_full["stages"][0])

    def test_33_legacy_profile_migration_adds_new_capabilities_with_safe_defaults(self):
        legacy = cf._copy_preferences()
        legacy["permissions"].pop("host_app_launch", None)
        migrated = cf.save_app_preferences({"profile": legacy})["profile"]
        self.assertEqual(migrated["permissions"]["host_app_launch"], "ask")
        self.assertEqual(set(migrated["permissions"]), set(cf.PREFERENCE_CAPABILITIES))


if __name__ == "__main__":
    unittest.main()
