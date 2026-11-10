import base64
import json
import os
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock
from http.server import ThreadingHTTPServer
import threading
from urllib.request import urlopen
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V140SecurityIntegrationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf140-test-")
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.ROOT, cf.VAULT_KEY)
        base = Path(self.tmp.name)
        cf.DATA_DIR = base / "data"
        cf.DB_PATH = cf.DATA_DIR / "cyberforge.db"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.ROOT = ROOT
        cf.VAULT_KEY = None
        cf.init_database()
        self.case = cf.create_case({"title": "v1.4.0 integration case", "scope": "local test fixtures only"})
        cf.vault_create("unit-test-passphrase-123", "unit-test-passphrase-123")

    def tearDown(self):
        cf.VAULT_KEY = self.old[4]
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.ROOT = self.old[:4]
        self.tmp.cleanup()

    def _store(self, name="sample.exe", data=b"MZ\x90\x00unit-test-sample"):
        return cf.store_evidence(data, name, self.case["id"], "unit fixture")

    def test_version_and_vault_encryption_metadata(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        status = cf.vault_status()
        self.assertTrue(status["configured"])
        self.assertTrue(status["unlocked"])
        self.assertEqual(status["algorithm"], "AES-256-GCM")

    def test_evidence_ciphertext_is_not_plaintext_at_rest(self):
        row = self._store(data=b"PRIVATE EVIDENCE CONTENT")
        con = cf._db_connect()
        try:
            item = con.execute("SELECT * FROM evidence WHERE id=?", (row["id"],)).fetchone()
        finally:
            con.close()
        blob = (cf.EVIDENCE_DIR / item["stored_name"]).read_bytes()
        self.assertTrue(blob.startswith(cf.VAULT_MAGIC))
        self.assertNotIn(b"PRIVATE EVIDENCE CONTENT", blob)
        self.assertEqual(item["encrypted"], 1)

    def test_vault_lock_prevents_read_and_unlock_restores_read(self):
        row = self._store(data=b"locked-test")
        cf.vault_lock_now()
        with self.assertRaises(PermissionError):
            cf.get_evidence_bytes(row["id"])
        cf.vault_unlock("unit-test-passphrase-123")
        _, data = cf.get_evidence_bytes(row["id"])
        self.assertEqual(data, b"locked-test")

    def test_wrong_passphrase_is_rejected(self):
        cf.vault_lock_now()
        with self.assertRaises((ValueError, RuntimeError, PermissionError)):
            cf.vault_unlock("wrong-passphrase-123")
        self.assertFalse(cf.vault_status()["unlocked"])

    def test_rekey_updates_all_file_names_and_old_key_fails(self):
        one = self._store(data=b"rekey-one")
        two = self._store("second.bin", b"rekey-two")
        result = cf.vault_change_passphrase("unit-test-passphrase-123", "new-unit-passphrase-456", "new-unit-passphrase-456")
        self.assertTrue(result["changed"])
        self.assertEqual(result["re_encrypted"], 2)
        for item, expected in ((one, b"rekey-one"), (two, b"rekey-two")):
            _, data = cf.get_evidence_bytes(item["id"])
            self.assertEqual(data, expected)
        cf.vault_lock_now()
        with self.assertRaises((ValueError, RuntimeError, PermissionError)):
            cf.vault_unlock("unit-test-passphrase-123")
        cf.vault_unlock("new-unit-passphrase-456")
        self.assertEqual(cf.get_evidence_bytes(one["id"])[1], b"rekey-one")

    def test_encrypted_case_backup_does_not_export_plaintext(self):
        self._store(data=b"SECRET-BINARY-FIXTURE-2026")
        blob = cf.export_case_backup(self.case["id"])
        with zipfile.ZipFile(BytesIO(blob)) as archive:
            names = archive.namelist()
            self.assertIn("evidence_vault.json", names)
            encrypted = [x for x in names if x.startswith("evidence-encrypted/")]
            self.assertEqual(len(encrypted), 1)
            self.assertTrue(archive.read(encrypted[0]).startswith(cf.VAULT_MAGIC))
            self.assertNotIn(b"SECRET-BINARY-FIXTURE-2026", blob)
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["encrypted_evidence_count"], 1)

    def test_legacy_evidence_migrates_on_vault_unlock(self):
        # Simulate a v1.3.0 unencrypted row in the already-created DB.
        eid = "legacy-evidence-01"
        payload = b"legacy-plaintext"
        path = cf.EVIDENCE_DIR / (eid + ".bin")
        path.write_bytes(payload)
        con = cf._db_connect()
        try:
            con.execute("INSERT INTO evidence(id,case_id,finding_id,original_name,stored_name,sha256,size,note,encrypted,key_version,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (eid, self.case["id"], None, "legacy.bin", path.name, cf.hashlib.sha256(payload).hexdigest(), len(payload), "legacy", 0, 0, cf._now()))
            con.commit()
        finally:
            con.close()
        cf.vault_lock_now()
        result = cf.vault_unlock("unit-test-passphrase-123")
        self.assertEqual(result["migration"]["migrated"], 1)
        self.assertFalse(path.exists())
        row, recovered = cf.get_evidence_bytes(eid)
        self.assertEqual(recovered, payload)
        self.assertEqual(row["encrypted"], 1)

    def test_misp_bulk_query_is_bounded_and_partial_failures_visible(self):
        with mock.patch.object(cf, "query_misp_attribute", side_effect=[{"count": 1}, RuntimeError("offline")]):
            result = cf.query_misp_attributes(["a.example", "b.example"])
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["failed"], 1)
        with self.assertRaises(ValueError):
            cf.query_misp_attributes(["x"] * 31)

    def test_mobsf_connector_never_returns_api_key(self):
        status = cf.configure_connector({"kind": "mobsf", "base_url": "https://mobsf.example", "api_key": "secret-mobsf-key"})
        self.assertTrue(status["configured"])
        self.assertNotIn("secret-mobsf-key", json.dumps(status))

    def test_mobsf_upload_requires_acknowledgement(self):
        item = self._store("app.apk", b"PK\x03\x04APKfixture")
        cf.configure_connector({"kind": "mobsf", "base_url": "https://mobsf.example", "api_key": "api-key"})
        with self.assertRaises(PermissionError):
            cf.mobsf_scan_evidence(item["id"], False)

    def test_mobsf_upload_scan_report_integration(self):
        item = self._store("app.apk", b"PK\x03\x04APKfixture")
        cf.configure_connector({"kind": "mobsf", "base_url": "https://mobsf.example", "api_key": "api-key"})
        with mock.patch.object(cf, "_connector_multipart", return_value={"hash": "a" * 64}) as upload, \
             mock.patch.object(cf, "_connector_request", side_effect=[{"status": "scan started"}, {"security_score": 85}]) as request:
            result = cf.mobsf_scan_evidence(item["id"], True)
        self.assertEqual(result["provider"], "MobSF")
        self.assertEqual(result["report"]["security_score"], 85)
        self.assertEqual(upload.call_args.args[0], "https://mobsf.example/api/v1/upload")
        self.assertEqual(request.call_count, 2)

    def test_cape_submit_requires_explicit_acknowledgement(self):
        item = self._store()
        cf.configure_connector({"kind": "cape", "base_url": "https://cape.example", "token": "cape-token"})
        with mock.patch.object(cf, "_connector_multipart") as submit:
            with self.assertRaises(PermissionError):
                cf.cape_submit_evidence(item["id"], False)
            submit.assert_not_called()

    def test_cape_submit_sends_only_selected_evidence_after_ack(self):
        item = self._store(data=b"MZ\x90sample")
        cf.configure_connector({"kind": "cape", "base_url": "https://cape.example", "token": "cape-token"})
        with mock.patch.object(cf, "_connector_multipart", return_value={"data": {"task_ids": [123, 124]}}) as submit:
            result = cf.cape_submit_evidence(item["id"], True, 90)
        self.assertEqual(result["task_ids"], [123, 124])
        self.assertEqual(submit.call_args.args[0], "https://cape.example/apiv2/tasks/create/file/")
        self.assertIn("may be executed", result["critical_notice"])

    def test_cape_task_view_validates_id_and_uses_get(self):
        cf.configure_connector({"kind": "cape", "base_url": "https://cape.example", "token": "cape-token"})
        with mock.patch.object(cf, "_connector_request", return_value={"status": "reported"}) as request:
            result = cf.cape_task_view(321)
        self.assertEqual(result["task_id"], 321)
        self.assertEqual(request.call_args.args[0], "https://cape.example/apiv2/tasks/view/321/")
        with self.assertRaises(ValueError):
            cf.cape_task_view("../../etc/passwd")

    def test_analysis_inventory_reports_local_engine_availability(self):
        with mock.patch.object(cf, "_analysis_tool_paths", return_value={"ghidra": "/opt/ghidra/analyzeHeadless", "jadx": None}):
            inv = cf.analysis_engine_inventory()
        self.assertTrue(inv["ghidra"]["available"])
        self.assertFalse(inv["jadx"]["available"])

    def test_jadx_runs_fixed_headless_argv_and_returns_summary(self):
        item = self._store("app.apk", b"PK\x03\x04apkdata")
        def fake_run(cmd, **kwargs):
            out = Path(cmd[cmd.index("-d") + 1])
            (out / "sources").mkdir(parents=True)
            (out / "sources" / "Main.java").write_text("class Main {}")
            return cf.subprocess.CompletedProcess(cmd, 0, "done", "")
        with mock.patch.object(cf, "_analysis_tool_paths", return_value={"ghidra": None, "jadx": "/usr/bin/jadx"}), \
             mock.patch.object(cf.subprocess, "run", side_effect=fake_run) as run:
            result = cf.run_jadx_evidence(item["id"], True)
        self.assertEqual(result["java_file_count"], 1)
        self.assertIn("--no-res", run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs.get("shell", True))

    def test_jadx_requires_confirmation_and_extension(self):
        item = self._store("note.txt", b"text")
        with self.assertRaises(PermissionError):
            cf.run_jadx_evidence(item["id"], False)

    def test_ghidra_requires_confirmation_before_engine_lookup(self):
        item = self._store(data=b"MZtest")
        with self.assertRaises(PermissionError):
            cf.run_ghidra_evidence(item["id"], False)

    def test_plugin_manifest_is_runnable_only_for_verified_entrypoint(self):
        items = cf.list_plugin_manifests()
        sample = next(x for x in items if x["id"] == "example.indicator-enricher")
        self.assertTrue(sample["runnable"])
        self.assertEqual(sample["runtime"], "python:3.12-alpine")

    def test_plugin_sandbox_requires_acknowledgement(self):
        with self.assertRaises(PermissionError):
            cf.run_plugin_sandbox({"plugin_id": "example.indicator-enricher", "acknowledged": False})

    def test_plugin_runtime_is_fixed_no_network_no_pull(self):
        cf.update_plugin_access({"plugin_id": "example.indicator-enricher", "enabled": True,
                                 "permissions": ["knowledge.read", "case.read", "threatintel.read"]})
        calls = []
        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if "image" in cmd:
                return cf.subprocess.CompletedProcess(cmd, 0, "ok", "")
            return cf.subprocess.CompletedProcess(cmd, 0, json.dumps({"result": "ok"}), "")
        with mock.patch.object(cf.shutil, "which", return_value="docker"), mock.patch.object(cf.subprocess, "run", side_effect=fake_run):
            result = cf.run_plugin_sandbox({"plugin_id": "example.indicator-enricher", "acknowledged": True,
                                            "case_id": self.case["id"], "query": "malware"})
        self.assertEqual(result["status"], "completed")
        joined = " ".join(calls[-1])
        self.assertIn("--network none", joined)
        self.assertIn("--pull=never", joined)
        self.assertIn("--read-only", joined)

    def test_plugin_permission_cannot_grant_network_or_unknown_capabilities(self):
        with self.assertRaises(ValueError):
            cf.update_plugin_access({"plugin_id": "example.indicator-enricher", "enabled": True,
                                     "permissions": ["network.passive"]})

    def test_agent_execution_report_uses_real_allowlisted_tool_results(self):
        plan_id = "AG-UNIT-REPORT"
        with cf.AI_AGENT_LOCK:
            cf.AI_AGENT_PLANS[plan_id] = {"id": plan_id, "goal": "inventory local tools", "steps": [
                {"step": 1, "tool": "engine_inventory", "args": {}, "why": "inventory", "permission": "local-read-only"}],
                "status": "ready", "case_id": self.case["id"]}
        result = cf.ai_agent_execute({"plan_id": plan_id})
        self.assertEqual(result["report"]["completed_steps"], 1)
        self.assertEqual(result["report"]["tool_steps"][0]["status"], "completed")
        self.assertEqual(result["report"]["tool_steps"][0]["tool"], "engine_inventory")


    def test_cloud_agent_summary_does_not_forward_raw_code_ioc_or_evidence_names(self):
        captured = {}
        def fake_request(messages, cfg, max_tokens=2500):
            captured["messages"] = messages
            return {"content": "Báo cáo tổng hợp đã nhận dữ liệu rút gọn."}
        results = [
            {"step": 1, "tool": "code_review", "status": "completed", "result": {"review": {"lines": 3, "findings": [{"line": 2, "severity": "high", "title": "Unsafe call", "snippet": "PRIVATE_SOURCE_MARKER", "recommendation": "Use safe API"}]}, "syntax": {"valid_syntax": True}}},
            {"step": 2, "tool": "log_triage", "status": "completed", "result": {"lines": 4, "severity_hints": {"warning": 1}, "iocs": {"ipv4": ["198.51.100.77"], "hashes": ["deadbeef" * 8]}}},
            {"step": 3, "tool": "evidence_triage", "status": "completed", "result": {"evidence": {"id": "E1", "name": "private-customer-document.bin", "sha256": "a" * 64, "size": 10}, "scan": {"assessment": "suspicious", "risk_score": 65, "engines": []}}},
        ]
        with mock.patch.object(cf, "_ai_request", side_effect=fake_request):
            output = cf._agent_cloud_summary(results, "triage", {"provider": "xkiro", "model": "test"})
        serialized = json.dumps(captured["messages"], ensure_ascii=False)
        self.assertIn("Unsafe call", serialized)
        self.assertNotIn("PRIVATE_SOURCE_MARKER", serialized)
        self.assertNotIn("198.51.100.77", serialized)
        self.assertNotIn("private-customer-document.bin", serialized)
        self.assertIn("evidence_sha256", serialized)
        self.assertEqual(output, "Báo cáo tổng hợp đã nhận dữ liệu rút gọn.")

    def test_multi_agent_can_retrieve_local_rag_and_return_citations(self):
        old_cfg = dict(cf.AI_RUNTIME_CONFIG)
        try:
            cf.configure_ai({"provider": "qwencloud", "model": "qwen3.8-max", "region": "ap-southeast-1", "reasoning_effort": "low", "api_key": "test-key"})
            indexed = cf.index_knowledge_document("local-malware-reference.md", "Malware triage should preserve the original sample, record the SHA-256, use static analysis first and never run an untrusted sample on the analyst workstation.", "unit-test")
            self.assertTrue(indexed["indexed"])
            captured = []
            def fake_request(messages, cfg, max_tokens=1600):
                captured.append(messages)
                return {"content": "Specialist report with local reference context."}
            with mock.patch.object(cf, "_ai_request", side_effect=fake_request):
                result = cf.multi_agent_run({"objective": "malware triage and static analysis", "mode": "security", "depth": "quick", "use_knowledge": True})
            self.assertEqual(result["completed_agents"], 3)
            self.assertTrue(any("local-malware-reference.md" in str(x) for x in result["knowledge_sources"]))
            first_user = json.loads(captured[0][1]["content"])
            self.assertIn("LOCAL KNOWLEDGE BASE REFERENCES", first_user["untrusted_context"])
            self.assertEqual(first_user["local_knowledge_sources"], result["knowledge_sources"])
        finally:
            with cf.AI_LOCK:
                cf.AI_RUNTIME_CONFIG.clear(); cf.AI_RUNTIME_CONFIG.update(old_cfg)

    def test_multi_agent_rag_is_not_attached_when_opted_out(self):
        old_cfg = dict(cf.AI_RUNTIME_CONFIG)
        try:
            cf.configure_ai({"provider": "qwencloud", "model": "qwen3.8-max", "region": "ap-southeast-1", "reasoning_effort": "low", "api_key": "test-key"})
            cf.index_knowledge_document("local-no-rag.md", "This unique phrase should not appear in agent context if local RAG is disabled.", "unit-test")
            captured = []
            def fake_request(messages, cfg, max_tokens=1600):
                captured.append(messages)
                return {"content": "Report."}
            with mock.patch.object(cf, "_ai_request", side_effect=fake_request):
                result = cf.multi_agent_run({"objective": "general architecture review", "mode": "development", "depth": "quick", "context": "plain user context", "use_knowledge": False})
            self.assertEqual(result["knowledge_sources"], [])
            first_user = json.loads(captured[0][1]["content"])
            self.assertNotIn("LOCAL KNOWLEDGE BASE REFERENCES", first_user["untrusted_context"])
        finally:
            with cf.AI_LOCK:
                cf.AI_RUNTIME_CONFIG.clear(); cf.AI_RUNTIME_CONFIG.update(old_cfg)

    def test_virtualbox_start_requires_basic_isolation_checks(self):
        vm_uuid = "11111111-2222-3333-4444-555555555555"
        inventory = {"available": True, "vms": [{"uuid": vm_uuid, "running": False, "basic_isolation_checks_passed": False}]}
        with mock.patch.object(cf.shutil, "which", return_value="VBoxManage"), mock.patch.object(cf, "vm_lab_info", return_value=inventory), mock.patch.object(cf, "_vbox_run") as run:
            with self.assertRaises(PermissionError):
                cf.vm_lab_snapshot({"action": "start", "vm_uuid": vm_uuid, "acknowledged": True})
            run.assert_not_called()

    def test_virtualbox_start_uses_headless_fixed_argv_after_isolation(self):
        vm_uuid = "11111111-2222-3333-4444-555555555555"
        inventory = {"available": True, "vms": [{"uuid": vm_uuid, "running": False, "basic_isolation_checks_passed": True}]}
        with mock.patch.object(cf.shutil, "which", return_value="VBoxManage"), mock.patch.object(cf, "vm_lab_info", return_value=inventory), mock.patch.object(cf, "_vbox_run", return_value=cf.subprocess.CompletedProcess(["VBoxManage"], 0, "started", "")) as run:
            result = cf.vm_lab_snapshot({"action": "start", "vm_uuid": vm_uuid, "acknowledged": True})
        self.assertTrue(result["success"])
        self.assertEqual(run.call_args.args[1], ["startvm", vm_uuid, "--type", "headless"])

    def test_virtualbox_restore_refuses_running_vm(self):
        vm_uuid = "11111111-2222-3333-4444-555555555555"
        inventory = {"available": True, "vms": [{"uuid": vm_uuid, "running": True, "basic_isolation_checks_passed": True}]}
        with mock.patch.object(cf.shutil, "which", return_value="VBoxManage"), mock.patch.object(cf, "vm_lab_info", return_value=inventory), mock.patch.object(cf, "_vbox_run") as run:
            with self.assertRaises(PermissionError):
                cf.vm_lab_snapshot({"action": "restore", "vm_uuid": vm_uuid, "snapshot_name": "clean", "acknowledged": True})
            run.assert_not_called()

    def test_vault_rekey_failure_rolls_back_database_files_and_metadata(self):
        item = self._store(data=b"rollback-evidence")
        con = cf._db_connect()
        try:
            before = con.execute("SELECT stored_name FROM evidence WHERE id=?", (item["id"],)).fetchone()["stored_name"]
        finally:
            con.close()
        old_meta = cf._vault_meta_path().read_bytes()
        old_path = cf.EVIDENCE_DIR / before
        with mock.patch.object(cf, "_audit", side_effect=RuntimeError("injected audit failure")):
            with self.assertRaisesRegex(RuntimeError, "injected audit failure"):
                cf.vault_change_passphrase("unit-test-passphrase-123", "new-unit-test-passphrase-456", "new-unit-test-passphrase-456")
        self.assertEqual(cf._vault_meta_path().read_bytes(), old_meta)
        self.assertTrue(old_path.exists())
        self.assertEqual(cf.get_evidence_bytes(item["id"])[1], b"rollback-evidence")
        con = cf._db_connect()
        try:
            after = con.execute("SELECT stored_name FROM evidence WHERE id=?", (item["id"],)).fetchone()["stored_name"]
        finally:
            con.close()
        self.assertEqual(after, before)

    def test_http_routes_for_vault_and_analysis_inventory(self):
        server = ThreadingHTTPServer((cf.HOST, 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://{cf.HOST}:{server.server_address[1]}"
            with urlopen(base + "/api/vault/status", timeout=3) as response:
                vault = json.loads(response.read())
            with urlopen(base + "/api/analysis/engines", timeout=3) as response:
                engines = json.loads(response.read())
            with urlopen(base + "/api/plugins/runs?permission_ack=plugin_admin", timeout=3) as response:
                runs = json.loads(response.read())
            self.assertTrue(vault["configured"])
            self.assertIn("ghidra", engines)
            self.assertIsInstance(runs, list)
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_ui_exposes_encrypted_vault_and_deep_connectors(self):
        ui = (cf.ROOT / "static" / "index.html").read_text(encoding="utf-8")
        for token in ("vaultPassphrase", "vaultOldPass", "capeSubmitAck", "mobsfUploadAck", "runGhidraUI", "runJADXUI", "runPluginUI", "searchMISPBatchUI"):
            self.assertIn(token, ui)


if __name__ == "__main__":
    unittest.main()
