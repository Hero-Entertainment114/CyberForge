from __future__ import annotations
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess

import v193_modules as v
import cyberforge as cf


class V193FreeAIRouterTests(unittest.TestCase):
    def tearDown(self):
        v.clear_remote_ai()

    def test_01_provider_status_separates_three_free_options_and_paid_qwen_without_secrets(self):
        v.configure_remote_ai("groq", "gsk_test_secret_123456789", "openai/gpt-oss-20b")
        status = v.remote_ai_status()
        providers = {x["id"]: x for x in status["providers"]}
        self.assertEqual(set(providers), {"groq", "openrouter", "gemini", "qwencloud"})
        self.assertIn("paid", providers["qwencloud"]["label"].lower())
        self.assertTrue(providers["groq"]["configured"])
        self.assertNotIn("gsk_test_secret", json.dumps(status))
        self.assertEqual(status["remote_default"], False)

    def test_02_config_rejects_unknown_provider_short_key_and_bad_model(self):
        with self.assertRaises(ValueError): v.configure_remote_ai("unknown", "x" * 20)
        with self.assertRaises(ValueError): v.configure_remote_ai("groq", "tiny")
        with self.assertRaises(ValueError): v.configure_remote_ai("groq", "x" * 20, "foo/../../etc/passwd")
        with self.assertRaises(ValueError): v.configure_remote_ai("openrouter", "or_test_key_123456789", "openai/gpt-oss-20b")
        with self.assertRaises(ValueError): v.configure_remote_ai("gemini", "gemini_test_key_123456789", "gemini-2.5-pro")

    def test_03_remote_requires_explicit_request_consent_before_network(self):
        v.configure_remote_ai("groq", "gsk_test_secret_123456789")
        with patch.object(v, "_json_request") as request:
            with self.assertRaises(PermissionError):
                v.remote_ai_chat("groq", "", "", "hello", acknowledged=False)
            request.assert_not_called()

    def test_04_remote_chat_redacts_common_secrets_before_sending(self):
        v.configure_remote_ai("groq", "gsk_test_secret_123456789", "openai/gpt-oss-20b")
        fake = {"choices": [{"message": {"content": "Reviewed safely."}}]}
        with patch.object(v, "_json_request", return_value=fake) as request:
            result = v.remote_ai_chat("groq", "", "", "Review api_key=sk-verysecretvalue123 and this code",
                "Authorization: Bearer supersecrettoken", acknowledged=True)
        sent = json.dumps(request.call_args.args[2])
        self.assertNotIn("sk-verysecretvalue123", sent)
        self.assertNotIn("supersecrettoken", sent)
        self.assertGreaterEqual(result["redactions_count"], 2)
        self.assertEqual(result["provider"], "groq")
        self.assertTrue(result["cloud_used"])

    def test_05_openrouter_and_gemini_use_fixed_https_endpoints(self):
        v.configure_remote_ai("openrouter", "or_test_key_123456789", "openrouter/free")
        with patch.object(v, "_json_request", return_value={"choices": [{"message": {"content": "ok"}}]}) as request:
            v.remote_ai_chat("openrouter", "", "", "hello", acknowledged=True)
        self.assertTrue(request.call_args.args[0].startswith("https://openrouter.ai/api/v1/"))
        self.assertEqual(request.call_args.args[1]["Authorization"], "Bearer or_test_key_123456789")
        v.clear_remote_ai()
        v.configure_remote_ai("gemini", "gemini_test_key_123456789", "gemini-3.1-flash-lite")
        with patch.object(v, "_json_request", return_value={"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}) as request:
            v.remote_ai_chat("gemini", "", "", "hello", acknowledged=True)
        self.assertTrue(request.call_args.args[0].startswith("https://generativelanguage.googleapis.com/v1beta/models/"))
        self.assertEqual(request.call_args.args[1]["x-goog-api-key"], "gemini_test_key_123456789")

    def test_06_redaction_private_key_and_github_token(self):
        text, count = v.redact_sensitive_text("ghp_" + "A" * 36 + "\n-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
        self.assertGreaterEqual(count, 2)
        self.assertNotIn("A" * 36, text)
        self.assertNotIn("\nabc\n", text)

    def test_07_redaction_google_and_groq_api_key_formats(self):
        text, count = v.redact_sensitive_text("AIza" + "A" * 36 + " gsk_" + "B" * 36)
        self.assertEqual(count, 2)
        self.assertNotIn("A" * 36, text)
        self.assertNotIn("B" * 36, text)


class V193NetLabTests(unittest.TestCase):
    def _stage(self, root, name="sample.py", source=b"print('hello')", duration=5):
        return v.prepare_netlab_session(root, name, base64.b64encode(source).decode(), duration)

    def test_01_netlab_prepare_is_staging_only_readonly_and_hashed(self):
        with tempfile.TemporaryDirectory() as td:
            result = self._stage(td)
            session = Path(td) / "sandbox_netlab" / result["session_id"]
            sample = next((session / "input").iterdir())
            self.assertEqual(sample.read_bytes(), b"print('hello')")
            self.assertEqual(result["status"], "prepared")
            self.assertFalse(result["host_execution"])
            self.assertEqual(sample.stat().st_mode & 0o777, 0o400)
            self.assertEqual(result["sha256"], v._sha256(sample))

    def test_02_netlab_rejects_windows_executable_and_oversize(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError): self._stage(td, "sample.exe")
            with self.assertRaises(ValueError): self._stage(td, "sample.py", b"x" * (v.MAX_NETLAB_SAMPLE + 1))
            with self.assertRaises(ValueError): v.prepare_netlab_session(td, "x.py", "not-base64")

    def test_03_netlab_rejects_bad_duration_and_session_id(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError): self._stage(td, duration=121)
            with self.assertRaises(ValueError): v.read_netlab_report(td, "foo/../../etc/passwd")

    def test_04_netlab_detects_tampered_sample_hash(self):
        with tempfile.TemporaryDirectory() as td:
            item = self._stage(td)
            sample = Path(td) / "sandbox_netlab" / item["session_id"] / "input" / "sample.py"
            sample.chmod(0o600); sample.write_text("changed", encoding="utf-8")
            with self.assertRaises(PermissionError): v._netlab_session(td, item["session_id"])

    def test_05_build_requires_acknowledgement(self):
        with self.assertRaises(PermissionError): v.build_netlab_image(".", False)

    def test_06_run_command_is_no_network_and_hardened(self):
        with tempfile.TemporaryDirectory() as td:
            item = self._stage(td)
            fake_report = {"schema": "cyberforge.netlab.v1", "events": [], "summary": {"dns_queries": 1}, "sample_exit_code": 0}
            completed = subprocess.CompletedProcess([], 0, "CF_NETLAB_REPORT:" + json.dumps(fake_report), "")
            with patch.object(v.shutil, "which", return_value="/usr/bin/docker"), patch.object(v.subprocess, "run", side_effect=[subprocess.CompletedProcess([],0,"",""), completed, subprocess.CompletedProcess([],0,"","")]) as run:
                result = v.run_netlab_session(td, item["session_id"], True)
            args = run.call_args_list[1].args[0]
            self.assertIn("--network", args); self.assertEqual(args[args.index("--network")+1], "none")
            self.assertIn("--read-only", args); self.assertIn("--cap-drop", args)
            self.assertIn("no-new-privileges", args); self.assertIn("--pids-limit", args)
            self.assertTrue(result["report_ready"])
            self.assertEqual(result["report"]["isolation"]["network"], "none")
            stored = v.read_netlab_report(td, item["session_id"])
            self.assertTrue(stored["report_ready"])

    def test_07_status_discloses_container_kernel_boundary_and_no_network(self):
        with patch.object(v.shutil, "which", return_value=None):
            status = v.netlab_capabilities()
        self.assertFalse(status["runtime_available"])
        self.assertIn("--network none", status["network_mode"])
        self.assertTrue(any("shares the Docker Linux kernel" in x for x in status["limitations"]))

    def test_09_input_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            item = self._stage(td)
            session = Path(td) / "sandbox_netlab" / item["session_id"]
            input_dir = session / "input"
            real_input = session / "input-real"
            input_dir.rename(real_input)
            input_dir.symlink_to(Path(outside), target_is_directory=True)
            with self.assertRaises(PermissionError): v._netlab_session(td, item["session_id"])

    def test_10_report_schema_is_checked(self):
        with tempfile.TemporaryDirectory() as td:
            item = self._stage(td)
            session = Path(td) / "sandbox_netlab" / item["session_id"]
            (session / "report.json").write_text('{"schema":"wrong"}', encoding="utf-8")
            with self.assertRaises(ValueError): v.read_netlab_report(td, item["session_id"])


class V193APIGuardTests(unittest.TestCase):
    def test_01_remote_ai_requires_both_data_consent_and_zero_cost_ack(self):
        base = {"mode": "remote", "allow_remote": True, "message": "hello", "provider": "gemini"}
        with self.assertRaises(PermissionError):
            cf.v193_ai_chat({**base, "zero_cost_ack": False})
        with self.assertRaises(PermissionError):
            cf.v193_ai_chat({**base, "allow_remote": False, "zero_cost_ack": True})


if __name__ == "__main__":
    unittest.main()
