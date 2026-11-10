import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from unittest import mock
import urllib.error
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, limit=-1): return self.payload[:limit]


class V100AITests(unittest.TestCase):
    def setUp(self):
        self.old_config = dict(cf.AI_RUNTIME_CONFIG)
        self.old_conversations = dict(cf.AI_CONVERSATIONS)
        self.old_paths = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        self.temp_data = tempfile.TemporaryDirectory()
        cf.DATA_DIR = Path(self.temp_data.name) / "data"
        cf.DB_PATH = cf.DATA_DIR / "cyberforge.db"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.init_database()
        # Provider tests focus on API compatibility, not the v1.7 permission UI.
        prefs = cf.get_app_preferences()
        prefs["permissions"]["ai_provider_access"] = "allow"
        prefs["ai"]["acknowledge_cloud_context"] = False
        cf.save_app_preferences({"profile": prefs})
        with cf.AI_LOCK:
            cf.AI_CONVERSATIONS.clear()
            cf.AI_RUNTIME_CONFIG.update({"provider": "qwencloud", "model": "qwen3.8-max", "region": "ap-southeast-1", "reasoning_effort": "xhigh", "api_key": None, "disable_env": True})

    def tearDown(self):
        with cf.AI_LOCK:
            cf.AI_RUNTIME_CONFIG.clear(); cf.AI_RUNTIME_CONFIG.update(self.old_config)
            cf.AI_CONVERSATIONS.clear(); cf.AI_CONVERSATIONS.update(self.old_conversations)
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old_paths
        self.temp_data.cleanup()

    def test_version_is_120(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))

    def test_status_never_returns_api_key(self):
        secret = "sk-test-super-secret-key"
        cf.configure_ai({"provider": "qwencloud", "model": "qwen3.8-max", "api_key": secret})
        status = cf.ai_status()
        self.assertTrue(status["configured"])
        self.assertEqual(status["key_source"], "session")
        self.assertNotIn(secret, json.dumps(status))

    def test_provider_and_model_are_allowlisted(self):
        with self.assertRaises(ValueError): cf.configure_ai({"provider": "custom-url", "model": "qwen3.8-max"})
        with self.assertRaises(ValueError): cf.configure_ai({"provider": "qwencloud", "model": "attacker/model"})
        with self.assertRaises(ValueError): cf.configure_ai({"provider": "qwencloud", "model": "qwen3.8-max", "region": "invalid"})

    def test_qwencloud_uses_official_singapore_endpoint_and_reasoning_effort(self):
        cf.configure_ai({"provider": "qwencloud", "model": "qwen3.8-max", "region": "ap-southeast-1", "reasoning_effort": "medium", "api_key": "qwen-secret"})
        fake = FakeResponse({"model": "qwen3.8-max", "choices": [{"message": {"role": "assistant", "content": "Phân tích hoàn tất.", "reasoning_content": "private reasoning metadata"}}], "usage": {"total_tokens": 42}})
        with mock.patch.object(cf, "_ai_open_request", return_value=fake) as call:
            result = cf.ai_chat({"message": "Phân tích lỗi này", "task": "debug"})
        req = call.call_args.args[0]
        sent = json.loads(req.data.decode())
        self.assertEqual(req.full_url, "https://ap-southeast-1.maas.qwencloudapi.com/compatible-mode/v1/chat/completions")
        self.assertEqual(req.get_header("Authorization"), "Bearer qwen-secret")
        self.assertEqual(sent["model"], "qwen3.8-max")
        self.assertEqual(sent["reasoning_effort"], "medium")
        self.assertEqual(result["answer"], "Phân tích hoàn tất.")
        self.assertNotIn("reasoning_content", result)
        self.assertIn("reasoning_content", cf.AI_CONVERSATIONS[result["conversation_id"]][-1])

    def test_qwen_reasoning_metadata_stays_server_side_and_is_reused(self):
        cf.configure_ai({"provider": "qwencloud", "model": "qwen3.8-max", "api_key": "qwen-secret"})
        responses = [
            FakeResponse({"choices": [{"message": {"content": "First answer", "reasoning_content": "private trace"}}]}),
            FakeResponse({"choices": [{"message": {"content": "Second answer"}}]}),
        ]
        with mock.patch.object(cf, "_ai_open_request", side_effect=responses) as call:
            first = cf.ai_chat({"message": "First question"})
            second = cf.ai_chat({"conversation_id": first["conversation_id"], "message": "Follow up"})
        request2 = call.call_args_list[1].args[0]
        messages = json.loads(request2.data.decode())["messages"]
        assistant = next(m for m in messages if m.get("role") == "assistant")
        self.assertEqual(assistant.get("reasoning_content"), "private trace")
        self.assertNotIn("private trace", json.dumps(second))

    def test_xkiro_free_route_uses_compatible_endpoint_and_omits_qwencloud_effort(self):
        cf.configure_ai({"provider": "xkiro", "model": "qwen/qwen3.8-max:free", "api_key": "xkiro-secret"})
        fake = FakeResponse({"model": "qwen/qwen3.8-max:free", "choices": [{"message": {"content": "XKiro answer"}}]})
        with mock.patch.object(cf, "_ai_open_request", return_value=fake) as call:
            result = cf.ai_chat({"message": "Hello"})
        req = call.call_args.args[0]
        sent = json.loads(req.data.decode())
        self.assertEqual(req.full_url, "https://api.xkiro.com/v1/chat/completions")
        self.assertEqual(req.get_header("Authorization"), "Bearer xkiro-secret")
        self.assertEqual(sent["model"], "qwen/qwen3.8-max:free")
        self.assertNotIn("reasoning_effort", sent)
        self.assertEqual(result["provider"], "xkiro")

    def test_chat_input_limits(self):
        with self.assertRaises(ValueError): cf.ai_chat({"message": ""})
        with self.assertRaises(ValueError): cf.ai_chat({"message": "x" * (cf.AI_MAX_MESSAGE_CHARS + 1)})
        with self.assertRaises(ValueError): cf.ai_chat({"message": "hello", "task": "execute_anything"})

    def test_oversized_history_is_rejected_without_mutating_conversation(self):
        cid = "11111111-1111-1111-1111-111111111111"
        cf.AI_CONVERSATIONS[cid] = [{"role": "assistant", "content": "x" * 22_000} for _ in range(cf.AI_MAX_HISTORY_MESSAGES)]
        before = list(cf.AI_CONVERSATIONS[cid])
        with self.assertRaises(ValueError):
            cf.ai_chat({"conversation_id": cid, "message": "hello"})
        self.assertEqual(cf.AI_CONVERSATIONS[cid], before)

    def test_chat_requires_key_without_calling_network(self):
        with self.assertRaises(RuntimeError): cf.ai_chat({"message": "hello"})

    def test_ai_authenticated_opener_disables_redirects(self):
        seen = {}
        class FakeOpener:
            def open(self, request, timeout):
                seen["request"] = request
                seen["timeout"] = timeout
                return FakeResponse({"ok": True})
        with mock.patch.object(cf.urllib.request, "build_opener", side_effect=lambda handler: (seen.update({"handler": handler}) or FakeOpener())):
            response = cf._ai_open_request(cf.urllib.request.Request("https://api.xkiro.com/v1/chat/completions"))
        self.assertIsInstance(seen["handler"], cf._NoRedirect)
        self.assertEqual(seen["timeout"], 150)

    def test_ai_test_connection_uses_selected_provider(self):
        cf.configure_ai({"provider": "xkiro", "model": "qwen/qwen3.8-max:free", "api_key": "xkiro-test"})
        fake = FakeResponse({"model": "qwen/qwen3.8-max:free", "choices": [{"message": {"content": "OK"}}], "usage": {"total_tokens": 4}})
        with mock.patch.object(cf, "_ai_open_request", return_value=fake):
            result = cf.ai_test_connection()
        self.assertTrue(result["ok"])
        self.assertEqual(result["provider"], "xkiro")
        self.assertIn("may consume tokens", result["note"])

    def test_reset_conversation(self):
        cid = "00000000-0000-0000-0000-000000000000"
        cf.AI_CONVERSATIONS[cid] = [{"role": "user", "content": "x"}]
        self.assertTrue(cf.ai_reset_conversation({"conversation_id": cid})["cleared"])
        self.assertNotIn(cid, cf.AI_CONVERSATIONS)

    def test_http_error_redacts_provider_key(self):
        cf.configure_ai({"provider": "xkiro", "model": "qwen/qwen3.8-max:free", "api_key": "xkiro-secret-key"})
        error = urllib.error.HTTPError("https://api.xkiro.com", 401, "unauthorized", {}, io.BytesIO(b'{"error":{"message":"xkiro-secret-key invalid"}}'))
        with mock.patch.object(cf, "_ai_open_request", side_effect=error):
            with self.assertRaises(RuntimeError) as ctx: cf.ai_chat({"message": "test"})
        self.assertNotIn("xkiro-secret-key", str(ctx.exception))
        self.assertIn("401", str(ctx.exception))

    def test_ai_status_endpoint_is_registered(self):
        self.assertEqual(cf.ai_status()["providers"][0]["id"], "qwencloud")
        self.assertEqual(cf.ai_status()["providers"][1]["id"], "xkiro")

    def test_http_ai_status_config_and_chat_routes(self):
        fake = FakeResponse({"model": "qwen3.8-max", "choices": [{"message": {"content": "HTTP route answer"}}], "usage": {"total_tokens": 6}})
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            config_body = json.dumps({"provider": "qwencloud", "model": "qwen3.8-max", "region": "ap-southeast-1", "reasoning_effort": "low", "api_key": "route-secret"}).encode()
            config_request = Request(base + "/api/ai/config", data=config_body, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(config_request, timeout=3) as response:
                configured = json.loads(response.read())
            self.assertTrue(configured["configured"])
            with urlopen(base + "/api/ai/status", timeout=3) as response:
                status = json.loads(response.read())
            self.assertTrue(status["configured"])
            self.assertNotIn("route-secret", json.dumps(status))
            body = json.dumps({"message": "Explain this test", "task": "chat"}).encode()
            request = Request(base + "/api/ai/chat", data=body, headers={"Content-Type": "application/json"}, method="POST")
            with mock.patch.object(cf, "_ai_open_request", return_value=fake):
                with urlopen(request, timeout=3) as response:
                    result = json.loads(response.read())
            self.assertEqual(result["answer"], "HTTP route answer")
            self.assertIn("conversation_id", result)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
