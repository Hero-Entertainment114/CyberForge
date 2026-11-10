import json
import socket
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf
import privacy_net as pn


class PrivacyNetworkTests(unittest.TestCase):
    def setUp(self):
        pn.clear_privacy_session()
        self.tmp = tempfile.TemporaryDirectory(prefix="cf160-test-")
        self.old_paths = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        base = Path(self.tmp.name) / "data"
        cf.DATA_DIR = base
        cf.DB_PATH = base / "cyberforge.db"
        cf.EVIDENCE_DIR = base / "evidence"
        cf.init_database()

    def tearDown(self):
        pn.clear_privacy_session()
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old_paths
        self.tmp.cleanup()

    def test_version_is_160(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))

    def test_default_route_is_direct_and_explicitly_not_anonymous(self):
        status = pn.privacy_status()
        self.assertEqual(status["route"], "direct")
        self.assertIn("not an anonymous", status["detail"])
        self.assertTrue(status["session_only"])

    def test_tor_route_requires_literal_proxy_ip(self):
        with self.assertRaises(ValueError):
            pn.configure_privacy({"route": "tor", "tor_host": "tor.local"})
        good = pn.configure_privacy({"route": "tor", "tor_host": "127.0.0.1", "tor_port": 9050})
        self.assertEqual(good["route"], "tor")

    def test_proxy_credentials_are_not_returned(self):
        status = pn.configure_privacy({"route": "http_proxy", "http_proxy": "http://user:secret@127.0.0.1:8080"})
        serialized = json.dumps(status)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("user:secret", serialized)
        self.assertIn("127.0.0.1:8080", status["proxy_display"])

    def test_socks5_domain_is_sent_to_proxy_without_local_dns(self):
        class FakeSocket:
            def __init__(self):
                self.responses = [b"\x05\x00", b"\x05\x00\x00\x03", b"\x0b", b"torproject.org", b"\x00\x50"]
                self.sent = []
                self.closed = False
            def settimeout(self, value): pass
            def sendall(self, data): self.sent.append(data)
            def recv(self, n):
                item = self.responses.pop(0)
                if len(item) > n:
                    self.responses.insert(0, item[n:])
                    return item[:n]
                return item
            def close(self): self.closed = True
        fs = FakeSocket()
        with mock.patch.object(pn.socket, "create_connection", return_value=fs):
            out = pn._socks5_connect("127.0.0.1", 9050, "torproject.org", 443)
        self.assertIs(out, fs)
        self.assertIn(b"\x03\x0etorproject.org\x01\xbb", fs.sent[1])

    def test_non_public_ip_targets_are_blocked(self):
        for url in ("http://127.0.0.1/", "http://10.0.0.1/", "http://169.254.169.254/", "http://192.168.1.2/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                pn.privacy_read(url)

    def test_private_ip_is_blocked_even_when_tor_route_selected(self):
        pn.configure_privacy({"route": "tor", "tor_host": "127.0.0.1", "tor_port": 9050})
        for url in ("http://127.0.0.1/", "http://10.0.0.1/", "http://169.254.169.254/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                pn._validate_url(url, "tor")

    def test_remote_http_proxy_basic_credentials_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "HTTP proxy từ xa"):
            pn.configure_privacy({"route": "http_proxy", "http_proxy": "http://alice:secret@proxy.example:8080"})

    def test_local_hostname_is_blocked(self):
        with self.assertRaises(ValueError):
            pn.privacy_read("http://router.local/")

    def test_onion_requires_tor_route(self):
        with self.assertRaises(ValueError):
            pn._validate_url("http://samplehiddenservice.onion/", "direct")
        p = pn._validate_url("http://samplehiddenservice.onion/", "tor")
        self.assertEqual(p.hostname, "samplehiddenservice.onion")

    def test_direct_dns_rejects_non_global_answers(self):
        with mock.patch.object(pn.socket, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                pn._resolve_public("public.example.org", 443)

    def test_tor_route_fails_closed_when_proxy_missing(self):
        pn.configure_privacy({"route": "tor", "tor_host": "127.0.0.1", "tor_port": 9050})
        with mock.patch.object(pn, "_tor_probe", return_value={"available": False}):
            with self.assertRaises(RuntimeError):
                pn._connect_route("example.org", 443, "https", "tor", pn._snapshot())

    def test_wireguard_route_fails_closed_when_default_route_missing(self):
        pn.configure_privacy({"route": "wireguard_system"})
        with mock.patch.object(pn, "_wireguard_status", return_value={"default_route_via_wireguard": False}):
            with self.assertRaises(RuntimeError):
                pn._connect_route("example.org", 443, "https", "wireguard_system", pn._snapshot())

    def test_reader_strips_active_content_and_keeps_safe_links(self):
        html = b'''<html><head><title>Demo Page</title><script>alert(1)</script></head><body><h1>Hello</h1><p>Safe text</p><form><input value="secret"></form><iframe src="https://evil.test"></iframe><a href="https://example.org/next">Next page</a></body></html>'''
        with mock.patch.object(pn, "_fetch_bytes", return_value=(200, {"content-type": "text/html; charset=utf-8"}, html, "https://example.org/")):
            result = pn.privacy_read("https://example.org/")
        self.assertEqual(result["title"], "Demo Page")
        self.assertIn("Safe text", result["content"])
        self.assertNotIn("alert(1)", result["content"])
        self.assertNotIn("secret", result["content"])
        self.assertEqual(result["links"][0]["url"], "https://example.org/next")

    def test_reader_does_not_follow_redirects(self):
        class FakeResponse:
            status = 302
            def getheaders(self): return [("Location", "http://127.0.0.1/")]
            def read(self, size): return b""
        class FakeConn:
            sock = object()
            def request(self, *args, **kwargs): pass
            def getresponse(self): return FakeResponse()
            def close(self): pass
        with mock.patch.object(pn, "_connect_route", return_value=FakeConn()), \
             mock.patch.object(pn, "_resolve_public", return_value="93.184.216.34"):
            with self.assertRaises(RuntimeError):
                pn._fetch_bytes("https://example.org/")

    def test_search_uses_sanitized_result_parser(self):
        page = b'''<html><div class="result"><a class="result__a" href="https://example.org/a">Example title</a><a class="result__snippet">A safe snippet</a></div></html>'''
        with mock.patch.object(pn, "_fetch_bytes", return_value=(200, {"content-type": "text/html; charset=utf-8"}, page, "https://html.duckduckgo.com/html/")):
            result = pn.privacy_search("example query", "duckduckgo")
        self.assertTrue(result["results"])
        self.assertEqual(result["results"][0]["title"], "Example title")

    def test_searxng_requires_configured_https_endpoint(self):
        with self.assertRaises(ValueError):
            pn.configure_privacy({"route": "direct", "searxng_url": "http://search.example.org"})
        pn.configure_privacy({"route": "direct", "searxng_url": "https://search.example.org"})
        with mock.patch.object(pn, "_fetch_bytes", return_value=(200, {"content-type": "application/json"}, b'{"results":[]}', "https://search.example.org/search")):
            result = pn.privacy_search("test", "searxng")
        self.assertEqual(result["provider"], "SearXNG")

    def test_tor_route_test_rejects_error_response(self):
        pn.configure_privacy({"route": "tor", "tor_host": "127.0.0.1", "tor_port": 9050})
        with mock.patch.object(pn, "_fetch_bytes", return_value=(503, {"content-type": "text/plain"}, b"unavailable", "https://check.torproject.org/api/ip")):
            with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
                pn.privacy_route_test(True)

    def test_route_test_requires_explicit_ack(self):
        with self.assertRaises(PermissionError):
            pn.privacy_route_test(False)

    def test_network_simulator_is_explicitly_simulated(self):
        out = pn.simulate_network({"route": "tor"})
        self.assertTrue(out["simulated"])
        self.assertIn("remote DNS", out["nodes"][1]["dns"])
        self.assertIn("không thay đổi", out["notice"])

    def test_clear_session_removes_proxy_credentials(self):
        pn.configure_privacy({"route": "http_proxy", "http_proxy": "http://alice:secret@127.0.0.1:8080"})
        pn.clear_privacy_session()
        self.assertEqual(pn._snapshot()["http_proxy"], "")
        self.assertEqual(pn._snapshot()["route"], "direct")


    def test_http_proxy_http_target_uses_explicit_proxy_and_never_direct_handler(self):
        pn.configure_privacy({"route": "http_proxy", "http_proxy": "http://proxy.example:3128"})
        class FakeResponse:
            status = 200
            def getheaders(self): return [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", "2")]
            def read(self, size): return b"ok"
        class FakeConnection:
            def __init__(self, host, port, timeout=None):
                self.host, self.port, self.timeout = host, port, timeout
                self.request_args = None
            def request(self, method, target, headers=None): self.request_args = (method, target, headers or {})
            def getresponse(self): return FakeResponse()
            def close(self): pass
        made = []
        def factory(*args, **kwargs):
            conn = FakeConnection(*args, **kwargs); made.append(conn); return conn
        with mock.patch.object(pn.http.client, "HTTPConnection", side_effect=factory), \
             mock.patch.object(pn.socket, "create_connection", side_effect=AssertionError("direct socket forbidden")):
            status, headers, body, _ = pn._fetch_bytes("http://example.org/path")
        self.assertEqual((status, body), (200, b"ok"))
        self.assertEqual((made[0].host, made[0].port), ("proxy.example", 3128))
        method, target, req_headers = made[0].request_args
        self.assertEqual(method, "GET")
        self.assertEqual(target, "http://example.org/path")
        self.assertEqual(req_headers.get("Host"), "example.org")
        self.assertNotIn("Proxy-Authorization", req_headers)

    def test_http_proxy_https_target_uses_connect_tunnel_without_direct_fallback(self):
        pn.configure_privacy({"route": "http_proxy", "http_proxy": "http://proxy.example:8080"})
        class FakeResponse:
            status = 200
            def getheaders(self): return [("Content-Type", "text/plain")]
            def read(self, size): return b"secure"
        class FakeConnection:
            def __init__(self, host, port, timeout=None, context=None):
                self.host, self.port, self.timeout = host, port, timeout
                self.tunnel = None; self.request_args = None
            def set_tunnel(self, host, port, headers=None): self.tunnel = (host, port, headers or {})
            def request(self, method, target, headers=None): self.request_args = (method, target, headers or {})
            def getresponse(self): return FakeResponse()
            def close(self): pass
        made = []
        def factory(*args, **kwargs):
            conn = FakeConnection(*args, **kwargs); made.append(conn); return conn
        with mock.patch.object(pn.http.client, "HTTPSConnection", side_effect=factory), \
             mock.patch.object(pn.socket, "create_connection", side_effect=AssertionError("direct socket forbidden")):
            status, headers, body, _ = pn._fetch_bytes("https://example.org/secure")
        self.assertEqual((status, body), (200, b"secure"))
        self.assertEqual((made[0].host, made[0].port), ("proxy.example", 8080))
        self.assertEqual(made[0].tunnel[:2], ("example.org", 443))
        self.assertEqual(made[0].request_args[1], "/secure")
        self.assertEqual(made[0].request_args[2].get("Host"), "example.org")

    def test_http_api_exposes_privacy_status_and_search(self):
        server = ThreadingHTTPServer((cf.HOST, 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://{cf.HOST}:{server.server_port}"
            with urlopen(base + "/api/privacy/status", timeout=3) as r:
                self.assertEqual(json.loads(r.read())["route"], "direct")
            req = Request(base + "/api/privacy/simulate", data=json.dumps({"route": "tor", "_permission_acknowledged": ["network_connectors"]}).encode(),
                          headers={"Content-Type": "application/json", "Origin": base}, method="POST")
            with urlopen(req, timeout=3) as r:
                self.assertTrue(json.loads(r.read())["simulated"])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
