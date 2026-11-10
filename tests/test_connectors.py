from __future__ import annotations
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import connectors
from server import create_handler
from server_core import AIService, Store
from pathlib import Path
import tempfile


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/-/healthy':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Prometheus Server is Healthy.')
        elif self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/-/healthy')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *args):
        pass


class ConnectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), _HealthHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.httpd.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=2)

    def test_prometheus_health_check_real_loopback_http(self):
        with patch.dict(os.environ, {'PROMETHEUS_URL': self.base}, clear=False):
            result = connectors.test_connector('prometheus')
        self.assertTrue(result['connected'])
        self.assertEqual(result['http_status'], 200)
        self.assertGreaterEqual(result['latency_ms'], 0)

    def test_unconfigured_endpoint_is_reported(self):
        with patch.dict(os.environ, {'PROMETHEUS_URL': ''}, clear=False):
            with self.assertRaises(connectors.ConnectorError) as ctx:
                connectors.test_connector('prometheus')
        self.assertEqual(ctx.exception.code, 'connector_endpoint_not_configured')

    def test_remote_host_requires_allowlist_before_request(self):
        with patch.dict(os.environ, {'PROMETHEUS_URL': 'https://metrics.example.invalid', 'CF_CONNECTOR_ALLOWED_HOSTS': ''}, clear=False):
            with self.assertRaises(connectors.ConnectorError) as ctx:
                connectors.test_connector('prometheus')
        self.assertEqual(ctx.exception.code, 'connector_host_not_allowlisted')

    def test_remote_http_is_rejected_even_if_allowlisted(self):
        with patch.dict(os.environ, {'PROMETHEUS_URL': 'http://metrics.example.invalid', 'CF_CONNECTOR_ALLOWED_HOSTS': 'metrics.example.invalid'}, clear=False):
            with self.assertRaises(connectors.ConnectorError) as ctx:
                connectors.test_connector('prometheus')
        self.assertEqual(ctx.exception.code, 'connector_remote_requires_https')

    def test_unknown_connector_has_no_dynamic_url(self):
        with self.assertRaises(connectors.ConnectorError) as ctx:
            connectors.test_connector('arbitrary-url')
        self.assertEqual(ctx.exception.code, 'connector_test_not_supported')

    def test_redirect_is_not_followed(self):
        cfg = dict(connectors.CHECKS['prometheus'])
        cfg['path'] = '/redirect'
        with patch.dict(connectors.CHECKS, {'prometheus': cfg}), patch.dict(os.environ, {'PROMETHEUS_URL': self.base}, clear=False):
            result = connectors.test_connector('prometheus')
        self.assertFalse(result['connected'])
        self.assertEqual(result['http_status'], 302)

    def test_required_credentials_are_checked(self):
        with patch.dict(os.environ, {'GITHUB_API_URL': 'http://127.0.0.1', 'GITHUB_TOKEN': ''}, clear=False):
            with self.assertRaises(connectors.ConnectorError) as ctx:
                connectors.test_connector('github')
        self.assertEqual(ctx.exception.code, 'connector_credentials_missing')

    def test_response_body_is_never_returned(self):
        with patch.dict(os.environ, {'PROMETHEUS_URL': self.base}, clear=False):
            result = connectors.test_connector('prometheus')
        self.assertNotIn('body', result)
        self.assertNotIn('content', result)


class ConnectorAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = Path(cls.tmp.name)
        cls.store = Store(cls.data / 'server.sqlite3')
        cls.admin = cls.store.create_token('admin', 'admin')['token']
        cls.operator = cls.store.create_token('operator', 'operator')['token']
        cls.viewer = cls.store.create_token('viewer', 'viewer')['token']
        cls.ai = AIService(cls.store)
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), create_handler(cls.store, cls.ai, cls.data))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.httpd.server_port}'
        cls.health_httpd = ThreadingHTTPServer(('127.0.0.1', 0), _HealthHandler)
        cls.health_thread = threading.Thread(target=cls.health_httpd.serve_forever, daemon=True)
        cls.health_thread.start()
        cls.health_base = f'http://127.0.0.1:{cls.health_httpd.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.health_httpd.shutdown(); cls.health_httpd.server_close(); cls.health_thread.join(timeout=2)
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=3); cls.tmp.cleanup()

    def request(self, token, body):
        req = __import__('urllib.request').request.Request(
            self.base + '/api/v200/integrations/test', data=json.dumps(body).encode(), method='POST',
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        try:
            with __import__('urllib.request').request.urlopen(req, timeout=4) as response:
                return response.status, json.loads(response.read())
        except __import__('urllib.error').error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_operator_can_run_fixed_connector_check(self):
        with patch.dict(os.environ, {'PROMETHEUS_URL': self.health_base}, clear=False):
            status, body = self.request(self.operator, {'id': 'prometheus'})
        self.assertEqual(status, 200)
        self.assertTrue(body['result']['connected'])

    def test_viewer_cannot_run_connector_check(self):
        status, body = self.request(self.viewer, {'id': 'prometheus'})
        self.assertEqual(status, 403)
        self.assertEqual(body['error']['code'], 'forbidden')

    def test_client_cannot_supply_endpoint_or_headers(self):
        with patch.dict(os.environ, {'PROMETHEUS_URL': self.health_base}, clear=False):
            status, body = self.request(self.operator, {'id': 'prometheus', 'url': 'http://attacker.invalid', 'headers': {'Authorization': 'x'}})
        self.assertEqual(status, 200)
        self.assertEqual(body['result']['id'], 'prometheus')


if __name__ == '__main__':
    unittest.main(verbosity=2)

class AgentRedirectTests(unittest.TestCase):
    def test_agent_does_not_follow_redirect_with_node_credentials(self):
        from agent.agent import send_report
        received = []
        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.path, self.headers.get('X-CF-Node-Token')))
                self.send_response(302)
                self.send_header('Location', second_url[0] + '/steal')
                self.end_headers()
            def log_message(self, *args): pass
        class SinkHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(('sink', self.headers.get('X-CF-Node-Token')))
                self.send_response(200); self.end_headers()
            def log_message(self, *args): pass
        sink = ThreadingHTTPServer(('127.0.0.1', 0), SinkHandler)
        second_url = [f'http://127.0.0.1:{sink.server_port}']
        source = ThreadingHTTPServer(('127.0.0.1', 0), RedirectHandler)
        a = threading.Thread(target=source.serve_forever, daemon=True); a.start()
        b = threading.Thread(target=sink.serve_forever, daemon=True); b.start()
        try:
            env = {'CF_SERVER_URL': f'http://127.0.0.1:{source.server_port}', 'CF_NODE_ID': 'node_test', 'CF_NODE_TOKEN': 'secret-node-token'}
            with patch.dict(os.environ, env, clear=False):
                with self.assertRaises(Exception): send_report()
            self.assertEqual(len(received), 1)
            self.assertEqual(received[0][1], 'secret-node-token')
        finally:
            source.shutdown(); source.server_close(); a.join(timeout=2)
            sink.shutdown(); sink.server_close(); b.join(timeout=2)
