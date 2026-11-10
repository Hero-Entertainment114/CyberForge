from __future__ import annotations
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'server.py'), *args], cwd=ROOT,
                              text=True, capture_output=True, timeout=10, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})


    def test_server_edition_refuses_non_linux_runtime(self):
        import server
        with tempfile.TemporaryDirectory() as tmp, patch('server.platform.system', return_value='Windows'):
            with self.assertRaisesRegex(SystemExit, 'Linux-only'):
                server.serve(SimpleNamespace(bind='127.0.0.1', port=8787, data_dir=tmp))
            self.assertFalse((Path(tmp) / 'server.sqlite3').exists())

    def test_help_works(self):
        cp = self.run_cli('--help')
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn('CyberForge Server Edition', cp.stdout)
        self.assertIn('doctor', cp.stdout)

    def test_version_works(self):
        cp = self.run_cli('--version')
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.strip(), '2.1.0')

    def test_doctor_creates_read_only_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = self.run_cli('--data-dir', tmp, 'doctor')
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertIn('integrations', cp.stdout)
            self.assertIn('audit', cp.stdout)
            self.assertTrue((Path(tmp) / 'server.sqlite3').exists())


    def test_non_loopback_bind_is_refused_before_database_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = self.run_cli('--data-dir', tmp, 'serve', '--bind', '0.0.0.0')
            self.assertNotEqual(cp.returncode, 0)
            self.assertIn('binds to loopback by default', cp.stderr + cp.stdout)
            self.assertFalse((Path(tmp) / 'server.sqlite3').exists())

    def test_private_bind_requires_proxy_allowlist_before_database_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, 'CF_SERVER_ALLOW_PRIVATE_BIND': '1', 'CF_SERVER_TRUST_PROXY': '0'}
            cp = subprocess.run([sys.executable, str(ROOT / 'server.py'), '--data-dir', tmp,
                                 'serve', '--bind', '192.168.10.5'], cwd=ROOT, text=True,
                                 capture_output=True, timeout=10, env=env)
            self.assertNotEqual(cp.returncode, 0)
            self.assertIn('CF_SERVER_TRUST_PROXY=1', cp.stderr + cp.stdout)
            self.assertFalse((Path(tmp) / 'server.sqlite3').exists())

    def test_public_bind_remains_refused_even_with_private_optin(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, 'CF_SERVER_ALLOW_PRIVATE_BIND': '1', 'CF_SERVER_TRUST_PROXY': '1',
                   'CF_SERVER_TRUST_PROXY_CIDRS': '10.0.0.0/8'}
            cp = subprocess.run([sys.executable, str(ROOT / 'server.py'), '--data-dir', tmp,
                                 'serve', '--bind', '8.8.8.8'], cwd=ROOT, text=True,
                                 capture_output=True, timeout=10, env=env)
            self.assertNotEqual(cp.returncode, 0)
            self.assertIn('public/unspecified addresses are refused', cp.stderr + cp.stdout)
            self.assertFalse((Path(tmp) / 'server.sqlite3').exists())

    def test_initial_admin_token_is_one_time_and_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = self.run_cli('--data-dir', tmp, 'init-admin')
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertIn('cf_', cp.stdout)
            second = self.run_cli('--data-dir', tmp, 'init-admin')
            self.assertNotEqual(second.returncode, 0)
            self.assertIn('active token already exists', second.stderr + second.stdout)

if __name__ == '__main__':
    unittest.main(verbosity=2)

class BoundedHTTPTests(unittest.TestCase):
    def test_server_caps_concurrent_requests_and_returns_503(self):
        import socket
        from http.server import BaseHTTPRequestHandler
        from server import BoundedThreadingHTTPServer
        server = BoundedThreadingHTTPServer(('127.0.0.1', 0), BaseHTTPRequestHandler, max_concurrency=1)
        left, right = socket.socketpair()
        try:
            acquired = [server._capacity.acquire(blocking=False) for _ in range(server.max_concurrency)]
            self.assertTrue(all(acquired))
            server.process_request(left, ('127.0.0.1', 12345))
            response = right.recv(1024)
            self.assertIn(b'503 Service Unavailable', response)
            self.assertIn(b'Retry-After: 2', response)
            for _ in acquired: server._capacity.release()
        finally:
            right.close()
            server.server_close()
