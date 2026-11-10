from __future__ import annotations
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

import integrations
from server import create_handler, is_allowed_bind_address, is_trusted_proxy_client
from server_core import AIService, Store, host_inventory, run_workflow, validate_node_payload, VERSION
from agent.agent import send_report


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        self.store = Store(self.data / 'server.sqlite3')

    def tearDown(self):
        self.tmp.cleanup()

    def test_version(self):
        self.assertEqual(VERSION, '2.1.0')

    def test_private_bind_requires_explicit_opt_in(self):
        self.assertTrue(is_allowed_bind_address('127.0.0.1'))
        self.assertFalse(is_allowed_bind_address('192.168.10.5'))
        self.assertTrue(is_allowed_bind_address('192.168.10.5', allow_private=True))
        self.assertFalse(is_allowed_bind_address('8.8.8.8', allow_private=True))
        self.assertFalse(is_allowed_bind_address('0.0.0.0', allow_private=True))
        self.assertFalse(is_allowed_bind_address('example.internal', allow_private=True))

    def test_remote_proxy_requires_explicit_cidr_allowlist(self):
        with patch.dict(os.environ, {'CF_SERVER_TRUST_PROXY': '1', 'CF_SERVER_TRUST_PROXY_CIDRS': '10.20.0.0/24'}):
            self.assertTrue(is_trusted_proxy_client('10.20.0.5'))
            self.assertTrue(is_trusted_proxy_client('::ffff:10.20.0.5'))
            self.assertFalse(is_trusted_proxy_client('10.21.0.5'))
            self.assertTrue(is_trusted_proxy_client('127.0.0.1'))
        with patch.dict(os.environ, {'CF_SERVER_TRUST_PROXY': '1', 'CF_SERVER_TRUST_PROXY_CIDRS': ''}):
            self.assertFalse(is_trusted_proxy_client('10.20.0.5'))
        with patch.dict(os.environ, {'CF_SERVER_TRUST_PROXY': '1', 'CF_SERVER_TRUST_PROXY_CIDRS': 'not-a-cidr'}):
            self.assertFalse(is_trusted_proxy_client('10.20.0.5'))

    def test_data_directory_created(self):
        self.assertTrue((self.data / 'server.sqlite3').exists())

    def test_admin_token_created_once_and_hashed(self):
        token = self.store.create_token('root', 'admin')
        self.assertTrue(token['token'].startswith('cf_'))
        with self.store.connect() as con:
            row = con.execute('select token_hash from api_tokens').fetchone()
        self.assertNotEqual(row['token_hash'], token['token'])

    def test_token_authentication(self):
        x = self.store.create_token('op', 'operator')
        actor = self.store.authenticate(x['token'])
        self.assertEqual(actor['role'], 'operator')
        self.assertIsNone(self.store.authenticate('invalid'))

    def test_scope_enforcement(self):
        x = self.store.create_token('viewer', 'viewer')
        actor = self.store.authenticate(x['token'])
        self.assertTrue(Store.has_scope(actor, 'fleet:read'))
        self.assertFalse(Store.has_scope(actor, 'ai:invoke'))

    def test_invalid_role_rejected(self):
        with self.assertRaises(ValueError):
            self.store.create_token('x', 'root')

    def test_host_inventory_is_read_only_shaped(self):
        inv = host_inventory(self.data)
        for key in ('hostname', 'platform', 'kernel', 'cpu_logical_cores', 'memory_total_bytes', 'disk_total_bytes', 'gpu_tooling'):
            self.assertIn(key, inv)

    def test_integration_catalog_stable_and_contains_commercial(self):
        ids = [x['id'] for x in integrations.INTEGRATIONS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn('crowdstrike', ids)
        self.assertIn('datadog', ids)
        self.assertIn('vllm', ids)
        self.assertGreater(len(ids), 30)

    def test_integration_inventory_does_not_execute_binaries(self):
        with patch('integrations.shutil.which', return_value=None) as which:
            out = integrations.inventory()
        self.assertGreater(len(out), 20)
        which.assert_called()

    def test_node_create_and_status_pending(self):
        n = self.store.create_node('worker-1', {'env': 'lab'})
        nodes = self.store.list_nodes()
        self.assertEqual(nodes[0]['node_id'], n['node_id'])
        self.assertEqual(nodes[0]['status'], 'pending')

    def test_node_report_accepted(self):
        n = self.store.create_node('worker-1')
        payload = {'hostname': 'worker-1', 'platform': 'Linux', 'cpu_logical_cores': 4,
                   'memory_total_bytes': 4096, 'memory_available_bytes': 1024, 'disk_total_bytes': 8192,
                   'disk_free_bytes': 2048, 'load_average': [0.1, 0.2, 0.3], 'services': {'ssh': 'active'}}
        self.store.accept_node_report(n['node_id'], n['token'], int(time.time()), 'nonce_a1', payload)
        node = self.store.list_nodes()[0]
        self.assertEqual(node['status'], 'online')
        self.assertEqual(node['metrics']['hostname'], 'worker-1')

    def test_node_report_replay_rejected(self):
        n = self.store.create_node('worker-1')
        payload = {'hostname': 'worker-1'}
        ts = int(time.time())
        self.store.accept_node_report(n['node_id'], n['token'], ts, 'same_nonce', payload)
        with self.assertRaises(PermissionError):
            self.store.accept_node_report(n['node_id'], n['token'], ts, 'same_nonce', payload)

    def test_node_timestamp_window(self):
        n = self.store.create_node('worker-1')
        with self.assertRaises(ValueError):
            self.store.accept_node_report(n['node_id'], n['token'], 1, 'nonce_old', {})

    def test_node_bad_token_rejected(self):
        n = self.store.create_node('worker-1')
        with self.assertRaises(PermissionError):
            self.store.accept_node_report(n['node_id'], 'wrong', int(time.time()), 'nonce', {})

    def test_node_payload_strips_unknown(self):
        v = validate_node_payload({'hostname': 'host', 'arbitrary_command': 'rm -rf /'})
        self.assertNotIn('arbitrary_command', v)

    def test_node_payload_rejects_large_metrics(self):
        with self.assertRaises(ValueError):
            validate_node_payload({'cpu_logical_cores': -10})

    def test_node_revocation(self):
        n = self.store.create_node('worker-1')
        self.assertTrue(self.store.revoke_node(n['node_id'], 'admin'))
        self.assertEqual(self.store.list_nodes()[0]['status'], 'revoked')

    def test_workflow_allowlist(self):
        with self.assertRaises(ValueError):
            self.store.add_workflow('bad', ['run_shell'], 'admin')

    def test_workflow_expiry(self):
        wid = self.store.add_workflow('check', ['check_integrations'], 'admin')
        with self.store.connect() as con:
            con.execute('update workflows set expires_at=? where workflow_id=?', (int(time.time()) - 1, wid))
        with self.assertRaises(TimeoutError):
            self.store.approve_workflow(wid, 'operator')
        row = next(x for x in self.store.list_workflows() if x['workflow_id'] == wid)
        self.assertEqual(row['status'], 'expired')

    def test_v201_workflow_schema_migrates_execution_lease_columns(self):
        legacy = self.data / 'legacy-v201.sqlite3'
        con = sqlite3.connect(legacy)
        con.execute("CREATE TABLE workflows(workflow_id TEXT PRIMARY KEY,title TEXT NOT NULL,steps_json TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,expires_at INTEGER NOT NULL,status TEXT NOT NULL,approved_by TEXT,approved_at TEXT,result_json TEXT)")
        con.commit(); con.close()
        migrated = Store(legacy)
        with migrated.connect() as db:
            cols = {row['name'] for row in db.execute('PRAGMA table_info(workflows)').fetchall()}
            index = {row['name'] for row in db.execute('PRAGMA index_list(workflows)').fetchall()}
        self.assertIn('execution_owner', cols)
        self.assertIn('execution_lease_until', cols)
        self.assertIn('idx_workflows_execution_lease', index)

    def test_workflow_concurrent_approval_has_one_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        wid = self.store.add_workflow('approve-race', ['check_integrations'], 'admin')
        barrier = threading.Barrier(2)
        def approve(actor):
            barrier.wait(timeout=2)
            try:
                self.store.approve_workflow(wid, actor)
                return 'approved'
            except ValueError:
                return 'rejected'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(approve, ['operator-a', 'operator-b']))
        self.assertEqual(results.count('approved'), 1)
        self.assertEqual(results.count('rejected'), 1)

    def test_workflow_two_person_setting(self):
        wid = self.store.add_workflow('check', ['check_integrations'], 'alice')
        with patch.dict(os.environ, {'CF_WORKFLOW_REQUIRE_TWO_PERSON': '1'}):
            with self.assertRaises(PermissionError):
                self.store.approve_workflow(wid, 'alice')
            self.store.approve_workflow(wid, 'bob')

    def test_workflow_requires_approval(self):
        wid = self.store.add_workflow('check', ['check_integrations'], 'admin')
        with self.assertRaises(ValueError):
            run_workflow(self.store, wid, 'admin', self.data)

    def test_workflow_execution_and_backup(self):
        wid = self.store.add_workflow('backup', ['check_integrations', 'backup_database', 'verify_audit_chain'], 'admin')
        self.store.approve_workflow(wid, 'operator')
        result = run_workflow(self.store, wid, 'operator', self.data)
        self.assertEqual(len(result['steps']), 3)
        self.assertTrue(Path(result['steps'][1]['result']['path']).exists())

    def test_workflow_execution_claim_is_atomic_and_owner_bound(self):
        wid = self.store.add_workflow('claim', ['check_integrations'], 'admin')
        self.store.approve_workflow(wid, 'operator')
        owner = self.store.claim_workflow(wid, 'operator')
        with self.assertRaisesRegex(ValueError, 'workflow_already_executing'):
            self.store.claim_workflow(wid, 'second-instance')
        self.assertTrue(self.store.renew_workflow(wid, owner))
        with self.assertRaisesRegex(ValueError, 'workflow_execution_lease_lost'):
            self.store.finish_workflow(wid, 'operator', {'steps': []}, owner='wrong-owner')
        self.store.finish_workflow(wid, 'operator', {'steps': []}, owner=owner)
        row = next(x for x in self.store.list_workflows() if x['workflow_id'] == wid)
        self.assertEqual(row['status'], 'completed')

    def test_workflow_expired_execution_lease_can_be_reclaimed(self):
        wid = self.store.add_workflow('lease-reclaim', ['check_integrations'], 'admin')
        self.store.approve_workflow(wid, 'operator')
        first = self.store.claim_workflow(wid, 'operator')
        with self.store.connect() as con:
            con.execute('UPDATE workflows SET execution_lease_until=? WHERE workflow_id=?', (int(time.time()) - 1, wid))
        second = self.store.claim_workflow(wid, 'recovery-instance')
        self.assertNotEqual(first, second)
        self.assertFalse(self.store.fail_workflow(wid, 'operator', {'failed_step': 'x'}, first))
        self.assertTrue(self.store.fail_workflow(wid, 'recovery-instance', {'failed_step': 'check_integrations'}, second))
        row = next(x for x in self.store.list_workflows() if x['workflow_id'] == wid)
        self.assertEqual(row['status'], 'failed')

    def test_workflow_failure_persists_partial_result(self):
        import server_core
        wid = self.store.add_workflow('failure', ['check_ai_runtimes'], 'admin')
        self.store.approve_workflow(wid, 'operator')
        with patch('server_core.runtime_inventory', side_effect=RuntimeError('private provider detail')):
            with self.assertRaises(RuntimeError):
                run_workflow(self.store, wid, 'operator', self.data)
        row = next(x for x in self.store.list_workflows() if x['workflow_id'] == wid)
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(row['result']['failed_step'], 'check_ai_runtimes')
        self.assertNotIn('private provider detail', json.dumps(row['result']))

    def test_audit_chain_valid(self):
        self.store.create_token('admin', 'admin')
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_audit_chain_detects_tamper(self):
        self.store.create_token('admin', 'admin')
        with self.store.connect() as con:
            con.execute("update audit set action='tampered' where seq=1")
        self.assertFalse(self.store.verify_audit()['valid'])

    def test_ai_status_never_returns_api_key(self):
        with patch.dict(os.environ, {'CF_AI_API_KEY': 'super-secret', 'CF_AI_MODEL': 'test-model'}, clear=False):
            status = AIService(self.store).status()
        self.assertTrue(status['api_key_configured'])
        self.assertNotIn('super-secret', json.dumps(status))


    def test_ai_budget_reservation_is_atomic_across_threads(self):
        from concurrent.futures import ThreadPoolExecutor
        barrier = threading.Barrier(2)
        def reserve():
            barrier.wait(timeout=2)
            return self.store.reserve_ai_usage('actor', 'paid-model', 4.0, 5.0)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: reserve(), range(2)))
        self.assertEqual(sum(bool(x) for x in results), 1)
        self.assertLessEqual(self.store.ai_spend_today('paid-model'), 5.0)


    def test_stale_ai_reservation_is_expired(self):
        rid = self.store.reserve_ai_usage('actor', 'paid-model', 4.0, 5.0)
        self.assertTrue(rid)
        with self.store.connect() as con:
            con.execute("UPDATE ai_usage SET created_at='2000-01-01T00:00:00+00:00' WHERE request_id=?", (rid,))
        self.assertAlmostEqual(self.store.ai_spend_today('paid-model'), 0.0)
        with self.store.connect() as con:
            row = con.execute('select status from ai_usage where request_id=?', (rid,)).fetchone()
        self.assertEqual(row['status'], 'reservation_expired')

    def test_ai_budget_reservation_is_replaced_by_actual_usage(self):
        rid = self.store.reserve_ai_usage('actor', 'paid-model', 0.20, 1.0)
        self.assertTrue(rid)
        self.assertAlmostEqual(self.store.ai_spend_today('paid-model'), 0.20)
        self.store.finish_ai_usage(rid, 100, 50, 0.12, 'success')
        self.assertAlmostEqual(self.store.ai_spend_today('paid-model'), 0.12)
        with self.store.connect() as con:
            row = con.execute('select status,input_tokens,output_tokens from ai_usage where request_id=?', (rid,)).fetchone()
        self.assertEqual(row['status'], 'success')
        self.assertEqual(row['input_tokens'], 100)

    def test_ai_not_configured_refuses_chat(self):
        with patch.dict(os.environ, {'CF_AI_MODEL': ''}, clear=False):
            with self.assertRaises(RuntimeError):
                AIService(self.store).chat('admin', {'messages': [{'role': 'user', 'content': 'hi'}]})

    def test_paid_ai_requires_explicit_enablement_before_network(self):
        env = {'CF_AI_MODEL': 'paid-model', 'CF_AI_BILLING_MODE': 'paid', 'CF_AI_ALLOW_PAID': '0',
               'CF_AI_API_KEY': 'secret', 'CF_AI_DAILY_BUDGET_USD': '10', 'CF_AI_MAX_REQUEST_USD': '1',
               'CF_AI_INPUT_PRICE_PER_1M': '1', 'CF_AI_OUTPUT_PRICE_PER_1M': '2',
               'CF_AI_BASE_URL': 'https://api.example.test/v1', 'CF_AI_ALLOWED_HOSTS': 'api.example.test'}
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(PermissionError):
                AIService(self.store).chat('admin', {'messages': [{'role': 'user', 'content': 'hello'}]})

    def test_remote_ai_host_must_be_allowlisted(self):
        env = {'CF_AI_MODEL': 'x', 'CF_AI_BILLING_MODE': 'free', 'CF_AI_BASE_URL': 'https://untrusted.example/v1',
               'CF_AI_ALLOWED_HOSTS': ''}
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(PermissionError):
                AIService(self.store).chat('admin', {'messages': [{'role': 'user', 'content': 'hello'}]})

    def test_remote_ai_requires_https(self):
        env = {'CF_AI_MODEL': 'x', 'CF_AI_BILLING_MODE': 'free', 'CF_AI_BASE_URL': 'http://model.example/v1',
               'CF_AI_ALLOWED_HOSTS': 'model.example'}
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(PermissionError):
                AIService(self.store).chat('admin', {'messages': [{'role': 'user', 'content': 'hello'}]})

    def test_prompt_limit(self):
        with patch.dict(os.environ, {'CF_AI_MODEL': 'x'}, clear=False):
            with self.assertRaises(ValueError):
                AIService(self.store).chat('admin', {'messages': [{'role': 'user', 'content': 'x' * 61000}]})


    def test_multiple_ai_deployment_catalog(self):
        raw = json.dumps([
            {"id": "local-a", "model": "model-a", "base_url": "http://127.0.0.1:11434/v1", "billing_mode": "local"},
            {"id": "local-b", "model": "model-b", "base_url": "http://localhost:9000/v1", "billing_mode": "free"}
        ])
        with patch.dict(os.environ, {"CF_AI_DEPLOYMENTS_JSON": raw, "CF_AI_DEFAULT_DEPLOYMENT": "local-b"}, clear=False):
            status = AIService(self.store).status()
        self.assertEqual(len(status["deployments"]), 2)
        self.assertEqual(status["default_deployment"], "local-b")

    def test_multiple_ai_deployments_reject_duplicate_ids(self):
        raw = json.dumps([
            {"id": "same", "model": "a", "base_url": "http://127.0.0.1:1/v1"},
            {"id": "same", "model": "b", "base_url": "http://127.0.0.1:2/v1"}
        ])
        with patch.dict(os.environ, {"CF_AI_DEPLOYMENTS_JSON": raw}, clear=False):
            with self.assertRaises(ValueError):
                AIService(self.store).status()

    def test_ai_openai_compatible_chat_round_trip(self):
        class MockHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                request = json.loads(self.rfile.read(length).decode())
                assert request['model'] == 'mock-local-model'
                payload = json.dumps({"choices": [{"message": {"content": "mock response"}}],
                                      "usage": {"prompt_tokens": 8, "completion_tokens": 3}}).encode()
                self.send_response(200); self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload))); self.end_headers(); self.wfile.write(payload)
            def log_message(self, *args):
                pass
        httpd = ThreadingHTTPServer(('127.0.0.1', 0), MockHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True); thread.start()
        try:
            env = {"CF_AI_DEPLOYMENTS_JSON": json.dumps([{"id": "mock", "model": "mock-local-model",
                   "base_url": f"http://127.0.0.1:{httpd.server_port}/v1", "billing_mode": "local"}]),
                   "CF_AI_DEFAULT_DEPLOYMENT": "mock"}
            with patch.dict(os.environ, env, clear=False):
                result = AIService(self.store).chat('tester', {"messages": [{"role": "user", "content": "hello"}]})
            self.assertEqual(result['answer'], 'mock response')
            self.assertEqual(result['deployment_id'], 'mock')
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)

    def test_agent_reports_to_loopback_server(self):
        node = self.store.create_node('agent-node')
        handler = __import__('server').create_handler(self.store, AIService(self.store), self.data)
        httpd = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True); thread.start()
        env = {"CF_SERVER_URL": f"http://127.0.0.1:{httpd.server_port}", "CF_NODE_ID": node['node_id'],
               "CF_NODE_TOKEN": node['token']}
        try:
            with patch.dict(os.environ, env, clear=False):
                result = send_report()
            self.assertTrue(result['ok'])
            self.assertEqual(self.store.list_nodes()[0]['status'], 'online')
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = Path(cls.tmp.name)
        cls.store = Store(cls.data / 'server.sqlite3')
        cls.admin = cls.store.create_token('test-admin', 'admin')['token']
        cls.viewer = cls.store.create_token('test-viewer', 'viewer')['token']
        cls.operator = cls.store.create_token('test-operator', 'operator')['token']
        cls.ai = AIService(cls.store)
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), create_handler(cls.store, cls.ai, cls.data))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.httpd.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=3); cls.tmp.cleanup()

    def req(self, path, method='GET', token=None, body=None, headers=None):
        data = json.dumps(body or {}).encode() if method == 'POST' else None
        h = {'Content-Type': 'application/json', **(headers or {})}
        if token: h['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(request, timeout=4) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if 'json' in r.headers.get('Content-Type', '') else raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            return e.code, (json.loads(raw) if 'json' in e.headers.get('Content-Type', '') else raw)

    def test_health_public(self):
        status, body = self.req('/api/v200/health')
        self.assertEqual(status, 200); self.assertEqual(body['version'], '2.1.0')

    def test_overview_requires_auth(self):
        status, _ = self.req('/api/v200/overview')
        self.assertEqual(status, 401)

    def test_overview_admin(self):
        status, body = self.req('/api/v200/overview', token=self.admin)
        self.assertEqual(status, 200); self.assertIn('fleet', body)

    def test_host_header_allowlist(self):
        status, body = self.req('/api/v200/health', headers={'Host': 'attacker.example'})
        self.assertEqual(status, 421)
        self.assertEqual(body['error']['code'], 'invalid_host_header')

    def test_node_enrollment_admin_only(self):
        status, body = self.req('/api/v200/nodes/enroll', 'POST', self.admin, {'name': 'api-node'})
        self.assertEqual(status, 201); self.assertIn('token', body)
        status, _ = self.req('/api/v200/nodes/enroll', 'POST', self.viewer, {'name': 'blocked'})
        self.assertEqual(status, 403)

    def test_metrics_scope(self):
        status, body = self.req('/metrics', token=self.operator)
        self.assertEqual(status, 200)
        self.assertIn('cyberforge_nodes_total', body)

    def test_workflow_api_plan_approve_execute(self):
        status, plan = self.req('/api/v200/workflows/plan', 'POST', self.operator,
                               {'title': 'API health check', 'steps': ['check_integrations', 'verify_audit_chain']})
        self.assertEqual(status, 201)
        wid = plan['workflow_id']
        status, _ = self.req(f'/api/v200/workflows/{wid}/approve', 'POST', self.operator)
        self.assertEqual(status, 200)
        status, done = self.req(f'/api/v200/workflows/{wid}/execute', 'POST', self.operator)
        self.assertEqual(status, 200); self.assertEqual(len(done['result']['steps']), 2)

    def test_ai_route_requires_ai_scope(self):
        status, _ = self.req('/api/v200/ai/chat', 'POST', self.viewer,
                             {'messages': [{'role': 'user', 'content': 'hello'}]})
        self.assertEqual(status, 403)

    def test_localization_vi_error(self):
        status, body = self.req('/api/v200/overview', headers={'Accept-Language': 'vi'})
        self.assertEqual(status, 401)
        self.assertIn('Yêu cầu', body['error']['message'])

    def test_dashboard_served(self):
        request = urllib.request.Request(self.base + '/')
        with urllib.request.urlopen(request, timeout=4) as response:
            html = response.read().decode()
        self.assertIn('Server Control Plane', html)
        self.assertIn('AI Platform', html)
        self.assertIn('Workflow Engine', html)


if __name__ == '__main__':
    unittest.main(verbosity=2)
