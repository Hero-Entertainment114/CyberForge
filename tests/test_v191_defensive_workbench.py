from __future__ import annotations
import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf
import v191_modules as v


class V191ModuleTests(unittest.TestCase):
    def test_01_capabilities_are_honest_and_local(self):
        cap = v.capabilities()
        self.assertFalse(cap['web_posture']['network_io'])
        self.assertFalse(cap['sandbox']['executes_samples'])
        self.assertFalse(cap['privacy']['guarantees_anonymity'])
        self.assertFalse(cap['defense_lab']['network_io'])

    def test_02_python_review_reports_line_cwe_and_secret_redaction(self):
        source = "API_KEY = 'do-not-print-this-secret'\nimport os\nos.system(user_input)\neval(user_value)"
        result = v.secure_code_review(source, 'python')
        rules = {x['rule'] for x in result['findings']}
        self.assertTrue({'hardcoded-secret', 'shell-command', 'dynamic-evaluation'} <= rules)
        self.assertNotIn('do-not-print-this-secret', json.dumps(result))
        self.assertTrue(all('cwe' in f and f['line'] > 0 and f['recommendation'] for f in result['findings']))

    def test_03_python_review_detects_unsafe_deserialization_and_tls(self):
        src = "import pickle\nimport requests\npickle.loads(blob)\nrequests.get(url, verify=False)"
        rules = {x['rule'] for x in v.secure_code_review(src, 'python')['findings']}
        self.assertIn('unsafe-deserialization', rules)
        self.assertIn('tls-verification-disabled', rules)

    def test_04_safe_yaml_loader_is_not_flagged_as_unsafe_deserialization(self):
        rules = {x['rule'] for x in v.secure_code_review("import yaml\nyaml.load(data, Loader=yaml.SafeLoader)", 'python')['findings']}
        self.assertNotIn('unsafe-deserialization', rules)

    def test_05_javascript_review_detects_dom_sink_and_dynamic_eval(self):
        src = "element.innerHTML = userInput;\neval(location.hash);\nconst x = new Function(code);"
        rules = {x['rule'] for x in v.secure_code_review(src, 'javascript')['findings']}
        self.assertIn('unsafe-dom-sink', rules)
        self.assertIn('dynamic-evaluation', rules)

    def test_05_shell_review_detects_remote_pipe_to_shell(self):
        src = "curl https://example.invalid/install.sh | bash"
        rules = {x['rule'] for x in v.secure_code_review(src, 'shell')['findings']}
        self.assertIn('remote-script-pipe', rules)

    def test_06_review_limits_and_language_are_enforced(self):
        with self.assertRaises(ValueError): v.secure_code_review('x' * 100_001)
        with self.assertRaises(ValueError): v.secure_code_review('print(1)', 'brainfuck')

    def test_07_web_review_checks_csp_cors_and_cookie_flags(self):
        result = v.web_posture_review(
            {'content-security-policy': "default-src * 'unsafe-inline'",
             'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true'},
            ['session=do-not-leak-this; Path=/'])
        rules = {x['rule'] for x in result['findings']}
        self.assertIn('csp-wildcard', rules)
        self.assertIn('csp-unsafe-source', rules)
        self.assertIn('cors-wildcard-credentials', rules)
        self.assertIn('cookie-secure', rules)
        self.assertNotIn('do-not-leak-this', json.dumps(result))

    def test_08_web_review_detects_hsts_and_accepts_secure_cookie(self):
        result = v.web_posture_review(
            {'strict-transport-security': 'max-age=31536000; includeSubDomains',
             'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
             'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin',
             'permissions-policy': 'camera=()', 'x-frame-options': 'DENY'},
            ['session=redacted; Secure; HttpOnly; SameSite=Lax'])
        rules = {x['rule'] for x in result['findings']}
        self.assertNotIn('hsts-missing', rules)
        self.assertNotIn('cookie-secure', rules)
        self.assertNotIn('cookie-httponly', rules)
        self.assertNotIn('cookie-samesite', rules)

    def test_09_header_and_cookie_bounds(self):
        with self.assertRaises(ValueError): v.web_posture_review({str(i): 'x' for i in range(121)})
        with self.assertRaises(ValueError): v.web_posture_review({}, ['x'] * 41)

    def test_10_defense_simulation_has_no_network_and_bounds_work(self):
        result = v.simulate_defense_scenario(legitimate_rps=60, agents=20,
            events_per_agent_rps=25, capacity_rps=500, duration_seconds=10,
            rate_limit_per_agent=4, cache_percent=20, queue_limit=1000, challenge_filter_percent=10)
        self.assertFalse(result['network_io'])
        self.assertEqual(result['totals']['bot_in'], 5000)
        self.assertGreater(result['totals']['bot_rate_limited'], 0)
        self.assertGreaterEqual(result['estimated_legitimate_availability'], 0)
        self.assertLessEqual(result['estimated_legitimate_availability'], 1)

    def test_11_defense_rate_limit_improves_legitimate_availability_in_saturation(self):
        baseline = v.simulate_defense_scenario(legitimate_rps=80, agents=50,
            events_per_agent_rps=50, capacity_rps=500, duration_seconds=15,
            rate_limit_per_agent=1000, cache_percent=0, queue_limit=1000)
        protected = v.simulate_defense_scenario(legitimate_rps=80, agents=50,
            events_per_agent_rps=50, capacity_rps=500, duration_seconds=15,
            rate_limit_per_agent=2, cache_percent=0, queue_limit=1000)
        self.assertGreaterEqual(protected['estimated_legitimate_availability'], baseline['estimated_legitimate_availability'])
        self.assertGreater(protected['totals']['bot_rate_limited'], baseline['totals']['bot_rate_limited'])

    def test_12_defense_simulation_rejects_unbounded_or_wrong_types(self):
        with self.assertRaises(ValueError): v.simulate_defense_scenario(agents=201)
        with self.assertRaises(ValueError): v.simulate_defense_scenario(duration_seconds=121)
        with self.assertRaises(ValueError): v.simulate_defense_scenario(agents=True)

    def test_13_privacy_audit_uses_only_supplied_hints(self):
        result = v.privacy_posture_audit('Mozilla/5.0 (Windows NT 10.0) Chrome/120',
            {'via': 'proxy', 'accept-language': 'vi-VN'},
            {'timezone': 'Asia/Ho_Chi_Minh', 'screen': '1920x1080', 'platform': 'Win32'})
        self.assertFalse(result['network_io'])
        self.assertTrue(result['provided_hint_categories'])
        self.assertGreaterEqual(result['signal_count'], 3)
        self.assertIn('Không có chế độ', result['guarantee'])

    def test_14_static_sandbox_never_executes_and_reports_context(self):
        result = v.static_sandbox_triage("import os\nos.system('whoami')\n# DownloadString and RunOnce", 'python')
        self.assertFalse(result['executed'])
        self.assertIn('shell-command', {x['rule'] for x in result['findings']})
        self.assertTrue(result['sample_indicators'])

    def test_15_static_sandbox_accepts_powershell_and_php_as_generic_static_text(self):
        for language, sample in [('powershell', 'Invoke-WebRequest -Uri https://example.invalid'), ('php', '<?php system($_GET["cmd"]);')]:
            result = v.static_sandbox_triage(sample, language)
            self.assertFalse(result['executed'])
            self.assertEqual(result['language'], language)

    def test_16_static_sandbox_rejects_oversized_source(self):
        with self.assertRaises(ValueError): v.static_sandbox_triage('x' * 50_001, 'python')


class V191APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cf-v191-api-')
        self.old_paths = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        base = Path(self.temp.name) / 'data'
        cf.DATA_DIR = base
        cf.DB_PATH = base / 'cyberforge.db'
        cf.EVIDENCE_DIR = base / 'evidence'
        cf.init_database()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), cf.Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old_paths
        self.temp.cleanup()

    def post(self, path, payload):
        payload['_permission_acknowledged'] = ['static_analysis']
        request = Request(self.base + '/api/' + path, data=json.dumps(payload).encode(),
                          headers={'Content-Type': 'application/json'}, method='POST')
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read())

    def test_16_capabilities_endpoint(self):
        with urlopen(self.base + '/api/v191/capabilities', timeout=10) as response:
            result = json.loads(response.read())
        self.assertEqual(result['version'], '1.9.1')
        self.assertFalse(result['defense_lab']['network_io'])

    def test_17_review_endpoint(self):
        result = self.post('v191/ai/review', {'source': 'eval(user_input)', 'language': 'python'})
        self.assertIn('dynamic-evaluation', {x['rule'] for x in result['findings']})

    def test_18_defense_endpoint(self):
        result = self.post('v191/lab/defense', {'legitimate_rps': 10, 'agents': 2,
            'events_per_agent_rps': 5, 'capacity_rps': 100, 'duration_seconds': 2})
        self.assertFalse(result['network_io'])
        self.assertEqual(result['totals']['bot_in'], 20)

    def test_19_web_endpoint_does_not_echo_cookie_value(self):
        result = self.post('v191/web/posture', {'headers': {}, 'cookies': ['sid=super-secret-session-value']})
        self.assertNotIn('super-secret-session-value', json.dumps(result))

    def test_20_sandbox_endpoint_is_static(self):
        result = self.post('v191/sandbox/triage', {'source': 'eval(x)', 'language': 'python'})
        self.assertFalse(result['executed'])

    def test_21_v190_capabilities_remain_available(self):
        with urlopen(self.base + '/api/v190/capabilities', timeout=10) as response:
            result = json.loads(response.read())
        self.assertEqual(result['version'], '1.9.0')
        self.assertFalse(result['traffic_lab']['network_io'])

    def test_22_v190_capacity_api_remains_compatible(self):
        result = self.post('v190/lab/capacity', {'requests': 1000, 'capacity_rps': 100,
            'duration_seconds': 10, 'legitimate_rate': 20})
        self.assertFalse(result['network_io'])
        self.assertEqual(result['offered_rps'], 100)


if __name__ == '__main__':
    unittest.main(verbosity=2)
