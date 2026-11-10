import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class CoreTests(unittest.TestCase):
    def test_validate_host_ip(self):
        self.assertEqual(cf.validate_host('127.0.0.1'), '127.0.0.1')

    def test_validate_host_rejects_url(self):
        with self.assertRaises(ValueError):
            cf.validate_host('https://example.com/path')

    def test_scan_requires_authorization(self):
        with self.assertRaises(PermissionError):
            cf.tcp_scan('127.0.0.1', [80], False)

    def test_scan_rejects_unlisted_port(self):
        with self.assertRaises(ValueError):
            cf.tcp_scan('127.0.0.1', [4444], True)

    def test_file_analysis_hash_and_signature(self):
        data = b'MZ' + b'\x00' * 100
        report = cf.analyze_file_bytes(data, 'test.exe')
        self.assertEqual(report['sha256'], __import__('hashlib').sha256(data).hexdigest())
        self.assertIn('PE', report['kind'])

    def test_file_analysis_limit(self):
        with self.assertRaises(ValueError):
            cf.analyze_file_bytes(b'x' * (cf.MAX_BODY + 1))

    def test_dev_json_pretty(self):
        result = cf.dev_tool('json-pretty', '{"a":1}')['result']
        self.assertEqual(json.loads(result), {'a': 1})

    def test_jwt_decode_does_not_verify(self):
        h = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip('=')
        p = base64.urlsafe_b64encode(b'{"sub":"demo"}').decode().rstrip('=')
        out = cf.dev_tool('jwt-decode', h + '.' + p + '.')
        self.assertEqual(out['payload']['sub'], 'demo')
        self.assertIn('warning', out)

    def test_code_review_flags_eval(self):
        out = cf.code_review('x = eval(user_input)')
        self.assertTrue(any(x['title'] == 'Dynamic code execution' for x in out['findings']))

    def test_log_triage_extracts_hash(self):
        h = 'a' * 64
        out = cf.log_triage('ERROR request from 192.168.1.5 hash=' + h)
        self.assertIn(h, out['iocs']['hashes'])


if __name__ == '__main__':
    unittest.main()
