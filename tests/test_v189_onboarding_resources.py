from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import cyberforge as cf
import runtime_diagnostics as rd

class V189Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='cf-v189-')
        self.old=cf.DATA_DIR
        cf.DATA_DIR=Path(self.tmp.name)/'data'
    def tearDown(self):
        cf.DATA_DIR=self.old
        self.tmp.cleanup()
    def test_version_and_resource_profile_are_bounded(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))
        profile=cf.resource_profile()
        self.assertIn(profile['profile'],{'low_memory','balanced','throughput'})
        self.assertGreaterEqual(profile['max_http_workers'],2)
        self.assertLessEqual(profile['max_http_workers'],64)
    def test_report_redacts_common_secret_patterns_and_stores_locally(self):
        result=cf.create_user_bug_report({'title':'Test API key=secret123','category':'ui',
            'description':'Crash after request Authorization: Bearer abcdefghijklmnop',
            'steps':'password=hunter2'})
        self.assertTrue(result['saved'])
        path=Path(result['path']); self.assertTrue(path.is_file())
        data=json.loads(path.read_text(encoding='utf-8'))
        raw=json.dumps(data)
        self.assertNotIn('secret123',raw); self.assertNotIn('abcdefghijklmnop',raw); self.assertNotIn('hunter2',raw)
        self.assertIn('[REDACTED]',raw)
    def test_report_requires_description(self):
        with self.assertRaises(ValueError): cf.create_user_bug_report({'description':' '})
    def test_low_memory_profile_and_worker_override(self):
        with patch.dict('os.environ', {'CYBERFORGE_PROFILE':'low_memory','CYBERFORGE_MAX_WORKERS':'3'}):
            profile=cf.resource_profile()
        self.assertEqual(profile['profile'],'low_memory')
        self.assertEqual(profile['max_http_workers'],3)
    def test_report_can_omit_environment_when_user_unchecks_it(self):
        result=cf.create_user_bug_report({'description':'UI issue','include_environment':False})
        self.assertEqual(result['report']['environment'],{})
    def test_support_report_http_endpoint(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),cf.Handler)
        server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            payload=json.dumps({'title':'HTTP report','description':'Button is unresponsive','category':'ui'}).encode()
            request=Request(f'http://127.0.0.1:{server.server_port}/api/support/report',data=payload,
                            headers={'Content-Type':'application/json'},method='POST')
            with urlopen(request,timeout=10) as response: data=json.loads(response.read())
            self.assertTrue(data['saved']); self.assertTrue(Path(data['path']).is_file())
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
    def test_gpu_probe_is_best_effort(self):
        result=rd.gpu_inventory()
        self.assertIn(result['status'],{'detected','no_vendor_cli_detected'})
        self.assertIn('detected_tools',result)
    def test_http_server_has_worker_cap(self):
        from http.server import BaseHTTPRequestHandler
        server=cf.BoundedThreadingHTTPServer(('127.0.0.1',0),BaseHTTPRequestHandler,max_workers=1000)
        try: self.assertEqual(server.max_workers,64)
        finally: server.server_close()
    def test_help_pages_and_bug_report_ui_exist(self):
        html=(ROOT/'static/index.html').read_text(encoding='utf-8')
        for page in ('about','helpcenter','support'):
            self.assertIn(f'id="{page}"',html)
        self.assertIn('submitBugReport()',html)
        self.assertIn('data-page="helpcenter"',html)

if __name__=='__main__': unittest.main(verbosity=2)
