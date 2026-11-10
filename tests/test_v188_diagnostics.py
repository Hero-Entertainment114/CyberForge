from __future__ import annotations
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import cyberforge as cf
import runtime_diagnostics as rd

class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='cf-v188-test-')
        self.old=(cf.DATA_DIR,cf.DB_PATH,cf.EVIDENCE_DIR,cf.PORT)
        base=Path(self.temp.name)
        cf.DATA_DIR=base/'data'; cf.DB_PATH=cf.DATA_DIR/'cyberforge.db'; cf.EVIDENCE_DIR=cf.DATA_DIR/'evidence'
        cf.init_database()
    def tearDown(self):
        cf.DATA_DIR,cf.DB_PATH,cf.EVIDENCE_DIR,cf.PORT=self.old
        self.temp.cleanup()
    def test_01_compatibility_report_has_host_and_tool_groups(self):
        report=cf.compatibility_diagnostics_report()
        self.assertEqual(report['schema'],rd.DIAGNOSTICS_SCHEMA)
        self.assertIn('host',report); self.assertIn('python',report['runtime_groups'])
        self.assertIn('python',report['lsp_groups']); self.assertIn('sast_and_secrets',report['scanner_groups'])
        self.assertIn('containers',report['sandbox_groups'])
        self.assertTrue(any(x['component']=='SQLite' for x in report['checks']))
        self.assertTrue(any(x['component']=='Python runtime' for x in report['version_compatibility']))
        self.assertIn('sandbox_runtime_probe',report)
    def test_02_frontend_profile_detects_unique_ids_and_size(self):
        report=rd.frontend_report(ROOT/'static'/'index.html')
        self.assertEqual(report['status'],'ok')
        self.assertEqual(report['duplicate_ids'],[])
        self.assertGreater(report['inline_script_bytes'],10000)
    def test_03_performance_report_reads_sqlite_wal_and_frontend(self):
        report=cf.performance_diagnostics_report()
        self.assertTrue(report['sqlite']['exists'])
        self.assertEqual(report['sqlite']['quick_check'],'ok')
        self.assertIn('frontend',report); self.assertIn('memory_trend',report)
        self.assertIn('query_plans',report['sqlite'])
        self.assertEqual(report['sqlite']['pragmas']['cache_size'],-2048)
        self.assertEqual(report['sqlite']['pragmas']['wal_autocheckpoint'],500)
        self.assertTrue(report['sqlite']['indexed_query_paths'].get('cases_priority_updated'))
    def test_04_sqlite_connection_uses_bounded_tuning(self):
        con=cf._db_connect()
        try:
            self.assertEqual(con.execute('PRAGMA cache_size').fetchone()[0],-2048)
            self.assertEqual(con.execute('PRAGMA temp_store').fetchone()[0],2)
            self.assertEqual(con.execute('PRAGMA wal_autocheckpoint').fetchone()[0],500)
            self.assertEqual(con.execute('PRAGMA journal_mode').fetchone()[0].lower(),'wal')
            indexes={row[1] for row in con.execute('PRAGMA index_list(findings)')}
            self.assertIn('idx_findings_case_severity_updated',indexes)
            cases_indexes={row[1] for row in con.execute('PRAGMA index_list(cases)')}
            self.assertIn('idx_cases_priority_updated',cases_indexes)
        finally: con.close()
    def test_05_sqlite_benchmark_uses_temporary_database_and_index(self):
        result=rd.sqlite_benchmark(250)
        self.assertEqual(result['integrity'],'ok'); self.assertTrue(result['used_index'])
        self.assertIn('temporary',result['database'])
    def test_06_concurrency_stress_completes_all_workers_and_rows(self):
        result=rd.concurrency_stress(4,24)
        self.assertEqual(result['completed_tasks'],24); self.assertEqual(result['database_rows'],24)
        self.assertEqual(result['integrity'],'ok'); self.assertEqual(result['failures'],[])
    def test_07_crash_probe_recovers_commits_and_rolls_back_inflight_write(self):
        result=rd.crash_recovery_probe()
        self.assertTrue(result['passed'],result)
        self.assertTrue(result['uncommitted_transaction_rolled_back'])
    def test_08_http_diagnostics_get_and_gated_post_routes(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),cf.Handler); cf.PORT=server.server_port
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        base=f'http://127.0.0.1:{server.server_port}'
        try:
            with urlopen(base+'/api/diagnostics/compatibility',timeout=10) as response:
                report=json.loads(response.read())
            self.assertEqual(report['schema'],rd.DIAGNOSTICS_SCHEMA)
            request=Request(base+'/api/diagnostics/stress',data=json.dumps({'acknowledged':True,'workers':2,'tasks':8}).encode(),headers={'Content-Type':'application/json'},method='POST')
            with urlopen(request,timeout=15) as response: stress=json.loads(response.read())
            self.assertEqual(stress['completed_tasks'],8)
            request=Request(base+'/api/diagnostics/recovery',data=json.dumps({'acknowledged':True}).encode(),headers={'Content-Type':'application/json'},method='POST')
            with urlopen(request,timeout=15) as response: recovery=json.loads(response.read())
            self.assertTrue(recovery['passed'])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
    def test_09_probe_bounds_prevent_unbounded_work(self):
        stress=rd.concurrency_stress(1,1)
        self.assertGreaterEqual(stress['workers'],2)
        self.assertLessEqual(stress['workers'],16)
        self.assertGreaterEqual(stress['requested_tasks'],2)
        self.assertLessEqual(stress['requested_tasks'],300)
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))

if __name__=='__main__': unittest.main(verbosity=2)
