from __future__ import annotations
import base64
import hashlib
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf
import v192_modules as v


class V192SandboxTests(unittest.TestCase):
    def test_01_capabilities_disable_guest_network(self):
        cap = v.dynamic_capabilities()
        self.assertEqual(cap['network_policy'], 'disabled')
        self.assertEqual(cap['limits']['sample_bytes'], 10 * 1024 * 1024)
        self.assertIn('process starts and parent/child hints', cap['telemetry'])

    def test_02_prepare_creates_nonexecuted_readonly_sample_and_wsb(self):
        with tempfile.TemporaryDirectory() as temp:
            payload = b'MZ' + b'harmless test fixture'
            result = v.prepare_dynamic_session(temp, 'probe.exe', base64.b64encode(payload).decode(), 45)
            root = Path(temp) / 'sandbox_dynamic' / result['session_id']
            cfg = ET.parse(root / 'CyberForge-Isolated-Analysis.wsb').getroot()
            values = {x.tag: (x.text or '') for x in cfg if x.tag != 'MappedFolders'}
            self.assertEqual(values['Networking'], 'Disable')
            self.assertEqual(values['VGpu'], 'Disable')
            self.assertEqual(values['ClipboardRedirection'], 'Disable')
            mapped = cfg.find('MappedFolders').findall('MappedFolder')
            self.assertEqual([x.findtext('ReadOnly') for x in mapped], ['true', 'true', 'false'])
            self.assertEqual((root / 'input' / 'probe.exe').read_bytes(), payload)
            self.assertFalse((root / 'output' / 'report.json').exists())
            self.assertEqual(result['status'], 'prepared')
            self.assertIsInstance(result['launch_supported'], bool)

    def test_03_prepare_quotes_filename_safely(self):
        with tempfile.TemporaryDirectory() as temp:
            result = v.prepare_dynamic_session(temp, 'bad"name.exe', base64.b64encode(b'MZx').decode())
            root = Path(temp) / 'sandbox_dynamic' / result['session_id']
            xml = (root / 'CyberForge-Isolated-Analysis.wsb').read_text(encoding='utf-8')
            self.assertNotIn('bad"name.exe', xml)
            self.assertIn('bad_name.exe', xml)

    def test_04_prepare_rejects_unsupported_extension(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            v.prepare_dynamic_session(temp, 'payload.dll', base64.b64encode(b'MZx').decode())

    def test_05_prepare_rejects_invalid_base64(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            v.prepare_dynamic_session(temp, 'payload.exe', '!!!not-base64!!!')

    def test_06_prepare_rejects_empty_sample(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            v.prepare_dynamic_session(temp, 'payload.exe', '')

    def test_07_prepare_rejects_oversized_sample(self):
        with tempfile.TemporaryDirectory() as temp:
            too_large = base64.b64encode(b'A' * (v.MAX_SAMPLE_BYTES + 1)).decode()
            with self.assertRaises(ValueError):
                v.prepare_dynamic_session(temp, 'payload.exe', too_large)

    def test_08_prepare_rejects_duration_out_of_bounds(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            v.prepare_dynamic_session(temp, 'payload.exe', base64.b64encode(b'MZx').decode(), 10)

    def test_09_prepare_rejects_non_numeric_duration(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            v.prepare_dynamic_session(temp, 'payload.exe', base64.b64encode(b'MZx').decode(), 'forever')

    def test_10_launch_requires_explicit_acknowledgement(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(PermissionError):
            v.launch_dynamic_session(temp, '0' * 32, False)

    def test_11_launch_refuses_non_windows_host_after_acknowledgement(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(v.os, 'name', 'posix'), patch.object(v.platform, 'system', return_value='Linux'):
                with self.assertRaises(RuntimeError):
                    v.launch_dynamic_session(temp, '0' * 32, True)

    def test_12_report_not_ready_is_not_clean_verdict(self):
        with tempfile.TemporaryDirectory() as temp:
            result = v.prepare_dynamic_session(temp, 'payload.exe', base64.b64encode(b'MZx').decode())
            report = v.dynamic_session_report(temp, result['session_id'])
            self.assertFalse(report['report_ready'])
            self.assertIn('không đồng nghĩa mẫu an toàn', report['notice'])

    def test_13_report_parses_bounded_guest_evidence_and_hashes_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            result = v.prepare_dynamic_session(temp, 'payload.exe', base64.b64encode(b'MZx').decode())
            output = Path(temp) / 'sandbox_dynamic' / result['session_id'] / 'output'
            report = {
                'schema': 'cyberforge.dynamic-sandbox.v1', 'created_at': '2026-11-05T00:00:00Z',
                'duration_seconds': 45, 'sample': {'sha256': result['sha256']},
                'isolation': {'network': 'disabled'}, 'coverage': {'process': 'polling'},
                'telemetry': {
                    'process_events': [{'data': {'name': 'sample.exe', 'pid': 100}}],
                    'network_events': [{'data': {'remote_address': '203.0.113.4', 'remote_port': 443}}],
                    'dns_delta': ['example.invalid|A|203.0.113.4'],
                    'file_events': [{'data': {'path': 'C:\\Temp\\drop.bin'}}],
                    'registry_events': [{'data': {'key': 'HKCU\\Run'}}], 'event_count': 4},
                'etw': {'status': 'stopped'}, 'result': {'sample_started': True}, 'warning': 'untrusted'}
            (output / 'report.json').write_text(json.dumps(report), encoding='utf-8')
            (output / 'events.csv').write_text('time,type\nnow,process_start_observed\n', encoding='utf-8')
            parsed = v.dynamic_session_report(temp, result['session_id'])
            self.assertTrue(parsed['report_ready'])
            self.assertEqual(parsed['summary']['remote_endpoints'], ['203.0.113.4:443'])
            self.assertEqual(parsed['summary']['process_names'], ['sample.exe'])
            self.assertTrue(any(x['name'] == 'events.csv' for x in parsed['artifacts']))

    def test_14_report_rejects_wrong_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            result = v.prepare_dynamic_session(temp, 'payload.exe', base64.b64encode(b'MZx').decode())
            output = Path(temp) / 'sandbox_dynamic' / result['session_id'] / 'output'
            (output / 'report.json').write_text('{"schema":"wrong"}', encoding='utf-8')
            parsed = v.dynamic_session_report(temp, result['session_id'])
            self.assertFalse(parsed['report_ready'])
            self.assertIn('schema không hợp lệ', parsed['error'])

    def test_15_report_rejects_symlinked_output(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            result = v.prepare_dynamic_session(temp, 'payload.exe', base64.b64encode(b'MZx').decode())
            output = Path(temp) / 'sandbox_dynamic' / result['session_id'] / 'output'
            backup = output.with_name('output-original')
            output.rename(backup)
            output.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                v.dynamic_session_report(temp, result['session_id'])

    def test_16_report_rejects_path_traversal_session_id(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            v.dynamic_session_report(temp, '../outside')

    def test_17_report_size_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            result = v.prepare_dynamic_session(temp, 'payload.exe', base64.b64encode(b'MZx').decode())
            output = Path(temp) / 'sandbox_dynamic' / result['session_id'] / 'output'
            (output / 'report.json').write_bytes(b'{' + b' ' * v.MAX_REPORT_BYTES + b'}')
            parsed = v.dynamic_session_report(temp, result['session_id'])
            self.assertIn('vượt giới hạn', parsed['error'])

    def test_18_summarizer_marks_network_absence_as_inconclusive(self):
        summary = v.summarize_dynamic_report({'telemetry': {}, 'etw': {}})
        self.assertIn('does not prove', summary['assessment'])

    def test_19_etw_parser_extracts_network_metadata_heuristically(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'etw_events.csv'
            path.write_text(
                'Event Name,Provider Name,PID,Clock Time,User Data\n'
                'TcpIp/Connect,Microsoft-Windows-TCPIP,432,2026-11-05 10:00:00,Connect to example.invalid 203.0.113.7:443\n'
                'Process/Start,Microsoft-Windows-Kernel-Process,500,2026-11-05 10:00:01,Image=sample.exe\n'
                'Other,Other,3,now,noise\n', encoding='utf-8')
            parsed = v._parse_etw_csv(path)
        self.assertEqual(parsed['status'], 'parsed')
        self.assertEqual(parsed['parsed_rows'], 3)
        self.assertEqual(len(parsed['network_events']), 1)
        self.assertIn('example.invalid', parsed['domains'])
        self.assertIn('203.0.113.7', parsed['ip_addresses'])
        self.assertIn('heuristic', parsed['notice'])

    def test_20_etw_parser_rejects_oversized_csv(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'etw_events.csv'
            path.write_bytes(b'x' * (v.MAX_TRACE_BYTES + 1))
            parsed = v._parse_etw_csv(path)
        self.assertEqual(parsed['status'], 'rejected')
        self.assertEqual(parsed['relevant_events'], [])

    def test_21_report_integrates_parsed_etw_csv(self):
        with tempfile.TemporaryDirectory() as temp:
            result = v.prepare_dynamic_session(temp, 'payload.exe', base64.b64encode(b'MZx').decode())
            output = Path(temp) / 'sandbox_dynamic' / result['session_id'] / 'output'
            report = {
                'schema': 'cyberforge.dynamic-sandbox.v1', 'created_at': '2026-11-05T00:00:00Z',
                'sample': {}, 'telemetry': {'process_events': [], 'network_events': [], 'dns_delta': [], 'file_events': [], 'registry_events': []},
                'etw': {'status': 'stopped'}, 'result': {}, 'warning': 'untrusted'}
            (output / 'report.json').write_text(json.dumps(report), encoding='utf-8')
            (output / 'etw_events.csv').write_text(
                'Event Name,Provider Name,PID,Clock Time,User Data\n'
                'DNS/Query,Microsoft-Windows-DNS-Client,432,now,example.invalid\n', encoding='utf-8')
            parsed = v.dynamic_session_report(temp, result['session_id'])
        self.assertTrue(parsed['report_ready'])
        self.assertEqual(parsed['summary']['etw_relevant_event_count'], 1)
        self.assertEqual(parsed['summary']['etw_domains'], ['example.invalid'])


    def test_22_guest_collector_monitors_and_stops_in_guest(self):
        script = v._guest_collector_script()
        for required in ('Get-CFProcessMap', 'Get-CFFileSnapshot', 'Get-CFRegistrySnapshot',
                         'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Get-DnsClientCache',
                         'tracerpt', 'taskkill.exe', 'sample_process_tree_terminated'):
            self.assertIn(required, script)
        self.assertNotIn('etl=if(', script)
        self.assertNotIn('csv=if(', script)


class V192OfflineAITests(unittest.TestCase):
    def test_23_status_is_explicit_about_no_cloud_and_runtime(self):
        with patch.object(v, 'local_model_status', return_value={'available': False, 'models': [], 'notice': 'No local model'}):
            status = v.offline_ai_status()
        self.assertTrue(status['offline_core'])
        self.assertFalse(status['cloud_used'])
        self.assertFalse(status['api_key_required'])
        self.assertIn('not a generative LLM', status['limitations'])

    def test_24_local_model_chat_uses_only_loopback_api(self):
        fake = [
            {'models': [{'name': 'qwen2.5-coder:1.5b', 'size': 1, 'details': {'family': 'qwen', 'parameter_size': '1.5B', 'quantization_level': 'Q4'}}]},
            {'message': {'content': 'Local answer'}, 'done': True, 'total_duration': 1234},
        ]
        with patch.object(v, '_ollama_request', side_effect=fake) as request:
            result = v.local_model_chat('', 'Write a tiny function', task='code_fix')
        self.assertEqual(result['answer'], 'Local answer')
        self.assertEqual(result['provider'], 'ollama-local')
        self.assertEqual(request.call_args_list[0].args[:2], ('GET', '/api/tags'))
        self.assertEqual(request.call_args_list[1].args[:2], ('POST', '/api/chat'))
        self.assertEqual(v.LOCAL_MODEL_HOST, '127.0.0.1')

    def test_25_local_model_rejects_absent_model(self):
        with patch.object(v, 'local_model_status', return_value={'available': False, 'models': []}):
            with self.assertRaises(RuntimeError):
                v.local_model_chat('', 'hello')

    def test_26_offline_rule_code_review_is_labeled_non_generative(self):
        result = v.offline_rule_reply('Review code', "value = eval(user_input)", 'code_review')
        self.assertEqual(result['provider'], 'offline-expert-rules')
        self.assertIn('generative', result['answer'].lower())

    def test_27_offline_sandbox_analysis_counts_observed_events(self):
        report = {'schema': 'cyberforge.dynamic-sandbox.v1', 'telemetry': {
            'process_events': [{'data': {'name': 'bad.exe'}}], 'network_events': [],
            'dns_delta': [], 'file_events': [{}], 'registry_events': []}, 'etw': {'status': 'stopped'}}
        result = v.offline_rule_reply('Interpret this', json.dumps(report), 'sandbox_analysis')
        self.assertIn('Tiến trình mới quan sát: 1', result['answer'])
        self.assertEqual(result['provider'], 'offline-expert-rules')


class V192ApiIntegrationTests(unittest.TestCase):
    def test_28_new_api_namespaces_and_permissions_are_wired(self):
        self.assertEqual(cf._api_capabilities('GET', '/api/v192/ai/status'), [])
        self.assertIn('dynamic_analysis', cf._api_capabilities('POST', '/api/v192/sandbox/launch'))
        self.assertIn('evidence_write', cf._api_capabilities('POST', '/api/v192/sandbox/prepare'))
        self.assertEqual(cf._api_capabilities('POST', '/api/v192/ai/chat'), [])

    def test_29_offline_chat_api_never_routes_to_cloud(self):
        with patch.object(cf.v192_modules, 'local_model_status', return_value={'available': False, 'models': [], 'notice': 'no LLM'}):
            result = cf.v192_offline_ai_chat({'message': 'Plan a safe sandbox', 'task': 'architecture'})
        self.assertFalse(result['cloud_used'])
        self.assertEqual(result['provider'], 'offline-expert-rules')
        self.assertEqual(result['task'], 'architecture')

    def test_30_offline_chat_rejects_cloud_or_unknown_task_profiles(self):
        with self.assertRaises(ValueError):
            cf.v192_offline_ai_chat({'message': 'hello', 'task': 'phishing_triage'})

    def test_31_offline_chat_rejects_bad_conversation_id(self):
        with self.assertRaises(ValueError):
            cf.v192_offline_ai_chat({'message': 'hello', 'conversation_id': '../bad'})

    def test_32_ai_chat_knowledge_permission_is_scoped(self):
        caps = cf._api_capabilities('POST', '/api/v192/ai/chat', {'message': 'test', 'use_knowledge': True})
        self.assertIn('knowledge_access', caps)

    def test_33_sandbox_prepare_api_requires_acknowledgement(self):
        with self.assertRaises(PermissionError):
            cf.v192_sandbox_prepare({'filename': 'probe.exe', 'content_base64': base64.b64encode(b'MZx').decode(), 'acknowledged': False})


if __name__ == '__main__':
    unittest.main()
