import io
import json
import struct
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V011Tests(unittest.TestCase):
    def test_elf_header_identification(self):
        # ELF64 little-endian x86-64 executable header
        blob = bytearray(64)
        blob[:16] = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
        struct.pack_into('<HHIQQQIHHHHHH', blob, 16, 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 0, 64, 0, 0)
        report = cf.analyze_file_bytes(bytes(blob), 'sample.elf')
        self.assertEqual(report['elf']['machine'], 'x86-64')
        self.assertEqual(report['elf']['class'], '64-bit')

    def test_zip_traversal_is_flagged_without_extracting(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as zf:
            zf.writestr('../outside.txt', 'not extracted')
            zf.writestr('docs/readme.txt', 'hello')
        report = cf.analyze_file_bytes(stream.getvalue(), 'archive.zip')
        self.assertIsNotNone(report['archive'])
        self.assertTrue(any('path_traversal' in x['flags'] for x in report['archive']['warnings']))

    def test_pcap_header_summary(self):
        packet_header = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        report = cf.analyze_file_bytes(packet_header, 'capture.pcap')
        self.assertEqual(report['pcap']['format'], 'PCAP')
        self.assertEqual(report['pcap']['packets_parsed'], 0)

    def test_builtin_signature_flags_eicar_as_harmless_test(self):
        data = b'prefix EICAR-STANDARD-ANTIVIRUS-TEST-FILE suffix'
        matches = cf._builtin_signature_scan(data)
        match = next(x for x in matches if x['severity'] == 'test')
        self.assertIn('harmless', match['guidance'])

    def test_python_syntax_does_not_execute(self):
        good = cf.code_syntax('print("not executed")', 'python')
        bad = cf.code_syntax('def broken(:', 'python')
        self.assertTrue(good['valid_syntax'])
        self.assertFalse(bad['valid_syntax'])

    def test_dependency_hygiene(self):
        report = cf.dependency_review('requests\nflask==3.0.0\nexample @ https://example.invalid/pkg.whl', 'requirements.txt')
        self.assertEqual(report['dependency_count'], 3)
        self.assertGreaterEqual(len(report['review_findings']), 2)
        self.assertIn('does not check CVEs', report['important'])

    def test_stix_export_structure(self):
        report = cf.export_iocs_stix('connection from 192.0.2.10 to https://example.com/a hash=' + 'a' * 64)
        self.assertEqual(report['type'], 'bundle')
        self.assertTrue(all(x['type'] == 'indicator' for x in report['objects']))
        self.assertGreaterEqual(len(report['objects']), 3)

    def test_sandbox_requires_explicit_acknowledgement(self):
        with self.assertRaises(PermissionError):
            cf.sandbox_run('print(1)', 'python', False)

    def test_code_review_detects_private_key_marker(self):
        report = cf.code_review('-----BEGIN PRIVATE KEY-----')
        self.assertTrue(any(x['title'] == 'Private key embedded in source' for x in report['findings']))

    def test_file_report_has_sha512(self):
        report = cf.analyze_file_bytes(b'hello world', 'hello.txt')
        self.assertEqual(len(report['sha512']), 128)
        self.assertEqual(len(report['blake2b']), 128)

    def test_eicar_test_string_is_harmless_reference(self):
        self.assertIn(b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE', cf.EICAR_TEST_STRING)
        self.assertTrue(any(x['severity'] == 'test' for x in cf._builtin_signature_scan(cf.EICAR_TEST_STRING)))


if __name__ == '__main__':
    unittest.main()
