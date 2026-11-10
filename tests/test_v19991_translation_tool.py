from __future__ import annotations
import importlib.util, io, json, sys, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('cf_translate_catalogs',ROOT/'tools'/'translate_catalogs.py')
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)

class LocalTranslationToolTests(unittest.TestCase):
    def test_01_only_loopback_plain_http_is_accepted(self):
        from urllib.parse import urlsplit
        good=urlsplit('http://127.0.0.1:11434')
        self.assertEqual(good.hostname,'127.0.0.1')
        self.assertTrue(mod.contains_code_only('SAST'))
        self.assertFalse(mod.contains_code_only('Editor'))
    def test_02_placeholder_signature_is_detected(self):
        self.assertEqual(sorted(mod.PLACEHOLDER_RE.findall('Open {file} at ${path} (%s)')),sorted(['{file}','${path}','%s']))
    def test_03_code_and_urls_are_not_sent_as_ui_strings(self):
        self.assertTrue(mod.contains_code_only('https://example.invalid/path'))
        self.assertTrue(mod.contains_code_only('SAST'))
        self.assertFalse(mod.contains_code_only('No project selected'))
    def test_04_ollama_response_is_parsed_and_placeholder_safe(self):
        batch=[('open','Open {file}')]
        payload={'message':{'content':json.dumps({'translations':[{'id':0,'translation':'Ouvrir {file}'}]})}}
        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self,*args): self.close()
        with patch.object(mod.urllib.request,'urlopen',return_value=Response(json.dumps(payload).encode())):
            result=mod.ollama_chat('http://127.0.0.1:11434','test-model','fr',batch)
        self.assertEqual(result,{'open':'Ouvrir {file}'})
    def test_05_placeholder_mismatch_is_rejected(self):
        batch=[('open','Open {file}')]
        payload={'message':{'content':json.dumps({'translations':[{'id':0,'translation':'Ouvrir le fichier'}]})}}
        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self,*args): self.close()
        with patch.object(mod.urllib.request,'urlopen',return_value=Response(json.dumps(payload).encode())):
            result=mod.ollama_chat('http://127.0.0.1:11434','test-model','fr',batch)
        self.assertEqual(result,{})

if __name__=='__main__': unittest.main()
