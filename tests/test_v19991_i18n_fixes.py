from __future__ import annotations
import json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import cyberforge as cf

class V19991LocalizationRegressionTests(unittest.TestCase):
    def test_01_all_locale_catalogs_have_identical_message_keys(self):
        catalogs=[cf.load_locale_catalog(code) for code in cf.SUPPORTED_LOCALES]
        baseline=set(catalogs[0]['messages'])
        self.assertGreaterEqual(len(baseline),1700)
        for catalog in catalogs:
            self.assertEqual(set(catalog['messages']),baseline)
    def test_02_each_locale_has_the_same_complete_error_code_set(self):
        catalogs=[cf.load_locale_catalog(code) for code in cf.SUPPORTED_LOCALES]
        baseline=set(catalogs[0]['errors']['code'])
        self.assertGreaterEqual(len(baseline),20)
        for catalog in catalogs:
            self.assertEqual(set(catalog['errors']['code']),baseline)
            self.assertTrue(all(isinstance(v,str) and v.strip() for v in catalog['errors']['code'].values()))
    def test_03_error_messages_are_localized_for_all_non_english_locales(self):
        english=cf.load_locale_catalog('en')['errors']['code']
        for locale in set(cf.SUPPORTED_LOCALES)-{'en'}:
            messages=cf.load_locale_catalog(locale)['errors']['code']
            self.assertTrue(all(messages[k]!=english[k] for k in english),locale)
    def test_04_arabic_direction_and_english_default_preserved(self):
        self.assertEqual(cf.load_locale_catalog('ar')['direction'],'rtl')
        self.assertEqual(cf.PREFERENCE_DEFAULTS['localization']['locale'],'en')
        self.assertEqual(cf._copy_preferences()['localization']['locale'],'en')
    def test_05_runtime_restores_original_when_target_locale_lacks_key(self):
        html=(ROOT/'static'/'index.html').read_text(encoding='utf-8')
        self.assertIn("const target=typeof translated==='string'?translated:original;",html)
        self.assertIn("const result=typeof translated==='string'?translated:sourceValue;",html)
    def test_06_mutation_observer_queues_and_batches_dom_changes(self):
        html=(ROOT/'static'/'index.html').read_text(encoding='utf-8')
        self.assertIn('function cfQueueTranslate(node)',html)
        self.assertIn('queueMicrotask(',html)
        self.assertIn('CF_I18N.pendingNodes.clear()',html)
    def test_07_api_read_write_binary_failures_use_locale_error_mapper(self):
        html=(ROOT/'static'/'index.html').read_text(encoding='utf-8')
        self.assertIn('throw cfMakeError(data.error_code||cfErrorCode(data.error,r.status)',html)
        self.assertIn('async function binaryApi(',html)
        self.assertIn('async function getJSON(url)',html)
        self.assertIn("'X-CF-Locale':CF_I18N.locale",html)
    def test_08_catalog_loader_validates_and_returns_error_messages(self):
        catalog=cf.load_locale_catalog('es')
        self.assertIn('code',catalog['errors'])
        self.assertIn('permission_denied',catalog['errors']['code'])
        with self.assertRaises(ValueError): cf.load_locale_catalog('xx')
    def test_09_error_translations_keep_code_identifiers_outside_catalog(self):
        catalog=cf.load_locale_catalog('vi')
        self.assertNotIn('PermissionError',catalog['errors']['code'].values())
        self.assertIn('permission_denied',catalog['errors']['code'])
    def test_10_translation_guard_excludes_code_and_user_data(self):
        html=(ROOT/'static'/'index.html').read_text(encoding='utf-8')
        self.assertIn("script,style,textarea,code,pre,svg,[data-no-translate]",html)

if __name__=='__main__': unittest.main()
