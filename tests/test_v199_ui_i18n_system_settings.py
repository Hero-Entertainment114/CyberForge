from __future__ import annotations
import json, sys, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import cyberforge as cf

class V199LocalesAndSystemSettingsTests(unittest.TestCase):
    def test_01_all_twelve_bundled_locales_load(self):
        self.assertEqual(len(cf.SUPPORTED_LOCALES),12)
        for code in cf.SUPPORTED_LOCALES:
            catalog=cf.load_locale_catalog(code)
            self.assertEqual(catalog['locale'],code)
            self.assertGreater(len(catalog['messages']),1000)
    def test_02_english_is_default_locale(self):
        self.assertEqual(cf.PREFERENCE_DEFAULTS['localization']['locale'],'en')
        self.assertEqual(cf._copy_preferences()['localization']['locale'],'en')
    def test_03_arabic_is_rtl_and_other_locales_are_ltr(self):
        self.assertEqual(cf.load_locale_catalog('ar')['direction'],'rtl')
        for code in set(cf.SUPPORTED_LOCALES)-{'ar'}:
            self.assertEqual(cf.load_locale_catalog(code)['direction'],'ltr')
    def test_04_unknown_locale_is_rejected(self):
        with self.assertRaises(ValueError): cf.load_locale_catalog('xx')
        with self.assertRaises(ValueError): cf._validate_preferences({'localization':{'locale':'xx'}})
    def test_05_all_locale_catalogs_have_common_core_translations(self):
        for code in cf.SUPPORTED_LOCALES:
            messages=cf.load_locale_catalog(code)['messages']
            self.assertIn('System Settings',messages)
            self.assertIn('Command Center',messages)
            self.assertIn('Interface language',messages)
    def test_06_ten_new_locale_catalog_files_exist(self):
        self.assertEqual(set(cf.SUPPORTED_LOCALES)-{'en','vi'},{'es','fr','de','pt','ja','ko','zh','ru','ar','hi'})
        for code in cf.SUPPORTED_LOCALES:
            self.assertTrue((ROOT/'locales'/f'{code}.json').is_file())
    def test_07_system_settings_inventory_is_bounded_and_secret_free(self):
        info=cf.system_settings_info()
        self.assertIn('application',info); self.assertIn('machine',info); self.assertIn('runtime_tools',info)
        serialized=json.dumps(info).lower()
        self.assertNotIn('api_key',serialized); self.assertNotIn('password',serialized)
        self.assertIn('database_size_bytes',info['application'])
    def test_08_os_settings_targets_are_fixed_allowlist(self):
        self.assertEqual(set(cf.SYSTEM_SETTINGS_TARGETS),{'display','network','sound','storage','apps','updates','developer'})
        with self.assertRaises(ValueError): cf.open_operating_system_settings({'target':'powershell -Command whoami'})
    def test_09_os_settings_capability_requires_host_launch(self):
        self.assertIn('host_app_launch',cf._api_capabilities('POST','/api/system/settings/open',{'target':'display'}))
    def test_10_get_settings_endpoint_requires_diagnostics_policy(self):
        self.assertIn('system_diagnostics',cf._api_capabilities('GET','/api/system/settings',{}))
    def test_11_settings_page_and_twelve_locale_options_are_wired(self):
        html=(ROOT/'static'/'index.html').read_text(encoding='utf-8')
        self.assertIn('<html lang="en" dir="ltr">',html)
        self.assertIn('id="systemsettings"',html)
        self.assertIn('function loadSystemSettings()',html)
        for code in cf.SUPPORTED_LOCALES: self.assertIn(f'<option value="{code}">',html)
    def test_12_settings_open_uses_fixed_commands_without_shell(self):
        with patch.object(cf.subprocess,'Popen') as popen, patch.object(cf.shutil,'which',return_value='/usr/bin/gnome-control-center'), patch.object(cf.sys,'platform','linux'):
            out=cf.open_operating_system_settings({'target':'display'})
            self.assertTrue(out['opened']); self.assertEqual(popen.call_args.args[0],['/usr/bin/gnome-control-center','display'])
            self.assertNotIn('shell',popen.call_args.kwargs)
    def test_13_system_backup_results_are_mirrored_in_both_pages(self):
        html=(ROOT/'static'/'index.html').read_text(encoding='utf-8')
        self.assertIn("function systemBackupResultTargets(){return ['systemBackupResult','systemSettingsBackupResult']",html)
        self.assertIn('writeSystemBackupResult',html)
        self.assertIn("async function createSystemBackup()",html)
        self.assertIn("async function verifySystemBackup(name)",html)
    def test_14_locale_preview_syncs_both_settings_selectors(self):
        html=(ROOT/'static'/'index.html').read_text(encoding='utf-8')
        self.assertIn("if($('prefLocale'))$('prefLocale').value=selected;if($('sysAppLocale'))$('sysAppLocale').value=selected",html)
        self.assertEqual(html.count("systemsettings:'System Settings'"),1)

if __name__=='__main__': unittest.main()
