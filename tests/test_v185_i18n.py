"""Localization and locale-persistence regression tests for CyberForge v1.8.5."""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberforge as cf
import build_desktop as builder


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "textarea", "code", "pre", "svg"}:
            self.skip_depth += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "textarea", "code", "pre", "svg"} and self.skip_depth:
            self.skip_depth -= 1

    def handle_data(self, data):
        value = " ".join(data.split())
        if not self.skip_depth and len(value) > 2:
            self.text.append(value)


class LocaleCatalogTests(unittest.TestCase):
    def test_01_supported_locale_catalogs_exist_and_are_substantial(self):
        for locale in cf.SUPPORTED_LOCALES:
            catalog = cf.load_locale_catalog(locale)
            self.assertEqual(catalog["locale"], locale)
            self.assertEqual(catalog["direction"], "rtl" if locale == "ar" else "ltr")
            self.assertGreaterEqual(len(catalog["messages"]), 250)

    def test_02_unsupported_locale_is_rejected(self):
        with self.assertRaises(ValueError):
            cf.load_locale_catalog("xx")

    def test_03_catalog_keys_and_values_are_strings(self):
        for locale in cf.SUPPORTED_LOCALES:
            messages = cf.load_locale_catalog(locale)["messages"]
            self.assertTrue(all(isinstance(k, str) and isinstance(v, str) for k, v in messages.items()))

    def test_04_english_catalog_covers_all_vietnamese_static_copy(self):
        source = VisibleTextParser()
        source.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
        english = cf.load_locale_catalog("en")["messages"]
        vietnamese = {text for text in source.text if re.search(r"[À-ỹĐđ]", text)}
        self.assertTrue(vietnamese)
        self.assertEqual(vietnamese - set(english), set())

    def test_05_vietnamese_catalog_covers_primary_long_interface_copy(self):
        source = VisibleTextParser()
        source.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
        vietnamese = cf.load_locale_catalog("vi")["messages"]
        long_english = {text for text in source.text if len(text) > 30 and not re.search(r"[À-ỹĐđ]", text)}
        missing = long_english - set(vietnamese)
        self.assertEqual(missing, set(), sorted(missing))
        for common_label in (
            "Interface language", "Find text...", "Enter a strong passphrase",
            "IOC / keyword / knowledge query", "Paste source code here...",
            "Project purpose", "CyberForge process & resources",
        ):
            self.assertIn(common_label, vietnamese)

    def test_06_desktop_builder_bundles_locale_resources(self):
        for platform in ("windows", "macos", "linux"):
            command, _ = builder.pyinstaller_command("aio", platform)
            joined = " ".join(command)
            separator = ";" if platform == "windows" else ":"
            self.assertIn(f"locales{separator}locales", joined)

    def test_07_frozen_bundle_self_test_requires_both_locales(self):
        source = (ROOT / "cyberforge.py").read_text(encoding="utf-8")
        self.assertIn('"Vietnamese locale catalog": BUNDLE_ROOT / "locales" / "vi.json"', source)
        self.assertIn('"English locale catalog": BUNDLE_ROOT / "locales" / "en.json"', source)
        self.assertIn('catalog = load_locale_catalog(locale)', source)

    def test_08_interface_exposes_persisted_language_selector_and_dynamic_translator(self):
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        for fragment in (
            'id="prefLocale"', 'localization:{locale:', 'await setInterfaceLocale',
            'new MutationObserver', "document.documentElement.lang=selected",
            "closest('script,style,textarea,code,pre,svg,[data-no-translate]')",
        ):
            self.assertIn(fragment, html)

    def test_09_translation_runtime_does_not_translate_code_or_user_input(self):
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("script,style,textarea,code,pre,svg,[data-no-translate]", html)
        self.assertIn("const allowed=['placeholder','title','aria-label']", html)
        self.assertNotIn("innerHTML=translated", html)

    def test_10_locale_route_is_loopback_accessible(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for locale in cf.SUPPORTED_LOCALES:
                with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/i18n/{locale}", timeout=5) as response:
                    data = json.loads(response.read())
                self.assertEqual(data["locale"], locale)
                self.assertGreaterEqual(len(data["messages"]), 250)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_11_unknown_locale_endpoint_is_not_exposed(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(Exception):
                urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/i18n/xx", timeout=5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


class PreferenceLocaleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf185-i18n-")
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR)
        base = Path(self.tmp.name) / "data"
        cf.DATA_DIR = base
        cf.DB_PATH = base / "cyberforge.db"
        cf.EVIDENCE_DIR = base / "evidence"
        cf.init_database()

    def tearDown(self):
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR = self.old
        self.tmp.cleanup()

    def test_12_default_locale_is_english(self):
        self.assertEqual(cf.get_app_preferences()["localization"]["locale"], "en")

    def test_13_legacy_profile_migrates_without_losing_other_preferences(self):
        legacy = cf._validate_preferences({"appearance": {"theme": "light"}, "editor": {"font_size": 15}})
        self.assertEqual(legacy["localization"]["locale"], "en")
        self.assertEqual(legacy["appearance"]["theme"], "light")
        self.assertEqual(legacy["editor"]["font_size"], 15)

    def test_14_locale_can_be_saved_and_read_back(self):
        saved = cf.save_app_preferences({"localization": {"locale": "en"}})
        self.assertEqual(saved["profile"]["localization"]["locale"], "en")
        self.assertEqual(cf.get_app_preferences()["localization"]["locale"], "en")

    def test_15_invalid_locale_is_rejected(self):
        with self.assertRaises(ValueError):
            cf.save_app_preferences({"localization": {"locale": "xx"}})

    def test_16_partial_preference_update_preserves_other_groups(self):
        cf.save_app_preferences({"appearance": {"theme": "light"}})
        saved = cf.save_app_preferences({"localization": {"locale": "en"}})["profile"]
        self.assertEqual(saved["appearance"]["theme"], "light")
        self.assertEqual(saved["localization"]["locale"], "en")

    def test_17_exported_profile_contains_locale_but_no_secrets(self):
        cf.save_app_preferences({"localization": {"locale": "en"}})
        profile = cf.get_app_preferences()
        self.assertEqual(profile["localization"], {"locale": "en"})
        self.assertNotIn("api_key", json.dumps(profile).lower())

    def test_18_reset_restores_english_default(self):
        cf.save_app_preferences({"localization": {"locale": "en"}})
        restored = cf.reset_app_preferences()
        self.assertEqual(restored["profile"]["localization"]["locale"], "en")

    def test_19_schema_stays_backward_compatible(self):
        self.assertEqual(cf.PREFERENCE_DEFAULTS["schema_version"], 1)
        self.assertIn("localization", cf.PREFERENCE_DEFAULTS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
