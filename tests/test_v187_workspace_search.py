from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class WorkspaceSearchV187Tests(unittest.TestCase):
    def test_workspace_search_control_and_shortcut_are_wired(self):
        html = (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')
        self.assertIn('id="workspaceSearch"', html)
        self.assertIn('id="workspaceSearchResults"', html)
        self.assertIn("e.key.toLowerCase()==='k'", html)
        self.assertIn('function runWorkspaceSearch()', html)
        self.assertIn('function openWorkspaceSearchHit(h)', html)

    def test_search_is_local_and_uses_existing_workspace_metadata(self):
        html = (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')
        self.assertIn("document.querySelectorAll('.page')", html)
        self.assertIn("page.querySelectorAll('h2,h3,h4,.sectiontitle,label')", html)
        self.assertNotIn('fetch(', html[html.index('function runWorkspaceSearch()'):html.index('function permissionPromptFromError')])

    def test_version_manifests_match(self):
        import sys
        sys.path.insert(0, str(ROOT))
        import cyberforge
        self.assertTrue(cyberforge.APP_VERSION.startswith("1.9."))
        self.assertEqual((ROOT / "VERSION.txt").read_text().strip(), cyberforge.APP_VERSION)
        self.assertEqual(json.loads((ROOT / "edition.json").read_text())["version"], cyberforge.APP_VERSION)
        self.assertEqual(json.loads((ROOT / "RELEASE_MANIFEST.json").read_text())["version"], cyberforge.APP_VERSION)

    def test_inline_javascript_is_balanced_for_parser(self):
        html = (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')
        scripts = re.findall(r'<script>(.*?)</script>', html, re.S)
        self.assertEqual(len(scripts), 1)
        self.assertIn('runWorkspaceSearch', scripts[0])

if __name__ == '__main__':
    unittest.main()
