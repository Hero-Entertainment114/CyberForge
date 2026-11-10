"""Regression tests for the Dev Studio workspace redesign in v1.8.2."""
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "static" / "index.html"
SOURCE = HTML.read_text(encoding="utf-8")


class DocumentIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.tabs = {}
        self.panels = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if attrs.get("role") == "tab":
            self.tabs[attrs.get("id")] = attrs.get("aria-controls")
        if attrs.get("role") == "tabpanel":
            self.panels[attrs.get("id")] = attrs.get("aria-labelledby")


class DevStudioV182Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = DocumentIndex()
        cls.doc.feed(SOURCE)

    def test_document_ids_are_unique(self):
        duplicates = [key for key, count in Counter(self.doc.ids).items() if count > 1]
        self.assertEqual([], duplicates)

    def test_all_workspace_tabs_map_to_real_panels(self):
        expected = {
            "devTabProjects": "devPanelProjects",
            "devTabWorkspace": "devPanelWorkspace",
            "devTabAI": "devPanelAI",
            "devTabDiagnostics": "devPanelDiagnostics",
        }
        for tab_id, panel_id in expected.items():
            with self.subTest(tab=tab_id):
                self.assertEqual(panel_id, self.doc.tabs.get(tab_id))
                self.assertEqual(tab_id, self.doc.panels.get(panel_id))

    def test_ai_panel_is_separate_from_editor_grid(self):
        workspace_start = SOURCE.index('id="devPanelWorkspace"')
        ai_start = SOURCE.index('id="devPanelAI"')
        workspace = SOURCE[workspace_start:ai_start]
        self.assertIn('class="ide-grid dev-editor-grid"', workspace)
        self.assertNotIn('AI PAIR PROGRAMMER', workspace)
        self.assertIn('id="devAIAssistant"', SOURCE[ai_start:SOURCE.index('id="devPanelDiagnostics"')])

    def test_old_scroll_only_navigation_is_removed(self):
        self.assertNotIn("scrollIntoView({behavior:'smooth'})", SOURCE)
        self.assertIn("function switchDevStudioPanel(name)", SOURCE)
        self.assertIn("panel.hidden=!active", SOURCE)

    def test_task_and_git_actions_flush_unsaved_buffers(self):
        self.assertIn("await persistDevDirtyTabs();const d=await api('dev/project/task'", SOURCE)
        self.assertIn("await persistDevDirtyTabs();let payload={project_id:id,action,acknowledged:false}", SOURCE)
        self.assertIn("async function persistDevDirtyTabs()", SOURCE)

    def test_search_and_diagnostics_return_to_the_correct_editor_line(self):
        self.assertIn("focusDevEditorLine(hit.line)", SOURCE)
        self.assertIn("focusDevEditorLine(btn.dataset.diagnosticLine)", SOURCE)

    def test_ai_patch_refuses_to_overwrite_new_editor_changes(self):
        self.assertIn("The editor changed after this patch was generated", SOURCE)


if __name__ == "__main__":
    unittest.main()
