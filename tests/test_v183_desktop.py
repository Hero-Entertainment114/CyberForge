"""Regression checks for native desktop packaging in v1.8.5."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
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

import build_desktop as builder
import cyberforge as cf


class NativeDesktopBuilderTests(unittest.TestCase):
    def test_host_platform_is_recognized(self):
        self.assertIn(builder.current_platform(), {"windows", "macos", "linux"})

    def test_platform_aliases_are_explicit(self):
        with patch.object(builder.sys, "platform", "win32"):
            self.assertEqual(builder.current_platform(), "windows")
        with patch.object(builder.sys, "platform", "darwin"):
            self.assertEqual(builder.current_platform(), "macos")
        with patch.object(builder.sys, "platform", "linux"):
            self.assertEqual(builder.current_platform(), "linux")

    def test_unknown_platform_is_rejected(self):
        with patch.object(builder.sys, "platform", "freebsd"):
            with self.assertRaises(SystemExit):
                builder.current_platform()

    def test_windows_command_selects_webview2_backend(self):
        command, _ = builder.pyinstaller_command("aio", "windows")
        joined = " ".join(command)
        self.assertIn("webview.platforms.winforms", joined)
        self.assertIn("webview.platforms.edgechromium", joined)
        self.assertIn("clr_loader", joined)
        self.assertIn("psutil", joined)
        self.assertIn("static;static", joined)

    def test_macos_command_selects_cocoa_and_bundle_identifier(self):
        command, _ = builder.pyinstaller_command("dev", "macos")
        joined = " ".join(command)
        self.assertIn("webview.platforms.cocoa", joined)
        self.assertIn("psutil", joined)
        self.assertIn("org.cyberforge.desktop", joined)
        self.assertIn("static:static", joined)

    def test_linux_command_selects_qt_webengine_backend(self):
        command, _ = builder.pyinstaller_command("security", "linux")
        joined = " ".join(command)
        self.assertIn("webview.platforms.qt", joined)
        self.assertIn("PySide6", joined)
        self.assertIn("shiboken6", joined)
        self.assertIn("psutil", joined)
        self.assertIn("pywebview[pyside6]", (ROOT / "requirements-build-linux.txt").read_text(encoding="utf-8"))

    def test_edition_manifest_staging_is_isolated(self):
        for edition in ("aio", "dev", "security"):
            builder.pyinstaller_command(edition, "linux")
            staged = ROOT / "build" / f"desktop-linux-{edition}" / "edition.json"
            self.assertEqual(json.loads(staged.read_text(encoding="utf-8")), {"edition": edition})

    def test_each_native_platform_uses_its_own_icon_format(self):
        expected = {"windows": "cyberforge.ico", "macos": "cyberforge.icns", "linux": "cyberforge.png"}
        for target, icon_name in expected.items():
            command, _ = builder.pyinstaller_command("aio", target)
            self.assertTrue((ROOT / "assets" / icon_name).is_file())
            if target in {"windows", "macos"}:
                self.assertIn(str(ROOT / "assets" / icon_name), command)
            else:
                self.assertNotIn("--icon", command)  # Linux launchers use the bundled PNG resource.

    def test_macos_artifact_is_an_app_bundle(self):
        self.assertEqual(builder.expected_artifact("CyberForge-AIO", "macos", ROOT / "dist"),
                         ROOT / "dist" / "CyberForge-AIO.app")

    def test_folder_artifacts_for_windows_and_linux(self):
        dist = ROOT / "dist"
        self.assertEqual(builder.expected_artifact("CyberForge-AIO", "windows", dist), dist / "CyberForge-AIO")
        self.assertEqual(builder.expected_artifact("CyberForge-AIO", "linux", dist), dist / "CyberForge-AIO")

    def test_cross_platform_build_is_refused(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit):
                builder.main(["--platform", "windows", "--dry-run"])

    def test_dry_run_does_not_invoke_pyinstaller(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = builder.main(["--platform", builder.current_platform(), "--edition", "aio", "--dry-run"])
        self.assertEqual(result, 0)
        self.assertIn("PyInstaller", out.getvalue())

    def test_bundle_self_test_checks_source_resources(self):
        self.assertEqual(cf._desktop_bundle_self_test(), 0)

    def test_runtime_status_reports_current_process_resources(self):
        status = cf.runtime_status()
        self.assertEqual(status["pid"], os.getpid())
        self.assertEqual(status["version"], cf.APP_VERSION)
        self.assertTrue(status["local_only"])
        self.assertGreaterEqual(status["thread_count"], 1)
        self.assertGreaterEqual(status["uptime_seconds"], 0)
        self.assertIn("memory_rss_bytes", status)
        self.assertNotIn("process_list", status)

    def test_runtime_api_endpoint_returns_process_metrics(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/runtime", timeout=5) as response:
                data = json.loads(response.read())
            self.assertEqual(data["version"], cf.APP_VERSION)
            self.assertEqual(data["pid"], os.getpid())
            self.assertTrue(data["local_only"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_dashboard_exposes_runtime_and_resource_monitor(self):
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="runtimeStats"', html)
        self.assertIn('id="runtimeMeta"', html)
        self.assertIn("async function loadRuntimeStatus()", html)
        self.assertIn("/api/runtime", html)
        self.assertIn("setInterval(()=>{if(document.visibilityState!=='hidden')loadRuntimeStatus()},15000)", html)

    def test_linux_builder_script_is_executable_and_platform_specific(self):
        script = ROOT / "BUILD_DESKTOP_LINUX.sh"
        self.assertTrue(script.stat().st_mode & 0o111)
        self.assertIn("requirements-build-linux.txt", script.read_text(encoding="utf-8"))
        self.assertIn("--platform linux", script.read_text(encoding="utf-8"))

    def test_macos_builder_script_is_platform_specific(self):
        script = ROOT / "BUILD_DESKTOP_MACOS.command"
        content = script.read_text(encoding="utf-8")
        self.assertIn("requirements-build-macos.txt", content)
        self.assertIn("--platform macos", content)

    def test_legacy_windows_builder_rejects_non_windows_host(self):
        if sys.platform == "win32":
            self.skipTest("Windows-only guard cannot be exercised from Windows")
        result = subprocess.run([sys.executable, str(ROOT / "build_windows.py"), "--dry-run"],
                                cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must run on Windows", result.stderr + result.stdout)

    def test_windows_scripts_use_platform_specific_requirements(self):
        for filename in ("BUILD_WINDOWS.bat", "BUILD_ALL_WINDOWS.bat", "BUILD_WINDOWS_DEV.bat", "BUILD_WINDOWS_SECURITY.bat", "BUILD_WINDOWS.ps1"):
            content = (ROOT / filename).read_text(encoding="utf-8")
            self.assertIn("requirements-build-windows.txt", content)
            self.assertIn("build_desktop.py", content)

    def test_ci_build_matrix_covers_nine_platform_edition_pairs(self):
        workflow = (ROOT / ".github" / "workflows" / "desktop-editions.yml").read_text(encoding="utf-8")
        self.assertIn(f"tags: ['v{cf.APP_VERSION}']", workflow)
        self.assertEqual(workflow.count("platform: windows"), 3)
        self.assertEqual(workflow.count("platform: macos"), 3)
        self.assertEqual(workflow.count("platform: linux"), 3)
        self.assertEqual(workflow.count("edition: aio"), 3)
        self.assertEqual(workflow.count("edition: dev"), 3)
        self.assertEqual(workflow.count("edition: security"), 3)
        self.assertIn("build_desktop.py --platform", workflow)


if __name__ == "__main__":
    unittest.main()
