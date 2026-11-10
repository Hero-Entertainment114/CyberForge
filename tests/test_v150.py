import json
import os
import subprocess
import tempfile
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import urlopen, Request
import threading
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
import cyberforge as cf


class V150LinuxSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf150-test-")
        self.old = (cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.ROOT, cf.VAULT_KEY)
        cf.DATA_DIR = Path(self.tmp.name) / "data"
        cf.DB_PATH = cf.DATA_DIR / "cyberforge.db"
        cf.EVIDENCE_DIR = cf.DATA_DIR / "evidence"
        cf.ROOT = ROOT
        cf.VAULT_KEY = None
        cf.init_database()
        self.case = cf.create_case({"title": "Linux security fixture", "scope": "local test evidence only"})
        cf.vault_create("v150-unit-test-passphrase", "v150-unit-test-passphrase")

    def tearDown(self):
        cf.VAULT_KEY = self.old[4]
        cf.DATA_DIR, cf.DB_PATH, cf.EVIDENCE_DIR, cf.ROOT = self.old[:4]
        self.tmp.cleanup()

    def store(self, name="sample.elf", data=b"\x7fELF" + b"fixture-data" * 40):
        return cf.store_evidence(data, name, self.case["id"], "v1.5.0 test evidence")

    def test_version_is_current_release(self):
        self.assertTrue(cf.APP_VERSION.startswith("1.9."))

    def test_blackarch_reverse_alias_maps_to_official_reversing_group(self):
        self.assertEqual(cf.BLACKARCH_GROUPS["reverse"]["group"], "blackarch-reversing")
        inventory_alias = cf.blackarch_inventory()["groups"][-1]["requested_alias"]
        self.assertEqual(inventory_alias, "blackarch-reverse")

    def test_blackarch_inventory_is_read_only_and_parses_groups(self):
        def which(name):
            return "/usr/bin/pacman" if name == "pacman" else None
        def run(args, **kwargs):
            if args[1] == "-Sg":
                return subprocess.CompletedProcess(args, 0, stdout=f"{args[2]} tool-one\n{args[2]} tool-two\n", stderr="")
            return subprocess.CompletedProcess(args, 0, stdout=f"{args[2]} tool-two\n", stderr="")
        with mock.patch.object(cf, "_linux_distro_info", return_value={"id": "blackarch", "name": "BlackArch", "id_like": "arch"}), \
             mock.patch.object(cf.sys, "platform", "linux"), mock.patch.object(cf.shutil, "which", side_effect=which), \
             mock.patch.object(cf.subprocess, "run", side_effect=run) as runner:
            out = cf.blackarch_inventory()
        self.assertTrue(out["supported"])
        self.assertEqual(len(out["groups"]), 4)
        self.assertEqual(out["groups"][0]["package_count"], 2)
        self.assertEqual(out["groups"][0]["installed_count"], 1)
        self.assertTrue(all(call.kwargs.get("shell") is False for call in runner.call_args_list))
        self.assertFalse(any("-Syu" in call.args[0] for call in runner.call_args_list))

    def test_blackarch_inventory_handles_non_arch_host(self):
        with mock.patch.object(cf.sys, "platform", "linux"), \
             mock.patch.object(cf, "_linux_distro_info", return_value={"id": "ubuntu", "name": "Ubuntu", "id_like": "debian"}), \
             mock.patch.object(cf.shutil, "which", return_value=None), mock.patch.object(cf.subprocess, "run") as runner:
            out = cf.blackarch_inventory()
        self.assertFalse(out["supported"])
        self.assertFalse(out["pacman_available"])
        runner.assert_not_called()

    def test_blackarch_group_parser_rejects_unexpected_group_and_package_text(self):
        got = cf._parse_pacman_group_output("blackarch-recon dnsrecon\nother evil\nblackarch-recon bad/name\n", "blackarch-recon")
        self.assertEqual(got, ["dnsrecon"])

    def test_reverse_inventory_includes_only_detected_tools(self):
        def which(name):
            return "/usr/bin/" + name if name in {"file", "strings", "readelf", "firejail"} else None
        with mock.patch.object(cf.shutil, "which", side_effect=which), \
             mock.patch.object(cf, "_analysis_tool_paths", return_value={"ghidra": None, "jadx": None}):
            out = cf.reverse_engineering_inventory()
        available = {x["id"] for x in out["engines"] if x["available"]}
        self.assertIn("metadata", available)
        self.assertIn("strings", available)
        self.assertNotIn("ghidra", available)
        self.assertTrue(out["firejail"]["available"])

    def test_reverse_analysis_requires_acknowledgement(self):
        row = self.store()
        with self.assertRaises(PermissionError):
            cf.run_reverse_engineering({"evidence_id": row["id"], "engine": "metadata"})

    def test_reverse_analysis_builtin_metadata_uses_real_evidence_hash(self):
        row = self.store()
        out = cf.run_reverse_engineering({"evidence_id": row["id"], "engine": "metadata", "acknowledged": True})
        self.assertEqual(out["sha256"], row["sha256"])
        self.assertEqual(out["status"], "completed")
        self.assertIn("ELF", out["format_hints"])

    def test_reverse_analysis_rejects_unknown_engine(self):
        row = self.store()
        with self.assertRaises(ValueError):
            cf.run_reverse_engineering({"evidence_id": row["id"], "engine": "shell", "acknowledged": True})

    def test_reverse_analysis_calls_fixed_argv_without_shell(self):
        row = self.store()
        def which(name):
            return "/usr/bin/strings" if name == "strings" else None
        def run(args, **kwargs):
            self.assertEqual(args[0], "/usr/bin/strings")
            self.assertIn("--", args)
            self.assertIs(kwargs.get("shell"), False)
            return subprocess.CompletedProcess(args, 0, stdout="hello\n", stderr="")
        with mock.patch.object(cf.shutil, "which", side_effect=which), mock.patch.object(cf.subprocess, "run", side_effect=run):
            out = cf.run_reverse_engineering({"evidence_id": row["id"], "engine": "strings", "acknowledged": True})
        self.assertEqual(out["stdout"], "hello\n")
        self.assertFalse(out["firejail"])

    def test_reverse_analysis_firejail_uses_no_network_and_dropped_capabilities(self):
        row = self.store()
        def which(name):
            return {"strings": "/usr/bin/strings", "firejail": "/usr/bin/firejail"}.get(name)
        def run(args, **kwargs):
            self.assertEqual(args[0], "/usr/bin/firejail")
            self.assertIn("--net=none", args)
            self.assertIn("--caps.drop=all", args)
            self.assertIn("--seccomp", args)
            self.assertTrue(any(str(x).startswith("--private=") for x in args))
            self.assertIs(kwargs.get("shell"), False)
            return subprocess.CompletedProcess(args, 0, stdout="sandboxed strings", stderr="")
        with mock.patch.object(cf.shutil, "which", side_effect=which), mock.patch.object(cf.os, "geteuid", return_value=1000), \
             mock.patch.object(cf.subprocess, "run", side_effect=run):
            out = cf.run_reverse_engineering({"evidence_id": row["id"], "engine": "strings", "use_firejail": True, "acknowledged": True})
        self.assertTrue(out["firejail"])
        self.assertIn("Firejail used", out["notice"])

    def test_firejail_rejected_for_dedicated_ghidra_adapter(self):
        row = self.store()
        with self.assertRaises(ValueError):
            cf.run_reverse_engineering({"evidence_id": row["id"], "engine": "ghidra", "use_firejail": True, "acknowledged": True})

    def test_firejail_status_read_only(self):
        def run(args, **kwargs):
            if args[1] == "--version":
                return subprocess.CompletedProcess(args, 0, stdout="firejail version 0.9", stderr="")
            return subprocess.CompletedProcess(args, 0, stdout="1000:user:firejail strings sample.bin\n", stderr="")
        with mock.patch.object(cf.sys, "platform", "linux"), mock.patch.object(cf.shutil, "which", return_value="/usr/bin/firejail"), \
             mock.patch.object(cf.subprocess, "run", side_effect=run):
            out = cf.firejail_status()
        self.assertTrue(out["available"])
        self.assertIn("version 0.9", out["version"])
        self.assertEqual(len(out["sandboxes"]), 1)

    def test_firejail_status_not_available_on_windows(self):
        with mock.patch.object(cf.sys, "platform", "win32"), mock.patch.object(cf.shutil, "which") as which:
            out = cf.firejail_status()
        self.assertFalse(out["available"])
        which.assert_not_called()

    def test_anonsurf_status_not_installed(self):
        with mock.patch.object(cf.sys, "platform", "linux"), mock.patch.object(cf.shutil, "which", return_value=None):
            out = cf.anonsurf_status()
        self.assertFalse(out["available"])
        self.assertEqual(out["status"], "not-installed")

    def test_anonsurf_status_parses_json_state(self):
        proc = subprocess.CompletedProcess(["anonsurf", "status", "--json"], 0,
                                           stdout=json.dumps({"anonsurf_active": True, "tor_active": True}), stderr="")
        with mock.patch.object(cf.sys, "platform", "linux"), mock.patch.object(cf.shutil, "which", return_value="/usr/bin/anonsurf"), \
             mock.patch.object(cf.subprocess, "run", return_value=proc):
            out = cf.anonsurf_status()
        self.assertTrue(out["available"])
        self.assertTrue(out["active"])
        self.assertEqual(out["status"], "active")

    def test_anonsurf_control_requires_exact_confirmation(self):
        with self.assertRaises(PermissionError):
            cf.anonsurf_control({"action": "start", "acknowledged": True, "confirmation": "yes"})

    def test_anonsurf_control_rejects_identity_and_boot_changes(self):
        for action in ("changeid", "boot-enable", "boot"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                cf.anonsurf_control({"action": action, "acknowledged": True, "confirmation": ""})

    def test_anonsurf_control_runs_only_fixed_action_and_rechecks_status(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[1:] == ["status", "--json"]:
                active = len([x for x in calls if x[1:] == ["start"]]) > 0
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"anonsurf_active": active}), stderr="")
            return subprocess.CompletedProcess(args, 0, stdout="started", stderr="")
        with mock.patch.object(cf.sys, "platform", "linux"), mock.patch.object(cf.shutil, "which", return_value="/usr/bin/anonsurf"), \
             mock.patch.object(cf.subprocess, "run", side_effect=run):
            out = cf.anonsurf_control({"action": "start", "acknowledged": True, "confirmation": "START ANONSURF"})
        self.assertEqual(out["result"], "completed")
        self.assertTrue(out["status_after"]["active"])
        self.assertTrue(all("sudo" not in c and "sh" not in c for c in calls))

    def test_agent_adapter_requires_current_case_for_reverse_analysis(self):
        row = self.store()
        args = cf._agent_clean_args("reverse_analysis", {"evidence_id": row["id"], "engine": "metadata"},
                                    "reverse engineer the selected binary", "", self.case["id"], row["id"])
        self.assertEqual(args["evidence_id"], row["id"])
        with self.assertRaises(PermissionError):
            cf._agent_clean_args("reverse_analysis", {"evidence_id": row["id"], "engine": "metadata"},
                                 "reverse engineer the selected binary", "", "OTHER-CASE", row["id"])

    def test_agent_inventory_tools_are_in_specs_but_never_change_host_state(self):
        for tool in ("blackarch_inventory", "firejail_status", "anonsurf_status", "reverse_analysis"):
            self.assertIn(tool, cf.AGENT_TOOL_SPECS)
        with mock.patch.object(cf, "anonsurf_control") as control:
            clean = cf._agent_clean_args("anonsurf_status", {}, "Check AnonSurf status", "", "", "")
            self.assertEqual(clean, {})
            control.assert_not_called()

    def test_linux_workspace_http_routes_are_exposed_loopback_only(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cf.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            for route in ("/api/linux/blackarch", "/api/linux/reverse/engines", "/api/linux/anonsurf/status", "/api/linux/firejail/status"):
                with urlopen(base + route, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    payload = json.loads(response.read())
                    self.assertIsInstance(payload, dict)
            req = Request(base + "/api/linux/reverse/run", data=json.dumps({"evidence_id": "missing", "engine": "metadata"}).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
            with self.assertRaises(Exception) as raised:
                urlopen(req, timeout=5)
            self.assertIn("403", str(raised.exception))
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
