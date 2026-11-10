from __future__ import annotations
import base64
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess

import cyberforge as cf
import v193_modules as v193
import v194_modules as v194
from sandbox.netlab import netlab_telemetry


def _minimal_pcap() -> bytes:
    # PCAP global header (DLT_RAW) and one minimal IPv4/TCP packet.
    ip = bytearray(40)
    ip[0] = 0x45
    ip[2:4] = struct.pack("!H", 40)
    ip[8] = 64; ip[9] = 6
    ip[12:16] = socket.inet_aton("127.0.0.1")
    ip[16:20] = socket.inet_aton("127.0.0.1")
    ip[20:24] = struct.pack("!HH", 43210, 80)
    ip[32] = 0x50
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    record = struct.pack("<IIII", 1700000000, 100, len(ip), len(ip))
    return header + record + bytes(ip)


class V194TelemetryTests(unittest.TestCase):
    def test_01_ipv4_tcp_flow_parser_extracts_only_headers(self):
        pcap = _minimal_pcap()
        packet = pcap[40:]
        flow = netlab_telemetry._parse_ip_flow(packet)
        self.assertEqual(flow["protocol"], "TCP")
        self.assertEqual(flow["src"], "127.0.0.1")
        self.assertEqual(flow["dst_port"], 80)
        self.assertNotIn("payload", flow)

    def test_02_capture_fails_closed_without_raw_socket_permission(self):
        with tempfile.TemporaryDirectory() as td:
            cap = netlab_telemetry.LoopbackPcapCapture(Path(td) / "test.pcap")
            with patch.object(netlab_telemetry.socket, "socket", side_effect=PermissionError("denied")):
                cap.start()
            meta = cap.stop()
            self.assertFalse(meta["available"])
            self.assertEqual(meta["error"], "PermissionError")
            self.assertFalse((Path(td) / "test.pcap").exists())

    def test_03_ipv6_udp_flow_parser(self):
        packet = bytearray(48); packet[0] = 0x60; packet[6] = 17
        packet[8:24] = socket.inet_pton(socket.AF_INET6, "::1")
        packet[24:40] = socket.inet_pton(socket.AF_INET6, "::1")
        packet[40:44] = struct.pack("!HH", 53000, 53)
        flow = netlab_telemetry._parse_ip_flow(bytes(packet))
        self.assertEqual(flow["protocol"], "UDP")
        self.assertEqual(flow["dst_port"], 53)

    def test_04_invalid_ip_packet_is_ignored(self):
        self.assertIsNone(netlab_telemetry._parse_ip_flow(b""))
        self.assertIsNone(netlab_telemetry._parse_ip_flow(b"not-an-ip-packet"))


class V194CorrelationTests(unittest.TestCase):
    def _report(self):
        return {
            "schema": "cyberforge.netlab.v2",
            "sample": {"name": "sample.py", "sha256": "a" * 64},
            "coverage": {"https": "SNI only; no decryption"},
            "timeline": [
                {"time": 3, "type": "dns_query", "data": {"domain": "bad.example", "pid": 77, "process": "sample.py", "peer_port": 43210, "local_port": 53}},
                {"time": 4, "type": "http_request", "data": {"host": "bad.example", "path": "/stage", "method": "GET", "pid": 77, "process": "sample.py", "peer_port": 43210, "local_port": 80}},
                {"time": 5, "type": "process_start_observed", "data": {"pid": 78, "ppid": 77, "name": "child-probe", "command_line": "child-probe --test"}},
                {"time": 6, "type": "file_change_observed", "data": {"path": "/tmp/drop.txt", "state": "created"}},
                {"time": 7, "type": "pcap_flow_observed", "data": {"src": "127.0.0.1", "dst": "127.0.0.1", "protocol": "TCP", "src_port": 43210, "dst_port": 80}},
            ],
            # Current reports also keep network events in this convenience array.
            "events": [
                {"time": 3, "type": "dns_query", "data": {"domain": "bad.example", "pid": 77, "process": "sample.py"}},
                {"time": 4, "type": "http_request", "data": {"host": "bad.example", "path": "/stage", "method": "GET", "pid": 77, "process": "sample.py"}},
            ],
        }

    def test_05_timeline_is_authoritative_and_does_not_double_count(self):
        result = v194.correlate_static_dynamic([], self._report())
        self.assertEqual(result["dynamic_event_count"], 5)
        self.assertEqual(result["event_counts"]["dns_query"], 1)
        self.assertEqual(result["process_pid_map"][77], "sample.py")
        self.assertEqual(result["process_pid_map"][78], "child-probe")
        pcap_flow = next(x for x in result["timeline"] if x["type"] == "pcap_flow_observed")
        self.assertEqual(pcap_flow["pid"], 77)
        self.assertEqual(pcap_flow["process"], "sample.py")

    def test_06_static_ioc_is_correlated_with_dynamic_endpoint(self):
        findings = [{"rule": "remote-script-pipe", "title": "Download remote script",
                     "severity": "high", "evidence": "requests.get('bad.example')"}]
        result = v194.correlate_static_dynamic(findings, self._report())
        self.assertEqual(len(result["correlations"]), 1)
        row = result["correlations"][0]
        self.assertEqual(row["correlation_strength"], "high")
        self.assertEqual(row["matches"][0]["value"], "bad.example")
        self.assertIn("IOC", row["interpretation"])
        self.assertTrue(any("not proof" in x.lower() for x in result["interpretation_limits"]))

    def test_07_timeline_contains_process_and_file_events(self):
        result = v194.correlate_static_dynamic([], self._report())
        kinds = {x["type"] for x in result["timeline"]}
        self.assertIn("process_start_observed", kinds)
        self.assertIn("file_change_observed", kinds)
        self.assertIn("/tmp/drop.txt", result["observed_file_paths"])

    def test_08_detection_rule_templates_are_experimental(self):
        result = v194.correlate_static_dynamic([], self._report())
        rules = result["detection_rules"]["sigma"]
        self.assertTrue(rules)
        self.assertEqual(rules[0]["status"], "experimental")
        self.assertIn("falsepositives", rules[0])

    def test_09_unsupported_dynamic_schema_is_rejected(self):
        with self.assertRaises(ValueError):
            v194.correlate_static_dynamic([], {"schema": "untrusted.unsupported.v9"})

    def test_10_static_findings_are_bounded_and_shape_checked(self):
        with self.assertRaises(ValueError): v194.correlate_static_dynamic("not a list", self._report())
        with self.assertRaises(ValueError): v194.correlate_static_dynamic([], "not a report")


class V194NetworkAssistTests(unittest.TestCase):
    def test_11_osv_requires_explicit_consent_before_network(self):
        with patch.object(v194.urllib.request, "build_opener") as opener:
            with self.assertRaises(PermissionError):
                v194.query_osv_package("PyPI", "requests", "2.31.0", acknowledged=False)
            opener.assert_not_called()

    def test_12_osv_uses_fixed_endpoint_and_only_package_metadata(self):
        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self, size=-1): return b'{"vulns":[]}'
        class FakeOpener:
            def __init__(self): self.request = None
            def open(self, request, timeout): self.request = request; return FakeResponse()
        fake = FakeOpener()
        with patch.object(v194.urllib.request, "build_opener", return_value=fake):
            result = v194.query_osv_package("PyPI", "requests", "2.31.0", acknowledged=True)
        self.assertEqual(fake.request.full_url, "https://api.osv.dev/v1/query")
        body = json.loads(fake.request.data.decode())
        self.assertEqual(body["package"], {"name": "requests", "ecosystem": "PyPI"})
        self.assertEqual(body["version"], "2.31.0")
        self.assertEqual(result["vulnerability_count"], 0)

    def test_13_osv_rejects_unknown_ecosystem_and_bad_package_name(self):
        with self.assertRaises(ValueError): v194.query_osv_package("Unknown", "pkg", "1", True)
        with self.assertRaises(ValueError): v194.query_osv_package("PyPI", "../secret", "1", True)


class V194QwenAITests(unittest.TestCase):
    def tearDown(self):
        v193.clear_remote_ai()
        with cf.V194_AI_LOCK: cf.V194_AI_SESSIONS.clear()

    def test_14_qwen_model_is_allowlisted_and_status_marks_paid(self):
        result = v193.configure_remote_ai("qwencloud", "qwen_test_api_key_123456", "qwen3.8-max")
        self.assertEqual(result["model"], "qwen3.8-max")
        status = v193.remote_ai_status()
        qwen = next(x for x in status["providers"] if x["id"] == "qwencloud")
        self.assertIn("paid", qwen["label"].lower())
        self.assertIn("qwencloud", status["paid_providers"])
        with self.assertRaises(ValueError): v193.configure_remote_ai("qwencloud", "qwen_test_api_key_123456", "not-a-qwen-model")

    def test_15_qwen_requires_paid_ack_before_provider_request(self):
        v193.configure_remote_ai("qwencloud", "qwen_test_api_key_123456", "qwen3.8-max")
        body = {"mode": "remote", "provider": "qwencloud", "allow_remote": True, "message": "Explain this log"}
        with patch.object(v193, "remote_ai_chat") as call:
            with self.assertRaises(PermissionError): cf.v194_ai_chat({**body, "paid_cost_ack": False})
            call.assert_not_called()

    def test_16_qwen_uses_selected_provider_without_free_fallback(self):
        v193.configure_remote_ai("qwencloud", "qwen_test_api_key_123456", "qwen3.8-max")
        body = {"mode": "remote", "provider": "qwencloud", "allow_remote": True,
                "paid_cost_ack": True, "message": "Explain this log"}
        with patch.object(v193, "remote_ai_chat", return_value={"answer": "Qwen answer", "provider": "qwencloud", "model": "qwen3.8-max"}) as call:
            result = cf.v194_ai_chat(body)
        self.assertEqual(result["billing_class"], "paid")
        self.assertEqual(result["answer"], "Qwen answer")
        self.assertEqual(call.call_args.args[0], "qwencloud")
        self.assertNotIn("free_fallback", result)

    def test_17_local_network_assist_requires_separate_consent(self):
        body = {"mode": "local", "message": "Review dependencies", "task": "chat",
                "osv_packages": [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0"}]}
        with patch.object(v194, "query_osv_package") as query:
            with self.assertRaises(PermissionError): cf.v194_ai_chat(body)
            query.assert_not_called()


class V194OrchestrationTests(unittest.TestCase):
    def _stage(self, root):
        return v193.prepare_netlab_session(root, "sample.py", base64.b64encode(b"print('hello')").decode(), 5)

    def _write_run(self, root, session_id, run_id, domain, path):
        session = Path(root) / "sandbox_netlab" / session_id
        run = session / "runs" / run_id
        run.mkdir(parents=True)
        report = {"schema": "cyberforge.netlab.v2", "run_id": run_id,
                  "sample": {"sha256": v193._netlab_session(root, session_id)[1]["sha256"]},
                  "created_at": "2026-11-06T00:00:00+00:00",
                  "timeline": [{"time": 1, "type": "dns_query", "data": {"domain": domain}},
                               {"time": 2, "type": "http_request", "data": {"host": domain, "path": path}}],
                  "events": [{"time": 1, "type": "dns_query", "data": {"domain": domain}}],
                  "summary": {"dns_queries": 1, "http_requests": 1}, "pcap": {"stored": False}}
        (run / "report.json").write_text(json.dumps(report))
        meta_path = session / "session.json"
        meta = json.loads(meta_path.read_text())
        history = meta.get("run_history", [])
        history.append({"run_id": run_id, "completed_at": "2026-11-06T00:00:00+00:00", "event_count": 2, "pcap_available": False})
        meta.update({"run_history": history, "latest_run_id": run_id, "status": "completed", "completed_at": "2026-11-06T00:00:00+00:00"})
        meta_path.write_text(json.dumps(meta))
        return report

    def test_18_snapshot_and_restore_recover_sample_and_run_history(self):
        with tempfile.TemporaryDirectory() as td:
            staged = self._stage(td); sid = staged["session_id"]
            rid = "1" * 32
            self._write_run(td, sid, rid, "alpha.example", "/one")
            snap = v193.snapshot_netlab_session(td, sid, acknowledged=True)
            self.assertIn(rid, snap["saved_run_ids"])
            sample = next((Path(td) / "sandbox_netlab" / sid / "input").iterdir())
            sample.chmod(0o600); sample.write_text("tampered")
            restored = v193.restore_netlab_snapshot(td, sid, snap["snapshot_id"], acknowledged=True)
            self.assertTrue(restored["restored"])
            self.assertEqual(sample.read_bytes(), b"print('hello')")
            self.assertTrue(v193.read_netlab_report(td, sid, rid)["report_ready"])

    def test_19_snapshot_refuses_symlinked_run_root_without_partial_snapshot(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            staged = self._stage(td); sid = staged["session_id"]
            session = Path(td) / "sandbox_netlab" / sid
            (session / "runs").symlink_to(Path(outside), target_is_directory=True)
            with self.assertRaises(PermissionError): v193.snapshot_netlab_session(td, sid, acknowledged=True)
            self.assertFalse((session / "snapshots").exists())

    def test_20_restore_refuses_symlinked_snapshot_runs_before_mutation(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            staged = self._stage(td); sid = staged["session_id"]
            snap = v193.snapshot_netlab_session(td, sid, acknowledged=True)
            snap_dir = Path(td) / "sandbox_netlab" / sid / "snapshots" / snap["snapshot_id"]
            (snap_dir / "runs").symlink_to(Path(outside), target_is_directory=True)
            sample = next((Path(td) / "sandbox_netlab" / sid / "input").iterdir())
            sample.chmod(0o600); sample.write_text("leave-me")
            with self.assertRaises(PermissionError): v193.restore_netlab_snapshot(td, sid, snap["snapshot_id"], acknowledged=True)
            self.assertEqual(sample.read_text(), "leave-me")

    def test_21_compare_two_runs_in_the_same_session(self):
        with tempfile.TemporaryDirectory() as td:
            staged = self._stage(td); sid = staged["session_id"]
            left, right = "2" * 32, "3" * 32
            self._write_run(td, sid, left, "a.example", "/a")
            self._write_run(td, sid, right, "b.example", "/b")
            result = v193.compare_netlab_reports(td, sid, sid, left, right)
            self.assertEqual(result["left"]["run_id"], left)
            self.assertEqual(result["right"]["run_id"], right)
            self.assertGreater(result["right_only_count"], 0)

    def test_22_run_stores_pcap_and_reads_it_back_from_run_history(self):
        with tempfile.TemporaryDirectory() as td:
            staged = self._stage(td); sid = staged["session_id"]
            pcap = _minimal_pcap()
            report = {"schema": "cyberforge.netlab.v2", "events": [], "timeline": [],
                      "summary": {"pcap_packets": 1}, "sample_exit_code": 0,
                      "pcap": {"available": True, "packet_count": 1},
                      "pcap_base64": base64.b64encode(pcap).decode()}
            completed = subprocess.CompletedProcess([], 0, "CF_NETLAB_REPORT:" + json.dumps(report), "")
            side_effects = [subprocess.CompletedProcess([], 0, "", ""), completed,
                            subprocess.CompletedProcess([], 0, "", "")]
            with patch.object(v193.shutil, "which", return_value="/usr/bin/docker"), \
                 patch.object(v193.subprocess, "run", side_effect=side_effects):
                result = v193.run_netlab_session(td, sid, acknowledged=True)
            self.assertTrue(result["report"]["pcap"]["stored"])
            data, filename = v193.read_netlab_pcap(td, sid, result["run_id"])
            self.assertEqual(data, pcap)
            self.assertTrue(filename.endswith(".pcap"))

    def test_23_run_history_inventory_includes_ids_and_artifact_status(self):
        with tempfile.TemporaryDirectory() as td:
            staged = self._stage(td); sid = staged["session_id"]
            rid = "4" * 32; self._write_run(td, sid, rid, "x.example", "/")
            inventory = v193.list_netlab_sessions(td)
            row = next(x for x in inventory["sessions"] if x["session_id"] == sid)
            self.assertEqual(row["runs"][0]["run_id"], rid)
            self.assertEqual(row["run_count"], 1)


class V194PermissionTests(unittest.TestCase):
    def test_24_ai_provider_capability_is_dynamic_for_qwen_and_network_assist(self):
        self.assertIn("ai_provider_access", cf._api_capabilities("POST", "/api/v194/ai/chat", {"allow_remote": True}))
        self.assertIn("network_connectors", cf._api_capabilities("POST", "/api/v194/ai/chat", {"allow_network": True}))
        self.assertNotIn("network_connectors", cf._api_capabilities("POST", "/api/v194/ai/chat", {}))

    def test_25_pcap_read_requires_evidence_read(self):
        self.assertIn("evidence_read", cf._api_capabilities("GET", "/api/v194/sandbox/netlab/pcap"))

    def test_26_qwen_remote_status_is_never_default(self):
        status = cf.v194_ai_status()
        self.assertEqual(status["default_mode"], "local-first")
        self.assertFalse(status["remote_ai"]["remote_default"])
        self.assertIn("qwencloud", status["remote_ai"]["paid_providers"])


if __name__ == "__main__":
    unittest.main()
