import base64
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cyberforge as cf
import v195_modules as v195
import v193_modules as v193
from sandbox.netlab.netlab_telemetry import _normalize_loopback_packet


def ip_packet(proto: int, payload: bytes, src="127.0.0.1", dst="127.0.0.1") -> bytes:
    import socket
    src_b = socket.inet_aton(src); dst_b = socket.inet_aton(dst)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src_b, dst_b)
    return header + payload


def udp_packet(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def tcp_packet(src_port: int, dst_port: int, seq: int, payload: bytes, flags=0x18) -> bytes:
    header = struct.pack("!HHIIHHHH", src_port, dst_port, seq, 0, (5 << 12) | flags, 65535, 0, 0)
    return header + payload




def ip6_packet(proto: int, payload: bytes, src="::1", dst="::1") -> bytes:
    import socket
    src_b = socket.inet_pton(socket.AF_INET6, src); dst_b = socket.inet_pton(socket.AF_INET6, dst)
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, 64, src_b, dst_b) + payload


def pcapng_with_timestamp_resolution(records, resolution=9, linktype=101):
    def block(kind, body):
        size = 12 + len(body)
        size += (-size) % 4
        body = body + b"\x00" * (size - 12 - len(body))
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)
    shb = block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    # if_tsresol option 9, then end-of-options.
    opts = struct.pack("<HHB3xHH", 9, 1, resolution, 0, 0)
    idb = block(1, struct.pack("<HHI", linktype, 0, 262144) + opts)
    out = bytearray(shb + idb)
    for i, packet in enumerate(records, 1):
        ticks = i * (10 ** resolution)
        body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xffffffff, len(packet), len(packet)) + packet
        out += block(6, body)
    return bytes(out)


def pcapng_packet_block(packet, linktype=101):
    def block(kind, body):
        size = 12 + len(body); size += (-size) % 4
        body += b"\x00" * (size - 12 - len(body))
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)
    shb = block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    idb = block(1, struct.pack("<HHI", linktype, 0, 262144))
    packet_body = struct.pack("<HHIIII", 0, 0, 0, 2_000_000, len(packet), len(packet)) + packet
    return shb + idb + block(2, packet_body)


def tls_server_hello():
    extensions = struct.pack("!HHH", 43, 2, 0x0304)
    body = (b"\x03\x03" + b"S" * 32 + b"\x00" + struct.pack("!H", 0x1301) +
            b"\x00" + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def pcap(records, linktype=101):
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
    for index, packet in enumerate(records, 1):
        out += struct.pack("<IIII", 1700000000 + index, 0, len(packet), len(packet)) + packet
    return bytes(out)


def pcapng(records, linktype=101):
    def block(kind, body):
        size = 12 + len(body)
        size += (-size) % 4
        body = body + b"\x00" * (size - 12 - len(body))
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)
    shb = block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    idb = block(1, struct.pack("<HHI", linktype, 0, 262144))
    out = bytearray(shb + idb)
    for i, packet in enumerate(records, 1):
        body = struct.pack("<IIIII", 0, 0, i * 1_000_000, len(packet), len(packet)) + packet
        out += block(6, body)
    return bytes(out)


def dns_query(name="telemetry.example", qtype=1):
    labels = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def tls_client_hello(name="telemetry.example"):
    sni_name = name.encode()
    sni_entry = b"\x00" + struct.pack("!H", len(sni_name)) + sni_name
    sni_ext = struct.pack("!H", len(sni_entry)) + sni_entry
    alpn_names = b"\x02h2\x08http/1.1"
    alpn_ext = struct.pack("!H", len(alpn_names)) + alpn_names
    versions_ext = b"\x04\x03\x04\x03\x03"
    extensions = (struct.pack("!HH", 0, len(sni_ext)) + sni_ext +
                  struct.pack("!HH", 16, len(alpn_ext)) + alpn_ext +
                  struct.pack("!HH", 43, len(versions_ext)) + versions_ext)
    body = (b"\x03\x03" + b"R" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" +
            b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class V195PacketDecoderTests(unittest.TestCase):
    def test_01_decode_dns_query_from_raw_pcap(self):
        capture = pcap([ip_packet(17, udp_packet(53000, 53, dns_query()))])
        result = v195.decode_pcap(capture)
        self.assertEqual(result["capture"]["format"], "pcap")
        self.assertEqual(result["summary"]["dns_queries"], 1)
        event = result["timeline"][0]
        self.assertEqual(event["data"]["domain"], "telemetry.example")

    def test_02_decode_http_metadata_and_strip_query_values(self):
        request = b"GET /api/check?token=secret-value HTTP/1.1\r\nHost: api.example\r\nAuthorization: Bearer super-secret-token\r\nContent-Length: 15\r\n\r\nsecret-body-data"
        capture = pcap([ip_packet(6, tcp_packet(50000, 80, 100, request))])
        result = v195.decode_pcap(capture)
        event = next(x for x in result["timeline"] if x["type"] == "http_request")
        self.assertEqual(event["data"]["method"], "GET")
        self.assertEqual(event["data"]["path"], "/api/check")
        serialized = json.dumps(result)
        for secret in ("secret-value", "super-secret-token", "secret-body-data"):
            self.assertNotIn(secret, serialized.lower())
        self.assertFalse(result["privacy"]["payload_exported"])

    def test_03_decode_tls_clienthello_sni_alpn_and_fingerprint(self):
        capture = pcap([ip_packet(6, tcp_packet(50001, 443, 200, tls_client_hello()))])
        result = v195.decode_pcap(capture)
        event = next(x for x in result["timeline"] if x["type"] == "tls_client_hello")
        self.assertEqual(event["data"]["sni"], "telemetry.example")
        self.assertEqual(event["data"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(len(event["data"]["ja3_like_sha256"]), 64)
        self.assertFalse(event["data"]["tls_decrypted"])

    def test_04_pcapng_enhanced_packet_block_is_supported(self):
        capture = pcapng([ip_packet(17, udp_packet(53000, 53, dns_query("pcapng.example")))])
        result = v195.decode_pcap(capture)
        self.assertEqual(result["capture"]["format"], "pcapng")
        self.assertEqual(result["summary"]["dns_queries"], 1)
        self.assertEqual(result["timeline"][0]["data"]["domain"], "pcapng.example")

    def test_05_ethernet_and_vlan_link_headers_are_normalized(self):
        raw = ip_packet(17, udp_packet(53000, 53, dns_query("ethernet.example")))
        ethernet = b"\x00" * 12 + b"\x08\x00" + raw
        self.assertEqual(_normalize_loopback_packet(ethernet), raw)
        vlan = b"\x00" * 12 + b"\x81\x00\x00\x01\x08\x00" + raw
        self.assertEqual(_normalize_loopback_packet(vlan), raw)
        result = v195.decode_pcap(pcap([ethernet], linktype=1))
        self.assertEqual(result["summary"]["dns_queries"], 1)

    def test_06_raw_pcap_limit_is_enforced(self):
        with self.assertRaises(ValueError): v195.decode_pcap(b"x" * (v195.MAX_PCAP_BYTES + 1))
        with self.assertRaises(ValueError): v195.decode_pcap(b"not pcap")

    def test_07_malformed_or_unsupported_linktype_is_not_misdecoded(self):
        capture = pcap([b"random data"], linktype=999)
        result = v195.decode_pcap(capture)
        self.assertEqual(result["capture"]["unsupported_link_packets"], 1)
        self.assertEqual(result["summary"]["events"], 0)

    def test_08_dns_compression_pointer_is_bounded(self):
        malformed = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        capture = pcap([ip_packet(17, udp_packet(54000, 53, malformed))])
        result = v195.decode_pcap(capture)
        self.assertLessEqual(result["summary"]["events"], 1)

    def test_09_tls_alert_is_recorded_without_payload(self):
        alert = b"\x15\x03\x03\x00\x02\x02\x28"
        capture = pcap([ip_packet(6, tcp_packet(50002, 443, 300, alert))])
        result = v195.decode_pcap(capture)
        self.assertTrue(any(x["type"] == "tls_alert" for x in result["timeline"]))

    def test_10_output_has_no_raw_packet_or_payload_fields(self):
        capture = pcap([ip_packet(6, tcp_packet(50003, 80, 400, b"GET /safe HTTP/1.1\r\nHost: example.test\r\n\r\nsecret"))])
        result = v195.decode_pcap(capture)
        serialized = json.dumps(result)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("secret", serialized.lower())
        self.assertNotIn('"payload":', serialized.lower())


    def test_11_decode_ipv6_udp_dns(self):
        capture = pcap([ip6_packet(17, udp_packet(53001, 53, dns_query("ipv6.example")))])
        result = v195.decode_pcap(capture)
        self.assertEqual(result["summary"]["dns_queries"], 1)
        self.assertEqual(result["timeline"][0]["data"]["domain"], "ipv6.example")

    def test_12_decode_http_response_metadata(self):
        response = b"HTTP/1.1 200 OK\r\nServer: example-edge\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nSet-Cookie: session=secret\r\n\r\nbody"
        result = v195.decode_pcap(pcap([ip_packet(6, tcp_packet(80, 50010, 900, response))]))
        event = next(x for x in result["timeline"] if x["type"] == "http_response")
        self.assertEqual(event["data"]["status"], 200)
        self.assertEqual(event["data"]["headers"]["server"], "example-edge")
        self.assertNotIn("Set-Cookie", json.dumps(result))

    def test_13_tcp_stream_reassembly_decodes_split_http_request(self):
        payload = b"GET /chunked HTTP/1.1\r\nHost: split.example\r\n\r\n"
        first = payload[:19]; second = payload[19:]
        capture = pcap([ip_packet(6, tcp_packet(50100, 80, 1000, first)),
                        ip_packet(6, tcp_packet(50100, 80, 1000 + len(first), second))])
        result = v195.decode_pcap(capture)
        event = next(x for x in result["timeline"] if x["type"] == "http_request")
        self.assertEqual(event["data"]["path"], "/chunked")

    def test_14_decode_tls_server_hello_selected_version(self):
        result = v195.decode_pcap(pcap([ip_packet(6, tcp_packet(443, 50101, 1200, tls_server_hello()))]))
        event = next(x for x in result["timeline"] if x["type"] == "tls_server_hello")
        self.assertEqual(event["data"]["selected_version"], "0x0304")
        self.assertEqual(event["data"]["selected_cipher"], "0x1301")
        self.assertFalse(event["data"]["tls_decrypted"])

    def test_15_pcapng_obsolete_packet_block_is_supported(self):
        packet = ip_packet(17, udp_packet(54000, 53, dns_query("packetblock.example")))
        result = v195.decode_pcap(pcapng_packet_block(packet))
        self.assertEqual(result["summary"]["dns_queries"], 1)
        self.assertEqual(result["timeline"][0]["data"]["domain"], "packetblock.example")

    def test_16_pcapng_nanosecond_timestamp_resolution_is_respected(self):
        packet = ip_packet(17, udp_packet(54001, 53, dns_query("timestamp.example")))
        result = v195.decode_pcap(pcapng_with_timestamp_resolution([packet], resolution=9))
        self.assertAlmostEqual(result["timeline"][0]["time"], 1.0, places=6)


class V195DockerDiagnosticsTests(unittest.TestCase):
    def test_11_diagnostics_returns_actionable_when_docker_missing(self):
        with patch.object(v195.shutil, "which", return_value=None):
            result = v195.docker_desktop_diagnostics()
        self.assertFalse(result["daemon_reachable"])
        self.assertTrue(any(x["name"] == "docker_cli" for x in result["checks"]))

    def test_12_windows_diagnostics_identifies_linux_engine_and_wsl(self):
        def which(name):
            return {"docker":"C:/Docker/docker.exe", "wsl.exe":"C:/Windows/wsl.exe", "powershell.exe":"C:/Windows/powershell.exe"}.get(name)
        def run(args, timeout=8):
            if args[1:2] == ["version"]:
                return {"returncode":0,"stdout":json.dumps({"Server":{"Version":"28.0.0"},"Client":{"Version":"28.0.0"}}),"stderr":""}
            if args[1:2] == ["info"]:
                return {"returncode":0,"stdout":json.dumps({"OSType":"linux","OperatingSystem":"Docker Desktop","Architecture":"x86_64","KernelVersion":"6.6","SecurityOptions":["name=seccomp"]}),"stderr":""}
            if args[1:2] == ["context"]: return {"returncode":0,"stdout":"desktop-linux","stderr":""}
            if "--version" in args: return {"returncode":0,"stdout":"WSL version: 2.2.4","stderr":""}
            if "--status" in args: return {"returncode":0,"stdout":"Default Distribution: Ubuntu","stderr":""}
            if "-l" in args: return {"returncode":0,"stdout":"docker-desktop Running 2","stderr":""}
            return {"returncode":0,"stdout":"Docker Desktop\ncom.docker.backend","stderr":""}
        with patch.object(v195.shutil, "which", side_effect=which), patch.object(v195.platform, "system", return_value="Windows"), patch.object(v195, "_run_command", side_effect=run):
            result = v195.docker_desktop_diagnostics()
        self.assertTrue(result["daemon_reachable"])
        self.assertTrue(result["linux_container_engine"])
        self.assertIn("windows_notes", result)
        self.assertTrue(any(x["name"] == "wsl_version" and x["ok"] for x in result["checks"]))

    def test_13_capability_probe_requires_ack(self):
        with self.assertRaises(PermissionError): v195.docker_sandbox_smoke_test("cyberforge/netlab:1.9.5", False)

    def test_14_probe_never_runs_without_existing_image(self):
        with patch.object(v195.shutil, "which", return_value="docker"), patch.object(v195, "_run_command", return_value={"returncode":1,"stdout":"","stderr":"missing","timed_out":False}) as run:
            result = v195.docker_sandbox_smoke_test("cyberforge/netlab:1.9.5", True)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "image_not_present")
        self.assertEqual(run.call_count, 1)


    def test_17_probe_requires_packet_seen_and_no_default_route(self):
        outputs = [
            {"returncode":0,"stdout":"{}","stderr":"","timed_out":False},
            {"returncode":0,"stdout":json.dumps({"euid":0,"loopback_raw_socket":True,"loopback_packet_seen":True,"default_routes":[],"default_route_absent":True}),"stderr":"","timed_out":False},
        ]
        with patch.object(v195.shutil, "which", return_value="docker"), patch.object(v195, "_run_command", side_effect=outputs) as run:
            result = v195.docker_sandbox_smoke_test("cyberforge/netlab:1.9.5", True)
        self.assertTrue(result["passed"])
        command = run.call_args_list[1].args[0]
        self.assertIn("none", command)
        self.assertNotIn("-v", command)
        self.assertNotIn("--mount", command)
        self.assertNotIn("--network=host", command)

    def test_18_probe_fails_if_loopback_packet_is_not_observed(self):
        outputs = [
            {"returncode":0,"stdout":"{}","stderr":"","timed_out":False},
            {"returncode":0,"stdout":json.dumps({"euid":0,"loopback_raw_socket":True,"loopback_packet_seen":False,"default_routes":[],"default_route_absent":True}),"stderr":"","timed_out":False},
        ]
        with patch.object(v195.shutil, "which", return_value="docker"), patch.object(v195, "_run_command", side_effect=outputs):
            result = v195.docker_sandbox_smoke_test("cyberforge/netlab:1.9.5", True)
        self.assertFalse(result["passed"])


    def test_19_windows_acceptance_script_documents_real_host_probe(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "tools" / "windows_docker_acceptance.ps1").read_text(encoding="utf-8")
        self.assertIn("--network", script)
        self.assertIn("--cap-add", script)
        self.assertIn("NET_RAW", script)
        self.assertIn("loopback_packet_seen", script)
        self.assertIn("default_route_absent", script)
        self.assertIn("'--network', 'none'", script)


class V195AgentWorkflowTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self._old_data, self._old_evidence, self._old_db = cf.DATA_DIR, cf.EVIDENCE_DIR, cf.DB_PATH
        cf.DATA_DIR = Path(self._temp.name)
        cf.EVIDENCE_DIR = Path(self._temp.name) / "evidence"
        cf.DB_PATH = Path(self._temp.name) / "cyberforge.db"
        cf.init_database()

    def tearDown(self):
        with cf.V195_AGENT_LOCK: cf.V195_AGENT_PLANS.clear()
        cf.DATA_DIR, cf.EVIDENCE_DIR, cf.DB_PATH = self._old_data, self._old_evidence, self._old_db
        self._temp.cleanup()

    def test_15_plan_creation_is_non_executing_and_explicit(self):
        with patch.object(cf, "v195_docker_diagnostics") as diagnostics:
            result = cf.v195_agent_plan({"static_source":"eval(input())", "language":"python"})
        diagnostics.assert_not_called()
        self.assertEqual(result["status"], "awaiting_approval")
        self.assertTrue(result["approval"]["required"])
        self.assertIn("static_review", [x["action"] for x in result["steps"]])

    def test_16_agent_executes_only_selected_static_review_steps(self):
        plan = cf.v195_agent_plan({"static_source":"eval(input())", "language":"python"})
        step = next(x for x in plan["steps"] if x["action"] == "static_review")
        result = cf.v195_agent_execute({"plan_id":plan["plan_id"], "approved_step_ids":[step["step_id"]]})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["executed_steps"][0]["action"], "static_review")

    def test_17_agent_rejects_unapproved_or_unknown_step_ids(self):
        plan = cf.v195_agent_plan({"static_source":"print('safe')"})
        with self.assertRaises(ValueError): cf.v195_agent_execute({"plan_id":plan["plan_id"],"approved_step_ids":["arbitrary_command"]})

    def test_18_agent_requires_dependencies_to_be_approved(self):
        plan = cf.v195_agent_plan({"static_source":"eval(input())"})
        summary = next(x for x in plan["steps"] if x["action"] == "offline_summary")
        with self.assertRaises(ValueError): cf.v195_agent_execute({"plan_id":plan["plan_id"],"approved_step_ids":[summary["step_id"]]})

    def test_19_agent_requires_separate_approval_for_sample_execution(self):
        # The session is mocked only for the planning preflight; no real sample is executed.
        sid = "a" * 32
        with patch.object(v193, "read_netlab_report", return_value={"report_ready":False}):
            plan = cf.v195_agent_plan({"session_id":sid,"run_sample":True})
        sample = next(x for x in plan["steps"] if x["action"] == "run_sample")
        with patch.object(cf, "v193_netlab_run") as runner:
            result = cf.v195_agent_execute({"plan_id":plan["plan_id"],"approved_step_ids":[next(x["step_id"] for x in plan["steps"] if x["action"]=="docker_diagnostics"),sample["step_id"]],"run_sample_ack":False})
        runner.assert_not_called()
        self.assertEqual(result["status"], "partial_or_failed")
        self.assertEqual(result["executed_steps"][-1]["status"], "failed")

    def test_20_agent_network_step_requires_separate_network_consent(self):
        plan = cf.v195_agent_plan({"osv_packages":[{"ecosystem":"PyPI","name":"requests","version":"2.31.0"}]})
        step = next(x for x in plan["steps"] if x["action"] == "osv_lookup")
        with patch.object(cf.v194_modules, "query_osv_package") as query:
            result = cf.v195_agent_execute({"plan_id":plan["plan_id"],"approved_step_ids":[step["step_id"]],"allow_network":False})
        query.assert_not_called()
        self.assertEqual(result["executed_steps"][0]["status"], "failed")

    def test_21_agent_plan_expires_and_is_one_shot(self):
        plan = cf.v195_agent_plan({"static_source":"print('ok')"})
        step = next(x for x in plan["steps"] if x["action"] == "static_review")
        cf.v195_agent_execute({"plan_id":plan["plan_id"],"approved_step_ids":[step["step_id"]]})
        with self.assertRaises(PermissionError): cf.v195_agent_execute({"plan_id":plan["plan_id"],"approved_step_ids":[step["step_id"]]})

    def test_22_execute_capabilities_are_derived_from_selected_plan_actions(self):
        plan = cf.v195_agent_plan({"static_source":"eval(input())"})
        step = next(x for x in plan["steps"] if x["action"] == "static_review")
        caps = cf._api_capabilities("POST", "/api/v195/agent/execute", {"plan_id":plan["plan_id"],"approved_step_ids":[step["step_id"]]})
        self.assertIn("static_analysis", caps)

    def test_23_status_does_not_expose_source_code_or_package_contents(self):
        plan = cf.v195_agent_plan({"static_source":"VERY_SECRET_SOURCE", "osv_packages":[{"ecosystem":"PyPI","name":"requests","version":"2"}]})
        status = cf.v195_agent_status()
        self.assertNotIn("VERY_SECRET_SOURCE", json.dumps(status))
        self.assertNotIn("requests", json.dumps(status))


    def test_32_failed_agent_step_reports_approved_steps_not_attempted(self):
        plan = cf.v195_agent_plan({"static_source":"eval(input())"})
        ids = [x["step_id"] for x in plan["steps"]]
        with patch.object(cf, "v195_docker_diagnostics", side_effect=RuntimeError("engine unavailable")):
            result = cf.v195_agent_execute({"plan_id":plan["plan_id"], "approved_step_ids":ids})
        self.assertEqual(result["status"], "partial_or_failed")
        self.assertEqual(result["approved_but_not_attempted_step_ids"], ids[1:])


if __name__ == "__main__":
    unittest.main()
