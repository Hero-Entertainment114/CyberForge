#!/usr/bin/env python3
"""Loopback-only fake network for a disposable, no-network Docker container."""
from __future__ import annotations
import argparse
import base64
import hashlib
import http.server
import json
import os
import pwd
import re
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from netlab_telemetry import LoopbackPcapCapture, socket_owner

EVENTS = []
LOCK = threading.Lock()
MAX_EVENTS = 3000
STOP = threading.Event()


def emit(kind, **data):
    with LOCK:
        if len(EVENTS) < MAX_EVENTS:
            EVENTS.append({"time": time.time(), "type": kind, "data": data})


def parse_dns_name(packet):
    try:
        pos, labels = 12, []
        while pos < len(packet):
            n = packet[pos]; pos += 1
            if n == 0: break
            if n & 0xC0: return "", pos + 1, 1
            if n > 63 or pos + n > len(packet): return "", pos, 1
            labels.append(packet[pos:pos+n].decode("ascii", "replace")); pos += n
        qtype = struct.unpack("!H", packet[pos:pos+2])[0] if pos + 2 <= len(packet) else 1
        return ".".join(labels)[:253], pos + 4, qtype
    except Exception:
        return "", 0, 1


def dns_answer(packet):
    if len(packet) < 17: return b""
    name, end, qtype = parse_dns_name(packet)
    if not name or end > len(packet): return b""
    question = packet[12:end]
    qid = packet[:2]
    # Reply to A/AAAA with loopback; all other queries receive an empty NOERROR.
    answers = b""
    if qtype == 1:
        answers = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + b"\x7f\x00\x00\x01"
    elif qtype == 28:
        answers = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 30, 16) + (b"\x00" * 15 + b"\x01")
    flags = b"\x81\x80"
    return qid + flags + struct.pack("!HHHH", 1, 1 if answers else 0, 0, 0) + question + answers


class DNSUDP(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        name, _, qtype = parse_dns_name(packet)
        owner = socket_owner("udp", self.client_address[1], 53) or {"pid": None, "process": None, "attribution": "unavailable"}
        emit("dns_query", domain=name, qtype=qtype, answer="127.0.0.1/::1", peer_port=self.client_address[1], local_port=53, **owner)
        response = dns_answer(packet)
        if response: sock.sendto(response, self.client_address)


class DNSTCP(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(1.5)
        try:
            n = struct.unpack("!H", self.rfile.read(2))[0]
            packet = self.rfile.read(min(n, 4096))
            name, _, qtype = parse_dns_name(packet)
            owner = socket_owner("tcp", self.client_address[1], 53) or {"pid": None, "process": None, "attribution": "unavailable"}
            emit("dns_query_tcp", domain=name, qtype=qtype, answer="127.0.0.1/::1", peer_port=self.client_address[1], local_port=53, **owner)
            response = dns_answer(packet)
            if response: self.wfile.write(struct.pack("!H", len(response)) + response)
        except Exception: pass


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "CFNetLab/1.9.5"
    sys_version = ""
    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_OPTIONS(self): self._handle()
    def _handle(self):
        self.connection.settimeout(1.5)
        host = self.headers.get("Host", "")[:253]
        path = self.path.split("?", 1)[0][:500]
        # Redact long opaque route segments that are commonly used as reset/session tokens.
        path = re.sub(r"/(?=[A-Za-z0-9_-]{32,}(?:/|$))[A-Za-z0-9_-]{32,}", "/[REDACTED_SEGMENT]", path)
        path = re.sub(r"(?i)(api[_-]?key|token|secret|password)=([^/]+)", r"\1=[REDACTED]", path)
        try: body_len = min(int(self.headers.get("Content-Length", "0")), 2**31-1)
        except Exception: body_len = 0
        body_hash = ""
        body_captured = 0
        if body_len > 0:
            raw = self.rfile.read(min(body_len, 1024 * 1024))
            body_captured = len(raw)
            body_hash = hashlib.sha256(raw).hexdigest()
        safe_headers = {}
        for key in ("User-Agent", "Accept", "Content-Type", "Origin"):
            val = self.headers.get(key)
            if val: safe_headers[key.lower()] = val[:250]
        owner = socket_owner("tcp", self.client_address[1], self.connection.getsockname()[1]) or {"pid": None, "process": None, "attribution": "unavailable"}
        emit("http_request", method=self.command, host=host, path=path, peer_port=self.client_address[1], local_port=self.connection.getsockname()[1], **owner, body_bytes=body_len,
             body_bytes_captured=body_captured, body_sha256=body_hash,
             body_hash_scope="captured_prefix_only" if body_captured < body_len else "complete_or_empty",
             headers=safe_headers, query_values_captured=False)
        payload = b'{"cyberforge_netlab":true,"simulated":true}\n'
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload))); self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(payload)
    def log_message(self, fmt, *args): pass


def _tls_sni(data):
    # Minimal ClientHello parser. Records SNI only; no TLS interception/decryption.
    try:
        if len(data) < 9 or data[0] != 22: return ""
        p = 5
        if data[p] != 1: return ""
        p += 4 + 2 + 32
        sid = data[p]; p += 1 + sid
        ciphers = struct.unpack("!H", data[p:p+2])[0]; p += 2 + ciphers
        comp = data[p]; p += 1 + comp
        ext_len = struct.unpack("!H", data[p:p+2])[0]; p += 2
        end = min(p + ext_len, len(data))
        while p + 4 <= end:
            typ, size = struct.unpack("!HH", data[p:p+4]); p += 4
            ext = data[p:p+size]; p += size
            if typ == 0 and len(ext) >= 5:
                q = 2
                while q + 3 <= len(ext):
                    nt = ext[q]; ln = struct.unpack("!H", ext[q+1:q+3])[0]; q += 3
                    if nt == 0: return ext[q:q+ln].decode("ascii", "replace")[:253]
                    q += ln
        return ""
    except Exception: return ""


class TLSSink(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1.5)
        try: data = self.request.recv(16384)
        except Exception: data = b""
        sni = _tls_sni(data)
        owner = socket_owner("tcp", self.client_address[1], self.request.getsockname()[1]) or {"pid": None, "process": None, "attribution": "unavailable"}
        emit("tls_client_hello", sni=sni or None, peer_port=self.client_address[1], local_port=self.request.getsockname()[1], **owner, client_hello_bytes=len(data), decrypted=False)
        try: self.request.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
        except Exception: pass


class GenericSink(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(0.5)
        try: sample = self.request.recv(512)
        except Exception: sample = b""
        owner = socket_owner("tcp", self.client_address[1], self.request.getsockname()[1]) or {"pid": None, "process": None, "attribution": "unavailable"}
        emit("tcp_connection", peer_port=self.client_address[1], **owner, local_port=int(self.server.server_address[1]),
             initial_bytes=len(sample), initial_data_sha256=hashlib.sha256(sample).hexdigest() if sample else "")


class ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadingUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start(); return server, t


def start_emulators():
    servers = []
    servers.append(start_server(ThreadingUDP(("127.0.0.1", 53), DNSUDP)))
    servers.append(start_server(ThreadingServer(("127.0.0.1", 80), HTTPHandler)))
    servers.append(start_server(ThreadingServer(("127.0.0.1", 443), TLSSink)))
    servers.append(start_server(ThreadingServer(("127.0.0.1", 53), DNSTCP)))
    for port in (21, 22, 25, 110, 143, 445, 3306, 3389, 5432, 8080, 8443):
        try: servers.append(start_server(ThreadingServer(("127.0.0.1", port), GenericSink)))
        except OSError: pass
    return servers


def proc_snapshot():
    rows = {}
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(proc.name); raw = (proc / "stat").read_text()
            tail = raw[raw.rfind(")")+2:].split(); ppid = int(tail[1])
            cmd = (proc / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip()[:500]
            name = (proc / "comm").read_text().strip()[:120]
            rows[pid] = {"pid": pid, "ppid": ppid, "name": name, "command_line": cmd}
        except Exception: continue
    return rows


def file_snapshot():
    rows = {}
    for path in Path("/tmp").rglob("*"):
        try:
            if path.is_file() and not path.is_symlink() and path.name != "netlab-loopback.pcap" and len(rows) < 400:
                st = path.stat(); rows[str(path)[:400]] = (st.st_size, st.st_mtime_ns)
        except Exception: pass
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True); ap.add_argument("--kind", choices=("py", "sh"), required=True)
    ap.add_argument("--duration", type=int, choices=range(5, 121), required=True)
    args = ap.parse_args()
    sample = Path(args.sample)
    if not sample.is_file() or sample.is_symlink(): raise SystemExit("sample is not a regular file")
    servers = start_emulators()
    pcap_capture = LoopbackPcapCapture("/tmp/netlab-loopback.pcap").start()
    before = proc_snapshot(); files_before = file_snapshot()
    if args.kind == "py": cmd = [sys.executable, "-I", str(sample)]
    else: cmd = ["/bin/sh", str(sample)]
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp", "LANG": "C.UTF-8"}
    nobody = pwd.getpwnam("nobody")
    started = time.monotonic(); seen = set(before); proc_events = []; file_events = []
    deadline = started + args.duration
    proc = None
    exit_code = -1
    try:
        proc = subprocess.Popen(cmd, cwd="/tmp", env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                close_fds=True, start_new_session=True, user=nobody.pw_uid,
                                group=nobody.pw_gid, extra_groups=[], umask=0o077)
        while time.monotonic() < deadline and proc.poll() is None:
            current = proc_snapshot()
            for pid, row in current.items():
                if pid not in seen:
                    seen.add(pid)
                    # Environment values are never collected; redact common credentials in command-line text.
                    cmdline = row.get("command_line", "")
                    for token in ("token=", "password=", "api_key=", "access_key=", "secret="):
                        if token in cmdline.lower(): cmdline = cmdline[:cmdline.lower().find(token)] + token + "[REDACTED]"
                    cmdline = re.sub(r"\b(?:sk-|gsk_)[A-Za-z0-9_-]{12,}\b", "[REDACTED_KEY]", cmdline)
                    cmdline = re.sub(r"\bAIza[0-9A-Za-z_-]{30,}\b", "[REDACTED_GOOGLE_KEY]", cmdline)
                    cmdline = re.sub(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "[REDACTED_GITHUB_TOKEN]", cmdline)
                    cmdline = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]", cmdline)
                    row["command_line"] = cmdline[:500]
                    if len(proc_events) < 500: proc_events.append({"observed_at": time.time(), **row})
            current_files = file_snapshot()
            for path, meta in current_files.items():
                if files_before.get(path) != meta and len(file_events) < 500:
                    file_events.append({"observed_at": time.time(), "path": path, "state": "created" if path not in files_before else "modified", "size_bytes": meta[0]})
            time.sleep(0.2)
    finally:
        if proc is not None and proc.poll() is None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except Exception: proc.kill()
        if proc is not None:
            try: exit_code = proc.wait(timeout=3)
            except Exception: exit_code = -1
        for server, _ in servers:
            try: server.shutdown(); server.server_close()
            except Exception: pass
        pcap_meta = pcap_capture.stop()
    process_tree = [{"pid": x.get("pid"), "ppid": x.get("ppid"), "name": x.get("name"), "command_line": x.get("command_line")} for x in proc_events]
    timeline = ([{"time": x.get("time"), "type": x.get("type"), "data": x.get("data", {})} for x in EVENTS] +
                [{"time": x.get("observed_at", time.time()), "type": "process_start_observed", "data": x} for x in proc_events] +
                [{"time": x.get("observed_at", time.time()), "type": "file_change_observed", "data": x} for x in file_events])
    timeline.sort(key=lambda x: float(x.get("time") or 0))
    report = {"schema": "cyberforge.netlab.v2", "created_at": time.time(), "duration_seconds": round(time.monotonic()-started, 2),
              "sample_exit_code": exit_code, "sample_timed_out": time.monotonic() >= deadline,
              "process_events": proc_events, "process_tree": process_tree, "file_events": file_events, "events": EVENTS,
              "timeline": timeline[:6000],
              "network_flows": pcap_capture.flows[:2000],
              "pcap": pcap_meta,
              "coverage": {"dns": "loopback A/AAAA queries logged and redirected to loopback", "http": "request metadata captured; body is hashed then discarded", "https": "TLS ClientHello SNI captured only; TLS terminated with alert; no decryption", "direct_ip": "non-loopback route absent; failed attempts not attributed"},
              "summary": {"dns_queries": sum(1 for x in EVENTS if x["type"].startswith("dns_")),
                          "http_requests": sum(1 for x in EVENTS if x["type"] == "http_request"),
                          "tls_hellos": sum(1 for x in EVENTS if x["type"] == "tls_client_hello"),
                          "tcp_connections": sum(1 for x in EVENTS if x["type"] == "tcp_connection"),
                          "new_processes": len(proc_events), "file_changes": len(file_events),
                          "pcap_packets": pcap_meta.get("packet_count", 0), "network_flows": len(pcap_capture.flows)}}
    encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    # Keep Docker stdout bounded. Drop oldest lower-priority observations if necessary.
    while len(encoded.encode("utf-8")) > 1_400_000 and report["events"]:
        report["events"].pop(0)
        report["truncated"] = True
        encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    if pcap_meta.get("available") and Path("/tmp/netlab-loopback.pcap").is_file():
        try:
            pcap_bytes = Path("/tmp/netlab-loopback.pcap").read_bytes()
            if len(pcap_bytes) <= 2 * 1024 * 1024:
                report["pcap_base64"] = base64.b64encode(pcap_bytes).decode("ascii")
        except Exception:
            report["pcap"]["export_error"] = "capture_read_failed"
    encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    while len(encoded.encode("utf-8")) > 7_000_000 and report.get("pcap_base64"):
        report.pop("pcap_base64", None)
        report["pcap"]["export_error"] = "transport_size_limit"
        encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    print("CF_NETLAB_REPORT:" + encoded)

if __name__ == "__main__": main()
